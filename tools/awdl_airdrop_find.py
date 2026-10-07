#!/usr/bin/env python3
# OWL: an open Apple Wireless Direct Link (AWDL) implementation
# Copyright (C) 2018  The Open Wireless Link Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Discover AirDrop receivers and map their real device name to a MAC.

Phase 1 of a single-radio workflow: with AWDL up (``awdl0`` from the ``owl``
daemon) this tool acts as an AirDrop *sender*.  It browses ``_airdrop._tcp``
over AWDL, and for every receiver it finds it performs the AirDrop HTTPS
``Discover`` exchange to read the receiver's **real** computer name -- the one
that shows on a sender's share sheet.  That name is *not* in the AWDL frames
(there it is a random UUID) and is not sniffable (the Discover is TLS-
encrypted), so an active Discover is the only way to obtain it.

It then prints a ``name <-> MAC`` table (the MAC is derived from the
receiver's AWDL link-local address) and writes the chosen target's MAC to a
file, which ``awdl_master_inject.py --targets-file`` picks up for phase 2.
Because discovery and injection never run at the same time, one radio
suffices: run this first in managed mode (with ``owl``), then switch the same
card to monitor mode for the injector.

What it does NOT do: it reads only the device *name* the receiver returns for
display; it does not complete a transfer and does not touch the contact
identifiers (phone / email) that AirDrop's contact matching is based on.

================================  AUTHORISED USE  ============================
Run this ONLY against devices you own or are explicitly authorised to test, in
an isolated RF lab.  Like the rest of OWL it is experimental research software
-- use it at your own risk.
=============================================================================

Example:
    sudo owl -i wlan0 -c 6 &                 # bring AWDL up (awdl0)
    sudo ./awdl_airdrop_find.py -i awdl0 --out captured_target.txt
    # ...pick the target by name; then (same card, now monitor mode):
    sudo ./awdl_master_inject.py -i wlan0 --targets-file captured_target.txt \
         --channels 6,6,44,149 --channel-dwell 300ms --interval 110tu

Requires the receiver to be discoverable (AirDrop set to "Everyone", or you in
its contacts). The Discover TLS/plist handshake may need tuning against a given
iOS version; OpenDrop (`opendrop find`) is the proven fallback for this step.
"""

import argparse
import os
import plistlib
import socket
import ssl
import struct
import sys
import time

import awdl_airdrop_honeypot as hp     # shared mDNS / MAC / cert helpers

T_A = 1
T_PTR = 12
T_TXT = 16
T_AAAA = 28
T_SRV = 33
C_IN = 1


# ---------------------------------------------------------------------------
# mDNS browse (client side)
# ---------------------------------------------------------------------------

def build_ptr_query(service):
    """A standard mDNS query asking for the PTR records of ``service``."""
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + hp.encode_name(service) + struct.pack(">HH", T_PTR, C_IN)


def build_query(name, rtype):
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + hp.encode_name(name) + struct.pack(">HH", rtype, C_IN)


def _parse_txt(buf, offset, rdlen):
    out = []
    end = offset + rdlen
    while offset < end:
        n = buf[offset]
        offset += 1
        out.append(buf[offset:offset + n].decode("utf-8", "replace"))
        offset += n
    return out


def parse_records(buf):
    """Parse all resource records of a DNS/mDNS message into a list of
    ``(name_lower, rtype, value)``. Names in rdata are decompressed against the
    whole message. Unknown types are skipped."""
    recs = []
    if len(buf) < 12:
        return recs
    qd, an, ns, ar = struct.unpack_from(">HHHH", buf, 4)
    offset = 12
    try:
        for _ in range(qd):                     # skip questions
            _, offset = hp.decode_name(buf, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = hp.decode_name(buf, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", buf, offset)
            offset += 10
            rdata_off = offset
            value = None
            if rtype == T_PTR:
                value, _ = hp.decode_name(buf, rdata_off)
            elif rtype == T_SRV:
                port = struct.unpack_from(">HHH", buf, rdata_off)[2]
                target, _ = hp.decode_name(buf, rdata_off + 6)
                value = (port, target.lower())
            elif rtype == T_TXT:
                value = _parse_txt(buf, rdata_off, rdlen)
            elif rtype == T_AAAA and rdlen == 16:
                value = socket.inet_ntop(socket.AF_INET6, buf[rdata_off:rdata_off + 16])
            elif rtype == T_A and rdlen == 4:
                value = socket.inet_ntop(socket.AF_INET, buf[rdata_off:rdata_off + 4])
            recs.append((name.lower(), rtype, value))
            offset = rdata_off + rdlen
    except (ValueError, struct.error, IndexError):
        pass                                    # best effort: keep what parsed
    return recs


def browse(ifname, ifindex, timeout):
    """Browse ``_airdrop._tcp`` for ``timeout`` seconds. Returns a list of
    receiver dicts: {instance, host, port, addr6, mac}."""
    sock = hp.open_mdns_socket(ifname, ifindex)
    group = (hp.MDNS_ADDR6 + "%" + str(ifindex), hp.MDNS_PORT, 0, ifindex)
    ptr, srv, aaaa = {}, {}, {}

    def ingest(buf):
        for name, rtype, value in parse_records(buf):
            if value is None:
                continue
            if rtype == T_PTR and name == hp.AIRDROP_SERVICE:
                ptr.setdefault(value.lower(), None)
            elif rtype == T_SRV:
                srv[name] = value               # instance -> (port, host)
            elif rtype == T_AAAA:
                aaaa.setdefault(name, []).append(value)   # host -> [addr6]

    try:
        sock.sendto(build_ptr_query(hp.AIRDROP_SERVICE), group)
    except OSError:
        pass
    end = time.monotonic() + timeout
    asked_follow_up = False
    while time.monotonic() < end:
        try:
            buf, _ = sock.recvfrom(4096)
        except socket.timeout:
            # Half-way through, re-ask for any instance still missing SRV/AAAA.
            if not asked_follow_up and ptr:
                asked_follow_up = True
                for inst in list(ptr):
                    if inst not in srv:
                        _try_send(sock, build_query(inst, T_SRV), group)
                for host in {h for (_p, h) in srv.values()}:
                    if host not in aaaa:
                        _try_send(sock, build_query(host, T_AAAA), group)
            continue
        except OSError:
            break
        ingest(buf)

    sock.close()
    receivers = []
    for inst in ptr:
        port, host = srv.get(inst, (None, None))
        addr6 = aaaa.get(host, [None])[0] if host else None
        mac = hp.mac_from_ipv6(addr6) if addr6 else None
        receivers.append({"instance": inst, "host": host, "port": port,
                          "addr6": addr6, "mac": mac})
    return receivers


def _try_send(sock, data, dest):
    try:
        sock.sendto(data, dest)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# AirDrop HTTPS Discover (to read the real receiver name)
# ---------------------------------------------------------------------------

def make_client_context():
    """A permissive TLS client context presenting a throwaway client cert
    (AirDrop uses mutual TLS). Returns a context, or None to go without a cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cert, key = hp.generate_self_signed_certfiles()
    if cert:
        try:
            ctx.load_cert_chain(cert, key)
        except ssl.SSLError:
            pass
    return ctx


def discover_name(ifname, addr6, port, ctx, timeout=4.0):
    """Perform an AirDrop ``POST /Discover`` and return the receiver's details
    dict (with ``ReceiverComputerName`` etc.), or None on failure."""
    if not addr6 or not port:
        return None
    scope = socket.if_nametoindex(ifname)
    raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((addr6, port, 0, scope))
        conn = ctx.wrap_socket(raw, server_hostname=None) if ctx else raw
        body = plistlib.dumps({}, fmt=plistlib.FMT_BINARY)
        req = (
            "POST /Discover HTTP/1.1\r\n"
            "Host: [%s]:%d\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (addr6, port, len(body))
        ).encode("ascii") + body
        conn.sendall(req)
        data = b""
        while len(data) < 1 << 20:              # 1 MiB cap
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        try:
            conn.close()
        except OSError:
            pass
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            raw.close()
        except OSError:
            pass
    _, _, bdy = data.partition(b"\r\n\r\n")
    if not bdy:
        return None
    try:
        plist = plistlib.loads(bdy)
    except Exception:
        return None
    return plist if isinstance(plist, dict) else None


# ---------------------------------------------------------------------------
# self-test (offline, no radio)
# ---------------------------------------------------------------------------

def run_self_test():
    # A browse response built by the honeypot parses back to its instance /
    # port / address, and the address yields the right MAC.
    mac = bytes([0x00, 0xc0, 0xca, 0xbd, 0x09, 0x8a])
    eui = bytes([mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]])
    addr6 = socket.inet_ntop(socket.AF_INET6,
                             bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0]) + eui)
    inst = "a1b2c3d4e5f6." + hp.AIRDROP_SERVICE
    host = "a1b2c3d4e5f6.local"
    resp = hp.build_airdrop_response(inst, host, 8770,
                                     socket.inet_pton(socket.AF_INET6, addr6),
                                     ["flags=136"])
    recs = parse_records(resp)
    types = {t: v for (_n, t, v) in recs}
    assert any(t == T_PTR and v == inst for (_n, t, v) in recs), recs
    assert types.get(T_SRV) == (8770, host), types.get(T_SRV)
    assert types.get(T_AAAA) == addr6, types.get(T_AAAA)
    assert hp.mac_from_ipv6(types[T_AAAA]) == mac
    # Query build round-trips through the honeypot's question parser.
    q = build_ptr_query(hp.AIRDROP_SERVICE)
    assert hp.parse_questions(q) == [hp.AIRDROP_SERVICE]
    # A Discover response body (plist) parses and the name is extracted.
    pl = plistlib.dumps({"ReceiverComputerName": "Peters iPad",
                         "ReceiverModelName": "iPad"}, fmt=plistlib.FMT_BINARY)
    http = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(pl) + pl
    _, _, bdy = http.partition(b"\r\n\r\n")
    got = plistlib.loads(bdy)
    assert got["ReceiverComputerName"] == "Peters iPad", got
    print("self-test OK")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def choose(receivers, args):
    """Return the list of receivers whose MAC should be written out."""
    usable = [r for r in receivers if r["mac"]]
    if not usable:
        return []
    if args.all:
        return usable
    if args.name_filter:
        sub = args.name_filter.lower()
        matches = [r for r in usable if r["name"] and sub in r["name"].lower()]
        return matches[:1]
    if args.pick is not None:
        return [usable[args.pick]] if 0 <= args.pick < len(usable) else []
    if args.first:
        return usable[:1]
    # interactive
    try:
        raw = input("\nPick a target by number (blank = first, q = none): ").strip()
    except (EOFError, KeyboardInterrupt):
        return []
    if raw.lower() == "q":
        return []
    if raw == "":
        return usable[:1]
    try:
        idx = int(raw)
    except ValueError:
        return []
    return [usable[idx]] if 0 <= idx < len(usable) else []


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Discover AirDrop receivers over AWDL and map their real "
                    "device name to a MAC (phase 1 for the injector).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default="awdl0",
                        help="AWDL interface the owl daemon created")
    parser.add_argument("--timeout", type=float, default=6.0,
                        help="seconds to browse for receivers")
    parser.add_argument("--out", default="captured_target.txt",
                        help="file to write the chosen target MAC(s) to "
                             "(read by awdl_master_inject.py --targets-file)")
    parser.add_argument("--first", action="store_true",
                        help="auto-pick the first discovered receiver")
    parser.add_argument("--pick", type=int, default=None, metavar="N",
                        help="auto-pick receiver number N (no prompt)")
    parser.add_argument("--name-filter", default=None, metavar="SUB",
                        help="auto-pick the first receiver whose name contains SUB")
    parser.add_argument("--all", action="store_true",
                        help="write every discovered receiver's MAC")
    parser.add_argument("--no-discover", action="store_true",
                        help="skip the HTTPS Discover; list MACs only (names "
                             "stay unknown)")
    parser.add_argument("--no-tls-cert", action="store_true",
                        help="do not present a client certificate during Discover")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline unit checks and exit (no radio needed)")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if os.geteuid() != 0:
        print("[!] note: mDNS/AWDL access usually needs root (sudo)")

    try:
        ifindex = socket.if_nametoindex(args.interface)
    except OSError:
        sys.exit("error: no such interface %r (is the owl daemon running?)"
                 % args.interface)

    print("[*] browsing %s for AirDrop receivers (%.0fs)..."
          % (args.interface, args.timeout))
    receivers = browse(args.interface, ifindex, args.timeout)
    if not receivers:
        sys.exit("no AirDrop receivers found (is a device in range set to "
                 "'Receiving: Everyone', and is AWDL up?)")

    ctx = None if (args.no_discover or args.no_tls_cert) else make_client_context()
    for r in receivers:
        r["name"] = None
        r["model"] = None
        if not args.no_discover:
            info = discover_name(args.interface, r["addr6"], r["port"], ctx)
            if info:
                r["name"] = info.get("ReceiverComputerName")
                r["model"] = info.get("ReceiverModelName")

    print("\n  #  %-28s %-10s %s" % ("name", "model", "MAC"))
    print("  " + "-" * 60)
    usable = [r for r in receivers if r["mac"]]
    for i, r in enumerate(usable):
        name = r["name"] or ("?(" + r["instance"].split(".")[0] + ")")
        print("  %-2d %-28s %-10s %s"
              % (i, name[:28], (r["model"] or "")[:10], hp.mac_str(r["mac"])))
    skipped = len(receivers) - len(usable)
    if skipped:
        print("  (%d receiver(s) without a usable EUI-64 address skipped)" % skipped)

    chosen = choose(receivers, args)
    if not chosen:
        print("\n[*] nothing selected; %s not written" % args.out)
        return 0

    try:
        with open(args.out, "w") as fh:
            for r in chosen:
                fh.write(hp.mac_str(r["mac"]) + "\n")
    except OSError as exc:
        sys.exit("error: could not write %s: %s" % (args.out, exc))

    print("\n[*] wrote %d MAC(s) to %s:" % (len(chosen), args.out))
    for r in chosen:
        print("      %s  (%s)" % (hp.mac_str(r["mac"]),
                                  r["name"] or r["instance"].split(".")[0]))
    print("[*] now switch this card to monitor mode and run:")
    print("      sudo ./awdl_master_inject.py -i %s --targets-file %s \\"
          % (args.interface, args.out))
    print("           --channels 6,6,44,149 --channel-dwell 300ms --interval 110tu")
    return 0


if __name__ == "__main__":
    sys.exit(main())
