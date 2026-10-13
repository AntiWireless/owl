#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit + integration tests for airdrop_target.py (stdlib unittest, no radio).

Run:  python3 -m unittest tools.test_airdrop_target   (from the repo root)
  or:  python3 tools/test_airdrop_target.py
"""
import gzip
import http.client
import io
import os
import plistlib
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import awdl_master_inject as awdl
import airdrop_target as at


class TestEui64(unittest.TestCase):
    # The worked example from the research: MAC <-> awdl0 link-local.
    MAC = "66:aa:30:33:93:af"
    LL = "fe80::64aa:30ff:fe33:93af"

    def test_reverse_known(self):
        self.assertEqual(awdl.mac_str(at.ll_to_mac(self.LL)), self.MAC)

    def test_forward_known(self):
        self.assertEqual(at.mac_to_ll(awdl.parse_mac(self.MAC)), self.LL)

    def test_roundtrip_random(self):
        for _ in range(200):
            mac = awdl.random_local_mac()
            self.assertEqual(at.ll_to_mac(at.mac_to_ll(mac)), mac)

    def test_strips_scope(self):
        self.assertEqual(awdl.mac_str(at.ll_to_mac(self.LL + "%awdl0")), self.MAC)

    def test_ul_bit_flipped(self):
        # A locally-administered MAC (0x02 set) -> IID first byte clears it.
        self.assertTrue(at.mac_to_ll(awdl.parse_mac(self.MAC)).startswith("fe80::64"))

    def test_rejects_non_eui64(self):
        # Loopback / an RFC 4941-style IID has no ff:fe marker.
        with self.assertRaises(ValueError):
            at.ll_to_mac("fe80::1")
        with self.assertRaises(ValueError):
            at.ll_to_mac("::1")


class TestNeighParse(unittest.TestCase):
    def test_dev_filtered(self):
        out = ("fe80::64aa:30ff:fe33:93af lladdr 66:aa:30:33:93:af PERMANENT\n"
               "fe80::1 lladdr aa:bb:cc:dd:ee:ff STALE\n"
               "fe80::dead INCOMPLETE\n")        # no lladdr -> skipped
        t = at.parse_neigh_output(out)
        self.assertEqual(t["fe80::64aa:30ff:fe33:93af"], "66:aa:30:33:93:af")
        self.assertEqual(t["fe80::1"], "aa:bb:cc:dd:ee:ff")
        self.assertNotIn("fe80::dead", t)

    def test_full_line_with_dev(self):
        out = "fe80::64aa:30ff:fe33:93af dev awdl0 lladdr 66:AA:30:33:93:AF REACHABLE\n"
        t = at.parse_neigh_output(out)
        self.assertEqual(t["fe80::64aa:30ff:fe33:93af"], "66:aa:30:33:93:af")


class TestResolvePeerMac(unittest.TestCase):
    def test_eui64_fallback(self):
        # No `ip` neighbor hit available in this sandbox -> EUI-64 fallback.
        mac = at.resolve_peer_mac("fe80::64aa:30ff:fe33:93af", "awdl0")
        self.assertEqual(awdl.mac_str(mac), "66:aa:30:33:93:af")

    def test_unresolvable(self):
        self.assertIsNone(at.resolve_peer_mac("fe80::1", "awdl0"))


class TestIfInet6(unittest.TestCase):
    def test_prefers_linklocal(self):
        # format: <32hex> <ifidx> <plen> <scope> <flags> <ifname>
        ll = "fe8000000000000064aa30fffe3393af"
        gl = "20010db8000000000000000000000001"
        lines = [
            "%s 05 40 20 80 awdl0" % gl,      # global first
            "%s 05 40 20 80 awdl0" % ll,      # link-local -> preferred
            "%s 02 40 20 80 wlan0" % ll,
        ]
        self.assertEqual(at._select_linklocal(lines, "awdl0"),
                         "fe80::64aa:30ff:fe33:93af")

    def test_missing_iface(self):
        self.assertIsNone(at._select_linklocal([], "awdl0"))


class TestIdentityPlist(unittest.TestCase):
    def test_parse_ask(self):
        body = plistlib.dumps({
            "SenderID": "a1b2c3d4e5f6",
            "SenderComputerName": "Ben's iPhone",
            "SenderModelName": "iPhone13,2",
            "BundleID": "com.apple.finder",
            "Files": [{"FileName": "IMG_0001.jpg", "FileType": "public.jpeg"},
                      {"FileName": "note.txt"}],
        }, fmt=plistlib.FMT_BINARY)
        out = at.parse_identity_plist(body)
        self.assertEqual(out["sender_id"], "a1b2c3d4e5f6")
        self.assertEqual(out["computer_name"], "Ben's iPhone")
        self.assertEqual(out["model"], "iPhone13,2")
        self.assertEqual(out["files"], ["IMG_0001.jpg", "note.txt"])

    def test_garbage(self):
        self.assertEqual(at.parse_identity_plist(b"not a plist"), {})
        self.assertEqual(at.parse_identity_plist(b""), {})


def _make_newc_cpio(files):
    """Build a minimal 'newc' cpio archive (what AirDrop uploads use)."""
    out = io.BytesIO()

    def entry(name, data, mode):
        namebytes = name.encode() + b"\x00"
        hdr = b"070701"
        fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(namebytes), 0]
        hdr += b"".join(b"%08X" % f for f in fields)
        out.write(hdr)
        out.write(namebytes)
        out.write(b"\x00" * ((-(110 + len(namebytes))) % 4))
        out.write(data)
        out.write(b"\x00" * ((-len(data)) % 4))

    for name, data in files:
        entry(name, data, 0o100644)
    entry("TRAILER!!!", b"", 0)
    return out.getvalue()


class TestCpioExtract(unittest.TestCase):
    def test_extract(self):
        archive = _make_newc_cpio([("hello.txt", b"hi there"),
                                   ("sub/x.bin", b"\x00\x01\x02")])
        with tempfile.TemporaryDirectory() as d:
            names = at._extract_cpio_newc(archive, d)
            self.assertIn("hello.txt", names)
            self.assertIn(os.path.join("sub", "x.bin"), names)
            with open(os.path.join(d, "hello.txt"), "rb") as fh:
                self.assertEqual(fh.read(), b"hi there")

    def test_non_newc_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(at._extract_cpio_newc(b"random", d), [])

    def test_save_upload_gzip(self):
        archive = _make_newc_cpio([("a.txt", b"content A")])
        gzipped = gzip.compress(archive)
        with tempfile.TemporaryDirectory() as d:
            at._save_upload(gzipped, d)
            self.assertTrue(os.path.exists(os.path.join(d, "a.txt")))


class TestChunkedReader(unittest.TestCase):
    def test_read_chunked(self):
        payload = b"abcdefghij" * 100          # 1000 bytes
        # encode as two HTTP/1.1 chunks + terminator
        c1, c2 = payload[:600], payload[600:]
        wire = (b"%X\r\n" % len(c1) + c1 + b"\r\n"
                + b"%X\r\n" % len(c2) + c2 + b"\r\n"
                + b"0\r\n\r\n")
        self.assertEqual(at._read_chunked_body(io.BytesIO(wire)), payload)

    def test_read_chunked_with_extension(self):
        wire = b"4;foo=bar\r\nabcd\r\n0\r\n\r\n"
        self.assertEqual(at._read_chunked_body(io.BytesIO(wire)), b"abcd")


def _new_store():
    src = awdl.parse_mac("de:ad:be:ef:00:01")
    store = awdl.ParamStore(
        targets=[], source=src, channel=6,
        master_metric=awdl.UINT32_MAX, master_counter=awdl.MASTER_COUNTER_BASE,
        self_metric=awdl.UINT32_MAX, self_counter=awdl.MASTER_COUNTER_BASE,
        awdl_version=0xa0, hostname="owl-master",
        devclass=awdl.DEVCLASS_NAMES["macos"], aw_offset=0)
    return store


class _FakeObserver:
    def __init__(self, name):
        self._name = name

    def name_for(self, mac, wait=0.0):
        return self._name


class TestCaptureBridge(unittest.TestCase):
    LL = "fe80::64aa:30ff:fe33:93af"
    MAC = "66:aa:30:33:93:af"

    def test_mac_only_pins_fixed(self):
        store = _new_store()
        tracker = awdl.HostnameTracker(store, fixed=[], names=[])
        bridge = at.CaptureBridge(store, tracker, observer=None,
                                  awdl_iface="awdl0", inject=True)
        ident = bridge.on_request(self.LL, 0, "ask",
                                  plistlib.dumps({"SenderID": "x"},
                                                 fmt=plistlib.FMT_BINARY))
        self.assertEqual(ident.mac_str, self.MAC)
        self.assertEqual([awdl.mac_str(m) for m in store.get("targets")],
                         [self.MAC])

    def test_uuid_tracks_name(self):
        store = _new_store()
        tracker = awdl.HostnameTracker(store, fixed=[], names=[])
        obs = _FakeObserver("af98f343-bad6-4904-a36b-09c15adb795f")
        bridge = at.CaptureBridge(store, tracker, observer=obs,
                                  awdl_iface="awdl0", inject=True)
        ident = bridge.on_request(self.LL, 0, "ask", None)
        self.assertEqual(ident.uuid, "af98f343-bad6-4904-a36b-09c15adb795f")
        self.assertEqual([awdl.mac_str(m) for m in store.get("targets")],
                         [self.MAC])
        # Rotation: same UUID on a new MAC -> targets follow it.
        new_ll = at.mac_to_ll(awdl.parse_mac("11:22:33:44:55:66"))
        tracker.observe(awdl.parse_mac("11:22:33:44:55:66"),
                        "af98f343-bad6-4904-a36b-09c15adb795f")
        self.assertEqual([awdl.mac_str(m) for m in store.get("targets")],
                         ["11:22:33:44:55:66"])

    def test_dedup_window(self):
        store = _new_store()
        tracker = awdl.HostnameTracker(store, fixed=[], names=[])
        calls = []
        bridge = at.CaptureBridge(store, tracker, observer=None,
                                  awdl_iface="awdl0", inject=True,
                                  on_capture=lambda ident: calls.append(ident))
        body = plistlib.dumps({"SenderID": "x"}, fmt=plistlib.FMT_BINARY)
        bridge.on_request(self.LL, 0, "ask", body)
        bridge.on_request(self.LL, 0, "ask", body)   # within window -> deduped
        self.assertEqual(len(calls), 1)

    def test_unresolvable_mac_no_target(self):
        store = _new_store()
        tracker = awdl.HostnameTracker(store, fixed=[], names=[])
        bridge = at.CaptureBridge(store, tracker, observer=None,
                                  awdl_iface="awdl0", inject=True)
        ident = bridge.on_request("fe80::1", 0, "ask", None)
        self.assertIsNone(ident)
        self.assertEqual(store.get("targets"), [])

    def test_no_inject_prints_command(self):
        store = _new_store()
        tracker = awdl.HostnameTracker(store, fixed=[], names=[])
        bridge = at.CaptureBridge(store, tracker, observer=None,
                                  awdl_iface="awdl0", inject=False,
                                  monitor_iface="wlan0")
        ident = bridge.on_request(self.LL, 0, "ask", None)
        # capture-only must NOT touch targets, but must produce a command
        self.assertEqual(store.get("targets"), [])
        self.assertIn(self.MAC, bridge.injector_command(ident))


class TestCert(unittest.TestCase):
    def test_generate_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = at.ensure_selfsigned_cert(d, "TestBox")
            self.assertTrue(os.path.exists(cert) and os.path.exists(key))
            ctx = at.airdrop_ssl_context(cert, key)
            self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
            # idempotent: second call reuses the same files
            cert2, key2 = at.ensure_selfsigned_cert(d, "TestBox")
            self.assertEqual((cert, key), (cert2, key2))


class TestBuiltinServerIntegration(unittest.TestCase):
    """Drive the real TLS receiver over loopback and verify routing/parsing and
    that the capture hook fires with the right kind + body."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cert, key = at.ensure_selfsigned_cert(self.tmp.name, "TestBox")
        ctx = at.airdrop_ssl_context(cert, key)

        self.captured = []

        class RecordingBridge:
            def on_request(_self, peer_ip, scope_id, kind, body):
                self.captured.append((kind, body))
                return None

        self.download = tempfile.mkdtemp()
        at.AirDropHandler.bridge = RecordingBridge()
        at.AirDropHandler.receiver_name = "TestBox"
        at.AirDropHandler.receiver_model = "OpenDrop"
        at.AirDropHandler.trigger = "both"
        at.AirDropHandler.download_dir = self.download
        at.AirDropHandler.decline = False

        self.server = at.AirDropHTTPServer(("::1", 0), at.AirDropHandler, ctx)
        self.port = self.server.server_address[1]
        self.t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.t.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _conn(self):
        cctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection("::1", self.port, context=cctx,
                                           timeout=5)

    def test_get_root(self):
        c = self._conn()
        c.request("GET", "/")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.read(), b"\n")
        c.close()

    def test_discover_response(self):
        c = self._conn()
        c.request("POST", "/Discover", body=plistlib.dumps({}, fmt=plistlib.FMT_BINARY))
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        resp = plistlib.loads(r.read())
        self.assertEqual(resp["ReceiverComputerName"], "TestBox")
        self.assertIn("ReceiverMediaCapabilities", resp)
        c.close()
        self.assertIn("discover", [k for k, _ in self.captured])

    def test_ask_capture_and_accept(self):
        c = self._conn()
        body = plistlib.dumps({"SenderID": "abc", "SenderComputerName": "iPhone"},
                              fmt=plistlib.FMT_BINARY)
        c.request("POST", "/Ask", body=body)
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        resp = plistlib.loads(r.read())
        self.assertEqual(resp["ReceiverComputerName"], "TestBox")
        c.close()
        kinds = [k for k, _ in self.captured]
        self.assertIn("ask", kinds)
        ask_body = dict(self.captured)["ask"]
        self.assertEqual(plistlib.loads(ask_body)["SenderID"], "abc")

    def test_upload_saves_file(self):
        # Send with an explicit Content-Length (the _read_chunked_body path is
        # covered by TestChunkedReader; here we exercise the end-to-end save).
        archive = gzip.compress(_make_newc_cpio([("up.txt", b"uploaded!")]))
        c = self._conn()
        c.request("POST", "/Upload", body=archive,
                  headers={"Content-Type": "application/x-cpio"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        c.close()
        self.assertTrue(os.path.exists(os.path.join(self.download, "up.txt")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
