# OWL tools

Companion scripts for experimenting with and testing the OWL AWDL stack.

## `awdl_master_inject.py`

Crafts and injects AWDL **Master Indication Frames (MIF)** that are
guaranteed to win the AWDL election, directed at one specific destination MAC
address. It is a pure-stdlib Python 3 reimplementation of the frame layout
produced by `src/tx.c`.

### How it guarantees becoming master

AWDL elects a master by comparing, per `src/election.c`
(`awdl_election_compare_master`):

1. the **master counter** (higher wins), then
2. the **master metric** (higher wins).

The script advertises an **Election Parameters v2 TLV** (type 24) with both
the counter and the metric set to `0xFFFFFFFF` and a distance-to-master of 0
(i.e. it claims to *be* the top master). A genuine node starts its counter at
0 and increments it only once every ~3.14 s, so it can never out-vote a
`0xFFFFFFFF` advertisement — the injected node wins and stays the master /
sync root the target synchronises to.

To be accepted as a *valid* peer at all (`awdl_peer_is_valid` in
`src/peers.c` requires `sent_mif && devclass && version`), every frame is a
MIF and carries a Version TLV with a non-zero version and device class.

The frames also include the full set of TLVs a real MIF carries (sync
parameters, channel sequence, service parameters, HT capabilities, Arpa /
hostname, data-path state) so they parse cleanly in OWL and on genuine Apple
implementations.

### Requirements

* Linux, Python 3.6+, **root**
* a Wi-Fi card in **monitor mode**
* `iw` (used for channel detection and tuning; only needed if you let the tool
  pick the channel)

No third-party Python modules are needed (raw `AF_PACKET` injection).

### Usage

```sh
# 1. put the card into monitor mode (channel is auto-detected below)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# 2. inject MIFs at a specific target MAC; the channel is detected automatically
sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66
```

With no `-c`, the tool sweeps the three AWDL social channels (6, 44, 149),
counts AWDL frames coming *from the target MAC* on each, tunes the card to the
one with the most, and injects there. Pass `-c` to skip detection and force a
channel.

Useful options:

| option | meaning |
| --- | --- |
| `-t, --target` | destination MAC the frames are directed at (required) |
| `-s, --source` | master identity to advertise (default: interface MAC) |
| `-c, --channel` | AWDL social channel 6/44/149 (default: auto-detect by sweep) |
| `--sweep-dwell` | seconds to listen per channel while detecting (default: 3.0) |
| `--counter` / `--metric` | election counter / metric (default: `0xffffffff`) |
| `--count` | number of frames to send (`0` = until Ctrl-C) |
| `--psf` | also interleave PSF frames |
| `--dry-run` | build and hex-dump one frame without injecting |

### Timing

The send cadence and the AWDL timing parameters advertised in the Sync
Parameters TLV are configurable. Durations accept an `s`/`ms`/`us`/`tu`
suffix (`1 TU = 1024 µs`), e.g. `0.5`, `500ms`, `110tu`.

| option | meaning |
| --- | --- |
| `--interval` | time between send cycles (default: 1.0 s; `0` = send once) |
| `--duration` | stop after this much time (default: `0` = until `--count`/Ctrl-C) |
| `--aw-period` | advertised Availability Window period in TU (default: 16) |
| `--af-period` | advertised action-frame / PSF period in TU (default: 110) |
| `--presence-mode` | advertised presence mode / EAW multiplier (default: 4) |
| `--aw-offset` | availability-window phase offset in TU, may be negative (default: 0) |

A genuine AWDL master announces action frames about every 110 TU
(≈ 112 ms), so for realistic, hard-to-lose timing match the send cadence to
it, e.g. `--interval 110tu`. Note that `--presence-mode` values other than
`4` change the channel-sequence `step_count` and will be rejected by OWL
peers (which expect a presence mode of 4).

`--aw-offset` shifts the phase of the advertised availability-window
schedule. Once the injected node is a peer's master, the peer reads our
`time_to_next_aw` and `aw_counter` from the Sync Parameters TLV and re-aligns
its own clock to them (`awdl_handle_sync_params_tlv` in `src/rx.c`), so the
offset moves the AW phase every synchronised peer adopts. The countdown to
the next AW and the AW sequence counter are shifted together, so `1` AW worth
of offset (`--aw-period` TU, 16 by default) advances the sequence counter by
one. Use it to steer — or deliberately desynchronise — a target's
availability windows.

Inspect a frame without touching the radio:

```sh
./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66 -c 44 --dry-run
```

### ⚠️ Authorised use only

AWDL is always on on Apple devices, and forcing a foreign master disrupts the
synchronisation of every node in radio range. Run this **only** against
devices you own or are explicitly authorised to test, in an isolated RF lab.
This reproduces the election-manipulation behaviour studied by the OWL authors
in *"A Billion Open Interfaces for Eve and Mallory"* (USENIX Security '19).
Like the rest of OWL, it is experimental software — use it at your own risk.
