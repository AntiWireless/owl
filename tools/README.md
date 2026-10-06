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

### Preparing the Wi-Fi stick

`awdl_prepare_stick.sh` gets a card ready for injection. It forces a **clean,
plain monitor interface** — recreating the interface to drop any stale
*active* monitor flag, which is the root cause of the peer-instability seen on
USB adapters such as the `mt76x0u` — and sets a **regulatory domain** that
permits the 5 GHz AWDL channels (44/149):

```sh
sudo ./awdl_prepare_stick.sh wlan0 44        # <iface> [channel] [regdomain]
```

The injector can do this for you with `--setup` (optionally `--regdomain CC`),
so a one-liner prepares the card and injects:

```sh
sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66 -c 44 --setup
```

### Usage

```sh
# 1. prepare the card (clean plain monitor + regulatory domain)
sudo ./awdl_prepare_stick.sh wlan0

# 2. inject MIFs at a specific target MAC; the channel is detected automatically
sudo ./awdl_master_inject.py -i wlan0 -t 11:22:33:44:55:66
```

With no `-c`, the tool sweeps the three AWDL social channels (6, 44, 149),
counts AWDL frames coming *from the target MAC* on each, tunes the card to the
one with the most, and injects there. Pass `-c` to skip detection and force a
channel.

**Multiple targets:** give several destination MACs — comma-separated, by
repeating `-t`, or both — and one frame is sent to each per cycle:

```sh
sudo ./awdl_master_inject.py -i wlan0 -c 6 \
     -t 66:aa:30:33:93:af,66:aa:30:33:93:b0 -t 11:22:33:44:55:66
```

(When detecting the channel, the sweep counts frames from *any* of the
targets.)

Useful options:

| option | meaning |
| --- | --- |
| `-t, --target` | destination MAC(s) the frames are directed at — comma-separated and/or repeatable (required unless `--track`) |
| `--track` | AWDL hostname(s) to follow; resolved to the current MAC by sniffing, re-targeted automatically as it rotates |
| `-s, --source` | master identity to advertise (default: interface MAC) |
| `-c, --channel` | AWDL social channel 6/44/149 (default: auto-detect by sweep) |
| `--sweep-dwell` | seconds to listen per channel while detecting (default: 3.0) |
| `--metric` | election master metric (default: `0xffffffff`) |
| `--counter` | starting election master counter (default: `0x40000000`) |
| `--counter-interval` | how often the counter is advanced (default: `3.14s`, a real master's rate; `0` = every frame) |
| `--count` | number of frames to send (`0` = until Ctrl-C) |
| `--psf` | also interleave PSF frames |
| `--watch` | inject *and* listen on the same card; report each peer's master (and hostname) |
| `--setup` | prepare the stick first (clean plain monitor + regulatory domain) |
| `--regdomain` | ISO country code applied by `--setup` (default: `US`) |
| `--dry-run` | build and hex-dump one frame without injecting |

### Following a device across MAC rotation (`--track`)

Apple devices rotate their Wi-Fi / AWDL MAC, so a MAC you pass to `-t` goes
stale and you'd have to keep looking it up. Each device also broadcasts an
**AWDL name** in its MIFs (the Arpa TLV), which `--track` follows, resolving it
to the device's current MAC and re-targeting automatically as the MAC rotates:

```sh
sudo ./awdl_master_inject.py -i wlan0 -c 6 --track "Peters-iPad"
```

**What that name is matters.** On older devices it's the readable hostname
(`Peters-iPad`). On modern iOS/iPadOS it's **randomised to a UUID** (e.g.
`af98f343-bad6-4904-a36b-09c15adb795f`) for privacy — AWDL deliberately carries
no clear-text device name there. Run `--watch` first to read whatever your
target advertises, then pass that exact value to `--track`.

Tracking only works **while that name stays constant across MAC rotations**.
Use `--watch` to check: if you see the *same* name reappear on changing MACs,
it's a stable handle and `--track` will follow it; if the name itself changes
every time the MAC does, the device is rotating its identity too and nothing
can follow it. Notes:

* Matching is case-insensitive. Give several names comma-separated and/or by
  repeating `--track`, and combine freely with fixed `-t` MACs.
* Until a tracked device is first heard, nothing is injected for it; a
  `[track] <name> -> <mac>` line is printed on first resolve and on each
  rotation (`[track] <name> rotated <old> -> <new>`).
* The device must be actively sending AWDL (keep an AWDL feature in use).

### Covering a channel-hopping target (`--channels`)

Apple devices hop across the social channels (6, 44, 149). With one radio you
can't be on all of them at once, so a device parked on 44 stops hearing your
master and, after ~10 s without a fresh counter, briefly re-elects itself
(you'll see its `self_counter` tick up in `--watch`) before re-adopting you.

Mitigations, in order of effort:

* **Stay on its busiest channel.** Run the sweep (no `-c`) to see where the
  target spends most frames, then pin there with `-c`.
* **Rotate fast across the channels it uses.** A *short* dwell visits every
  channel several times inside the ~10 s staleness window — unlike a long
  dwell, which leaves each channel uncovered for too long:

  ```sh
  sudo ./awdl_master_inject.py -i wlan0 --channels 6,44,149 \
       --channel-dwell 300ms --interval 110tu -t <mac>
  ```

* **Weight the rotation** toward the busiest channel by listing it more than
  once — `--channels 6,6,44,149` spends half the dwell on 6.

Hopping relies on `iw`, which the driver sometimes rejects while busy; the
tool retries each tune and, if hops keep failing, prints a count at the end
(shorten the channel list or raise `--channel-dwell` if that happens a lot).
A single radio can't fully close the gap for a target that spends long
stretches off your channel — that needs a second card (one per channel).

### Verifying with a single card (`--watch`)

Monitor mode keeps receiving while you inject, so one card can both send the
master frames and watch the result. With `--watch` the tool listens on the
same interface and prints, once a second, which master every AWDL peer in
range currently advertises — plus the peer's **hostname** when it advertises
one — so you can see whether the target adopted you, and discover a device's
name to pass to `--track`, without a second radio or `tshark`:

```sh
sudo ./awdl_master_inject.py -i wlan0 -t 66:aa:30:33:93:af -c 6 \
     -s 00:c0:ca:bd:09:8a --interval 110tu --watch
```

```
[watch] 66:aa:30:33:93:af (Peters-iPad) -> master 00:c0:ca:bd:09:8a (self_counter=1902)  <== ADOPTED YOU
```

When the target's advertised master flips to your `-s` address, it has
adopted you as the AWDL master. Notes:

* Real AWDL masters broadcast their MIFs, so against a genuine (e.g. Apple)
  device use `-t ff:ff:ff:ff:ff:ff` — many implementations only run the
  election on broadcast MIFs.
* Peers hop across 6/44/149, so a target pinned-watched on one channel only
  shows up intermittently. Apple devices also keep AWDL dormant unless an
  AWDL feature is active, so keep one in use on the target while testing.

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

### Integrating with other code (`ParamStore`)

The injection loop reads **every live parameter from a `ParamStore` (a
thread-safe "Zwischenspeicher") before building each frame**, so you can drive
it from your own code by mutating that store — the next injected frame picks
the new values up. No restart, no CLI.

The store holds `targets` (a **list** of destination MACs), `source`,
`channel`, `master_metric`, `master_counter`, `self_metric`, `self_counter`,
`awdl_version`, `hostname`, `devclass` and `aw_offset`. One frame is sent to
each MAC in `targets` per cycle. Call `run_injection(sock, store, builder,
iface, ...)` (optionally in a thread, with a `threading.Event` to stop it):

```python
import threading, awdl_master_inject as awdl

store = awdl.ParamStore(
    targets=[awdl.parse_mac("ff:ff:ff:ff:ff:ff")],
    source=awdl.parse_mac("de:ad:be:ef:00:01"),
    channel=6,
    master_metric=awdl.UINT32_MAX, master_counter=awdl.MASTER_COUNTER_BASE,
    self_metric=awdl.UINT32_MAX,   self_counter=awdl.MASTER_COUNTER_BASE,
    awdl_version=0xa0, hostname="owl-master",
    devclass=awdl.DEVCLASS_NAMES["macos"], aw_offset=0)

sock = awdl.open_injection_socket("wlan0")
builder = awdl.AwdlFrameBuilder(
    src=store.get("source"), dst=store.get("targets")[0], channel=6,
    master_metric=awdl.UINT32_MAX, master_counter=awdl.MASTER_COUNTER_BASE,
    self_metric=awdl.UINT32_MAX,   self_counter=awdl.MASTER_COUNTER_BASE,
    hostname="owl-master", devclass=awdl.DEVCLASS_NAMES["macos"])

stop = threading.Event()
threading.Thread(target=awdl.run_injection,
                 args=(sock, store, builder, "wlan0"),
                 kwargs=dict(interval=0.11, stop=stop)).start()

# from your own code, at any time:
store.update(targets=[awdl.parse_mac("66:aa:30:33:93:af"),   # live target list
                      awdl.parse_mac("66:aa:30:33:93:b0")])
store.update(source=awdl.parse_mac("de:ad:be:ef:00:02"))     # live identity change

stop.set()            # end the loop
sock.close()
```

The election counter advances automatically on a timer (`counter_interval`,
default 3.14 s — the rate a genuine AWDL master increments its `self_counter`,
per `src/frame.h`). That keeps the master live without looking anomalous;
advancing it *per frame* makes the victim treat every frame as a new master
generation and re-elect constantly. Write `master_counter` through
`store.update(...)` only if you want to override it. In single-channel mode a
changed `channel` re-tunes the radio on the next cycle; with `rotate_channels`
the rotation owns the channel.

To follow devices by hostname from your own code, build a `HostnameTracker`
and pass it to `run_injection(..., tracker=tracker)`; it keeps the store's
`targets` in sync as MACs rotate:

```python
tracker = awdl.HostnameTracker(store, fixed=[], names=["Peters-iPad"])
# ... run_injection(sock, store, builder, "wlan0", tracker=tracker, stop=stop)
# store.get("targets") now tracks Peters-iPad's current MAC automatically
```

### ⚠️ Authorised use only

AWDL is always on on Apple devices, and forcing a foreign master disrupts the
synchronisation of every node in radio range. Run this **only** against
devices you own or are explicitly authorised to test, in an isolated RF lab.
This reproduces the election-manipulation behaviour studied by the OWL authors
in *"A Billion Open Interfaces for Eve and Mallory"* (USENIX Security '19).
Like the rest of OWL, it is experimental software — use it at your own risk.
