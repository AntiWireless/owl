#!/bin/sh
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
#
# Prepare a Wi-Fi stick for awdl_master_inject.py.
#
# It forces a CLEAN, PLAIN monitor interface: recreating the interface drops
# any stale "active" monitor flag (NL80211_MNTR_FLAG_ACTIVE) left behind by a
# previous run, which is the root cause of the peer-instability seen on USB
# adapters such as the mt76x0u. It also sets a regulatory domain that permits
# the 5 GHz AWDL social channels (44/149), and optionally tunes to a channel.
#
# Usage: sudo ./awdl_prepare_stick.sh <iface> [channel] [regdomain]
#   <iface>      monitor-capable Wi-Fi interface, e.g. wlan0 or wlx00c0ca...
#   [channel]    optional AWDL social channel to tune to (6, 44 or 149)
#   [regdomain]  optional ISO country code for `iw reg set` (default: US)
#
# The injector (awdl_master_inject.py --setup) runs this script for you, but it
# can also be used stand-alone or from your own integration code.

set -u

PROG=$(basename "$0")

die() { echo "$PROG: error: $*" >&2; exit 1; }
note() { echo "$PROG: $*"; }

IFACE=${1:-}
CHANNEL=${2:-}
REGDOM=${3:-US}

[ -n "$IFACE" ] || die "usage: sudo $PROG <iface> [channel] [regdomain]"
[ "$(id -u)" = 0 ] || die "must run as root (use sudo)"
command -v iw >/dev/null 2>&1 || die "'iw' not found (install the 'iw' package)"
command -v ip >/dev/null 2>&1 || die "'ip' not found (install 'iproute2')"
[ -d "/sys/class/net/$IFACE" ] || die "no such interface: $IFACE"

if [ -n "$CHANNEL" ]; then
	case "$CHANNEL" in
		6|44|149) ;;
		*) die "unsupported channel '$CHANNEL' (use 6, 44 or 149)" ;;
	esac
fi

# Stop NetworkManager / wpa_supplicant from managing the device. Their periodic
# scans keep the radio busy, which makes `iw ... set channel` fail with EBUSY
# ("Device or resource busy", -16). Releasing the interface is reversible:
# re-manage later with `nmcli dev set <iface> managed yes`.
if command -v nmcli >/dev/null 2>&1; then
	note "releasing $IFACE from NetworkManager (set unmanaged)"
	nmcli dev disconnect "$IFACE" 2>/dev/null || true
	nmcli dev set "$IFACE" managed no 2>/dev/null \
		|| note "warning: could not set $IFACE unmanaged in NetworkManager"
fi
if command -v wpa_cli >/dev/null 2>&1; then
	# Detach any wpa_supplicant instance bound to this interface (best effort).
	wpa_cli -i "$IFACE" terminate >/dev/null 2>&1 || true
fi

# Regulatory domain: the 5 GHz AWDL channels (44/149) are blocked under the
# default 'world' domain on many adapters.
note "setting regulatory domain to $REGDOM"
iw reg set "$REGDOM" 2>/dev/null \
	|| note "warning: could not set regulatory domain to $REGDOM"

PHY=$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/ {print "phy"$2; exit}')

note "bringing $IFACE down"
ip link set "$IFACE" down || die "could not bring $IFACE down"

# Force a clean, plain monitor interface by recreating it. This is the proven
# fix for the stale 'active' monitor flag that destabilises mt76x0u adapters.
recreated=0
if [ -n "$PHY" ]; then
	if iw dev "$IFACE" del 2>/dev/null; then
		if iw phy "$PHY" interface add "$IFACE" type monitor 2>/dev/null; then
			recreated=1
		else
			# Re-add failed once: wait for the driver to settle and retry,
			# then give up with a clear recovery hint.
			sleep 1
			if iw phy "$PHY" interface add "$IFACE" type monitor 2>/dev/null; then
				recreated=1
			else
				die "deleted $IFACE but could not re-create it; re-plug the" \
				    "adapter or run: iw phy $PHY interface add $IFACE type monitor"
			fi
		fi
	fi
fi

if [ "$recreated" -eq 1 ]; then
	note "recreated $IFACE as a plain monitor interface on $PHY"
else
	# Fallback (no phy resolved, or delete refused): flip the type in place.
	# Setting the type to monitor without flags also clears the active flag.
	note "setting $IFACE type to monitor (in place)"
	iw dev "$IFACE" set type monitor 2>/dev/null \
		|| die "could not set $IFACE to monitor mode"
fi

note "bringing $IFACE up"
ip link set "$IFACE" up || die "could not bring $IFACE up"

if [ -n "$CHANNEL" ]; then
	note "tuning $IFACE to channel $CHANNEL"
	# Retry on a transient EBUSY (the radio may settle a moment after bring-up).
	tuned=0
	i=0
	while [ "$i" -lt 5 ]; do
		if iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null; then
			tuned=1
			break
		fi
		i=$((i + 1))
		sleep 1
	done
	[ "$tuned" -eq 1 ] \
		|| note "warning: could not set channel $CHANNEL (still busy, or regulatory domain)"
fi

# Verify we really ended up in monitor mode.
TYPE=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/ {print $2; exit}')
[ "$TYPE" = "monitor" ] || die "$IFACE is not in monitor mode (type=$TYPE)"

note "ready: $IFACE is a plain monitor interface${CHANNEL:+ on channel $CHANNEL} (regdom $REGDOM)"
