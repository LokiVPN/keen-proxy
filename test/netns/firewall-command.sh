#!/bin/sh
# Installed under both command names in the disposable NDM fixture directory.
# Run real kernel operations and simulate a table rewrite at named boundaries.
set -eu

state=${0%/*}
iptables=/usr/sbin/iptables
restore=/usr/sbin/iptables-restore

record_release() {
	printf '%s %s\n' "$1" "$(date +%s%N)" >>"$state/release-trace"
}

case ${0##*/} in
iptables)
	if [ -f "$state/released" ] && [ ! -f "$state/first-probe" ]; then
		status=0
		"$iptables" "$@" || status=$?
		printf '%s %s\n' "$status" "$*" >"$state/first-probe"
		record_release first-probe
		exit "$status"
	fi
	if [ -f "$state/rearmed" ]; then
		case " $* " in
			*' -C '*|*' -S '*|*' -L '*) ;;
			*) record_release iptables-write ;;
		esac
	fi
	if [ "$*" = '-w -t nat -I PREROUTING 1 -j KEENPROXY_DNS' ] && [ -f "$state/insert-losses" ]; then
		"$iptables" "$@"
		"$iptables" -w -t filter -S KEENPROXY_DNS_GUARD | grep -q -- ' -j DROP$'
		"$iptables" -w -t nat -D PREROUTING -j KEENPROXY_DNS
		read -r remaining <"$state/insert-losses"
		if [ "$remaining" -gt 1 ]; then
			printf '%s\n' "$((remaining - 1))" >"$state/insert-losses"
		else
			rm "$state/insert-losses"
		fi
		exit 0
	fi
	exec "$iptables" "$@"
	;;
iptables-restore)
	if [ ! -f "$state/lose-on-release" ] && [ ! -f "$state/released" ] && [ ! -f "$state/rearmed" ]; then
		exec "$restore" "$@"
	fi
	rules=$(mktemp "$state/restore.XXXXXX")
	trap 'rm -f "$rules"' 0
	cat >"$rules"
	read -r table <"$rules"
	if [ "$table" = '*filter' ] && [ -f "$state/lose-on-release" ] && ! grep -q -- ' -j DROP$' "$rules"; then
		"$iptables" -w -t nat -D PREROUTING -j KEENPROXY_DNS
		"$restore" "$@" <"$rules"
		record_release filter-commit
		mv "$state/lose-on-release" "$state/released"
		exit 0
	fi
	if [ -f "$state/rearmed" ]; then
		# Check the active guard before replacing it at retry entry and before restoring NAT.
		if ! "$iptables" -w -t filter -S | cmp -s "$state/filter-at-rearm" -; then
			echo 'filter changed between DNS guard re-arm and retry' >&2
			exit 1
		fi
		case "$table" in
		'*filter')
			record_release retry-entry
			grep -q -- ' -j DROP$' "$rules"
			"$restore" "$@" <"$rules"
			record_release retry-protection
			exit 0
			;;
		'*nat')
			record_release retry-nat
			rm "$state/rearmed"
			;;
		*) record_release unexpected-restore ;;
		esac
	fi
	"$restore" "$@" <"$rules"
	if [ "$table" = '*filter' ] && [ -f "$state/released" ] && grep -q -- ' -j DROP$' "$rules"; then
		# Hold only after the re-arm commits, so DNS probes see the real guard.
		record_release rearm-commit
		"$iptables" -w -t filter -S >"$state/filter-at-rearm"
		mv "$state/released" "$state/rearmed"
		for _ in $(seq 1 80); do
			[ ! -f "$state/resume" ] || exit 0
			sleep 0.1
		done
		echo 'timed out observing re-armed firewall drops' >&2
		exit 1
	fi
	;;
*) exit 2 ;;
esac
