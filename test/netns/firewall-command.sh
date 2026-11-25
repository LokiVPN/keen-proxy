#!/bin/sh
# Installed under both command names in the disposable NDM fixture directory.
# Run real kernel operations and simulate a table rewrite at named boundaries.
set -eu

state=${0%/*}
iptables=/usr/sbin/iptables
restore=/usr/sbin/iptables-restore

case ${0##*/} in
iptables)
	if [ -f "$state/released" ] && [ ! -f "$state/first-probe" ]; then
		printf '%s\n' "$*" >"$state/first-probe"
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
	if [ ! -f "$state/lose-on-release" ] && [ ! -f "$state/released" ]; then
		exec "$restore" "$@"
	fi
	rules=$(mktemp "$state/restore.XXXXXX")
	trap 'rm -f "$rules"' 0
	cat >"$rules"
	read -r table <"$rules"
	if [ "$table" = '*filter' ] && [ -f "$state/lose-on-release" ] && ! grep -q -- ' -j DROP$' "$rules"; then
		"$iptables" -w -t nat -D PREROUTING -j KEENPROXY_DNS
		"$restore" "$@" <"$rules"
		mv "$state/lose-on-release" "$state/released"
		exit 0
	fi
	"$restore" "$@" <"$rules"
	if [ "$table" = '*filter' ] && [ -f "$state/released" ] && grep -q -- ' -j DROP$' "$rules"; then
		# Hold only after the re-arm commits, so DNS probes see the real guard.
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
