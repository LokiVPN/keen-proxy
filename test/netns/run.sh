#!/bin/sh
# Run real interception tests inside isolated network namespaces.
# make integration supplies /work/keenproxy in a privileged disposable container.
#
#   client (192.168.77.10) --br0-- router (this namespace) --veth-- wan (198.51.100.2)
#
# There is no router NAT. WAN has a return route only for the DNS bypass source;
# successful client HTTP still requires the embedded engine to carry the connection.
set -eu

KEENPROXY=/work/keenproxy
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok   $*"; }

update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
echo 1 >/proc/sys/net/ipv4/ip_forward

# --- Isolated LAN/router/WAN topology
ip netns add client
ip netns add wan
ip link add br0 type bridge && ip addr add 192.168.77.1/24 dev br0 && ip link set br0 up
ip link add veth-c type veth peer name eth0 netns client
ip link set veth-c master br0 up
ip -n client addr add 192.168.77.10/24 dev eth0
ip -n client addr add 192.168.77.11/24 dev eth0 # DNS forwarder source
ip -n client link set eth0 up && ip -n client link set lo up
ip -n client route add default via 192.168.77.1
ip link add veth-w type veth peer name eth0 netns wan
ip addr add 198.51.100.1/24 dev veth-w && ip link set veth-w up
ip -n wan addr add 198.51.100.2/24 dev eth0
ip -n wan addr add 198.51.100.3/24 dev eth0 # ordinary site; .2 hosts DNS and tunnel servers
ip -n wan addr add 198.51.100.4/24 dev eth0 # Steam: reachable directly, but mapped to Finland by GeoIP
ip -n wan addr add 198.51.100.5/24 dev eth0 # DNS fallback: RU, direct without a rule
ip -n wan link set eth0 up && ip -n wan link set lo up
ip -n wan route add 192.168.77.11/32 via 198.51.100.1

# --- Synthetic internet: controlled DNS and HTTP targets
ip netns exec wan dnsmasq -k --no-resolv --no-hosts --listen-address=198.51.100.2,198.51.100.3 --bind-interfaces \
	--local-ttl=5 --address=/fallback.test/198.51.100.5 --address=/example.test/198.51.100.2 --address=/ads.test/198.51.100.2 \
	--address=/provads.test/198.51.100.3 --address=/provdirect.test/198.51.100.4 --log-queries --log-facility=/tmp/dnsmasq.log &
ip netns exec wan python3 -u -m http.server 80 --bind 198.51.100.3 >/tmp/http.log 2>&1 &
ip netns exec wan python3 -u -m http.server 80 --bind 198.51.100.4 >/tmp/steam.log 2>&1 &
ip netns exec wan python3 -u -m http.server 80 --bind 198.51.100.5 >/tmp/fallback-http.log 2>&1 &
# Hidden targets exist only inside the WAN namespace and have no router route.
# Reaching them proves use of the configured tunnel server.
ip -n wan addr add 203.0.113.80/32 dev lo
ip -n wan addr add 203.0.113.81/32 dev lo
ip netns exec wan python3 -u -m http.server 80 --bind 203.0.113.80 >/tmp/hidden.log 2>&1 &
ip netns exec wan python3 -u -m http.server 80 --bind 203.0.113.81 >/tmp/hidden2.log 2>&1 &
cat >/tmp/server.json <<'JSON'
{
  "log": {"level": "info"},
  "inbounds": [
    {"type": "shadowsocks", "listen": "198.51.100.2", "listen_port": 8388, "method": "aes-128-gcm", "password": "test-pass"},
    {"type": "vless", "listen": "198.51.100.2", "listen_port": 8443, "users": [{"uuid": "11111111-2222-3333-4444-555555555555"}]}
  ],
  "outbounds": [{"type": "direct"}]
}
JSON
ip netns exec wan /work/sbserver /tmp/server.json >/tmp/sbserver.log 2>&1 &
# The primary server starts offline to exercise failover before recovery.
cat >/tmp/server-main.json <<'JSON'
{
  "log": {"level": "info"},
  "inbounds": [{"type": "shadowsocks", "listen": "198.51.100.2", "listen_port": 8389, "method": "aes-128-gcm", "password": "test-pass"}],
  "outbounds": [{"type": "direct"}]
}
JSON
sleep 1

# --- Establish the negative control before enabling interception
if ip netns exec client curl -s -m 3 -o /dev/null http://198.51.100.3/; then
	fail "HTTP must fail without keenProxy (no NAT)"
fi
ok "client HTTP fails without keenProxy"

/work/mkgeo /tmp/geo.mmdb 198.51.100.0/24=RU 198.51.100.4/32=FI 203.0.113.0/24=FI
SS="ss://$(printf 'aes-128-gcm:test-pass' | base64 | tr -d '=\n')@198.51.100.2:8388"
SS_MAIN="ss://$(printf 'aes-128-gcm:test-pass' | base64 | tr -d '=\n')@198.51.100.2:8389"
# An HTTPS subscription provider with a Happ routing profile. KeenProxy trusts
# its self-signed certificate through SSL_CERT_FILE.
echo 'vless://11111111-2222-3333-4444-555555555555@198.51.100.2:8443?type=tcp&encryption=none#Provider' >/tmp/provider-nodes.txt
cat >/tmp/provider-profile.json <<'JSON'
{"Name": "Netns", "GlobalProxy": "false", "DirectSites": ["domain:provdirect.test"], "BlockSites": ["domain:provads.test"]}
JSON
ip netns exec wan /work/provider 198.51.100.2:8444 /tmp/provider-ca.pem /tmp/provider-nodes.txt /tmp/provider-profile.json >/tmp/provider.log 2>&1 &
for i in $(seq 1 50); do [ -s /tmp/provider-ca.pem ] && break; sleep 0.1; done
[ -s /tmp/provider-ca.pem ] || { cat /tmp/provider.log; fail "subscription provider did not start"; }
cat >/tmp/config.yaml <<YAML
lan: {interface: br0}
dns: {listen: "0.0.0.0:5354", upstreams: ["udp://198.51.100.2:53"], fallback: "127.0.0.1:53", bypass_sources: ["192.168.77.11"]}
intercept: {mode: redirect}
geoip: {file: /tmp/geo.mmdb}
connections:
  - {id: ss, type: link, link: "$SS"}
  - {id: vless, type: link, link: "vless://11111111-2222-3333-4444-555555555555@198.51.100.2:8443?type=tcp"}
  - {id: main, name: Main, type: link, link: "$SS_MAIN", fallback: vless}
failover: {url: "http://203.0.113.80/", interval: 1, down_after: 2, up_after: 3}
groups:
  - {name: Advertising, target: block, entries: ["ads.test"]}
  - {name: All except Russia, target: ss, countries: [RU], except: true}
  - {name: Via VLESS, target: vless, entries: ["hidden.test"]}
  - {name: Steam direct, target: direct, entries: ["steam.test"]}
  - {name: With fallback, target: main, entries: ["backup.test"]}
networks:
  - {name: LAN, cidr: 192.168.77.0/24, mode: split}
YAML

SSL_CERT_FILE=/tmp/provider-ca.pem $KEENPROXY -config /tmp/config.yaml -rule-sets /tmp/rule-sets -watch 1s \
	-iptables /usr/sbin/iptables -iptables-restore /usr/sbin/iptables-restore >/tmp/keenproxy.log 2>&1 &
KPID=$!
for i in $(seq 1 50); do
	iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null && break
	kill -0 $KPID 2>/dev/null || { cat /tmp/keenproxy.log; fail "keenProxy exited"; }
	sleep 0.2
done
iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null || { cat /tmp/keenproxy.log; fail "interception rules were not installed"; }
ok "keenProxy started with interception rules installed"

# --- Intercept UDP/TCP DNS to any destination and block a selected domain
a=$(ip netns exec client dig +short +time=2 +tries=1 @8.8.8.8 example.test A)
[ "$a" = "198.51.100.2" ] || fail "DNS UDP: '$a'"
ok "UDP DNS intercepted (our frontend answered a query to 8.8.8.8)"
a=$(ip netns exec client dig +tcp +short +time=2 +tries=1 @8.8.8.8 example.test A)
[ "$a" = "198.51.100.2" ] || fail "DNS TCP: '$a'"
ok "TCP DNS intercepted"
a=$(ip netns exec client dig -b 192.168.77.10 +short +time=2 +tries=1 @192.168.77.1 x.ads.test A)
[ "$a" = "0.0.0.0" ] || fail "blocking: '$a'"
ok "blocked domain → 0.0.0.0"
for transport in +notcp +tcp; do
	# .3 is not a tunnel endpoint: the generic TCP redirect would capture this without the source exception.
	name="bypass-${transport#+}.ads.test"
	a=$(ip netns exec client dig "$transport" -b 192.168.77.11 +short +time=2 +tries=1 @198.51.100.3 "$name" A)
	[ "$a" = "198.51.100.2" ] || fail "DNS bypass ($transport): '$a'"
	grep -Fq "query[A] $name from 192.168.77.11" /tmp/dnsmasq.log || fail "DNS bypass ($transport) did not reach WAN directly"
	a=$(ip netns exec client dig "$transport" -b 192.168.77.10 +short +time=2 +tries=1 @198.51.100.3 "$name" A)
	[ "$a" = "0.0.0.0" ] || fail "DNS interception for other clients ($transport): '$a'"
done
ok "DNS bypass permits UDP/TCP port 53 only for the configured source"
r=$(ip netns exec client curl --interface 192.168.77.11 -s -m 5 -o /dev/null -w '%{http_code}' http://198.51.100.3/)
[ "$r" = "200" ] && grep -q '^198.51.100.1 ' /tmp/http.log || fail "DNS bypass must not exempt HTTP"
ok "DNS bypass source still uses TCP application interception"

# --- Prove TCP forwarding through sing-box
ip netns exec client curl -s -m 5 -o /dev/null http://198.51.100.3/ || { cat /tmp/keenproxy.log; fail "HTTP through keenProxy"; }
grep -q '^198.51.100.1 ' /tmp/http.log || fail "server must see the router address: $(cat /tmp/http.log)"
ok "client HTTP passed through sing-box (server sees 198.51.100.1)"

# --- Hidden targets require the tunnel server in the WAN namespace
ip netns exec client curl -s -m 5 -o /dev/null http://203.0.113.80/ || { cat /tmp/keenproxy.log /tmp/sbserver.log; fail "Shadowsocks: restricted site is unavailable"; }
grep -q 'inbound/shadowsocks.*203.0.113.80' /tmp/sbserver.log || { cat /tmp/sbserver.log; fail "connection did not arrive through Shadowsocks"; }
ok "all-except-Russia group routed the restricted site through Shadowsocks"
# Sniffed HTTP Host selects VLESS; address .81 is absent from explicit groups.
ip netns exec client curl -s -m 5 -o /dev/null -H 'Host: hidden.test' http://203.0.113.81/ || { cat /tmp/keenproxy.log /tmp/sbserver.log; fail "domain-based VLESS route"; }
grep -q 'inbound/vless.*203.0.113.81' /tmp/sbserver.log || { cat /tmp/sbserver.log; fail "connection did not arrive through VLESS"; }
ok "explicit domain wins over country: hidden.test used VLESS instead of Shadowsocks"
# Explicit domain routing precedes country rules within a routed policy.
# The same address without a hostname takes the country-selected tunnel.
ip netns exec client curl -s -m 5 -o /dev/null -H 'Host: steam.test' http://198.51.100.4/ || { cat /tmp/keenproxy.log; fail "Steam direct"; }
grep -q '^198.51.100.1 ' /tmp/steam.log || { cat /tmp/steam.log; fail "Steam must connect directly (server sees the router)"; }
ip netns exec client curl -s -m 5 -o /dev/null http://198.51.100.4/ || { cat /tmp/keenproxy.log; fail "Finnish address without a domain"; }
grep -q 'inbound/shadowsocks.*198.51.100.4' /tmp/sbserver.log || { cat /tmp/sbserver.log; fail "Finnish address without a domain must use Shadowsocks"; }
ok "outside-Russia tunnel with Steam direct: steam.test used direct, the same IP without a domain used Shadowsocks"

# --- The live tracker must account for bytes on each selected outbound
TOKEN=$(cat /opt/etc/keenproxy/token 2>/dev/null || true)
STATS=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8086/api/stats)
echo "$STATS" | python3 -c '
import json, sys
s = json.load(sys.stdin)
o = {x["tag"]: x for x in s["outbounds"] or []}
assert o.get("ss", {}).get("down_total", 0) > 0, o.get("ss")
assert o.get("vless", {}).get("down_total", 0) > 0, o.get("vless")
assert o.get("direct", {}).get("down_total", 0) > 0, o.get("direct")
' || { echo "$STATS"; fail "statistics did not count tunnel traffic"; }
HOSTS=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/stats/hosts?tag=vless")
echo "$HOSTS" | grep -q '203.0.113.81\|hidden.test' || { echo "$HOSTS"; fail "host is missing from the VLESS traffic table"; }
ok "statistics API counted ss/vless/direct bytes and listed the VLESS host"

# --- Read process counters after two procfs samples.
for attempt in $(seq 1 12); do
    STATS=$(curl -fsS -m 5 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8086/api/stats)
    if echo "$STATS" | python3 -c '
import json, sys
process = json.load(sys.stdin)["system"].get("process", {})
sys.exit(not (process.get("rss_bytes", 0) > 0 and 0 <= process.get("cpu", -1) <= 100))
'; then
        break
    fi
    [ "$attempt" -lt 12 ] || fail "KeenProxy CPU or RSS is missing from live statistics"
    sleep 1
done
ok "statistics API reported live KeenProxy CPU and RSS"

# --- Verify route explanations, audit events and on-disk journal export
ROUTES=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/journal/routes?limit=200")
echo "$ROUTES" | python3 -c '
import json, sys
e = json.load(sys.stdin)["entries"]
def find(host, out):
    for x in e:
        if x["host"] == host and x["outbound"] == out:
            return x
    raise SystemExit("missing record %s → %s: %s" % (host, out, [(x["host"], x["outbound"], x["rule"]) for x in e]))
assert find("steam.test", "direct")["rule"] == "network «LAN»: group «Steam direct»", find("steam.test", "direct")
assert find("hidden.test", "vless")["rule"] == "network «LAN»: group «Via VLESS»", find("hidden.test", "vless")
ss = find("198.51.100.4", "ss")
assert ss["rule"] == "network «LAN»: group «All except Russia» (all except RU)", ss
assert ss["client"].startswith("192.168.77.10:"), ss
' || { echo "$ROUTES" | head -c 3000; fail "routing journal"; }
AUDIT=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/journal/audit")
echo "$AUDIT" | grep -q 'Start keenProxy' || { echo "$AUDIT"; fail "startup audit record is missing"; }
[ -s /tmp/journal/routes.jsonl ] && [ -s /tmp/journal/audit.jsonl ] || { ls -la /tmp/journal; fail "journals are not written to disk"; }
ok "journal: Steam direct and country routes, startup audit and files"

# --- DNS fallback: a live rule-set reload changes routing.
api_get() { curl -fsS -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/$1"; }
api_post() { curl -fsS -m 10 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:8086/api/$1"; }

# Remove the exception through the configuration endpoint.
api_get config | python3 -c 'import json,sys; c=json.load(sys.stdin); del c["dns"]["bypass_sources"]; print(json.dumps(c))' >/tmp/dns-no-bypass.json
curl -fsS -m 10 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary @/tmp/dns-no-bypass.json http://127.0.0.1:8086/api/config >/dev/null || fail "clear DNS bypass"
for transport in +notcp +tcp; do
	a=$(ip netns exec client dig "$transport" -b 192.168.77.11 +short +time=2 +tries=1 @198.51.100.3 x.ads.test A)
	[ "$a" = "0.0.0.0" ] || fail "DNS interception not restored on Apply ($transport): '$a'"
done
ok "clearing DNS bypass through Apply restores UDP/TCP interception"

api_get config | python3 -c 'import json,sys; c=json.load(sys.stdin);c["groups"].append({"name":"DNS reserve","target":"vless","entries":["fallback.test"]});print(json.dumps(c))' >/tmp/dns-config.json
curl -fsS -m 10 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @/tmp/dns-config.json http://127.0.0.1:8086/api/config >/dev/null || fail "DNS group apply"
# The daemon resolves configured names itself within about a second of Apply.
dns_routed() {
 api_get 'journal/routes?limit=200' | python3 -c 'import json,sys; assert any(x.get("ip")=="198.51.100.5" and x["outbound"]=="vless" and "DNS" in x["rule"] for x in json.load(sys.stdin)["entries"])' 2>/dev/null
}
for i in $(seq 1 100); do
 ip netns exec client curl -s -m 2 --http1.0 -H 'Host:' http://198.51.100.5/ >/dev/null || true
 dns_routed && break
 sleep 0.1
done
dns_routed || { cat /tmp/keenproxy.log; fail "no-SNI DNS fallback"; }
ip netns exec client curl -fsS -m 3 -H 'Host: unrelated.test' http://198.51.100.5/ >/dev/null
api_get 'journal/routes?limit=200' | python3 -c 'import json,sys; assert any(x["host"]=="unrelated.test" and x["outbound"]=="direct" for x in json.load(sys.stdin)["entries"])' || fail "shared IP overrode Host"
# Wait past the resolved entry's TTL: dnsmasq runs with local-ttl=5, so 7 seconds expire it.
sleep 7
expired_direct() {
 ip netns exec client curl -fsS -m 3 --http1.0 -H 'Host:' http://198.51.100.5/ >/dev/null
 api_get 'journal/routes?limit=200' | python3 -c 'import json,sys; r=[x for x in json.load(sys.stdin)["entries"] if x.get("ip")=="198.51.100.5" and x.get("host")=="198.51.100.5"]; assert r and r[0]["outbound"]=="direct"' 2>/dev/null
}
for i in $(seq 1 15); do expired_direct && break; sleep 0.2; done
expired_direct || fail "expired DNS still routes"
ok "DNS reserve: no-SNI via VLESS, readable Host direct, TTL expiry removed route"

# --- Simulate firmware removing an interception jump; the watchdog repairs it
iptables -t nat -D PREROUTING -j KEENPROXY_TCP
for i in $(seq 1 25); do
	iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null && break
	sleep 0.2
done
iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null || fail "watchdog did not restore the removed jump"
ip netns exec client curl -s -m 5 -o /dev/null http://198.51.100.3/ || fail "HTTP after recovery"
ok "watchdog restored the removed jump and HTTP works again"
curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/journal/audit?actor=watchdog" | grep -q 'Interception rules restored' || fail "watchdog audit record is missing"
# A direct connection to a closed port must produce an engine error record.
ip netns exec client curl -s -m 3 -o /dev/null http://198.51.100.3:81/ || true
SYS=""
for i in $(seq 1 25); do
	SYS=$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086/api/journal/system?source=sing-box")
	echo "$SYS" | grep -q '"source":"sing-box"' && break
	sleep 0.2
done
echo "$SYS" | grep -q '"source":"sing-box"' || { echo "$SYS"; tail -20 /tmp/keenproxy.log; fail "sing-box journal is not collected"; }
ok "audit records watchdog repairs and sing-box errors reach the system journal"
api_get 'journal/audit?actor=watchdog' | python3 -c 'import json,sys; events=[e for e in json.load(sys.stdin)["entries"] if e.get("action")=="Interception rules restored"]; assert any(e.get("firewall",{}).get("outcome")=="restored" and e["firewall"].get("trigger")=="watchdog" and e["firewall"].get("duration_ms",-1)>=0 and e["firewall"]["before"]["table"]=="nat" and e["firewall"]["before"]["chain"]=="PREROUTING" and e["firewall"]["before"]["target"]=="KEENPROXY_TCP" and e["firewall"]["before"]["exit_code"]==1 and "after" not in e["firewall"] for e in events)' || fail "verified watchdog repair evidence is missing"
ok "watchdog records the missing jump and verifies recovery"


# --- Fail over from the offline primary, then recover after the up hysteresis
api() { curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8086$1"; }
waitfor() { # API path, pattern, seconds
	for i in $(seq 1 $(($3 * 5))); do
		api "$1" | grep -q "$2" && return 0
		sleep 0.2
	done
	api "$1"; tail -20 /tmp/keenproxy.log; return 1
}
# Schedule a request and verify its host, actual outbound and route explanation.
route_is() {
	ip netns exec client curl -s -m 5 -o /dev/null -H 'Host: backup.test' http://203.0.113.80/ || fail "backup.test is unavailable"
	api "/api/journal/routes?limit=20" | python3 -c '
import json, sys
out, note = sys.argv[1], sys.argv[2]
e = [x for x in json.load(sys.stdin)["entries"] if x["host"] == "backup.test"][0]
assert e["outbound"] == out and note in e["rule"], e
' "$1" "$2" || fail "backup.test must use $1"
}
waitfor "/api/journal/audit?target=main" 'Switch to fallback' 10 || fail "did not switch to fallback"
waitfor "/api/status" '"main":{"active":"vless"' 2 || fail "status does not show fallback"
route_is vless "fallback: «Main» is unavailable"
ok "primary unavailable: traffic uses fallback VLESS, confirmed by audit and routing journal"
ip netns exec wan /work/sbserver /tmp/server-main.json >/tmp/sbserver-main.log 2>&1 &
waitfor "/api/journal/audit?target=main" 'Return to primary' 15 || fail "did not return to primary"
route_is main "group «With fallback»"
grep -q 'inbound/shadowsocks.*203.0.113.80' /tmp/sbserver-main.log || fail "primary server did not receive the connection"
ok "primary recovered and traffic returned after up_after"

# --- DNS guard must also catch TCP already redirected into a local inbound.
ip netns exec wan python3 -u -m http.server 853 --bind 198.51.100.3 >/tmp/dot-guard.log 2>&1 &
sleep 1
ip netns exec client curl -fsS -m 3 http://198.51.100.3:853/ >/dev/null || fail "853 baseline"
api_get config | python3 -c 'import json,sys;c=json.load(sys.stdin);c["dns"]["block_encrypted"]=True;print(json.dumps(c))' >/tmp/guard-config.json
curl -fsS -m 10 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @/tmp/guard-config.json http://127.0.0.1:8086/api/config >/dev/null || fail "guard apply"
if ip netns exec client curl -fsS -m 3 http://198.51.100.3:853/ >/dev/null 2>&1; then fail "DoT guard bypassed by TCP redirect"; fi
dig +short +time=2 +tries=1 @127.0.0.1 -p 5354 example.test A | grep -q '198.51.100.2' || fail "guard blocked own DNS"
ok "DNS guard rejects redirected port 853, own resolver works"

# --- Pause and off devices are untouched: no DNS interception, no TCP redirect.
# .11 has a WAN return route, so direct traffic from it can complete.
put_config() { # python expression body mutating c
	api_get config | python3 -c "import json,sys; c=json.load(sys.stdin); $1; print(json.dumps(c))" >/tmp/untouched-config.json
	curl -fsS -m 10 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @/tmp/untouched-config.json http://127.0.0.1:8086/api/config >/dev/null || fail "apply: $1"
}
untouched_probe() { # label; expect direct DNS and direct TCP from .11
	name="$1.ads.test"
	a=$(ip netns exec client dig -b 192.168.77.11 +short +time=2 +tries=1 @198.51.100.3 "$name" A)
	[ "$a" = "198.51.100.2" ] || fail "$1: DNS was intercepted: '$a'"
	grep -Fq "query[A] $name from 192.168.77.11" /tmp/dnsmasq.log || fail "$1: DNS did not reach the resolver directly"
	ip netns exec client curl --interface 192.168.77.11 -s -m 5 -o /dev/null http://198.51.100.3/ || fail "$1: direct HTTP failed"
	tail -1 /tmp/http.log | grep -q '^192.168.77.11 ' || fail "$1: TCP was redirected"
}
intercepted_probe() { # label
	name="$1.ads.test"
	a=$(ip netns exec client dig -b 192.168.77.11 +short +time=2 +tries=1 @198.51.100.3 "$name" A)
	[ "$a" = "0.0.0.0" ] || fail "$1: DNS not intercepted: '$a'"
	ip netns exec client curl --interface 192.168.77.11 -s -m 5 -o /dev/null http://198.51.100.3/ || fail "$1: HTTP through keenProxy failed"
	tail -1 /tmp/http.log | grep -q '^198.51.100.1 ' || fail "$1: TCP was not intercepted"
}
intercepted_probe before-pause
put_config 'c["paused"]=True'
untouched_probe paused
put_config 'c.pop("paused",None)'
intercepted_probe unpaused
put_config 'c["clients"]=c.get("clients",[])+[{"name":"Off","mac":"02:00:00:00:00:99","ip":"192.168.77.11","mode":"off"}]'
untouched_probe off-device
put_config 'c["clients"]=[x for x in c["clients"] if x["name"]!="Off"]'
intercepted_probe off-removed
ok "pause and off devices: DNS and TCP untouched; interception returns after unpause"

# --- Activation is applied through the real API without deleting profiles or references.
# Register cleanup before creating this phase's uniquely owned temporary directory.
ACTIVATION_TMP=""
activation_cleanup() {
	if [ -n "$ACTIVATION_TMP" ]; then
		rm -rf "$ACTIVATION_TMP"
		[ ! -e "$ACTIVATION_TMP" ] || fail "activation temporary files remain"
	fi
}
trap activation_cleanup 0
trap 'exit 1' 1 2 15
ACTIVATION_TMP=$(mktemp -d /tmp/keenproxy-activation.XXXXXX)
api_get config >"$ACTIVATION_TMP/baseline.json"

activation_apply() {
	python3 - "$ACTIVATION_TMP/baseline.json" "$1" >"$ACTIVATION_TMP/draft.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
mode=sys.argv[2]
for cn in c["connections"]:
    cn["disabled"] = cn["id"] == "main" or mode in ("blocked", "client-blocked", "direct")
    if mode == "intermediate" and cn["id"] == "vless":
        cn["disabled"], cn["fallback"] = True, "ss"
    if mode == "direct" and cn["id"] == "main":
        cn["fallback"] = "direct"
if mode in ("blocked", "direct"):
    c["networks"][0]["mode"], c["networks"][0]["target"] = "full", "main"
if mode == "client-blocked":
    c["clients"] = [{"name":"Activation client","mac":"02:00:00:00:00:77","ip":"192.168.77.10","mode":"full","target":"main"}]
print(json.dumps(c))
PY
	curl -fsS -m 15 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		--data-binary @"$ACTIVATION_TMP/draft.json" http://127.0.0.1:8086/api/config >/dev/null || fail "activation $1 apply"
}
activation_rule_apply() {
	python3 - "$ACTIVATION_TMP/baseline.json" "$1" >"$ACTIVATION_TMP/draft.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
mode=sys.argv[2]
g={"name":"Activation rules","target":"block","entries":["ads.test","198.51.100.3/32"]}
if mode == "entries-off":
    g["disabled_entries"]=["ADS.TEST","198.51.100.3/32"]
elif mode in ("parent-off","parent-on"):
    g["disabled"]=mode == "parent-off"
    g["disabled_entries"]=["ADS.TEST"]
elif mode == "geo-off":
    g={"name":"Empty inverted geo","target":"block","countries":[" ru "],
       "disabled_countries":["rU"],"except":True}
c["groups"]=[g]
c["clients"]=[]
c["networks"][0]["mode"]="split"
c["networks"][0].pop("target",None)
print(json.dumps(c))
PY
	curl -fsS -m 15 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		--data-binary @"$ACTIVATION_TMP/draft.json" http://127.0.0.1:8086/api/config >/dev/null || fail "rule activation $1 apply"
}
activation_ads_allowed() {
	answer=$(ip netns exec client dig +short +time=2 +tries=1 @8.8.8.8 x.ads.test A)
	[ "$answer" = "198.51.100.2" ] || fail "disabled block domain still affects DNS: $answer"
}
activation_apply reserve
route_is vless "group «With fallback»"
activation_apply intermediate
route_is ss "group «With fallback»"
for activation_mode in blocked client-blocked; do
	activation_apply "$activation_mode"
	if ip netns exec client curl -fsS -m 3 -H 'Host: backup.test' http://198.51.100.3/ >/dev/null 2>&1; then
		fail "all-disabled $activation_mode selection escaped directly"
	fi
	api_get status | python3 -c 'import json,sys;s=json.load(sys.stdin);assert s["failover"]["main"]["active"]=="block";assert all(not h["ok"] and h.get("error")=="connection is disabled" for h in s["health"].values())' || fail "disabled status or stale selection"
done
activation_apply direct
ip netns exec client curl -fsS -m 3 -H 'Host: backup.test' http://198.51.100.3/ >/dev/null || fail "explicit direct fallback"
curl -fsS -m 15 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary @"$ACTIVATION_TMP/baseline.json" http://127.0.0.1:8086/api/config >/dev/null || fail "activation restore"
route_is main "group «With fallback»"
activation_rule_apply rules-on
if ip netns exec client curl -fsS -m 3 http://198.51.100.3/ >/dev/null 2>&1; then
	fail "active IP block did not reject traffic"
fi
answer=$(ip netns exec client dig +short +time=2 +tries=1 @8.8.8.8 x.ads.test A)
[ "$answer" = "0.0.0.0" ] || fail "active domain block did not affect DNS"
activation_rule_apply entries-off
ip netns exec client curl -fsS -m 3 http://198.51.100.3/ >/dev/null || fail "disabled IP block remained active"
activation_ads_allowed
api_get config | python3 -c 'import json,sys;g=json.load(sys.stdin)["groups"][0];assert len(g["entries"])==2 and len(g["disabled_entries"])==2' || fail "off state deleted original rules"
activation_rule_apply parent-off
ip netns exec client curl -fsS -m 3 http://198.51.100.3/ >/dev/null || fail "disabled group remained active"
activation_ads_allowed
activation_rule_apply parent-on
if ip netns exec client curl -fsS -m 3 http://198.51.100.3/ >/dev/null 2>&1; then
	fail "re-enabled parent did not restore its active child"
fi
activation_ads_allowed
activation_rule_apply geo-off
ip netns exec client curl -fsS -m 3 http://198.51.100.3/ >/dev/null || fail "all-off inverted geo became a global block"
curl -fsS -m 15 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary @"$ACTIVATION_TMP/baseline.json" http://127.0.0.1:8086/api/config >/dev/null || fail "rule activation restore"
route_is main "group «With fallback»"
ok "activation rules: off domain/IP and group release DNS/traffic; parent preserves child state; all-off country inversion stays inactive"
activation_cleanup
ACTIVATION_TMP=""
trap - 0 1 2 15
ok "activation: disabled primary and intermediate bypassed; all-off network/client references block; explicit direct and re-enable restore"

# --- Provider rules in DNS: for split devices a block rule answers locally
# unless an own list holds the name; a full tunnel device (.11) gets the real
# answer. A domain rule learns addresses only from device answers.
api_get config >/tmp/provider-baseline.json
provider_apply() { # JSON list of switched-off provider rule keys
	python3 - "$1" >/tmp/provider-config.json <<'PY'
import json, sys
c = json.load(open("/tmp/provider-baseline.json"))
c["subscriptions"] = [{"id": "prov", "url": "https://198.51.100.2:8444/sub"}]
c["provider_rules"] = {"source": "prov", "disabled": json.loads(sys.argv[1])}
# Provider proxy rules go to the split network's target, which they require.
c["networks"][0]["target"] = "ss"
c["groups"].append({"name": "Provider exception", "target": "direct", "entries": ["keep.provads.test"]})
c["clients"] = [{"name": "Full tunnel", "mac": "02:00:00:00:00:88", "ip": "192.168.77.11", "mode": "full", "target": "ss"}]
print(json.dumps(c))
PY
	curl -fsS -m 30 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		--data-binary @/tmp/provider-config.json http://127.0.0.1:8086/api/config >/dev/null ||
		{ tail -20 /tmp/keenproxy.log; cat /tmp/provider.log; fail "provider rules apply"; }
}
dig_a() { ip netns exec client dig +short +time=2 +tries=1 @8.8.8.8 "$1" A; }
provider_apply '[]'
grep -q 'GET /sub' /tmp/provider.log || fail "the subscription was not fetched over HTTPS"
a=$(dig_a x.provads.test)
[ "$a" = "0.0.0.0" ] || fail "provider block rule: '$a'"
a=$(dig_a www.keep.provads.test)
[ "$a" = "198.51.100.3" ] || fail "an own list must win over a provider block rule: '$a'"
a=$(dig_a x.ads.test)
[ "$a" = "0.0.0.0" ] || fail "block group next to provider rules: '$a'"
a=$(ip netns exec client dig -b 192.168.77.11 +short +time=2 +tries=1 @8.8.8.8 x.provads.test A)
[ "$a" = "198.51.100.3" ] || fail "a full tunnel device must get the real answer for a provider block name: '$a'"
a=$(ip netns exec client dig -b 192.168.77.11 +short +time=2 +tries=1 @8.8.8.8 x.ads.test A)
[ "$a" = "0.0.0.0" ] || fail "block group for a full tunnel device: '$a'"
api_get 'journal/routes?limit=200' | python3 -c 'import json,sys; assert any(x["host"]=="x.provads.test." and x.get("source")=="provider" for x in json.load(sys.stdin)["entries"])' ||
	fail "the provider DNS block is not journaled"
ok "provider block rule answers DNS locally for split devices only; an own list and a block group keep their rules"

# Without a name, .4 takes the country tunnel (FI → ss). A device answer for
# provdirect.test sends it directly until the answer's 5-second TTL ends.
a=$(dig_a provdirect.test)
[ "$a" = "198.51.100.4" ] || fail "provider domain: '$a'"
provider_route() { # outbound expected for a request to .4 without a name
	ip netns exec client curl -s -m 3 --http1.0 -H 'Host:' http://198.51.100.4/ >/dev/null || return 1
	api_get 'journal/routes?limit=50' | python3 -c '
import json, sys
e = [x for x in json.load(sys.stdin)["entries"] if x.get("ip") == "198.51.100.4" and x.get("host") == "198.51.100.4"]
assert e and e[0]["outbound"] == sys.argv[1], e[:1]
assert sys.argv[1] != "direct" or "dns-" in e[0].get("rule_raw", ""), e[:1]
' "$1" 2>/dev/null
}
for i in $(seq 1 30); do provider_route direct && break; sleep 0.2; done
provider_route direct || { tail -20 /tmp/keenproxy.log; fail "provider DNS fallback did not route the observed address"; }
sleep 7
for i in $(seq 1 15); do provider_route ss && break; sleep 0.2; done
provider_route ss || fail "an expired provider answer still routes"
# KeenProxy resolves an observed own subdomain again after its 30-second retry
# minimum, but never an observed provider name.
queries() { grep -c "query\[A\] $1 from 198.51.100.1" /tmp/dnsmasq.log || true; }
for i in $(seq 1 200); do [ "$(queries www.keep.provads.test)" -ge 2 ] && break; sleep 0.2; done
[ "$(queries www.keep.provads.test)" -ge 2 ] || fail "the observed own subdomain was not kept warm"
[ "$(queries provdirect.test)" = "1" ] || fail "KeenProxy resolved the provider name itself: $(queries provdirect.test) queries"
ok "provider DNS fallback: a device answer routed the address until its TTL; the provider name was never resolved by KeenProxy"

provider_apply '["block:literals:site"]'
a=$(dig_a y.provads.test)
[ "$a" = "198.51.100.3" ] || fail "a switched-off provider block rule still answers locally: '$a'"
curl -fsS -m 15 -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary @/tmp/provider-baseline.json http://127.0.0.1:8086/api/config >/dev/null || fail "provider rules restore"
ok "switching the provider block rule off releases its names on Apply"

# --- Shutdown removes all interception owned by KeenProxy
kill -TERM $KPID
wait $KPID || true
if iptables-save | grep -q KEENPROXY; then
	iptables-save | grep KEENPROXY
	fail "interception rules remain after shutdown"
fi
ok "SIGTERM removed all KEENPROXY rules"
# --- Optional NDM callback: emulate only the firmware socket and callback launch.
# Polling above ran on a non-NDM instance. Here an hour-long interval proves
# that the real generated shell hook, rather than polling, repairs traffic.
mkdir -p /opt/bin /opt/etc/keenproxy /opt/etc/ndm /var/run
cp "$KEENPROXY" /opt/bin/keenproxy
cp /tmp/config.yaml /opt/etc/keenproxy/config.yaml
# The same /opt layout can be used without NDM (for example OpenWrt/Entware).
# It must create no hook state and still repair through the periodic watchdog.
/opt/bin/keenproxy -config /opt/etc/keenproxy/config.yaml -rule-sets /tmp/portable/rule-sets -watch 1s \
    -iptables /usr/sbin/iptables -iptables-restore /usr/sbin/iptables-restore >/tmp/keenproxy-portable.log 2>&1 &
KPID=$!
waitfor "/api/status" '"firewall":true' 10 || { cat /tmp/keenproxy-portable.log; fail "non-NDM managed instance did not start"; }
[ ! -e /opt/etc/ndm/netfilter.d/99-keenproxy.sh ] || fail "hook installed without NDM"
[ ! -e /var/run/keenproxy/netfilter ] || fail "event state created without NDM"
iptables -t nat -D PREROUTING -j KEENPROXY_TCP
waitfor '/api/journal/audit?actor=watchdog' '"trigger":"watchdog"' 5 || fail "non-NDM managed polling did not repair"
iptables -t nat -C PREROUTING -j KEENPROXY_TCP || fail "non-NDM managed repair left missing jump"
ip netns exec client curl -s -m 5 -o /dev/null http://198.51.100.3/ || fail "HTTP after non-NDM managed polling"
kill -TERM "$KPID"
wait "$KPID"
ok "managed Linux without NDM creates no hook and retains polling recovery"
python3 -u - <<'PY' >/tmp/ndm-fixture.log 2>&1 &
import socket,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.bind('/var/run/ndm.core.socket')
s.listen()
time.sleep(120)
PY
NDMPID=$!
for i in $(seq 1 20); do
    [ -S /var/run/ndm.core.socket ] && break
    sleep 0.1
done
/opt/bin/keenproxy -config /opt/etc/keenproxy/config.yaml -rule-sets /tmp/event-rule-sets -watch 1h \
    -iptables /usr/sbin/iptables -iptables-restore /usr/sbin/iptables-restore >/tmp/keenproxy-event.log 2>&1 &
KPID=$!
for i in $(seq 1 50); do
    iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null && break
    kill -0 "$KPID" 2>/dev/null || { cat /tmp/keenproxy-event.log; fail "event instance exited"; }
    sleep 0.2
done
HOOK=/opt/etc/ndm/netfilter.d/99-keenproxy.sh
[ -x "$HOOK" ] || { cat /tmp/keenproxy-event.log; fail "NDM hook not installed"; }
iptables -t nat -D PREROUTING -j KEENPROXY_TCP
iptables -t nat -F KEENPROXY_TCP
iptables -t nat -X KEENPROXY_TCP
type=ip6tables table=nat sh "$HOOK"
type=iptables table=raw sh "$HOOK"
if iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null; then
    fail "irrelevant callback repaired IPv4 NAT"
fi
type=iptables table=nat sh "$HOOK"
for i in $(seq 1 30); do
    iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null && break
    sleep 0.1
done
iptables -t nat -C PREROUTING -j KEENPROXY_TCP 2>/dev/null || { cat /tmp/keenproxy-event.log; fail "NDM callback did not restore missing chain"; }
ip netns exec client curl -s -m 5 -o /dev/null http://198.51.100.3/ || fail "HTTP after NDM event recovery"
api_get 'journal/audit?actor=watchdog' | python3 -c 'import json,sys; events=json.load(sys.stdin)["entries"]; assert any(e.get("firewall",{}).get("trigger")=="netfilter_hook" and e["firewall"]["outcome"]=="restored" and e["firewall"].get("duration_ms",-1)>=0 for e in events)' || fail "event recovery source or verification is missing"
if grep -Eq 'checking firewall after netfilter event|interception rules restored and verified|interception rule check failed' /tmp/keenproxy-event.log; then fail "successful event recovery duplicated into system log"; fi
ok "NDM callback restores a deleted chain and HTTP before the one-hour poll"
kill -TERM "$KPID"
wait "$KPID"
[ ! -e "$HOOK" ] || fail "owned NDM hook remains after stop"
[ ! -e /var/run/keenproxy/netfilter/changed ] || fail "event marker remains after stop"
kill "$NDMPID"
ok "NDM lifecycle cleanup is safe"

# Give both families direct return routes so the probes detect an unguarded gap.
ip -n wan route add 192.168.77.10/32 via 198.51.100.1
ip addr add 2001:db8:1::1/64 dev br0 nodad
ip addr add 2001:db8:2::1/64 dev veth-w nodad
ip -n client addr add 2001:db8:1::2/64 dev eth0 nodad
ip -n wan addr add 2001:db8:2::2/64 dev eth0 nodad
ip -n client -6 route add default via 2001:db8:1::1
ip -n wan -6 route add default via 2001:db8:2::1
echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
PYTHONPATH=/work/test/install python3 -B /work/test/netns/update_guard.py
ok "release replacement and rollback protect IPv4 and IPv6 forwarding"

echo "PASS"
