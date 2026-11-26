"""Exercise scheduled subscription selection and guarded firewall repair in netns."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler, Request


HTTP = build_opener(ProxyHandler({}))
WAN_HTTP_LOG = Path("/tmp/http.log")
FORWARD_URL = "http://198.51.100.1:18080/payload"
FORWARD_BODY = "forwarded from LAN\n"


def api(path, config=None):
    request = Request(f"http://127.0.0.1:8086/api/{path}")
    if config is not None:
        request = Request(request.full_url, data=json.dumps(config).encode(), method="PUT",
                          headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=12 if config is not None else 3) as response:
        return json.load(response)


def command(*args, check=True, env=None):
    result = subprocess.run(args, timeout=5, text=True, capture_output=True, env=env)
    if check and result.returncode:
        raise AssertionError(f"{' '.join(args)}: {result.stderr or result.stdout}")
    return result


def wait_for(description, probe, seconds=9):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {description}")


def audit(target):
    return api(f"journal/audit?actor=watchdog&target={target}")["entries"]


def curl(namespace, url, *options, check=True):
    return command("ip", "netns", "exec", namespace, "curl", "--noproxy", "*", "-fsS", "-m", "2",
                   *options, url, check=check)


def subscription_packet(inbound):
    with Path("/tmp/sbserver.log").open() as log:
        log.seek(0, os.SEEK_END)
        curl("client", "http://203.0.113.81/", "-o", "/dev/null")
        assert any(inbound in line and "203.0.113.81:80" in line for line in log), inbound


def node_reject(action, port):
    command("ip", "netns", "exec", "wan", "iptables", "-w", "2", action, "INPUT", "-i", "eth0",
            "-d", "198.51.100.2", "-p", "tcp", "--dport", port, "-j", "REJECT", "--reject-with", "tcp-reset")


def reserve_event(action, started, minimum, reason=None):
    def matching():
        for entry in audit("reserve"):
            if entry["action"] == action and (reason is None or entry["details"].startswith(reason)):
                return entry

    event = wait_for(action, matching, seconds=12)
    elapsed = (datetime.fromisoformat(event["time"]) - started).total_seconds()
    # Allow an HTTPS check already in flight when the test closes a node's port.
    assert elapsed >= minimum - 0.1, f"{action} after only {elapsed:.3f}s (configured {minimum}s)"
    return elapsed


def subscription_reserve():
    baseline = api("config")
    config = deepcopy(baseline)
    config["subscriptions"] = [{"id": "reserve", "url": "https://198.51.100.2:8444/sub-reserve", "fallback": "ss"}]
    config["networks"][0].update(mode="full", target="subscription:reserve:auto")
    config["failover"].update(url="https://198.51.100.2:8444/healthz", down_after=3, up_after=4)
    api("config", config)

    blocked = set()
    try:
        subscription_packet("inbound/vless[node-a]")
        outage = datetime.now(timezone.utc)
        for port in ("8445", "8446"):
            node_reject("-I", port)
            blocked.add(port)
        down = reserve_event("Subscription reserve in use", outage, config["failover"]["down_after"])
        subscription_packet("inbound/shadowsocks")

        recovery = datetime.now(timezone.utc)
        node_reject("-D", "8446")
        blocked.remove("8446")
        up = reserve_event("Subscription node selected", recovery, config["failover"]["up_after"], "recovered ")
        subscription_packet("inbound/vless[node-b]")
    finally:
        for port in blocked:
            node_reject("-D", port)
        api("config", baseline)
    print(f"ok   subscription node A, reserve after down_after ({down:.2f}s), node B after up_after ({up:.2f}s)")


def firewall(*args):
    return command("iptables", "-w", "2", *args).stdout


def nat_jump(action, target):
    position = ["1"] if action == "-I" else []
    firewall("-t", "nat", action, "PREROUTING", *position, "-j", f"KEENPROXY_{target}")


def dns(address, protocol, label, source="192.168.77.10"):
    return command("ip", "netns", "exec", "client", "dig", f"+{protocol}", "-b", source, "+short",
                   "+time=1", "+tries=1", f"@{address}", f"{label}-{protocol}.ads.test", "A", check=False)


def dns_answer(address, protocol, label, expected, source="192.168.77.10"):
    probe = dns(address, protocol, label, source)
    assert probe.returncode == 0 and probe.stdout.strip() == expected, probe


def assert_drops(active):
    for chain in ("KEENPROXY_DNS_GUARD", "KEENPROXY_QUIC"):
        rules = firewall("-t", "filter", "-S", chain).splitlines()
        assert any(rule.endswith(" -j DROP") for rule in rules) == active, rules


def notify(hook):
    cursor = max((entry["id"] for entry in audit("firewall")), default=0)
    command("sh", hook, env={**os.environ, "type": "iptables", "table": "nat"})
    return cursor


def repair_event(cursor, outcome, missing="DNS", retry=True):
    events = wait_for(outcome, lambda: [e for e in audit("firewall") if e["id"] > cursor])
    assert len(events) == 1, events
    event = events[0]["firewall"]
    assert event["trigger"] == "netfilter_hook" and event["outcome"] == outcome, event
    assert event["before"]["table"] == "nat" and event["before"]["target"] == f"KEENPROXY_{missing}", event
    if retry:
        assert event["duration_ms"] >= 250, event
    if outcome == "restored":
        assert "after" not in event, event
        nat_jump("-C", "DNS")
        assert_drops(False)
        for protocol in ("notcp", "tcp"):
            dns_answer("192.168.77.254", protocol, f"restored-{cursor}", "0.0.0.0")
    else:
        assert event["after"]["target"] == "KEENPROXY_DNS" and event["after"]["exit_code"] == 1, event
        assert_drops(True)


def insertion_loss(state, hook, losses):
    nat_jump("-D", "DNS")
    if losses == 1:
        # With the standalone DNS jump gone, the earlier TCP hook still sends TCP DNS to our frontend.
        dns_answer("198.51.100.3", "tcp", "tcp-hook-only", "0.0.0.0")
        firewall("-t", "nat", "-F", "KEENPROXY_DNS")
        # Even without DNS rules the TCP core intercepts. The WAN resolver sees the router.
        answer = command("ip", "netns", "exec", "client", "dig", "+tcp", "+short", "+time=1", "+tries=1",
                         "@198.51.100.3", "empty-chain.example.test", "A")
        assert answer.stdout.strip() == "198.51.100.2", answer
        assert "query[A] empty-chain.example.test from 198.51.100.1" in Path("/tmp/dnsmasq.log").read_text()
    budget = state / "insert-losses"
    budget.write_text(f"{losses}\n")
    repair_event(notify(hook), "restored" if losses == 1 else "verify_failed")
    assert not budget.exists(), "the repair did not perform the expected DNS insertions"


def release_loss(state, hook):
    (state / "lose-on-release").touch()
    nat_jump("-D", "DNS")
    cursor = notify(hook)
    wait_for("DNS guard re-arm after the filter commit", (state / "rearmed").exists)
    try:
        probe = (state / "first-probe").read_text().strip()
        assert probe == "1 -w -t nat -C PREROUTING -j KEENPROXY_DNS", probe
        assert_drops(True)
        for protocol in ("notcp", "tcp"):
            dns_answer("192.168.77.1", protocol, "frontend", "0.0.0.0")
            result = dns("192.168.77.254", protocol, "guard")
            assert result.returncode != 0, result
            dns_answer("192.168.77.254", protocol, "exempt", "198.51.100.5", "192.168.77.11")
            assert f"guard-{protocol}.ads.test from 192.168.77.10" not in (state / "dns.log").read_text()
    finally:
        (state / "resume").touch()
    repair_event(cursor, "restored")
    trace = [line.split() for line in (state / "release-trace").read_text().splitlines()]
    expected = ["filter-commit", "first-probe", "rearm-commit", "retry-entry", "retry-protection", "retry-nat"]
    steps = [step for step, _ in trace]
    assert steps == expected, f"expected release trace {expected}, got {steps}"
    times = {step: int(at) for step, at in trace}
    rearm_ms = (times["rearm-commit"] - times["filter-commit"]) / 1_000_000
    print(f"ok   DNS jump loss during guard removal re-arms both DNS drops before the retry "
          f"(filter commit to re-arm {rearm_ms:.1f} ms)")


# Keep one forwarded TCP flow open so transfers use the same socket on both sides of recovery.
KEEPALIVE = """
from http.client import HTTPConnection
import sys

conn = HTTPConnection("198.51.100.1", 18080, timeout=2, source_address=("198.51.100.5", 0))
original = None
for _ in sys.stdin:
    conn.request("GET", "/payload")
    response = conn.getresponse()
    assert response.status == 200 and response.read() == sys.argv[1].encode()
    assert conn.sock is not None and (original is None or conn.sock is original)
    original = conn.sock
    print("ok", flush=True)
"""


def transfer_on_open_socket(process):
    process.stdin.write("\n")
    process.stdin.flush()
    ready, _, _ = select.select([process.stdout], [], [], 3)
    assert ready and process.stdout.readline() == "ok\n", "WAN transfer on the open TCP flow failed"


def assert_lan_tcp_source(label, peer):
    path = f"/?probe={label}"
    curl("client", f"http://198.51.100.3{path}", "--interface", "192.168.77.10", "-o", "/dev/null")
    sources = [line.split()[0] for line in WAN_HTTP_LOG.read_text().splitlines() if f'"GET {path} HTTP/' in line]
    assert sources == [peer], f"{label} reached WAN from {sources}, expected {peer}"


def port_forward(state, hook):
    dnat = ("-i", "veth-w", "-p", "tcp", "-d", "198.51.100.1", "--dport", "18080",
            "-j", "DNAT", "--to-destination", "192.168.77.10:18080")
    firewall("-t", "nat", "-A", "PREROUTING", *dnat)
    with subprocess.Popen(["ip", "netns", "exec", "wan", "python3", "-u", "-c", KEEPALIVE, FORWARD_BODY],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as flow:
        try:
            wait_for("LAN HTTP fixture", lambda: curl("wan", FORWARD_URL, "--interface", "198.51.100.5",
                                                      check=False).stdout == FORWARD_BODY, seconds=4)
            transfer_on_open_socket(flow)
            insertion_loss(state, hook, 2)
            print("ok   DNS jump lost on both insertions reports verify_failed and keeps the recovery drops")
            nat_jump("-D", "TCP")
            transfer_on_open_socket(flow)
            assert curl("wan", FORWARD_URL, "--interface", "198.51.100.5").stdout == FORWARD_BODY
            blocked = curl("client", "http://198.51.100.3/", "--interface", "192.168.77.10", check=False)
            assert blocked.returncode == 28, f"new LAN flow was not dropped: {blocked.returncode}"
            repair_event(notify(hook), "restored", missing="TCP", retry=False)
            assert_lan_tcp_source("recovered-lan", "198.51.100.1")
            transfer_on_open_socket(flow)
            assert curl("wan", FORWARD_URL, "--interface", "198.51.100.5").stdout == FORWARD_BODY
        finally:
            flow.stdin.close()
            firewall("-t", "nat", "-D", "PREROUTING", *dnat)
    print("ok   established and new WAN port forwards transfer during recovery while new LAN TCP is dropped")
    print("ok   fresh LAN TCP uses restored interception (WAN sees 198.51.100.1)")


def firewall_recovery(state, hook):
    config = api("config")
    config["dns"].update(listen="192.168.77.1:53", bypass_sources=["192.168.77.11"])
    api("config", config)
    command("ip", "addr", "add", "192.168.77.254/24", "dev", "br0")
    (state / "payload").write_text(FORWARD_BODY)
    with (state / "dns.log").open("w") as log:
        resolver = subprocess.Popen(["dnsmasq", "-k", "--no-resolv", "--no-hosts", "--bind-interfaces",
                                     "--listen-address=192.168.77.254", "--address=/ads.test/198.51.100.5",
                                     "--log-queries", "--log-facility=-"], stdout=log, stderr=subprocess.STDOUT)
    with (state / "http.log").open("w") as log:
        server = subprocess.Popen(["ip", "netns", "exec", "client", "python3", "-m", "http.server", "18080",
                                   "--protocol", "HTTP/1.1", "--bind", "192.168.77.10", "--directory", str(state)],
                                  stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_for("router-local alternate resolver", lambda: dns("192.168.77.254", "notcp", "alias-ready",
                                                                "192.168.77.11").stdout.strip() == "198.51.100.5")
        # The return route makes a completely unhooked TCP flow succeed at this same destination.
        nat_jump("-D", "TCP")
        assert_lan_tcp_source("unhooked-lan", "192.168.77.10")
        nat_jump("-I", "TCP")
        dns_answer("198.51.100.3", "tcp", "tcp-hook-first", "0.0.0.0")
        insertion_loss(state, hook, 1)
        print("ok   TCP DNS stays intercepted with the TCP hook first, the DNS jump absent, or the DNS chain empty")
        print("ok   DNS jump lost once after insertion retries in the same repair and clears the drops")
        port_forward(state, hook)
        release_loss(state, hook)
    finally:
        for process in (resolver, server):
            process.terminate()
            process.wait(timeout=3)
        command("ip", "addr", "del", "192.168.77.254/24", "dev", "br0")


if __name__ == "__main__":
    if sys.argv[1:] == ["reserve"]:
        subscription_reserve()
    elif len(sys.argv) == 4 and sys.argv[1] == "firewall":
        firewall_recovery(Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit("usage: simple_ui_cases.py reserve | firewall state-directory hook")
