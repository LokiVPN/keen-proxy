#!/usr/bin/env python3
"""Measure the candidate with provider rules on and off in disposable namespaces."""
import argparse
from collections import Counter
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import time
import traceback
import uuid

import scenario
import stress

WAN = "198.51.100.2"
PROVIDER = f"https://{WAN}:8444"
SOURCE = "fixture"
SUB = "/sub"
RETRY_SUB = "/sub-retry"
SITE = "/data/geosite.dat"
IP = "/data/geoip.dat"
RETRY_IP = "/data/retry-ip.dat"
NODE_PORTS = (8445, 8446)
NEIGHBOR_MAC = "02:00:00:00:00:42"
NEIGHBOR_CHANGES = 20
DNS_NAMES = 4096
GO_LIMIT = 320 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise scenario.ScenarioError(message)


def file_stamp(path):
    info = path.stat()
    return info.st_ino, info.st_mtime_ns


def read_snapshot(path):
    entries = json.loads(path.read_bytes())
    require(len(entries) == 1, "expected exactly one saved subscription")
    snapshot = next(iter(entries.values()))
    require(len(snapshot["nodes"]) == 2, "expected both subscription nodes in the snapshot")
    return snapshot


def check_rules(snapshot, size, enabled, expect_ip=True):
    rules = snapshot.get("rules")
    if not enabled:
        require(rules is None, "rules-off run saved evaluated provider rules")
        return {}
    require(rules and rules.get("built"), "missing evaluated provider rules")
    built = {rule["key"]: rule for rule in rules["built"]["rules"]}
    site, ip, block = (built[key] for key in ("direct:geosite:fixture", "direct:geoip:fixture", "block:literals:site"))
    require(len(site.get("suffix", [])) == size["domains"]
            and not site.get("unavailable") and rules["geosite"].get("downloaded"),
            "geosite payload was not fully installed")
    require(block.get("full") == ["blocked.provider.test"], "missing DNS block control")
    if expect_ip:
        require(len(ip.get("cidr", [])) == size["prefixes"] and not rules.get("error")
                and not ip.get("unavailable") and rules["geoip"].get("downloaded"),
                "geoip payload was not fully installed")
    else:
        require(not ip.get("cidr") and not rules["geoip"].get("downloaded")
                and rules.get("error") == "geoip file could not be downloaded",
                "retry did not start from a verified missing geoip file")
    return {"geosite": rules["geosite"], "geoip": rules["geoip"],
            "domains": len(site["suffix"]), "prefixes": len(ip.get("cidr", []))}


def phase_metrics(proc, heap, ticks):
    start, end = proc[0], proc[-1]
    before = [row for row in heap if row[0] <= start["time_ns"]]
    during = [row for row in heap if start["time_ns"] < row[0] <= end["time_ns"]]
    require(before and during, "missing heap measurements at the phase boundary")
    heap = before[-1:] + during
    require(all(0 < row[1] <= row[2] and row[3] == GO_LIMIT for row in heap),
            "invalid heap sample or runtime Go limit differs from 320 MiB")
    require(all(a[0] < b[0] and a[2] <= b[2] for a, b in zip(heap, heap[1:])),
            "heap time or allocation counter went backwards")
    require(not any(stress.exceeds_rss(row) for row in proc), "daemon RSS or VmHWM reached 384 MiB")
    elapsed = (end["time_ns"] - start["time_ns"]) / 1_000_000_000
    cpu = end["cpu_ticks"] - start["cpu_ticks"]
    require(elapsed > 0 and cpu >= 0 and end["hwm_bytes"] >= start["hwm_bytes"],
            "invalid process metric interval")
    return {**stress.summarize(proc, elapsed, cpu, ticks),
            "heap_start_bytes": heap[0][1], "heap_end_bytes": heap[-1][1],
            "heap_peak_bytes": max(row[1] for row in heap),
            "heap_allocated_bytes": heap[-1][2] - heap[0][2], "heap_samples": len(during)}


class Measurements:
    """Procfs at operation boundaries and timestamped heap samples throughout."""

    def __init__(self, fixture, result):
        self.result = result
        self.heap_file = fixture.directory / "heap.csv"
        pid = fixture.daemon.pid
        self.memory = stress.memory_reader(fixture.daemon, pid)
        self.cpu = stress.cpu_reader(pid)
        self.ticks = os.sysconf("SC_CLK_TCK")
        scenario.wait_for(lambda: self.heap_file.stat().st_size, 5, "candidate heap sampler")

    def sample(self):
        return {**self.memory(), "cpu_ticks": self.cpu(), "time_ns": time.monotonic_ns()}

    @contextmanager
    def phase(self, name):
        proc = self.result["proc_samples"][name] = [self.sample()]
        try:
            yield
        except BaseException:
            stress.attempt(lambda: proc.append(self.sample()), self.result, "partial_measurement_error")
            raise
        action_ended = time.monotonic_ns()
        # Give short operations at least one in-window runtime sample.
        time.sleep(stress.SAMPLE_INTERVAL)
        proc.append(self.sample())
        # The daemon is still sampling. Only parse complete lines.
        lines = self.heap_file.read_text().rpartition("\n")[0].splitlines()
        heap = [tuple(map(int, line.split(","))) for line in lines]
        self.result["phases"][name] = {
            **phase_metrics(proc, heap, self.ticks),
            "operation_seconds": (action_ended - proc[0]["time_ns"]) / 1_000_000_000,
        }


class ProviderFixture(scenario.Fixture):
    def __init__(self, args, directory, cleanup, size_name, enabled):
        super().__init__(args, directory, cleanup)
        self.enabled, self.size_name = enabled, size_name
        self.arp = directory / "arp"
        self.data = directory / "data"
        self.snapshots = directory / "subscriptions"

    def setup(self):
        self.size = json.loads(scenario.command([self.args.load, "generate", self.size_name, self.directory]))
        for name in ("geosite", "geoip"):
            raw = (self.data / (name + ".dat")).read_bytes()
            require(len(raw) == self.size[name + "_bytes"], "incorrect synthetic dat size")
            self.size[name + "_sha256"] = sha256(raw).hexdigest()
        self.write_neighbor("192.168.77.100")
        super().setup()

    def configuration(self):
        config, server = super().configuration()
        config["schema_version"] = 2
        config["clients"] = [{"name": "Moving fixture device", "mac": NEIGHBOR_MAC, "mode": "off"}]
        config["failover"] = {"url": PROVIDER + "/healthz", "interval": 2, "down_after": 4, "up_after": 4}
        server["inbounds"] = [
            {"type": "vless", "tag": f"fixture-{port}", "listen": WAN, "listen_port": port,
             "users": [{"uuid": "11111111-2222-3333-4444-555555555555"}]}
            for port in NODE_PORTS
        ]
        return config, server

    def launch(self, namespace, label, *args):
        if label == "keenproxy":
            cert = self.start_provider()
            args = stress.prefix_daemon(label, (
                f"SSL_CERT_FILE={cert}", f"KEENPROXY_FIXTURE_HEAP={self.directory / 'heap.csv'}",
                *args, "-arp", self.arp))
        return super().launch(namespace, label, *args)

    def start_provider(self):
        cert = self.directory / "provider-ca.pem"
        nodes = self.directory / "nodes.txt"
        nodes.write_text("".join(f"vless://11111111-2222-3333-4444-555555555555@{WAN}:{port}"
                                 f"?type=tcp&encryption=none#Fixture-{port}\n" for port in NODE_PORTS))
        for name, ip in (("profile", IP), ("retry-profile", RETRY_IP)):
            scenario.save_json(self.directory / (name + ".json"), {
                "Name": "Synthetic provider", "GlobalProxy": False,
                "Geositeurl": PROVIDER + SITE, "Geoipurl": PROVIDER + ip,
                "DirectSites": ["geosite:fixture"], "DirectIp": ["geoip:fixture"],
                "BlockSites": ["full:blocked.provider.test"],
            })
        super().launch(self.wan, "provider", self.args.provider, "-dat-dir", self.data,
                       f"{WAN}:8444", cert, nodes, self.directory / "profile.json",
                       RETRY_SUB, nodes, self.directory / "retry-profile.json")
        super().launch(self.wan, "dnsmasq", "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null",
                       "--user=root", "--no-resolv", "--no-hosts", "--bind-interfaces", f"--listen-address={WAN}",
                       "--local-ttl=120", f"--addn-hosts={self.directory / 'hosts'}")

        def ready():
            self.healthy()
            self.execute(self.router, "curl", "--noproxy", "*", "-fsS", "--max-time", "2",
                         "--cacert", cert, PROVIDER + "/healthz")
            return True

        scenario.wait_for(ready, 10, "local HTTPS provider")
        return cert

    def request(self, path, *args, **kwargs):
        return self.execute(self.router, "curl", "--noproxy", "*", "--fail-with-body",
                            "--silent", "--show-error", "--max-time", "65", *args,
                            "http://127.0.0.1:8086" + path, timeout=70, **kwargs)

    def apply_source(self, path):
        config = self.api("config")
        source = {"id": SOURCE, "url": PROVIDER + path}
        config["subscriptions"] = [source]
        config["networks"][0]["target"] = f"subscription:{SOURCE}:auto"
        config["provider_rules"] = {"source": SOURCE, "off": not self.enabled}
        old = set(self.snapshots.glob("snapshots-*.json"))
        applied = json.loads(self.request("/api/config", "-X", "PUT", "-H", "Content-Type: application/json",
                                          "--data-binary", "@-", input=json.dumps(config)))
        require(applied["subscriptions"][0]["url"] == source["url"]
                and applied["provider_rules"].get("off", False) == (not self.enabled),
                "Apply did not commit the requested source and rules toggle")
        new = set(self.snapshots.glob("snapshots-*.json")) - old
        require(len(new) == 1, "Apply did not save a fresh snapshot")
        return new.pop()

    def refresh(self):
        # The control API encodes the same config JSON as ConfigRevision,
        # followed by a newline. Use the revision-checked operator entry point.
        config = self.request("/api/config").removesuffix("\n")
        revision = sha256(config.encode()).hexdigest()
        code = self.request("/overview/refresh", "--data-urlencode", "rev=" + revision,
                            "-o", "/dev/null", "-w", "%{http_code}")
        require(code == "303", "subscription refresh was not queued")

    def requests(self):
        rows = (self.directory / "provider.log").read_text().splitlines()
        return Counter(row.split()[-1] for row in rows if " GET " in row and not row.endswith(" /healthz"))

    def write_neighbor(self, address):
        next_path = self.arp.with_suffix(".new")
        next_path.write_text("IP address HW type Flags HW address Mask Device\n"
                             f"{address} 0x1 0x2 {NEIGHBOR_MAC} * lan0\n")
        next_path.replace(self.arp)

    def audit(self, target, actor):
        return self.api(f"journal/audit?target={target}&actor={actor}&limit=32")["entries"] or []

    def recompile_neighbors(self, evidence):
        for n in range(NEIGHBOR_CHANGES):
            address = f"192.168.77.{120 + n}"
            self.write_neighbor(address)

            def compiled():
                self.healthy()
                return next((row for row in self.audit("clients", "watchdog")
                             if row["action"] == "Device addresses updated"
                             and row["details"].startswith(f"added: {address} ({NEIGHBOR_MAC});")), None)

            evidence.append(scenario.wait_for(compiled, 10, f"watchdog recompile for {address}"))

    def dns_under_load(self, evidence):
        traffic = self.start_traffic()
        before = json.loads(traffic[1].read_bytes())
        block = "0.0.0.0" if self.enabled else "198.19.0.1"
        received = int(self.execute(self.client, self.args.load, "dns", "192.168.77.1:53", block, timeout=50))
        after = json.loads(traffic[1].read_bytes())
        scenario.validate_traffic(after, 32)
        scenario.active_connections(self.stats(), loaded=True)
        self.udp_progress.observe(after)
        for protocol in ("tcp_bytes", "udp_bytes"):
            require(all(after[protocol][tag] > before[protocol][tag] for tag in scenario.TAGS),
                    "tunnel traffic did not advance during the DNS workload")
        require(received == DNS_NAMES, "could not verify all 4096 DNS names")
        evidence.update(verified_names=received, block_answer=block, traffic_before=before, traffic_after=after)
        key = sha256(b"direct:geosite:fixture").hexdigest()[:16]
        rule_set = self.directory / "rule-sets" / f"dns-{key}.json"
        if self.enabled:
            hosts = (self.directory / "hosts").read_text().splitlines()[:DNS_NAMES]
            addresses = {line.split()[0] + "/32" for line in hosts}
            require(len(addresses) == DNS_NAMES, "DNS fixture reused a response address")

            def all_observed():
                data = json.loads(rule_set.read_bytes())
                return set(data["rules"][0]["ip_cidr"]) == addresses

            scenario.wait_for(all_observed, 10, "provider DNS cache to publish all 4096 answers")
            evidence["provider_fallback_addresses"] = len(addresses)
        else:
            require(not rule_set.exists(), "rules-off run produced a provider DNS fallback set")
            evidence["provider_fallback_addresses"] = 0
        self.drain_tcp(traffic)
        evidence["traffic_drained"] = self.finish_traffic(traffic)


def exercise(fixture, measurement, evidence, control_wait):
    enabled, size = fixture.enabled, fixture.size

    def requests(expected):
        expected = {path: count for path, count in expected.items() if enabled or not path.startswith("/data/")}
        observed = fixture.requests()
        require(observed == expected, f"unexpected HTTPS requests: {dict(observed)} (expected {expected})")
        return dict(observed)

    with measurement.phase("first_apply"):
        path = fixture.apply_source(SUB)
    first = read_snapshot(path)
    expected = {SUB: 1, SITE: 1, IP: 1}
    evidence["first_apply"] = {"rules": check_rules(first, size, enabled), "requests": requests(expected)}

    stamp = file_stamp(path)
    with measurement.phase("refresh_reuse"):
        fixture.refresh()
        scenario.wait_for(lambda: file_stamp(path) != stamp, 30, "refreshed subscription snapshot")
    refreshed = read_snapshot(path)
    expected[SUB] += 1
    reused = check_rules(refreshed, size, enabled)
    require(refreshed["last_success"] != first["last_success"] and reused == evidence["first_apply"]["rules"],
            "refresh did not commit a new fetch using the same dat records")
    evidence["refresh_reuse"] = {"rules": reused, "requests": requests(expected)}

    retry_setup = time.monotonic()
    with measurement.phase("retry_setup_apply"):
        path = fixture.apply_source(RETRY_SUB)
    partial = read_snapshot(path)
    expected.update({RETRY_SUB: 1, SITE: 2, RETRY_IP: 1})
    evidence["retry_setup_apply"] = {"rules": check_rules(partial, size, enabled, expect_ip=False),
                                     "requests": requests(expected)}
    (fixture.data / "geoip.dat").replace(fixture.data / "retry-ip.dat")
    stamp = file_stamp(path)
    with measurement.phase("geo_retry"):
        started = time.monotonic()
        if enabled:
            scenario.wait_for(lambda: file_stamp(path) != stamp, 135, "scheduled geo-only retry")
            expected[RETRY_IP] += 1
        else:
            time.sleep(control_wait)
        retry_wait = time.monotonic() - started
    restored = read_snapshot(path)
    rules = check_rules(restored, size, enabled)
    require(not enabled or time.monotonic() - retry_setup >= 60, "geo retry ran before its initial backoff")
    require(restored["last_success"] == partial["last_success"]
            and rules.get("geosite") == evidence["retry_setup_apply"]["rules"].get("geosite"),
            "geo retry refetched the subscription or discarded reusable geosite data")
    require(enabled or file_stamp(path) == stamp, "rules-off control rewrote the subscription during retry wait")
    evidence["geo_retry"] = {"rules": rules, "wait_seconds": retry_wait, "requests": requests(expected)}

    evidence["neighbor_recompiles"] = []
    with measurement.phase("neighbor_recompiles"):
        fixture.recompile_neighbors(evidence["neighbor_recompiles"])

    evidence["dns_under_load"] = {}
    with measurement.phase("dns_under_load"):
        fixture.dns_under_load(evidence["dns_under_load"])

    before = read_snapshot(path)
    first_node, second_node = [node["id"] for node in before["nodes"]]
    selection = before.pop("selection")
    require(selection["node"] == first_node, "initial node was not selected before the outage")
    stamp, config = file_stamp(path), file_stamp(fixture.directory / "config.yaml")
    with measurement.phase("selection_save"):
        fixture.execute(fixture.wan, "/usr/sbin/iptables", "-w", "2", "-I", "INPUT", "-i", "eth0",
                        "-d", WAN, "-p", "tcp", "--dport", NODE_PORTS[0], "-j", "REJECT", "--reject-with", "tcp-reset")
        scenario.wait_for(lambda: file_stamp(path) != stamp, 25, "selection-only snapshot save")
    after = read_snapshot(path)
    selected = after.pop("selection")
    require(selected["node"] == second_node and selected["reason"] == "failure" and selected["at"] != selection["at"],
            "the scheduled health check did not persist the expected node failover")
    require(after == before and file_stamp(fixture.directory / "config.yaml") == config,
            "selection save changed the subscription payload or configuration")
    evidence["selection_save"] = {"before": selection, "after": selected, "snapshot_bytes": path.stat().st_size,
                                  "requests": requests(expected)}
    fixture.healthy()
    return retry_wait


def run_case(args, output, size, enabled, case, control_wait=None):
    cleanup = scenario.Cleanup()
    directory = Path("/tmp") / ("keenproxy-provider-" + uuid.uuid4().hex)
    stress.install_preserve(cleanup, directory, output, {})
    fixture = ProviderFixture(args, directory, cleanup, size, enabled)
    case.update(rules_on=enabled, success=False, phases={}, proc_samples={}, evidence={})
    try:
        directory.mkdir()
        fixture.setup()
        case["data"] = fixture.size
        case["identity"] = stress.capture_identity(fixture.daemon, stress.only_process(fixture, "sbserver"),
                                                   args.binary, args.server)
        measurement = Measurements(fixture, case)
        with measurement.phase("idle"):
            time.sleep(1)
        retry_wait = exercise(fixture, measurement, case["evidence"], control_wait)
        case["final_proc_sample"] = measurement.sample()
        require(not stress.exceeds_rss(case["final_proc_sample"]), "daemon RSS or VmHWM reached 384 MiB")
    except BaseException:
        case["failure"] = traceback.format_exc()
        raise
    finally:
        if directory.exists():
            stress.attempt(lambda: scenario.save_json(directory / "stats.json", fixture.stats_samples), case, "stats_error")
        cleanup_error = stress.attempt(cleanup.close, case, "cleanup_error")
    require(not cleanup_error and "stats_error" not in case, "provider evidence or cleanup failed")
    case["success"] = True
    return retry_wait


def run(args):
    os.umask(0o077)
    output = Path(args.output).resolve()
    result = {"schema_version": 1, "variant": "candidate", "scenario": "provider", "success": False,
              "limits": {"rss_hard_bytes": stress.HARD_RSS_BYTES, "soft_gomemlimit_bytes": GO_LIMIT},
              "cases": {}, "rules_on_minus_off": {}}
    try:
        for size in ("real", "limit"):
            on, off = {}, {}
            result["cases"][size] = {"on": on, "off": off}
            wait = run_case(args, output.with_name(f"{size}-on.json"), size, True, on)
            run_case(args, output.with_name(f"{size}-off.json"), size, False, off, wait)
            require(on["data"] == off["data"], "rules on/off runs used different synthetic input files")
            metrics = ("rss_bytes", "hwm_bytes", "heap_peak_bytes", "heap_allocated_bytes", "cpu_seconds")
            result["rules_on_minus_off"][size] = {
                phase: {key: values[key] - off["phases"][phase][key] for key in metrics}
                for phase, values in on["phases"].items()
            }
            print(f"ok   {size} provider memory with rules on and off", flush=True)
        result["success"] = True
    finally:
        scenario.save_json(output, result)
    print("PASS provider memory", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("binary", "server", "provider", "load", "output"):
        parser.add_argument("--" + arg, required=True)
    args = parser.parse_args()
    args.scenario = "wireguard"
    signal.signal(signal.SIGINT, stress.interrupt)
    signal.signal(signal.SIGTERM, stress.interrupt)
    run(args)


if __name__ == "__main__":
    main()
