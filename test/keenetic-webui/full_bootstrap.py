"""Run the saved KeeneticOS WebUI against a disposable HTTP/RCI fixture."""

import argparse
from dataclasses import dataclass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import urlsplit

from probe import PROFILES, patch_bundle


HERE = Path(__file__).resolve().parent
ZONE_DIGEST = "71d535d91e868fff82124d19ac13ff2a5e98a2e38ef42f40f1c33e601158a034"
USER = "fixture-user"
REALM = "local-fixture"
PASSWORD = "fixture-password"
CHALLENGE = "00000000000000000000000000000000"
SESSION = "ndw-fixture-session=local; Path=/; HttpOnly; SameSite=Strict"
AUTH_CHALLENGE = {
    "WWW-Authenticate": 'Fixture realm="local-fixture"',
    "X-NDM-Challenge": CHALLENGE,
    "X-NDM-Realm": REALM,
}
HTML = b"""<!doctype html><html lang="en"><head><meta charset="utf-8"><base href="/">
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><ndw-root></ndw-root><script src="/zone.js"></script>
<script type="module" src="/bundle.js"></script><script src="/scenario.js"></script></body></html>"""

STATUS_TEXT = {
    200: "Configured connections: 3",
    401: "KeenProxy sign-in required",
    403: "KeenProxy access denied",
    503: "KeenProxy is unavailable",
}


@dataclass(frozen=True)
class Scenario:
    path: str = "/keenproxy"
    role: str = "admin"
    authenticated: bool = True
    status: int | None = None
    available_components: tuple[str, ...] = ()


SCENARIOS = {
    "sidebar": Scenario(path="/opkg", status=200),
    "direct": Scenario(status=200),
    "login": Scenario(authenticated=False, status=200),
    "anonymous": Scenario(authenticated=False),
    "readonly": Scenario(role="readonly"),
    "manager": Scenario(role="manager"),
    "demo": Scenario(role="demo", status=403),
    "api-401": Scenario(status=401),
    "api-403": Scenario(status=403),
    "api-503": Scenario(status=503),
    "leave": Scenario(),
}


class Fixture:
    """Serve the router-facing requests from the saved app using synthetic data."""

    def __init__(self, source, name, scenario, zone=None):
        self.scenario = scenario
        settings = json.dumps({"name": name, "statusText": STATUS_TEXT.get(scenario.status)})
        self.assets = {
            "/bundle.js": source.encode("utf-8"),
            "/scenario.js": f"window.fixtureScenario = {settings};\n".encode()
                            + (HERE / "bootstrap_scenarios.js").read_bytes(),
        }
        if zone is not None:
            self.assets["/zone.js"] = zone
        self.requests = []
        self.rci_commands = set()
        self.logins = 0

    def rci_batch(self, queries):
        """Mirror each nested RCI command path in the corresponding response."""
        responses = []
        for query in queries:
            path = []
            while isinstance(query, dict) and len(query) == 1:
                key, value = next(iter(query.items()))
                if not isinstance(value, dict):
                    break
                path.append(key)
                query = value
            data = self.rci(".".join(path))
            for key in reversed(path):
                data = {key: data}
            responses.append(data)
        return responses

    def rci(self, command):
        self.rci_commands.add(command)
        if command == "components.list" and self.scenario.available_components:
            return {"component": {name: {} for name in self.scenario.available_components}}
        restricted_tag = {"readonly": "readonly", "manager": "manager", "demo": "readonly"}
        tags = ["http", "cli"]
        if self.scenario.role in restricted_tag:
            tags.append(restricted_tag[self.scenario.role])
        return {
            "whoami": {"user": USER, "password": "normal", "demo-mode": self.scenario.role == "demo"},
            "show.sc.user": {USER: {"tag": tags}},
            "show.last-change": {},
        }.get(command, {})


def handler_for(fixture):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def write(self, status, content_type, body, headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def reply(self, data, status=200, headers=None):
            self.write(status, "application/json", json.dumps(data).encode(), headers)

        def authenticated(self):
            return "ndw-fixture-session=local" in self.headers.get("Cookie", "").split("; ")

        def do_GET(self):
            path = urlsplit(self.path).path
            fixture.requests.append((self.command, path))
            if path in fixture.assets:
                self.write(200, "text/javascript", fixture.assets[path])
                return
            if path in ("/", "/opkg", "/login", "/dashboard", "/keenproxy"):
                headers = {"Set-Cookie": SESSION} if fixture.scenario.authenticated else None
                self.write(200, "text/html", HTML, headers)
                return
            if path == "/auth":
                if self.authenticated():
                    self.reply({"method": "x-ndw2-interactive"})
                else:
                    self.reply({}, 401, AUTH_CHALLENGE)
                return
            if path.startswith("/rci/"):
                if not self.authenticated():
                    self.reply({}, 401, AUTH_CHALLENGE)
                    return
                self.reply(fixture.rci(path.removeprefix("/rci/").replace("/", ".")))
                return
            if path == "/keenproxy-api/status":
                status = (fixture.scenario.status or 403) if self.authenticated() else 401
                data = {"connections": 3} if status == 200 else {"error": "Synthetic HTTP error"}
                self.reply(data, status)
                return
            if path in ("/ndmFeatures.json", "/ndmConstants.json") and not self.authenticated():
                self.reply({}, 401, AUTH_CHALLENGE)
                return
            data = {
                "/ndmContacts.json": {"contacts": {}, "model": "Keenetic Hopper SE"},
                "/ndmLanguages.json": {"profile": {"languages": {"en": "English"}}, "LANGUAGES_ORDER": ["en"]},
                "/ndmFeatures.json": {"features": {}},
                "/ndmConstants.json": {
                    "mode": "router", "model": "Keenetic Hopper SE", "USB_PORTS_NUMBER": 1,
                    "components": {"storage": True, "opkg": True},
                },
            }
            if path in data:
                self.reply(data[path])
            elif path.startswith("/assets/language/") and path.endswith(".json"):
                self.reply({
                    "menu": {"control": "Management", "opkg": "OPKG", "dashboard": "Dashboard"},
                    "login": {"title": "Sign in", "form": {
                        "login": "Username", "password": "Password", "login-button": "Sign in",
                    }},
                    "stay-leave": {"stay": "Stay", "leave": "Leave"},
                    "confirm-cancelling-changes": "Discard unsaved changes?",
                })
            else:
                self.send_error(404)

        def do_POST(self):
            path = urlsplit(self.path).path
            fixture.requests.append((self.command, path))
            try:
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except (ValueError, TypeError):
                self.reply({"error": "Invalid fixture input"}, 400)
                return
            if path == "/auth":
                # Match only the known test account and its synthetic challenge.
                digest = hashlib.md5(f"{USER}:{REALM}:{PASSWORD}".encode()).hexdigest()
                expected = hashlib.sha256((CHALLENGE + digest).encode()).hexdigest()
                if data != {"login": USER, "password": expected}:
                    self.reply({}, 401, AUTH_CHALLENGE)
                    return
                fixture.logins += 1
                self.reply({}, headers={"Set-Cookie": SESSION})
            elif path.startswith("/rci/") and not self.authenticated():
                self.reply({}, 401, AUTH_CHALLENGE)
            elif path == "/rci/" and isinstance(data, list):
                self.reply(fixture.rci_batch(data))
            elif path.startswith("/rci/"):
                self.reply(fixture.rci(path.removeprefix("/rci/").replace("/", ".")))
            else:
                self.send_error(404)

    return Handler


def run(browser, source, zone, name, baseline, verbose):
    scenario = SCENARIOS[name]
    fixture = Fixture(source, name, scenario, zone)
    with ThreadingHTTPServer(("127.0.0.1", 0), handler_for(fixture)) as server:
        Thread(target=server.serve_forever, daemon=True).start()
        with TemporaryDirectory(prefix="keenproxy-bootstrap-") as profile:
            try:
                result = subprocess.run(
                    [browser, "--dump-dom", "--virtual-time-budget=16000", "--disable-gpu",
                     "--disable-background-networking", "--disable-background-timer-throttling",
                     "--window-size=1440,1000", f"--user-data-dir={profile}",
                     f"http://127.0.0.1:{server.server_port}{scenario.path}"],
                    capture_output=True, text=True, check=True, timeout=35,
                )
            finally:
                server.shutdown()
    match = re.search(r'data-proof="([^"]*)"', result.stdout)
    observed = match[1] if match else "no-result"
    expected = "missing-native-menu-link" if baseline else name + "-passed"
    if observed != expected or verbose:
        print("Observed:", observed)
        print("HTTP:", sorted(set(fixture.requests))[:45])
        print("RCI:", sorted(fixture.rci_commands))
        errors = [line for line in result.stderr.splitlines() if "CONSOLE" in line]
        for line in dict.fromkeys(errors):
            print(line[:400])
    if observed != expected:
        body = result.stdout.split("<ndw-root", 1)[-1]
        raise RuntimeError(f"Expected {expected}, got {observed}. Browser output: {body[:650]}")
    if fixture.logins != int(name == "login"):
        raise RuntimeError(f"{name}: unexpected number of successful test logins")
    count = fixture.requests.count(("GET", "/keenproxy-api/status"))
    if count != int(scenario.status is not None and not baseline):
        raise RuntimeError(f"{name}: unexpected status request count {count}")
    if name in ("readonly", "manager", "demo") and "show.sc.user" not in fixture.rci_commands:
        raise RuntimeError(f"{name}: the stock role check did not read user tags")
    print(observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--zone-js", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--case", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    bundle = args.bundle.read_bytes()
    if hashlib.sha256(bundle).hexdigest() not in PROFILES:
        raise ValueError("Unexpected firmware bundle")
    zone = args.zone_js.read_bytes()
    if hashlib.sha256(zone).hexdigest() != ZONE_DIGEST:
        raise ValueError("Expected the pinned Zone.js 0.15.1 browser fixture")
    source = bundle.decode("utf-8")
    if args.baseline:
        run(args.browser, source, zone, "sidebar", True, args.verbose)
    else:
        candidate = patch_bundle(source)
        for case in args.case or SCENARIOS:
            run(args.browser, candidate, zone, case, False, args.verbose)


if __name__ == "__main__":
    main()
