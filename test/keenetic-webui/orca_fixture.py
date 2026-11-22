"""Serve comparable stock and patched firmware assets for Orca screenshots."""

import argparse
from contextlib import ExitStack
import hashlib
from http.server import ThreadingHTTPServer
import mimetypes
from pathlib import Path
from threading import Event, Thread
from urllib.parse import urlsplit

from full_bootstrap import Fixture, Scenario, SESSION, handler_for
from probe import patch_bundle


FIRMWARE = "06ce78bd2cd0b4521c45f511eecf84ec0c868f3933a1736204505ebde7517a8c"
MAIN = "/main-545548A.js"
MAIN_DIGEST = "67eff6ec79ddea853a7ed383fc7cc37d41e1b93d90ea9eb0260973d1ba5e224f"
STYLES = "/styles-545548A.css"
POLYFILLS = "/polyfills-545548A.js"
WORKER = "/worker-G5Z4KKB2.js"
DOCROOT = "/usr/share/htdocs_"

HTML = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<base href="/"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="{STYLES}"></head><body><ndw-root></ndw-root>
<script type="module" src="{POLYFILLS}"></script>
<script type="module" src="{MAIN}"></script></body></html>""".encode()


def archive_assets(path):
    """Load regular WebUI resources from the pinned public firmware image."""
    from PySquashfsImage import SquashFsImage

    firmware = path.read_bytes()
    if hashlib.sha256(firmware).hexdigest() != FIRMWARE:
        raise ValueError("Unexpected archive fingerprint")
    paths = (MAIN, STYLES, POLYFILLS, WORKER)
    assets = {}
    with SquashFsImage.from_bytes(firmware[firmware.index(b"hsqs"):]) as image:
        for entry in image:
            if not entry.path.startswith(DOCROOT + "/") or entry.is_dir or entry.is_symlink:
                continue
            name = entry.path.removeprefix(DOCROOT)
            if name in paths or name.startswith("/assets/"):
                assets[name] = entry.read_bytes()
    if hashlib.sha256(assets[MAIN]).hexdigest() != MAIN_DIGEST:
        raise ValueError("Unexpected WebUI fingerprint")
    return assets


def visual_handler(source, scenario, assets):
    """Use the regular loopback HTTP fixture with the archive's static assets."""
    bundle = source.encode()
    fixture = Fixture(source, "visual", scenario)
    base = handler_for(fixture)

    class Handler(base):
        def do_GET(self):
            path = urlsplit(self.path).path
            if path in ("/", "/dashboard", "/keenproxy", "/login", "/opkg"):
                headers = {"Set-Cookie": SESSION} if scenario.authenticated else None
                self.write(200, "text/html", HTML, headers)
            elif path == MAIN:
                self.write(200, "text/javascript", bundle)
            elif path in assets:
                mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
                self.write(200, mime, assets[path])
            else:
                super().do_GET()

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path, required=True)
    args = parser.parse_args()
    assets = archive_assets(args.firmware)
    stock = assets[MAIN].decode()
    candidate = patch_bundle(stock)
    cases = (
        ("stock", stock, Scenario(path="/opkg", status=200)),
        ("admin", candidate, Scenario(path="/opkg", status=200)),
        ("readonly", candidate, Scenario(role="readonly")),
    )
    with ExitStack() as stack:
        servers = []
        for name, source, scenario in cases:
            handler = visual_handler(source, scenario, assets)
            server = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), handler))
            servers.append(server)
            Thread(target=server.serve_forever, daemon=True).start()
            print(f"{name} http://127.0.0.1:{server.server_port}{scenario.path}", flush=True)
        try:
            Event().wait()
        except KeyboardInterrupt:
            for server in servers:
                server.shutdown()


if __name__ == "__main__":
    main()
