#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build the opt-in KeenProxy Applications shortcut as an Entware package."""

import argparse
import gzip
import io
import tarfile
from pathlib import Path


SOURCE = Path(__file__).resolve().parent
PACKAGE = "keenproxy-app-card"
VERSION = "0.1.0-1"
SERVICE = "opt/etc/init.d/S97keenproxy-app-card"
ASSETS = f"opt/share/{PACKAGE}"


def archive(entries):
    """Write the gzip-wrapped tar members expected by Entware's opkg."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data, mode in entries:
                entry = tarfile.TarInfo(f"./{name}")
                entry.mode = mode
                entry.uname = entry.gname = "root"
                if data is None:
                    # Entware's extractor needs the package-owned directory first.
                    entry.type = tarfile.DIRTYPE
                    tar.addfile(entry)
                else:
                    entry.size = len(data)
                    tar.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


def hook(operation):
    """Run a live service action only when opkg targets the running system."""
    return (
        "#!/bin/sh\n"
        "case \"${IPKG_INSTROOT:-}\" in\n"
        f"    ''|/) exec /{SERVICE} {operation} ;;\n"
        "esac\n"
    ).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="directory for the .ipk artifact")
    args = parser.parse_args()

    control = f"""Package: {PACKAGE}
Version: {VERSION}
Architecture: all
Section: net
Priority: optional
License: GPL-3.0-only
Description: KeenProxy shortcut for the stock KeeneticOS Applications page
""".encode()
    control_archive = archive([
        ("control", control, 0o644),
        ("postinst", hook("start"), 0o755),
        ("prerm", hook("stop"), 0o755),
    ])
    data_archive = archive([
        (SERVICE, (SOURCE / Path(SERVICE).name).read_bytes(), 0o755),
        (ASSETS, None, 0o755),
        (f"{ASSETS}/applications-card.css", (SOURCE / "applications-card.css").read_bytes(), 0o644),
        (f"{ASSETS}/applications-card.js", (SOURCE / "applications-card.js").read_bytes(), 0o644),
        (f"{ASSETS}/LICENSE", (SOURCE.parents[1] / "LICENSE").read_bytes(), 0o644),
    ])
    package = archive([
        ("debian-binary", b"2.0\n", 0o644),
        ("control.tar.gz", control_archive, 0o644),
        ("data.tar.gz", data_archive, 0o644),
    ])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"{PACKAGE}_{VERSION}_all.ipk"
    output.write_bytes(package)
    print(output)


if __name__ == "__main__":
    main()
