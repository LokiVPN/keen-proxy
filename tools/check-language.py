#!/usr/bin/env python3
"""Check source language and keep product text independent of the release publisher."""
from pathlib import Path
import re
import subprocess
import sys

CYRILLIC = re.compile(r'[\u0400-\u052f\u1c80-\u1c8f\u2de0-\u2dff\ua640-\ua69f]')
SOURCE_MANIFEST = '.release-source-files'

BRAND_PARTS = ('loki', 'vpn')
SERVICE_BRAND = re.compile(r'[ \t_-]*'.join(BRAND_PARTS), re.IGNORECASE)
REPOSITORY_OWNER = ''.join(BRAND_PARTS)
REPOSITORY_URL = re.compile(
    rf'https://(?:github\.com|raw\.githubusercontent\.com)/{REPOSITORY_OWNER}/keen-proxy'
    rf'(?:/blob/master/RELEASING\.md#build-a-{REPOSITORY_OWNER}-release)?'
    r"(?=[/#?`\"')\s]|$)",
    re.IGNORECASE,
)

# These files describe or implement the GitHub release channel.
PUBLICATION_FILES = {
    '.github/workflows/release.yml',
    'AGENTS.md',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'README.md',
    'RELEASING.md',
    'docs/en/releases/index.md',
    'docs/ru/releases/index.md',
    'internal/update/manager_test.go',
    'internal/update/release.go',
    'test/install/test_bootstrap.py',
    'test/install/test_release_assets.py',
    'tools/bootstrap.sh',
}

# Mixed files may use the repository address. Their display text is checked.
REPOSITORY_LINK_FILES = {
    'docs/en/development.md',
    'docs/en/getting-started.md',
    'docs/ru/development.md',
    'docs/ru/getting-started.md',
    'internal/ui/templates/partials.html',
}


def allowed(path: Path) -> bool:
    """Declare the small set of intentionally Russian content locations."""
    if path.parts[:2] == ('docs', 'ru'):
        return True
    return path.parent == Path('locales') and path.name.endswith('.ru.yml')


def violations(root: Path, paths: list[Path]) -> list[str]:
    """Return language and brand diagnostics for source text."""
    root = root.resolve()
    found = []
    for path in paths:
        source = root / path
        if not source.is_file() or not source.resolve().is_relative_to(root):
            continue
        try:
            text = source.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        name = path.as_posix()
        check_cyrillic = not allowed(path)
        check_brand = name not in PUBLICATION_FILES
        allow_repo_url = name in REPOSITORY_LINK_FILES
        for number, line in enumerate(text.splitlines(), 1):
            if check_cyrillic and CYRILLIC.search(line):
                found.append(f'{name}:{number}: Cyrillic text outside Russian documentation/localization')
            if not check_brand or not SERVICE_BRAND.search(line):
                continue
            if allow_repo_url and not SERVICE_BRAND.search(REPOSITORY_URL.sub('', line)):
                continue
            found.append(f'{name}:{number}: Service brand in product text')
    return found


def source_paths(root: Path) -> list[Path] | None:
    """Read the Git file set or the tracked-file list packaged with a release."""
    if (root / '.git').exists():
        raw = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z'])
    else:
        manifest = root / SOURCE_MANIFEST
        if not manifest.is_file():
            return None
        raw = manifest.read_bytes()
    return [Path(name) for name in raw.decode().split('\0') if name]


def main() -> int:
    """Scan source files without walking local reports or secrets."""
    root = Path(__file__).resolve().parents[1]
    paths = source_paths(root)
    if paths is None:
        print('Source language check skipped: no Git checkout or release file list')
        return 0
    found = violations(root, paths)
    for diagnostic in found:
        print(diagnostic, file=sys.stderr)
    if not found:
        print('Source language check passed')
    return int(bool(found))


if __name__ == '__main__':
    raise SystemExit(main())
