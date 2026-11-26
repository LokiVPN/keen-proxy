"""Check source language and brand policy using synthetic UTF-8 files."""
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).absolute().parents[2] / 'tools/check-language.py'
spec = importlib.util.spec_from_file_location('check_language', SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class LanguagePolicyTest(unittest.TestCase):
    def test_reports_source_line_and_accepts_escaped_unicode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sample.go').write_text('package sample\n// \u041f\u0440\u0438\u043c\u0435\u0440\n')
            self.assertEqual(checker.violations(root, [Path('sample.go')]), [
                'sample.go:2: Cyrillic text outside Russian documentation/localization',
            ])
            (root / 'sample.go').write_text(r'var fixture = "\u041f\u0440\u0438\u043c\u0435\u0440"')
            self.assertEqual(checker.violations(root, [Path('sample.go')]), [])

    def test_only_russian_documentation_and_localization_are_allowed(self):
        for path in ['docs/ru/user-guide.md', 'locales/mkdocs.ru.yml']:
            self.assertTrue(checker.allowed(Path(path)), path)
        for path in ['docs/en/user-guide.md', 'internal/config.go', 'tools/helper.py', 'locales/mkdocs.en.yml', 'tools/example.ru.yml']:
            self.assertFalse(checker.allowed(Path(path)), path)

    def test_binary_assets_are_not_source_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'image.png').write_bytes(b'\x89PNG\xff')
            self.assertEqual(checker.violations(root, [Path('image.png')]), [])
            self.assertEqual(checker.violations(root, [Path('missing.go')]), [])
            (root / 'docs/ru').mkdir(parents=True)
            (root / 'docs/ru/guide.md').write_text('\u041f\u0440\u0438\u043c\u0435\u0440')
            self.assertEqual(checker.violations(root, [Path('docs/ru/guide.md')]), [])

    def test_cli_exit_status_reports_policy_violations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            source = root / 'sample.go'
            with patch.object(checker, '__file__', str(root / 'tools/check-language.py')), patch.object(checker.subprocess, 'check_output', return_value=b'sample.go\0'), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
                source.write_text('// \u041f\u0440\u0438\u043c\u0435\u0440\n')
                self.assertEqual(checker.main(), 1)
                self.assertNotIn("Source language check passed", output.getvalue())
                source.write_text('// English\n')
                self.assertEqual(checker.main(), 0)
                self.assertIn("Source language check passed", output.getvalue())

    def test_cli_rejects_service_brand_in_product_text(self):
        brand = 'Loki' + 'VPN'
        spaced_brand = 'LoKi ' 'vPn'
        repo = f'https://github.com/{brand}/keen-proxy'
        files = {
            'locales/ui.en.yml': f'title: "{brand}"\n',
            'locales/ui.ru.yml': f'title: "\u041f\u0440\u0438\u043c\u0435\u0440 {spaced_brand}"\n',
            'internal/ui/setup_view.go': f'const title = "{brand.lower()}"\n',
            'internal/ui/templates/partials.html': (
                f'<a href="{repo}/blob/master/docs/en/user-guide.md">Help</a>\n'
                f'<a href="{repo}/blob/master/docs/en/user-guide.md">{brand} Help</a>\n'
            ),
            'docs/en/getting-started.md': (
                f'[GitHub Releases]({repo}/releases)\n'
                f'Install from [GitHub Releases]({repo}/releases) with your {brand} account.\n'
                f'[Another repository]({repo}-other)\n'
            ),
            'docs/en/development.md': f'[Release]({repo}/blob/master/RELEASING.md#build-a-{brand.lower()}-release)\n',
            'docs/ru/user-guide.md': f'\u041f\u0440\u0438\u043c\u0435\u0440: {brand}\n',
            'docs/assets/network-flow.svg': f'<text>{brand}</text>\n',
            '.serena/memories/core.md': f'Test fixture: {brand}\n',
            '.github/workflows/release.yml': f'if: github.repository == "{brand}/keen-proxy"\n',
            'RELEASING.md': f'Build a {brand} release\n',
            'docs/en/releases/index.md': f'Use GitHub Releases for the {brand} builds.\n',
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, content in files.items():
                source = root / path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(content, encoding='utf-8')
            (root / '.release-source-files').write_bytes(('\0'.join(files) + '\0').encode())
            with (
                patch.object(checker, '__file__', str(root / 'tools/check-language.py')),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(checker.main(), 1)
                self.assertCountEqual([line.rsplit(': ', 1)[0] for line in errors.getvalue().splitlines()], [
                    'locales/ui.en.yml:1',
                    'locales/ui.ru.yml:1',
                    'internal/ui/setup_view.go:1',
                    'internal/ui/templates/partials.html:2',
                    'docs/en/getting-started.md:2',
                    'docs/en/getting-started.md:3',
                    'docs/ru/user-guide.md:1',
                    'docs/assets/network-flow.svg:1',
                    '.serena/memories/core.md:1',
                ])

    def test_release_archive_uses_manifest_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.release-source-files').write_bytes(b'sample.go\0')
            (root / 'local.txt').write_text('\u041f\u0440\u0438\u043c\u0435\u0440\n')
            source = root / 'sample.go'
            with patch.object(checker, '__file__', str(root / 'tools/check-language.py')), patch.object(checker.subprocess, 'check_output', side_effect=AssertionError('Git must not run in archives')), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                source.write_text('// English\n')
                self.assertEqual(checker.main(), 0)
                source.write_text('// \u041f\u0440\u0438\u043c\u0435\u0440\n')
                self.assertEqual(checker.main(), 1)

    def test_archive_without_file_list_does_not_scan_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(checker, '__file__', str(root / 'tools/check-language.py')), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(checker.main(), 0)
                self.assertIn('Source language check skipped', output.getvalue())
