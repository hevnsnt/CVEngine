"""No code or configuration carries the upstream project's name any more (1.5.0): the package is ``cvengine``, the variables CVENGINE_*,
the proxy configuration config/nginx/cvengine.conf, the certificates cvengine*.pem, the network cvengine_network.

The name may appear only where this list says why: the documentation and the licence texts, which credit the upstream project; the one
module that moves an older install to the new names (scripts/legacy_names.py) with its test; the migration history that recorded the old
column name; and the About page's credit to the upstream project with the tests that keep that credit word for word.
"""
import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORD = re.compile('re' + 'ngine', re.I)  # spelled in two parts so this file needs no entry of its own below

ALLOWED_FILES = {
    'CHANGELOG.md': 'release history: names what each release changed, in the words of that time',
    'LICENSE': 'the GPL text with the upstream copyright notice',
    'THIRD-PARTY.md': 'credits the upstream project',
    'CONTRIBUTORS.md': 'credits the upstream project and its contributors',
    'scripts/legacy_names.py': 'the one compatibility module: moves an install made before 1.5.0 to the new names',
    'web/tests/test_legacy_names.py': 'tests that move from the old names',
    'web/scanEngine/migrations/0001_initial.py': 'migration history: the column as it was created',
    'web/scanEngine/migrations/0009_rename_show_banner.py': 'the migration that renames that column',
}
ALLOWED_PREFIXES = {
    'docs/': 'documentation (it credits the upstream project and tells how older installs moved)',
    'README': 'the README and its translations credit the upstream project',
}
# (file, text on the line) pairs: the credit on the About page and the tests that keep it unchanged
ALLOWED_LINES = (
    ('web/cveFeed/templates/cveFeed/about.html', 'Built on '),
    ('web/cveFeed/templates/cveFeed/about.html', 'github.com/yogeshojha/'),
    ('web/tests/test_about_page.py', 'Yogesh Ojha, and still uses its code'),
    ('web/tests/test_about_page.py', "contributors page.\")"),
    ('web/tests/test_about_page.py', "['Built on "),
    ('web/tests/test_about_page.py', "'Built on "),
    ('web/tests/test_tenancy.py', 'assertContains(r, '),
)


def tracked_files():
    got = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(ROOT), 'ls-files', '-z'], capture_output=True)
    if got.returncode == 0 and got.stdout:
        return [p for p in got.stdout.decode().split('\0') if p]
    skip = {'.git', 'node_modules', '__pycache__', 'staticfiles', '.venv', 'venv'}
    found = []
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in skip]
        found += [os.path.relpath(os.path.join(folder, f), ROOT) for f in files]
    return found


def allowed_file(path):
    return path in ALLOWED_FILES or any(path.startswith(p) for p in ALLOWED_PREFIXES)


class NoLegacyNameTests(unittest.TestCase):
    def test_no_file_or_folder_is_named_after_the_upstream_project(self):
        named = [p for p in tracked_files() if WORD.search(p) and not allowed_file(p)]
        self.assertEqual(named, [], 'rename these files (git mv) to their cvengine names')

    def test_no_code_or_configuration_spells_the_upstream_name(self):
        found = []
        for path in tracked_files():
            if allowed_file(path):
                continue
            try:
                text = (ROOT / path).read_text(encoding='utf-8')
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                continue
            if not WORD.search(text):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if WORD.search(line) and not any(path == f and needle in line for f, needle in ALLOWED_LINES):
                    found.append(f'{path}:{number}: {line.strip()[:160]}')
        self.assertEqual(found, [], 'use the cvengine name; only scripts/legacy_names.py may know the old one (see the list at the top of this test)')

    def test_every_allowed_file_exists(self):
        for path in list(ALLOWED_FILES) + [f for f, _ in ALLOWED_LINES]:
            self.assertTrue((ROOT / path).is_file(), f'{path} is on the allow list but does not exist: take it off')

    def test_the_rename_left_no_old_package(self):
        self.assertFalse((ROOT / 'web' / ('re' + 'Ngine')).joinpath('settings.py').exists())
        self.assertTrue((ROOT / 'web' / 'cvengine' / 'settings.py').is_file())


if __name__ == '__main__':
    unittest.main()
