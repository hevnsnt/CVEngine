"""No source file carries an invisible or direction changing character as itself (CVE-2021-42574, "Trojan Source"): such a character makes
code read differently from what runs, and review tools show nothing. Where code needs one (a regex that strips them, a byte order mark), it
is written as an escape such as ``\\u202e``. The character classes that strip them still match exactly the same characters."""
import os
import re
import unittest

from django.conf import settings

HIDDEN = re.compile('[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u2028\u2029]')
TEXT = ('.py', '.js', '.mjs', '.html', '.css', '.sh', '.yml', '.yaml', '.md', '.txt', '.toml', '.cfg', '.conf')
SKIP_DIRS = {'.git', 'node_modules', '__pycache__'}


def _repo_root():
    return os.path.dirname(os.path.abspath(str(settings.BASE_DIR)))


def _ranges(*spans):
    out = set()
    for span in spans:
        lo, hi = (span, span) if isinstance(span, int) else span
        out.update(chr(c) for c in range(lo, hi + 1))
    return out


def _matched(pattern):
    return {chr(c) for c in range(0x10000) if not 0xD800 <= c <= 0xDFFF and pattern.search(chr(c))}


class NoHiddenCharacterTests(unittest.TestCase):
    def test_no_source_file_holds_an_invisible_or_bidirectional_character(self):
        root = _repo_root()
        found = []
        for top in ('web', 'scripts', 'reviewer', 'docs', '.github'):
            for folder, dirs, files in os.walk(os.path.join(root, top)):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    if not name.endswith(TEXT):
                        continue
                    path = os.path.join(folder, name)
                    with open(path, encoding='utf-8', errors='replace') as fh:
                        for number, line in enumerate(fh, 1):
                            for char in HIDDEN.findall(line):
                                found.append(f'{os.path.relpath(path, root)}:{number} U+{ord(char):04X}')
        self.assertEqual(found, [], 'write these characters as escapes (\\u200b, \\u202e, \\ufeff), never as themselves')


class StripClassesUnchangedTests(unittest.TestCase):
    """The classes now written with escapes match the same characters they matched when the characters were written as themselves."""

    BIDI_AND_SEPARATORS = ((0x200B, 0x200F), (0x2028, 0x202E), (0x2066, 0x2069), 0xFEFF)

    def test_alias_and_note_classes(self):
        from targetApp import alias_note
        controls = _ranges((0x00, 0x08), 0x0B, 0x0C, (0x0E, 0x1F), (0x7F, 0x9F))
        self.assertEqual(_matched(alias_note._BAD), controls | _ranges(*self.BIDI_AND_SEPARATORS))
        self.assertEqual(_matched(alias_note._BAD_LINE), _ranges((0x00, 0x1F), (0x7F, 0x9F), *self.BIDI_AND_SEPARATORS))

    def test_version_catalogue_class(self):
        from cveFeed import version_catalogue
        expected = _ranges((0x00, 0x1F), (0x7F, 0x9F), 0x2028, 0x2029, (0x200B, 0x200F), (0x202A, 0x202E), 0xFEFF)
        self.assertEqual(_matched(version_catalogue._CONTROL), expected)

    def test_banner_line_and_byte_order_mark(self):
        from agentapi import host_export
        from cveFeed import js_libraries
        self.assertEqual(host_export.BOM, '\ufeff')
        self.assertTrue(re.match(js_libraries._LINE + 'x', '\ufeff/*! x'))
        self.assertTrue(re.match(js_libraries._LINE + 'x', '/*! x'))
