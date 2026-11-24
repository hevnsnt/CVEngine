"""No source file carries an invisible or bidirectional control character as a raw character.

A right-to-left override or isolate (U+202A to U+202E, U+2066 to U+2069) in source makes an editor or a code review page show the text in another
order than the interpreter reads it ("Trojan Source", CVE-2021-42574), and a zero-width character or byte order mark is invisible altogether.
Code that strips or tests these characters writes them as escapes (``\\u202e``), which read the same to Python, JavaScript and the regular
expression engines and show what they are to a reviewer. Pictures and other binary files are not text and are skipped.
"""
import re
import unittest

from tests.test_no_legacy_name import ROOT, tracked_files

INVISIBLE = re.compile('[\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]')


class NoInvisibleCharacterTests(unittest.TestCase):
    def test_no_source_file_holds_a_raw_invisible_or_bidirectional_character(self):
        found = []
        for path in tracked_files():
            try:
                text = (ROOT / path).read_text(encoding='utf-8')
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                continue
            for number, line in enumerate(text.split('\n'), 1):
                for match in INVISIBLE.finditer(line):
                    found.append(f'{path}:{number}: U+{ord(match.group(0)):04X}')
        self.assertEqual(found, [], 'write these characters as escapes (\\u202e), never as the raw character')

    def test_the_pattern_covers_the_trojan_source_characters(self):
        for code in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200B, 0x200F, 0x2028, 0xFEFF):
            self.assertTrue(INVISIBLE.fullmatch(chr(code)), hex(code))
        self.assertIsNone(INVISIBLE.search('plain text, tab\tand newline\n'))


if __name__ == '__main__':
    unittest.main()
