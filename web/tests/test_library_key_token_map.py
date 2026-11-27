"""detection.library_key builds its token map of cveFeed.js_libraries.LIBRARIES once per process instead of on every call. The answers must
stay exactly those of the old per call map, and the cost of a call must no longer grow with the size of the table. Cost is counted as calls
of detection._token (deterministic), never by wall clock."""
import re
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import detection


def _old_library_key(name):
    """library_key as it was before the map was held: the whole token map built again on every call."""
    tokens = {detection._token(n): key for key, (product, _s, _d) in detection._libraries().items() for n in (key, product)}
    raw = str(name or '').strip().lower()
    found = tokens.get(detection._token(raw), '')
    if not found and re.search(r'[/:]', raw):
        found = tokens.get(detection._token(re.split(r'[/:]', raw)[-1]), '')
    return found


def _names():
    """Every key and product name in several spellings and packagings, plus names that are not a library. Sorted, so the order is fixed."""
    names = {'', None, 'jquery-validation', 'jquery-rails', '@angular/core', 'lodash.merge', 'not-a-library', 'org.webjars.npm:jquery',
             'components/jquery', 'Vue.js', 'jquery_ui'}
    for key, (product, _s, _d) in detection._libraries().items():
        for n in (key, product):
            names.update({n, n.upper(), n.title(), f' {n} ', n.replace('-', '_'), n.replace(' ', '.'), f'components/{n}',
                          f'org.webjars.npm:{n}', f'{n}-plugin', f'@scope/{n}'})
    return sorted(names, key=lambda n: (n is None, str(n)))


class LibraryKeyTokenMapTests(SimpleTestCase):
    def setUp(self):
        # Start every test from an empty held map (create=True so the test also runs, and fails, on the code before the change).
        patcher = mock.patch.object(detection, '_TOKENS', (None, {}), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_same_answer_as_the_per_call_map_for_every_name(self):
        names = _names()
        self.assertGreater(len(names), 100)
        self.assertEqual([detection.library_key(n) for n in names], [_old_library_key(n) for n in names])
        self.assertEqual(detection.library_key('jQuery'), 'jquery')
        self.assertEqual(detection.library_key('org.webjars.npm:jquery'), 'jquery')
        self.assertEqual(detection.library_key('jquery-rails'), '')

    def test_map_is_built_once_not_per_call(self):
        table_names = 2 * len(detection._libraries())
        detection.library_key('warm up')
        with mock.patch.object(detection, '_token', wraps=detection._token) as token:
            for _ in range(100):
                detection.library_key('jQuery')
                detection.library_key('components/jquery')
        # After the change each call tokenises only the name it was given (once, or twice for a packaging): 300 for these 200 calls.
        # Before it, every call also tokenised every key and product of the table again: 200 times (table_names + 1) or more.
        self.assertEqual(token.call_count, 300)
        self.assertLess(token.call_count, 200 * (table_names + 1))

    def test_a_different_table_gets_its_own_map(self):
        self.assertEqual(detection.library_key('jQuery'), 'jquery')
        other = {'foolib': ('Foo Lib', None, None)}
        with mock.patch.object(detection, '_libraries', return_value=other):
            self.assertEqual(detection.library_key('Foo-Lib'), 'foolib')
            self.assertEqual(detection.library_key('jQuery'), '')
        self.assertEqual(detection.library_key('jQuery'), 'jquery')
