"""A CVE List entry whose defaultStatus is "affected" and that lists only the unaffected releases (Jenkins, CVE-2024-23897)."""
from django.test import SimpleTestCase

from cveFeed import correlation, intel

# the CNA's own affected entry of CVE-2024-23897, as published in the CVE List V5 record
JENKINS = {
    'defaultStatus': 'affected', 'product': 'Jenkins', 'vendor': 'Jenkins Project',
    'versions': [
        {'lessThan': '1.606', 'status': 'unaffected', 'version': '0', 'versionType': 'maven'},
        {'lessThan': '*', 'status': 'unaffected', 'version': '2.442', 'versionType': 'maven'},
        {'lessThan': '2.426.*', 'status': 'unaffected', 'version': '2.426.3', 'versionType': 'maven'},
        {'lessThan': '2.440.*', 'status': 'unaffected', 'version': '2.440.1', 'versionType': 'maven'},
    ],
}


class Fake:
    def __init__(self, affected):
        self.id, self.affected, self.kev = 1, affected, False


def matches(version, entry=JENKINS):
    cve = Fake(intel.convert_affected([entry]))
    index = correlation.build_product_index([cve])
    found = list(correlation._match_candidates('Jenkins', correlation.parse_version(version), correlation._norm('Jenkins'), index, {cve.id: cve}))
    return bool(found) and found[0][2] is True


class RangeTests(SimpleTestCase):
    def test_the_affected_releases_are_what_lies_between_the_unaffected_intervals(self):
        ranges = intel._ranges(JENKINS)
        self.assertEqual([(r.get('introduced'), r.get('fixed')) for r in ranges],
                         [('1.606', '2.426.3'), ('2.427', '2.440.1'), ('2.441', '2.442')])

    def test_the_order_the_entries_are_listed_in_does_not_matter(self):
        shuffled = {**JENKINS, 'versions': list(reversed(JENKINS['versions']))}
        self.assertEqual(intel._ranges(shuffled), intel._ranges(JENKINS))


class MatchTests(SimpleTestCase):
    def test_releases_before_the_fix_of_each_line_match(self):
        for version in ('1.606', '2.200', '2.426.2', '2.427', '2.440.0', '2.441'):
            self.assertTrue(matches(version), version)

    def test_the_fixed_releases_do_not(self):
        for version in ('1.500', '2.426.3', '2.426.9', '2.440.1', '2.440.5', '2.442', '2.500', '3.0'):
            self.assertFalse(matches(version), version)


class ShapeTests(SimpleTestCase):
    def test_an_entry_with_a_default_of_unaffected_is_read_as_before(self):
        entry = {'defaultStatus': 'unaffected', 'product': 'X', 'versions': [{'status': 'affected', 'version': '1.0', 'lessThan': '1.5'}]}
        self.assertEqual([(r.get('introduced'), r.get('fixed')) for r in intel._ranges(entry)], [('1.0', '1.5')])

    def test_an_unaffected_entry_that_is_one_exact_version_is_not_guessed_at(self):
        entry = {'defaultStatus': 'affected', 'product': 'X', 'versions': [{'status': 'unaffected', 'version': '2.0'}]}
        self.assertEqual(intel._ranges(entry), [])

    def test_an_inclusive_unaffected_bound_is_not_guessed_at(self):
        entry = {'defaultStatus': 'affected', 'product': 'X', 'versions': [{'status': 'unaffected', 'version': '0', 'lessThanOrEqual': '1.5'}]}
        self.assertEqual(intel._ranges(entry), [])

    def test_an_unreadable_bound_yields_nothing_rather_than_a_wrong_range(self):
        entry = {'defaultStatus': 'affected', 'product': 'X', 'versions': [{'status': 'unaffected', 'version': '0', 'lessThan': 'main'}]}
        self.assertEqual(intel._ranges(entry), [])

    def test_a_default_of_affected_with_no_unaffected_entries_adds_nothing(self):
        self.assertEqual(intel._ranges({'defaultStatus': 'affected', 'product': 'X', 'versions': []}), [])

    def test_an_entry_unaffected_from_the_first_release_to_a_fix_leaves_everything_after_it_affected_only_when_stated(self):
        entry = {'defaultStatus': 'affected', 'product': 'X', 'versions': [{'status': 'unaffected', 'version': '0', 'lessThan': '3.0'}]}
        self.assertEqual([(r.get('introduced'), r.get('fixed')) for r in intel._ranges(entry)], [('3.0', None)])
