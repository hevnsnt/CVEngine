"""Version ranges at ingest: what is stored from a CVE List V5 record and from a cve.now entry, for the real records of Confluence
(CVE-2022-26134), Bitbucket (CVE-2022-36804), Juniper Junos (CVE-2023-36844..36847, CVE-2023-4481, CVE-2024-21591, CVE-2025-21590) and
Jenkins (CVE-2024-23897). The fixtures under tests/fixtures are trimmed copies of the real CVE List records (cve5/) and of the live cve.now
entries (cvenow/): only the fields the code reads were kept. Issues 205 (introduced and fixed in separate range objects, a branch lower bound
lost) and 210 (defaultStatus affected)."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import correlation, intel
from cveFeed.correlation import _vcmp, parse_version
from cveFeed.models import CVEEntry, MatchVerdict

FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def cve5(cve_id):
    return json.loads((FIXTURES / 'cve5' / f'{cve_id}.json').read_text())


def cvenow(cve_id):
    return json.loads((FIXTURES / 'cvenow' / f'{cve_id}.json').read_text())


def verdict(affected, name, version, cpe=''):
    """True / False / None for one host version against stored ``affected``, read exactly as correlation reads it; 'nomatch' when the CVE
    is not a candidate for the product at all."""
    cve = SimpleNamespace(id=1, cve_id='CVE-X', affected=affected, kev=True, epss_reached=None, exploit_db=None, cvss=9.8)
    index = correlation.build_product_index([cve])
    found = list(correlation._match_candidates(name, parse_version(version), correlation._norm(name), index, {1: cve}, cpe=cpe))
    return found[0][2] if found else 'nomatch'


def mismatches(affected, name, table, cpe_for=None):
    return [(version, expected, verdict(affected, name, version, cpe_for(version) if cpe_for else ''))
            for version, expected in table if verdict(affected, name, version, cpe_for(version) if cpe_for else '') is not expected]


def feed_from_api(cve_id, record=None, offline=True):
    """Store the live cve.now entry through ``CVEEntry.from_api``. The CVE List is unreachable unless ``record`` is given."""
    effect = RuntimeError('offline') if record is None else (lambda *a, **k: record)
    with mock.patch('cveFeed.intel.fetch_cve5', side_effect=effect):
        obj, _ = CVEEntry.from_api(cvenow(cve_id))
    return CVEEntry.objects.get(pk=obj.pk)


# ---------------------------------------------------------------------------------------------- Confluence (issue 205, second shape)

CONFLUENCE = [('7.4.16', True), ('7.4.17', False), ('7.12.0', False), ('7.13.0', True), ('7.13.6', True), ('7.13.7', False),
              ('7.14.0', True), ('7.14.2', True), ('7.14.3', False), ('7.15.0', True), ('7.15.1', True), ('7.15.2', False),
              ('7.16.3', True), ('7.16.4', False), ('7.17.3', True), ('7.17.4', False), ('7.18.0', True), ('7.18.1', False),
              ('7.19.0', False), ('8.0.0', False)]
CONFLUENCE_RANGES = [(None, '7.4.17'), ('7.13.0', '7.13.7'), ('7.14.0', '7.14.3'), ('7.15.0', '7.15.2'), ('7.16.0', '7.16.4'),
                     ('7.17.0', '7.17.4'), ('7.18.0', '7.18.1')]


def intro_fixed(ranges):
    return [(r.get('introduced'), r.get('fixed')) for r in ranges]


class ConfluenceTests(TestCase):
    def test_the_live_cvenow_entry_is_stored_as_one_range_per_branch_whether_or_not_the_cve_list_is_reachable(self):
        # cve.now writes "unspecified" for the bound a branch does not state, so the entry has `introduced 7.13.0, fixed unspecified` and
        # `introduced unspecified, fixed 7.13.7` as two ranges. The CVE List overlay does not fire for it (it is not a list of bare fixes), so
        # without a conversion at ingest every range was unreadable and the whole entry gave "unknown" for every version
        for record in (None, cve5('CVE-2022-26134')):
            entry = feed_from_api('CVE-2022-26134', record)
            for item in entry.affected:
                self.assertEqual(intro_fixed(item['ranges']), CONFLUENCE_RANGES, item['product'])

    def test_every_version_of_the_live_cvenow_entry_is_judged_on_both_sides_of_each_fix(self):
        entry = feed_from_api('CVE-2022-26134')
        self.assertEqual(mismatches(entry.affected, 'Confluence Server', CONFLUENCE), [])
        self.assertEqual(mismatches(entry.affected, 'Confluence Data Center', CONFLUENCE), [])
        self.assertEqual(mismatches(entry.affected, 'Confluence', CONFLUENCE, cpe_for=lambda v: f'cpe:/a:atlassian:confluence_server:{v}'), [])

    def test_the_cve_list_record_gives_the_same_ranges(self):
        fields = intel.entry_from_cve5(cve5('CVE-2022-26134'), {})
        for item in fields['affected']:
            self.assertEqual(intro_fixed(item['ranges']), CONFLUENCE_RANGES, item['product'])
        self.assertEqual(mismatches(fields['affected'], 'Confluence Server', CONFLUENCE), [])

    def test_bitbucket_cve_2022_36804_is_read_the_same_way(self):
        entry = feed_from_api('CVE-2022-36804')
        expected = [('7.0.0', '7.6.17'), ('7.7.0', '7.17.10'), ('7.18.0', '7.21.4'), ('8.0.0', '8.0.3'), ('8.1.0', '8.1.3'), ('8.2.0', '8.2.2'),
                    ('8.3.0', '8.3.1')]
        for item in entry.affected:
            self.assertEqual(intro_fixed(item['ranges']), expected, item['product'])
        table = [('7.0.0', True), ('7.6.16', True), ('7.6.17', False), ('7.17.9', True), ('7.17.10', False), ('8.3.0', True), ('8.3.1', False)]
        self.assertEqual(mismatches(entry.affected, 'Bitbucket Server', table), [])

    def test_a_branch_whose_fix_is_not_stated_stays_open_and_a_pair_that_is_not_one_is_not_joined(self):
        affected = [{'product': 'X', 'ranges': [{'introduced': '1.0', 'fixed': 'unspecified'}, {'introduced': '2.0', 'fixed': '2.5'}]}]
        out = intel.normalize_feed_ranges(affected)
        self.assertEqual(intro_fixed(out[0]['ranges']), [('1.0', None), ('2.0', '2.5')])
        # the fix of the second is older than the introduction of the first: not the same branch, so not joined
        backwards = [{'product': 'X', 'ranges': [{'introduced': '3.0', 'fixed': 'unspecified'}, {'introduced': 'unspecified', 'fixed': '2.5'}]}]
        self.assertEqual(intro_fixed(intel.normalize_feed_ranges(backwards)[0]['ranges']), [('3.0', None), (None, '2.5')])

    def test_ranges_with_no_placeholder_are_returned_untouched(self):
        affected = [{'product': 'X', 'ranges': [{'introduced': '1.0', 'fixed': '1.5'}, {'introduced': '2.0'}, {'fixed': '3.0'}]}, {'package': 'p'}]
        self.assertEqual(intel.normalize_feed_ranges(affected), affected)


# ---------------------------------------------------------------------------------------------- Junos (issue 205, the Junos KEVs)

def junos(*pairs):
    return list(pairs)


# every table lists versions on both sides of each fix; the expected answer is what the advisory's text says
J_36845 = [('19.4R3', True), ('20.4R3-S8', True), ('20.4R3-S9', False), ('20.4R3-S10', False), ('21.1R1', True), ('21.1R3', True),
           ('21.2R1', True), ('21.2R3-S6', True), ('21.2R3-S7', False), ('21.2R3-S8', False), ('21.3R1', True), ('21.3R3-S4', True),
           ('21.3R3-S5', False), ('21.4R3-S4', True), ('21.4R3-S5', False), ('22.1R3-S3', True), ('22.1R3-S4', False),
           ('22.2R3-S1', True), ('22.2R3-S2', False), ('22.3R1', True), ('22.3R2-S1', True), ('22.3R2-S2', False), ('22.3R2-S3', False),
           ('22.3R3', True), ('22.3R3-S1', False), ('22.3R3-S2', False), ('22.4R1', True), ('22.4R2', True), ('22.4R2-S1', False),
           ('22.4R2-S2', False), ('22.4R3', False), ('22.4R3-S1', False), ('23.2R1', True), ('23.2R1-S1', False), ('23.2R2', False),
           ('23.4R3', False), ('24.2R1', False), ('25.2R1', False)]
J_36844 = [('20.4R3-S8', True), ('20.4R3-S9', False), ('21.1R1', True), ('21.2R3-S5', True), ('21.2R3-S6', False), ('22.3R3', True),
           ('22.3R2-S2', True), ('22.3R3-S1', False), ('22.4R1', True), ('22.4R2-S1', True), ('22.4R2-S2', False), ('22.4R3', False),
           ('23.2R1', True), ('23.2R1-S1', False), ('23.2R2', False), ('24.2R1', False)]
J_36846 = [('20.4R3-S7', True), ('20.4R3-S8', False), ('21.1R2', True), ('21.2R3-S5', True), ('21.2R3-S6', False), ('22.1R3-S2', True),
           ('22.1R3-S3', False), ('22.3R1', True), ('22.3R2-S1', True), ('22.3R2-S2', False), ('22.3R3', False), ('22.4R2-S1', False),
           ('22.4R2', True), ('22.4R3', False), ('23.4R3', False), ('24.2R1', False)]
J_36847 = [('20.4R3-S7', True), ('20.4R3-S8', False), ('21.4R3-S3', True), ('21.4R3-S4', False), ('22.2R3', True), ('22.2R3-S1', False),
           ('22.3R2-S1', True), ('22.3R2-S2', False), ('22.3R3', False), ('22.4R2', True), ('22.4R2-S1', False), ('22.4R3', False),
           ('23.4R3', False), ('24.2R1', False), ('25.2R1', False)]
J_21591 = [('20.4R3-S8', True), ('20.4R3-S9', False), ('21.2R1', True), ('21.2R3-S6', True), ('21.2R3-S7', False), ('21.3R3-S4', True),
           ('21.3R3-S5', False), ('21.4R3-S4', True), ('21.4R3-S5', False), ('22.1R3-S3', True), ('22.1R3-S4', False), ('22.2R3-S2', True),
           ('22.2R3-S3', False), ('22.3R3-S1', True), ('22.3R3-S2', False), ('22.4R1', True), ('22.4R2-S1', True), ('22.4R2-S2', False),
           ('22.4R3', False), ('23.2R1', False), ('23.4R3', False), ('24.2R1', False)]
J_21590 = [('21.2R3-S8', True), ('21.2R3-S9', False), ('21.4R3-S9', True), ('21.4R3-S10', False), ('22.2R3-S5', True), ('22.2R3-S6', False),
           ('22.4R3-S5', True), ('22.4R3-S6', False), ('23.2R2-S2', True), ('23.2R2-S3', False), ('23.4R2-S3', True), ('23.4R2-S4', False),
           ('24.2R1', True), ('24.2R1-S1', True), ('24.2R1-S2', False), ('24.2R2', False), ('24.4R1', False), ('25.2R1', False)]
# "from 21.1R1 through 21.*" (all of release 21) and "from 21.4 before 21.4R3-S7 (unaffected from 21.4R3-S5, affected from 21.4R3-S6)"
J_4481 = [('20.4R3-S9', True), ('20.4R3-S10', False), ('21.1R1', True), ('21.1R3', True), ('21.4R3-S6', True), ('22.1R3-S3', True),
          ('22.1R3-S4', False), ('22.2R3-S2', True), ('22.2R3-S3', False), ('22.3R2', True), ('22.3R3', True), ('22.3R3-S1', False),
          ('22.4R2', True), ('22.4R3', False), ('23.2R1', True), ('23.2R2', False), ('24.2R1', False), ('25.2R1', False)]
J_4481_EVO = [('22.4R2-EVO', True), ('22.4R3-EVO', False), ('23.2R1-EVO', True), ('23.2R2-EVO', False), ('24.2R1-EVO', False)]

JUNOS_CVES = (('CVE-2023-36844', J_36844), ('CVE-2023-36845', J_36845), ('CVE-2023-36846', J_36846), ('CVE-2023-36847', J_36847),
              ('CVE-2024-21591', J_21591), ('CVE-2025-21590', J_21590), ('CVE-2023-4481', J_4481))


class JunosTests(TestCase):
    def test_the_cve_list_record_of_each_cve_is_judged_correctly_on_both_sides_of_every_fix(self):
        for cve_id, table in JUNOS_CVES:
            affected = intel.entry_from_cve5(cve5(cve_id), {})['affected']
            self.assertEqual(mismatches(affected, 'Junos OS', table), [], cve_id)

    def test_the_live_cvenow_entry_of_each_cve_is_judged_correctly_on_both_sides_of_every_fix(self):
        for cve_id, table in JUNOS_CVES:
            if cve_id == 'CVE-2024-21591':  # the live cve.now entry has no 22.4 branch at all (the CVE List record has one): not a conversion matter
                table = [(v, e) for v, e in table if not v.startswith('22.4')]
            if cve_id == 'CVE-2023-4481':  # the live cve.now entry keeps "from 21.1R1 through 21.*" as the open range {introduced 21.1R1}: it cannot
                table = [(v, e) for v, e in table if e or v.startswith('20.')]  # say where it ends, so only what it can say is asserted
            entry = feed_from_api(cve_id)
            self.assertEqual(mismatches(entry.affected, 'Junos OS', table), [], cve_id)

    def test_junos_os_evolved_of_cve_2023_4481(self):
        affected = intel.entry_from_cve5(cve5('CVE-2023-4481'), {})['affected']
        self.assertEqual(mismatches(affected, 'Junos OS Evolved', J_4481_EVO), [])
        self.assertEqual(mismatches(feed_from_api('CVE-2023-4481').affected, 'Junos OS Evolved', J_4481_EVO), [])

    def test_a_wildcard_branch_is_that_branch_and_a_comma_list_of_fixes_is_one_range_per_service_train(self):
        fields = intel.entry_from_cve5(cve5('CVE-2023-36845'), {})
        ranges = intro_fixed(fields['affected'][0]['ranges'])
        self.assertIn(('21.1', '21.2'), ranges)  # "21.1*": every 21.1 release
        self.assertIn(('22.3', '22.3R2-S2'), ranges)  # "22.3R2-S2, 22.3R3-S1": 22.3R2 before its fix ...
        self.assertIn(('22.3R3', '22.3R3-S1'), ranges)  # ... and 22.3R3 before its own
        self.assertIn(('22.4', '22.4R2-S1'), ranges)  # "22.4R2-S1, 22.4R3": 22.4R3 is the base release of the second fix, nothing before it
        self.assertIn(('23.2', '23.2R1-S1'), ranges)  # the record writes the branch "23,2"
        self.assertNotIn((None, '22.4R3'), ranges)
        for introduced, fixed in ranges:
            self.assertTrue(introduced is None or fixed, (introduced, fixed))  # no open range in the whole list

    def test_cve_2023_4481_reads_the_advisorys_own_text(self):
        # "from 21.1R1 through 21.*" is every release of 21; the other 21.x lines of the record overlap it
        ranges = intro_fixed(intel.entry_from_cve5(cve5('CVE-2023-4481'), {})['affected'][0]['ranges'])
        self.assertIn(('21.1R1', '22'), ranges)
        self.assertIn(('21.4', '21.4R3-S5'), ranges)
        self.assertIn(('21.4R3-S6', '21.4R3-S7'), ranges)

    def test_an_unreadable_comma_list_never_leaves_an_open_or_lower_unbounded_range(self):
        entry = {'product': 'X', 'versions': [{'version': '1.0', 'lessThan': '1.4.2, 1.5.1', 'status': 'affected'},
                                              {'version': 'next of 3', 'lessThan': '4.1, 4.2', 'status': 'affected'}]}
        ranges = intel._ranges(entry)
        # a list of plain fixes says only that nothing before the oldest is safe: that is the part that is certain
        self.assertEqual(intro_fixed(ranges), [('1.0', '1.4.2')])
        self.assertEqual(verdict([{'product': 'Xprod', 'ranges': ranges}], 'Xprod', '1.5.0'), False)
        self.assertEqual(verdict([{'product': 'Xprod', 'ranges': ranges}], 'Xprod', '1.3.0'), True)


# ---------------------------------------------------------------------------------------------- version ordering

class JunosVersionParsingTests(SimpleTestCase):
    def test_release_and_service_release_are_read(self):
        self.assertEqual(parse_version('21.2R1'), (21, 2, 1, 0))
        self.assertEqual(parse_version('22.4R2-S2'), (22, 4, 2, 2))
        self.assertEqual(parse_version('22.4R3'), (22, 4, 3, 0))
        self.assertEqual(parse_version('22.4R3-EVO'), (22, 4, 3, 0))
        self.assertEqual(parse_version('21.2R3-S7-EVO'), (21, 2, 3, 7))
        self.assertEqual(parse_version('21.2'), (21, 2))
        self.assertEqual(parse_version('24.2R1-S2', strict=True), (24, 2, 1, 2))

    def test_junos_releases_order_by_release_then_service_release(self):
        ascending = ['20.4R3-S9', '21.1', '21.1R1', '21.1R2', '21.2', '21.2R1', '21.2R1-S1', '21.2R1-S2', '21.2R2', '21.2R3-S6', '21.2R3-S7',
                     '21.2R3-S10', '21.3R1', '22.2R3-S6', '22.4R2-S1', '22.4R2-S2', '22.4R2-S10', '22.4R3', '22.4R3-S1', '23.2R1', '24.2R1-S2',
                     '24.2R2', '25.2R1']
        for lower, higher in zip(ascending, ascending[1:]):
            self.assertEqual(_vcmp(parse_version(lower), parse_version(higher)), -1, (lower, higher))

    def test_a_release_with_no_r_part_is_not_changed(self):
        for text in ('3.0R2', '1.2R3-S4', '21.2r3', '9.2.1R3', '21.2R', '2.4.1-R3'):
            self.assertEqual(parse_version(text), tuple(json.loads((FIXTURES / 'version_golden.json').read_text())['nonstrict'].get(text) or parse_version(text)), text)


class VersionOrderingRegressionTests(SimpleTestCase):
    """The parse of every common shape that is not a Junos release, recorded from the parser before the Junos form was added: unchanged."""

    golden = json.loads((FIXTURES / 'version_golden.json').read_text())

    def test_every_recorded_version_still_parses_to_the_same_tuple(self):
        for strict, key in ((False, 'nonstrict'), (True, 'strict')):
            for text, expected in self.golden[key].items():
                got = parse_version(text, strict=strict)
                self.assertEqual(None if got is None else list(got), expected, (text, strict))

    def test_common_shapes_still_order_the_way_they_always_did(self):
        sequences = [
            ['1.0', '1.0.1', '1.1', '1.2', '1.10', '2.0', '10.0'],
            ['2.0-alpha-1', '2.0-beta-1', '2.0-beta9', '2.0-rc1', '2.0'],
            ['1.0.2', '1.0.2a', '1.0.2k', '1.0.2zh', '1.1.0'],
            ['8.9', '8.9p1', '8.9p2', '9.0'],
            ['2.426.2', '2.426.3', '2.427', '2.440.1', '2.441', '2.442'],
            ['7.4.33', '8.0.0', '8.2.35', '8.3.36', '8.4.27'],
            ['2.4.57', '2.4.58', '2.4.58-1ubuntu1', '2.4.59'],
        ]
        for sequence in sequences:
            parsed = [parse_version(text) for text in sequence]
            for (lower, a), (higher, b) in zip(zip(sequence, parsed), zip(sequence[1:], parsed[1:])):
                self.assertLessEqual(_vcmp(a, b), 0, (lower, higher))

    def test_parse_is_total_and_never_raises_on_odd_text(self):
        for text in ('', ' ', 'R', 'R2', '21.2R', '21.2R-S1', '21.2R3-S', '21.2R3-Sx', '21.2R99999999999999999999', '..', '1..2', 'v', '٣.٤R5'):
            parse_version(text)
            parse_version(text, strict=True)


# ---------------------------------------------------------------------------------------------- Jenkins (issue 210)

JENKINS = [('1.605', False), ('1.606', True), ('2.200', True), ('2.425', True), ('2.426.2', True), ('2.426.3', False), ('2.426.4', False),
           ('2.427', True), ('2.439', True), ('2.440.0', True), ('2.440.1', False), ('2.440.3', False), ('2.441', True), ('2.442', False),
           ('2.500', False)]
JENKINS_CPE = lambda v: f'cpe:/a:jenkins:jenkins:{v}'  # noqa: E731 - what nmap prints


class JenkinsRepairTests(TestCase):
    def stored(self):
        return CVEEntry.objects.get(cve_id='CVE-2024-23897')

    def test_the_live_cvenow_entry_has_an_empty_jenkins_block(self):
        # the shape every other Jenkins test starts from: the feed's own Jenkins block states no range, next to the OSV jenkins-core blocks
        blocks = {a.get('product') or a.get('package'): a['ranges'] for a in cvenow('CVE-2024-23897')['affected']}
        self.assertEqual(blocks['Jenkins'], [])
        self.assertEqual(blocks['org.jenkins-ci.main:jenkins-core'], [{'introduced': '2.441', 'fixed': '2.442'}])

    def test_a_refresh_from_cvenow_does_not_replace_the_cve_list_ranges_with_the_empty_block(self):
        fields = intel.entry_from_cve5(cve5('CVE-2024-23897'), {})
        CVEEntry.objects.create(cve_id='CVE-2024-23897', sources=['CVE List V5'], **fields)
        before = [i for i in self.stored().affected if i.get('product') == 'Jenkins'][0]['ranges']
        self.assertEqual(intro_fixed(before), [('1.606', '2.426.3'), ('2.427', '2.440.1'), ('2.441', '2.442')])
        entry = feed_from_api('CVE-2024-23897')  # the refresh: the CVE List is not asked and the feed's Jenkins block is empty
        jenkins = [i for i in entry.affected if i.get('product') == 'Jenkins']
        self.assertEqual([i['ranges'] for i in jenkins], [before])
        self.assertIn('CVE List V5', entry.sources)
        self.assertEqual(mismatches(entry.affected, 'Jenkins', JENKINS), [])
        self.assertEqual(mismatches(entry.affected, 'Jenkins', JENKINS, cpe_for=JENKINS_CPE), [])

    def test_a_second_refresh_is_stable(self):
        CVEEntry.objects.create(cve_id='CVE-2024-23897', sources=['CVE List V5'], **intel.entry_from_cve5(cve5('CVE-2024-23897'), {}))
        first = feed_from_api('CVE-2024-23897').affected
        self.assertEqual(feed_from_api('CVE-2024-23897').affected, first)

    def test_a_refresh_keeps_the_feeds_own_ranges_when_it_has_them_and_when_nothing_better_is_stored(self):
        entry = feed_from_api('CVE-2024-23897')  # first sight of the entry: the empty block is all there is
        self.assertEqual([i['ranges'] for i in entry.affected if i.get('product') == 'Jenkins'], [[]])
        CVEEntry.objects.create(cve_id='CVE-2099-1', affected=[{'product': 'Widget', 'ranges': [{'introduced': '1.0', 'fixed': '1.5'}]}])
        feed = {'id': 'CVE-2099-1', 'affected': [{'product': 'Widget', 'ranges': [{'introduced': '1.0', 'fixed': '1.7'}]}]}
        obj, _ = CVEEntry.from_api(feed)
        self.assertEqual(obj.affected[0]['ranges'], [{'introduced': '1.0', 'fixed': '1.7'}])  # a feed range always wins over a stored one

    def test_a_stored_entry_with_empty_ranges_is_not_repaired_by_the_import_of_missing_cves(self):
        # camstork's instance: the entry was stored before the defaultStatus import existed, so its Jenkins block has no ranges
        CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}])
        with mock.patch('cveFeed.intel.import_candidates', return_value=['CVE-2024-23897']), \
                mock.patch('cveFeed.intel.fetch_cve5', return_value=cve5('CVE-2024-23897')), mock.patch('cveFeed.intel.intel_for', return_value={}):
            self.assertEqual(intel.import_missing({}, 10), [])
        self.assertEqual(self.stored().affected[0]['ranges'], [])  # import_missing only creates rows; the repair below is what fills it

    def test_the_repair_fills_the_empty_ranges_from_the_cve_list_record(self):
        CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}],
                                sources=['cve.now'])
        with mock.patch('cveFeed.intel.fetch_cve5', return_value=cve5('CVE-2024-23897')):
            out = intel.repair_ranges(limit=10)
        self.assertEqual(out['repaired'], 1)
        entry = self.stored()
        self.assertEqual(intro_fixed(entry.affected[0]['ranges']), [('1.606', '2.426.3'), ('2.427', '2.440.1'), ('2.441', '2.442')])
        self.assertIn('CVE List V5', entry.sources)
        self.assertTrue(entry.needs_recorrelation)
        self.assertEqual(mismatches(entry.affected, 'Jenkins', JENKINS, cpe_for=JENKINS_CPE), [])

    def test_the_repair_resets_the_verdicts_that_were_read_from_the_empty_ranges(self):
        entry = CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'product': 'Jenkins', 'ranges': []}])
        MatchVerdict.objects.create(cve_entry=entry, matched_product='Jenkins', matched_version='2.442', version_in_range=None, ai_verdict='unknown')
        with mock.patch('cveFeed.intel.fetch_cve5', return_value=cve5('CVE-2024-23897')):
            intel.repair_ranges(limit=10)
        self.assertFalse(MatchVerdict.objects.filter(cve_entry_id=entry.pk).exists())

    def test_the_repair_is_bounded_and_resumes_where_it_stopped(self):
        for n in range(5):
            CVEEntry.objects.create(cve_id=f'CVE-2099-{n + 10}', affected=[{'product': f'Prod{n}', 'ranges': []}])
        record = cve5('CVE-2024-23897')
        calls = []
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, **k: calls.append(cve) or record):
            first = intel.repair_ranges(limit=2)
            second = intel.repair_ranges(limit=2)
            third = intel.repair_ranges(limit=2)
            fourth = intel.repair_ranges(limit=2)
        self.assertEqual((first['examined'], second['examined'], third['examined'], fourth['examined']), (2, 2, 1, 0))
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(set(calls)), 5)  # every entry asked once

    def test_a_record_that_is_not_default_affected_is_left_alone(self):
        CVEEntry.objects.create(cve_id='CVE-2023-36845', affected=[{'product': 'Junos OS', 'ranges': []}])
        with mock.patch('cveFeed.intel.fetch_cve5', return_value=cve5('CVE-2023-36845')):
            out = intel.repair_ranges(limit=10)
        self.assertEqual(out['repaired'], 0)
        self.assertEqual(CVEEntry.objects.get(cve_id='CVE-2023-36845').affected[0]['ranges'], [])

    def test_a_cve_list_error_leaves_the_entry_and_does_not_stop_the_run(self):
        CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'product': 'Jenkins', 'ranges': []}])
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=intel.SourceError('HTTP 503')):
            out = intel.repair_ranges(limit=10)
        self.assertEqual((out['repaired'], out['failed']), (0, 1))

    def test_stored_placeholder_ranges_are_rewritten_without_the_network(self):
        CVEEntry.objects.create(cve_id='CVE-2022-26134', affected=cvenow('CVE-2022-26134')['affected'])
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=AssertionError('no network for a local fix')):
            out = intel.repair_ranges(limit=10)
        self.assertEqual(out['normalized'], 1)
        for item in CVEEntry.objects.get(cve_id='CVE-2022-26134').affected:
            self.assertEqual(intro_fixed(item['ranges']), CONFLUENCE_RANGES)

    def test_the_management_command_runs_the_repair(self):
        from django.core.management import call_command
        CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'product': 'Jenkins', 'ranges': []}])
        from io import StringIO
        out = StringIO()
        with mock.patch('cveFeed.intel.fetch_cve5', return_value=cve5('CVE-2024-23897')):
            call_command('repair_cve_ranges', '--limit', '10', stdout=out)
        self.assertIn('repaired', out.getvalue())
        self.assertTrue(self.stored().affected[0]['ranges'])

