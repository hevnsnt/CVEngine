"""Version ranges at ingest: what is stored from a CVE List V5 record and from a cve.now entry, for the real records of Confluence
(CVE-2022-26134), Bitbucket (CVE-2022-36804), Juniper Junos (CVE-2023-36844..36847, CVE-2023-4481, CVE-2024-21591, CVE-2025-21590),
Jenkins (CVE-2024-23897), Cisco, Oracle, the Linux kernel (CVE-2024-53104) and Microsoft (CVE-2020-0787, CVE-2024-38063). The fixtures under
tests/fixtures are trimmed copies of the real CVE List records (cve5/) and of the live cve.now
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



# ---------------------------------------------------------------------------------------------- Cisco exact builds

# Trimmed copies of the real records: CVE-2023-20109 (IOS 44 of its 674 builds, IOS XE 97 of its 364) and CVE-2024-20353 (ASA 46 of its 187,
# FTD 10 of its 80), each build exactly as the CNA wrote it and in its order. The real IOS list also holds 15.2(4)M8; the trimmed one leaves it
# out so it can stand for a near miss.

ASA_NAME = 'Cisco Adaptive Security Appliance (ASA) Software'


def converted(cve_id):
    return intel.convert_affected(cve5(cve_id)['containers']['cna']['affected'])


def listed(cve_id, product):
    block = next(a for a in cve5(cve_id)['containers']['cna']['affected'] if a['product'] == product)
    return [v['version'] for v in block['versions']]


def read(affected, name, version, cpe=''):
    """``verdict`` with the version text passed along, as ``_record_matches`` passes it."""
    cve = SimpleNamespace(id=1, cve_id='CVE-X', affected=affected, kev=True, epss_reached=None, exploit_db=None, cvss=9.8)
    index = correlation.build_product_index([cve])
    found = list(correlation._match_candidates(name, parse_version(version), correlation._norm(name), index, {1: cve}, cpe=cpe, raw=version))
    return found[0][2] if found else 'nomatch'


def old_shape(affected):
    """What the conversion stored before the builds: the same blocks without them."""
    return [{k: v for k, v in item.items() if k != 'builds'} for item in affected]


class CiscoExactBuildTests(SimpleTestCase):
    def test_every_listed_build_is_kept_in_order(self):
        ios, xe = converted('CVE-2023-20109')
        self.assertEqual(ios['builds'], [v.lower() for v in listed('CVE-2023-20109', 'IOS')])
        self.assertEqual(len(ios['builds']), 44)
        self.assertEqual(xe['builds'], [v.lower() for v in listed('CVE-2023-20109', 'Cisco IOS XE Software')])
        self.assertEqual(len(xe['builds']), 97)
        asa, ftd = converted('CVE-2024-20353')
        self.assertEqual(asa['builds'], listed('CVE-2024-20353', 'Cisco Adaptive Security Appliance (ASA) Software'))
        self.assertEqual(len(asa['builds']), 46)
        self.assertNotIn('builds', ftd)  # its 10 builds all fit in the ranges: stored as it always was
        self.assertEqual(len(ftd['ranges']), 10)

    def test_the_ranges_are_as_before(self):
        ios, xe = converted('CVE-2023-20109')
        self.assertEqual(ios['ranges'], [])  # a parenthesised build is never a range bound
        self.assertEqual(len(xe['ranges']), 30)
        self.assertEqual(xe['ranges'][0], {'type': 'SEMVER', 'introduced': '3.7.0S', 'lastAffected': '3.7.0S'})

    def test_parenthesised_builds_are_kept(self):
        ios, _xe = converted('CVE-2023-20109')
        for build in ('15.2(4)m7', '15.2(4)m6a', '12.4(24)t', '15.9(3)m7a'):
            self.assertIn(build, ios['builds'])
        self.assertTrue(all('(' in b for b in ios['builds']))

    def test_a_build_past_the_thirtieth_matches_exactly(self):
        xe = converted('CVE-2023-20109')
        asa = converted('CVE-2024-20353')
        self.assertGreater(listed('CVE-2024-20353', 'Cisco Adaptive Security Appliance (ASA) Software').index('9.16.4.18'), 30)
        self.assertGreater(listed('CVE-2023-20109', 'Cisco IOS XE Software').index('17.9.3a'), 30)
        self.assertIs(read(asa, ASA_NAME, '9.16.4.18'), True)
        self.assertIs(read(asa, ASA_NAME, '9.16(4)18'), True)  # how the ASA itself prints it
        self.assertIs(read(xe, 'Cisco IOS XE Software', '17.9.3a'), True)
        self.assertIs(read(xe, 'Cisco IOS XE Software', '17.09.03a'), True)  # IOS XE 17 prints its version with leading zeros
        self.assertIs(read(xe, 'Cisco IOS', '15.2(4)M7'), True)
        self.assertIs(read(xe, 'Cisco IOS', '15.2(4)m7'), True)
        self.assertIs(read(xe, 'Cisco IOS', '15.2\\(4\\)m7', cpe='cpe:/o:cisco:ios:15.2\\(4\\)m7'), True)  # as a CPE escapes it

    def test_before_the_builds_those_hosts_had_no_match(self):
        # the shape the conversion stored before: the ASA list cut at 30 and no IOS range at all
        self.assertIs(read(old_shape(converted('CVE-2024-20353')), ASA_NAME, '9.16.4.18'), False)
        self.assertIsNone(read(old_shape(converted('CVE-2023-20109')), 'Cisco IOS', '15.2(4)M7'))

    def test_a_near_miss_build_does_not_match(self):
        xe = converted('CVE-2023-20109')
        asa = converted('CVE-2024-20353')
        self.assertIs(read(xe, 'Cisco IOS', '15.2(4)M8'), False)
        self.assertIs(read(xe, 'Cisco IOS', '15.2(4)'), False)
        self.assertIs(read(xe, 'Cisco IOS', '15.2'), False)
        self.assertIs(read(xe, 'Cisco IOS XE Software', '17.9.4a'), False)  # the fixed rebuild of 17.9.4 is not on the list
        self.assertIs(read(xe, 'Cisco IOS XE Software', '17.9.3b'), False)
        self.assertIs(read(asa, ASA_NAME, '9.16.4.17'), False)

    def test_a_listed_build_is_not_a_whole_release(self):
        # a range of one version reads "1.0.2" as the whole release (1.0.2k is inside it); a listed build is that build only
        affected = [{'vendor': 'Cisco', 'product': 'Cisco IOS XE Software', 'ranges': [{'introduced': '17.9.4', 'lastAffected': '17.9.4'}],
                     'builds': ['17.9.4', '17.9.3']}]
        self.assertIs(read(affected, 'Cisco IOS XE Software', '17.9.4'), True)
        self.assertIs(read(affected, 'Cisco IOS XE Software', '17.9.4a'), False)

    def test_a_parenthesised_build_is_never_a_range_bound_or_a_prefix(self):
        self.assertIsNone(parse_version('15.2(4)M7', strict=True))
        host = parse_version('15.2(4)M7')
        self.assertEqual(host.text, '15.2(4)m7')
        self.assertIsNone(correlation.version_in_range(host, {'introduced': '15.0', 'fixed': '15.5'}))
        self.assertIsNone(correlation.version_in_range(parse_version('15.3'), {'introduced': '15.2(4)M7', 'fixed': '15.5'}))
        # a feed's range around the release says nothing about the build: unknown, never in range
        wide = [{'vendor': 'Cisco', 'product': 'IOS', 'ranges': [{'introduced': '15.0', 'fixed': '15.5'}]}]
        self.assertIsNone(read(wide, 'Cisco IOS', '15.2(4)M7'))
        # nor a fix-only branch list read by major.minor
        fixes = [{'vendor': 'Cisco', 'product': 'IOS', 'ranges': [{'fixed': '15.2.9'}, {'fixed': '15.5.3'}]}]
        self.assertIsNone(read(fixes, 'Cisco IOS', '15.2(4)M7'))
        # a bound that names exactly this build holds it
        through = [{'vendor': 'Zyxel', 'product': 'GS1900-8 firmware', 'ranges': [{'lastAffected': '2.90(AAHH.2)C0'}]}]
        self.assertIs(read(through, 'GS1900-8 firmware', '2.90(AAHH.2)C0'), True)
        self.assertIsNone(read(through, 'GS1900-8 firmware', '2.80(AAHH.1)C0'))

    def test_a_dotted_version_against_a_list_without_its_text_reads_the_ranges_as_before(self):
        xe = converted('CVE-2023-20109')
        self.assertIs(verdict(xe, 'Cisco IOS XE Software', '3.7.0S'), True)

    def test_the_evidence_names_the_build_and_the_triage_text_says_so(self):
        from cveFeed import match_policy, triage
        asa = converted('CVE-2024-20353')
        cve = SimpleNamespace(id=1, cve_id='CVE-2024-20353', affected=asa, kev=True, epss_reached=None, exploit_db=None, cvss=8.6)

        class Sub:
            id, scan_history_id, target_domain_id, name = 5, 7, 3, 'fw.example.test'
        rows = []
        correlation._record_matches(Sub, ASA_NAME, '9.16.4.18', correlation._norm(ASA_NAME),
                                    'tech', correlation.build_product_index([cve]), {1: cve}, 0.0, None, rows)
        self.assertEqual([(r['version_in_range'], r['evidence']['range']) for r in rows], [(True, {'build': '9.16.4.18'})])
        self.assertTrue(match_policy.hard_version_evidence(True, rows[0]['evidence']))
        self.assertEqual(triage.range_text(rows[0]['evidence']['range']), 'the listed build 9.16.4.18')
        self.assertIs(correlation.range_holds('9.16.4.18', {'build': '9.16.4.18'}), True)
        self.assertIs(correlation.range_holds('9.16.4.19', {'build': '9.16.4.18'}), False)

    def test_apple_ios_and_cisco_ios_never_match_each_other(self):
        apple = intel.convert_affected(cve5('CVE-2022-32917')['containers']['cna']['affected'])
        cisco = converted('CVE-2023-20109')
        for version in ('15.2(4)M7', '15.1', '12.0'):
            self.assertEqual(read(apple, 'Cisco IOS', version), 'nomatch', version)
            self.assertEqual(read(apple, 'Cisco IOS http-config', version), 'nomatch', version)  # nmap's name for it, an alias of "ios"
        for version in ('15.1', '15.2(4)M7'):
            self.assertEqual(read(cisco, 'Apple iOS', version), 'nomatch', version)
        # each still matches its own
        self.assertIs(read(apple, 'iOS', '15.1'), True)
        self.assertIs(read(cisco, 'Cisco IOS', '15.2(4)M7'), True)
        self.assertIs(read(cisco, 'Cisco IOS http-config', '15.2(4)M7'), True)

    def test_a_vendor_word_still_matches_its_own_vendors_product(self):
        nginx_project = [{'vendor': 'nginx', 'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]
        self.assertIs(read(nginx_project, 'F5 NGINX', '1.10.0'), True)  # the project is its own vendor
        tomcat = [{'vendor': 'Apache Software Foundation', 'product': 'Apache Tomcat', 'ranges': [{'introduced': '9.0.0', 'fixed': '9.0.50'}]}]
        self.assertIs(read(tomcat, 'Apache Tomcat', '9.0.10'), True)
        oracle_on_apache = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '1.0', 'fixed': '9.0'}]}]
        self.assertEqual(read(oracle_on_apache, 'Oracle HTTP Server', '2.4.52'), 'nomatch')

    def test_a_feed_refresh_keeps_the_builds_the_cve_list_record_gave(self):
        stored = converted('CVE-2023-20109')
        feed = old_shape(stored)
        kept = intel.keep_published_ranges(feed, stored)
        self.assertEqual([item.get('builds') for item in kept], [item['builds'] for item in stored])
        other_vendor = [{'vendor': 'Apple', 'product': 'IOS', 'ranges': []}]
        self.assertNotIn('builds', intel.keep_published_ranges(other_vendor, stored)[0])

    def test_the_seed_carries_the_builds_and_cleans_them(self):
        from cveFeed import seed
        affected = converted('CVE-2023-20109')
        cve = SimpleNamespace(cve_id='CVE-2023-20109', kev=True, epss_reached=None, exploit_db=None, cvss=8.8, affected=affected, references=[],
                              sources=['CVE List V5'], intel={}, published_at=None, first_seen_at=None,
                              **{field: '' for field in seed.TEXT_LIMITS})
        line = json.loads(json.dumps(seed.record_for(cve)))
        self.assertEqual(seed.clean_record(line)['affected'], affected)
        line['affected'][0]['builds'] += [7, None, 'x' * 100, 'two words', '15.2(4)M7']
        self.assertEqual(seed.clean_record(line)['affected'][0]['builds'], affected[0]['builds'])


class CiscoExactBuildBackfillTests(TestCase):
    def store(self, cve_id, **extra):
        return CVEEntry.objects.create(cve_id=cve_id, affected=old_shape(converted(cve_id)), sources=['CVE List V5'], **extra)

    def records(self, cve_id):
        return {'CVE-2023-20109': cve5('CVE-2023-20109'), 'CVE-2024-20353': cve5('CVE-2024-20353'),
                'CVE-2022-32917': cve5('CVE-2022-32917')}[cve_id]

    def test_the_backfill_reingests_the_stored_records_and_marks_them_for_correlation(self):
        ios = self.store('CVE-2023-20109')
        asa = self.store('CVE-2024-20353')
        apple = CVEEntry.objects.create(cve_id='CVE-2022-32917', affected=converted('CVE-2022-32917'), sources=['CVE List V5'])
        MatchVerdict.objects.create(cve_entry=asa, matched_product='Cisco ASA', matched_version='9.16.4.18', version_in_range=False,
                                    ai_verdict='uncertain')
        self.assertEqual(set(intel.builds_candidates().values_list('cve_id', flat=True)), {'CVE-2023-20109', 'CVE-2024-20353'})
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: self.records(cve)) as fetch:
            out = intel.backfill_exact_builds(limit=10)
        self.assertEqual(sorted(c.args[0] for c in fetch.call_args_list), ['CVE-2023-20109', 'CVE-2024-20353'])
        self.assertEqual((out['scanned'], out['updated'], out['failed']), (2, 2, 0))
        for row, cve_id in ((ios, 'CVE-2023-20109'), (asa, 'CVE-2024-20353')):
            row.refresh_from_db()
            self.assertEqual(row.affected, converted(cve_id))
            self.assertTrue(row.needs_recorrelation)
        self.assertFalse(MatchVerdict.objects.filter(cve_entry=asa).exists())  # judged again on the new reading
        apple.refresh_from_db()
        self.assertFalse(apple.needs_recorrelation)
        self.assertIs(read(CVEEntry.objects.get(pk=asa.pk).affected, ASA_NAME, '9.16.4.18'), True)
        # resumable and done: the next step finds nothing and reads nothing
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=AssertionError('read twice')):
            self.assertEqual(intel.backfill_exact_builds(limit=10), {'scanned': 0, 'updated': 0, 'failed': 0, 'failed_ids': [], 'skipped': 0, 'skipped_ids': [], 'done': True})

    def test_the_backfill_is_bounded_per_step_and_continues_where_it_stopped(self):
        self.store('CVE-2023-20109')
        self.store('CVE-2024-20353')
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: self.records(cve)) as fetch:
            first = intel.backfill_exact_builds(limit=1)
            second = intel.backfill_exact_builds(limit=1)
            third = intel.backfill_exact_builds(limit=1)
        self.assertEqual([first['scanned'], second['scanned'], third['scanned']], [1, 1, 0])
        self.assertEqual(fetch.call_count, 2)
        self.assertTrue(third['done'])

    def test_the_update_step_runs_the_command(self):
        from io import StringIO

        from cveFeed import upgrade_backfills
        from django.core.management import call_command
        self.assertIn('backfill_exact_builds', upgrade_backfills.BACKFILLS)
        self.store('CVE-2024-20353')
        out = StringIO()
        call_command('backfill_exact_builds', stdout=out)
        self.assertIn('1 stored CVEs would', out.getvalue())
        self.assertNotIn('builds', CVEEntry.objects.get(cve_id='CVE-2024-20353').affected[0])  # a dry run writes nothing
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: self.records(cve)):
            self.assertEqual(upgrade_backfills.run_one('backfill_exact_builds'), 'done')
        self.assertIn('builds', CVEEntry.objects.get(cve_id='CVE-2024-20353').affected[0])

    def test_an_unreadable_record_fails_the_step_so_it_is_tried_again(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        self.store('CVE-2024-20353')
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=intel.TransientSourceError('HTTP 503')), \
                mock.patch('cveFeed.intel._sleep'), self.assertRaises(CommandError):
            call_command('backfill_exact_builds', '--apply')
        self.assertEqual(intel.builds_candidates().count(), 1)  # the walk starts again
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: self.records(cve)):
            call_command('backfill_exact_builds', '--apply')
        self.assertTrue(CVEEntry.objects.get(cve_id='CVE-2024-20353').needs_recorrelation)


# ---------------------------------------------------------------------------------------------- Oracle's supported versions

# CVE-2026-114938 (Oracle Java SE, published 2026-11-17): the CVE List record (cve5/, trimmed) lists each product's supported versions as
# plain exact versions, and the live cve.now entry (cvenow/) passes them on as a bare ``versions`` list with ``ranges: []``. The other
# records below are the real ``affected`` blocks of WebLogic (CVE-2024-21182), MySQL Cluster (CVE-2022-21490) and Java SE (CVE-2017-3241).
WEBLOGIC = [{'vendor': 'Oracle Corporation', 'product': 'WebLogic Server',
             'versions': [{'version': '12.2.1.4.0', 'status': 'affected'}, {'version': '14.1.1.0.0', 'status': 'affected'}]}]
MYSQL_CLUSTER = [{'vendor': 'Oracle Corporation', 'product': 'MySQL Cluster',
                  'versions': [{'status': 'affected', 'version': '7.4.35 and prior'}, {'status': 'affected', 'version': '7.5.25 and prior'},
                               {'status': 'affected', 'version': '7.6.21 and prior'}, {'status': 'affected', 'version': '8.0.28 and prior'}]}]
JAVA_2017 = [{'vendor': 'Oracle', 'product': 'Java SE', 'versions': [{'status': 'affected', 'version': '6u131'}, {'status': 'affected', 'version': '7u121'},
                                                                      {'status': 'affected', 'version': '8u112'}]},
             {'vendor': 'Oracle', 'product': 'JRockit', 'versions': [{'status': 'affected', 'version': 'R28.3.12'}]}]


def oracle_record():
    return intel.entry_from_cve5(cve5('CVE-2026-114938'), {})['affected']


def lines(item):
    return [(r.get('introduced'), r.get('lastAffected')) for r in item['ranges']]


def java_verdict(affected, version):
    from cveFeed import java_runtime
    return java_runtime.verdict(version, [item for item in affected if java_runtime.is_runtime_item(item)])[0]


class OracleSupportedVersionTests(SimpleTestCase):
    def test_each_release_line_is_read_up_to_the_listed_version(self):
        java_se, graal_jdk, graal_ee = oracle_record()
        self.assertEqual(lines(java_se), [('8.0.0', '8.0.511'), ('17.0.0', '17.0.21'), ('21.0.0', '21.0.13'), ('25.0.0', '25.0.5'),
                                          ('27.0.0', '27.0.1')])
        self.assertEqual(lines(graal_jdk), [('17.0.0', '17.0.21'), ('21.0.0', '21.0.13')])
        self.assertEqual(lines(graal_ee), [('21.3.0', '21.3.20.0.3')])  # not the Java runtime: Oracle's own version, its first two numbers the line
        for item in (java_se, graal_jdk, graal_ee):
            self.assertEqual(item['reading'], intel.ORACLE_READING)
            self.assertNotIn('builds', item)
            self.assertTrue(all(r.get('introduced') and r.get('lastAffected') for r in item['ranges']))  # never an open range

    def test_the_java_runtime_matcher_reads_older_updates_of_a_line_as_affected(self):
        affected = oracle_record()
        table = [('17.0.10', True), ('17.0.21', True), ('17.0.22', False), ('8u401', True), ('1.8.0_511', True), ('8u511', True),
                 ('8u512', False), ('11.0.20', False), ('21.0.13', True), ('21.0.14', False), ('25.0.5', True), ('25.0.6', False),
                 ('27.0.1', True), ('27.0.2', False)]
        self.assertEqual([(v, e, java_verdict(affected, v)) for v, e in table if java_verdict(affected, v) is not e], [])

    def test_an_exact_reading_would_miss_the_older_updates(self):
        # the record read as it is written (what an exact version means for any other CNA): 17.0.10 is outside
        plain = intel.convert_affected(cve5('CVE-2026-114938')['containers']['cna']['affected'], assigner='mitre')
        self.assertIs(java_verdict(plain, '17.0.10'), False)
        self.assertIs(java_verdict(plain, '17.0.21'), True)

    def test_weblogic_lines_and_mysql_bounds(self):
        weblogic = intel.convert_affected(WEBLOGIC, assigner='oracle')[0]
        self.assertEqual(lines(weblogic), [('12.2.0', '12.2.1.4.0'), ('14.1.0', '14.1.1.0.0')])
        self.assertIs(verdict([weblogic], 'Oracle WebLogic Server', '12.2.1.3.0'), True)
        self.assertIs(verdict([weblogic], 'Oracle WebLogic Server', '12.2.1.4.0'), True)
        self.assertIs(verdict([weblogic], 'Oracle WebLogic Server', '14.1.2.0.0'), False)
        self.assertIs(verdict([weblogic], 'Oracle WebLogic Server', '12.1.3.0.0'), False)
        # the bounds Oracle wrote itself ("7.4.35 and prior") are read as before, not as lines
        mysql = intel.convert_affected(MYSQL_CLUSTER, assigner='oracle')[0]
        self.assertNotIn('reading', mysql)
        self.assertEqual(mysql['ranges'], intel.convert_affected(MYSQL_CLUSTER, assigner='mitre')[0]['ranges'])
        self.assertEqual([r.get('lastAffected') for r in mysql['ranges']], ['7.4.35', '7.5.25', '7.6.21', '8.0.28'])

    def test_older_java_records_and_what_cannot_be_read(self):
        java_se, jrockit = intel.convert_affected(JAVA_2017, assigner='oracle')
        self.assertEqual(lines(java_se), [('6.0.0', '6.0.131'), ('7.0.0', '7.0.121'), ('8.0.0', '8.0.112')])
        self.assertNotIn('reading', jrockit)  # "R28.3.12" is no version: left to the plain conversion, which reads nothing from it
        self.assertEqual(jrockit['ranges'], [])
        one_number = [{'vendor': 'Oracle', 'product': 'Solaris', 'versions': [{'status': 'affected', 'version': '11'}]}]
        self.assertNotIn('reading', intel.convert_affected(one_number, assigner='oracle')[0])

    def test_another_cnas_record_of_an_oracle_product_is_read_as_written(self):
        other = intel.convert_affected(WEBLOGIC, assigner='mitre')[0]
        self.assertNotIn('reading', other)
        self.assertEqual(lines(other), [('12.2.1.4.0', '12.2.1.4.0'), ('14.1.1.0.0', '14.1.1.0.0')])


class OracleFeedTests(TestCase):
    def test_the_live_cvenow_entry_had_no_range_and_now_takes_the_records_lines(self):
        offline = feed_from_api('CVE-2026-114938')
        self.assertEqual([item['ranges'] for item in offline.affected], [[], [], []])  # what was stored: the feed's bare versions list
        CVEEntry.objects.all().delete()
        entry = feed_from_api('CVE-2026-114938', cve5('CVE-2026-114938'))
        self.assertEqual(lines(entry.affected[0])[1], ('17.0.0', '17.0.21'))
        self.assertIn('CVE List V5', entry.sources)
        self.assertIs(java_verdict(entry.affected, '17.0.10'), True)
        # a refresh keeps them without reading the record again
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=AssertionError('read again')):
            again, _ = CVEEntry.from_api(cvenow('CVE-2026-114938'))
        self.assertEqual(CVEEntry.objects.get(pk=again.pk).affected, entry.affected)

    def test_the_backfill_rereads_oracle_records(self):
        stored = feed_from_api('CVE-2026-114938')
        exact = CVEEntry.objects.create(cve_id='CVE-2024-21182', sources=['CVE List V5'],
                                        affected=intel.convert_affected(WEBLOGIC, assigner='mitre'))
        mysql = CVEEntry.objects.create(cve_id='CVE-2022-21490', sources=['CVE List V5'],
                                        affected=intel.convert_affected(MYSQL_CLUSTER, assigner='oracle'))
        self.assertEqual(set(intel.builds_candidates().values_list('cve_id', flat=True)), {'CVE-2026-114938', 'CVE-2024-21182'})
        records = {'CVE-2026-114938': cve5('CVE-2026-114938'),
                   'CVE-2024-21182': {'cveMetadata': {'cveId': 'CVE-2024-21182', 'state': 'PUBLISHED', 'assignerShortName': 'oracle'},
                                      'containers': {'cna': {'affected': WEBLOGIC}}}}
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: records[cve]):
            out = intel.backfill_exact_builds(limit=10)
        self.assertEqual(out['updated'], 2)
        stored.refresh_from_db()
        self.assertIs(java_verdict(stored.affected, '17.0.10'), True)
        self.assertTrue(stored.needs_recorrelation)
        exact.refresh_from_db()
        self.assertEqual(lines(exact.affected[0]), [('12.2.0', '12.2.1.4.0'), ('14.1.0', '14.1.1.0.0')])
        mysql.refresh_from_db()
        self.assertFalse(mysql.needs_recorrelation)
        self.assertFalse(intel.builds_candidates().exists())


# ---------------------------------------------------------------------------------------------- bare versions lists (Linux kernel, Microsoft)

# CVE-2024-53104 (Linux kernel uvcvideo, KEV, CVSS vector local): the CVE List record (cve5/, trimmed) has two "Linux" entries, git commits
# with defaultStatus unaffected, and releases with defaultStatus affected: unaffected below 2.6.26, from each stable line's fix to the end of
# that line (lessThanOrEqual "6.1.*"), and from 6.13 on. The live cve.now entry (cvenow/) keeps the commits as ranges and passes the release
# entry on as ``versions: ["2.6.26"]`` with ``ranges: []``. CVE-2020-0787 (Windows BITS, KEV): Microsoft's records before 2021 put product
# names in ``version`` ("10 Version 1803 for 32-bit Systems"), which are not versions. CVE-2024-38063 (cve5/, four of its 25 products): the
# shape Microsoft writes now, ``version: 10.0.0, lessThan: 10.0.22000.3197, versionType: custom``.

KERNEL_RANGES = [('2.6.26', '4.19.324'), ('4.20', '5.4.286'), ('5.5', '5.10.230'), ('5.11', '5.15.172'), ('5.16', '6.1.117'), ('6.2', '6.6.61'),
                 ('6.7', '6.11.8'), ('6.12', '6.12.1')]
KERNEL = [('2.6.25', False), ('2.6.26', True), ('4.19.323', True), ('4.19.324', False), ('4.19.999', False), ('4.20', True), ('5.4.0', True),
          ('5.4.285', True), ('5.4.286', False), ('5.10.229', True), ('5.10.230', False), ('5.15.172', False), ('6.1.116', True),
          ('6.1.117', False), ('6.6.60', True), ('6.6.61', False), ('6.11.7', True), ('6.11.8', False), ('6.12.0', True), ('6.12.1', False),
          ('6.13', False), ('7.0', False)]


def release_block(affected):
    return next(item for item in affected if item.get('versions') == ['2.6.26'])


def kernel_record(**changes):
    doc = cve5('CVE-2024-53104')
    for entry in doc['containers']['cna']['affected']:
        if entry['defaultStatus'] == 'affected':
            entry.update(changes)
    return doc


class LinuxKernelBareVersionsTests(TestCase):
    def test_the_release_entry_is_read_as_the_releases_between_the_fixed_lines(self):
        git, releases = intel.convert_affected(cve5('CVE-2024-53104')['containers']['cna']['affected'], 'Linux')
        self.assertEqual(intro_fixed(releases['ranges']), KERNEL_RANGES)
        self.assertTrue(all(r['type'] == 'SEMVER' for r in releases['ranges']))
        self.assertNotIn('builds', releases)  # "2.6.26" is where the flaw began, not one affected build
        self.assertEqual({r['type'] for r in git['ranges']}, {'GIT'})  # the commits stay commits

    def test_the_live_entry_takes_the_record_ranges_and_never_the_commits(self):
        offline = feed_from_api('CVE-2024-53104')
        self.assertEqual(release_block(offline.affected)['ranges'], [])  # what was stored: no range, a "version unknown" KEV candidate
        CVEEntry.objects.all().delete()
        entry = feed_from_api('CVE-2024-53104', cve5('CVE-2024-53104'))
        block = release_block(entry.affected)
        self.assertEqual(intro_fixed(block['ranges']), KERNEL_RANGES)
        for rng in block['ranges']:
            for bound in ('introduced', 'fixed'):
                self.assertIsNotNone(parse_version(rng[bound], strict=True))  # a version, never a commit
        self.assertEqual(entry.affected[0], cvenow('CVE-2024-53104')['affected'][0])  # the commit block as the feed gave it
        self.assertIn('CVE List V5', entry.sources)

    def test_every_kernel_release_is_judged_on_both_sides_of_each_fix(self):
        entry = feed_from_api('CVE-2024-53104', cve5('CVE-2024-53104'))
        block = release_block(entry.affected)
        self.assertEqual(mismatches([block], 'Linux Kernel', KERNEL), [])
        # with the commit block beside it, a release outside the ranges stays unknown (the commits cannot be compared), never matched
        for version, expected in KERNEL:
            self.assertIs(verdict(entry.affected, 'Linux Kernel', version), True if expected else None, version)

    def test_a_refresh_keeps_the_release_ranges_without_reading_the_record(self):
        entry = feed_from_api('CVE-2024-53104', cve5('CVE-2024-53104'))
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=AssertionError('read again')):
            again, _ = CVEEntry.from_api(cvenow('CVE-2024-53104'))
        self.assertEqual(CVEEntry.objects.get(pk=again.pk).affected, entry.affected)

    def test_a_record_that_gives_nothing_sound_leaves_the_block_unbounded(self):
        star = {'version': '6.13', 'lessThanOrEqual': '*', 'status': 'unaffected', 'versionType': 'original_commit_for_fix'}
        releases = next(e for e in cve5('CVE-2024-53104')['containers']['cna']['affected'] if e['defaultStatus'] == 'affected')
        unfixed = kernel_record(versions=[v for v in releases['versions'] if v != star])  # mainline not fixed: 6.13 on is an open range
        inclusive = kernel_record(versions=[{**v, 'lessThanOrEqual': '6.1.200'} if v.get('lessThanOrEqual') == '6.1.*' else v
                                            for v in releases['versions']])  # an exact inclusive bound: a hole no range can write
        nothing = kernel_record(versions=[{'version': '2.6.26', 'status': 'affected'}])  # every release affected
        for doc in (unfixed, inclusive, nothing):
            CVEEntry.objects.all().delete()
            entry = feed_from_api('CVE-2024-53104', doc)
            self.assertEqual(release_block(entry.affected)['ranges'], [])
            self.assertNotIn('CVE List V5', entry.sources)

    def test_the_feeds_list_alone_is_never_read_and_commits_never_become_bounds(self):
        bare = {'vendor': 'Linux', 'product': 'Linux', 'ranges': [], 'versions': ['2.6.26']}
        self.assertIsNone(intel.record_ranges_for(bare, [], 'Linux'))
        git = cve5('CVE-2024-53104')['containers']['cna']['affected'][0]
        hashes = {'vendor': 'Linux', 'product': 'Linux', 'ranges': [], 'versions': [git['versions'][0]['version']]}
        self.assertIsNone(intel.record_ranges_for(hashes, [git], 'Linux'))
        digits = [{'vendor': 'x', 'product': 'Widget', 'versions': [{'version': '25407073', 'status': 'affected'}]}]  # all digits, hash-shaped
        self.assertIsNone(intel.record_ranges_for({'vendor': 'x', 'product': 'Widget', 'versions': ['25407073']}, digits))

    def test_a_kernel_cve_stays_local_and_never_matches_a_host(self):
        from cveFeed import locality
        entry = feed_from_api('CVE-2024-53104', cve5('CVE-2024-53104'))
        self.assertTrue(entry.kev)
        before = locality.classify(entry.cvss_vector, entry.original_description, entry.title, cvenow('CVE-2024-53104')['affected'], True)
        after = locality.classify(entry.cvss_vector, entry.original_description, entry.title, entry.affected, True)
        self.assertEqual((before[0], after[0]), (True, True))  # the ranges change nothing about where it can be exploited from
        locality.refresh()
        self.assertTrue(CVEEntry.objects.get(pk=entry.pk).local_only)
        correlation._INDEX_CACHE['key'] = None
        cve_by_id, _index = correlation.cve_pool()
        self.assertNotIn(entry.pk, cve_by_id)


class MicrosoftBareVersionsTests(TestCase):
    def test_product_names_in_the_version_field_are_never_read_as_versions(self):
        doc = cve5('CVE-2020-0787')
        for item in cvenow('CVE-2020-0787')['affected']:
            self.assertIsNone(intel.record_ranges_for(item, doc['containers']['cna']['affected'], 'microsoft'), item['product'])
        entry = feed_from_api('CVE-2020-0787', doc)
        self.assertEqual([item['ranges'] for item in entry.affected], [[], [], []])  # unbounded, as before: a "version unknown" candidate
        self.assertNotIn('CVE List V5', entry.sources)

    def test_the_custom_build_ranges_are_read_per_product(self):
        entries = cve5('CVE-2024-38063')['containers']['cna']['affected']
        converted = {item['product']: intro_fixed(item['ranges']) for item in intel.convert_affected(entries, 'microsoft')}
        self.assertEqual(converted, {'Windows 10 Version 1809': [('10.0.17763.0', '10.0.17763.6293')],
                                     'Windows Server 2022': [('10.0.20348.0', '10.0.20348.2700')],
                                     'Windows 11 version 21H2': [('10.0.0', '10.0.22000.3197')],
                                     'Windows 10 Version 22H2': [('10.0.19045.0', '10.0.19045.4780')]})

    def test_a_bare_block_of_the_custom_shape_takes_only_its_own_products_range(self):
        entries = cve5('CVE-2024-38063')['containers']['cna']['affected']
        win11 = {'vendor': 'Microsoft', 'product': 'Windows 11 version 21H2', 'ranges': [], 'versions': ['10.0.0']}
        found = intel.record_ranges_for(win11, entries, 'microsoft')
        self.assertEqual(intro_fixed(found['ranges']), [('10.0.0', '10.0.22000.3197')])
        block = [{**win11, **found}]
        self.assertIs(verdict(block, 'Windows 11 version 21H2', '10.0.22000.3196'), True)
        self.assertIs(verdict(block, 'Windows 11 version 21H2', '10.0.22000.3197'), False)
        # a block whose listed version the record's block for that product does not list is not read
        self.assertIsNone(intel.record_ranges_for({**win11, 'versions': ['10.0.19045.0']}, entries, 'microsoft'))


class BareVersionShapeTests(SimpleTestCase):
    def ranges(self, product, versions, **entry):
        found = intel.record_ranges_for({'vendor': 'V', 'product': product, 'ranges': [], 'versions': [v['version'] for v in versions]},
                                        [{'vendor': 'V', 'product': product, 'versions': versions, **entry}])
        return [(r.get('introduced'), r.get('fixed') or r.get('lastAffected')) for r in found['ranges']] if found else None

    def test_exact_versions_and_written_ranges(self):
        aff = lambda *texts: [{'version': t, 'status': 'affected'} for t in texts]  # noqa: E731
        self.assertEqual(self.ranges('Questions For Confluence', aff('2.7.34', '2.7.35', '3.0.2')),  # CVE-2022-26138: exactly these
                         [('2.7.34', '2.7.34'), ('2.7.35', '2.7.35'), ('3.0.2', '3.0.2')])
        # Apache writes the product's name in front of the version (CVE-2021-42013, CVE-2021-41773, CVE-2021-33193)
        self.assertEqual(self.ranges('Apache HTTP Server', aff('Apache HTTP Server 2.4.49', 'Apache HTTP Server 2.4.50')),
                         [('2.4.49', '2.4.49'), ('2.4.50', '2.4.50')])
        self.assertEqual(self.ranges('Apache HTTP Server', aff('Apache HTTP Server 2.4 2.4.49')), [('2.4.49', '2.4.49')])
        self.assertEqual(self.ranges('Apache HTTP Server', aff('Apache HTTP Server 2.4 2.4.17 to 2.4.48')), [('2.4.17', '2.4.48')])
        self.assertEqual(self.ranges('PHP', aff('7.2.x below 7.2.30')), [('7.2', '7.2.30')])  # CVE-2020-7067
        self.assertEqual(self.ranges('tokio', aff('= 1.54.0')), [('1.54.0', '1.54.0')])  # GitHub's "=" (cve.now drops it)
        self.assertEqual(self.ranges('Slurm', [{'version': '25.05.0', 'lessThan': '25.05.9', 'status': 'affected'}]), [('25.05.0', '25.05.9')])

    def test_what_is_not_sound_is_left_unbounded(self):
        aff = lambda *texts: [{'version': t, 'status': 'affected'} for t in texts]  # noqa: E731
        self.assertIsNone(self.ranges('Restaurant_IMS', aff('922ff6d208278282e7c8e36d70d9ae356adec9fe')))  # a commit
        self.assertIsNone(self.ranges('llama.cpp', aff('0.4.0', '55d4206c8')))  # one commit spoils the list
        self.assertIsNone(self.ranges('Phoca Gallery', aff('4.5.0-6.1.5')))  # two releases or a revision: not known
        self.assertIsNone(self.ranges('Windows', aff('10 Version 1607 for 32-bit Systems', '2019')))  # product names
        self.assertIsNone(self.ranges('Widget', aff('2.0 and later')))  # open
        self.assertIsNone(self.ranges('Widget', [{'version': '2.0', 'lessThan': '*', 'status': 'affected'}]))  # open
        self.assertIsNone(self.ranges('Widget', aff('0')))  # every release
        self.assertIsNone(self.ranges('Widget', aff('1.0'), defaultStatus='affected'))  # every release
        self.assertIsNone(self.ranges('Widget', [{'version': '1.0', 'lessThan': '2.0', 'status': 'affected', 'versionType': 'git'}]))
        twice = [{'vendor': 'V', 'product': 'Widget', 'versions': aff('1.0')}] * 2  # which entry the block is cannot be told
        self.assertIsNone(intel.record_ranges_for({'vendor': 'V', 'product': 'Widget', 'versions': ['1.0']}, twice))
        other_vendor = [{'vendor': 'Other', 'product': 'Widget', 'versions': aff('1.0')}]
        self.assertIsNone(intel.record_ranges_for({'vendor': 'V', 'product': 'Widget', 'versions': ['1.0']}, other_vendor))

    def test_a_refresh_gives_a_bare_block_only_its_own_stored_ranges(self):
        commits = {'vendor': 'Linux', 'product': 'Linux', 'ranges': [{'introduced': 'c0efd232929c2cd8', 'fixed': '95edf13a48e75dc2'},
                                                                    {'introduced': '5.0', 'fixed': '5.1'}]}
        releases = {'vendor': 'Linux', 'product': 'Linux', 'ranges': [{'introduced': '2.6.26', 'fixed': '4.19.324'}], 'versions': ['2.6.26']}
        feed = [{**commits}, {**releases, 'ranges': []}]
        self.assertEqual(intel.keep_published_ranges(feed, [commits, releases]), [commits, releases])
        changed = [{**commits}, {**releases, 'ranges': [], 'versions': ['2.6.27']}]  # the record changed: read again, never the commits
        self.assertEqual(intel.keep_published_ranges(changed, [commits, releases])[1]['ranges'], [])


class BareVersionsBackfillTests(TestCase):
    RECORDS = {'CVE-2024-53104': 'CVE-2024-53104', 'CVE-2020-0787': 'CVE-2020-0787'}

    def fetch(self, cve, get=None):
        return cve5(self.RECORDS[cve])

    def test_the_backfill_reads_the_stored_bare_blocks_and_marks_the_changed_cves(self):
        kernel = feed_from_api('CVE-2024-53104')
        windows = feed_from_api('CVE-2020-0787')
        jenkins = CVEEntry.objects.create(cve_id='CVE-2024-23897', affected=[{'product': 'Jenkins', 'ranges': []}])  # no versions: not this walk
        MatchVerdict.objects.create(cve_entry=kernel, matched_product='Linux', matched_version='6.1.50', version_in_range=None, ai_verdict='unknown')
        self.assertEqual(set(intel.bare_candidates().values_list('cve_id', flat=True)), {'CVE-2024-53104', 'CVE-2020-0787'})
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=self.fetch):
            out = intel.backfill_bare_versions(limit=10)
        self.assertEqual((out['scanned'], out['updated'], out['failed']), (2, 1, 0))
        kernel.refresh_from_db()
        self.assertEqual(intro_fixed(release_block(kernel.affected)['ranges']), KERNEL_RANGES)
        self.assertTrue(kernel.needs_recorrelation)
        self.assertIn('CVE List V5', kernel.sources)
        self.assertFalse(MatchVerdict.objects.filter(cve_entry=kernel).exists())
        windows.refresh_from_db()
        self.assertFalse(windows.needs_recorrelation)  # nothing sound: left as it was
        jenkins.refresh_from_db()
        self.assertFalse(jenkins.needs_recorrelation)
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=AssertionError('read twice')):
            self.assertEqual(intel.backfill_bare_versions(limit=10), {'scanned': 0, 'updated': 0, 'failed': 0, 'failed_ids': [], 'skipped': 0,
                                                                       'skipped_ids': [], 'done': True})

    def test_the_update_step_runs_the_command_and_a_failure_walks_again(self):
        from io import StringIO

        from cveFeed import upgrade_backfills
        from django.core.management import call_command
        from django.core.management.base import CommandError
        self.assertIn('backfill_bare_versions', upgrade_backfills.BACKFILLS)
        feed_from_api('CVE-2024-53104')
        out = StringIO()
        call_command('backfill_bare_versions', stdout=out)
        self.assertIn('1 stored CVEs would', out.getvalue())
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=intel.TransientSourceError('HTTP 503')), \
                mock.patch('cveFeed.intel._sleep'), self.assertRaises(CommandError):
            call_command('backfill_bare_versions', '--apply')
        self.assertEqual(intel.bare_candidates().count(), 1)
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=self.fetch):
            self.assertEqual(upgrade_backfills.run_one('backfill_bare_versions'), 'done')
        self.assertTrue(CVEEntry.objects.get(cve_id='CVE-2024-53104').needs_recorrelation)

    def test_the_seed_carries_the_ranges_a_bare_block_was_given(self):
        from cveFeed import seed
        entry = feed_from_api('CVE-2024-53104', cve5('CVE-2024-53104'))
        line = json.loads(json.dumps(seed.record_for(entry)))
        self.assertEqual(seed.clean_record(line)['affected'], entry.affected)
        self.assertEqual(intro_fixed(release_block(seed.clean_record(line)['affected'])['ranges']), KERNEL_RANGES)


class PatientRecordFetchTests(TestCase):
    """GitHub rate-limits a burst of raw reads: the update step on the VPS failed on its first run (backfill_bare_versions, CommandError)
    because one record answered 429 among about a thousand read eight at a time, and every failure started the walk again."""

    class Resp:
        def __init__(self, status, body=b'', headers=None):
            self.status_code, self._body, self.headers = status, body, headers or {}

        def iter_content(self, size):
            yield self._body

        def close(self):
            pass

    def test_a_rate_limited_read_is_asked_again_after_the_wait_github_names(self):
        answers = [self.Resp(429, headers={'Retry-After': '20'}), self.Resp(503), self.Resp(200, json.dumps({'ok': 1}).encode())]
        with mock.patch('cveFeed.intel._sleep') as sleep:
            doc = intel.fetch_cve5_patiently('CVE-2024-53104', get=lambda *a, **k: answers.pop(0))
        self.assertEqual(doc, {'ok': 1})
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [20.0, intel.FETCH_WAITS[1]])

    def test_a_missing_record_is_not_asked_again_and_a_read_that_cannot_pass_is_raised_at_once(self):
        calls = []

        def get(*a, **k):
            calls.append(1)
            return self.Resp(404)
        with mock.patch('cveFeed.intel._sleep') as sleep:
            self.assertIsNone(intel.fetch_cve5_patiently('CVE-2024-0001', get=get))
            with self.assertRaises(intel.SourceError):
                intel.fetch_cve5_patiently('CVE-2024-0002', get=lambda *a, **k: self.Resp(410))
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_a_record_that_never_reads_is_left_as_stored_and_never_fails_the_update_step(self):
        from io import StringIO

        from django.core.management import call_command
        feed_from_api('CVE-2024-53104')
        out = StringIO()
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=intel.SourceError('the file is larger than the limit')), \
                mock.patch('cveFeed.intel._sleep') as sleep:
            call_command('backfill_bare_versions', '--apply', stdout=out)
        self.assertIn('1 left as stored because their record cannot be read (CVE-2024-53104)', out.getvalue())
        sleep.assert_not_called()

    def test_a_record_still_rate_limited_after_the_waits_fails_the_step_so_it_is_tried_again(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        feed_from_api('CVE-2024-53104')
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=intel.TransientSourceError('HTTP 429', retry_after=5)) as fetch, \
                mock.patch('cveFeed.intel._sleep') as sleep, self.assertRaises(CommandError):
            call_command('backfill_bare_versions', '--apply')
        self.assertEqual(fetch.call_count, len(intel.FETCH_WAITS) + 1)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [max(w, 5) for w in intel.FETCH_WAITS])


class RetryMarksMigrationTests(TestCase):
    def test_the_migration_clears_only_the_two_reread_steps_marks(self):
        import importlib

        from django.apps import apps
        from cveFeed.models import BackgroundCursor
        for lane in ('bf:backfill_bare_versions', 'bfa:backfill_bare_versions', 'bf:backfill_exact_builds', 'bf:rerate_findings'):
            BackgroundCursor.objects.create(lane=lane, last_pk=1)
        importlib.import_module('cveFeed.migrations.0171_retry_record_rereads').clear(apps, None)
        self.assertEqual(set(BackgroundCursor.objects.filter(lane__startswith='bf').values_list('lane', flat=True)), {'bf:rerate_findings'})
