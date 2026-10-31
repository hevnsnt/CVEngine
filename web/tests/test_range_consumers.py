"""Every reader of a CVE's version ranges prepares them the same way (issue 205, second shape: introduced and fixed in separate ranges).

The matcher, the WordPress plugin matcher, the triage brief, the detection strategy, the agent API and the AI prompts must agree on what a
list of ranges says, and a range list that cannot be read with certainty must never give a confident "in range" for a version the advisory
fixes: the answer is unknown (``version_in_range`` None, which routes to needs_validation) and the WordPress path records no match."""
import json
from types import SimpleNamespace

from django.test import SimpleTestCase

from cveFeed.correlation import _match_candidates, _norm, build_product_index, parse_version, split_name_version
from cveFeed import wp_correlation


class FakeCVE:
    def __init__(self, affected, cid=1):
        self.id = cid
        self.cve_id = f'CVE-2099-{cid}'
        self.affected = affected
        self.kev = True  # a fire-tier CVE: the unlisted-branch rule does not apply to ICE
        self.title = 'Plugin X flaw'


PRODUCT = 'Plugin X'


def affected_of(ranges):
    return [{'vendor': 'wpvendor', 'product': PRODUCT, 'ranges': ranges}]


def main_verdict(ranges, version, details=None):
    cve = FakeCVE(affected_of(ranges))
    name, _ = split_name_version(PRODUCT)
    rows = list(_match_candidates(name, parse_version(version), _norm(name), build_product_index([cve]), {cve.id: cve}, details=details))
    return rows[0][2] if rows else 'no candidate'


def wp_matches(ranges, version):
    """Whether the WordPress path records a match for plugin ``plugin-x`` at ``version``."""
    cve = FakeCVE(affected_of(ranges))
    sub = SimpleNamespace(id=1, scan_history_id=None)
    found = [{'slug': 'plugin-x', 'title': PRODUCT, 'version': version, 'kind': 'wp-plugin'}]
    return bool(wp_correlation.match_rows(sub, found, {cve.id: cve}, build_product_index([cve])))


# (ranges, versions the advisory says are vulnerable, versions it fixes or leaves unaffected). Every version of the second list must never
# be a confident True; every version of the first must be True.
SHAPES = {
    'fix-only branch list': ([{'fixed': '3.1.0'}, {'fixed': '4.2.0'}], ['3.0.9', '4.1.9'], ['3.1.0', '3.5.0', '4.2.0', '4.9.0']),
    'introduced then lastAffected': ([{'introduced': '1.0'}, {'lastAffected': '1.5'}], ['1.0', '1.2', '1.5'], ['0.9', '1.6', '2.0']),
    'introduced then lastAffected, twice': ([{'introduced': '1.0'}, {'lastAffected': '1.5'}, {'introduced': '2.0'}, {'lastAffected': '2.5'}],
                                            ['1.0', '1.5', '2.0', '2.5'], ['0.9', '1.6', '1.9', '2.6']),
    'interleaved introduced then fixed': ([{'introduced': '1.0'}, {'introduced': '2.0'}, {'fixed': '1.5'}, {'fixed': '2.5'}],
                                          ['1.0', '1.4', '2.0', '2.4'], ['0.5', '1.5', '1.7', '2.5', '3.0']),
    'fixed listed before its introduced': ([{'fixed': '1.5'}, {'introduced': '1.0'}], ['1.0', '1.4'], ['0.5', '1.5', '1.7']),
    'fixed equal to introduced': ([{'introduced': '1.0'}, {'fixed': '1.0'}], [], ['0.5', '1.0', '1.5', '2.0']),
    'introduced and fixed of different type': ([{'introduced': '1.0', 'type': 'SEMVER'}, {'fixed': '1.5', 'type': 'ECOSYSTEM'}],
                                               [], ['0.5', '1.0', '1.2', '1.5', '1.7']),
    'two introduced then a far fixed': ([{'introduced': '1.0'}, {'introduced': '2.0'}, {'introduced': '3.0'}, {'fixed': '2.5'}],
                                        [], ['0.5', '1.5', '2.5', '2.7', '3.5']),
}


class RangeShapeTests(SimpleTestCase):
    def test_the_matcher_never_says_in_range_for_a_fixed_version_and_says_it_for_an_affected_one(self):
        for label, (ranges, affected, fixed) in SHAPES.items():
            for version in affected:
                self.assertIs(main_verdict(ranges, version), True, f'{label}: {version}')
            for version in fixed:
                self.assertIsNot(main_verdict(ranges, version), True, f'{label}: {version}')

    def test_the_wordpress_path_matches_exactly_when_the_matcher_does(self):
        for label, (ranges, affected, fixed) in SHAPES.items():
            for version in affected:
                self.assertTrue(wp_matches(ranges, version), f'{label}: {version}')
            for version in fixed:
                self.assertFalse(wp_matches(ranges, version), f'{label}: {version}')

    def test_a_range_list_that_cannot_be_paired_is_unknown_for_every_version(self):
        for label in ('fixed equal to introduced', 'introduced and fixed of different type', 'two introduced then a far fixed'):
            ranges, _affected, fixed = SHAPES[label]
            for version in fixed:
                self.assertIsNone(main_verdict(ranges, version), f'{label}: {version}')

    def test_a_fix_only_branch_list_reads_the_same_in_both_paths_for_versions_between_and_beyond_its_fixes(self):
        ranges = [{'fixed': '3.1.0'}, {'fixed': '4.2.0'}]
        for version in ('1.0', '2.9', '3.0.9', '3.1.0', '3.5.0', '4.1.9', '4.2.0', '5.0'):
            self.assertEqual(main_verdict(ranges, version) is True, wp_matches(ranges, version), version)

    def test_the_evidence_of_a_fix_only_branch_match_names_its_fix_in_the_wordpress_path(self):
        cve = FakeCVE(affected_of([{'fixed': '3.1.0'}, {'fixed': '4.2.0'}]))
        found = [{'slug': 'plugin-x', 'title': PRODUCT, 'version': '3.0.9', 'kind': 'wp-plugin'}]
        row = wp_correlation.match_rows(SimpleNamespace(id=1, scan_history_id=None), found, {cve.id: cve}, build_product_index([cve]))[0]
        self.assertEqual(row['evidence']['range'], {'fixed': '3.1.0'})


SPLIT_PHP = [{'introduced': '8.2'}, {'fixed': '8.2.35'}, {'introduced': '8.3'}, {'fixed': '8.3.36'}, {'introduced': '8.4'}, {'fixed': '8.4.27'}]


class UnlistedBranchTests(SimpleTestCase):
    """A branch-by-branch advisory names only the branches that got a fix; an older branch is not cleared (match_policy: branch_unlisted).
    That holds when the CVE List wrote each branch as two entries."""

    def _verdict(self, ranges, version):
        details = {}
        return main_verdict(ranges, version, details), details.get(1, {})

    def test_an_older_branch_of_a_split_branch_list_is_unknown_not_cleared(self):
        joined = [{'introduced': '8.2', 'fixed': '8.2.35'}, {'introduced': '8.3', 'fixed': '8.3.36'}, {'introduced': '8.4', 'fixed': '8.4.27'}]
        for version in ('7.4.33', '8.0.30', '8.1.30'):
            verdict, detail = self._verdict(joined, version)
            self.assertIsNone(verdict, version)
            self.assertTrue(detail.get('branch_unlisted'), version)
            verdict, detail = self._verdict(SPLIT_PHP, version)
            self.assertIsNone(verdict, f'split: {version}')
            self.assertTrue(detail.get('branch_unlisted'), f'split: {version}')

    def test_the_fixed_releases_of_a_split_branch_list_are_still_not_vulnerable(self):
        for version in ('8.2.35', '8.3.40', '8.4.27', '9.0.0'):
            self.assertIs(self._verdict(SPLIT_PHP, version)[0], False, version)
        self.assertIs(self._verdict(SPLIT_PHP, '8.3.10')[0], True)


def _confluence():
    out = [{'fixed': '7.4.17'}]
    for branch, fix in (('7.13', '7.13.7'), ('7.14', '7.14.3'), ('7.15', '7.15.2'), ('7.16', '7.16.4'), ('7.17', '7.17.4'), ('7.18', '7.18.1')):
        out += [{'introduced': branch + '.0'}, {'fixed': fix}]
    return out


CONFLUENCE = _confluence()  # 13 ranges: the real CVE-2022-26134 shape
CONFLUENCE_AFFECTED = [{'vendor': 'Atlassian', 'product': 'Confluence Server', 'ranges': CONFLUENCE}]
JOINED_TAIL = [{'introduced': '7.17.0', 'fixed': '7.17.4'}, {'introduced': '7.18.0', 'fixed': '7.18.1'}]


def plain(ranges):
    return [{k: v for k, v in r.items()} for r in ranges]


class ConsumerTests(SimpleTestCase):
    """The brief, the strategy, the agent API and the prompts read the ranges as matching does: a branch is one range, and the last
    branches are not cut off by a limit counted in the CVE List's half-entries."""

    def assertJoined(self, ranges):
        ranges = plain(ranges)
        for joined in JOINED_TAIL:
            self.assertIn(joined, ranges)
        self.assertNotIn({'introduced': '7.17.0'}, ranges)  # no half left over
        self.assertNotIn({'introduced': '7.13.0'}, ranges)

    def test_the_triage_brief(self):
        from cveFeed.triage import affected_brief
        self.assertJoined(affected_brief(CONFLUENCE_AFFECTED)[0]['ranges'])

    def test_the_rules_detection_strategy(self):
        from cveFeed import detection
        strategy = detection.rules_strategy(FakeCVE(CONFLUENCE_AFFECTED), [])
        check = next(c for c in strategy['remote_checks'] if c['kind'] == 'version_banner')
        self.assertJoined(check['params']['ranges'])
        self.assertIn({'fixed': '7.4.17'}, check['params']['ranges'])

    def test_the_agent_api_cve_context(self):
        from agentapi import services
        from cveFeed.models import CVEEntry
        cve = CVEEntry(cve_id='CVE-2099-5', title='x', affected=CONFLUENCE_AFFECTED)
        self.assertJoined(services._cve_context(cve)['affected'][0]['ranges'])

    def test_the_detection_authoring_prompt(self):
        from cveFeed import detection_author
        from cveFeed.models import CVEEntry
        cve = CVEEntry(cve_id='CVE-2099-6', title='x', affected=CONFLUENCE_AFFECTED)
        prompt = detection_author.build_user_prompt(cve)
        info = json.loads(prompt[prompt.index('{'):prompt.rindex('}') + 1])
        self.assertJoined(info['affected'][0]['ranges'])

    def test_the_template_and_validation_prompt_context(self):
        from cveFeed import templategen
        from cveFeed.models import CVEEntry
        cve = CVEEntry(cve_id='CVE-2099-7', title='x', affected=CONFLUENCE_AFFECTED)
        self.assertJoined(templategen.cve_info_for(cve)['affected'][0]['ranges'])

    def test_the_fixed_versions_of_a_finding_list_every_fix_of_the_split_ranges(self):
        from agentapi import services
        cve = SimpleNamespace(affected=CONFLUENCE_AFFECTED)
        self.assertEqual(services._fixed_versions(cve, 'Confluence'),
                         sorted({'7.4.17', '7.13.7', '7.14.3', '7.15.2', '7.16.4', '7.17.4', '7.18.1'}))

    def test_a_consumer_never_reads_a_fixed_release_as_inside_a_range_the_matcher_clears(self):
        """The brief's ranges, read with the matcher's own comparison, agree with the matcher for every release."""
        from cveFeed.correlation import version_in_range
        from cveFeed.triage import affected_brief
        brief = affected_brief(CONFLUENCE_AFFECTED)[0]['ranges']
        for version in ('7.4.16', '7.4.17', '7.13.6', '7.13.7', '7.14.3', '7.16.3', '7.16.4', '7.17.3', '7.17.4', '7.18.0', '7.18.1', '7.19.0'):
            from_brief = any(version_in_range(parse_version(version), r) is True for r in brief)
            self.assertEqual(from_brief, main_verdict(CONFLUENCE, version) is True, version)


class PairingTests(SimpleTestCase):
    def pair(self, ranges):
        from cveFeed.correlation import pair_split_ranges
        return pair_split_ranges(ranges)

    def test_an_introduced_range_is_joined_to_the_last_affected_that_follows_it(self):
        self.assertEqual(self.pair([{'introduced': '1.0'}, {'lastAffected': '1.5'}]), [{'introduced': '1.0', 'lastAffected': '1.5'}])
        self.assertEqual(self.pair([{'introduced': '1.0'}, {'lastAffected': '1.0'}]), [{'introduced': '1.0', 'lastAffected': '1.0'}])  # one release

    def test_starts_and_fixes_listed_apart_are_paired_by_version(self):
        self.assertEqual(self.pair([{'introduced': '1.0'}, {'introduced': '2.0'}, {'fixed': '1.5'}, {'fixed': '2.5'}]),
                         [{'introduced': '1.0', 'fixed': '1.5'}, {'introduced': '2.0', 'fixed': '2.5'}])
        self.assertEqual(self.pair([{'fixed': '1.5'}, {'introduced': '1.0'}]), [{'introduced': '1.0', 'fixed': '1.5'}])
        # the last start may stay open: a branch with no fix
        self.assertEqual(self.pair([{'introduced': '1.0'}, {'introduced': '2.0'}, {'fixed': '1.5'}]),
                         [{'introduced': '1.0', 'fixed': '1.5'}, {'introduced': '2.0'}])

    def test_a_fix_older_than_every_start_is_left_alone(self):
        ranges = [{'introduced': '2.0'}, {'fixed': '1.0'}]
        self.assertEqual(self.pair(ranges), ranges)

    def test_bounds_that_cannot_be_paired_are_unknown_never_in_range(self):
        from cveFeed.correlation import _Unpaired, version_in_range
        for ranges in ([{'introduced': '1.0'}, {'fixed': '1.0'}],
                       [{'introduced': '1.0'}, {'introduced': '2.0'}, {'introduced': '3.0'}, {'fixed': '2.5'}],
                       [{'introduced': '1.0', 'type': 'SEMVER'}, {'fixed': '1.5', 'type': 'ECOSYSTEM'}]):
            paired = self.pair(ranges)
            self.assertEqual(paired, ranges)  # still the feed's own dicts, only marked
            self.assertTrue(all(isinstance(r, _Unpaired) for r in paired), ranges)
            self.assertTrue(all(version_in_range(parse_version(v), r) is None for r in paired for v in ('0.5', '1.2', '9.0')), ranges)

    def test_pairing_twice_changes_nothing(self):
        for ranges, _a, _f in SHAPES.values():
            once = self.pair(ranges)
            self.assertEqual(self.pair(once), once)
            self.assertEqual([type(r) for r in self.pair(once)], [type(r) for r in once])
