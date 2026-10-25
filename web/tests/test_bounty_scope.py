from django.test import SimpleTestCase

from cveFeed import bounty_scope as bs


def a(kind, ident, inside=True, pays=None, sev='', removed=None):
    return {'kind': kind, 'identifier': ident, 'in_scope': inside, 'eligible_for_bounty': pays, 'max_severity': sev, 'removed_at': removed}


class ScopeVerdictTests(SimpleTestCase):
    def check(self, assets, host):
        return bs.ScopeIndex(assets).check(host)

    def test_exact_domain(self):
        v = self.check([a('domain', 'app.example.com', pays=True, sev='high')], 'app.example.com')
        self.assertEqual(v.state, bs.IN)
        self.assertTrue(v.reportable)
        self.assertEqual((v.eligible_for_bounty, v.max_severity), (True, 'high'))

    def test_a_listed_domain_does_not_cover_its_subdomains(self):
        v = self.check([a('domain', 'example.com')], 'api.example.com')
        self.assertEqual(v.state, bs.NOT_LISTED)
        self.assertIn('subdomains', v.reason)

    def test_wildcard_covers_subdomains_at_any_depth(self):
        for host in ('a.example.com', 'a.b.example.com'):
            self.assertEqual(self.check([a('wildcard', '*.example.com')], host).state, bs.IN)

    def test_wildcard_apex_is_unclear_not_in_scope(self):
        v = self.check([a('wildcard', '*.example.com')], 'example.com')
        self.assertEqual(v.state, bs.AMBIGUOUS)
        self.assertTrue(v.needs_confirmation)
        self.assertFalse(v.reportable)

    def test_out_of_scope_beats_a_wildcard(self):
        v = self.check([a('wildcard', '*.example.com'), a('domain', 'status.example.com', inside=False)], 'status.example.com')
        self.assertEqual(v.state, bs.OUT)

    def test_out_of_scope_rules_out_everything_under_it(self):
        v = self.check([a('wildcard', '*.example.com'), a('domain', 'corp.example.com', inside=False)], 'x.corp.example.com')
        self.assertEqual(v.state, bs.OUT)

    def test_out_of_scope_wildcard(self):
        v = self.check([a('domain', 'www.example.com'), a('wildcard', '*.example.com', inside=False)], 'www.example.com')
        self.assertEqual(v.state, bs.OUT)

    def test_the_longest_wildcard_gives_the_verdict_entry(self):
        v = self.check([a('wildcard', '*.example.com', pays=False), a('wildcard', '*.api.example.com', pays=True)], 'x.api.example.com')
        self.assertEqual((v.state, v.asset, v.eligible_for_bounty), (bs.IN, '*.api.example.com', True))

    def test_a_url_entry_with_a_path_is_unclear_for_the_host(self):
        v = self.check([a('url', 'www.example.com/app')], 'www.example.com')
        self.assertEqual(v.state, bs.AMBIGUOUS)
        self.assertIn('/app', v.reason)

    def test_a_url_entry_without_a_path_is_the_host(self):
        self.assertEqual(self.check([a('url', 'www.example.com')], 'https://www.example.com/x').state, bs.IN)

    def test_pattern_entries_are_unclear_never_in_scope(self):
        v = self.check([a('other', 'api-*.example.com')], 'api-eu.example.com')
        self.assertEqual(v.state, bs.AMBIGUOUS)

    def test_prose_scope_makes_everything_unclear(self):
        v = self.check([a('other', 'all')], 'whatever.example.org')
        self.assertEqual(v.state, bs.AMBIGUOUS)

    def test_nothing_listed(self):
        self.assertEqual(self.check([a('domain', 'example.com')], 'other.org').state, bs.NOT_LISTED)
        self.assertEqual(self.check([], 'other.org').state, bs.NOT_LISTED)

    def test_removed_entries_are_ignored(self):
        self.assertEqual(self.check([a('domain', 'app.example.com', removed='2026-01-01')], 'app.example.com').state, bs.NOT_LISTED)

    def test_case_ports_and_urls_do_not_matter(self):
        self.assertEqual(self.check([a('domain', 'app.example.com')], 'HTTPS://App.Example.com:8443/x?y=1').state, bs.IN)

    def test_not_a_host(self):
        for value in ('', None, 'not a host', 'x' * 3000):
            self.assertEqual(self.check([a('domain', 'example.com')], value).state, bs.NOT_LISTED, value)

    def test_ip_in_cidr_and_exact(self):
        assets = [a('cidr', '198.51.100.0/24'), a('ip', '203.0.113.7')]
        self.assertEqual(self.check(assets, '198.51.100.9').state, bs.IN)
        self.assertEqual(self.check(assets, '203.0.113.7').state, bs.IN)
        self.assertEqual(self.check(assets, '203.0.113.8').state, bs.NOT_LISTED)

    def test_out_of_scope_range_beats_in_scope_range(self):
        v = self.check([a('cidr', '198.51.100.0/24'), a('cidr', '198.51.100.128/25', inside=False)], '198.51.100.200')
        self.assertEqual(v.state, bs.OUT)

    def test_ipv6(self):
        self.assertEqual(self.check([a('cidr', '2001:db8::/32')], '2001:db8::5').state, bs.IN)

    def test_verdict_dict_shape(self):
        d = self.check([a('domain', 'example.com', pays=True)], 'example.com').as_dict()
        self.assertEqual(set(d), {'state', 'reason', 'asset', 'eligible_for_bounty', 'max_severity'})


class ImportPlanTests(SimpleTestCase):
    def test_in_scope_entries_become_targets_and_wildcards_become_their_base(self):
        plan = bs.import_plan([a('domain', 'app.example.com'), a('wildcard', '*.example.org'), a('url', 'www.example.net/app')])
        self.assertEqual([t['value'] for t in plan['targets']], ['app.example.com', 'example.org', 'www.example.net'])
        self.assertEqual(plan['skipped'], [])

    def test_out_of_scope_and_removed_are_never_imported(self):
        plan = bs.import_plan([a('domain', 'no.example.com', inside=False), a('domain', 'gone.example.com', removed='2026-01-01')])
        self.assertEqual(plan['targets'], [])

    def test_an_explicit_entry_wins_over_a_wildcards_base(self):
        plan = bs.import_plan([a('wildcard', '*.x.example.com'), a('domain', 'x.example.com')])
        self.assertEqual(plan['targets'], [{'value': 'x.example.com', 'asset': 'x.example.com', 'note': ''}])

    def test_duplicates_collapse(self):
        plan = bs.import_plan([a('domain', 'x.example.com'), a('url', 'x.example.com/a'), a('wildcard', '*.x.example.com')])
        self.assertEqual([t['value'] for t in plan['targets']], ['x.example.com'])

    def test_a_big_block_is_skipped_with_a_reason_and_a_small_one_expands(self):
        plan = bs.import_plan([a('cidr', '198.51.100.0/24'), a('cidr', '203.0.113.0/30')])
        self.assertEqual(len(plan['skipped']), 1)
        self.assertIn('256 addresses', plan['skipped'][0]['reason'])
        self.assertEqual([t['value'] for t in plan['targets']], ['203.0.113.1', '203.0.113.2'])

    def test_addresses_the_scanner_may_not_touch_are_skipped(self):
        plan = bs.import_plan([a('ip', '10.0.0.5'), a('ip', '203.0.113.7')], scannable=lambda ip: not ip.startswith('10.'))
        self.assertEqual([t['value'] for t in plan['targets']], ['203.0.113.7'])
        self.assertEqual(plan['skipped'][0]['asset'], '10.0.0.5')

    def test_mobile_code_and_prose_are_skipped_with_reasons(self):
        plan = bs.import_plan([a('mobile', 'com.x.app'), a('code', 'https://github.com/x/y'), a('other', 'everything we own')])
        self.assertEqual(plan['targets'], [])
        self.assertEqual(len(plan['skipped']), 3)
