"""Third review of the JavaScript library provenance rule (cveFeed.js_libraries, correlation): a page proves a library ABSENT (or a version
a cache-buster) only when every script on it was read whole; a fresh reading, even a partial one, reopens a match the page closed; a match
someone vouched for survives a rescan. Each test asserts the safe outcome."""
from django.test import SimpleTestCase
from django.utils import timezone
from unittest import mock
import os

from cveFeed import correlation, js_libraries
from cveFeed.models import CVEMatch, RouteAuth
from startScan.models import Technology
from tests.test_js_libraries_provenance import ReviewScenarioBase
from tests.test_js_library_versions import JQ_371_MIN

JQ_1124 = '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}'
JQ_UI_1121 = '/*! jQuery UI - v1.12.1 - 2016-09-14\n* http://jqueryui.com\n* Includes: widget.js */\n!function(){}'


class ReopenOnAFreshReadingTests(ReviewScenarioBase):
    """A match the page closed reopens on any fresh reading that no longer supports the closure, even a partial one."""

    def closed_by_absence(self, name):
        sub = self.host(name, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(name, 200, '<script src="/site.js"></script>')
        match = self.correlate(sub)[(name, 'CVE-2020-11023', '1.12.4')]
        self.assertEqual(match.ai_verdict, 'not_affected')
        return sub

    def test_the_page_now_pastes_the_library_inline(self):
        sub = self.closed_by_absence('inl2.x.test')
        self.read_root('inl2.x.test', 200, f'<script>{JQ_1124}</script><script src="/site.js"></script>')
        self.assertEqual(RouteAuth.objects.get(host='inl2.x.test').evidence['script_page']['inline'], [{'library': 'jquery', 'version': '1.12.4'}])
        self.assertNotEqual(self.correlate(sub)[('inl2.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_a_host_that_redirected_now_serves_its_own_login_page(self):
        sub = self.host('al.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('al.x.test', 301, '', location='https://other.example/')
        self.assertIn('only redirects', self.correlate(sub)[('al.x.test', 'CVE-2020-11023', '1.12.4')].ai_reason)
        self.read_root('al.x.test', 200, '<html><title>Sign in</title><form><input type="password" name="p"></form>'
                                          '<script src="/app.js"></script></html>', title='Sign in')
        self.assertNotEqual(self.correlate(sub)[('al.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_page_now_loads_the_library_past_the_parse_limit(self):
        sub = self.closed_by_absence('cap.x.test')
        filler = ''.join(f'<script src="/p/{i}.js"></script>' for i in range(85))
        self.read_root('cap.x.test', 200, filler + '<script src="/legacy/jquery-1.12.4.min.js"></script>')
        self.assertNotEqual(self.correlate(sub)[('cap.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_host_gains_a_web_port_not_read_yet(self):
        from startScan.models import Port
        sub = self.closed_by_absence('port.x.test')
        sub.ip_addresses.first().ports.add(Port.objects.create(number=8443, service_name='https', state='open'))
        self.assertNotEqual(self.correlate(sub)[('port.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')


class UnreadScriptsProveNothingTests(ReviewScenarioBase):
    """A script that was not read whole may hold the library under any name: no absence, no cache-buster."""

    def test_a_bundle_whose_read_failed(self):
        sub = self.host('bun.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('bun.x.test', 200, '<script src="/assets/vendor.bundle.js"></script>', scripts={})
        self.assertEqual(RouteAuth.objects.get(host='bun.x.test').evidence['script_page']['unread'], 1)
        self.assertEqual(self.correlate(sub)[('bun.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        read = self.host('bun2.x.test', ['jQuery:1.12.4'])  # and read, the bundle states it: matched from the file
        self.correlate(read)
        self.read_root('bun2.x.test', 200, '<script src="/assets/vendor.bundle.js"></script>', scripts={'https://bun2.x.test/assets/vendor.bundle.js': JQ_1124})
        self.assertEqual(self.correlate(read)[('bun2.x.test', 'CVE-2020-11023', '1.12.4')].evidence['version_source'], 'body')

    def test_the_read_budget_spent_before_the_bundle(self):
        sub = self.host('bud.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        scripts = {f'https://bud.x.test/t/{i}.js': 'var a=1;' for i in range(8)}
        scripts['https://bud.x.test/assets/vendor.bundle.js'] = JQ_1124
        self.read_root('bud.x.test', 200, ''.join(f'<script src="/t/{i}.js"></script>' for i in range(8))
                       + '<script src="/assets/vendor.bundle.js"></script>', scripts=scripts)
        self.assertEqual(self.correlate(sub)[('bud.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')

    def test_a_third_party_bundle_that_is_never_read(self):
        sub = self.host('cdnb.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('cdnb.x.test', 200, '<script src="https://cdn.shop-assets.example/s/files/1/theme/vendor.min.js"></script>')
        self.assertEqual(self.correlate(sub)[('cdnb.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')

    def test_script_reading_switched_off(self):
        sub = self.host('off.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        with mock.patch.dict(os.environ, {'CVENGINE_SCRIPT_BODY_READ': '0'}):
            self.read_root('off.x.test', 200, '<script src="/assets/vendor.min.js"></script>', scripts={'https://off.x.test/assets/vendor.min.js': JQ_1124})
        self.assertEqual(self.correlate(sub)[('off.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')


class WordPressCoreQueryVersionTests(ReviewScenarioBase):
    """WordPress core loads jQuery UI as wp-includes/js/jquery/ui/*.min.js?ver=<jQuery UI's own version>: that ?ver= is never a theme's or
    plugin's cache-buster, whether or not the file was read."""

    def setUp(self):
        super().setUp()
        from cveFeed.models import CVEEntry
        self.ui = CVEEntry.objects.create(cve_id='CVE-2021-41184', cvss=6.1, published_at=timezone.now(),
                                          affected=[{'vendor': 'jqueryui', 'product': 'jquery_ui', 'ranges': [{'introduced': '0', 'fixed': '1.13.0'}]}])
        self.entries = [self.jq, self.bs, self.ui]

    def jquery_ui(self, host, plugins):
        page = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                '<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>'
                + ''.join(f'<script src="/wp-content/plugins/p{i}/front.js?ver=2.{i}"></script>' for i in range(plugins))
                + '<script src="/wp-includes/js/jquery/ui/core.min.js?ver=1.12.1"></script>'
                  '<script src="/wp-includes/js/jquery/ui/datepicker.min.js?ver=1.12.1"></script>')
        scripts = {f'https://{host}/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN,
                   f'https://{host}/wp-includes/js/jquery/jquery-migrate.min.js': '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation */',
                   f'https://{host}/wp-includes/js/jquery/ui/core.min.js': JQ_UI_1121, f'https://{host}/wp-includes/js/jquery/ui/datepicker.min.js': JQ_UI_1121}
        scripts.update({f'https://{host}/wp-content/plugins/p{i}/front.js': 'var p=1;' for i in range(plugins)})
        sub = self.host(host, ['jQuery UI:1.12.1', 'jQuery:3.7.1'])
        self.correlate(sub)
        self.read_root(host, 200, page, scripts=scripts)
        return self.correlate(sub)[(host, 'CVE-2021-41184', '1.12.1')]

    def test_ui_core_read(self):
        self.assertNotEqual(self.jquery_ui('wpa.x.test', 1).ai_verdict, 'not_affected')

    def test_ui_core_past_the_read_budget(self):
        self.assertNotEqual(self.jquery_ui('wpb.x.test', 8).ai_verdict, 'not_affected')
        page = RouteAuth.objects.get(host='wpb.x.test').evidence['script_page']
        self.assertIn({'version': '1.12.1', 'library': 'other'}, page['query_versions'])  # a core path: never a cache-buster


class VouchedForTests(ReviewScenarioBase):
    def test_a_vouched_for_match_is_held_only_against_the_page(self):
        from django.contrib.auth import get_user_model
        from cveFeed.tasks import reconcile_library_provenance
        user = get_user_model().objects.create(username='v6')
        sub = self.host('v6.x.test', ['jQuery:1.12.4'])
        match = self.correlate(sub)[('v6.x.test', 'CVE-2020-11023', '1.12.4')]
        CVEMatch.objects.filter(pk=match.pk).update(assignee=user)
        self.read_root('v6.x.test', 200, '<script src="/site.js"></script>')
        self.correlate(sub)
        reconcile_library_provenance()
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).ai_verdict, '')
        sibling = self.host('v7.x.test', ['jQuery:1.12.4'])  # the same page, nobody vouches: it closes
        self.correlate(sibling)
        self.read_root('v7.x.test', 200, '<script src="/site.js"></script>')
        self.assertEqual(self.correlate(sibling)[('v7.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_a_vouched_for_version_that_left_the_host_closes_even_where_the_page_contradicts_it(self):
        from django.contrib.auth import get_user_model
        user = get_user_model().objects.create(username='v9')
        sub = self.host('v9.x.test', ['jQuery:1.12.4'])
        match = self.correlate(sub)[('v9.x.test', 'CVE-2020-11023', '1.12.4')]
        CVEMatch.objects.filter(pk=match.pk).update(assignee=user)
        # the whole page says 3.7.1, every script read; the host's technologies now name 3.7.1 only: an ordinary stale match
        self.read_root('v9.x.test', 200, '<script src="/js/jquery.min.js"></script>', scripts={'https://v9.x.test/js/jquery.min.js': JQ_371_MIN})
        sub.technologies.clear()
        sub.technologies.add(Technology.objects.get_or_create(name='jQuery:3.7.1')[0])
        self.correlate(sub)
        after = CVEMatch.objects.get(pk=match.pk)
        self.assertEqual(after.ai_verdict, 'not_affected')
        self.assertTrue(after.ai_reason.startswith('Closed automatically: the host no longer matches'), after.ai_reason)

    def test_the_next_scans_row_keeps_a_vouched_for_match_and_its_work(self):
        from django.contrib.auth import get_user_model
        from startScan.models import ScanHistory, Subdomain
        user = get_user_model().objects.create(username='n10')
        sub = self.host('ns.x.test', ['jQuery:1.12.4'])
        match = self.correlate(sub)[('ns.x.test', 'CVE-2020-11023', '1.12.4')]
        CVEMatch.objects.filter(pk=match.pk).update(assignee=user, remediation_status='in_progress')
        self.read_root('ns.x.test', 200, '<script src="/site.js"></script>')
        self.assertEqual(self.correlate(sub)[('ns.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')  # held on its own row
        scan2 = ScanHistory.objects.create(domain=self.site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[],
                                           results_dir='y')
        sub2 = Subdomain.objects.create(name='ns.x.test', target_domain=self.site, scan_history=scan2)
        sub2.ip_addresses.add(*sub.ip_addresses.all())
        sub2.technologies.add(*sub.technologies.all())
        carried = self.correlate(sub2)[('ns.x.test', 'CVE-2020-11023', '1.12.4')]
        self.assertEqual((carried.ai_verdict, carried.remediation_status, carried.assignee_id), ('', 'in_progress', user.pk))
        unvouched = self.host('nu.x.test', ['jQuery:1.12.4'])  # nobody vouched: the next row has no match
        self.read_root('nu.x.test', 200, '<script src="/site.js"></script>')
        self.assertEqual(self.correlate(unvouched), {})


class ParseAndSeedTests(SimpleTestCase):
    def test_more_inline_scripts_than_are_read_make_the_page_capped(self):
        page = ''.join('<script>var x%d=1;</script>' % i for i in range(101)) + '<script src="/a.js"></script>'
        self.assertTrue(js_libraries.parse_page(page, 'https://x.test/').capped)
        page = ''.join('<script>var x%d=1;</script>' % i for i in range(100)) + '<script src="/a.js"></script>'
        self.assertFalse(js_libraries.parse_page(page, 'https://x.test/').capped)

    def test_a_banner_deep_in_an_inline_script_and_an_unnamed_licensed_inline_bundle(self):
        late = '<script>' + 'var cfg=1;' * 500 + '\n/*! jQuery v1.12.4 | (c) jQuery Foundation */\n!function(){}</script>'
        self.assertEqual(js_libraries.parse_page(late, 'https://x.test/').inline, [('jquery', '1.12.4')])
        lodash = ('<script>' + 'var cfg=1;' * 500 + '\n/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */\n'
                  ';(function(){var VERSION="4.17.15";}())</script>')
        parsed = js_libraries.parse_page(lodash, 'https://x.test/')
        self.assertEqual((parsed.inline, parsed.inline_unread), ([], 1))  # licensed third-party code no rule names: unknown, not absent
        self.assertEqual(js_libraries.parse_page('<script>var a=1;</script>', 'https://x.test/').inline_unread, 0)

    def test_seeding_refuses_a_library_closure_where_every_other_rule_would_seed_it(self):
        from types import SimpleNamespace
        row = {'source': 'tech', 'evidence': {'source': 'tech'}, 'version_in_range': False, 'distro_status': 'no_data'}
        # no shared closing verdict is seeded at all since task 256 (it may rest on another tenant's host); the library guard also refuses
        # a verdict that is not a closure when its reason is a library closure, where every other rule would seed it
        other = SimpleNamespace(ai_verdict='uncertain', ai_reason='needs a check', ai_model='x')
        self.assertIs(correlation._seedable(other, row), other)
        closed = SimpleNamespace(ai_verdict='not_affected', ai_reason='Closed automatically: different product', ai_model='x')
        self.assertIsNone(correlation._seedable(closed, row))
        library = SimpleNamespace(ai_verdict='not_affected', ai_reason=js_libraries.closed_reason('the front page loads no jQuery'), ai_model='x')
        self.assertIsNone(correlation._seedable(library, row))
        library.ai_verdict = 'uncertain'
        self.assertIsNone(correlation._seedable(library, row))
