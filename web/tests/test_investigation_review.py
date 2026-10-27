"""Regression tests for the independent review of the investigation work: hostile pages, forged headers, weak signals, privacy and tenancy of
what goes into a prompt, ordering under a cap, and the exact identity a plugin CVE needs."""
import time
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import host_context, probes, triage, versions, wp_correlation, wpscan_scan
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation, ServiceRun
from startScan.models import Subdomain
from tenancy.scope import SCOPES
from tests.test_investigation import ContextFixture
from tests.test_probes import page
from tests.test_wordpress import PLUGIN_REPORT, WordPressFixture, cve


class HostilePageTests(SimpleTestCase):
    """A scanned host chooses what it answers: no pattern may cost time that grows faster than the page."""
    LIMIT = 2.0

    def timed(self, fn):
        started = time.monotonic()
        fn()
        return time.monotonic() - started

    def test_a_page_of_blank_lines_does_not_stall_the_error_page_rules(self):
        probe = probes.BY_ID['error-page']
        body = '\n' * probes.route_auth.MAX_PROBE_BYTES if hasattr(probes, 'route_auth') else '\n' * 262144
        self.assertLess(self.timed(lambda: probes.apply_rules(probe, [page(404, body=body)])), self.LIMIT)

    def test_repeated_wordpress_paths_do_not_stall_the_signature_scan(self):
        body = '/wp-includes/' * 20000
        self.assertLess(self.timed(lambda: probes._wordpress_signals([('/', page(body=body))])), self.LIMIT)

    def test_a_long_script_tag_does_not_stall_the_nextjs_rule(self):
        self.assertLess(self.timed(lambda: probes.next_version('next' + ' ' * 200000 + '=' + ' ' * 200000)), self.LIMIT)

    def test_only_the_first_64_kb_of_a_page_is_read_for_markers(self):
        late = '<meta name="generator" content="WordPress 6.4.2">'
        signals, _version = probes._wordpress_signals([('/', page(body='x' * (probes.BODY_SCAN + 10) + late))])
        self.assertFalse(signals)


class ForgedHeaderTests(SimpleTestCase):
    def names(self, value):
        return {c['product'] for c in versions.parse_server_header(value)['components']}

    def test_a_name_the_host_adds_after_its_web_server_is_not_a_technology(self):
        self.assertEqual(self.names('nginx/1.25.3 Log4j/2.14.1 Struts/2.3.30'), {'nginx'})

    def test_nothing_after_an_edge_names_the_software_behind_it(self):
        self.assertEqual(self.names('cloudflare Log4j/2.14.1'), {'Cloudflare'})

    def test_apache_modules_still_count(self):
        found = versions.parse_server_header('Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16 mod_wsgi/3.4 Python/2.7.5')
        self.assertTrue({'Apache HTTP Server', 'OpenSSL', 'PHP'} <= {c['product'] for c in found['components']})

    def test_a_bare_major_or_a_v_prefix_is_read_correctly(self):
        self.assertEqual(versions._version('10'), '')  # "Drupal 10" parses as (10,) and would sit inside every "before 10.2" range
        self.assertEqual(versions._version('v5.16.3'), '5.16.3')
        self.assertEqual(versions._version('1.24.0'), '1.24.0')


class SignalsAreNoTechnologyTests(WordPressFixture, TestCase):
    def test_a_weak_wordpress_signal_never_becomes_a_technology(self):
        wpscan_scan.record_signals(self.project.id, self.domain.id, 'www.rt.test', ['archive:wp-content'])
        self.assertEqual(probes.apply_known(self.scan_obj), 0)
        self.assertFalse(Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test').technologies.filter(name__icontains='wordpress').exists())

    def test_a_wpscan_state_row_never_becomes_a_technology(self):
        wpscan_scan.record_state(self.project.id, self.domain.id, 'www.rt.test', 'scanned', version='6.4.2')
        self.assertEqual(probes.apply_known(self.scan_obj), 0)


class PrivacyTests(ContextFixture, TestCase):
    def test_a_tailnet_device_gives_the_prompt_no_name_address_or_login(self):
        from cveFeed.models import TailscaleDevice, TailscaleLink
        link = TailscaleLink.objects.create(project=self.project)
        TailscaleDevice.objects.create(
            link=link, project=self.project, node_id='n1', domain=self.domain, name='laptop-of-someone', online=True,
            facts={'os': 'linux', 'client_version': '1.80.0', 'tags': ['tag:server'], 'hostname': 'laptop-of-someone', 'addresses': ['100.64.1.2'],
                   'user': 'someone@example.test', 'name': 'laptop-of-someone.tailnet.ts.net'})
        self.sub.name = self.domain.name
        self.sub.save()
        text = str(host_context.clipped(host_context.host_context(self.fresh())))
        for secret in ('laptop-of-someone', '100.64.1.2', 'someone@example.test'):
            self.assertNotIn(secret, text)
        self.assertIn('1.80.0', text)


class ContextMemoTests(ContextFixture, TestCase):
    def test_nothing_is_remembered_outside_a_tracked_batch(self):
        match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-9', cvss=5, affected=[]), subdomain=self.sub,
                                        matched_product='nginx', matched_version='1.24.0', version_in_range=True, source='tech')
        d = {'facts': {}, 'signature_fields': {}}
        triage.attach_host_context(d, match)
        self.assertIsNone(triage._CONTEXT_MEMO.get())  # a long-lived worker serves a fresh context the next time
        before = d['facts'].get('closure_basis')
        self.observe('identity', 'nginx', variant='nginx', confidence=0.8)
        d2 = {'facts': {}, 'signature_fields': {}}
        triage.attach_host_context(d2, match)
        self.assertIsNotNone(d2['facts'])
        self.assertEqual(before, [])  # the first read had no probe; the second read is not served from a stale memo

    def test_inside_a_tracked_batch_one_host_is_read_once(self):
        with mock.patch('cveFeed.host_context.host_context', wraps=host_context.host_context) as read:
            token = triage._CONTEXT_MEMO.set({})
            try:
                match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.create(cve_id='CVE-2099-8', cvss=5, affected=[]), subdomain=self.sub,
                                                matched_product='nginx', version_in_range=True, source='tech')
                for _ in range(3):
                    triage.attach_host_context({'facts': {}, 'signature_fields': {}}, match)
            finally:
                triage._CONTEXT_MEMO.reset(token)
        self.assertEqual(read.call_count, 1)


class TenancyTests(SimpleTestCase):
    def test_probe_observations_are_scoped_to_their_project(self):
        self.assertEqual(SCOPES['cveFeed.ProbeObservation'], 'project_id')


class CapOrderTests(WordPressFixture, TestCase):
    def test_fresh_hosts_never_use_up_the_cap_that_a_never_probed_host_needs(self):
        # one probe slot, and the first name (alphabetically) was probed a minute ago: the host that never was must still get it
        for host in ('www.rt.test', 'rt.test'):
            ServiceRun.objects.create(project=self.project, service='probe', asset=host, status='done')
        subs = list(Subdomain.objects.filter(scan_history=self.scan_obj))
        for sub in subs:
            sub.http_status = 200
            sub.save()
        with mock.patch.object(probes, 'max_hosts', return_value=1), mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            ran = []
            with mock.patch.object(probes, 'run_one', side_effect=lambda project, domain, sub, entry, **kw: ran.append(sub.name) or []):
                probes.run_for_scan(self.scan_obj.id, get=lambda url: None, sleep=lambda s: None)
        self.assertTrue(all(name not in ('www.rt.test', 'rt.test') for name in ran))


class WordPressVerdictTests(WordPressFixture, TestCase):
    def test_a_positive_probe_is_not_overruled_by_a_wpscan_that_saw_a_decoy(self):
        self.table['/wp-login.php'] = page(200, headers={'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}, body='<form id="loginform">')

        def decoy(url, token):
            raise wpscan_scan.NotWordPress('does not seem to be running WordPress')
        self.go(runner=decoy)
        state = self.state('www.rt.test')
        self.assertEqual(state['state'], 'failed')
        self.assertIn('the probe did', state['reason'])
        self.assertEqual(wpscan_scan.status_counts([self.project.id])['reasons'].get('not_wordpress', 0), 0)

    def test_an_apex_that_redirects_to_www_is_asked_once_on_the_redirect_target(self):
        calls = []

        def runner(url, token):
            calls.append(url)
            if len(calls) == 1:
                raise RuntimeError('The URL supplied redirects to: https://www.rt.test/blog/')
            return PLUGIN_REPORT
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='rt.test')
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True), \
                mock.patch('cveFeed.archive_rediscovery.archived_names', return_value=frozenset()), \
                mock.patch('cveFeed.exclusions.is_excluded', return_value=False):
            self.assertIs(wpscan_scan._scan_site(runner, 'https://rt.test/', '', sub, self.project.id), PLUGIN_REPORT)
        self.assertEqual(calls, ['https://rt.test/', 'https://www.rt.test/blog'])

    def test_a_redirect_to_a_foreign_name_is_never_followed(self):
        def runner(url, token):
            raise RuntimeError('The URL supplied redirects to: https://evil.example.test/')
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='rt.test')
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True), self.assertRaises(RuntimeError):
            wpscan_scan._scan_site(runner, 'https://rt.test/', '', sub, self.project.id)


class PluginIdentityTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.sub = Subdomain.objects.select_related('target_domain').get(scan_history=self.scan_obj, name='www.rt.test')

    def sighting(self, slug, version, title=''):
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wpscan-plugin', kind='wp-plugin', product=slug,
                                        version=version, source='wpscan', outcome='found', evidence={'title': title} if title else {})

    def correlate(self):
        from cveFeed import correlation
        correlation._INDEX_CACHE.update(key=None, value=None)
        return wp_correlation.run_for_host(self.sub)

    def test_a_range_of_another_product_in_the_same_advisory_is_not_this_plugins(self):
        CVEEntry.objects.create(cve_id='CVE-2099-0100', title='two products', cvss=6.1, affected=[
            {'product': 'Other Plugin', 'ranges': [{'introduced': '0', 'lastAffected': '9.9'}]},
            {'product': 'Cloudflare Image Resizing', 'ranges': [{'introduced': '2.0', 'fixed': '3.0'}]}])
        self.sighting('other-plugin', '1.0', 'Other Plugin')  # in range of ITS entry
        self.sighting('cf-image-resizing', '1.5.5', 'Cloudflare Image Resizing')  # not inside ITS entry's range
        self.correlate()
        products = set(CVEMatch.objects.filter(subdomain=self.sub, source='wp-plugin').values_list('matched_product', flat=True))
        self.assertEqual(products, {'Other Plugin'})

    def test_a_worked_or_template_confirmed_plugin_match_survives_the_plugin_going_missing(self):
        cve('CVE-2099-0101', 'Cloudflare Image Resizing')
        self.sighting('cf-image-resizing', '1.5.5', 'Cloudflare Image Resizing')
        self.correlate()
        CVEMatch.objects.filter(subdomain=self.sub, source='wp-plugin').update(template_result='vulnerable')
        ProbeObservation.objects.filter(kind='wp-plugin').delete()
        self.correlate()
        self.assertNotEqual(CVEMatch.objects.get(subdomain=self.sub, source='wp-plugin').ai_verdict, 'not_affected')


class NmapArgvTests(SimpleTestCase):
    def test_the_probe_runs_one_fixed_set_of_scripts_and_nothing_else(self):
        argv = probes.nmap_argv('203.0.113.5', 443, 'https')
        self.assertEqual(argv.count('--script'), 1)
        scripts = argv[argv.index('--script') + 1]
        self.assertFalse({'vuln', 'exploit', 'brute', 'intrusive', 'dos', 'fuzzer', 'all'} & set(scripts.split(',')))
        self.assertEqual(argv.count('-p'), 1)
        self.assertEqual(argv[-1], '203.0.113.5')
