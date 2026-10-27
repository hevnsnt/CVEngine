"""WordPress as the primary WPScan target: every sign of WordPress triggers a probe and a scan, every candidate ends in a recorded state, an edge
that challenges the scanner is recorded and never solved, and plugin CVEs match only by exact plugin identity."""
import json
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import host_context, wp_correlation, wpscan_scan
from cveFeed.models import CVEEntry, CVEMatch, HostArchive, ProbeObservation, RouteAuth, ServiceRun
from dashboard.models import ApiCredential
from startScan.models import Subdomain, Technology
from tests.test_probes import answers, page
from tests.test_route_auth import RouteFixture
from tests.test_wpscan import REPORT

LINK = {'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}
CHALLENGE = {**page(202, headers={'server': 'cloudflare', 'cf-ray': 'abc-AMS'}, title=''), 'challenge': 'Cloudflare'}
PLUGIN_REPORT = {'version': {'number': '6.4.2', 'vulnerabilities': []}, 'main_theme': {},
                 'plugins': {'cf-image-resizing': {'version': {'number': '1.5.5'}, 'latest_version': '1.6.0', 'outdated': True,
                                                   'found_by': 'Urls In Homepage (Passive Detection)'},
                             'akismet': {'version': {'number': None}}},
                 'vuln_api': {'plan': 'free', 'requests_remaining': 5}}


class WordPressFixture(RouteFixture):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'rt.test', 'plain.rt.test'))
        self.asked, self.table = [], {}
        self.calls = []

    def probe_get(self, url):
        self.asked.append(url)
        return answers(self.table)(url)

    def runner(self, url, token):
        self.calls.append((url, token))
        return PLUGIN_REPORT

    def go(self, **kw):
        kw.setdefault('probe_get', self.probe_get)
        kw.setdefault('sleep', lambda s: None)
        kw.setdefault('runner', self.runner)
        with mock.patch('cveFeed.route_auth.host_allowed', return_value=True), mock.patch('cveFeed.wp_correlation.run_for_host'):
            return wpscan_scan.run_wpscan(self.scan_obj.id, **kw)

    def state(self, host):
        return wpscan_scan.state_of(list(ProbeObservation.objects.filter(project=self.project, host=host)))


class CandidateTests(WordPressFixture, TestCase):
    def test_passive_archive_evidence_with_edge_only_live_tags_and_a_202_route_check_still_schedules_wpscan(self):
        """The production pattern: the web archive remembers WordPress (288 URLs under wp-content), the live tags are only the CDN, the route
        check was answered 202 by the edge, and the scanner's own requests are challenged. WPScan must still run and the host must say why."""
        HostArchive.objects.create(project=self.project, domain=self.domain, host='www.rt.test', technologies={'WordPress': {'count': 288, 'sample': ['/wp-content/plugins/cookie-law-info/x.js']}})
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        for name in ('Cloudflare', 'HSTS', 'HTTP/3'):
            sub.technologies.add(Technology.objects.get_or_create(name=name)[0])
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.rt.test', url='https://www.rt.test/', path='/', auth_state='error',
                                 http_status=202, title='', evidence={'server': 'cloudflare'})
        self.table = {'/': CHALLENGE, '/wp-login.php': CHALLENGE, '/wp-json/': CHALLENGE}
        out = self.go()
        self.assertEqual([u for u, _t in self.calls], ['https://www.rt.test'])  # WPScan ran on the candidate
        self.assertEqual(out['scanned'], 1)
        probe = ProbeObservation.objects.get(host='www.rt.test', probe='wordpress-detect')
        self.assertEqual(probe.outcome, 'challenged')
        self.assertIn('Allow the scanner', probe.evidence['hint'])
        self.assertEqual(self.state('www.rt.test')['state'], 'scanned')

    def test_a_header_only_signature_is_detected_and_scanned(self):
        self.table = {'/': page(200, headers=LINK, body='<html>welcome</html>')}
        self.go()
        probe = ProbeObservation.objects.get(host='www.rt.test', probe='wordpress-detect')
        self.assertEqual((probe.outcome, probe.source), ('found', 'header:link-api.w.org'))
        self.assertIn('https://www.rt.test', [u for u, _t in self.calls])
        self.assertTrue(Technology.objects.filter(name='WordPress').exists())

    def test_every_name_of_a_grouped_host_is_probed_and_the_positive_ones_scanned(self):
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        sub.technologies.add(Technology.objects.create(name='WordPress'))
        self.table = {'/wp-login.php': page(200, body='<form id="loginform">')}
        self.go()
        probed = {u.split('/')[2] for u in self.asked}
        self.assertTrue({'www.rt.test', 'rt.test'} <= probed)  # the apex shares the address and the group: probed as well
        self.assertIn('https://rt.test', [u for u, _t in self.calls])

    def test_a_host_with_no_sign_is_recorded_as_not_wordpress_and_not_scanned(self):
        self.go()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.state('plain.rt.test')['state'], 'not_wordpress')

    def test_a_crawled_wp_content_url_and_a_wp_login_form_are_signs(self):
        from startScan.models import EndPoint
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='plain.rt.test')
        EndPoint.objects.create(scan_history=self.scan_obj, target_domain=self.domain, subdomain=sub, http_url='https://plain.rt.test/wp-content/uploads/a.png')
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='rt.test', url='https://rt.test/wp-login.php', path='/wp-login.php',
                                 auth_state='login', http_status=200)
        signals = wpscan_scan.candidate_signals(self.scan_obj, list(Subdomain.objects.filter(scan_history=self.scan_obj)))
        self.assertEqual(signals['plain.rt.test'], ['crawled WordPress path'])
        self.assertEqual(signals['rt.test'], ['route /wp-login.php'])

    def test_a_catch_all_that_answers_200_to_wp_login_is_not_a_sign(self):
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='rt.test', url='https://rt.test/wp-login.php', path='/wp-login.php',
                                 auth_state='open', http_status=200)
        self.assertNotIn('rt.test', wpscan_scan.candidate_signals(self.scan_obj, list(Subdomain.objects.filter(scan_history=self.scan_obj))))


class StateTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test').technologies.add(Technology.objects.create(name='WordPress'))

    def test_an_edge_that_blocks_wpscan_is_an_explicit_state_with_a_hint(self):
        out = self.go(runner=mock.Mock(side_effect=wpscan_scan.Blocked('The target is responding with a 403')))
        state = self.state('www.rt.test')
        self.assertEqual(state['state'], 'blocked')
        self.assertIn('Allow the scanner', state['reason'])
        self.assertIn('never tries to get past', state['reason'])
        self.assertEqual(out['scanned'], 0)

    def test_a_failed_run_is_retried_at_the_next_scan_but_a_clean_one_waits_for_its_ttl(self):
        self.go(runner=mock.Mock(side_effect=RuntimeError('timed out')))
        self.assertEqual(self.state('www.rt.test')['state'], 'failed')
        self.assertEqual(ServiceRun.objects.get(service='wpscan', asset='www.rt.test').status, 'failed')
        out = self.go()  # the failure is not coverage: asked again straight away
        self.assertEqual(out['scanned'], 1)
        self.assertEqual(self.state('www.rt.test')['state'], 'scanned')
        again = self.go()
        self.assertEqual((again['scanned'], again['reused']), (0, 1))  # clean: inside the long window
        from cveFeed import ledger
        self.assertGreater(ledger.ttl('wpscan'), ledger.ttl('wpscan-partial'))

    def test_a_token_that_ran_out_gives_a_short_window_not_a_week(self):
        ApiCredential.objects.create(project=self.project, service='wpscan', value={'api_key': 'tok'})
        self.go(runner=lambda url, token: {**PLUGIN_REPORT, 'vuln_api': {'error': 'API limit reached'}})
        self.assertEqual(self.state('www.rt.test')['vulnerability_data'], 'not checked: API token budget exhausted')
        self.assertTrue(ServiceRun.objects.filter(service='wpscan-partial', asset='www.rt.test').exists())
        self.assertFalse(ServiceRun.objects.filter(service='wpscan', asset='www.rt.test').exists())

    def test_over_the_site_limit_a_candidate_says_it_is_waiting(self):
        Subdomain.objects.get(scan_history=self.scan_obj, name='rt.test').technologies.add(Technology.objects.get(name='WordPress'))
        with mock.patch('cveFeed.wpscan_scan.max_sites', return_value=1):
            self.go()
        states = {h: self.state(h)['state'] for h in ('www.rt.test', 'rt.test')}
        self.assertEqual(sorted(states.values()), ['scanned', 'waiting'])

    def test_without_the_binary_every_candidate_says_so(self):
        with mock.patch('cveFeed.wpscan_scan.installed', return_value=False):
            out = self.go(runner=wpscan_scan.run_wpscan_process)
        self.assertEqual(out['skipped'], 'wpscan is not installed')
        self.assertEqual(self.state('www.rt.test')['state'], 'unavailable')

    def test_status_counts_say_how_many_were_scanned_and_why_the_rest_were_not(self):
        Subdomain.objects.get(scan_history=self.scan_obj, name='rt.test').technologies.add(Technology.objects.get(name='WordPress'))

        def runner(url, token):
            if url.endswith('//rt.test') or url == 'https://rt.test':
                raise wpscan_scan.Blocked('403 forbidden')
            return PLUGIN_REPORT
        self.go(runner=runner)
        self.assertEqual(wpscan_scan.status_counts([self.project.id]), {'hosts': 2, 'scanned': 1, 'never_scanned': 1, 'reasons': {'blocked': 1}})
        self.assertEqual(wpscan_scan.status_counts([self.project.id + 999])['hosts'], 0)  # another project's hosts are not counted


class ComponentTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test').technologies.add(Technology.objects.create(name='WordPress'))

    def test_a_tokenless_run_still_records_plugin_versions_and_titles(self):
        self.table = {'/wp-content/plugins/cf-image-resizing/readme.txt': page(200, body='=== Cloudflare Image Resizing ===\nContributors: x')}
        self.go()
        row = ProbeObservation.objects.get(host='www.rt.test', probe='wpscan-plugin', product='cf-image-resizing')
        self.assertEqual((row.version, row.kind, row.source), ('1.5.5', 'wp-plugin', 'wpscan'))
        self.assertEqual(row.evidence['title'], 'Cloudflare Image Resizing')
        self.assertTrue(row.evidence['outdated'])
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', probe='wpscan-plugin', product='akismet').outcome, 'hidden')
        self.assertEqual(self.calls[0][1], '')  # no token configured
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', probe='wpscan-core').version, '6.4.2')

    def test_a_plugin_that_is_no_longer_reported_is_removed(self):
        self.go()
        self.go(force=True, runner=lambda u, t: {**PLUGIN_REPORT, 'plugins': {}})
        self.assertFalse(ProbeObservation.objects.filter(host='www.rt.test', probe='wpscan-plugin').exists())

    def test_the_host_record_shows_core_plugins_and_where_wordpress_stands(self):
        self.go()
        summary = host_context.wordpress_summary(list(ProbeObservation.objects.filter(host='www.rt.test')))
        self.assertEqual(summary['core'], '6.4.2')
        self.assertEqual(summary['status']['state'], 'scanned')
        self.assertEqual([p['slug'] for p in summary['plugins']], ['akismet', 'cf-image-resizing'])


def cve(cve_id, product, last='1.5.6', package=''):
    item = {'vendor': 'wpvendor', 'product': product, 'ranges': [{'type': 'SEMVER', 'introduced': '0', 'lastAffected': last}]}
    if package:
        item['package'] = package
    return CVEEntry.objects.create(cve_id=cve_id, title=product, affected=[item], cvss=6.1)


class PluginCorrelationTests(WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.sub = Subdomain.objects.select_related('target_domain').get(scan_history=self.scan_obj, name='www.rt.test')

    def sighting(self, slug, version, title='', kind='wp-plugin', probe='wpscan-plugin'):
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe=probe, kind=kind, product=slug,
                                        version=version, source='wpscan', outcome='found' if version else 'hidden', evidence={'title': title} if title else {})

    def correlate(self):
        from cveFeed import correlation
        correlation._INDEX_CACHE.update(key=None, value=None)
        return wp_correlation.run_for_host(self.sub)

    def test_a_plugin_cve_matches_only_when_the_plugin_is_found_at_a_version_in_range(self):
        cve('CVE-2099-0001', 'Cloudflare Image Resizing')
        self.sighting('cf-image-resizing', '1.5.5', 'Cloudflare Image Resizing')
        self.assertEqual(self.correlate(), 1)
        match = CVEMatch.objects.get(subdomain=self.sub, source='wp-plugin')
        self.assertEqual((match.cve_entry.cve_id, match.matched_version, match.version_in_range), ('CVE-2099-0001', '1.5.5', True))
        self.assertEqual(match.evidence['plugin'], 'cf-image-resizing')

    def test_a_fixed_version_a_missing_version_and_a_different_plugin_match_nothing(self):
        cve('CVE-2099-0002', 'Cloudflare Image Resizing')
        self.sighting('cf-image-resizing', '1.5.7', 'Cloudflare Image Resizing')  # past the last affected version
        self.sighting('image-resizing', '1.0', 'Image Resizing')  # a different plugin whose name is contained in the advisory's
        self.sighting('cloudflare', '1.0')  # the same words, not the same plugin
        self.sighting('other', '', 'Cloudflare Image Resizing')  # no version read
        self.assertEqual(self.correlate(), 0)
        self.assertFalse(CVEMatch.objects.filter(subdomain=self.sub).exists())

    def test_the_slug_may_equal_the_advisorys_package_name(self):
        cve('CVE-2099-0003', 'Some Marketing Name', package='cf-image-resizing')
        self.sighting('cf-image-resizing', '1.0')
        self.assertEqual(self.correlate(), 1)

    def test_a_removed_plugin_closes_its_match(self):
        cve('CVE-2099-0004', 'Cloudflare Image Resizing')
        self.sighting('cf-image-resizing', '1.5.5', 'Cloudflare Image Resizing')
        self.correlate()
        ProbeObservation.objects.filter(kind='wp-plugin').delete()
        self.correlate()
        match = CVEMatch.objects.get(subdomain=self.sub, source='wp-plugin')
        self.assertEqual(match.ai_verdict, 'not_affected')
        self.assertTrue(match.ai_reason.startswith('Closed automatically:'))

    def test_matches_follow_a_fresh_scan_row(self):
        cve('CVE-2099-0005', 'Cloudflare Image Resizing')
        self.sighting('cf-image-resizing', '1.5.5', 'Cloudflare Image Resizing')
        from cveFeed import correlation
        correlation._INDEX_CACHE.update(key=None, value=None)
        self.assertEqual(wp_correlation.carry_forward(self.scan_obj), 1)
        self.assertEqual(CVEMatch.objects.filter(source='wp-plugin').count(), 1)


class ProcessExitTests(SimpleTestCase):
    def run_process(self, returncode, report=None, token='tok'):
        def fake_run(cmd, **kwargs):
            out = cmd[cmd.index('-o') + 1]
            if report is not None:
                with open(out, 'w') as f:
                    f.write(json.dumps(report))
            return mock.Mock(returncode=returncode, stderr='')
        with mock.patch('cveFeed.wpscan_scan.subprocess.run', side_effect=fake_run):
            try:
                return wpscan_scan.run_wpscan_process('https://www.rt.test/', token)
            except Exception as exc:  # noqa: BLE001
                return exc

    def test_exit_code_4_is_classified_from_the_reports_scan_aborted_text(self):
        self.assertIsInstance(self.run_process(4, {'scan_aborted': 'The remote website is up, but does not seem to be running WordPress.'}), wpscan_scan.NotWordPress)
        self.assertIsInstance(self.run_process(4, {'scan_aborted': 'The target is responding with a 403 Forbidden, WAF suspected'}), wpscan_scan.Blocked)
        other = self.run_process(4, {'scan_aborted': 'The URL supplied redirects to elsewhere tok'})
        self.assertIsInstance(other, RuntimeError)
        self.assertNotIsInstance(other, wpscan_scan.Blocked)
        self.assertNotIn('tok', str(other))
        self.assertIsInstance(self.run_process(4), wpscan_scan.NotWordPress)  # no report at all: nothing readable

    def test_the_command_line_is_the_verified_wpscan_4_form(self):
        flags = wpscan_scan.FLAGS
        self.assertEqual(flags[flags.index('--enumerate') + 1], 'ap,at,tt,cb,dbe,u1-10')  # plugins are not enumerated by default in WPScan 4
        for flag in ('--random-user-agent', '--throttle', '--disable-tls-checks', '--format'):
            self.assertIn(flag, flags)
        self.assertNotIn('--api-token', flags)
        self.assertEqual(wpscan_scan.OK_EXIT_CODES, (0, 5))

    def test_findings_say_what_to_do(self):
        rows = {r[0]: r for r in wpscan_scan._vuln_rows({**REPORT, 'plugins': {'p': {'version': {'number': '1.0'}, 'latest_version': '2.0', 'outdated': True}},
                                                          'interesting_findings': [{'type': 'xmlrpc', 'to_s': 'XML-RPC seems to be enabled', 'url': 'https://x.test/xmlrpc.php'}]},
                                                         'https://www.rt.test/')}
        self.assertTrue(all('Remediation' in r[2] for r in rows.values() if r[1] >= 1))
        self.assertIn('WordPress plugin p 1.0 is outdated (latest 2.0)', rows)
        self.assertEqual(rows['WordPress: XML-RPC seems to be enabled'][1], 1)
