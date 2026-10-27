from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import discovery, wpscan_scan
from cveFeed.api_credentials import SERVICES, used_in_scans
from cveFeed.models import ProbeObservation, RouteAuth, ServiceRun
from dashboard.models import ApiCredential
from startScan.models import ScanActivity, Subdomain, Technology, Vulnerability
from tests.test_route_auth import RouteFixture

REPORT = {
    'version': {'number': '6.4.2', 'vulnerabilities': [
        {'title': 'WordPress core stored XSS', 'fixed_in': '6.4.3', 'cvss': {'score': '8.8'},
         'references': {'cve': ['2024-1234'], 'url': ['https://example.com/advisory']}}]},
    'main_theme': {'slug': 'twentytwentyfour', 'version': {'number': '1.0'}, 'vulnerabilities': []},
    'plugins': {
        'akismet': {'version': {'number': '5.3'}, 'vulnerabilities': [
            {'title': 'Akismet open redirect', 'fixed_in': None, 'references': {'cve': ['CVE-2023-9999'], 'wpvulndb': ['1']}}]},
        'quiet': {'version': {'number': None}, 'vulnerabilities': []}},
    'interesting_findings': [
        {'type': 'config_backup', 'to_s': 'A wp-config.php backup file has been found: https://www.rt.test/wp-config.php.bak',
         'url': 'https://www.rt.test/wp-config.php.bak'},
        {'type': 'headers', 'to_s': 'Headers', 'url': 'https://www.rt.test/'}],
    'users': {'admin': {}, 'editor': {}},
    'vuln_api': {'plan': 'free', 'requests_done_during_scan': 3, 'requests_remaining': 22},
}


class ReportTests(SimpleTestCase):
    def test_severity_comes_from_the_score_and_defaults_to_medium(self):
        self.assertEqual([wpscan_scan.severity_from_score(s) for s in ('9.8', '7.5', '5.0', '2.0', None, 'x')], [4, 3, 2, 1, 2, 2])

    def test_rows_cover_core_plugins_exposures_and_users(self):
        rows = {r[0]: r for r in wpscan_scan._vuln_rows(REPORT, 'https://www.rt.test/')}
        core = rows['WordPress 6.4.2: WordPress core stored XSS']
        self.assertEqual((core[1], core[3], core[4]), (3, ['CVE-2024-1234'], ['https://example.com/advisory']))
        plugin = rows['WordPress plugin akismet 5.3: Akismet open redirect']
        self.assertEqual((plugin[1], plugin[3]), (2, ['CVE-2023-9999']))
        self.assertIn('No fixed version', plugin[2])
        backup = next(r for n, r in rows.items() if 'wp-config.php backup' in n)
        self.assertEqual(backup[1], 3)
        self.assertFalse([n for n in rows if n == 'WordPress: Headers'])  # informational detections are not findings
        self.assertEqual(rows['WordPress usernames can be listed'][1], 1)

    def test_technologies_name_core_plugins_and_themes_with_versions(self):
        self.assertEqual(wpscan_scan._technologies(REPORT), [
            'WordPress plugin akismet:5.3', 'WordPress theme twentytwentyfour:1.0', 'WordPress:6.4.2'])

    def test_remaining_requests(self):
        self.assertEqual(wpscan_scan.remaining_requests(REPORT), 22)
        self.assertIsNone(wpscan_scan.remaining_requests({}))


class ProcessTests(SimpleTestCase):
    def run_process(self, returncode=0, stderr='', token='tok-secret'):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen['cmd'], seen['env'] = cmd, kwargs['env']
            out = cmd[cmd.index('-o') + 1]
            if returncode in (0, 5):
                with open(out, 'w') as f:
                    f.write('{"version": {"number": "6.0"}}')
            return mock.Mock(returncode=returncode, stderr=stderr)
        with mock.patch('cveFeed.wpscan_scan.subprocess.run', side_effect=fake_run):
            try:
                return wpscan_scan.run_wpscan_process('https://www.rt.test/', token), seen
            except Exception as exc:  # noqa: BLE001
                return exc, seen

    def test_the_token_is_in_the_environment_never_on_the_command_line(self):
        report, seen = self.run_process()
        self.assertEqual(report['version']['number'], '6.0')
        self.assertEqual(seen['env']['WPSCAN_API_TOKEN'], 'tok-secret')
        self.assertNotIn('tok-secret', ' '.join(seen['cmd']))
        self.assertNotIn('--api-token', seen['cmd'])
        self.assertIn('--enumerate', seen['cmd'])
        self.assertEqual(wpscan_scan.run_wpscan_process.__name__, 'run_wpscan_process')

    def test_vulnerabilities_found_is_not_an_error(self):
        report, _ = self.run_process(returncode=5)
        self.assertIn('version', report)

    def test_not_wordpress_and_failures(self):
        error, _ = self.run_process(returncode=4)  # no report was written: nothing was read, so it is a failure, not "not WordPress"
        self.assertIsInstance(error, RuntimeError)
        error, _ = self.run_process(returncode=2, stderr='boom tok-secret')
        self.assertIsInstance(error, RuntimeError)
        self.assertNotIn('tok-secret', str(error))

    def test_the_child_gets_no_other_secret_of_the_worker(self):
        with mock.patch.dict('os.environ', {'POSTGRES_PASSWORD': 'db-secret', 'FIELD_ENCRYPTION_KEY': 'key-secret', 'CELERY_BROKER': 'redis://x'}):
            _, seen = self.run_process()
        self.assertEqual(set(seen['env']) - {'WPSCAN_API_TOKEN'}, set(seen['env']) & set(wpscan_scan.CHILD_ENV_KEYS))
        self.assertNotIn('db-secret', ' '.join(seen['env'].values()))
        self.assertNotIn('key-secret', ' '.join(seen['env'].values()))

    def test_no_token_means_no_variable(self):
        with mock.patch.dict('os.environ', {'WPSCAN_API_TOKEN': 'leaked'}):
            _, seen = self.run_process(token='')
        self.assertNotIn('WPSCAN_API_TOKEN', seen['env'])


class StageTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        self.wp = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        self.wp.technologies.add(Technology.objects.create(name='WordPress'))
        self.calls = []

    def go(self, *args, **kw):
        kw.setdefault('probe_get', lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '',
                                                'content_type': '', 'final_url': url, 'url': url})
        kw.setdefault('sleep', lambda s: None)
        return wpscan_scan.run_wpscan(self.scan_obj.id, *args, **kw)

    def runner(self, url, token):
        self.calls.append((url, token))
        return REPORT

    def test_only_wordpress_hosts_are_scanned_and_findings_are_saved(self):
        out = self.go(runner=self.runner)
        self.assertEqual([c[0] for c in self.calls], ['https://www.rt.test'])
        self.assertEqual((out['scanned'], out['findings']), (1, 4))
        vuln = Vulnerability.objects.get(name__startswith='WordPress 6.4.2')
        self.assertEqual((vuln.source, vuln.severity, vuln.subdomain_id), ('wpscan', 3, self.wp.id))
        self.assertEqual([c.name for c in vuln.cve_ids.all()], ['CVE-2024-1234'])
        self.assertTrue(self.wp.technologies.filter(name='WordPress:6.4.2').exists())
        self.assertTrue(ServiceRun.objects.filter(service='wpscan', asset='www.rt.test').exists())

    def test_a_route_fingerprint_also_identifies_wordpress(self):
        plain = Subdomain.objects.get(scan_history=self.scan_obj, name='plain.rt.test')
        RouteAuth.objects.create(project=self.project, domain=self.domain, host=plain.name, url='https://plain.rt.test/', path='/',
                                 auth_state='open', evidence={'fingerprint_names': ['WordPress:6.4']})
        self.assertEqual([s.name for s, _ in wpscan_scan.wordpress_sites(self.scan_obj)], ['plain.rt.test', 'www.rt.test'])

    def test_each_site_is_scanned_once_a_week(self):
        self.go(runner=self.runner)
        again = self.go(runner=self.runner)
        self.assertEqual((len(self.calls), again['scanned']), (1, 0))
        self.go(runner=self.runner, force=True)
        self.assertEqual(len(self.calls), 2)

    def test_the_project_token_is_used(self):
        ApiCredential.objects.create(project=self.project, service='wpscan', value={'api_key': 'abc123'})
        self.go(runner=self.runner)
        self.assertEqual(self.calls[0][1], 'abc123')

    def test_a_failing_site_is_reported_but_the_rest_continue(self):
        other = Subdomain.objects.create(name='blog.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
        other.technologies.add(Technology.objects.get(name='WordPress'))

        def runner(url, token):
            if 'blog' in url:
                raise RuntimeError('timed out')
            return REPORT
        out = self.go(runner=runner)
        self.assertEqual(out['scanned'], 1)
        self.assertNotIn('error', out)
        self.assertEqual(ServiceRun.objects.get(service='wpscan', asset='blog.rt.test').status, 'failed')

    def test_every_site_failing_is_an_error_and_a_non_wordpress_site_is_not(self):
        out = self.go(runner=mock.Mock(side_effect=RuntimeError('boom')))
        self.assertIn('boom', out['error'])
        ServiceRun.objects.all().delete()
        out = self.go(runner=mock.Mock(side_effect=ValueError('not running WordPress')))
        self.assertNotIn('error', out)

    def test_when_the_api_budget_is_spent_the_next_site_is_still_scanned_without_the_token(self):
        other = Subdomain.objects.create(name='blog.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
        other.technologies.add(Technology.objects.get(name='WordPress'))
        ApiCredential.objects.create(project=self.project, service='wpscan', value={'api_key': 'abc123'})
        calls = []

        def runner(url, token):
            calls.append((url, token))
            return {**REPORT, 'vuln_api': {'requests_remaining': 0}}
        out = self.go(runner=runner)
        self.assertEqual(out['scanned'], 2)
        self.assertEqual([t for _u, t in calls], ['abc123', ''])  # the second site runs with no token: versions and exposures, no vulnerability data
        state = wpscan_scan.state_of(list(ProbeObservation.objects.filter(host='www.rt.test')))
        self.assertEqual(state['vulnerability_data'], 'not checked: API token budget exhausted')
        self.assertTrue(ServiceRun.objects.filter(service='wpscan-partial', asset='www.rt.test').exists())  # asked again soon, not in a week

    def test_skipped_without_the_binary(self):
        with mock.patch('cveFeed.wpscan_scan.installed', return_value=False):
            self.assertEqual(self.go()['skipped'], 'wpscan is not installed')

    def test_the_pipeline_runs_the_stage_only_for_wordpress_sites(self):
        stages = []
        runner = lambda url, token: stages.append(url) or REPORT  # noqa: E731
        with mock.patch('cveFeed.discovery.stopped', return_value=False):
            discovery._run_stages(self.scan_obj.id, {'scan_id': self.scan_obj.id, 'status': discovery.SUCCESS}, hygiene=False,
                                  nmap_runner=lambda targets, flags, timeout: '', db_exposure_checks={}, provider=None,
                                  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
                                  route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''}, wpscan_runner=runner,
                                  probe_get=lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '', 'content_type': '', 'final_url': url, 'url': url})
        self.assertEqual(stages, ['https://www.rt.test'])
        self.assertTrue(ScanActivity.objects.filter(scan_of=self.scan_obj, name='wpscan').exists())


class CredentialTests(SimpleTestCase):
    def test_wpscan_is_a_known_service_and_is_marked_as_used(self):
        self.assertIn('wpscan', SERVICES)
        self.assertTrue(used_in_scans('wpscan'))
        self.assertFalse(used_in_scans('runzero'))
