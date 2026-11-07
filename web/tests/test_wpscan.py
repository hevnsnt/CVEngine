from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import discovery, wpscan_scan
from cveFeed.api_credentials import SERVICES, used_in_scans
from cveFeed.models import ProbeObservation, RouteAuth, ServiceRun
from dashboard.models import ApiCredential
from startScan.models import ScanActivity, Subdomain, Technology, Vulnerability
from tests.fake_scanner import LocalFallback, assert_ran_nowhere_locally
from tests.test_route_auth import RouteFixture
from tests.port_stage_stub import port_double

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


class ClassifyTests(SimpleTestCase):
    """What a Sentinel reports ({report, returncode, stderr_tail}) becomes a report or a classified failure; nothing runs here."""

    def classify(self, returncode=0, stderr='', token='tok-secret', report=None):
        try:
            return wpscan_scan._classify(report, returncode, stderr, token)
        except Exception as exc:  # noqa: BLE001
            return exc

    def test_a_report_is_returned_as_it_came_and_vulnerabilities_found_is_not_an_error(self):
        self.assertEqual(self.classify(0, report={'version': {'number': '6.0'}})['version']['number'], '6.0')
        self.assertIn('version', self.classify(5, report={'version': {'number': '6.0'}}))
        self.assertIsInstance(self.classify(0, report=None), RuntimeError)  # a run that wrote nothing usable read nothing

    def test_exit_code_4_without_a_report_is_a_failure_not_not_wordpress(self):
        self.assertIsInstance(self.classify(4), RuntimeError)
        self.assertNotIsInstance(self.classify(4), wpscan_scan.NotWordPress)

    def test_failures_never_show_the_token(self):
        error = self.classify(2, stderr='boom tok-secret')
        self.assertIsInstance(error, RuntimeError)
        self.assertNotIn('tok-secret', str(error))

    def test_a_refused_option_or_address_says_why_instead_of_exit_1(self):
        error = self.classify(1, stderr='Scan Aborted: --url Invalid scheme format')
        self.assertIsInstance(error, RuntimeError)
        self.assertIn('Scan Aborted: --url Invalid scheme format', str(error))
        error = self.classify(1)
        self.assertIn('refused its options or the address', str(error))
        self.assertIn('(exit 1)', str(error))
        error = self.classify(3, stderr='x' * 1000 + ' tok-secret')
        self.assertLessEqual(len(str(error)), 200)  # clipped, and the token never shows
        self.assertNotIn('tok-secret', str(error))

    def test_a_dispatched_failure_reads_the_same(self):
        error = None
        try:
            wpscan_scan._classify(None, 1, 'Scan Aborted: invalid option: --nope', 'tok')
        except RuntimeError as exc:
            error = exc
        self.assertEqual(str(error), 'Scan Aborted: invalid option: --nope')


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
        self.assertIn('the scan failed', out['error'])
        self.assertNotIn('boom', out['error'])  # the raw reason goes to the worker log and the host record, not into the activity feed
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

    def test_the_pipeline_runs_the_stage_only_for_wordpress_sites(self):
        stages = []
        runner = lambda url, token: stages.append(url) or REPORT  # noqa: E731
        with mock.patch('cveFeed.discovery.stopped', return_value=False):
            discovery._run_stages(self.scan_obj.id, {'scan_id': self.scan_obj.id, 'status': discovery.SUCCESS}, hygiene=False,
                                  port_stage_run=port_double(), db_exposure_checks={}, provider=None,
                                  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]), wpscan_runner=runner,
                                  probe_get=lambda url: {'status': 404, 'headers': {}, 'body': '', 'title': '', 'challenge': '', 'server': '', 'powered_by': '', 'content_type': '', 'final_url': url, 'url': url})
        self.assertEqual(stages, ['https://www.rt.test'])
        self.assertTrue(ScanActivity.objects.filter(scan_of=self.scan_obj, name='wpscan').exists())


class CredentialTests(SimpleTestCase):
    def test_wpscan_is_a_known_service_and_is_marked_as_used(self):
        self.assertIn('wpscan', SERVICES)
        self.assertTrue(used_in_scans('wpscan'))
        self.assertFalse(used_in_scans('runzero'))


class SentinelDispatchTests(StageTests):
    """run_wpscan's own default runner, when none is passed in, is agentapi.sentinel_dispatch.wrap_wpscan_runner - not
    the local tool (there is none). A live, eligible Sentinel's reported outcome must reach the persistence
    this module has (findings, CVE links, the Technology row, the ServiceRun row), same as a local run does."""

    def make_sentinel(self):
        from django.contrib.auth.models import User
        from django.utils import timezone

        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user('wpscan-sentinel-owner', password='x')
        token, _raw = create_token(user, 'wpscan-sentinel-token')
        return Agent.objects.create(token=token, name='live-wpscan-sentinel', kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=['wpscan'], last_seen=timezone.now())

    def _answer_with(self, result):
        from django.utils import timezone

        from agentapi.models import SentinelTask

        def fake_sleep(_seconds):
            task = SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).order_by('-id').first()
            if task:
                SentinelTask.objects.filter(pk=task.pk).update(status='done', result=result, finished_at=timezone.now())
        return fake_sleep

    def test_no_runner_passed_in_dispatches_to_a_live_sentinel_and_findings_are_saved_the_same_way(self):
        self.make_sentinel()
        ApiCredential.objects.create(project=self.project, service='wpscan', value={'api_key': 'secret-token'})
        result = {'outcome': 'done', 'report': REPORT, 'returncode': 0, 'stderr_tail': ''}
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=self._answer_with(result)):
            out = self.go()  # no runner= kwarg: wpscan_scan.run_wpscan must build its own via wrap_wpscan_runner
        self.assertEqual((out['scanned'], out['findings']), (1, 4))
        vuln = Vulnerability.objects.get(name__startswith='WordPress 6.4.2')
        self.assertEqual((vuln.source, vuln.severity, vuln.subdomain_id), ('wpscan', 3, self.wp.id))
        from agentapi.models import SentinelTask
        task = SentinelTask.objects.get(kind='wpscan')
        self.assertEqual(task.status, 'done')
        self.assertEqual(task.target['token'], '***')  # the project's API token is scrubbed once the task is done

    def test_no_runner_passed_in_waits_and_never_runs_locally_when_no_sentinel_claims_in_time(self):
        self.make_sentinel()
        LocalFallback('none').apply(self)
        guard = assert_ran_nowhere_locally(self, 'wpscan')
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '0.2'}), mock.patch('cveFeed.wpscan_scan.queue_quick', return_value=[]):  # the retry job would go to the real broker
            out = self.go()  # nothing ever answers the task: the kind is NEVER_LOCAL, so the site waits instead of running here
        self.assertEqual(out['scanned'], 0)
        self.assertNotIn('error', out)
        self.assertFalse(ServiceRun.objects.filter(service='wpscan').exists())  # nothing is recorded as done: the site stays due
        state = wpscan_scan.state_of(list(ProbeObservation.objects.filter(host='www.rt.test')))
        self.assertEqual(state['state'], 'waiting')
        self.assertEqual(guard.calls, [])
