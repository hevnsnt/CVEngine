"""Every way a WPScan run ends, and what each one is.

Seen on a production server: "WordPress scan finished <host>: 0 site(s), 0 new finding(s); 1 problem(s): <host>: the scan failed (see the host page)"
and "Host assessment failed ... Failed stages: wpscan". WPScan exits 4 with the reason in the report's ``scan_aborted`` text for a site that
is down, a site that redirects away, a site WPScan will not scan (hosted on wordpress.com), a run out of time and a database it could not
update, and only "not WordPress" was told apart: every other reason was a bare RuntimeError, so a site that is down or moved read as a failed scan
and, when it was the only site, failed the host's assessment. Texts below are WPScan 4.2.0's own, the first three captured from the
real tool against a lab container."""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import wpscan_scan
from cveFeed.models import ProbeObservation, ServiceRun
from startScan.models import Subdomain, Technology
from tests.test_route_auth import RouteFixture
from tests import test_wpscan
from tests.test_wpscan import REPORT

NOT_WORDPRESS = 'The remote website is up, but does not seem to be running WordPress.'
DOWN = "The url supplied 'https://site.example.com/' seems to be down (Could not connect to server)"
DOWN_DNS = "The url supplied 'https://gone.example.com/' seems to be down (Couldn't resolve host name)"
REDIRECT = ('The URL supplied redirects to http://other.example.test/. Use the --follow-redirect option to automatically scan the redirected URL, the '
            '--ignore-main-redirect option to ignore the redirection and scan the target, or change the --url option value to the redirected URL.')
HOSTED = 'The target appears to be hosted on WordPress.com. Scanning such site is not supported.'
HTTP_TIMEOUT = 'HTTP Error: https://site.example.com/ (Timeout was reached)'
DURATION = 'Max Scan Duration Reached'
UPDATE_MISSING = 'Update required, you can not run a scan if a database file is missing.'
UPDATE_CHECKSUM = 'metadata.json: checksums do not match. Please try again in a few minutes.'
UPDATE_DOWNLOAD = 'Unable to get https://data.wpscan.org/metadata.json (Could not resolve host: data.wpscan.org)'


def aborted(text):
    return {'scan_aborted': text}


class ClassifyEveryEndTests(SimpleTestCase):
    def classify(self, returncode=4, report=None, stderr='', token='tok-secret'):
        try:
            return wpscan_scan._classify(report, returncode, stderr, token)
        except Exception as exc:  # noqa: BLE001
            return exc

    def test_a_site_that_is_down_is_unreachable_not_a_failed_scan(self):
        for text in (DOWN, DOWN_DNS, HTTP_TIMEOUT):
            with self.subTest(text=text):
                error = self.classify(report=aborted(text))
                self.assertIsInstance(error, wpscan_scan.SiteUnreachable)
                self.assertNotIsInstance(error, RuntimeError)
                self.assertIn('did not answer', str(error))
        self.assertIn('Could not connect to server', str(self.classify(report=aborted(DOWN))))

    def test_a_redirect_that_leaves_the_site_is_a_redirect_not_a_failed_scan(self):
        error = self.classify(report=aborted(REDIRECT))
        self.assertIsInstance(error, wpscan_scan.RedirectsElsewhere)
        self.assertIn('http://other.example.test/', str(error))
        self.assertNotIn('--follow-redirect', str(error))  # WPScan's usage advice is not a message for a person
        self.assertEqual(error.target, 'http://other.example.test/')

    def test_a_redirect_still_reads_as_one_the_site_scan_may_follow_to_a_name_of_its_own_group(self):
        self.assertTrue(wpscan_scan.REDIRECT.search(str(self.classify(report=aborted(REDIRECT)))))  # _scan_site follows these itself

    def test_a_site_wpscan_will_not_scan_is_not_scannable_not_a_failed_scan(self):
        self.assertIsInstance(self.classify(report=aborted(HOSTED)), wpscan_scan.NotScannable)

    def test_not_wordpress_is_still_not_wordpress(self):
        self.assertIsInstance(self.classify(report=aborted(NOT_WORDPRESS)), wpscan_scan.NotWordPress)

    def test_a_run_out_of_time_says_so(self):
        error = self.classify(report=aborted(DURATION))
        self.assertIsInstance(error, wpscan_scan.ToolFailure)
        self.assertIn('time limit', error.what)
        killed = self.classify(returncode=-9, stderr='')
        self.assertIsInstance(killed, wpscan_scan.ToolFailure)
        self.assertIn('time limit', killed.what)

    def test_a_database_that_could_not_be_updated_says_what_failed(self):
        for text in (UPDATE_MISSING, UPDATE_CHECKSUM, UPDATE_DOWNLOAD):
            with self.subTest(text=text):
                error = self.classify(report=aborted(text))
                self.assertIsInstance(error, wpscan_scan.ToolFailure)
                self.assertIn('vulnerability database', error.what)
                self.assertIn('Sentinel', error.what)

    def test_a_crash_and_a_refused_option_say_which(self):
        crash = self.classify(returncode=3, stderr='undefined method for nil')
        self.assertIsInstance(crash, wpscan_scan.ToolFailure)
        self.assertIn('unexpected error', crash.what)
        self.assertIn('undefined method for nil', str(crash))
        self.assertIn('refused its options', self.classify(returncode=1).what)

    def test_an_unknown_reason_is_a_failure_that_says_what_the_tool_said(self):
        error = self.classify(report=aborted('Something new went wrong tok-secret'))
        self.assertIsInstance(error, RuntimeError)
        self.assertIn('Something new went wrong', str(error))
        self.assertNotIn('tok-secret', str(error))

    def test_exit_4_with_no_report_names_the_last_stderr_line(self):
        error = self.classify(report=None, stderr='first\nlast words')
        self.assertIsInstance(error, wpscan_scan.ToolFailure)
        self.assertIn('last words', str(error))

    def test_results_read_before_an_abort_are_still_kept_whatever_the_reason(self):
        for text in (DOWN, REDIRECT, DURATION):
            with self.subTest(text=text):
                report = {**aborted(text), 'version': {'number': '6.4.2'}}
                self.assertEqual(self.classify(report=report)['cvengine_partial'][:20], text[:20])

    def test_no_token_ever_shows(self):
        for text in (DOWN + ' tok-secret', REDIRECT + ' tok-secret', DURATION + ' tok-secret', 'x tok-secret'):
            error = self.classify(report=aborted(text))
            self.assertNotIn('tok-secret', str(error))
            self.assertNotIn('tok-secret', getattr(error, 'what', ''))


class OutcomeStageTests(RouteFixture, TestCase):
    """Through the stage: what each ending is recorded as, and whether the host's assessment fails because of it."""

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        self.wp = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        self.wp.technologies.add(Technology.objects.create(name='WordPress'))
        self.scanner = test_wpscan.StageTests.start_scanner(self)

    def go(self, runner):
        return wpscan_scan.run_wpscan(self.scan_obj.id, runner=runner)

    def state(self):
        rows = list(ProbeObservation.objects.filter(host='www.rt.test'))
        return wpscan_scan.state_of(rows)

    def activity(self):
        from cveFeed.models import AgentActivity
        return list(AgentActivity.objects.order_by('id').values_list('status', 'message'))

    def test_a_site_that_is_down_does_not_fail_the_stage_and_says_so(self):
        out = self.go(mock.Mock(side_effect=wpscan_scan.SiteUnreachable('the site did not answer the scan (Could not connect to server)')))
        self.assertNotIn('error', out)
        self.assertEqual(self.state()['state'], 'unreachable')
        self.assertIn('did not answer', self.state()['reason'])
        status, message = self.activity()[-1]
        self.assertEqual(status, 'done')
        self.assertNotIn('the scan failed', message)
        self.assertIn('not reachable', message)
        self.assertEqual(ServiceRun.objects.get(service='wpscan', asset='www.rt.test').status, 'failed')  # asked again at the next scan

    def test_a_redirect_away_does_not_fail_the_stage_and_is_not_asked_again_at_once(self):
        out = self.go(mock.Mock(side_effect=wpscan_scan.RedirectsElsewhere('http://other.example.test/')))
        self.assertNotIn('error', out)
        self.assertEqual(self.state()['state'], 'redirected')
        self.assertIn('http://other.example.test/', self.state()['reason'])
        self.assertEqual(ServiceRun.objects.get(service='wpscan', asset='www.rt.test').status, 'done')
        self.assertEqual(self.activity()[-1][0], 'done')

    def test_a_site_wpscan_will_not_scan_does_not_fail_the_stage(self):
        out = self.go(mock.Mock(side_effect=wpscan_scan.NotScannable('hosted on WordPress.com, which WPScan does not scan')))
        self.assertNotIn('error', out)
        self.assertEqual(self.state()['state'], 'not_scannable')
        self.assertEqual(ServiceRun.objects.get(service='wpscan', asset='www.rt.test').status, 'done')

    def test_a_probe_that_saw_wordpress_does_not_turn_a_down_site_into_a_scan_that_could_not_see_it(self):
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-detect', port=0, kind='wordpress',
                                        product='WordPress', outcome='found', confidence=0.9, source='probe')
        out = self.go(mock.Mock(side_effect=wpscan_scan.SiteUnreachable('the site did not answer the scan')))
        self.assertNotIn('error', out)
        self.assertEqual(self.state()['state'], 'unreachable')

    def test_a_real_tool_failure_still_fails_the_stage_and_the_feed_says_what_failed(self):
        failure = wpscan_scan.ToolFailure("this Sentinel's WPScan vulnerability database is missing or could not be updated", 'detail')
        out = self.go(mock.Mock(side_effect=failure))
        self.assertIn('vulnerability database', out['error'])
        self.assertNotIn('the scan failed (see the host page)', out['error'])
        self.assertEqual(self.state()['state'], 'failed')
        self.assertEqual(self.activity()[-1][0], 'failed')

    def test_an_unclassified_failure_is_still_the_scan_failed(self):
        out = self.go(mock.Mock(side_effect=RuntimeError('boom')))
        self.assertIn('the scan failed', out['error'])

    def test_one_site_down_among_scanned_sites_is_not_a_problem_either(self):
        other = Subdomain.objects.create(name='blog.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
        other.technologies.add(Technology.objects.get(name='WordPress'))

        def runner(url, token):
            if 'blog' in url:
                raise wpscan_scan.SiteUnreachable('the site did not answer the scan')
            return REPORT
        out = self.go(runner)
        self.assertEqual(out['scanned'], 1)
        self.assertNotIn('error', out)

    def test_the_thorough_pass_records_a_down_site_without_a_failure_line(self):
        from cveFeed.models import AgentActivity
        wpscan_scan.record_thorough(self.project.id, self.domain.id, 'www.rt.test', 'pending', 'queued')
        with mock.patch('cveFeed.wpscan_scan._pending_hosts', side_effect=[[('www.rt.test', self.domain.id)], []]):
            summary = wpscan_scan.run_thorough(self.project.id, runner=mock.Mock(side_effect=wpscan_scan.SiteUnreachable('the site did not answer the scan')))
        self.assertEqual(summary['failed'], 1)
        entry = AgentActivity.objects.filter(message__contains='www.rt.test').order_by('-id').first()
        self.assertEqual(entry.status, 'done')
        self.assertNotIn('diagnostic', entry.message)
