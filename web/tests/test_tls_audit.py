import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import hygiene, tls_audit
from cveFeed.models import BountyEngagement, BountyProgram, CVEEntry, CVEMatch, HygieneFinding, ProbeObservation, ServiceRun
from startScan.models import Subdomain
from tests.fake_scanner import LocalFallback, assert_ran_nowhere_locally
from tests.test_route_auth import RouteFixture


def item(test_id, severity, finding, cve=None):
    """One report item in the shape a Sentinel reports (the four fields ``evaluate`` reads, plus the ones the cleaner drops)."""
    found = {'id': test_id, 'ip': 'rt.test/203.0.113.5', 'port': '443', 'severity': severity, 'finding': finding}
    if cve:
        found['cve'] = cve
    return found


# What a clean server answers (trimmed from a real report of an OpenSSL server).
CLEAN = [
    item('SSLv3', 'OK', 'not offered'), item('TLS1', 'LOW', 'offered (deprecated)'), item('TLS1_2', 'OK', 'offered'),
    item('cipherlist_NULL', 'OK', 'not offered'), item('cipherlist_EXPORT', 'OK', 'not offered'), item('cipherlist_3DES_IDEA', 'INFO', 'not offered'),
    item('FS', 'OK', 'offered'), item('secure_renego', 'OK', 'supported'), item('fallback_SCSV', 'OK', 'supported'),
    item('heartbleed', 'OK', 'not vulnerable, no heartbeat extension', 'CVE-2014-0160'), item('CCS', 'OK', 'not vulnerable', 'CVE-2014-0224'),
    item('ROBOT', 'OK', 'not vulnerable', 'CVE-2017-17382 CVE-2017-13098 CVE-2016-6883'),
    item('secure_client_renego', 'OK', 'not vulnerable', 'CVE-2011-1473'), item('CRIME_TLS', 'OK', 'not vulnerable', 'CVE-2012-4929'),
    item('BREACH', 'OK', "not vulnerable, no gzip/deflate/compress/br HTTP compression  - only supplied '/' tested", 'CVE-2013-3587'),
    item('POODLE_SSL', 'OK', 'not vulnerable, no SSLv3', 'CVE-2014-3566'), item('SWEET32', 'OK', 'not vulnerable', 'CVE-2016-2183 CVE-2016-6329'),
    item('FREAK', 'OK', 'not vulnerable', 'CVE-2015-0204'), item('DROWN', 'OK', 'not vulnerable on this host and port', 'CVE-2016-0800 CVE-2016-0703'),
    item('LOGJAM', 'OK', 'not vulnerable, no DH EXPORT ciphers,', 'CVE-2015-4000'), item('RC4', 'OK', 'not vulnerable', 'CVE-2013-2566 CVE-2015-2808'),
    item('winshock', 'OK', 'not vulnerable', 'CVE-2014-6321'), item('ticketbleed', 'OK', 'not vulnerable', 'CVE-2016-9244'),
    item('BEAST', 'LOW', 'VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)', 'CVE-2011-3389'),
    item('LUCKY13', 'LOW', 'potentially vulnerable, uses obsolete TLS CBC ciphers', 'CVE-2013-0169'),
    item('scanTime', 'INFO', '53'),
]


def report(*changes):
    """CLEAN with some tests replaced."""
    swapped = {c['id']: c for c in changes}
    return [swapped.get(i['id'], i) for i in CLEAN]


HEARTBLEED = item('heartbleed', 'CRITICAL', 'VULNERABLE', 'CVE-2014-0160')


class EvaluateTests(SimpleTestCase):
    def test_a_clean_server_has_no_proven_vulnerability_and_every_test_is_cleared(self):
        result = tls_audit.evaluate(CLEAN, 'rt.test:443')
        self.assertEqual(result.vulnerable, {})
        self.assertTrue(result.tested)
        self.assertIn('heartbleed', result.cleared)
        self.assertIn('ROBOT', result.cleared)
        self.assertEqual(result.protocols['TLS1'], 'offered')  # old TLS is hygiene's own check, not repeated here
        self.assertEqual(result.protocols['SSLv3'], 'not offered')

    def test_only_mitigated_or_application_dependent_results_are_findings_not_evidence(self):
        result = tls_audit.evaluate(CLEAN, 'rt.test:443')
        self.assertEqual({f['check'] for f in result.findings}, {'tlsa_beast', 'tlsa_lucky13'})
        self.assertEqual(result.vulnerable, {})
        beast = next(f for f in result.findings if f['check'] == 'tlsa_beast')
        self.assertEqual((beast['severity'], beast['title']), (1, 'rt.test:443: BEAST may apply'))

    def test_a_proven_vulnerability_is_evidence_with_its_cves(self):
        result = tls_audit.evaluate(report(HEARTBLEED), 'rt.test:443')
        self.assertEqual(result.vulnerable['heartbleed']['cves'], ['CVE-2014-0160'])
        self.assertNotIn('heartbleed', result.cleared)
        finding = next(f for f in result.findings if f['check'] == 'tlsa_heartbleed')
        self.assertEqual((finding['severity'], finding['title']), (4, 'rt.test:443: Heartbleed is exploitable'))

    def test_a_list_of_cves_is_split_and_sorted(self):
        robot = item('ROBOT', 'CRITICAL', 'VULNERABLE', 'CVE-2017-17382 CVE-2016-6883 cve-2017-13098')
        self.assertEqual(tls_audit.evaluate(report(robot), 'x:443').vulnerable['ROBOT']['cves'],
                         ['CVE-2016-6883', 'CVE-2017-13098', 'CVE-2017-17382'])

    def test_a_potential_or_mitigated_result_is_never_proof(self):
        sweet = item('SWEET32', 'LOW', 'uses 64 bit block ciphers', 'CVE-2016-2183 CVE-2016-6329')
        result = tls_audit.evaluate(report(sweet), 'x:443')
        self.assertEqual(result.vulnerable, {})
        self.assertIn('tlsa_sweet32', {f['check'] for f in result.findings})

    def test_weak_configuration_is_reported_at_testssls_severity(self):
        result = tls_audit.evaluate(report(item('cipherlist_NULL', 'CRITICAL', 'offered'), item('SSLv3', 'HIGH', 'offered'),
                                              item('FS', 'MEDIUM', 'not offered')), 'x:8443')
        by_check = {f['check']: f for f in result.findings}
        self.assertEqual(by_check['tlsa_cipherlist_null']['severity'], 4)
        self.assertEqual(by_check['tlsa_sslv3']['title'], 'x:8443 offers SSLv3')
        self.assertEqual(by_check['tlsa_fs']['severity'], 2)

    def test_a_test_that_did_not_run_to_an_answer_is_neither_proof_nor_all_clear(self):
        result = tls_audit.evaluate(report(item('heartbleed', 'WARN', 'Not tested, lack of local support'),
                                              item('CCS', 'FATAL', 'test failed')), 'x:443')
        self.assertEqual(result.vulnerable, {})
        self.assertNotIn('heartbleed', result.cleared)
        self.assertEqual({'tlsa_heartbleed', 'tlsa_ccs'} & result.inconclusive, {'tlsa_heartbleed', 'tlsa_ccs'})

    def test_a_report_with_no_answer_was_not_tested(self):
        self.assertFalse(tls_audit.evaluate([item('engine_problem', 'WARN', 'No engine or GOST support')], 'x:443').tested)

    def test_check_names_fit_the_column(self):
        self.assertEqual(tls_audit.check_name('cipherlist_3DES_IDEA'), 'tlsa_cipherlist_3des_idea')
        self.assertLessEqual(len(tls_audit.check_name('x' * 80)), 40)


class SweepTests(RouteFixture, TestCase):
    """The sweep on a Sentinel: nothing runs on this server (``NEVER_LOCAL``), a live Sentinel's reported items are evaluated and stored."""

    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ports=((443, 'https'), (80, 'http'), (22, 'ssh'), (587, 'smtp')))
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        self.cve = CVEEntry.objects.create(cve_id='CVE-2014-0160', title='Heartbleed', published_at=timezone.now(), cvss=7.5)
        self.calls = []  # (host:port, starttls) of each task a Sentinel was handed
        self.output = CLEAN
        mock.patch('cveFeed.activity.log').start()
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()
        LocalFallback('none').apply(self)
        self.guard = assert_ran_nowhere_locally(self, 'testssl')
        self.make_sentinel(['testssl'])
        mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=self._answer).start()

    def make_sentinel(self, capabilities):
        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user(f'sentinel-owner-{capabilities[0]}', password='x')
        token, _raw = create_token(user, 'sentinel-token')
        return Agent.objects.create(token=token, name='live-sentinel', kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=list(capabilities), last_seen=timezone.now())

    def _answer(self, _seconds):
        """The Sentinel: answers the queued task with ``self.output`` as its report items."""
        from agentapi.models import SentinelTask
        task = SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).order_by('-id').first()
        if task:
            self.calls.append((f"{task.target['host']}:{task.target['port']}", task.target.get('starttls', '')))
            SentinelTask.objects.filter(pk=task.pk).update(status='done', result={'items': self.output}, finished_at=timezone.now())

    def sweep(self):
        return tls_audit.sweep(self.project.id, resolve=lambda host, port, project: '203.0.113.5')

    def test_the_tls_ports_that_are_open_are_tested_and_http_and_ssh_are_not(self):
        out = self.sweep()
        self.assertEqual([c[0] for c in self.calls], ['www.rt.test:443', 'www.rt.test:587'])
        self.assertEqual(self.calls[1][1], 'smtp')
        self.assertEqual((out['tested'], out['failed']), (2, 0))
        self.assertEqual({r.asset for r in ServiceRun.objects.filter(service='testssl', status='done')}, {'www.rt.test:443', 'www.rt.test:587'})

    def test_a_target_is_tested_once_until_its_ttl_runs_out(self):
        self.sweep()
        self.calls.clear()
        self.assertEqual(self.sweep()['tested'], 0)
        self.assertEqual(self.calls, [])

    def test_a_host_with_no_port_data_is_tried_on_443(self):
        Subdomain.objects.all().delete()
        Subdomain.objects.create(name='bare.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
        self.sweep()
        self.assertEqual([c[0] for c in self.calls], ['bare.rt.test:443'])

    def test_a_proven_vulnerability_becomes_a_finding_an_observation_and_hard_cve_evidence(self):
        self.output = report(HEARTBLEED)
        out = self.sweep()
        self.assertEqual(out['proven'], 2)  # both ports answered the same
        finding = HygieneFinding.objects.get(domain=self.domain, host='www.rt.test:443', check_name='tlsa_heartbleed')
        self.assertEqual((finding.severity, finding.status), (4, 'open'))
        obs = ProbeObservation.objects.get(project=self.project, host='www.rt.test', probe='testssl', port=443, kind='tls-vuln', product='heartbleed')
        self.assertEqual((obs.outcome, obs.evidence['cves']), ('found', ['CVE-2014-0160']))
        match = CVEMatch.objects.get(cve_entry=self.cve, subdomain=self.sub, source='testssl', matched_product='TLS service on port 443')
        self.assertEqual((match.template_result, match.template_id, match.version_in_range), ('vulnerable', 'testssl:heartbleed', True))
        self.assertEqual(match.evidence['port'], 443)
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', port=443, kind='tls-audit').evidence['protocols']['TLS1'], 'offered')

    def test_a_later_clean_test_resolves_the_finding_and_closes_the_match(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        ServiceRun.objects.all().delete()
        self.output = CLEAN
        self.sweep()
        finding = HygieneFinding.objects.get(domain=self.domain, host='www.rt.test:443', check_name='tlsa_heartbleed')
        self.assertEqual(finding.status, 'resolved')
        match = CVEMatch.objects.get(cve_entry=self.cve, subdomain=self.sub, source='testssl', matched_product='TLS service on port 443')
        self.assertEqual((match.template_result, match.ai_verdict, match.confidence), ('no_match', 'not_affected', 0.0))
        self.assertTrue(match.ai_reason.startswith('Closed automatically:'))
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test', port=443, product='heartbleed').outcome, 'absent')

    def test_a_match_a_person_works_is_kept_open_when_a_later_test_is_clean(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        CVEMatch.objects.filter(source='testssl').update(remediation_status='in_progress')
        ServiceRun.objects.all().delete()
        self.output = CLEAN
        self.sweep()
        match = CVEMatch.objects.get(cve_entry=self.cve, subdomain=self.sub, source='testssl', matched_product='TLS service on port 443')
        self.assertEqual((match.ai_verdict, match.remediation_status, match.template_result), ('', 'in_progress', 'no_match'))

    def test_a_test_that_could_not_answer_leaves_the_earlier_result_alone(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        ServiceRun.objects.all().delete()
        self.output = report(item('heartbleed', 'WARN', 'Not tested, lack of local support', 'CVE-2014-0160'))
        self.sweep()
        self.assertEqual(HygieneFinding.objects.get(host='www.rt.test:443', check_name='tlsa_heartbleed').status, 'open')
        self.assertEqual(CVEMatch.objects.get(source='testssl', matched_product='TLS service on port 443').template_result, 'vulnerable')

    def test_a_rescan_row_gets_the_proven_match_from_the_stored_observation(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        later = self.scan(names=('www.rt.test',))
        self.assertEqual(tls_audit.carry_forward(later), 2)  # the match of each tested port
        fresh = Subdomain.objects.get(scan_history=later, name='www.rt.test')
        self.assertTrue(CVEMatch.objects.filter(subdomain=fresh, source='testssl', template_result='vulnerable').exists())

    def test_an_old_observation_is_not_carried_onto_a_new_scan(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        ProbeObservation.objects.update(observed_at=timezone.now() - timedelta(days=tls_audit.FRESH_DAYS + 1))
        later = self.scan(names=('www.rt.test',))
        self.assertEqual(tls_audit.carry_forward(later), 0)

    def test_a_target_that_cannot_be_tested_is_recorded_and_not_asked_again_at_once(self):
        self.output = [item('engine_problem', 'WARN', 'No engine or GOST support')]  # the Sentinel answered, but no test gave an answer
        out = self.sweep()
        self.assertEqual((out['tested'], out['failed']), (0, 2))
        self.assertEqual(ServiceRun.objects.filter(service='testssl-failed').count(), 2)
        self.calls.clear()
        self.assertEqual(self.sweep()['tested'], 0)  # three days, not the next sweep
        self.assertEqual(self.calls, [])

    def test_a_name_that_resolves_somewhere_prohibited_is_never_contacted(self):
        def prohibited(host, port, project):
            raise ValueError('probe destination is prohibited')
        out = tls_audit.sweep(self.project.id, resolve=prohibited)
        self.assertEqual((out['tested'], out['failed']), (0, 2))
        self.assertEqual(self.calls, [])

    def test_a_host_the_organization_excluded_is_not_tested(self):
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]):
            self.assertEqual(self.sweep()['tested'], 0)
        self.assertEqual(self.calls, [])

    def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_is_not_tested(self):
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        out = self.sweep()
        self.assertIn('automated testing', out['skipped'])
        self.assertEqual(self.calls, [])

    def test_nothing_runs_while_scanning_is_paused(self):
        with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
            out = self.sweep()
        self.assertIn('paused', out['skipped'])
        self.assertEqual(self.calls, [])

    def test_each_run_is_capped_and_the_longest_waiting_go_first(self):
        with mock.patch.dict(os.environ, {'CVENGINE_TESTSSL_MAX_TARGETS': '1'}):
            self.assertEqual(self.sweep()['tested'], 1)
            self.assertEqual(self.sweep()['tested'], 1)
            self.assertEqual(self.sweep()['tested'], 0)
        self.assertEqual(sorted(c[0] for c in self.calls), ['www.rt.test:443', 'www.rt.test:587'])

    def test_the_hygiene_sweep_leaves_these_findings_alone(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        found = [hygiene.Finding('tls_expired', 4, 'x', host='www.rt.test:443')]
        hygiene.store_findings(self.domain, found, owns=lambda check: not check.startswith(('ts_', 'tlsa_')))
        self.assertEqual(HygieneFinding.objects.get(host='www.rt.test:443', check_name='tlsa_heartbleed').status, 'open')

    def test_an_eligible_sentinels_report_is_stored(self):
        self.output = report(HEARTBLEED)
        out = self.sweep()
        self.assertEqual((out['tested'], out['proven']), (2, 2))
        match = CVEMatch.objects.get(cve_entry=self.cve, subdomain=self.sub, source='testssl', matched_product='TLS service on port 443')
        self.assertEqual(match.template_result, 'vulnerable')
        self.assertEqual(self.guard.calls, [])

    def test_with_no_scanner_the_sweep_waits_and_the_targets_stay_due(self):
        from agentapi.models import Agent
        Agent.objects.all().delete()
        self.calls.clear()
        out = self.sweep()
        self.assertEqual((out['tested'], out['failed']), (0, 0))
        self.assertIn('testssl', out['skipped'])
        self.assertFalse(ServiceRun.objects.exists())
        self.assertEqual(len(tls_audit.due(self.project.id)), 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.guard.calls, [])

    def test_a_kind_named_in_the_fallback_variable_still_never_runs_here(self):
        from agentapi import sentinel_dispatch
        with LocalFallback('all'):
            self.assertFalse(sentinel_dispatch.fallback_allowed('testssl'))
        with LocalFallback('testssl'):
            self.assertFalse(sentinel_dispatch.fallback_allowed('testssl'))

    def test_the_local_skip_list_does_not_stop_a_sentinel_from_being_handed_port_25(self):
        Subdomain.objects.all().delete()
        scan = self.scan(names=('mx.rt.test',), ports=((25, 'smtp'),))
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'}):
            self.sweep()
        self.assertIn(('mx.rt.test:25', 'smtp'), self.calls)
