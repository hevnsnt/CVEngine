import json
import os
import subprocess
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import hygiene, testssl_scan
from cveFeed.models import BountyEngagement, BountyProgram, CVEEntry, CVEMatch, HygieneFinding, ProbeObservation, ServiceRun
from startScan.models import Subdomain
from tests.test_route_auth import RouteFixture


def item(test_id, severity, finding, cve=None):
    """One finding in the shape of testssl.sh 3.2.3's ``--jsonfile``."""
    found = {'id': test_id, 'ip': 'rt.test/203.0.113.5', 'port': '443', 'severity': severity, 'finding': finding}
    if cve:
        found['cve'] = cve
    return found


# What a clean server answers (trimmed from a real run of testssl.sh 3.2.3 against an OpenSSL server).
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
        result = testssl_scan.evaluate(CLEAN, 'rt.test:443')
        self.assertEqual(result.vulnerable, {})
        self.assertTrue(result.tested)
        self.assertIn('heartbleed', result.cleared)
        self.assertIn('ROBOT', result.cleared)
        self.assertEqual(result.protocols['TLS1'], 'offered')  # old TLS is hygiene's own check, not repeated here
        self.assertEqual(result.protocols['SSLv3'], 'not offered')

    def test_only_mitigated_or_application_dependent_results_are_findings_not_evidence(self):
        result = testssl_scan.evaluate(CLEAN, 'rt.test:443')
        self.assertEqual({f['check'] for f in result.findings}, {'tlsa_beast', 'tlsa_lucky13'})
        self.assertEqual(result.vulnerable, {})
        beast = next(f for f in result.findings if f['check'] == 'tlsa_beast')
        self.assertEqual((beast['severity'], beast['title']), (1, 'rt.test:443: BEAST may apply'))

    def test_a_proven_vulnerability_is_evidence_with_its_cves(self):
        result = testssl_scan.evaluate(report(HEARTBLEED), 'rt.test:443')
        self.assertEqual(result.vulnerable['heartbleed']['cves'], ['CVE-2014-0160'])
        self.assertNotIn('heartbleed', result.cleared)
        finding = next(f for f in result.findings if f['check'] == 'tlsa_heartbleed')
        self.assertEqual((finding['severity'], finding['title']), (4, 'rt.test:443: Heartbleed is exploitable'))

    def test_a_list_of_cves_is_split_and_sorted(self):
        robot = item('ROBOT', 'CRITICAL', 'VULNERABLE', 'CVE-2017-17382 CVE-2016-6883 cve-2017-13098')
        self.assertEqual(testssl_scan.evaluate(report(robot), 'x:443').vulnerable['ROBOT']['cves'],
                         ['CVE-2016-6883', 'CVE-2017-13098', 'CVE-2017-17382'])

    def test_a_potential_or_mitigated_result_is_never_proof(self):
        sweet = item('SWEET32', 'LOW', 'uses 64 bit block ciphers', 'CVE-2016-2183 CVE-2016-6329')
        result = testssl_scan.evaluate(report(sweet), 'x:443')
        self.assertEqual(result.vulnerable, {})
        self.assertIn('tlsa_sweet32', {f['check'] for f in result.findings})

    def test_weak_configuration_is_reported_at_testssls_severity(self):
        result = testssl_scan.evaluate(report(item('cipherlist_NULL', 'CRITICAL', 'offered'), item('SSLv3', 'HIGH', 'offered'),
                                              item('FS', 'MEDIUM', 'not offered')), 'x:8443')
        by_check = {f['check']: f for f in result.findings}
        self.assertEqual(by_check['tlsa_cipherlist_null']['severity'], 4)
        self.assertEqual(by_check['tlsa_sslv3']['title'], 'x:8443 offers SSLv3')
        self.assertEqual(by_check['tlsa_fs']['severity'], 2)

    def test_a_test_that_did_not_run_to_an_answer_is_neither_proof_nor_all_clear(self):
        result = testssl_scan.evaluate(report(item('heartbleed', 'WARN', 'Not tested, lack of local support'),
                                              item('CCS', 'FATAL', 'test failed')), 'x:443')
        self.assertEqual(result.vulnerable, {})
        self.assertNotIn('heartbleed', result.cleared)
        self.assertEqual({'tlsa_heartbleed', 'tlsa_ccs'} & result.inconclusive, {'tlsa_heartbleed', 'tlsa_ccs'})

    def test_a_report_with_no_answer_was_not_tested(self):
        self.assertFalse(testssl_scan.evaluate([item('engine_problem', 'WARN', 'No engine or GOST support')], 'x:443').tested)

    def test_check_names_fit_the_column(self):
        self.assertEqual(testssl_scan.check_name('cipherlist_3DES_IDEA'), 'tlsa_cipherlist_3des_idea')
        self.assertLessEqual(len(testssl_scan.check_name('x' * 80)), 40)

    def test_flatten_reads_the_flat_and_the_grouped_report(self):
        self.assertEqual(testssl_scan.flatten([{'id': 'a'}, {'no': 'id'}, 'x']), [{'id': 'a'}])
        grouped = {'scanResult': [{'protocols': [{'id': 'SSLv3'}], 'vulnerabilities': [{'id': 'heartbleed'}]}]}
        self.assertEqual([i['id'] for i in testssl_scan.flatten(grouped)], ['SSLv3', 'heartbleed'])
        self.assertEqual(testssl_scan.flatten('garbage'), [])


class RunTests(SimpleTestCase):
    def test_the_command_pins_the_vetted_address_and_never_resolves_a_name(self):
        args = testssl_scan.command('rt.test', '203.0.113.5', 443, None, '/tmp/o.json')
        self.assertEqual(args[0], 'testssl.sh')
        self.assertEqual(args[args.index('--nodns') + 1], 'none')
        self.assertEqual(args[args.index('--ip') + 1], '203.0.113.5')
        self.assertEqual(args[-1], 'rt.test:443')
        self.assertNotIn('--starttls', args)
        for client_simulation_or_per_cipher in ('-c', '-e', '-E', '-h', '--full'):
            self.assertNotIn(client_simulation_or_per_cipher, args)

    def test_starttls_ports_and_ipv6_literals(self):
        args = testssl_scan.command('mail.rt.test', '203.0.113.9', 587, 'smtp', '/tmp/o.json')
        self.assertEqual((args[args.index('--starttls') + 1], args[-1]), ('smtp', 'mail.rt.test:587'))
        self.assertEqual(testssl_scan.command('2001:db8::1', '2001:db8::1', 443, None, '/x')[-1], '[2001:db8::1]:443')

    def test_it_reads_the_report_the_tool_wrote_and_runs_it_with_a_clean_environment(self):
        seen = {}

        def runner(args, env, timeout):
            seen.update(args=args, env=env, timeout=timeout)
            with open(args[args.index('--jsonfile') + 1], 'w') as out:
                json.dump(CLEAN, out)
        with mock.patch.dict(os.environ, {'SECRET_KEY': 's3cret', 'POSTGRES_PASSWORD': 'pw'}):
            items = testssl_scan.run_testssl('rt.test', '203.0.113.5', 443, runner=runner)
        self.assertEqual(len(items), len(CLEAN))
        self.assertEqual(sorted(seen['env']), ['HOME', 'LC_ALL', 'PATH', 'TERM'])  # no application secret reaches the tool
        self.assertEqual(seen['timeout'], testssl_scan.DEFAULT_TIMEOUT)

    def test_failures_are_reported_without_the_tools_output(self):
        def timed_out(args, env, timeout):
            raise subprocess.TimeoutExpired(args, timeout)

        def writes_nothing(args, env, timeout):
            pass

        def missing(args, env, timeout):
            raise FileNotFoundError('testssl.sh')
        for runner, text in ((timed_out, 'in time'), (writes_nothing, 'no usable report'), (missing, 'could not be started')):
            with self.assertRaisesRegex(testssl_scan.TestsslError, text):
                testssl_scan.run_testssl('rt.test', '203.0.113.5', 443, runner=runner)

    def test_the_timeout_can_be_set_but_not_below_two_minutes(self):
        with mock.patch.dict(os.environ, {'CVENGINE_TESTSSL_TIMEOUT': '30'}):
            self.assertEqual(testssl_scan.timeout_seconds(), 120)
        with mock.patch.dict(os.environ, {'CVENGINE_TESTSSL_TIMEOUT': 'x'}):
            self.assertEqual(testssl_scan.timeout_seconds(), testssl_scan.DEFAULT_TIMEOUT)


class SweepTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ports=((443, 'https'), (80, 'http'), (22, 'ssh'), (587, 'smtp')))
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        self.cve = CVEEntry.objects.create(cve_id='CVE-2014-0160', title='Heartbleed', published_at=timezone.now(), cvss=7.5)
        self.calls = []
        self.output = CLEAN
        mock.patch('cveFeed.activity.log').start()
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()

    def runner(self, args, env, timeout):
        self.calls.append(args)
        with open(args[args.index('--jsonfile') + 1], 'w') as out:
            json.dump(self.output, out)

    def sweep(self):
        return testssl_scan.sweep(self.project.id, runner=self.runner, resolve=lambda host, port, project: '203.0.113.5')

    def test_the_tls_ports_that_are_open_are_tested_and_http_and_ssh_are_not(self):
        out = self.sweep()
        self.assertEqual([c[-1] for c in self.calls], ['www.rt.test:443', 'www.rt.test:587'])
        self.assertEqual(self.calls[1][self.calls[1].index('--starttls') + 1], 'smtp')
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
        self.assertEqual([c[-1] for c in self.calls], ['bare.rt.test:443'])

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
        self.assertEqual(testssl_scan.carry_forward(later), 2)  # the match of each tested port
        fresh = Subdomain.objects.get(scan_history=later, name='www.rt.test')
        self.assertTrue(CVEMatch.objects.filter(subdomain=fresh, source='testssl', template_result='vulnerable').exists())

    def test_an_old_observation_is_not_carried_onto_a_new_scan(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        ProbeObservation.objects.update(observed_at=timezone.now() - timedelta(days=testssl_scan.FRESH_DAYS + 1))
        later = self.scan(names=('www.rt.test',))
        self.assertEqual(testssl_scan.carry_forward(later), 0)

    def test_a_target_that_cannot_be_tested_is_recorded_and_not_asked_again_at_once(self):
        def refused(args, env, timeout):
            raise subprocess.TimeoutExpired(args, timeout)
        out = testssl_scan.sweep(self.project.id, runner=refused, resolve=lambda host, port, project: '203.0.113.5')
        self.assertEqual((out['tested'], out['failed']), (0, 2))
        self.assertEqual(ServiceRun.objects.filter(service='testssl-failed').count(), 2)
        self.calls.clear()
        self.assertEqual(self.sweep()['tested'], 0)  # three days, not the next sweep
        self.assertEqual(self.calls, [])

    def test_a_name_that_resolves_somewhere_prohibited_is_never_contacted(self):
        def prohibited(host, port, project):
            raise ValueError('probe destination is prohibited')
        out = testssl_scan.sweep(self.project.id, runner=self.runner, resolve=prohibited)
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
        self.assertEqual(sorted(c[-1] for c in self.calls), ['www.rt.test:443', 'www.rt.test:587'])

    def test_it_reports_when_the_tool_is_not_installed(self):
        with mock.patch.object(testssl_scan, 'installed', return_value=False):
            self.assertIn('not installed', testssl_scan.sweep(self.project.id)['skipped'])

    def test_the_hygiene_sweep_leaves_these_findings_alone(self):
        self.output = report(HEARTBLEED)
        self.sweep()
        found = [hygiene.Finding('tls_expired', 4, 'x', host='www.rt.test:443')]
        hygiene.store_findings(self.domain, found, owns=lambda check: not check.startswith(('ts_', 'tlsa_')))
        self.assertEqual(HygieneFinding.objects.get(host='www.rt.test:443', check_name='tlsa_heartbleed').status, 'open')


class SentinelDispatchTests(SweepTests):
    """``sweep()`` offers each target to a Sentinel first (``agentapi.sentinel_dispatch.try_testssl``); its reported items
    run through the exact same ``evaluate()``/``record_observations``/``store`` path a local run's own items would."""

    def make_sentinel(self, capabilities):
        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user(f'sentinel-owner-{capabilities[0]}', password='x')
        token, _raw = create_token(user, 'sentinel-token')
        return Agent.objects.create(token=token, name='live-sentinel', kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=list(capabilities), last_seen=timezone.now())

    def _answer(self, items):
        from agentapi.models import SentinelTask

        def fake_sleep(_seconds):
            task = SentinelTask.objects.filter(status__in=('queued', 'claimed', 'running')).order_by('-id').first()
            if task:
                SentinelTask.objects.filter(pk=task.pk).update(status='done', result={'items': items}, finished_at=timezone.now())
        return fake_sleep

    def test_an_eligible_sentinels_report_is_used_instead_of_the_local_runner(self):
        self.make_sentinel(['testssl'])
        with mock.patch('agentapi.sentinel_dispatch.time.sleep', side_effect=self._answer(report(HEARTBLEED))):
            out = self.sweep()
        self.assertEqual((out['tested'], out['proven']), (2, 2))
        self.assertEqual(self.calls, [])  # the local runner never ran at all
        match = CVEMatch.objects.get(cve_entry=self.cve, subdomain=self.sub, source='testssl', matched_product='TLS service on port 443')
        self.assertEqual(match.template_result, 'vulnerable')

    def test_with_no_eligible_sentinel_the_sweep_runs_locally_exactly_as_before(self):
        out = self.sweep()
        self.assertEqual(out['tested'], 2)
        self.assertTrue(self.calls)  # the local runner did run
