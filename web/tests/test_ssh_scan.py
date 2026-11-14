"""The server half of ``ssh_probe``: which endpoints are asked, how the answer is cleaned and stored, and that an unanswered task is never clean."""
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_results, sentinel_dispatch, sentinel_policy
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from cveFeed import discovery, probe_scope, setup_flow, ssh_scan
from cveFeed.models import HostExclusion, ProbeObservation, ServiceRun
from reNgine.resources import ScannerUnavailable
from startScan.models import IpAddress, Port, Vulnerability
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally, fixture
from tests.test_route_auth import RouteFixture

OBS = {'ssh_banner': 'SSH-2.0-OpenSSH_9.6', 'ssh_hostkeys': 'ssh-ed25519 256 bits', 'ssh_auth_methods': 'publickey, password'}


def observation(ident, evidence='x', verified=True, severity=0):
    return {'id': ident, 'title': ident.replace('_', ' '), 'severity': severity, 'evidence': evidence, 'verified': verified}


def host_row(address, port, state='clear'):
    """A host entry as the Sentinel's parser writes it: ``clear`` (key checked, not listed), ``hit`` (key on the blocklist), ``unchecked`` (no blocklist data
    on the Sentinel) or ``down`` (nothing read)."""
    if state == 'down':
        why = 'the tool wrote no result'
        return {'address': address, 'port': port, 'reached': False, 'observations': [observation('ssh_not_inspected', why, False)], 'check_hits': [], 'error': why}
    observations = [observation(i, e) for i, e in OBS.items()]
    hits = []
    if state == 'clear':
        observations.append(observation('badkeys_blocklist_clear', 'checked'))
    elif state == 'hit':
        observations.append(observation('badkeys_blocklist_hit', 'badkeys-blocklist-ssh-rsa proof', severity=4))
        hits = [{'check': 'badkeys-blocklist', 'id': 'badkeys-blocklist-ssh-rsa', 'ref': 'https://badkeys.info', 'proof': 'proof'}]
    else:
        observations.append(observation('badkeys_not_checked', 'no blocklist data', False))
    return {'address': address, 'port': port, 'reached': True, 'observations': observations, 'check_hits': hits}


def responder(states=None, default='clear'):
    """A fake Sentinel's ``ssh_probe`` answer: one row per endpoint of the task, in the state ``states[(address, port)]`` (or ``default``)."""
    def answer(task):
        asked = task['target']['targets']
        return {'outcome': 'done', 'hosts': [host_row(t['address'], t['port'], (states or {}).get((t['address'], t['port']), default)) for t in asked],
                'touched': [t['address'] for t in asked], 'refused': []}
    return answer


class PortTests(SimpleTestCase):
    def port(self, number=22, service='', product='', banner='', protocol='tcp', version=''):
        return SimpleNamespace(number=number, service_name=service, product=product, banner=banner, protocol=protocol, version=version)

    def test_port_22_and_anything_that_says_ssh(self):
        self.assertTrue(ssh_scan.is_ssh_port(self.port(22)))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(22, 'tcpwrapped')))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(2222, 'ssh')))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(830, 'ssl/ssh')))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(2200, '', 'OpenSSH')))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(2200, '', 'Dropbear sshd')))
        self.assertTrue(ssh_scan.is_ssh_port(self.port(2201, 'unknown', banner='SSH-2.0-OpenSSH_9.6\r\n')))

    def test_other_ports_and_udp_are_not(self):
        for port in (self.port(443, 'https'), self.port(80, 'http', 'nginx'), self.port(8022, 'http-alt'), self.port(25, 'smtp', banner='220 ssh.example.test ESMTP'),
                     self.port(22, 'ssh', protocol='udp')):
            self.assertFalse(ssh_scan.is_ssh_port(port))

    def test_a_banner_or_version_change_changes_the_fingerprint_and_nothing_read_is_empty(self):
        a, b = self.port(22, banner='SSH-2.0-OpenSSH_9.6'), self.port(22, banner='SSH-2.0-OpenSSH_9.7')
        self.assertNotEqual(ssh_scan.fingerprint(a), ssh_scan.fingerprint(b))
        self.assertEqual(ssh_scan.fingerprint(a), ssh_scan.fingerprint(self.port(22, banner='SSH-2.0-OpenSSH_9.6')))
        self.assertEqual(ssh_scan.fingerprint(self.port(22)), '')


class WiringTests(SimpleTestCase):
    def test_the_kind_has_no_local_path_and_a_budget_a_label_and_a_family(self):
        self.assertIn('ssh_probe', SentinelTask.KINDS)
        self.assertIn('ssh_probe', sentinel_dispatch.NEVER_LOCAL)
        self.assertIn('ssh_probe', sentinel_dispatch.COMPLETION_CEILING)
        self.assertGreater(sentinel_dispatch._dispatch_timeout('ssh_probe', 25), sentinel_dispatch._dispatch_timeout('ssh_probe', 1))
        self.assertEqual(sentinel_policy.label('ssh_probe'), 'SSH inspection')
        families = {f[0]: f[3] for f in setup_flow.FAMILIES}
        self.assertEqual(families['ssh'], ('ssh_probe',))
        self.assertNotIn('ssh_probe', setup_flow.HEAVY)  # on by default, also on a small machine
        self.assertNotIn('ssh_probe', setup_flow.suggested_off(2.0))
        self.assertIn('ssh_probe', sentinel_policy.clean_kinds({'ssh_probe': {'mode': 'deny', 'max_concurrent': None}}))

    def test_the_scope_policy_names_only_the_addresses_asked(self):
        with mock.patch('cveFeed.probe_scope.address_rules', return_value={'private': False, 'addresses': [], 'blocked': []}):
            policy = probe_scope.for_ssh(1, ['192.0.2.10', '192.0.2.10', '198.51.100.7'])
        self.assertEqual(policy['hosts'], ['192.0.2.10', '198.51.100.7'])
        self.assertEqual((policy['domains'], policy['excluded'], policy['excluded_trees']), ([], [], []))

    def test_the_fixture_goes_through_the_cleaner_unchanged_and_task_hosts_are_the_addresses(self):
        sent = fixture('ssh_probe')
        self.assertEqual(broker.clean_result('ssh_probe', sent), sent)
        task = SentinelTask(kind='ssh_probe', target={'targets': [{'address': '192.0.2.10', 'port': 22}]})
        self.assertEqual(broker.task_hosts(task)[1], ['192.0.2.10'])


class CleanTests(SimpleTestCase):
    def test_everything_is_clipped_and_a_bad_row_is_dropped(self):
        long = 'x' * 900
        got = probe_results.clean_ssh_probe({'hosts': [
            {'address': '192.0.2.1', 'port': 22, 'reached': True, 'error': long,
             'observations': [observation('ssh_banner', long), {'id': 'Bad Id!', 'title': 't', 'severity': 0, 'evidence': 'e', 'verified': True},
                              {'id': 'ssh_x', 'title': long, 'severity': 99, 'evidence': 'e', 'verified': True}],
             'check_hits': [{'check': 'badkeys-blocklist', 'id': 'k', 'ref': long, 'proof': long}, {'check': 'other', 'id': 'k', 'ref': '', 'proof': ''}]},
            {'address': '192.0.2.2', 'port': 70000, 'reached': True, 'observations': [], 'check_hits': []},
            {'address': '', 'port': 22, 'observations': []}, 'junk']})
        self.assertEqual(len(got['hosts']), 1)
        host = got['hosts'][0]
        self.assertEqual([o['id'] for o in host['observations']], ['ssh_banner', 'ssh_x'])
        self.assertLessEqual(len(host['observations'][0]['evidence']), 300)
        self.assertEqual(host['observations'][1]['severity'], 0)  # out of range
        self.assertEqual(len(host['check_hits']), 1)
        self.assertLessEqual(len(host['check_hits'][0]['proof']), 300)
        self.assertLessEqual(len(host['error']), 200)

    def test_a_host_that_was_not_reached_keeps_no_verified_fact_and_no_hit(self):
        got = probe_results.clean_ssh_probe({'hosts': [{**host_row('192.0.2.1', 22, 'hit'), 'reached': False}]})
        host = got['hosts'][0]
        self.assertTrue(all(o['verified'] is False for o in host['observations']))
        self.assertEqual(host['check_hits'], [])

    def test_too_many_hosts_is_refused(self):
        from agentapi.services import ApiError
        with self.assertRaises(ApiError):
            probe_results.clean_ssh_probe({'hosts': [host_row('192.0.2.1', 22)] * 26})

    def test_the_result_is_cut_to_the_endpoints_the_task_asked_once_each(self):
        task = SentinelTask(kind='ssh_probe', target={'targets': [{'address': '192.0.2.1', 'port': 22}]})
        result = broker.clean_result('ssh_probe', {'outcome': 'done', 'touched': [], 'refused': [],
                                                   'hosts': [host_row('192.0.2.1', 22), host_row('192.0.2.1', 22), host_row('192.0.2.1', 2222), host_row('192.0.2.9', 22)]}, task)
        self.assertEqual([(h['address'], h['port']) for h in result['hosts']], [('192.0.2.1', 22)])
        self.assertEqual(result['dropped'], 3)


class SshFixture(RouteFixture):
    ADDRESS = '203.0.113.5'

    def setUp(self):
        super().setUp()
        self.ssh_guard = assert_ran_nowhere_locally(self, 'ssh_probe')
        self.ssh_tasks = []

    def ssh_scan_obj(self, ports=((22, 'ssh', ''),), names=('host.rt.test',), address=None):
        address = address or self.ADDRESS
        scan = self.scan(names=names, ports=(), ip=address)
        ip = IpAddress.objects.get(address=address)
        for number, service, banner in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, banner=banner, state='open'))
        return scan

    def sentinel(self, states=None, **kw):
        def answer(task):
            self.ssh_tasks.append(task)
            return responder(states)(task)
        return FakeScanner(kinds=['ssh_probe'], responders={'ssh_probe': answer}, **kw)

    def go(self, scan, fake=None, **kw):
        with (fake or self.sentinel()):
            return ssh_scan.run_for_scan(scan.id, **kw)


class ScheduleTests(SshFixture, TestCase):
    def test_only_open_ssh_endpoints_are_picked_once_per_address_and_port(self):
        scan = self.ssh_scan_obj(ports=((22, 'ssh', ''), (443, 'https', ''), (80, 'http', ''), (2222, 'unknown', 'SSH-2.0-dropbear'), (3306, 'mysql', '')),
                                 names=('a.rt.test', 'b.rt.test'))
        found = ssh_scan.candidates(scan)
        self.assertEqual(sorted(found), [(self.ADDRESS, 22), (self.ADDRESS, 2222)])
        self.assertEqual(sorted(s.name for s in found[(self.ADDRESS, 22)]['subs']), ['a.rt.test', 'b.rt.test'])

    def test_a_closed_port_and_a_host_without_ssh_are_not_asked(self):
        scan = self.ssh_scan_obj(ports=((22, 'ssh', ''),))
        Port.objects.filter(number=22).update(state='closed')
        self.assertEqual(ssh_scan.candidates(scan), {})
        other = self.ssh_scan_obj(ports=((443, 'https', ''),), names=('web.rt.test',), address='203.0.113.6')
        self.assertEqual(ssh_scan.candidates(other), {})

    def test_an_excluded_host_is_never_sent(self):
        scan = self.ssh_scan_obj()
        HostExclusion.objects.create(org=self.project.org, host='host.rt.test')
        with self.sentinel() as fake:
            result = ssh_scan.run_for_scan(scan.id)
        self.assertEqual(fake.served_kinds(), [])
        self.assertEqual(result['endpoints'], 0)

    def test_the_task_carries_the_endpoints_and_their_scope(self):
        scan = self.ssh_scan_obj(ports=((22, 'ssh', ''), (2222, 'ssh', '')))
        self.go(scan)
        self.assertEqual(len(self.ssh_tasks), 1)
        target = self.ssh_tasks[0]['target']
        self.assertEqual(target['targets'], [{'address': self.ADDRESS, 'port': 22}, {'address': self.ADDRESS, 'port': 2222}])
        self.assertEqual(target['scope']['hosts'], [self.ADDRESS])

    def test_an_endpoint_is_asked_weekly_not_every_scan_and_again_when_the_banner_changed(self):
        scan = self.ssh_scan_obj(ports=((22, 'ssh', 'SSH-2.0-OpenSSH_9.6'),))
        self.go(scan)
        self.assertEqual(len(self.ssh_tasks), 1)
        again = self.go(scan)  # the next scan: still inside the week
        self.assertEqual(len(self.ssh_tasks), 1)
        self.assertEqual(again['inspected'], 0)
        Port.objects.filter(number=22).update(banner='SSH-2.0-OpenSSH_9.7')  # upgraded: the banner changed
        self.go(scan)
        self.assertEqual(len(self.ssh_tasks), 2)
        ServiceRun.objects.filter(service=ssh_scan.SERVICE).update(finished_at=timezone.now() - timedelta(days=8))
        self.go(scan)  # the week is over
        self.assertEqual(len(self.ssh_tasks), 3)

    def test_a_retest_asks_again_now(self):
        scan = self.ssh_scan_obj()
        self.go(scan)
        self.go(scan, force=True)
        self.assertEqual(len(self.ssh_tasks), 2)


class StorageTests(SshFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.ssh_scan_obj()

    def observations(self):
        return {o.product: o for o in ProbeObservation.objects.filter(probe=ssh_scan.PROBE, kind='ssh', host='host.rt.test', port=22)}

    def test_a_clean_host_stores_inventory_facts_and_no_finding(self):
        result = self.go(self.scan_obj)
        self.assertEqual((result['inspected'], result['findings'], result['waiting']), (1, 0, 0))
        stored = self.observations()
        self.assertEqual(set(stored), {*OBS, 'badkeys_blocklist_clear'})
        self.assertTrue(all(o.outcome == 'found' and o.evidence['verified'] for o in stored.values()))
        self.assertEqual(Vulnerability.objects.filter(source='ssh-probe').count(), 0)
        self.assertEqual(ServiceRun.objects.filter(service=ssh_scan.SERVICE, status='done').count(), 1)

    def test_a_compromised_host_key_is_one_high_severity_finding_deduped_by_host_and_endpoint(self):
        for _ in range(2):  # a rescan updates the row
            self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'hit'}), force=True)
        found = Vulnerability.objects.filter(source='ssh-probe')
        self.assertEqual(found.count(), 1)
        vuln = found.get()
        self.assertEqual((vuln.severity, vuln.template_id, vuln.http_url, vuln.subdomain.name), (3, 'ssh-badkeys-blocklist', f'ssh://{self.ADDRESS}:22', 'host.rt.test'))
        self.assertEqual(ProbeObservation.objects.filter(probe=ssh_scan.PROBE, port=22, product='badkeys_blocklist_hit').count(), 1)

    def test_the_severity_a_sentinel_reports_is_not_used(self):
        def answer(task):
            row = host_row(self.ADDRESS, 22, 'hit')
            row['observations'][-1]['severity'] = 0
            return {'outcome': 'done', 'hosts': [row], 'touched': [self.ADDRESS], 'refused': []}
        with FakeScanner(kinds=['ssh_probe'], responders={'ssh_probe': answer}):
            ssh_scan.run_for_scan(self.scan_obj.id)
        self.assertEqual(Vulnerability.objects.get(source='ssh-probe').severity, 3)

    def test_a_later_clean_read_closes_the_finding(self):
        self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'hit'}))
        self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'clear'}), force=True)
        self.assertFalse(Vulnerability.objects.get(source='ssh-probe').open_status)
        self.assertNotIn('badkeys_blocklist_hit', self.observations())

    def test_an_unchecked_key_is_unverified_not_clean_and_is_asked_again_soon(self):
        result = self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'unchecked'}))
        self.assertEqual((result['inspected'], result['incomplete']), (0, 1))
        self.assertEqual(self.observations()['badkeys_not_checked'].outcome, 'unverified')
        self.assertNotIn('badkeys_blocklist_clear', self.observations())
        self.assertEqual(Vulnerability.objects.filter(source='ssh-probe').count(), 0)
        self.assertEqual(ServiceRun.objects.filter(service=ssh_scan.SERVICE).count(), 0)
        self.assertEqual(ServiceRun.objects.filter(service=ssh_scan.FAILED_SERVICE).count(), 1)  # the day-long retry window

    def test_a_host_that_was_not_reached_is_unverified_and_never_clean(self):
        result = self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'down'}))
        self.assertEqual((result['inspected'], result['incomplete'], result['findings']), (0, 1, 0))
        self.assertEqual({k: o.outcome for k, o in self.observations().items()}, {'ssh_not_inspected': 'unverified'})
        self.assertEqual(ServiceRun.objects.filter(service=ssh_scan.SERVICE).count(), 0)

    def test_an_unreachable_read_keeps_the_last_verified_facts_and_a_reached_read_drops_the_unreachable_row(self):
        self.go(self.scan_obj)
        self.go(self.scan_obj, self.sentinel({(self.ADDRESS, 22): 'down'}), force=True)
        self.assertEqual(self.observations()['ssh_banner'].outcome, 'found')
        self.assertIn('ssh_not_inspected', self.observations())
        self.go(self.scan_obj, force=True)
        self.assertNotIn('ssh_not_inspected', self.observations())

    def test_every_name_at_the_address_gets_the_facts_and_the_finding(self):
        scan = self.ssh_scan_obj(names=('one.rt.test', 'two.rt.test'), address='203.0.113.9')
        self.go(scan, self.sentinel({('203.0.113.9', 22): 'hit'}))
        self.assertEqual(sorted(Vulnerability.objects.filter(source='ssh-probe', http_url='ssh://203.0.113.9:22').values_list('subdomain__name', flat=True)),
                         ['one.rt.test', 'two.rt.test'])


class UnansweredTests(SshFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.ssh_scan_obj()

    def nothing_recorded(self):
        self.assertEqual(ServiceRun.objects.filter(service__in=(ssh_scan.SERVICE, ssh_scan.FAILED_SERVICE)).count(), 0)
        self.assertEqual(ProbeObservation.objects.filter(probe=ssh_scan.PROBE).count(), 0)
        self.assertEqual(Vulnerability.objects.filter(source='ssh-probe').count(), 0)

    def test_with_no_scanner_the_stage_waits_and_nothing_is_recorded(self):
        with self.sentinel(mode='offline'):
            with self.assertRaises(ScannerUnavailable):
                ssh_scan.run_for_scan(self.scan_obj.id)
        self.nothing_recorded()

    def test_a_task_that_failed_is_not_read_as_clean_and_the_endpoint_stays_due(self):
        with self.sentinel(mode='fail'):
            with self.assertRaises(ScannerUnavailable):
                ssh_scan.run_for_scan(self.scan_obj.id)
        self.nothing_recorded()
        self.go(self.scan_obj)  # a scanner is back: the endpoint is still due
        self.assertEqual(ServiceRun.objects.filter(service=ssh_scan.SERVICE, status='done').count(), 1)

    def test_an_endpoint_the_result_has_no_row_for_stays_due(self):
        def answer(task):
            return {'outcome': 'done', 'hosts': [], 'touched': [], 'refused': []}
        with FakeScanner(kinds=['ssh_probe'], responders={'ssh_probe': answer}):
            with self.assertRaises(ScannerUnavailable):
                ssh_scan.run_for_scan(self.scan_obj.id)
        self.nothing_recorded()

    def test_the_pipeline_stage_waits_instead_of_failing(self):
        from startScan.models import ScanActivity
        with self.sentinel(mode='offline'):
            result = discovery._run_stages(self.scan_obj.id, {'scan_id': self.scan_obj.id, 'status': 2, 'error': ''}, port_stage_run=lambda *a, **k: {'targets': 0},
                                           hygiene=False)
        self.assertIn('skipped', result['ssh_probe'])
        self.assertFalse(ScanActivity.objects.filter(scan_of=self.scan_obj, name='SSH inspection', status=0).exists())

    def test_the_switch_turns_the_stage_off_without_a_task(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SSH_PROBE': '0'}):
            with self.sentinel() as fake:
                result = ssh_scan.run_for_scan(self.scan_obj.id)
        self.assertEqual(fake.served_kinds(), [])
        self.assertEqual(result['skipped'], 'disabled')
