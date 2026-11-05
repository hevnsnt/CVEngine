"""The probe kinds of contract version 3 (``http_probe``, ``dns_resolve``): the scope policy the server computes for a task, the validation of what
a Sentinel reports, and each stage end to end through the fake built-in scanner, served, offline and failed."""
import os
from unittest import mock

from django.test import SimpleTestCase

from agentapi import probe_dispatch, probe_results
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from agentapi.services import ApiError
from cveFeed import discovery, ledger, probe_scope, probes
from cveFeed.models import HostExclusion, ProbeObservation, ServiceRun
from startScan.models import Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_scanner_unavailable_stages import ENV, FallbackOffBase

HOST = 'www.example.test'


def nginx_found(task):
    """A Sentinel's answer to every planned probe of ``task``: nginx 1.24.0 from its error page."""
    return {'outcome': 'done', 'touched': [p['host'] for p in task['target']['probes']], 'refused': [],
            'probes': [{'id': p['id'], 'observations': [{'kind': 'version', 'product': 'nginx', 'version': '1.24.0', 'variant': '', 'outcome': 'found',
                                                         'confidence': 0.9, 'source': 'page:error', 'port': 0, 'url': '/', 'evidence': {}}]}
                       for p in task['target']['probes']]}


class ProbeStageBase(FallbackOffBase):
    """``www.example.test`` serves https and is known to run nginx without a version: a lead for the error-page and nginx-variants probes."""

    def setUp(self):
        super().setUp()
        self.sub = Subdomain.objects.get(scan_history=self.scan, name=HOST)
        self.sub.technologies.add(Technology.objects.get_or_create(name='nginx')[0])
        self.sub.ip_addresses.first().ports.add(Port.objects.create(number=443, service_name='https', state='open'))
        mock.patch('cveFeed.probes.recorrelate').start()
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'http_probe')

    def planned(self):
        return [entry['probe'] for entry in probes.plan_for_host(self.sub)]


class HttpProbeStageTests(ProbeStageBase):
    def test_the_scanner_runs_the_planned_probes_and_the_stage_stores_what_they_found(self):
        self.assertTrue({'error-page', 'nginx-variants'} <= set(self.planned()))
        with FakeScanner(kinds=['http_probe'], responders={'http_probe': nginx_found}) as fake:
            stats = probes.run_for_scan(self.scan.id)
        self.assertEqual(fake.served_kinds(), ['http_probe'])
        self.assertEqual(self.guard.calls, [])
        self.assertGreaterEqual(stats['probes'], 2)
        self.assertGreaterEqual(stats['versions'], 2)
        rows = ProbeObservation.objects.filter(project_id=self.project.id, host=HOST, kind='version', product='nginx')
        self.assertEqual(set(rows.values_list('version', flat=True)), {'1.24.0'})
        self.assertIn('nginx:1.24.0', set(self.sub.technologies.values_list('name', flat=True)))
        self.assertTrue(ServiceRun.objects.filter(service=probes.SERVICE, status='done').exists())
        target = fake.served[0]['target']
        self.assertEqual({p['host'] for p in target['probes']}, {HOST})
        self.assertIn(HOST, target['scope']['hosts'])
        self.assertIn('example.test', target['scope']['hosts'])  # the redirect group: apex and www answer for each other
        self.assertEqual(target['scope']['domains'], [])  # every name is listed: nothing else may be asked

    def test_a_probe_the_scanner_reports_with_an_error_is_failed_and_stays_due_never_clean(self):
        def errors(task):
            return {**nginx_found(task), 'probes': [{'id': p['id'], 'observations': [], 'error': 'TimeoutError'} for p in task['target']['probes']]}
        with FakeScanner(kinds=['http_probe'], responders={'http_probe': errors}):
            stats = probes.run_for_scan(self.scan.id)
        self.assertEqual(stats['probes'], 0)
        self.assertGreaterEqual(stats['errors'], 2)
        self.assertFalse(ProbeObservation.objects.exists())
        self.assertFalse(ServiceRun.objects.filter(service=probes.SERVICE, status='done').exists())

    def test_an_answer_for_a_probe_the_task_did_not_plan_is_dropped(self):
        def stranger(task):
            out = nginx_found(task)
            out['probes'].append({**out['probes'][0], 'id': 'other.example.test|error-page|https://other.example.test'})
            return out
        with FakeScanner(kinds=['http_probe'], responders={'http_probe': stranger}) as fake:
            probes.run_for_scan(self.scan.id)
        self.assertEqual(fake.tasks()[0].result.get('dropped'), 1)
        self.assertFalse(ProbeObservation.objects.filter(host='other.example.test').exists())

    def test_with_the_scanner_offline_the_web_probes_wait_and_stay_due(self):
        with FakeScanner(kinds=['http_probe'], mode='offline') as fake:
            stats = probes.run_for_scan(self.scan.id)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertTrue(stats['waiting'])
        self.assertEqual((stats['probes'], stats['errors']), (0, 0))
        self.assertFalse(ServiceRun.objects.filter(service=probes.SERVICE).exists())  # neither done nor failed: due

    def test_a_scanner_that_fails_the_task_leaves_the_probes_due(self):
        with FakeScanner(kinds=['http_probe'], mode='fail') as fake:
            stats = probes.run_for_scan(self.scan.id)
        self.assertEqual(fake.served_kinds(), ['http_probe'])
        self.assertTrue(stats['waiting'])
        self.assertFalse(ServiceRun.objects.filter(service=probes.SERVICE).exists())

    def test_with_the_fallback_allowed_and_no_scanner_the_probes_run_here_as_before(self):
        with mock.patch.dict(os.environ, {ENV: 'all'}):
            with mock.patch('cveFeed.probes.run_one', return_value=[]) as local:
                stats = probes.run_for_scan(self.scan.id)
        self.assertGreaterEqual(local.call_count, 2)
        self.assertNotIn('waiting', stats)
        self.assertFalse(SentinelTask.objects.exists())


class DnsResolveStageTests(FallbackOffBase):
    def setUp(self):
        super().setUp()
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'dns_resolve')

    def test_the_scanner_resolves_and_the_pipeline_records_the_hosts(self):
        answer = {'outcome': 'done', 'resolved': {'api.example.test': ['93.184.215.14']}, 'errors': {'slow.example.test': 'no answer within 10 seconds'},
                  'refused': []}
        with FakeScanner(kinds=['dns_resolve'], responders={'dns_resolve': answer}) as fake:
            errors = {}
            pairs = probe_dispatch.resolve_for(self.domain, ['api.example.test', 'slow.example.test'], errors=errors)
        self.assertEqual(fake.served_kinds(), ['dns_resolve'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual(pairs, {('api.example.test', '93.184.215.14')})
        self.assertEqual(errors, {'slow.example.test': 'no answer within 10 seconds'})  # looked up again later, never "no address"
        target = fake.served[0]['target']
        self.assertEqual(target['names'], ['api.example.test', 'slow.example.test'])
        self.assertEqual(target['scope']['hosts'], ['api.example.test', 'slow.example.test'])

    def test_an_excluded_name_is_never_sent(self):
        HostExclusion.objects.create(org=self.org, host='secret.example.test')
        with FakeScanner(kinds=['dns_resolve'], responders={'dns_resolve': fixture('dns_resolve', resolved={}, errors={})}) as fake:
            probe_dispatch.resolve_for(self.domain, ['api.example.test', 'secret.example.test'])
        target = fake.served[0]['target']
        self.assertEqual(target['names'], ['api.example.test'])
        self.assertIn('secret.example.test', target['scope']['excluded'])

    def test_with_the_scanner_offline_the_pipeline_records_nothing_and_the_names_stay_due(self):
        with FakeScanner(kinds=['dns_resolve'], mode='offline') as fake:
            out = discovery.run_host_pipeline(self.domain.id, ['api.example.test'], by_person=True)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertNotEqual(out['status'], 'failed')
        self.assertFalse(Subdomain.objects.filter(name='api.example.test').exclude(scan_history=self.scan).exists())

    def test_an_explicit_resolver_is_used_as_before(self):
        with FakeScanner(kinds=['dns_resolve']) as fake:
            asked = []
            discovery.run_host_pipeline(self.domain.id, ['api.example.test'], resolver=lambda names: asked.append(list(names)) or set(), by_person=True)
        self.assertEqual(asked, [['api.example.test']])
        self.assertEqual(fake.served, [])


class ScopePolicyTests(ProbeStageBase):
    def test_the_policy_lists_each_host_and_its_redirect_group_and_leaves_out_excluded_names(self):
        HostExclusion.objects.create(org=self.org, host='example.test')
        entry = {'probe': 'error-page', 'target': {'base': f'https://{HOST}'}}
        scope = probe_scope.for_probes(self.project.id, [(self.sub, entry)])
        self.assertIn(HOST, scope['hosts'])
        self.assertNotIn('example.test', scope['hosts'])
        self.assertEqual(scope['excluded'], ['example.test'])
        self.assertNotIn('cdnjs.cloudflare.com', scope['hosts'])  # only a library probe reads scripts
        self.assertEqual((scope['private'], scope['addresses'], scope['blocked']), (False, [], []))

    def test_a_library_probe_may_read_the_cdns_and_the_sites_other_hosts_of_this_project(self):
        Subdomain.objects.create(scan_history=self.scan, name='static.example.test', target_domain=self.domain)
        self.sub.target_domain = self.domain
        self.sub.save()
        entry = {'probe': 'html-libraries', 'target': {'base': f'https://{HOST}'}}
        scope = probe_scope.for_probes(self.project.id, [(self.sub, entry)])
        self.assertIn('cdnjs.cloudflare.com', scope['hosts'])
        self.assertIn('static.example.test', scope['hosts'])
        self.domain.discovery_mode = Domain.DISCOVERY_PASSIVE  # a passive target's pages read no other host
        self.domain.save()
        self.sub.refresh_from_db()
        self.assertNotIn('static.example.test', probe_scope.for_probes(self.project.id, [(self.sub, entry)])['hosts'])

    def test_the_address_rules_are_the_servers(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1', 'CVENGINE_BLOCKED_CIDRS': '198.51.100.0/24'}), \
                mock.patch('cveFeed.tailscale_scope.authorised_addresses', return_value={'100.101.102.103': self.project.id, '100.64.0.9': 999}):
            rules = probe_scope.address_rules(self.project.id)
        self.assertEqual(rules, {'private': True, 'addresses': ['100.101.102.103'], 'blocked': ['198.51.100.0/24']})


class ResultTests(SimpleTestCase):
    def test_an_http_probe_result_is_clipped_to_the_contract(self):
        observation = {'kind': 'version', 'product': 'n' * 500, 'version': '1.2.3', 'outcome': 'found', 'confidence': 7, 'source': 'header:server',
                       'port': 99999, 'url': '/', 'evidence': {'blob': 'x' * 20_000}}
        got = probe_results.clean_http_probe({'probes': [
            {'id': 'a', 'observations': [observation, {**observation, 'kind': 'shell'}, {**observation, 'confidence': True}, 'nope']},
            {'id': 'b', 'observations': [], 'error': 'e' * 999}, {'observations': []}],
            'touched': ['WWW.Example.test.', 'bad host', 5], 'refused': []})
        first = got['probes'][0]['observations']
        self.assertEqual(len(first), 1)  # an unknown kind, a non-number confidence and junk are dropped
        self.assertEqual((len(first[0]['product']), first[0]['confidence'], first[0]['port'], first[0]['evidence']), (120, 1.0, 0, {}))
        self.assertEqual(len(got['probes'][1]['error']), 200)
        self.assertEqual(len(got['probes']), 2)
        self.assertEqual(got['touched'], ['www.example.test'])
        with self.assertRaises(ApiError):
            probe_results.clean_http_probe({'probes': [{}] * 301})

    def test_a_dns_result_keeps_only_plain_addresses(self):
        got = probe_results.clean_dns_resolve({'resolved': {'a.example.test': ['93.184.215.14', 'not-an-ip', '93.184.215.14'], 'b.example.test': ['x']},
                                               'errors': {'c.example.test': 'timeout', 'a.example.test': 'shadowed'}, 'refused': []})
        self.assertEqual(got, {'resolved': {'a.example.test': ['93.184.215.14']}, 'errors': {'c.example.test': 'timeout'}, 'refused': []})

    def test_a_result_is_bound_to_what_its_task_asked(self):
        task = mock.Mock(target={'names': ['a.example.test']})
        got = broker.clean_result('dns_resolve', {'outcome': 'done', 'resolved': {'a.example.test': ['93.184.215.14'], 'z.example.test': ['93.184.215.15']},
                                                  'errors': {}}, task=task)
        self.assertEqual((got['resolved'], got['dropped']), ({'a.example.test': ['93.184.215.14']}, 1))

    def test_the_hosts_of_a_batch_are_matched_against_a_sentinels_scope(self):
        task = SentinelTask(kind='http_probe', host='', ips=[], target={'probes': [{'host': 'a.example.test'}, {'host': 'b.example.test'}]})
        self.assertEqual(broker.task_hosts(task), (['a.example.test', 'b.example.test'], []))
        task = SentinelTask(kind='dns_resolve', host='', ips=[], target={'names': ['c.example.test']})
        self.assertEqual(broker.task_hosts(task), (['c.example.test'], []))

    def test_both_fixtures_go_through_unchanged(self):
        for kind in ('http_probe', 'dns_resolve'):
            sent = fixture(kind)
            self.assertEqual(broker.clean_result(kind, sent), sent, kind)
