"""The probe kinds of contract version 3 (``http_probe``, ``dns_resolve``, ``supplier_check``, and the later kinds): the scope policy the server computes for a task, the validation of what
a Sentinel reports, and each stage end to end through the fake built-in scanner, served, offline and failed."""
import datetime
import json
import os
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_dispatch, probe_results
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from agentapi.services import ApiError
from cveFeed import bucket_scan, changes, dangling_dns, discovery, domain_ownership, hosting, ledger, probe_scope, probes, route_auth, subdir_apps, supplier_scan, vhost_scan
from cveFeed import hygiene as hy
from cveFeed.models import (AgentActivity, AssetChange, CVEEntry, DiscoveryEvent, HostExclusion, HostState, HygieneFinding, ProbeObservation, RouteAuth, SecretFinding,
                            ServiceRun, SupplierFinding, SupplierHostCard, TlsCertificate)
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_bucket_scan import Fixture as BucketFixture
from tests.test_changes import ChangeFixture
from tests.test_sentinel_dispatch import DispatchBase
from tests.test_route_auth import RouteFixture
from tests.test_subdir_apps import BASELINE_PATH, SubdirFixture
from tests.test_vhost_scan import VhostFixture
from tests.test_scanner_unavailable_stages import FallbackOffBase
from tests.test_suppliers import Fixture as SupplierFixture, cert as supplier_cert, page as supplier_page

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
        errors = {}
        with FakeScanner(kinds=['dns_resolve'], responders={'dns_resolve': fixture('dns_resolve', resolved={}, errors={})}) as fake:
            probe_dispatch.resolve_for(self.domain, ['api.example.test', 'secret.example.test'], errors=errors)
        target = fake.served[0]['target']
        self.assertEqual(target['names'], ['api.example.test'])
        self.assertIn('secret.example.test', target['scope']['excluded'])
        self.assertIn('secret.example.test', errors)  # unknown, never "no address": a retire check would read absent as gone

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

    def test_a_vhost_result_is_clipped_and_an_unanswered_name_carries_no_fingerprint(self):
        fp = {'status': 200, 'title': 't' * 500, 'length': -4, 'location': '/' * 500, 'server': 's' * 99}
        got = probe_results.clean_vhost_probe({'addresses': [
            {'id': '203.0.113.10', 'default': {'state': 'answered', 'fingerprint': fp}, 'names': [
                {'name': 'WWW.Example.test.', 'state': 'answered', 'fingerprint': fp, 'page': {'body': 'b' * 200_000, 'headers': {'Server': 'x', 'n': 5}}},
                {'name': 'b.example.test', 'state': 'no_answer', 'fingerprint': fp},
                {'name': 'c.example.test', 'state': 'answered'},  # an answer with no fingerprint is no answer
                {'name': 'd.example.test', 'state': 'wat'}]},
            {'id': 'x', 'default': {'state': 'maybe'}, 'names': []}], 'touched': [], 'refused': []})
        self.assertEqual(len(got['addresses']), 1)
        names = got['addresses'][0]['names']
        self.assertEqual([n['name'] for n in names], ['www.example.test', 'b.example.test'])
        self.assertEqual((len(names[0]['fingerprint']['title']), names[0]['fingerprint']['length'], len(names[0]['fingerprint']['location']), len(names[0]['fingerprint']['server'])),
                         (200, 0, 200, 60))
        self.assertEqual((len(names[0]['page']['body']), names[0]['page']['headers']), (65536, {'server': 'x'}))
        self.assertNotIn('fingerprint', names[1])
        self.assertNotIn('page', names[1])
        with self.assertRaises(ApiError):
            probe_results.clean_vhost_probe({'addresses': [{}] * 11})

    def test_a_subdir_result_keeps_only_the_contract_s_shape(self):
        fp = {'status': 200, 'title': 'x', 'length': 3, 'location': '', 'server': ''}
        got = probe_results.clean_subdir_probe({'hosts': [
            {'id': 'h0', 'state': 'challenged', 'requests': 9999, 'challenge': {'edge': 'e' * 99, 'status': 403, 'path': '/jira/'}, 'baseline': None,
             'probed': ['/jira/', 7], 'answers': [{'path': '/jira/', 'source': 'wat', 'fingerprint': fp, 'found': {'product': 'Jira', 'confidence': 4, 'version': 'v' * 300}},
                                                  {'path': '/x/', 'source': 'curated', 'fingerprint': {'status': 'no'}, 'found': None}]},
            {'id': 'h1', 'state': 'exploded'}], 'touched': [], 'refused': []})
        host = got['hosts'][0]
        self.assertEqual(len(got['hosts']), 1)
        self.assertEqual((host['requests'], len(host['challenge']['edge']), host['probed']), (0, 60, ['/jira/']))  # a count past its bound is no count
        self.assertEqual(len(host['answers']), 1)
        self.assertEqual((host['answers'][0]['source'], host['answers'][0]['found']['confidence'], len(host['answers'][0]['found']['version'])), ('curated', 1.0, 100))

    def test_the_results_validate_against_the_contract_after_cleaning(self):
        for kind in ('vhost_probe', 'subdir_probe'):
            with self.subTest(kind=kind):
                cleaned = broker._CLEANERS[kind](fixture(kind))
                self.assertTrue(cleaned)

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


class AliveCheckStageTests(ChangeFixture, TestCase):
    """The retire check of a full scan (``changes._retire``): the names that vanished are looked up by the scanner (``dns_resolve``) and their last
    known addresses asked by it (``alive_check``): the web check first, then a bare connect for a host that answered nowhere."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.addCleanup(mock.patch.stopall)
        self.guards = [assert_ran_nowhere_locally(self, 'alive_check'), assert_ran_nowhere_locally(self, 'dns_resolve')]
        changes.record_scan_changes(self.baseline().id, resolver=lambda names: set())
        # a.ct.test (a web port) and b.ct.test (ssh only) are gone from the second scan, and neither resolves any more
        self.second = self.scan({'c.ct.test': {'ip': '203.0.113.7', 'ports': [(80, 'http', '', '')]}})
        self.asked = []

    def responders(self, web_alive=False, error=False):
        gone = fixture('dns_resolve', resolved={}, errors={}, refused=[])

        def alive(task):
            self.asked.append([(c['host'], c['ip'], c['port'], c['scheme']) for c in task['target']['checks']])
            rows = []
            for c in task['target']['checks']:
                row = {'id': c['id'], 'alive': web_alive and c['scheme'] != 'tcp' or c['scheme'] == 'tcp'}
                if error:
                    row = {'id': c['id'], 'alive': False, 'error': 'TimeoutError'}
                rows.append(row)
            return {'outcome': 'done', 'checks': rows, 'touched': [c['ip'] for c in task['target']['checks']], 'refused': []}
        return {'dns_resolve': gone, 'alive_check': alive}

    def test_an_address_that_still_answers_makes_a_zombie_not_a_retired_host(self):
        with FakeScanner(kinds=['dns_resolve', 'alive_check'], responders=self.responders(web_alive=True)) as fake:
            out = changes.record_scan_changes(self.second.id)
        self.assertEqual(fake.served_kinds(), ['dns_resolve', 'alive_check', 'alive_check'])
        self.assertEqual(self.asked[0], [('a.ct.test', '203.0.113.5', 443, 'https')])  # the web check: only the host that had a web port
        self.assertEqual(self.asked[1], [('b.ct.test', '203.0.113.6', 22, 'tcp')])  # the connect: only the host the web check found nothing on
        self.assertEqual((out['zombies'], out['retired']), (1, 1))
        self.assertIsNotNone(HostState.objects.get(host='a.ct.test').zombie_since)
        retired = AssetChange.objects.get(kind='host_retired')
        self.assertEqual((retired.host, retired.after), ('b.ct.test', {'tcp_alive': ['203.0.113.6:22']}))
        for guard in self.guards:
            self.assertEqual(guard.calls, [])

    def test_a_check_the_scanner_could_not_answer_never_retires_the_host(self):
        with FakeScanner(kinds=['dns_resolve', 'alive_check'], responders=self.responders(error=True)):
            out = changes.record_scan_changes(self.second.id)
        self.assertEqual(out['retired'], 1)  # b.ct.test had no web port: nothing unknown about it
        self.assertIsNone(HostState.objects.get(host='a.ct.test').retired_at)  # unknown: asked again at the next scan
        self.assertEqual(AssetChange.objects.get(kind='host_retired').host, 'b.ct.test')

    def test_with_the_scanner_offline_nothing_is_retired_and_the_hosts_wait(self):
        with FakeScanner(kinds=['dns_resolve', 'alive_check'], mode='offline') as fake:
            out = changes.record_scan_changes(self.second.id)
        self.assertEqual(fake.served, [])
        self.assertEqual((out.get('retired', 0), out.get('zombies', 0)), (0, 0))
        self.assertFalse(AssetChange.objects.filter(kind__in=('host_retired', 'zombie_host')).exists())
        for guard in self.guards:
            self.assertEqual(guard.calls, [])


class BucketCheckStageTests(BucketFixture, TestCase):
    """The cloud storage sweep (``bucket_scan.sweep``): the due buckets go to the scanner as one ``bucket_check`` batch, and the server
    evaluates what comes back exactly as it evaluates its own checks."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'bucket_check')
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')

    def public(self, task):
        return {'outcome': 'done', 'touched': ['ex-static.s3.amazonaws.com'], 'refused': [],
                'buckets': [{'id': b['id'], 'verdict': {'state': 'public', 'objects': ['css/site.css', 'backup/db.sql', 'keys/AKIAABCDEFGHIJKLMNOP.txt'], 'truncated': False,
                                                         'region': 'us-east-1', 'object_read': True, 'status': 200, 'code': '', 'request_count': 2}}
                            for b in task['target']['buckets']]}

    def test_the_scanner_checks_the_bucket_and_the_sweep_stores_the_finding(self):
        with FakeScanner(kinds=['bucket_check'], responders={'bucket_check': self.public}) as fake:
            out = bucket_scan.sweep(self.project.id)
        self.assertEqual(fake.served_kinds(), ['bucket_check'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual((out['checked'], out['public']), (1, 1))
        found = self.finding('static.example.test')
        self.assertEqual(found.status, 'open')
        self.assertEqual(found.evidence['sensitive_looking_names'], 1)  # backup/db.sql, read here from the raw names as for a local check
        self.assertNotIn('AKIAABCDEFGHIJKLMNOP', json.dumps(found.evidence))  # and a secret in a name is redacted before it is stored
        target = fake.served[0]['target']
        self.assertEqual(target['buckets'], [{'id': 's3:ex-static', 'provider': 's3', 'name': 'ex-static'}])
        self.assertEqual((target['scope']['domains'], target['scope']['hosts']), (['amazonaws.com'], []))  # the platform, never a project host
        self.assertTrue(ServiceRun.objects.filter(service=bucket_scan.SERVICE, asset='s3:ex-static').exists())

    def test_an_excluded_bucket_is_never_sent(self):
        HostExclusion.objects.create(org=self.org, host='static.example.test')
        with FakeScanner(kinds=['bucket_check'], responders={'bucket_check': self.public}) as fake:
            out = bucket_scan.sweep(self.project.id)
        self.assertEqual((fake.served, out['checked']), ([], 0))

    def test_with_the_scanner_offline_the_buckets_stay_due(self):
        with FakeScanner(kinds=['bucket_check'], mode='offline') as fake:
            out = bucket_scan.sweep(self.project.id)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual(out['checked'], 0)
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service__in=(bucket_scan.SERVICE, bucket_scan.FAILED_SERVICE)).exists())
        self.assertFalse(HygieneFinding.objects.exists())

    def test_an_unanswered_check_is_recorded_as_without_an_answer(self):
        def unknown(task):
            out = self.public(task)
            for row in out['buckets']:
                row['verdict'] = {**row['verdict'], 'state': 'unknown', 'objects': [], 'object_read': None, 'status': 0}
            return out
        with FakeScanner(kinds=['bucket_check'], responders={'bucket_check': unknown}):
            out = bucket_scan.sweep(self.project.id)
        self.assertEqual(out['unknown'], 1)
        self.assertFalse(HygieneFinding.objects.exists())
        self.assertTrue(ServiceRun.objects.filter(service=bucket_scan.FAILED_SERVICE).exists())


def _page_of(response):
    return {'status': response['status'], 'title': response['title'], 'server': response['server'], 'content_type': response['content_type'],
            'powered_by': response['powered_by'], 'url': response['url'], 'body': response['body'], 'headers': response['headers']}


class VhostProbeStageTests(VhostFixture, TestCase):
    """The virtual host sweep (``vhost_scan.sweep``): the due addresses go to the scanner as one ``vhost_probe`` batch, and the server reaches the
    verdicts itself from the fingerprints that come back."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.guard = assert_ran_nowhere_locally(self, 'vhost_probe')

    def answers(self, task, drop=(), state=None):
        """What a scanner reads from ``self.table`` for ``task``: the default, then each name; a name it never reached is left out."""
        out = []
        for item in task['target']['addresses']:
            default = self.table[(item['address'], None)]
            names = []
            for entry in item['names']:
                if entry['name'] in drop:
                    continue
                response = self.table.get((entry['name'], item['address']))
                if response is None:
                    names.append({'name': entry['name'], 'state': 'no_answer'})
                    continue
                row = {'name': entry['name'], 'state': state or 'answered', 'fingerprint': vhost_scan.fingerprint_of(response)}
                if state == 'challenged':
                    row['challenge'] = 'Cloudflare'
                if not vhost_scan.similar(row['fingerprint'], vhost_scan.fingerprint_of(default)):
                    row['page'] = _page_of(response)
                names.append(row)
            out.append({'id': item['id'], 'default': {'state': 'answered', 'fingerprint': vhost_scan.fingerprint_of(default)}, 'names': names})
        return {'outcome': 'done', 'addresses': out, 'touched': [item['address'] for item in task['target']['addresses']], 'refused': []}

    def test_the_scanner_asks_and_the_sweep_records_what_a_local_sweep_records(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': self.answers}) as fake:
            out = vhost_scan.sweep(self.project.id)
        self.assertEqual(fake.served_kinds(), ['vhost_probe'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual((out['asked'], out['distinct'], out['default_site'], out['same_app'], out['no_answer']), (4, 1, 1, 1, 1))
        self.assertEqual(self.observations(), {('portal.example.test', 'found', 'distinct'), ('app.example.test', 'absent', 'default_site'),
                                               ('wiki.example.test', 'absent', 'same_app')})
        sub = Subdomain.objects.get(name='portal.example.test', scan_history__isnull=True)
        self.assertEqual(sorted(t.name for t in sub.technologies.all()), ['PHP:8.1.2', 'nginx:1.25.3'])  # read from the page the scanner reported
        self.assertEqual([ip.address for ip in sub.ip_addresses.all()], [self.ADDRESS])
        self.assertTrue(ServiceRun.objects.filter(service=vhost_scan.SERVICE, asset=f'{self.ADDRESS}|portal.example.test').exists())

    def test_the_task_names_the_address_the_names_and_the_stored_own_site_and_no_project_data_else(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': self.answers}) as fake:
            vhost_scan.sweep(self.project.id)
        target = fake.served[0]['target']
        item = target['addresses'][0]
        self.assertEqual((item['address'], item['scheme'], item['port']), (self.ADDRESS, 'https', 443))
        names = {n['name']: n for n in item['names']}
        self.assertEqual(sorted(names), ['app.example.test', 'files.example.test', 'portal.example.test', 'wiki.example.test'])
        self.assertEqual(names['wiki.example.test']['own']['title'], 'Wiki')  # the stored front page travels, so the scanner need not ask for it
        self.assertNotIn('own', names['portal.example.test'])
        self.assertEqual(set(target['scope']['hosts']), {self.ADDRESS, *names})
        self.assertGreaterEqual(target['gap'], 0.2)

    def test_the_server_decides_the_verdict_not_the_scanner(self):
        def liar(task):
            out = self.answers(task)
            for row in out['addresses'][0]['names']:
                row['classification'] = 'distinct'  # a field the contract does not have: never read
            return out
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': liar}):
            vhost_scan.sweep(self.project.id)
        self.assertEqual(self.observations(), {('portal.example.test', 'found', 'distinct'), ('app.example.test', 'absent', 'default_site'),
                                               ('wiki.example.test', 'absent', 'same_app')})

    def test_a_name_the_scanner_did_not_report_stays_due(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': lambda task: self.answers(task, drop=('portal.example.test',))}):
            vhost_scan.sweep(self.project.id)
        self.assertNotIn('portal.example.test', {o[0] for o in self.observations()})
        self.assertFalse(ServiceRun.objects.filter(service=vhost_scan.SERVICE, asset=f'{self.ADDRESS}|portal.example.test').exists())
        self.assertFalse(Subdomain.objects.filter(name='portal.example.test', scan_history__isnull=True).exists())

    def test_a_name_the_task_did_not_ask_is_dropped(self):
        def extra(task):
            out = self.answers(task)
            out['addresses'][0]['names'].append({'name': 'other.example.test', 'state': 'answered', 'fingerprint': vhost_scan.fingerprint_of(self.table[('portal.example.test', self.ADDRESS)]),
                                                 'page': _page_of(self.table[('portal.example.test', self.ADDRESS)])})
            return out
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': extra}):
            vhost_scan.sweep(self.project.id)
        self.assertNotIn('other.example.test', {o[0] for o in self.observations()})
        self.assertFalse(Subdomain.objects.filter(name='other.example.test').exists())

    def test_a_challenge_is_recorded_and_the_address_left_alone(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': lambda task: self.answers(task, state='challenged')}):
            out = vhost_scan.sweep(self.project.id)
        self.assertEqual(out['challenged'], 1)
        self.assertEqual({o[1] for o in self.observations()}, {'challenged'})
        self.assertTrue(ServiceRun.objects.filter(service=vhost_scan.IP_SERVICE, asset=self.ADDRESS).exists())

    def test_with_the_scanner_offline_the_addresses_stay_due(self):
        with FakeScanner(kinds=['vhost_probe'], mode='offline') as fake:
            out = vhost_scan.sweep(self.project.id)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertEqual(out['ips'], 0)
        self.assertFalse(ServiceRun.objects.filter(service__in=(vhost_scan.SERVICE, vhost_scan.IP_SERVICE)).exists())
        self.assertFalse(ProbeObservation.objects.filter(probe=vhost_scan.PROBE).exists())

    def test_a_failed_task_with_the_kind_off_the_fallback_list_records_nothing(self):
        with FakeScanner(kinds=['vhost_probe'], mode='fail'):
            out = vhost_scan.sweep(self.project.id)
        self.assertEqual(out['ips'], 0)
        self.assertFalse(ServiceRun.objects.filter(service__in=(vhost_scan.SERVICE, vhost_scan.IP_SERVICE)).exists())

    def test_an_address_the_server_would_not_ask_is_never_sent(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': self.answers}) as fake:
            vhost_scan.sweep(self.project.id, vet_ip=lambda ip: False)
        self.assertEqual(fake.served, [])


class SubdirProbeStageTests(SubdirFixture, TestCase):
    """The subdirectory sweep (``subdir_apps.sweep``): the due hosts go to the scanner as one ``subdir_probe`` batch."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.guard = assert_ran_nowhere_locally(self, 'subdir_probe')
        self.mounts = {'/jenkins/': 'Jenkins'}

    def report(self, task, **changes):
        """What a scanner reads from ``self.site`` for ``task``: the baseline, then each curated path and each lead."""
        hosts = []
        for host in task['target']['hosts']:
            base = f"{host['scheme']}://{host['name']}"
            baseline = vhost_scan.fingerprint_of(self.site(base + BASELINE_PATH))
            answers, probed = [], []
            plan = [(p, 'curated') for p in task['target']['paths']] + [(lead['path'], lead['source']) for lead in host.get('leads', [])]
            for path, source in plan:
                response = self.site(base + path)
                probed.append(path)
                fp = vhost_scan.fingerprint_of(response)
                if fp['status'] in subdir_apps.THERE:
                    answers.append({'path': path, 'source': source, 'fingerprint': fp, 'found': subdir_apps.identify(response, path)})
            hosts.append({'id': host['id'], 'state': 'done', 'requests': len(plan) + 1, 'baseline': baseline, 'probed': probed, 'answers': answers, **changes})
        return {'outcome': 'done', 'hosts': hosts, 'touched': [h['name'] for h in task['target']['hosts']], 'refused': []}

    def sweep_remote(self, **kw):
        kw.setdefault('vet_ip', lambda address: True)  # the documentation addresses of these tests are not scannable ones
        return subdir_apps.sweep(self.project.id, **kw)

    def test_the_scanner_asks_and_the_sweep_records_what_a_local_sweep_records(self):
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': self.report}) as fake:
            summary = self.sweep_remote()
        self.assertEqual(fake.served_kinds(), ['subdir_probe'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual((summary['hosts'], summary['confirmed'], summary['versions'], summary['leads']), (1, 3, 1, 1))
        self.assertEqual(self.rows(), {('/jenkins/', 'Jenkins', '2.401.3', 'found', ''), ('/grafana/', 'Grafana', '', 'hidden', ''),
                                       ('/phpmyadmin/', 'phpMyAdmin', '', 'hidden', ''), ('/portal/', '/portal/', '', 'found', 'lead')})
        self.assertEqual(sorted(t.name for t in self.www.technologies.all()), ['Jenkins:2.401.3'])
        self.assertTrue(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())

    def test_the_task_carries_the_curated_paths_the_known_mounts_and_the_stored_front_page(self):
        RouteAuth.objects.create(project=self.project, domain=self.domain, url='https://www.example.test/', host='www.example.test', path='/',
                                 auth_state='open', http_status=200, title='Home', evidence={'bytes': 5000}, checked_at=timezone.now())
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': self.report}) as fake:
            self.sweep_remote()
        target = fake.served[0]['target']
        self.assertEqual(target['paths'], subdir_apps.curated_paths())
        self.assertEqual(target['max_requests'], subdir_apps.max_requests())
        host = target['hosts'][0]
        self.assertEqual((host['name'], host['scheme'], host['port']), ('www.example.test', 'https', 443))
        self.assertEqual(host['leads'], [{'path': '/portal/', 'count': 1, 'source': 'crawled'}])
        self.assertEqual(host['root']['title'], 'Home')
        self.assertEqual(target['scope']['hosts'], ['www.example.test'])

    def test_a_path_the_server_would_not_have_asked_is_ignored(self):
        def stray(task):
            out = self.report(task)
            out['hosts'][0]['answers'].append({'path': '/../etc/passwd', 'source': 'curated', 'fingerprint': {'status': 200, 'title': 'x', 'length': 9, 'location': '', 'server': ''},
                                               'found': {'product': 'Jenkins', 'confidence': 0.9, 'source': 'x', 'version': '1.0', 'indicated': '/jenkins/'}})
            return out
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': stray}):
            self.sweep_remote()
        self.assertNotIn('/../etc/passwd', {o.url for o in ProbeObservation.objects.filter(probe=subdir_apps.PROBE)})

    def test_a_product_that_is_not_in_the_curated_list_is_not_confirmed(self):
        def invented(task):
            out = self.report(task)
            for answer in out['hosts'][0]['answers']:
                if answer['found']:
                    answer['found'] = {**answer['found'], 'product': 'Totally Real CMS'}
            return out
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': invented}):
            self.sweep_remote()
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE, product='Totally Real CMS').exists())
        self.assertFalse(self.www.technologies.exists())

    def test_an_answer_the_host_gives_to_any_path_is_no_mount_even_when_the_scanner_called_it_one(self):
        everything = {'status': 200, 'title': 'Single page app', 'length': 900, 'location': '', 'server': ''}
        def spa(task):
            out = self.report(task)
            out['hosts'][0]['baseline'] = dict(everything)
            out['hosts'][0]['answers'] = [{'path': '/jira/', 'source': 'curated', 'fingerprint': dict(everything),
                                           'found': {'product': 'Jira', 'confidence': 0.9, 'source': 'x', 'version': '9.4.1', 'indicated': '/jira/'}}]
            return out
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': spa}):
            summary = self.sweep_remote()
        self.assertEqual((summary['catch_all'], summary['confirmed']), (1, 0))
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE).exists())

    def test_a_host_that_asked_for_time_is_not_recorded_as_asked(self):
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': lambda task: self.report(task, state='busy')}):
            self.sweep_remote()
        self.assertFalse(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())

    def test_a_challenge_is_recorded_and_the_host_is_complete(self):
        def challenged(task):
            out = self.report(task, state='challenged')
            out['hosts'][0]['challenge'] = {'edge': 'Cloudflare', 'status': 403, 'path': '/jira/'}
            out['hosts'][0]['answers'] = []
            return out
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': challenged}):
            summary = self.sweep_remote()
        self.assertEqual(summary['challenged'], 1)
        self.assertEqual(ProbeObservation.objects.get(probe=subdir_apps.PROBE, outcome='challenged').product, 'Cloudflare')
        self.assertTrue(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())

    def test_a_host_the_scanner_did_not_report_stays_due(self):
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': lambda task: {'outcome': 'done', 'hosts': [], 'touched': [], 'refused': []}}):
            summary = self.sweep_remote()
        self.assertEqual(summary['hosts'], 0)
        self.assertFalse(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE).exists())

    def test_with_the_scanner_offline_the_hosts_stay_due(self):
        with FakeScanner(kinds=['subdir_probe'], mode='offline') as fake:
            summary = self.sweep_remote()
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertIn('waiting for a scanner', summary['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service=subdir_apps.SERVICE).exists())
        self.assertFalse(ProbeObservation.objects.filter(probe=subdir_apps.PROBE).exists())

    def test_a_virtual_host_is_asked_at_its_address_with_its_name(self):
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='portal.example.test', probe=vhost_scan.PROBE, port=443, kind='vhost',
                                        product=self.ADDRESS, outcome='found', confidence=0.85, url='/', source='host-header', evidence={'scheme': 'https'})
        Subdomain.objects.create(target_domain=self.domain, name='portal.example.test', scan_history=None).ip_addresses.add(self.ip)
        with FakeScanner(kinds=['subdir_probe'], responders={'subdir_probe': self.report}) as fake:
            self.sweep_remote()
        by_name = {h['name']: h for h in fake.served[0]['target']['hosts']}
        self.assertEqual(by_name['portal.example.test']['connect_ip'], self.ADDRESS)
        self.assertNotIn('connect_ip', by_name['www.example.test'])


class RouteProbeStageTests(RouteFixture, TestCase):
    """The web route check (``route_auth.run_route_auth``): the planned routes of a scan go to the scanner as ``route_probe`` batches, one per 25 hosts, and
    the server stores what comes back exactly as it stores its own readings (states, auth changes, the secrets inventory)."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real')).start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'route_probe')
        # every local request resolves its host first: a route asked here is a call to this (it is the network, which the tests block anyway)
        self.local = mock.patch('cveFeed.pinned_transport.resolve', side_effect=OSError('asked here, not by the scanner')).start()

    @staticmethod
    def row(url, state='not_found', status=404, **extra):
        return {'id': url, 'status': status, 'title': extra.pop('title', ''), 'content_type': 'text/html', 'state': state,
                'evidence': {'markers': [], 'bytes': 0, 'cookies': [], 'provider': '', 'redirect_to': extra.pop('redirect_to', '')},
                'sensitive': {}, 'sensitive_score': 0, 'bytes': 0, 'credentials': [], **extra}

    def answer(self, known=None):
        """A responder: every asked route is not found, except the paths of ``known`` (``{path: changes to the row}``)."""
        known = known or {}

        def responder(task):
            urls = [u for h in task['target']['hosts'] for u in h['urls']]
            return {'outcome': 'done', 'touched': [h['host'] for h in task['target']['hosts']], 'refused': [],
                    'routes': [{**self.row(u), **known.get('/' + u.split('://', 1)[1].split('/', 1)[1], {})} for u in urls]}
        return responder

    def run_stage(self, scan, responder=None, **kw):
        with FakeScanner(kinds=['route_probe'], responders={'route_probe': responder or self.answer()}, **kw) as fake:
            out = route_auth.run_route_auth(scan.id)
        return out, fake

    def test_the_scanner_asks_the_routes_and_the_stage_stores_their_states(self):
        known = {'/': {'status': 200, 'state': 'open', 'title': 'Home'}, '/login': {'status': 200, 'state': 'login', 'title': 'Sign in'},
                 '/admin': {'status': 302, 'state': 'session_required', 'evidence': {'markers': ['redirect'], 'bytes': 0, 'cookies': [], 'provider': '',
                                                                                  'redirect_to': '/login?next=/admin'}}}
        out, fake = self.run_stage(self.scan(), self.answer(known))
        self.assertEqual(fake.served_kinds(), ['route_probe'])
        self.assertEqual((self.guard.calls, self.local.call_count), ([], 0))
        self.assertEqual((out['routes'], out['errors']), (len(route_auth.COMMON_PATHS), 0))
        rows = {r.path: r for r in RouteAuth.objects.filter(project=self.project)}
        self.assertEqual((rows['/'].auth_state, rows['/'].title, rows['/'].host), ('open', 'Home', 'www.rt.test'))
        self.assertEqual((rows['/admin'].auth_state, rows['/admin'].redirect_to), ('session_required', '/login?next=/admin'))
        self.assertEqual(rows['/wp-login.php'].auth_state, 'not_found')
        self.assertEqual(ServiceRun.objects.filter(service='route-auth', status='done').count(), len(route_auth.COMMON_PATHS))
        target = fake.served[0]['target']
        self.assertEqual([h['host'] for h in target['hosts']], ['www.rt.test'])
        self.assertEqual(target['hosts'][0]['urls'][:2], ['https://www.rt.test/', 'https://www.rt.test/login'])
        self.assertIn('www.rt.test', target['scope']['hosts'])
        self.assertIn('code.jquery.com', target['scope']['hosts'])  # the public library CDNs: a page's scripts may be read there
        self.assertEqual(target['scope']['domains'], [])

    def test_the_routes_asked_are_the_plans_and_the_per_host_cap_is_kept(self):
        out, fake = self.run_stage(self.scan(names=('a.rt.test', 'b.rt.test')))
        asked = {u for t in fake.served for h in t['target']['hosts'] for u in h['urls']}
        self.assertEqual(len(asked), 2 * len(route_auth.COMMON_PATHS))
        self.assertEqual(out['hosts'], 2)

    def test_more_than_25_hosts_go_in_more_than_one_task(self):
        names = tuple(f'h{i:02d}.rt.test' for i in range(27))
        with mock.patch.object(route_auth, 'MAX_URLS_PER_SCAN', 5000):
            out, fake = self.run_stage(self.scan(names=names))
        self.assertEqual([len(t['target']['hosts']) for t in fake.served], [25, 2])
        self.assertEqual(out['hosts'], 27)

    def test_a_credential_the_scanner_read_goes_to_the_inventory_and_is_never_stored_in_the_route(self):
        value = 'AKIA0000000000000000'

        def serve(task):
            out = self.answer({'/': {'status': 200, 'state': 'open', 'content_type': 'application/json',
                                     'sensitive': {'aws_key': {'count': 1, 'sample': 'AWS access key, 20 chars (AKIA...)'}}, 'sensitive_score': 3,
                                     'credentials': [{'type': 'aws_key', 'value': value}]}})(task)
            return out
        self.run_stage(self.scan(), serve)
        root = RouteAuth.objects.get(project=self.project, path='/')
        self.assertEqual(root.sensitive_score, 25)  # the server's own score, not the scanner's
        self.assertIn('aws_key', root.sensitive)
        self.assertTrue(SecretFinding.objects.filter(project=self.project).exists())
        self.assertNotIn(value, json.dumps(root.evidence) + json.dumps(root.sensitive))

    def test_with_the_scanner_offline_the_routes_wait_and_stay_due(self):
        out, fake = self.run_stage(self.scan(), mode='offline')
        self.assertEqual(fake.served, [])
        self.assertEqual((self.guard.calls, self.local.call_count), ([], 0))
        self.assertEqual(out['routes'], 0)
        self.assertIn('no scanner could take this work (route_probe)', out['skipped'])
        self.assertFalse(RouteAuth.objects.exists())
        self.assertFalse(ServiceRun.objects.filter(service='route-auth').exists())  # neither done nor failed: due
        self.assertTrue(AgentActivity.objects.filter(message__icontains='waiting').exists())
        with ledger.claim_many(f'route-auth@{self.project.id}', ['https://www.rt.test/']) as won:  # the claim was let go
            self.assertEqual(len(won), 1)

    def test_a_scanner_that_fails_the_task_leaves_the_routes_due(self):
        out, fake = self.run_stage(self.scan(), mode='fail')
        self.assertEqual(fake.served_kinds(), ['route_probe'])
        self.assertEqual((self.guard.calls, self.local.call_count), ([], 0))
        self.assertIn('skipped', out)
        self.assertFalse(RouteAuth.objects.exists())
        self.assertFalse(ServiceRun.objects.filter(service='route-auth').exists())

    def test_a_route_the_scanner_could_not_ask_is_unanswered_never_a_state(self):
        def partly(task):
            out = self.answer({'/': {'status': 200, 'state': 'open'}})(task)
            out['routes'] = [{'id': r['id'], 'error': 'TimeoutError: timed out'} if r['id'].endswith('/login') else r
                             for r in out['routes'] if not r['id'].endswith('/admin')]  # an error row, and one the scanner never reported
            return out
        out, _ = self.run_stage(self.scan(), partly)
        total = len(route_auth.COMMON_PATHS)
        self.assertEqual((out['routes'], out['errors']), (total - 2, 2))
        self.assertEqual(set(RouteAuth.objects.values_list('path', flat=True)) & {'/login', '/admin'}, set())
        failed = set(ServiceRun.objects.filter(service='route-auth', status='failed').values_list('asset', flat=True))
        self.assertEqual(len(failed), 2)
        self.assertEqual(ServiceRun.objects.filter(service='route-auth', status='done').count(), total - 2)

    def test_a_state_a_status_cannot_have_is_an_unanswered_route(self):
        def lies(task):
            out = self.answer()(task)
            out['routes'] = [self.row(r['id'], state='not_found', status=200) if r['id'].endswith('/admin') else r for r in out['routes']]
            return out
        out, _ = self.run_stage(self.scan(), lies)
        self.assertEqual(out['errors'], 1)
        self.assertFalse(RouteAuth.objects.filter(path='/admin').exists())

    def test_an_answer_for_a_route_the_task_did_not_ask_is_dropped(self):
        def stranger(task):
            out = self.answer()(task)
            out['routes'].append(self.row('https://other.rt.test/', state='open', status=200))
            return out
        _, fake = self.run_stage(self.scan(), stranger)
        self.assertEqual(fake.tasks()[0].result.get('dropped'), 1)
        self.assertFalse(RouteAuth.objects.filter(host='other.rt.test').exists())

    def test_a_catch_all_answer_is_stored_but_is_not_an_auth_change(self):
        known = {'/admin': {'status': 200, 'state': 'open', 'title': 'Admin'}}
        with FakeScanner(kinds=['route_probe'], responders={'route_probe': lambda task: self.answer(known)(task)}):
            route_auth.run_route_auth(self.scan().id)
            ServiceRun.objects.update(finished_at=timezone.now() - timedelta(days=8))
            known['/admin'] = {'status': 200, 'state': 'catch_all'}
            route_auth.run_route_auth(self.scan().id)
        self.assertEqual(RouteAuth.objects.get(path='/admin').auth_state, 'catch_all')
        self.assertFalse(AssetChange.objects.filter(kind='auth_changed').exists())




class RouteProbeResultTests(SimpleTestCase):
    def clean(self, **row):
        good = fixture('route_probe')['routes'][0]
        return broker.clean_result('route_probe', {**fixture('route_probe'), 'routes': [{**good, **row}]})['routes']

    def test_the_fixture_goes_through_unchanged(self):
        sent = fixture('route_probe')
        self.assertEqual(broker.clean_result('route_probe', sent), sent)

    def test_the_evidence_keeps_only_what_a_route_check_keeps(self):
        evidence = {**fixture('route_probe')['routes'][0]['evidence'], 'page_scripts': {'scripts': []}, 'invented': 1, 'markers': 'not a list', 'server': 's' * 500}
        got = self.clean(evidence=evidence)[0]['evidence']
        self.assertNotIn('page_scripts', got)
        self.assertNotIn('invented', got)
        self.assertNotIn('markers', got)
        self.assertEqual(len(got['server']), 100)

    def test_evidence_that_is_too_large_makes_the_route_unanswered(self):
        got = self.clean(evidence={'libraries': {'jquery': {'blob': 'x' * (probe_results.MAX_ROUTE_EVIDENCE_BYTES + 1)}}})[0]
        self.assertEqual(set(got), {'id', 'error'})

    def test_a_state_must_be_known_and_fit_the_status(self):
        self.assertEqual(set(self.clean(state='owned')[0]), {'id', 'error'})
        self.assertEqual(set(self.clean(state='not_found', status=200)[0]), {'id', 'error'})
        self.assertEqual(set(self.clean(state='open', status=500)[0]), {'id', 'error'})
        self.assertEqual(self.clean(state='sso', status=302)[0]['state'], 'sso')

    def test_the_score_is_the_servers_own_and_a_credential_is_a_known_type_with_a_value(self):
        got = self.clean(sensitive={'aws_key': {'count': 1, 'sample': 'x' * 900}, 'rm_rf': {'count': 1, 'sample': 'y'}}, sensitive_score=0,
                         credentials=[{'type': 'aws_key', 'value': 'AKIA0000000000000000'}, {'type': 'shell', 'value': 'ls'}, {'type': 'jwt', 'value': ''}, 'nope'])[0]
        self.assertEqual((got['sensitive_score'], list(got['sensitive'])), (25, ['aws_key']))
        self.assertEqual(len(got['sensitive']['aws_key']['sample']), 200)
        self.assertEqual(got['credentials'], [{'type': 'aws_key', 'value': 'AKIA0000000000000000'}])

    def test_an_error_row_carries_no_state_and_the_lists_are_bounded(self):
        got = self.clean(error='e' * 999)[0]
        self.assertEqual((set(got), len(got['error'])), ({'id', 'error'}, 200))
        with self.assertRaises(ApiError):
            probe_results.clean_route_probe({'routes': [{}] * 501})
        with self.assertRaises(ApiError):
            probe_results.clean_route_probe({})

    def test_the_hosts_of_a_task_are_matched_against_a_sentinels_scope(self):
        task = SentinelTask(kind='route_probe', host='', ips=[], target={'hosts': [{'host': 'a.example.test', 'urls': ['https://a.example.test/']}]})
        self.assertEqual(broker.task_hosts(task), (['a.example.test'], []))


class RouteScopeTests(RouteFixture, TestCase):
    def test_the_policy_names_the_planned_hosts_the_cdns_and_leaves_an_excluded_host_out(self):
        scan = self.scan(names=('a.rt.test', 'b.rt.test'))
        HostExclusion.objects.create(org=self.project.org, host='b.rt.test')
        got = probe_scope.for_routes(self.project.id, scan, ['b.rt.test', 'a.rt.test'])
        self.assertEqual(got['hosts'][0], 'a.rt.test')
        self.assertNotIn('b.rt.test', got['hosts'])
        self.assertIn('b.rt.test', got['excluded'])
        self.assertIn('unpkg.com', got['hosts'])
        self.assertEqual((got['domains'], got['excluded_trees']), ([], []))
        self.assertEqual(probe_scope.for_routes(self.project.id, scan, ['a.rt.test', 'b.rt.test']), got)  # the same task on every pass


# ----------------------------------------------------------------------------- supplier_check

class SupplierCheckStageTests(SupplierFixture, TestCase):
    """The supplier sweep (``supplier_scan.sweep``): a supplier's names go to the scanner as one ``supplier_check`` task, and the server stores what
    comes back as it stores its own checks, writing the text and the CVE match itself."""
    D = 'portal.vendor.test'

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'supplier_check')
        self.s = self.supplier(domains=[self.D])
        self.net.site(self.D, https=supplier_page(headers={}, server='nginx/1.25.3'), tls=supplier_cert(self.D, days=3))

    def responder(self, change=None):
        def serve(task):
            rows = []
            for domain in task['target']['domains']:
                rows.append(self.net.row(domain))
            out = {'outcome': 'done', 'domains': rows, 'touched': list(task['target']['domains']), 'refused': []}
            return change(out) if change else out
        return {'supplier_check': serve}

    def remote_sweep(self, **kw):
        with FakeScanner(kinds=['supplier_check'], **kw) as fake:
            out = supplier_scan.sweep(self.project.id)
        return out, fake

    def test_the_scanner_checks_the_names_and_the_sweep_stores_the_card_and_the_findings(self):
        out, fake = self.remote_sweep(responders=self.responder())
        self.assertEqual(fake.served_kinds(), ['supplier_check'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual((out['suppliers'], out['domains']), (1, 1))
        self.assertGreater(out['new'], 0)
        self.assertEqual({'tls_expiring', 'hsts_missing', 'security_headers_missing'} - set(self.checks(self.s)), set())
        found = self.finding(self.s, self.D, 'hsts_missing')
        self.assertIn('Ask the supplier to send a Strict-Transport-Security header', found.ask)  # the text is the server's
        card = SupplierHostCard.objects.get(supplier=self.s, domain=self.D)
        self.assertEqual((card.state, card.addresses, card.tls['issuer'], card.http['server']), ('ok', ['203.0.113.10'], 'Example CA', 'nginx/1.25.3'))
        self.assertEqual([t['name'] for t in card.technologies], ['nginx'])  # read here from the fingerprints
        self.assertIn('nginx 1.25.3', card.tech_text)
        self.s.refresh_from_db()
        self.assertIsNotNone(self.s.last_checked_at)
        self.assertTrue(ServiceRun.objects.filter(service=supplier_scan.SERVICE, asset=str(self.s.pk), status='done').exists())
        self.assertEqual(out['requests'], 17)  # the scanner's count is charged to the sweep's budget

    def test_the_task_carries_the_names_the_pacing_the_budget_and_a_policy_that_names_nothing_else(self):
        _out, fake = self.remote_sweep(responders=self.responder())
        target = fake.served[0]['target']
        self.assertEqual(target['domains'], [self.D])
        self.assertEqual(target['pace'], {'gap': 1.0, 'host_gap': 2.0})
        self.assertEqual(target['max_requests'], supplier_scan.max_requests())
        scope = target['scope']
        self.assertEqual((scope['hosts'], scope['domains'], scope['excluded_trees']), ([self.D, f'mta-sts.{self.D}'], [], []))  # no tree, no other name
        self.assertEqual((scope['private'], scope['addresses']), (False, []))
        self.assertEqual(list(SentinelTask.objects.filter(kind='supplier_check').values_list('host', flat=True)), [self.D])


    def test_the_catalog_is_matched_here_from_what_the_response_announced(self):
        CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=7.5, kev=False, title='t', published_at=timezone.now(),
                                affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.26.0'}]}])
        self.net.site(self.D, https=supplier_page(headers={}, server='nginx/1.25.3'), tls=supplier_cert(self.D, days=300))
        self.remote_sweep(responders=self.responder())
        found = self.finding(self.s, self.D, 'cve_nginx')
        self.assertEqual((found.category, found.evidence['cves'][0]['id'], found.evidence['validated']), ('cve', 'CVE-2099-7', False))
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s).evidence['announced'], ['nginx:1.25.3'])

    def test_an_excluded_name_is_never_sent(self):
        HostExclusion.objects.create(org=self.org1, host=self.D)
        out, fake = self.remote_sweep(responders=self.responder())
        self.assertEqual(fake.served, [])
        self.assertEqual(SupplierHostCard.objects.get(supplier=self.s, domain=self.D).state, 'excluded')
        self.assertFalse(SupplierFinding.objects.exists())

    def test_with_the_scanner_offline_the_suppliers_stay_due_and_nothing_is_recorded(self):
        with FakeScanner(kinds=['supplier_check'], mode='offline') as fake:
            out = supplier_scan.sweep(self.project.id)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertEqual(out['suppliers'], 0)
        self.assertFalse(ServiceRun.objects.filter(service__in=(supplier_scan.SERVICE, supplier_scan.FAILED_SERVICE)).exists())
        self.assertFalse(SupplierFinding.objects.exists() or SupplierHostCard.objects.exists())
        self.assertEqual(len(supplier_scan.due_suppliers(self.project.id)), 1)

    def test_a_scanner_that_fails_the_task_leaves_the_supplier_due(self):
        with FakeScanner(kinds=['supplier_check'], mode='fail') as fake:
            out = supplier_scan.sweep(self.project.id)
        self.assertEqual(fake.served_kinds(), ['supplier_check'])
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertFalse(ServiceRun.objects.filter(service__in=(supplier_scan.SERVICE, supplier_scan.FAILED_SERVICE)).exists())


    def test_a_name_the_scanner_could_not_read_changes_nothing_and_is_asked_again_tomorrow(self):
        with FakeScanner(kinds=['supplier_check'], responders=self.responder()):
            supplier_scan.sweep(self.project.id)
            before = self.checks(self.s)
            self.net.pages[f'https://{self.D}/'] = OSError('timed out')
            self.net.pages[f'http://{self.D}/'] = OSError('timed out')
            self.net.certs[self.D] = None
            ServiceRun.objects.filter(service__in=(supplier_scan.SERVICE, supplier_scan.FAILED_SERVICE)).delete()
            out = supplier_scan.sweep(self.project.id)
        self.assertEqual((self.checks(self.s), out['resolved']), (before, 0))  # nothing was resolved because nothing could be seen
        self.assertEqual(ServiceRun.objects.filter(service=supplier_scan.FAILED_SERVICE).count(), 1)
        self.assertEqual(ServiceRun.objects.filter(service=supplier_scan.SERVICE).count(), 0)

    def test_a_scanner_that_reports_nothing_for_a_name_has_checked_nothing(self):
        out, _fake = self.remote_sweep(responders=self.responder(lambda r: {**r, 'domains': []}))
        self.assertFalse(SupplierFinding.objects.exists())
        self.assertEqual(ServiceRun.objects.filter(service=supplier_scan.FAILED_SERVICE).count(), 1)
        self.assertEqual(ServiceRun.objects.filter(service=supplier_scan.SERVICE).count(), 0)

    def test_a_claim_to_have_decided_a_category_resolves_nothing_the_card_does_not_show(self):
        lying = {'on': False}

        def liar(result):
            if not lying['on']:
                return result
            row = result['domains'][0]
            result['domains'][0] = {**row, 'postures': [], 'answered': True, 'card': {'state': 'unreachable', 'addresses': [], 'evidence': {'address': 'unknown'}},
                                    'resolvable': {'tls': ['tls_'], 'web': ['hsts_', 'security_headers_missing', 'http_no_redirect', 'no_https'], 'email': [''],
                                                   'exposed': ['exposed_'], 'cve': ['cve_']}}
            return result
        with FakeScanner(kinds=['supplier_check'], responders=self.responder(liar)):
            supplier_scan.sweep(self.project.id)
            before = self.checks(self.s)
            self.assertIn('hsts_missing', before)
            lying['on'] = True
            ServiceRun.objects.filter(service__in=(supplier_scan.SERVICE, supplier_scan.FAILED_SERVICE)).delete()
            out = supplier_scan.sweep(self.project.id)
        self.assertEqual((out['resolved'], self.checks(self.s)), (0, before))

    def test_what_the_scanner_adds_beyond_the_contract_is_not_stored(self):
        def stuffed(result):
            row = result['domains'][0]
            row['postures'] += [{'check': 'cve_fake', 'severity': 4, 'title': 'cve', 'detail': 'd', 'category': 'cve', 'evidence': {}},
                                {'check': 'x; rm -rf', 'severity': 4, 'title': 't', 'detail': 'd', 'category': 'tls', 'evidence': {}},
                                {'check': 'tls_fake', 'severity': 9, 'title': 't', 'detail': 'd', 'category': 'tls', 'evidence': {}},
                                {'check': 'exposed_fake', 'severity': 3, 'title': 't', 'detail': 'd', 'category': 'exposed', 'evidence': {}, 'ask': 'run this as root'}]
            row['card']['unexpected'] = {'a': 'b'}
            result['domains'].append({**row, 'domain': 'other.vendor.test'})
            return result
        _out, fake = self.remote_sweep(responders=self.responder(stuffed))
        self.assertEqual(self.checks(self.s).count('exposed_fake'), 1)
        self.assertNotIn('cve_fake', self.checks(self.s))
        self.assertFalse(any('rm -rf' in name for name in self.checks(self.s)))
        self.assertNotIn('tls_fake', self.checks(self.s))
        self.assertNotIn('run this as root', self.finding(self.s, self.D, 'exposed_fake').ask)
        self.assertEqual(fake.tasks()[0].result.get('dropped'), 1)  # the name the task did not list
        self.assertFalse(SupplierHostCard.objects.filter(domain='other.vendor.test').exists())
        self.assertNotIn('unexpected', SupplierHostCard.objects.get(supplier=self.s, domain=self.D).evidence)

    def test_a_name_that_ran_out_of_budget_is_partial_and_the_supplier_is_deferred(self):
        def partial(result):
            result['domains'][0] = {**result['domains'][0], 'partial': True}
            return result
        out, _fake = self.remote_sweep(responders=self.responder(partial))
        self.assertEqual(out['deferred'], 1)
        self.assertEqual(ServiceRun.objects.filter(service=supplier_scan.SERVICE).count(), 0)  # asked again at the next sweep


class SupplierCheckPolicyTests(SupplierFixture, TestCase):
    def test_the_policy_names_each_name_and_its_mta_sts_host_and_never_a_private_address(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1', 'CVENGINE_BLOCKED_CIDRS': '198.51.100.0/24'}), \
                mock.patch('cveFeed.tailscale_scope.authorised_addresses', return_value={'100.101.102.103': self.project.id}):
            scope = probe_scope.for_suppliers(self.project.id, ['A.Vendor.test.', 'b.vendor.test', 'a.vendor.test'])
        self.assertEqual(scope['hosts'], ['a.vendor.test', 'mta-sts.a.vendor.test', 'b.vendor.test', 'mta-sts.b.vendor.test'])
        self.assertEqual((scope['domains'], scope['excluded'], scope['excluded_trees']), ([], [], []))
        self.assertEqual((scope['private'], scope['addresses'], scope['blocked']), (False, [], ['198.51.100.0/24']))  # the server's own rules travel, the lab ones do not

    def test_a_result_is_clipped_to_the_contract(self):
        row = {'domain': 'WWW.Vendor.test.', 'postures': [{'check': 'hsts_missing', 'severity': 2, 'title': 't' * 900, 'detail': 'd' * 9000, 'category': 'web',
                                                            'evidence': {'blob': 'x' * 20_000}}, {'check': 'a', 'severity': True, 'title': '', 'detail': '', 'category': 'web'}],
               'resolvable': {'web': ['hsts_'], 'shell': ['x'], 'cve': ['cve_']}, 'summary': {'address': 'ok', 'nested': {'a': 1}},
               'card': {'state': 'odd', 'addresses': ['203.0.113.10', 'not-an-ip', 'file:///etc/passwd'], 'evidence': {'address': 'bogus', 'dns': 'ok', 'x': 1}},
               'fingerprints': [{'name': 'n' * 500, 'source': 's'}, 'junk'], 'edges': ['cloudflare', 7], 'distro': 'Ubuntu',
               'answered': 'yes', 'stopped': False, 'partial': True, 'requests': 10 ** 9}
        got = probe_results.clean_supplier_check({'domains': [row, 'junk', {'domain': ''}], 'touched': ['A.vendor.test', 'bad host'], 'refused': []})
        self.assertEqual(len(got['domains']), 1)
        out = got['domains'][0]
        self.assertEqual(out['domain'], 'www.vendor.test')
        self.assertEqual([(p['check'], len(p['title']), len(p['detail']), p['evidence']) for p in out['postures']], [('hsts_missing', 300, 4000, {})])
        self.assertEqual(out['resolvable'], {'web': ['hsts_'], 'cve': ['cve_']})
        self.assertEqual(out['summary'], {'address': 'ok'})
        self.assertEqual((out['card']['state'], out['card']['addresses'], out['card']['evidence']), ('unreachable', ['203.0.113.10'], {'dns': 'ok'}))
        self.assertEqual(([len(f['name']) for f in out['fingerprints']], out['edges'], out['answered'], out['requests']), ([120], ['cloudflare'], False, 0))
        self.assertEqual(got['touched'], ['a.vendor.test'])
        with self.assertRaises(ApiError):
            probe_results.clean_supplier_check({'domains': [{}] * 26})

    def test_the_fixture_goes_through_unchanged_and_the_hosts_of_a_batch_are_its_names(self):
        sent = fixture('supplier_check')
        self.assertEqual(broker.clean_result('supplier_check', sent), sent)
        task = SentinelTask(kind='supplier_check', host='', ips=[], target={'domains': ['A.vendor.test', 'b.vendor.test'], 'scope': {'hosts': ['x.example.test']}})
        self.assertEqual(broker.task_hosts(task), (['a.vendor.test', 'b.vendor.test'], []))


class IdentityCheckResultTests(SimpleTestCase):
    """The ``identity_check`` kind: what a Sentinel reports is clipped to the contract and cut down to what the task asked."""

    def test_the_fixture_goes_through_unchanged_and_the_hosts_of_a_batch_are_its_names_and_addresses(self):
        sent = fixture('identity_check')
        self.assertEqual(broker.clean_result('identity_check', sent), sent)
        task = SentinelTask(kind='identity_check', host='', ips=[], target={'dns': [{'id': 'a', 'name': 'WWW.example.test', 'type': 'CNAME'}, {'id': 'b', 'name': '203.0.113.9', 'type': 'PTR'}],
                                                                           'certs': [{'id': 'c', 'host': '203.0.113.10', 'port': 443}], 'scope': {'hosts': ['x.example.test']}})
        self.assertEqual(broker.task_hosts(task), (['www.example.test'], ['203.0.113.9', '203.0.113.10']))

    def test_a_result_is_clipped_to_the_contract(self):
        got = probe_results.clean_identity_check({
            'dns': [{'id': 'a', 'status': 'ok', 'records': ['r' * 900, 7], 'canonical': 'App.Netlify.APP.'}, {'id': 'b', 'status': 'none', 'records': ['ignored'], 'canonical': 'x'},
                    {'id': 'c', 'status': 'maybe'}, {'id': '', 'status': 'ok'}, 'junk', {'id': 'd', 'status': 'unknown', 'error': 'e' * 900}],
            'certs': [{'id': 'e', 'status': 'ok', 'names': ['n' * 900, None, 'ok.example.test']}, {'id': 'f', 'status': 'unknown', 'names': ['ignored']}, {'id': 'g', 'status': 'x'}],
            'touched': ['A.example.test', 'bad host'], 'refused': []})
        self.assertEqual(got['dns'], [{'id': 'a', 'status': 'ok', 'records': ['r' * 260], 'canonical': 'app.netlify.app'},
                                      {'id': 'b', 'status': 'none', 'records': []}, {'id': 'd', 'status': 'unknown', 'records': [], 'error': 'e' * 200}])
        self.assertEqual(got['certs'], [{'id': 'e', 'status': 'ok', 'names': ['n' * 260, 'ok.example.test']}, {'id': 'f', 'status': 'unknown', 'names': []}])
        self.assertEqual(got['touched'], ['a.example.test'])
        with self.assertRaises(ApiError):
            probe_results.clean_identity_check({'dns': [{}] * 201, 'certs': []})
        with self.assertRaises(ApiError):
            probe_results.clean_identity_check({'dns': [], 'certs': 'x'})

    def test_an_answer_the_task_did_not_ask_for_is_dropped_and_an_id_counts_once(self):
        task = SentinelTask(kind='identity_check', target={'dns': [{'id': 'a', 'name': 'x.example.test', 'type': 'NS'}], 'certs': [{'id': 'c', 'host': '203.0.113.9', 'port': 443}]})
        result = {'outcome': 'done', 'dns': [{'id': 'a', 'status': 'none', 'records': []}, {'id': 'a', 'status': 'ok', 'records': ['ns.example.net.']}, {'id': 'zz', 'status': 'ok', 'records': []}],
                  'certs': [{'id': 'c', 'status': 'ok', 'names': ['a.example.test']}, {'id': 'other', 'status': 'ok', 'names': []}], 'touched': [], 'refused': []}
        got = probe_results.bind('identity_check', result, task)
        self.assertEqual([r['id'] for r in got['dns']], ['a'])
        self.assertEqual(got['dns'][0]['status'], 'none')  # the first answer to an id is the answer
        self.assertEqual([r['id'] for r in got['certs']], ['c'])
        self.assertEqual(got['dropped'], 3)


class IdentityCheckStageTests(DispatchBase):
    """Every read the server used to make of a name or an address, end to end through the fake built-in scanner: an IP target's reverse name and
    certificate (``discovery.discover_ip``), the CNAME of a name that has none stored (``hosting.shared_by_address``) and the name and mail
    servers of a domain (``domain_ownership``). The kind has no local path: with no scanner nothing is read and nothing is concluded."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'identity_check')
        self.asked = []

    def responder(self, dns=None, certs=None):
        def answer(task):
            self.asked.append(task['target'])
            return {'outcome': 'done', 'dns': [dns(q) for q in task['target'].get('dns', [])] if dns else [],
                    'certs': [certs(c) for c in task['target'].get('certs', [])] if certs else [], 'touched': [], 'refused': []}
        return {'identity_check': answer}

    def ip_scan(self, address='203.0.113.9'):
        Domain.objects.filter(pk=self.domain.pk).update(name=address)
        self.domain.refresh_from_db()
        return self.scan

    def test_an_ip_target_gets_its_reverse_name_and_certificate_names_from_the_scanner(self):
        scan = self.ip_scan()
        responders = self.responder(dns=lambda q: {'id': q['id'], 'status': 'ok', 'records': ['Host.Example.Test.']},
                                    certs=lambda c: {'id': c['id'], 'status': 'ok', 'names': ['cn.example.test', '*.example.test', 'cn.example.test', 'localhost']})
        with FakeScanner(kinds=['identity_check'], responders=responders) as fake:
            found = discovery.discover_ip(scan)
        self.assertEqual(fake.served_kinds(), ['identity_check'])
        self.assertEqual(self.guard.calls, [])
        self.assertEqual((found['status'], found['names']), (discovery.SUCCESS, ['cn.example.test', 'example.test', 'host.example.test']))
        target = fake.served[0]['target']
        self.assertEqual(target['dns'], [{'id': 'ptr', 'name': '203.0.113.9', 'type': 'PTR'}])
        self.assertEqual(target['certs'], [{'id': 'tls', 'host': '203.0.113.9', 'port': 443}])
        self.assertEqual(target['scope']['hosts'], ['203.0.113.9'])
        self.assertEqual(sorted(DiscoveryEvent.objects.filter(scan=scan, type='DNS_NAME').values_list('module', 'label')),
                         [('ptr', 'host.example.test'), ('tls-san', 'cn.example.test'), ('tls-san', 'example.test')])

    def test_a_read_the_scanner_could_not_answer_records_no_names_but_the_scan_goes_on(self):
        scan = self.ip_scan()
        responders = self.responder(dns=lambda q: {'id': q['id'], 'status': 'unknown', 'records': [], 'error': 'Timeout'},
                                    certs=lambda c: {'id': c['id'], 'status': 'unknown', 'names': []})
        with FakeScanner(kinds=['identity_check'], responders=responders):
            found = discovery.discover_ip(scan)
        self.assertEqual((found['status'], found['names']), (discovery.SUCCESS, []))

    def test_with_no_scanner_the_ip_lookup_waits_and_nothing_is_read_here(self):
        scan = self.ip_scan()
        with FakeScanner(kinds=['identity_check'], mode='offline') as fake:
            found = discovery.discover_ip(scan)
        self.assertEqual(fake.served, [])
        self.assertEqual(found['status'], discovery.FAILED)
        self.assertIn('waiting for a scanner', found['error'])
        self.assertEqual(self.guard.calls, [])
        self.assertFalse(DiscoveryEvent.objects.filter(scan=scan, type='DNS_NAME').exists())

    def test_a_platform_cname_that_was_never_stored_is_read_by_the_scanner(self):
        Subdomain.objects.filter(name='www.example.test').update(target_domain=self.domain)
        responders = self.responder(dns=lambda q: {'id': q['id'], 'status': 'ok', 'records': [], 'canonical': 'acme.netlify.app'})
        hosting._canon.clear()
        with FakeScanner(kinds=['identity_check'], responders=responders) as fake:
            found = hosting.shared_by_address(['192.0.2.10'])
        self.assertEqual(self.asked[0]['dns'], [{'id': 'www.example.test', 'name': 'www.example.test', 'type': 'CNAME'}])
        self.assertEqual(fake.served_kinds(), ['identity_check'])
        self.assertEqual(found['192.0.2.10']['provider'], 'Netlify')

    def test_with_no_scanner_the_stored_data_classifies_and_nothing_waits_for_the_read(self):
        Subdomain.objects.filter(name='www.example.test').update(target_domain=self.domain)
        hosting._canon.clear()
        self.assertEqual(hosting.shared_by_address(['192.0.2.10']), {})
        self.assertEqual(hosting.canonical_names(['www.example.test']), {})  # unknown is missing, never cached as "not an alias"
        self.assertEqual(self.guard.calls, [])

    def test_the_name_and_mail_servers_of_a_domain_are_read_by_the_scanner_in_one_task(self):
        def dns(q):
            return {'id': q['id'], 'status': 'ok', 'records': ['ns1.dns-example.net.'] if q['type'] == 'NS' else ['10 mx.mailhost-example.net.']} if q['name'] == 'example.test' \
                else {'id': q['id'], 'status': 'none', 'records': []}
        lookup = domain_ownership.Lookup(self.project.id)
        with FakeScanner(kinds=['identity_check'], responders=self.responder(dns=dns)) as fake:
            self.assertEqual(domain_ownership.infrastructure('example.test', lookup), ({'dns-example.net'}, {'mailhost-example.net'}))
            self.assertEqual(lookup.records('other.example.test', 'NS'), [])
        self.assertEqual(len(fake.served), 2)  # one task for both types of the domain, one for a name asked later
        self.assertEqual(sorted((q['type'], q['name']) for q in self.asked[0]['dns']), [('MX', 'example.test'), ('NS', 'example.test')])

    def test_with_no_scanner_a_domain_has_no_records_and_is_never_read_as_having_none(self):
        lookup = domain_ownership.Lookup(self.project.id)
        self.assertIsNone(lookup.records('example.test', 'NS'))
        self.assertIsNone(domain_ownership.infrastructure('example.test', lookup))
        self.assertEqual(self.guard.calls, [])


class IdentityScopeTests(DispatchBase):
    def test_an_excluded_name_is_never_listed_and_its_question_is_never_sent(self):
        HostExclusion.objects.create(org=self.org, host='secret.example.test')
        scope = probe_scope.for_identity(self.project.id, ['www.example.test', 'Secret.example.test.', '203.0.113.9', 'www.example.test'])
        self.assertEqual(scope['hosts'], ['www.example.test', '203.0.113.9'])
        self.assertEqual(scope['excluded'], ['secret.example.test'])
        self.assertEqual((scope['domains'], scope['excluded_trees']), ([], []))


def hygiene_answer(task, expiring=('www.example.test',), findings=None, skip_mail=False, errors=()):
    """A Sentinel's answer to a ``hygiene_check`` task: a certificate expiring in five days on each endpoint of ``expiring``, nothing speaking TLS elsewhere,
    and the mail review of every name the task flagged ``always``."""
    now = datetime.datetime.now(datetime.timezone.utc)
    certs = []
    for t in task['target']['tls']:
        row = {'host': t['host'], 'port': t['port'], 'found': False}
        if (t['host'], t['port']) in errors:
            row['error'] = 'not run: probe failed'
        elif t['host'] in expiring:
            row = {**row, 'found': True, 'cert': {'subject': t['host'], 'issuer': 'Example CA', 'sans': [t['host']], 'not_before': (now - datetime.timedelta(days=80)).isoformat(),
                                                  'not_after': (now + datetime.timedelta(days=5)).isoformat(), 'signature_algorithm': 'sha256 (sha256WithRSAEncryption)',
                                                  'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'cipher': 'X', 'chain_error': '', 'legacy_tls': False}}
        certs.append(row)
    default = [{'check': 'dmarc_none', 'severity': 2, 'title': 'DMARC policy is p=none (monitoring only)', 'detail': 'Spoofed mail is still delivered.',
                'host': 'example.test', 'evidence': {'record': 'v=DMARC1; p=none'}}]
    mail = [] if skip_mail else [{'name': m['name'], 'has_mx': True, 'findings': default if findings is None else findings}
                                 for m in task['target']['mail'] if m.get('always')]
    return {'outcome': 'done', 'certs': certs, 'mail': mail, 'touched': [t['host'] for t in task['target']['tls']], 'refused': []}


class HygieneCheckStageTests(TestCase):
    """``hygiene.run_hygiene``: the TLS endpoints and the mail names go to the scanner as one ``hygiene_check`` task; the server evaluates the certificates
    and stores everything, and what the scanner did not answer is unknown: its open findings stay open."""

    def setUp(self):
        LocalFallback('none').apply(self)
        now = timezone_now()
        self.project = Project.objects.create(name='H', slug='hp', insert_date=now, org=Org.objects.create(name='H', slug='h'))
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        sub = Subdomain.objects.create(name='www.example.test', target_domain=self.domain)
        ip = IpAddress.objects.create(address='192.0.2.7')
        sub.ip_addresses.add(ip)
        ip.ports.add(Port.objects.create(number=8443))
        for patch in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True),
                      mock.patch('time.sleep', side_effect=lambda seconds: self.assertLessEqual(seconds, 0.2, 'a test slept for real'))):
            patch.start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'hygiene_check')

    def open_checks(self):
        return set(HygieneFinding.objects.filter(domain=self.domain, status='open').values_list('check_name', flat=True))

    def test_the_scanner_reads_the_endpoints_and_the_server_evaluates_and_stores(self):
        with FakeScanner(kinds=['hygiene_check'], responders={'hygiene_check': hygiene_answer}) as fake:
            counts = hy.run_hygiene(self.domain.id)
        self.assertEqual(fake.served_kinds(), ['hygiene_check'])
        self.assertEqual(self.guard.calls, [])
        target = fake.served[0]['target']
        self.assertEqual(sorted((t['host'], t['port']) for t in target['tls']), [('example.test', 443), ('www.example.test', 443), ('www.example.test', 8443)])
        self.assertEqual(target['mail'], [{'name': 'example.test', 'always': True}, {'name': 'www.example.test', 'always': False}])
        self.assertIn('mta-sts.example.test', target['scope']['hosts'])
        self.assertEqual((target['confirm_resolvers'], target['rdap']), ([], True))
        self.assertEqual(counts['tls_hosts'], 2)
        self.assertEqual(TlsCertificate.objects.get(host='www.example.test', port=443).days_left, 4)
        self.assertEqual(self.open_checks(), {'tls_expiring', 'dmarc_none'})  # the certificate rule is the server's; the DMARC finding is the scanner's
        self.assertTrue(ledger.fresh('hygiene', [self.domain.name], self.project.id))

    def test_with_the_scanner_offline_nothing_is_recorded_and_the_target_stays_due(self):
        HygieneFinding.objects.create(domain=self.domain, host='example.test', check_name='dmarc_none', severity=2, title='t', status='open')
        with FakeScanner(kinds=['hygiene_check'], mode='offline') as fake:
            counts = hy.run_hygiene(self.domain.id)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertIn('waiting for a scanner', counts['skipped'])
        self.assertFalse(TlsCertificate.objects.exists())
        self.assertEqual(self.open_checks(), {'dmarc_none'})  # not resolved for want of an answer
        self.assertFalse(ledger.fresh('hygiene', [self.domain.name], self.project.id))

    def test_what_the_scanner_did_not_answer_keeps_its_open_findings_open(self):
        runs = []

        def answer(task):  # the first run is answered in full; in the second www:443 was not probed (an error) and the apex's mail review is missing
            runs.append(task)
            return hygiene_answer(task) if len(runs) == 1 else hygiene_answer(task, expiring=(), skip_mail=True, errors={('www.example.test', 443)})
        with FakeScanner(kinds=['hygiene_check'], responders={'hygiene_check': answer}):
            hy.run_hygiene(self.domain.id)
            self.assertEqual(self.open_checks(), {'tls_expiring', 'dmarc_none'})
            hy.run_hygiene(self.domain.id)
        rows = {(r.host, r.check_name): r.status for r in HygieneFinding.objects.filter(domain=self.domain)}
        self.assertEqual(rows[('www.example.test:443', 'tls_expiring')], 'open')  # unknown, not "fixed"
        self.assertEqual(rows[('www.example.test:8443', 'tls_expiring')], 'resolved')  # answered: nothing speaks TLS there now
        self.assertEqual(rows[('example.test', 'dmarc_none')], 'open')  # the review did not come back

    def test_a_finding_of_another_stage_or_out_of_range_is_dropped_before_anything_is_stored(self):
        odd = [{'check': 'tls_expired', 'severity': 4, 'title': 'x', 'detail': '', 'host': 'example.test:443', 'evidence': {}},
               {'check': 'bkt_public', 'severity': 4, 'title': 'x', 'detail': '', 'host': 'example.test', 'evidence': {}},
               {'check': 'spf_allow_all', 'severity': 9, 'title': 'x', 'detail': '', 'host': 'example.test', 'evidence': {}},
               {'check': 'spf_softfail', 'severity': 1, 'title': 'SPF ends in ~all (soft fail)', 'detail': '', 'host': 'example.test', 'evidence': {}}]
        with FakeScanner(kinds=['hygiene_check'], responders={'hygiene_check': lambda task: hygiene_answer(task, expiring=(), findings=odd)}):
            hy.run_hygiene(self.domain.id)
        self.assertEqual(self.open_checks(), {'spf_softfail'})



def timezone_now():
    from django.utils import timezone
    return timezone.now()


class HygieneResultTests(SimpleTestCase):
    def body(self, **over):
        return {'certs': [], 'mail': [], 'touched': [], 'refused': [], **over}

    def cert(self, **over):
        return {'subject': 's', 'issuer': 'i', 'sans': ['a.example.test'], 'not_before': '2026-01-01T00:00:00+00:00', 'not_after': '2026-04-01T00:00:00',
                'signature_algorithm': 'sha256', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'cipher': 'X', 'chain_error': '', 'legacy_tls': False, **over}

    def test_a_certificate_is_clipped_dated_with_a_zone_and_one_without_an_expiry_is_unknown(self):
        out = probe_results.clean_hygiene_check(self.body(certs=[
            {'host': 'a.example.test', 'port': 443, 'found': True, 'cert': self.cert(subject='S' * 900)},
            {'host': 'b.example.test', 'port': 443, 'found': True, 'cert': self.cert(not_after='soon')},
            {'host': 'c.example.test', 'port': 99999, 'found': False}, {'host': 'd.example.test', 'port': 443, 'found': False, 'error': 'not run: refused'}]))
        good, bad, _gone, refused = out['certs'][0], out['certs'][1], None, out['certs'][2]
        self.assertEqual(len(good['cert']['subject']), 500)
        self.assertEqual(good['cert']['not_after'], '2026-04-01T00:00:00+00:00')
        self.assertEqual((bad['found'], bad['error']), (False, 'the certificate could not be read'))
        self.assertEqual((refused['host'], refused['found'], refused['error']), ('d.example.test', False, 'not run: refused'))
        self.assertEqual(len(out['certs']), 3)  # the row with an impossible port is gone

    def test_mail_findings_keep_only_the_checks_the_review_raises(self):
        def f(check, severity=1, host='example.test', evidence=None):
            return {'check': check, 'severity': severity, 'title': 't' * 500, 'detail': 'd', 'host': host, 'evidence': evidence if evidence is not None else {}}
        out = probe_results.clean_hygiene_check(self.body(mail=[{'name': 'example.test', 'has_mx': True, 'findings': [
            f('spf_softfail'), f('tls_expired'), f('cleartext_telnet'), f('ts_exposed'), f('DMARC_NONE'), f('dmarc_none', severity=5), f('dmarc_none', severity=True),
            f('dmarc_none', host='bad host'), f('dkim_weak_key', evidence={'bits': 512}), f('mx_direct_send', evidence={'x': 'y' * 40000})]}]))
        kept = out['mail'][0]['findings']
        self.assertEqual([x['check'] for x in kept], ['spf_softfail', 'dkim_weak_key', 'mx_direct_send'])
        self.assertEqual(len(kept[0]['title']), 300)
        self.assertEqual((kept[1]['evidence'], kept[2]['evidence']), ({'bits': 512}, {}))  # oversize evidence is dropped

    def test_a_result_past_its_bounds_is_refused_and_rows_the_task_did_not_ask_for_are_dropped(self):
        with self.assertRaises(ApiError):
            probe_results.clean_hygiene_check(self.body(certs=[{'host': 'a', 'port': 443, 'found': False}] * 301))
        task = mock.Mock(target={'tls': [{'host': 'A.example.test', 'port': 443}], 'mail': [{'name': 'example.test', 'always': True}]})
        got = probe_results.clean_hygiene_check(self.body(
            certs=[{'host': 'a.example.test', 'port': 443, 'found': False}, {'host': 'a.example.test', 'port': 8443, 'found': False}, {'host': 'other.test', 'port': 443, 'found': False}],
            mail=[{'name': 'example.test', 'has_mx': True, 'findings': []}, {'name': 'other.test', 'has_mx': True, 'findings': []}]))
        bound = probe_results.bind('hygiene_check', got, task)
        self.assertEqual(([(c['host'], c['port']) for c in bound['certs']], [m['name'] for m in bound['mail']], bound['dropped']),
                         ([('a.example.test', 443)], ['example.test'], 3))


class HygieneScopeTests(TestCase):
    def test_the_policy_lists_the_endpoints_and_each_names_mta_sts_host_and_keeps_an_excluded_one_out(self):
        project = Project.objects.create(name='S', slug='sp', insert_date=timezone_now(), org=Org.objects.create(name='S', slug='s'))
        HostExclusion.objects.create(org=project.org, host='skip.example.test')
        scope = probe_scope.for_hygiene(project.pk, [('www.example.test', 443), ('skip.example.test', 443)], ['example.test', 'skip.example.test'])
        self.assertEqual(scope['hosts'], ['www.example.test', 'mta-sts.example.test', 'mta-sts.skip.example.test'])  # the name itself is not excluded, its mta-sts host is not either
        self.assertEqual((scope['domains'], scope['excluded'], scope['private']), ([], ['skip.example.test'], False))
        listed = probe_scope.for_dangling(project.pk, ['a.example.test', 'skip.example.test', 'A.example.test.'])
        self.assertEqual((listed['hosts'], listed['excluded']), (['a.example.test'], ['skip.example.test']))


class DanglingDnsCheckTests(TestCase):
    NX = ('Dangling CNAME, possible subdomain takeover (NXDOMAIN technique). Confidence: [MEDIUM] Signature: [GENERIC] Indicator: [Generic Dangling CNAME] '
          'Trigger: [app.example.test, gone.example.net] baddns Module: [CNAME]')
    NS = ('Dangling NS Records (NS records without SOA) with known impact. Confidence: [LOW] Signature: [GENERIC] Indicator: [DNSWalk Analysis] '
          'Trigger: [ns-cloud-c1.googledomains.com] baddns Module: [NS]')

    def setUp(self):
        LocalFallback('none').apply(self)
        self.project = Project.objects.create(name='D', slug='dp', insert_date=timezone_now(), org=Org.objects.create(name='D', slug='d'))
        self.findings = [{'host': 'app.example.test', 'description': self.NX, 'module': 'baddns'},
                         {'host': 'old.example.test', 'description': self.NS, 'module': 'baddns'},
                         {'host': 'x.example.test', 'description': 'No DMARC record found', 'module': 'baddns'}]
        for patch in (mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True), mock.patch('time.sleep')):
            patch.start()
        self.addCleanup(mock.patch.stopall)
        self.guard = assert_ran_nowhere_locally(self, 'dangling_dns_check')

    def answer(self, task):
        rows = {'0': {'id': '0', 'state': 'rated', 'severity': 1, 'drop': False, 'note': 'gone.example.net does not resolve: stale', 'zone': ''},
                '1': {'id': '1', 'state': 'unknown'}}
        return {'outcome': 'done', 'ratings': [rows[c['id']] for c in task['target']['checks']], 'touched': [], 'refused': []}

    def test_the_scanner_rates_the_findings_and_one_it_could_not_answer_keeps_baddns_rating(self):
        with FakeScanner(kinds=['dangling_dns_check'], responders={'dangling_dns_check': self.answer}) as fake:
            got = dangling_dns.assess_all(self.findings, project=self.project)
        self.assertEqual(fake.served_kinds(), ['dangling_dns_check'])
        self.assertEqual(self.guard.calls, [])
        target = fake.served[0]['target']
        self.assertEqual([(c['id'], c['host'], c['kind'], c['triggers']) for c in target['checks']],
                         [('0', 'app.example.test', 'cname_nxdomain', ['app.example.test', 'gone.example.net']),
                          ('1', 'old.example.test', 'ns', ['ns-cloud-c1.googledomains.com'])])  # a finding this does not rate is never sent
        self.assertEqual(target['providers'], dangling_dns.providers_doc())  # the server's own lists travel with the task
        self.assertEqual(target['scope']['hosts'], ['app.example.test', 'old.example.test'])
        self.assertEqual((got[0].severity, got[0].drop, got[0].note), (1, False, 'gone.example.net does not resolve: stale'))
        self.assertEqual((got[1], got[2]), (None, None))

    def test_a_dropped_rating_comes_back_as_a_drop_and_a_bad_severity_as_keep(self):
        rows = [{'id': '0', 'state': 'rated', 'severity': None, 'drop': True, 'note': 'a CNAME into a provider', 'zone': 'app.example.test'}]
        with FakeScanner(kinds=['dangling_dns_check'], responders={'dangling_dns_check': lambda task: {'outcome': 'done', 'ratings': rows, 'touched': [], 'refused': []}}):
            got = dangling_dns.assess_all(self.findings[:1], project=self.project)
        self.assertTrue(got[0].drop)
        self.assertEqual(dangling_dns._rating_from({'state': 'rated', 'severity': 7, 'drop': False}).severity, None)
        self.assertIsNone(dangling_dns._rating_from({'state': 'unknown'}))

    def test_with_the_scanner_offline_every_finding_keeps_baddns_rating_and_nothing_runs_here(self):
        with FakeScanner(kinds=['dangling_dns_check'], mode='offline') as fake:
            got = dangling_dns.assess_all(self.findings, project=self.project)
        self.assertEqual((fake.served, got, self.guard.calls), ([], [None, None, None], []))

    def test_an_excluded_host_is_not_sent_and_a_rating_for_a_check_never_asked_is_ignored(self):
        HostExclusion.objects.create(org=self.project.org, host='old.example.test')
        extra = lambda task: {'outcome': 'done', 'touched': [], 'refused': [], 'ratings': [  # noqa: E731
            {'id': '0', 'state': 'rated', 'severity': 1, 'drop': False, 'note': 'n', 'zone': ''}, {'id': '1', 'state': 'rated', 'severity': 3, 'drop': True, 'note': 'n', 'zone': ''}]}
        with FakeScanner(kinds=['dangling_dns_check'], responders={'dangling_dns_check': extra}) as fake:
            got = dangling_dns.assess_all(self.findings, project=self.project)
        target = fake.served[0]['target']
        self.assertEqual([c['host'] for c in target['checks']], ['app.example.test'])  # the excluded host is never sent
        self.assertIn('old.example.test', target['scope']['excluded'])
        self.assertEqual((got[0].severity, got[1]), (1, None))

