"""The probe kinds of contract version 3 (``http_probe``, ``dns_resolve``): the scope policy the server computes for a task, the validation of what
a Sentinel reports, and each stage end to end through the fake built-in scanner, served, offline and failed."""
import json
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_dispatch, probe_results
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from agentapi.services import ApiError
from cveFeed import bucket_scan, changes, discovery, ledger, probe_scope, probes, subdir_apps, vhost_scan
from cveFeed.models import AssetChange, HostExclusion, HostState, HygieneFinding, ProbeObservation, RouteAuth, ServiceRun
from startScan.models import Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_bucket_scan import Fixture as BucketFixture
from tests.test_changes import ChangeFixture
from tests.test_subdir_apps import SubdirFixture
from tests.test_vhost_scan import VhostFixture
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
            out = self.run_sweep(fetch=None, pace=None)
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
            self.run_sweep(fetch=None, pace=None)
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
            self.run_sweep(fetch=None, pace=None)
        self.assertEqual(self.observations(), {('portal.example.test', 'found', 'distinct'), ('app.example.test', 'absent', 'default_site'),
                                               ('wiki.example.test', 'absent', 'same_app')})

    def test_a_name_the_scanner_did_not_report_stays_due(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': lambda task: self.answers(task, drop=('portal.example.test',))}):
            self.run_sweep(fetch=None, pace=None)
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
            self.run_sweep(fetch=None, pace=None)
        self.assertNotIn('other.example.test', {o[0] for o in self.observations()})
        self.assertFalse(Subdomain.objects.filter(name='other.example.test').exists())

    def test_a_challenge_is_recorded_and_the_address_left_alone(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': lambda task: self.answers(task, state='challenged')}):
            out = self.run_sweep(fetch=None, pace=None)
        self.assertEqual(out['challenged'], 1)
        self.assertEqual({o[1] for o in self.observations()}, {'challenged'})
        self.assertTrue(ServiceRun.objects.filter(service=vhost_scan.IP_SERVICE, asset=self.ADDRESS).exists())

    def test_with_the_scanner_offline_the_addresses_stay_due(self):
        with FakeScanner(kinds=['vhost_probe'], mode='offline') as fake:
            out = self.run_sweep(fetch=None, pace=None)
        self.assertEqual(fake.served, [])
        self.assertEqual(self.guard.calls, [])
        self.assertIn('waiting for a scanner', out['skipped'])
        self.assertEqual(out['ips'], 0)
        self.assertFalse(ServiceRun.objects.filter(service__in=(vhost_scan.SERVICE, vhost_scan.IP_SERVICE)).exists())
        self.assertFalse(ProbeObservation.objects.filter(probe=vhost_scan.PROBE).exists())

    def test_a_failed_task_with_the_kind_off_the_fallback_list_records_nothing(self):
        with FakeScanner(kinds=['vhost_probe'], mode='fail'):
            out = self.run_sweep(fetch=None, pace=None)
        self.assertEqual(out['ips'], 0)
        self.assertFalse(ServiceRun.objects.filter(service__in=(vhost_scan.SERVICE, vhost_scan.IP_SERVICE)).exists())

    def test_an_address_the_server_would_not_ask_is_never_sent(self):
        with FakeScanner(kinds=['vhost_probe'], responders={'vhost_probe': self.answers}) as fake:
            self.run_sweep(fetch=None, pace=None, vet_ip=lambda ip: False)
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
            baseline = vhost_scan.fingerprint_of(self.site(base + subdir_apps.BASELINE_PATH))
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
