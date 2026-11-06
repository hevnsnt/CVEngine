"""The probe kinds of contract version 3 (``http_probe``, ``dns_resolve``): the scope policy the server computes for a task, the validation of what
a Sentinel reports, and each stage end to end through the fake built-in scanner, served, offline and failed."""
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
from cveFeed import bucket_scan, changes, discovery, ledger, probe_scope, probes, route_auth
from cveFeed.models import AgentActivity, AssetChange, HostExclusion, HostState, HygieneFinding, ProbeObservation, RouteAuth, SecretFinding, ServiceRun
from startScan.models import Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_bucket_scan import Fixture as BucketFixture
from tests.test_route_auth import RouteFixture
from tests.test_route_auth import RouteFixture
from tests.test_changes import ChangeFixture
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

    def test_with_the_fallback_allowed_and_no_scanner_the_routes_are_asked_here_as_before(self):
        with mock.patch.dict(os.environ, {ENV: 'all'}):
            out = route_auth.run_route_auth(self.scan().id)
        self.assertGreaterEqual(self.local.call_count, len(route_auth.COMMON_PATHS))
        self.assertEqual(out['errors'], len(route_auth.COMMON_PATHS))
        self.assertFalse(SentinelTask.objects.exists())

    def test_an_injected_probe_is_asked_here_even_with_a_scanner(self):
        asked = []

        def local(url):
            asked.append(url)
            return {'url': url, 'status': 404, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html', 'body': '', 'title': ''}
        with FakeScanner(kinds=['route_probe']) as fake:
            route_auth.run_route_auth(self.scan().id, probe=local)
        self.assertEqual(fake.served, [])
        self.assertEqual(len([u for u in asked if '/cvengine-' not in u]), len(route_auth.COMMON_PATHS))


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
