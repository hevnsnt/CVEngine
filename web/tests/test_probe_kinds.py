"""The probe kinds of contract version 3 (``http_probe``, ``dns_resolve``): the scope policy the server computes for a task, the validation of what
a Sentinel reports, and each stage end to end through the fake built-in scanner, served, offline and failed."""
import datetime
import json
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase

from agentapi import probe_dispatch, probe_results
from agentapi import sentinel_broker as broker
from agentapi.models import SentinelTask
from agentapi.services import ApiError
from cveFeed import bucket_scan, changes, dangling_dns, discovery, ledger, probe_scope, probes
from cveFeed import hygiene as hy
from cveFeed.models import AssetChange, HostExclusion, HostState, HygieneFinding, ProbeObservation, ServiceRun, TlsCertificate
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_bucket_scan import Fixture as BucketFixture
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

    def test_with_no_scanner_for_the_kind_and_the_fallback_allowed_it_runs_here_as_before(self):
        LocalFallback('all').apply(self)
        guard = mock.patch('cveFeed.hygiene._resolver', side_effect=RuntimeError('local DNS')).start()
        out = hy.run_hygiene(self.domain.id, probe=lambda host, port: None, emailer=lambda name: ([], False), mx=lambda n, t: False)
        self.assertEqual(out['tls_hosts'], 0)  # injected helpers keep the sweep here whatever scanners exist
        guard.assert_not_called()


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

    def test_without_a_project_or_a_scanner_the_findings_are_assessed_here_as_before(self):
        LocalFallback('all').apply(self)
        with mock.patch.object(dangling_dns, 'assess', side_effect=lambda f, net=None: dangling_dns.Rating(note=f['host'])) as local:
            got = dangling_dns.assess_all(self.findings, project=self.project)
        self.assertEqual([r.note if r else None for r in got], ['app.example.test', 'old.example.test', None])
        self.assertEqual(local.call_count, 2)
