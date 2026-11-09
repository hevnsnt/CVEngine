"""The streamed Sentinel kind (``bbot_discovery``, contract version 3): numbered partial batches held to the task's scope, stored once and in order,
consumed by the stage that dispatched the task, then a final result that closes it."""
import base64
import copy
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from jsonschema import Draft202012Validator

from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi import sentinel_dispatch
from agentapi import sentinel_stream as stream
from agentapi.models import Agent, SentinelPartial, SentinelTask
from agentapi.services import ApiError
from reNgine.resources import ScannerUnavailable
from tests.test_agentapi import call
from tests.test_sentinel_secret_read import SecretBase
from tests.test_sentinels import build_world, register_sentinel, reset_rates

FIXTURES = Path(__file__).with_name('fixtures')
PARTIAL = json.loads((FIXTURES / 'sentinel_partials' / 'bbot_discovery.json').read_text())
TARGET = json.loads((FIXTURES / 'sentinel_targets' / 'bbot_discovery.json').read_text())
RESULT = json.loads((FIXTURES / 'sentinel_results' / 'bbot_discovery.json').read_text())
CAPS = ['nmap', 'naabu', 'nuclei_light', 'bbot_discovery']


def task_with(target=None, **fields):
    return SentinelTask(kind='bbot_discovery', target=copy.deepcopy(target or TARGET), **fields)


class ContractTests(SimpleTestCase):
    def test_the_fixtures_are_in_contract_and_a_good_batch_goes_through_unchanged(self):
        self.assertEqual(contract.STREAMED, ('bbot_discovery',))
        self.assertEqual(list(Draft202012Validator(contract.partial_schema('bbot_discovery')).iter_errors(PARTIAL)), [])
        self.assertEqual(list(Draft202012Validator(contract.target_schema('bbot_discovery')).iter_errors(TARGET)), [])
        self.assertEqual(stream.clean_partial(task_with(), PARTIAL), PARTIAL)
        stored = broker.clean_result('bbot_discovery', RESULT)
        self.assertEqual(list(Draft202012Validator(contract.result_schema('bbot_discovery')).iter_errors(stored)), [])
        with self.assertRaises(KeyError):
            contract.partial_schema('nmap')

    def test_the_list_caps_equal_the_contracts(self):
        props = contract.load()['$defs']['partials']['bbot_discovery']['properties']
        self.assertEqual({k: props[k]['maxItems'] for k in stream.LIMITS}, stream.LIMITS)
        self.assertEqual(tuple(props['events']['items']['properties']['type']['enum']), stream.EVENT_TYPES)
        self.assertEqual(props['screenshots']['items']['properties']['data']['maxLength'], (stream.MAX_SCREENSHOT_BYTES + 2) // 3 * 4)

    def test_a_done_result_must_name_its_batches_and_mode(self):
        with self.assertRaises(ApiError):
            broker.clean_result('bbot_discovery', {'outcome': 'done', 'mode': 'standard'})
        with self.assertRaises(ApiError):
            broker.clean_result('bbot_discovery', {'outcome': 'done', 'partials': 1, 'mode': 'loud'})
        self.assertEqual(broker.clean_result('bbot_discovery', {'outcome': 'error', 'error': 'bbot exited 1'}), {'outcome': 'error', 'error': 'bbot exited 1'})


class ScopeTests(SimpleTestCase):
    """What a Sentinel reports is held to the scope its task carried, whatever the scanner did."""

    def clean(self, body, scope=None):
        target = copy.deepcopy(TARGET)
        if scope:
            target['scope'].update(scope)
        return stream.clean_partial(task_with(target), {'seq': 1, **body})

    def test_names_outside_the_target_excluded_or_in_a_denied_range_are_dropped(self):
        out = self.clean({'subdomains': ['www.example.com', 'example.org', 'evil-example.com', 'a.intranet.example.com', 'intranet.example.com',
                                         'old.example.com', 'x.old.example.com', '../etc', 'WWW.Example.com.'],
                          'ips': ['192.0.2.1', '10.20.3.4', '198.51.100.7', 'not-an-ip', '2001:0db8::5'],
                          'ports': [{'host': '10.20.0.9', 'port': 22}, {'host': 'www.example.com', 'port': 0}, {'host': 'example.net', 'port': 80},
                                    {'host': '192.0.2.1', 'port': 8443}],
                          'urls': [{'url': 'https://example.org/', 'status': 200}, {'url': 'ftp://www.example.com/', 'status': 0},
                                   {'url': 'https://user:pw@www.example.com/', 'status': 200}, {'url': 'https://www.example.com/a', 'status': 301}]})
        self.assertEqual(out['subdomains'], ['www.example.com', 'x.old.example.com'])
        self.assertEqual(out['ips'], ['192.0.2.1', '2001:db8::5'])
        self.assertEqual(out['ports'], [{'host': '192.0.2.1', 'port': 8443}])
        self.assertEqual(out['urls'], [{'url': 'https://www.example.com/a', 'status': 301}])

    def test_an_exact_host_keeps_only_itself(self):
        out = self.clean({'subdomains': ['example.com', 'www.example.com'], 'edges': [{'parent': 'example.com', 'child': 'www.example.com'}],
                          'events': [{'type': 'DNS_NAME', 'label': 'www.example.com', 'host': 'www.example.com', 'parent_host': 'example.com', 'module': 'crt'}]},
                         scope={'exact_host': True})
        self.assertEqual((out['subdomains'], out['edges'], out['events']), (['example.com'], [], []))

    def test_a_screenshot_must_be_the_image_it_says_of_a_host_in_scope(self):
        good = PARTIAL['screenshots'][0]
        bad = [{**good, 'host': 'example.org'}, {**good, 'filename': '../x.png'}, {**good, 'content_type': 'image/jpeg'},
               {**good, 'data': base64.b64encode(b'<svg onload=alert(1)>').decode()}, {**good, 'data': 'not base64!'}, {**good, 'content_type': 'image/svg+xml'}]
        self.assertEqual(self.clean({'screenshots': [good]})['screenshots'], [good])
        for shot in bad:
            self.assertEqual(self.clean({'screenshots': [shot]})['screenshots'], [], shot)

    def test_text_is_clipped_and_a_batch_over_its_caps_is_refused(self):
        out = self.clean({'findings': [{'name': 'x' * 900, 'informational': 'yes', 'severity': 9, 'host': '', 'url': '', 'description': 'd', 'module': 'm'}]})
        self.assertEqual(len(out['findings'][0]['name']), 200)
        self.assertEqual((out['findings'][0]['informational'], out['findings'][0]['severity']), (False, 0))
        with self.assertRaises(ApiError) as caught:
            self.clean({'subdomains': ['a.example.com'] * (stream.LIMITS['subdomains'] + 1)})
        self.assertEqual(caught.exception.status, 400)
        for seq in (0, -1, True, '1', None, stream.MAX_SEQ + 1):
            with self.assertRaises(ApiError):
                stream.clean_partial(task_with(), {'seq': seq})


class StreamBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        reset_rates(self.tokens)
        status, out = register_sentinel(self.tokens['alice'], capabilities=CAPS, info={'contract_version': 3})
        self.assertIn(status, (200, 201), out)
        self.agent = Agent.objects.get(pk=out['id'])
        self.target = copy.deepcopy(TARGET)
        self.target['domain'] = 'a.example'
        self.target['scope']['in_scope_domains'] = ['a.example']

    def running(self, kind='bbot_discovery', **fields):
        now = timezone.now()
        return SentinelTask.objects.create(project=self.pa, scan=self.scan, kind=kind, host='a.example', target=self.target, status='running',
                                           agent=self.agent, accepted_at=now, lease_expires_at=now + timedelta(minutes=5), **fields)

    def post(self, task, body):
        return call(self.tokens['alice'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/partial', body)

    def batch(self, seq, **lists):
        return {'seq': seq, 'subdomains': [f'h{seq}.a.example'], 'events': [], **lists}


class ReportPartialTests(StreamBase):
    def test_batches_are_taken_once_and_in_order_and_extend_the_lease(self):
        task = self.running()
        before = task.lease_expires_at
        status, out = self.post(task, self.batch(1))
        self.assertEqual((status, out), (200, {'accepted': True, 'duplicate': False, 'seq': 1}))
        status, out = self.post(task, self.batch(1))
        self.assertEqual((status, out), (200, {'accepted': False, 'duplicate': True, 'seq': 1}))
        status, out = self.post(task, self.batch(3))
        self.assertEqual(status, 400, out)
        status, out = self.post(task, self.batch(2))
        self.assertEqual((status, out['seq']), (200, 2))
        task.refresh_from_db()
        self.assertEqual(task.partial_seq, 2)
        self.assertGreater(task.lease_expires_at, before)
        self.assertEqual(list(SentinelPartial.objects.filter(task=task).values_list('seq', flat=True)), [1, 2])
        self.assertEqual(SentinelPartial.objects.get(task=task, seq=2).body['subdomains'], ['h2.a.example'])

    def test_the_final_result_comes_after_every_batch(self):
        task = self.running()
        self.post(task, self.batch(1))
        self.post(task, self.batch(2))
        status, out = call(self.tokens['alice'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {**RESULT, 'partials': 1})
        self.assertEqual(status, 400, out)
        task.refresh_from_db()
        self.assertEqual(task.status, 'failed')
        task = self.running()
        self.post(task, self.batch(1))
        self.post(task, self.batch(2))
        status, out = call(self.tokens['alice'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', RESULT)
        self.assertEqual(status, 200, out)
        task.refresh_from_db()
        self.assertEqual((task.status, task.result['partials'], task.result['mode']), ('done', 2, 'standard'))

    def test_a_task_that_is_not_the_sentinels_to_run_answers_stop(self):
        from tenancy import audit
        task = self.running()
        audit.record(None, 'sentinel.task.claim', 'task', org=self.org1.pk, task_id=task.pk, agent_id=self.agent.pk)
        broker.expire(task, 'cancelled by a person')
        status, out = self.post(task, self.batch(1))
        self.assertEqual(status, 409, out)
        self.assertIn('cancelled by a person', out['error'])
        other = self.running(kind='nmap')
        status, out = self.post(other, self.batch(1))
        self.assertEqual(status, 400, out)
        status, _ = call(self.tokens['dana'], 'POST', f'/api/v1/sentinel/tasks/{self.running().pk}/partial', self.batch(1))
        self.assertIn(status, (403, 404))

    def test_a_stopped_scan_ends_the_task_at_its_next_batch(self):
        task = self.running()
        with mock.patch('cveFeed.discovery.stopped', return_value=True):
            status, out = self.post(task, self.batch(1))
        self.assertEqual(status, 409, out)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')
        self.assertFalse(SentinelPartial.objects.filter(task=task).exists())

    def test_a_backlog_is_answered_429_and_a_malformed_batch_fails_the_task(self):
        task = self.running()
        with mock.patch.object(stream, 'MAX_PENDING', 1):
            self.assertEqual(self.post(task, self.batch(1))[0], 200)
            self.assertEqual(self.post(task, self.batch(2))[0], 429)
        status, _ = self.post(task, {'seq': 2, 'subdomains': ['x.a.example'] * (stream.LIMITS['subdomains'] + 1)})
        self.assertEqual(status, 400)
        task.refresh_from_db()
        self.assertEqual(task.status, 'failed')


class DispatchStreamTests(StreamBase):
    """The stage side: batches are handed over in order and deleted once stored, then the final result."""

    def test_the_stage_consumes_every_batch_then_returns_the_result(self):
        seen = []
        steps = iter(range(10))

        def sentinel_works(_seconds):
            step = next(steps)
            task = SentinelTask.objects.filter(kind='bbot_discovery').latest('id')
            if step == 0:
                SentinelTask.objects.filter(pk=task.pk).update(status='running', agent=self.agent, accepted_at=timezone.now(),
                                                               lease_expires_at=timezone.now() + timedelta(minutes=5))
                SentinelPartial.objects.create(task=task, seq=2, body=self.batch(2))  # stored before 1 here only: the stage still takes them in order
                SentinelPartial.objects.create(task=task, seq=1, body=self.batch(1))
            elif step == 1:
                SentinelPartial.objects.create(task=task, seq=3, body=self.batch(3))
                SentinelTask.objects.filter(pk=task.pk).update(status='done', result={**RESULT, 'partials': 3}, partial_seq=3)
        with mock.patch.object(broker, 'capacity_state', return_value={'state': 'free', 'slots': 1}), \
                mock.patch.object(sentinel_dispatch.time, 'sleep', side_effect=sentinel_works):
            out = stream.dispatch_stream(self.pa, 'bbot_discovery', self.target, self.scan, lambda b: seen.append(b['seq']), label='a.example')
        self.assertEqual(seen, [1, 2, 3])
        self.assertEqual((out['consumed'], out['result']['partials']), (3, 3))
        self.assertFalse(SentinelPartial.objects.exists())

    def test_a_run_that_failed_after_batches_keeps_them_and_no_scanner_means_waiting(self):
        def fails(_seconds):
            task = SentinelTask.objects.filter(kind='bbot_discovery').latest('id')
            SentinelPartial.objects.create(task=task, seq=1, body=self.batch(1))
            SentinelTask.objects.filter(pk=task.pk).update(status='failed', error='bbot crashed', agent=self.agent)
        with mock.patch.object(broker, 'capacity_state', return_value={'state': 'free', 'slots': 1}), \
                mock.patch.object(sentinel_dispatch.time, 'sleep', side_effect=fails):
            out = stream.dispatch_stream(self.pa, 'bbot_discovery', self.target, self.scan, lambda b: None)
        self.assertEqual((out['result'], out['consumed'], out['error']), (None, 1, 'bbot crashed'))
        with mock.patch.object(broker, 'capacity_state', return_value={'state': 'none', 'message': 'no Sentinel', 'slots': 0}):
            with self.assertRaises(ScannerUnavailable):  # no local path: the stage waits for a scanner
                stream.dispatch_stream(self.pa, 'bbot_discovery', self.target, self.scan, lambda b: None)

    def test_a_task_that_names_the_projects_keys_is_kept_for_the_builtin_scanner(self):
        none = {'state': 'none', 'reason': 'none', 'message': 'no built-in scanner is live', 'slots': 0}
        with mock.patch.object(broker, 'capacity_state', return_value=none) as capacity, self.assertRaises(ScannerUnavailable):  # waits: no local path
            stream.dispatch_stream(self.pa, 'bbot_discovery', self.target, self.scan, lambda b: None, secret_ref=stream.keys_ref(self.pa.pk),
                                   builtin_only=True)
        self.assertEqual(capacity.call_count, 1)
        self.assertTrue(capacity.call_args.kwargs['builtin_only'])
        self.assertFalse(SentinelTask.objects.filter(kind='bbot_discovery').exists())  # nothing was queued for another Sentinel to see


class TargetTests(StreamBase):
    def test_the_target_is_what_the_mode_runs_and_its_scope(self):
        from cveFeed.models import HostExclusion, InternalRange
        HostExclusion.objects.create(org=self.org1, host='vpn.a.example', include_subdomains=True)
        HostExclusion.objects.create(org=self.org1, host='other.example', include_subdomains=False)
        InternalRange.objects.create(project=self.pa, cidr='10.9.0.0/16')
        target = stream.bbot_target(self.da, 'standard', 3600)
        self.assertEqual(list(Draft202012Validator(contract.target_schema('bbot_discovery')).iter_errors(target)), [])
        self.assertEqual((target['presets'], target['require_flags'], target['force']), (['subdomain-enum', 'web', 'web-screenshots'], ['safe'], True))
        self.assertEqual((target['exclude_modules'], target['api_keys'], target['timeout_seconds']), (['trufflehog'], False, 3600))
        self.assertEqual(target['scope']['exclusions'], [{'host': 'vpn.a.example', 'subtree': True}])
        self.assertEqual(target['scope']['deny_ranges'], ['10.9.0.0/16'])
        self.assertEqual(stream.bbot_target(self.da, 'passive', 3600)['require_flags'], ['passive'])
        self.assertEqual(stream.bbot_target(self.da, 'deep', 3600, trufflehog=True)['exclude_modules'], [])


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='bbot-stream-'))
class DiscoveryOnSentinelTests(StreamBase):
    """``run_discovery`` hands the run to a Sentinel and stores its batches; with none able to take it the target stays due."""

    def batch_for(self):
        body = json.loads(json.dumps(PARTIAL).replace('example.com', 'a.example'))
        return stream.clean_partial(task_with(self.target), body)

    def test_batches_land_in_the_inventory_the_feed_and_the_screenshots(self):
        from cveFeed import discovery
        from cveFeed.models import DiscoveryEvent
        from startScan.models import ScanHistory, Subdomain
        batch = self.batch_for()

        def fake(project, kind, target, scan, on_partial, **kwargs):
            self.assertEqual((kind, target['domain'], kwargs['secret_ref'], kwargs['bbot_keys']), ('bbot_discovery', 'a.example', None, False))
            on_partial(batch)
            return {'result': {**RESULT, 'partials': 1}, 'consumed': 1}
        with mock.patch.object(stream, 'dispatch_stream', side_effect=fake), \
                mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False):
            out = discovery.run_discovery(self.scan.pk, 'standard')
        self.assertEqual(out['status'], discovery.SUCCESS, out)
        names = set(Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True))
        self.assertLessEqual({'www.a.example', 'api.a.example'}, names)
        self.assertEqual(DiscoveryEvent.objects.filter(scan=self.scan).count(), 2)
        shot = Subdomain.objects.filter(scan_history=self.scan, name='www.a.example').exclude(screenshot_path=None).exclude(screenshot_path='').first().screenshot_path
        self.assertTrue(shot.endswith('sentinel-https-www.a.example-443.png'), shot)
        from django.conf import settings
        self.assertTrue(os.path.isfile(os.path.join(settings.MEDIA_ROOT, shot)))
        self.assertEqual(ScanHistory.objects.get(pk=self.scan.pk).scan_status, discovery.SUCCESS)

    def test_an_unfinished_run_keeps_what_it_found_and_no_scanner_leaves_the_target_due(self):
        from cveFeed import discovery
        from startScan.models import ScanActivity, Subdomain
        ScanActivity.objects.create(scan_of=self.scan, title='bbot', name='bbot_discovery', time=timezone.now(), status=1)

        def unfinished(project, kind, target, scan, on_partial, **kwargs):
            on_partial(self.batch_for())
            return {'result': None, 'consumed': 1, 'error': 'the lease expired without a report'}
        with mock.patch.object(stream, 'dispatch_stream', side_effect=unfinished), \
                mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False):
            out = discovery.run_discovery(self.scan.pk, 'standard')
        self.assertEqual((out['status'], out['partial']), (discovery.SUCCESS, 'the lease expired without a report'))
        self.assertEqual(ScanActivity.objects.get(scan_of=self.scan, name='bbot_discovery').status, discovery.FAILED)
        self.assertTrue(Subdomain.objects.filter(scan_history=self.scan, name='api.a.example').exists())

    def test_with_no_scanner_able_to_take_it_nothing_runs_and_the_scan_waits(self):
        from cveFeed import discovery
        from startScan.models import ScanHistory, Subdomain
        from tests.fake_scanner import LocalFallback, assert_ran_nowhere_locally
        none = {'state': 'none', 'reason': 'none', 'message': 'no Sentinel is live', 'slots': 0}
        before = Subdomain.objects.filter(scan_history=self.scan).count()
        for fallback in ('none', 'all', 'bbot_discovery'):  # the kind has no local path, whatever the variable says
            with self.subTest(fallback=fallback), LocalFallback(fallback), mock.patch.object(broker, 'capacity_state', return_value=none), \
                    mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False):
                assert_ran_nowhere_locally(self, 'bbot_discovery')
                out = discovery.run_discovery(self.scan.pk, 'standard')
            self.assertEqual(out['status'], discovery.FAILED)
            self.assertIn('waiting for a scanner', out['error'])
        self.assertEqual(ScanHistory.objects.get(pk=self.scan.pk).error_message[:23], 'waiting for a scanner: ')
        self.assertEqual(Subdomain.objects.filter(scan_history=self.scan).count(), before)  # nothing was stored

    def test_the_projects_keys_go_by_reference_and_the_gate_decides_who_gets_them(self):
        from cveFeed import discovery
        seen = {}

        def capture(project, kind, target, scan, on_partial, **kwargs):
            seen.update(target=target, **kwargs)
            return None
        with mock.patch.object(stream, 'dispatch_stream', side_effect=capture), \
                mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=['-c', 'modules.shodan_dns.api_key=KEY-123']), \
                mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False):
            discovery.run_discovery(self.scan.pk, 'standard')
        self.assertEqual((seen['secret_ref'], seen['bbot_keys'], seen.get('builtin_only', False), seen['target']['api_keys']), (f'bbotkeys:{self.pa.pk}', True, False, True))
        self.assertNotIn('KEY-123', json.dumps(seen['target']))


class KeysReadTests(SecretBase):
    """The built-in scanner reads a project's bbot module keys once, through the same secure read as a stored credential."""

    def setUp(self):
        super().setUp()
        for agent in (self.builtin, self.external):
            Agent.objects.filter(pk=agent.pk).update(capabilities=[*agent.capabilities, 'bbot_discovery'], info={**agent.info, 'contract_version': 3})
            agent.refresh_from_db()

    def test_the_builtin_scanner_reads_the_keys_once_and_nobody_else_does(self):
        task = self.task(kind='bbot_discovery', ref=stream.keys_ref(self.pa.pk))
        args = ['-c', 'modules.shodan_dns.api_key=KEY-123', '-c', 'modules.censys_dns.api_key=ID:SECRET']
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=args):
            status, out = self.read('external', task)
            self.assertEqual(status, 403, out)
            status, out = self.read('builtin', task)
            self.assertEqual(status, 200, out)
            self.assertEqual(out['bbot_config'], {'modules': {'shodan_dns': {'api_key': 'KEY-123'}, 'censys_dns': {'api_key': 'ID:SECRET'}}})
            self.assertEqual(self.read('builtin', task)[0], 409)
        self.assertNotIn('KEY-123', json.dumps(list(SentinelTask.objects.values('target', 'secret_ref', 'error')), default=str))

    def test_keys_of_another_project_are_refused(self):
        task = self.task(kind='bbot_discovery', ref=stream.keys_ref(self.pb.pk))
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=['-c', 'modules.shodan_dns.api_key=KEY-123']):
            status, out = self.read('builtin', task)
        self.assertEqual(status, 403, out)
