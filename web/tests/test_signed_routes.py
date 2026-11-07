"""The signed-in web route check runs on the built-in scanner only (kind ``route_probe_signed``, contract version 3): the pass hands the scanner a
reference to the stored sign-in and the routes it covers, never a value; an external Sentinel is never offered it; with no scanner able to take it the
pass waits and the routes stay due; nothing runs on this server whatever ``CVENGINE_LOCAL_FALLBACK`` says."""
import json
from unittest import mock

from django.utils import timezone
from jsonschema import Draft202012Validator

from agentapi import scanner_state, sentinel_broker, sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import auth_routes, probe_scope, route_auth as ra
from cveFeed.models import AgentActivity, RouteAuth, ServiceRun
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_authcheck import COOKIE, COOKIE_VALUE, SECRET, TOKEN, Fixture, everything_stored

KIND = 'route_probe_signed'
CANARY = 'canary-sign-in-7c41d9e2b8'


class SignedRouteStageBase(Fixture):
    def setUp(self):
        mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False).start()
        mock.patch('reNgine.tasks.geo_localize.delay').start()
        self.addCleanup(mock.patch.stopall)
        LocalFallback('none').apply(self)
        self.guard = assert_ran_nowhere_locally(self, KIND)
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, tasks=[], results_dir='x')
        sub = Subdomain.objects.create(name='app.example.test', target_domain=self.domain, scan_history=self.scan)
        ip, _ = IpAddress.objects.get_or_create(address='203.0.113.10')
        sub.ip_addresses.add(ip)
        ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
        # the anonymous check ran first (a Sentinel's, ``route_probe``): every route answered with a redirect to the login page; then a sign-in was stored
        for path in ra.COMMON_PATHS:
            RouteAuth.objects.create(project=self.project, domain=self.domain, host='app.example.test', path=path, url=f'https://app.example.test{path}',
                                     auth_state='session_required', http_status=302, redirect_to='/login', checked_at=timezone.now())
        self.cred = self.make(host='app.example.test')

    def answer(self, task):
        """The built-in scanner's answer: a dashboard for every route the task names, echoing the session the way a careless page might."""
        rows = []
        for group in task['target']['hosts']:
            for url in group['urls']:
                rows.append({'id': url, 'status': 200, 'title': f'Dashboard {TOKEN}', 'content_type': 'text/html', 'state': 'open',
                             'evidence': {'markers': [], 'bytes': 10, 'provider': '', 'redirect_to': ''}, 'sensitive': {'email': {'count': 3, 'sample': 'a***@x'}},
                             'sensitive_score': 9, 'bytes': 10, 'credentials': [{'type': 'jwt', 'value': 'eyJ-must-not-be-kept'}]})
        return {**fixture(KIND), 'routes': rows, 'touched': ['app.example.test']}


class DispatchTests(SignedRouteStageBase):
    def test_the_pass_is_one_signed_task_with_a_reference_and_the_answers_are_stored(self):
        with FakeScanner(kinds=[KIND], responders={KIND: self.answer}) as fake:
            out = auth_routes.run_signed_in(self.scan.id)
        self.assertEqual(fake.served_kinds(), [KIND])
        task = SentinelTask.objects.get(kind=KIND)
        self.assertEqual(task.secret_ref, sentinel_broker.secret_ref_for(self.cred.pk))
        Draft202012Validator(sentinel_contract.target_schema(KIND)).validate(task.target)
        for plain in (SECRET, TOKEN, COOKIE, COOKIE_VALUE):
            self.assertNotIn(plain, json.dumps(task.target))
        self.assertEqual(task.target['scope']['hosts'], ['app.example.test'])  # no same-site host and no library CDN: no script is read signed in
        self.assertGreater(out['routes'], 0)
        row = RouteAuth.objects.get(url='https://app.example.test/')
        self.assertEqual(row.auth_state, 'session_required')  # the anonymous state stands
        signed = row.evidence['authenticated']
        self.assertEqual((signed['state'], signed['seen_while_authenticated']), ('open', True))
        self.assertIn('[redacted]', signed['title'])
        self.assertTrue(ServiceRun.objects.filter(service=auth_routes.SERVICE).exists())
        self.assertNotIn('eyJ-must-not-be-kept', everything_stored())  # a signed-in page yields no credential and no sensitive data, whatever a scanner says
        self.assertEqual(row.sensitive, {})
        for plain in (SECRET, TOKEN, COOKIE_VALUE):
            self.assertNotIn(plain, everything_stored())

    def test_with_the_scanner_offline_the_pass_waits_and_the_routes_stay_due(self):
        with FakeScanner(kinds=[KIND], responders={KIND: self.answer}, mode='offline') as fake:
            out = auth_routes.run_signed_in(self.scan.id)
            self.assertIn('no scanner could take this work (route_probe_signed)', out['skipped'])
            self.assertEqual(fake.tasks().count(), 0)
            self.assertFalse(ServiceRun.objects.filter(service=auth_routes.SERVICE).exists())
            self.assertFalse(RouteAuth.objects.filter(evidence__has_key='authenticated').exists())
            self.assertTrue(AgentActivity.objects.filter(message__contains='is waiting').exists())
            fake.go_online()
            self.assertGreater(auth_routes.run_signed_in(self.scan.id)['routes'], 0)  # the scanner is back: the same routes are asked

    def test_a_scanner_failure_is_unknown_never_a_state_and_the_routes_stay_due(self):
        with FakeScanner(kinds=[KIND], mode='fail') as fake:
            out = auth_routes.run_signed_in(self.scan.id)
        self.assertEqual(fake.served_kinds(), [KIND])
        self.assertFalse(RouteAuth.objects.filter(evidence__has_key='authenticated').exists())
        self.assertFalse(ServiceRun.objects.filter(service=auth_routes.SERVICE, status='done').exists())
        self.assertNotIn('routes', {k for k, v in out.items() if v and k == 'routes'})

    def test_a_builtin_image_that_cannot_read_sign_ins_is_not_offered_the_task(self):
        with FakeScanner(kinds=[KIND], responders={KIND: self.answer}) as fake:
            Agent.objects.filter(pk=fake.agent.pk).update(info={'contract_version': 3, 'builtin': True})
            fake.agent.refresh_from_db()
            fake._forget_scanner_state()
            out = auth_routes.run_signed_in(self.scan.id)
        self.assertIn('no scanner could take this work', out['skipped'])
        self.assertFalse(SentinelTask.objects.filter(kind=KIND).exists())

    def test_the_kind_has_no_local_path_whatever_the_fallback_says(self):
        self.assertIn(KIND, dispatch.NEVER_LOCAL)
        with mock.patch.dict('os.environ', {dispatch.LOCAL_FALLBACK_ENV: 'all'}):
            self.assertNotIn(KIND, dispatch.local_fallback_kinds())
            self.assertFalse(dispatch.fallback_allowed(KIND))
        self.guard.assert_clean()


class GateTests(SignedRouteStageBase):
    def external(self):
        token, _raw = create_token(self.users['orgadmin'], 'ext-token-sr')
        return Agent.objects.create(token=token, name='remote', kind='scanner', status='active', scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    capabilities=[KIND, 'route_probe'], last_seen=timezone.now(), info={'contract_version': 3, 'features': ['secret_read']})

    def test_an_external_sentinel_is_never_offered_the_kind_even_when_it_declares_it(self):
        agent = self.external()
        self.assertTrue(dispatch.any_scanner_for(self.project, 'route_probe'))
        self.assertFalse(dispatch.any_scanner_for(self.project, KIND))
        self.assertEqual(sentinel_broker.capacity_state(self.project, KIND, builtin_only=True, secret=True)['state'], 'none')
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind=KIND, host='app.example.test', target={'hosts': [], 'scope': {}},
                                           secret_ref=sentinel_broker.secret_ref_for(self.cred.pk))
        task = SentinelTask.objects.select_related('project').get(pk=task.pk)
        self.assertEqual(sentinel_broker.effective(agent).refusal(task), ('capability', sentinel_broker.BUILTIN))
        self.assertEqual(sentinel_broker.queued_for(agent), {})

    def test_the_stage_waits_with_only_an_external_sentinel(self):
        self.external()
        out = auth_routes.run_signed_in(self.scan.id)
        self.assertIn('no scanner could take this work (route_probe_signed)', out['skipped'])
        self.assertFalse(SentinelTask.objects.filter(kind=KIND).exists())

    def test_the_waiting_state_names_the_kind_without_a_builtin_scanner(self):
        self.external()
        offered = scanner_state.state()
        self.assertTrue(offered.get('offline'))
        self.assertIn(KIND, offered['kinds'])


class ResultTests(SignedRouteStageBase):
    def test_a_signed_in_result_is_cut_to_what_the_contract_allows(self):
        bad = {**fixture(KIND)}
        bad['routes'] = [{**bad['routes'][0], 'sensitive': {'email': {'count': 1, 'sample': 'a***@b'}}, 'sensitive_score': 5,
                          'credentials': [{'type': 'jwt', 'value': 'eyJ-secret'}]}]
        got = sentinel_broker.clean_result(KIND, bad)
        self.assertEqual((got['routes'][0]['sensitive'], got['routes'][0]['sensitive_score'], got['routes'][0]['credentials']), ({}, 0, []))
        self.assertEqual(sentinel_broker.clean_result(KIND, fixture(KIND)), fixture(KIND))

    def test_a_route_the_task_did_not_ask_is_dropped(self):
        task = SentinelTask(kind=KIND, host='', ips=[], target={'hosts': [{'host': 'app.example.test', 'urls': ['https://app.example.test/']}]})
        result = {**fixture(KIND), 'routes': [{**fixture(KIND)['routes'][0], 'id': 'https://elsewhere.example.test/'}]}
        got = sentinel_broker._bind_to_task(KIND, sentinel_broker.clean_result(KIND, result), task)
        self.assertEqual((got['routes'], got['dropped']), ([], 1))

    def test_the_scope_names_only_the_planned_hosts(self):
        scope = probe_scope.for_signed_routes(self.project.pk, ['App.example.test.', 'api.example.test'])
        self.assertEqual(scope['hosts'], ['api.example.test', 'app.example.test'])
        self.assertEqual(scope['domains'], [])
