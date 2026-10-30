"""Sentinel hardening: the sentinel token scope, who may enroll, a Sentinel's ceiling, result binding, internal-only work, tenancy."""
import json
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import auth
from agentapi import sentinel_broker as sentinels
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelEnrollment, SentinelTask
from cveFeed.models import InternalRange
from dashboard.models import ApiToken, AuditLog, Org, OrgMembership, Project, ProjectMembership
from tests.test_agentapi import call, rpc
from tests.test_sentinels import SentinelBase, register_sentinel


def enroll(token, path='/api/v1/projects/sen-a/sentinels/enroll', body=None):
    status, out = call(token, 'POST', path)
    assert status == 201, out
    status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'enrolled',
                                                                       'capabilities': ['nmap', 'naabu', 'nuclei_light', 'wpscan'], **(body or {})})
    assert status == 201, boot
    return boot


class SentinelTokenScopeTests(SentinelBase):
    def test_bootstrap_mints_a_sentinel_scoped_token_that_expires(self):
        boot = enroll(self.t['root'], '/api/v1/sentinels/enroll')
        token = ApiToken.objects.get(agent__pk=boot['id'])
        self.assertEqual(token.scope, auth.SCOPE_SENTINEL)
        self.assertFalse(token.read_only)
        self.assertIsNotNone(token.expires_at)
        self.assertGreater(token.expires_at, timezone.now() + timedelta(days=30))

    def test_a_sentinel_token_cannot_reach_the_rest_of_its_enrollers_api(self):
        boot = enroll(self.t['root'], '/api/v1/sentinels/enroll')  # an App Admin's enrollment: the worst case
        raw = boot['token']
        for method, path in (('GET', '/api/v1/me'), ('GET', '/api/v1/projects'), ('GET', '/api/v1/projects/sen-a/targets'),
                             ('POST', '/api/v1/sentinels/enroll'), ('POST', '/api/v1/projects/sen-a/sentinels/enroll'),
                             ('PUT', '/api/v1/agent'), ('GET', '/api/v1/agents'), ('GET', '/api/v1/sentinels/live'),
                             ('POST', '/api/v1/agent/heartbeat'), ('GET', '/api/v1//sentinel'), ('GET', '/api/v1/sentinel-x')):
            status, out = call(raw, method, path)
            self.assertEqual(status, 403, (method, path, out))
        status, _ = rpc(raw, 'tools/list')
        self.assertEqual(status, 403)

    def test_a_sentinel_token_can_run_the_sentinel_loop(self):
        boot = enroll(self.t['dana'])
        raw = boot['token']
        self.assertEqual(call(raw, 'GET', '/api/v1/sentinel')[0], 200)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'name': 'renamed', 'max_concurrent': 2})[0], 200)
        self.assertEqual(call(raw, 'POST', '/api/v1/sentinel/heartbeat')[0], 200)
        status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual((status, out['task']), (200, None))
        self.assertEqual(call(raw, 'GET', '/api/v1/sentinel/tasks/1')[0], 404)  # allowed by the scope, no such task of its own

    def test_a_person_cannot_ask_for_a_sentinel_token(self):
        client = Client()
        client.force_login(self.dana)
        response = client.post('/api/v1/tokens', json.dumps({'name': 'x', 'scope': 'sentinel'}), content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ApiToken.objects.filter(user=self.dana, scope='sentinel').exists())

    def test_heartbeat_renews_a_token_that_is_close_to_expiry_and_dates_an_undated_one(self):
        boot = enroll(self.t['dana'])
        token = ApiToken.objects.get(agent__pk=boot['id'])
        ApiToken.objects.filter(pk=token.pk).update(expires_at=timezone.now() + timedelta(days=2))
        self.assertEqual(call(boot['token'], 'POST', '/api/v1/sentinel/heartbeat')[0], 200)
        token.refresh_from_db()
        self.assertGreater(token.expires_at, timezone.now() + timedelta(days=60))
        ApiToken.objects.filter(pk=token.pk).update(expires_at=None)  # a token minted before sentinel tokens expired
        from tests.test_sentinels import reset_rates
        reset_rates({'s': boot['token']})
        self.assertEqual(call(boot['token'], 'POST', '/api/v1/sentinel/heartbeat')[0], 200)
        token.refresh_from_db()
        self.assertIsNotNone(token.expires_at)

    def test_an_expired_sentinel_token_stops_working(self):
        boot = enroll(self.t['dana'])
        ApiToken.objects.filter(agent__pk=boot['id']).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(call(boot['token'], 'GET', '/api/v1/sentinel')[0], 401)


class EnrollmentNeedsAWriteTokenTests(SentinelBase):
    def test_a_read_only_token_cannot_generate_any_enrollment(self):
        ro_root = create_token(self.root, 'ro-root', read_only=True)[1]
        ro_dana = create_token(self.dana, 'ro-dana', read_only=True)[1]
        for token, paths in ((ro_root, ('/api/v1/sentinels/enroll', '/api/v1/orgs/one/sentinels/enroll', '/api/v1/projects/sen-a/sentinels/enroll')),
                             (ro_dana, ('/api/v1/orgs/one/sentinels/enroll', '/api/v1/projects/sen-a/sentinels/enroll'))):
            for path in paths:
                for suffix in ('', '?format=blob'):
                    status, out = call(token, 'GET', path + suffix)
                    self.assertEqual(status, 403, (path, suffix, out))
        self.assertFalse(SentinelEnrollment.objects.exists())

    def test_a_write_token_still_can(self):
        for path in ('/api/v1/sentinels/enroll', '/api/v1/orgs/one/sentinels/enroll', '/api/v1/projects/sen-a/sentinels/enroll'):
            self.assertEqual(call(self.t['root'], 'GET', path)[0], 201, path)

    def test_the_mcp_tool_refuses_a_read_only_token_too(self):
        from tests.test_agentapi import tool_call
        ro_root = create_token(self.root, 'ro-root', read_only=True)[1]
        status, _ = rpc(ro_root, 'tools/call', {'name': 'generate_sentinel_enrollment', 'arguments': {}})
        self.assertEqual(status, 200)
        error, _ = tool_call(ro_root, 'generate_sentinel_enrollment', {})
        self.assertTrue(error)
        self.assertFalse(SentinelEnrollment.objects.exists())


class BootstrapValidationTests(SentinelBase):
    def test_a_bad_body_does_not_burn_the_single_use_secret(self):
        _, out = call(self.t['dana'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        raw = out['enrollment_token']
        for bad in ({'max_concurrent': 16}, {'settings': {'max_concurrent': 16}}, {'capabilities': 'nmap'}, {'name': 7}, {'tools': 'x'}):
            status, _ = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': raw, **bad})
            self.assertEqual(status, 400, bad)
        self.assertFalse(SentinelEnrollment.objects.get(prefix=raw[:10]).used_at)
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': raw, 'name': 'ok', 'max_concurrent': 10})
        self.assertEqual(status, 201, boot)
        self.assertEqual(call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': raw, 'name': 'again'})[0], 403)

    def test_a_failure_after_the_secret_is_consumed_gives_it_back(self):
        _, out = call(self.t['dana'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        from unittest import mock
        with mock.patch.object(sentinels, 'create_token', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                sentinels.bootstrap({'enrollment_token': out['enrollment_token'], 'name': 'x'})
        self.assertIsNone(SentinelEnrollment.objects.get(prefix=out['enrollment_token'][:10]).used_at)


class SentinelCeilingTests(SentinelBase):
    def test_a_project_enrolled_sentinel_cannot_widen_its_scope(self):
        boot = enroll(self.t['root'])  # a superuser enrolled it for sen-a only
        raw = boot['token']
        for scope in ({'instance': True}, {'orgs': ['two']}, {'orgs': ['one']}, {'projects': ['sen-a', 'sen-b']}, {'projects': ['sen-b']}):
            status, out = call(raw, 'PUT', '/api/v1/sentinel', {'scope': scope})
            self.assertEqual(status, 403, (scope, out))
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.scope['projects'], ['sen-a'])
        self.assertFalse(agent.scope['instance'])
        # narrowing by host, restating its own scope, and leaving scope out all stay allowed
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'projects': ['sen-a'], 'hosts': ['192.0.2.0/24']}})[0], 200)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'projects': ['sen-a'], 'hosts': []}})[0], 200)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'name': 'x'})[0], 200)

    def test_an_org_enrolled_sentinel_may_narrow_to_a_project_of_that_org_only(self):
        boot = enroll(self.t['root'], '/api/v1/orgs/one/sentinels/enroll')
        raw = boot['token']
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'projects': ['sen-a']}})[0], 200)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'projects': ['sen-b']}})[0], 403)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'orgs': ['two']}})[0], 403)
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'instance': True}})[0], 403)
        # after narrowing, widening back to the whole organization is still inside what the enrollment granted
        self.assertEqual(call(raw, 'PUT', '/api/v1/sentinel', {'scope': {'orgs': ['one']}})[0], 200)

    def test_a_person_registering_their_own_token_is_unchanged(self):
        status, out = register_sentinel(self.t['root'], name='mine', scope={'projects': ['sen-a', 'sen-b']})
        self.assertEqual(status, 201, out)
        self.assertEqual(call(self.t['root'], 'PUT', '/api/v1/sentinel', {'scope': {'instance': True}})[0], 200)


class ResultBindingTests(SimpleTestCase):
    def _task(self, kind, target, ips=None):
        return SentinelTask(kind=kind, target=target, ips=ips if ips is not None else target.get('addresses') or [])

    def test_nmap_hosts_outside_the_dispatched_addresses_are_dropped(self):
        task = self._task('nmap', {'addresses': ['192.0.2.50', '2001:db8::5']})
        body = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'ports': [{'number': 22}]}, {'ip': '192.0.2.99', 'ports': [{'number': 23}]},
                                              {'ip': '<script>alert(1)</script>', 'ports': []}, {'ip': '2001:0db8:0:0:0:0:0:5', 'ports': [{'number': 80}]},
                                              {'ip': '192.0.2.50 ', 'ports': []}]}
        clean = sentinels.clean_result('nmap', body, task)
        self.assertEqual([h['ip'] for h in clean['hosts']], ['192.0.2.50', '2001:db8::5', '192.0.2.50'])
        self.assertEqual(clean['dropped'], 1)  # the one valid address nobody asked about; the free text never gets that far

    def test_nmap_os_reliability_survives_sanitization_and_task_binding(self):
        task = self._task('nmap', {'addresses': ['192.0.2.50']})
        body = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': 'Linux', 'ports': []}],
                'os_reliable': False}
        self.assertIs(sentinels.clean_result('nmap', body, task)['os_reliable'], False)
        self.assertIs(sentinels.clean_result('nmap', {**body, 'os_reliable': True}, task)['os_reliable'], True)
        self.assertIs(sentinels.clean_result('nmap', {**body, 'os_reliable': 'false'}, task)['os_reliable'], True)

    def test_naabu_keys_must_be_dispatched_addresses(self):
        task = self._task('naabu', {'addresses': ['192.0.2.50']})
        clean = sentinels.clean_result('naabu', {'outcome': 'done', 'ports': {'192.0.2.50': [22, 80], 'not an ip': [1], '192.0.2.77': [3389]}}, task)
        self.assertEqual(clean['ports'], {'192.0.2.50': [22, 80]})
        self.assertEqual(clean['dropped'], 1)

    def test_addresses_must_be_ip_literals_even_without_a_task(self):
        clean = sentinels.clean_result('nmap', {'outcome': 'done', 'hosts': [{'ip': 'x' * 40, 'ports': []}, {'ip': '192.0.2.1', 'ports': []}]})
        self.assertEqual([h['ip'] for h in clean['hosts']], ['192.0.2.1'])
        clean = sentinels.clean_result('naabu', {'outcome': 'done', 'ports': {'evil<b>': [22], '192.0.2.1': [22]}})
        self.assertEqual(list(clean['ports']), ['192.0.2.1'])

    def test_a_task_that_named_no_addresses_accepts_none(self):
        clean = sentinels.clean_result('nmap', {'outcome': 'done', 'hosts': [{'ip': '192.0.2.1', 'ports': []}]}, self._task('nmap', {}, []))
        self.assertEqual(clean['hosts'], [])

    def test_nuclei_findings_must_be_on_a_dispatched_target(self):
        task = self._task('nuclei_light', {'targets': ['www.a.example', '192.0.2.50:8443', 'b.example']}, [])
        findings = [{'template_id': 't1', 'host': 'www.a.example', 'matched_at': 'https://www.a.example/x'},
                    {'template_id': 't2', 'host': '192.0.2.50:8443', 'matched_at': 'https://192.0.2.50:8443/'},
                    {'template_id': 't3', 'host': 'WWW.A.EXAMPLE:443', 'matched_at': ''},
                    {'template_id': 't4', 'host': 'https://b.example/', 'matched_at': ''},
                    {'template_id': 'bad1', 'host': 'other.example', 'matched_at': 'https://www.a.example/'},
                    {'template_id': 'bad2', 'host': '', 'matched_at': 'https://elsewhere.example/'},
                    {'template_id': 'bad3', 'host': '', 'matched_at': ''}]
        clean = sentinels.clean_result('nuclei_light', {'outcome': 'done', 'findings': findings}, task)
        self.assertEqual([f['template_id'] for f in clean['findings']], ['t1', 't2', 't3', 't4'])
        self.assertEqual(clean['dropped'], 3)

    def test_without_a_task_nothing_is_filtered_and_nothing_is_added(self):
        clean = sentinels.clean_result('nuclei_light', {'outcome': 'done', 'findings': [{'template_id': 't', 'host': 'x.example'}]})
        self.assertEqual(len(clean['findings']), 1)
        self.assertNotIn('dropped', clean)


class ResultBindingOverHttpTests(SentinelBase):
    def test_an_out_of_scope_host_is_never_stored(self):
        _, agent = register_sentinel(self.t['dana'], name='binder')
        task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example',
                                           ips=['192.0.2.50'])
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        status, out = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result',
                           {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'ports': []}, {'ip': '198.51.100.9', 'ports': [{'number': 22}]}]})
        self.assertEqual(status, 200, out)
        task.refresh_from_db()
        self.assertEqual([h['ip'] for h in task.result['hosts']], ['192.0.2.50'])


class InternalOnlyClaimTests(SentinelBase):
    def setUp(self):
        super().setUp()
        InternalRange.objects.create(project=self.pa, cidr='10.0.0.0/24')
        self.external = register_sentinel(self.t['dana'], name='outside', capabilities=['nmap', 'nuclei_light', 'wpscan'])[1]
        self.inside_token = create_token(self.dana, 'inside')[1]
        self.inside = register_sentinel(self.inside_token, name='inside', capabilities=['nmap', 'nuclei_light', 'wpscan', 'network:internal'])[1]
        Agent.objects.filter(pk=self.inside['id']).update(network='internal')  # granted by the server, not by what the Sentinel declares

    def _nuclei(self, targets):
        return SentinelTask.objects.create(project=self.pa, kind='nuclei_light', target={'targets': targets, 'tags': [], 'severities': []}, ips=[])

    def test_an_internal_nuclei_task_is_claimed_only_by_an_internal_sentinel(self):
        task = self._nuclei(['10.0.0.5', '10.0.0.6:8080'])
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNone(out['task'])  # the Sentinel outside the network cannot reach it and would report "clean"
        status, out = call(self.inside_token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], task.pk)

    def test_an_external_nuclei_task_is_still_claimed_by_an_external_sentinel(self):
        task = self._nuclei(['www.a.example', '192.0.2.50'])
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], task.pk)

    def test_an_internal_wpscan_task_with_only_a_url_needs_the_internal_capability(self):
        task = SentinelTask.objects.create(project=self.pa, kind='wpscan', target={'url': 'http://10.0.0.7/blog/', 'token': 't'}, ips=[])
        self.assertIsNone(call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task'])
        self.assertEqual(call(self.inside_token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task']['id'], task.pk)

    def test_refusal_says_why(self):
        eff = sentinels.effective(Agent.objects.get(pk=self.external['id']))
        self.assertEqual(eff.refusal(self._nuclei(['10.0.0.5'])), ('capability', sentinels.INTERNAL_CAPABILITY))


class HostScopeNarrowingTests(SentinelBase):
    def _sentinel(self, hosts):
        status, out = register_sentinel(self.t['dana'], name='narrow', capabilities=['nuclei_light', 'wpscan'], scope={'projects': ['sen-a'], 'hosts': hosts})
        self.assertEqual(status, 201, out)

    def test_a_nuclei_task_outside_the_declared_hosts_is_not_claimable(self):
        self._sentinel(['192.0.2.0/24'])
        SentinelTask.objects.create(project=self.pa, kind='nuclei_light', target={'targets': ['198.51.100.5']}, ips=[])
        self.assertIsNone(call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task'])
        inside = SentinelTask.objects.create(project=self.pa, kind='nuclei_light', target={'targets': ['198.51.100.5', '192.0.2.8']}, ips=[])
        self.assertEqual(call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task']['id'], inside.pk)

    def test_a_wpscan_task_is_matched_by_the_host_of_its_url(self):
        self._sentinel(['a.example'])
        SentinelTask.objects.create(project=self.pa, kind='wpscan', target={'url': 'https://www.other.example/'}, ips=[])
        self.assertIsNone(call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task'])
        mine = SentinelTask.objects.create(project=self.pa, kind='wpscan', target={'url': 'https://www.a.example/blog'}, ips=[])
        self.assertEqual(call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task']['id'], mine.pk)


class WpscanTokenScrubTests(SentinelBase):
    def _task(self, status='queued', **extra):
        return SentinelTask.objects.create(project=self.pa, kind='wpscan', target={'url': 'https://www.a.example/', 'token': 'secret-token'},
                                           ips=['192.0.2.50'], status=status, **extra)

    def test_every_way_a_task_ends_without_its_dispatcher_removes_the_token(self):
        for how in ('expire', 'cancel', 'reap'):
            task = self._task('running', lease_expires_at=timezone.now() + timedelta(minutes=5))
            if how == 'expire':
                sentinels.expire(task)
            elif how == 'cancel':
                SentinelTask.objects.filter(pk=task.pk).update(status='running')
                sentinels.cancel_task(type('C', (), {'user': self.root, 'token': None})(), 'sen-a', task.pk)
            else:
                SentinelTask.objects.filter(pk=task.pk).update(lease_expires_at=timezone.now() - timedelta(seconds=5))
                sentinels.reap_expired()
            task.refresh_from_db()
            self.assertNotIn('secret-token', json.dumps(task.target), how)
            self.assertEqual(task.target['url'], 'https://www.a.example/')

    def test_a_reported_result_removes_it_too(self):
        _, agent = register_sentinel(self.t['dana'], name='wp', capabilities=['wpscan'])
        task = self._task()
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        status, _ = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'report': None, 'returncode': 1})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertNotIn('secret-token', json.dumps(task.target))

    def test_a_task_that_is_still_waiting_keeps_it_for_the_sentinel_that_will_need_it(self):
        task = self._task()
        task.refresh_from_db()
        self.assertEqual(task.target['token'], 'secret-token')


class SentinelTenancyTests(SentinelBase):
    """A user in two organizations enrolls a Sentinel that works for both; an admin of only one of them must not see the other's work."""

    def setUp(self):
        super().setUp()
        self.msp = User.objects.create_user('s_msp', password='x')
        OrgMembership.objects.create(user=self.msp, org=self.org1, role='admin')
        OrgMembership.objects.create(user=self.msp, org=self.org2, role='admin')
        self.msp_token = create_token(self.msp, 'msp')[1]
        _, self.agent = register_sentinel(self.msp_token, name='msp-sentinel', scope={'orgs': ['one', 'two']})
        agent = Agent.objects.get(pk=self.agent['id'])
        now = timezone.now()
        self.mine = SentinelTask.objects.create(project=self.pa, kind='nmap', host='visible.a.example', target={}, status='done', agent=agent, finished_at=now,
                                                result={'hosts': []})
        self.theirs = SentinelTask.objects.create(project=self.pb, kind='nmap', host='secret.b.example', target={}, status='done', agent=agent,
                                                  finished_at=now, result={'hosts': [{'ip': '203.0.113.7', 'ports': []}]})
        SentinelTask.objects.create(project=self.pb, kind='nmap', host='queued.b.example', target={}, status='queued')

    def test_sentinel_task_is_a_scoped_model(self):
        from tenancy.scope import SCOPES
        self.assertEqual(SCOPES.get('agentapi.SentinelTask'), 'project_id')

    def test_agent_detail_leaves_another_tenants_tasks_out(self):
        status, out = call(self.t['dana'], 'GET', f'/api/v1/agents/{self.agent["id"]}')
        self.assertEqual(status, 200, out)
        text = json.dumps(out)
        self.assertIn('visible.a.example', text)
        self.assertNotIn('secret.b.example', text)
        self.assertNotIn('203.0.113.7', text)
        self.assertNotIn('sen-b', text)
        self.assertEqual([t['id'] for t in out['recent_tasks']], [self.mine.pk])

    def test_recent_tasks_filters_by_the_viewer_even_with_no_request_scope(self):
        agent = Agent.objects.get(pk=self.agent['id'])
        self.assertEqual({t['id'] for t in sentinels.recent_tasks(agent)}, {self.mine.pk, self.theirs.pk})
        self.assertEqual({t['id'] for t in sentinels.recent_tasks(agent, self.dana)}, {self.mine.pk})
        self.assertEqual({t['id'] for t in sentinels.recent_tasks(agent, self.root)}, {self.mine.pk, self.theirs.pk})

    def test_the_sentinels_page_leaves_another_tenants_tasks_and_counts_out(self):
        status, out = call(self.t['dana'], 'GET', '/api/v1/sentinels/live')
        self.assertEqual(status, 200, out)
        text = json.dumps(out)
        self.assertNotIn('secret.b.example', text)
        self.assertNotIn('queued.b.example', text)
        self.assertEqual(out['queued'], 0)
        status, out = call(self.t['root'], 'GET', '/api/v1/sentinels/live')
        self.assertEqual(out['queued'], 1)
        self.assertIn('secret.b.example', json.dumps(out))


class ExistingSentinelTokensMigrationTests(SentinelBase):
    def test_a_sentinel_enrolled_before_sentinel_tokens_existed_is_narrowed_and_tied_to_its_enrollment(self):
        import importlib

        from django.apps import apps
        migration = importlib.import_module('agentapi.migrations.0006_sentinel_enrollment_token')
        token = create_token(self.dana, 'sentinel:old')[0]  # a full token, as bootstrap used to mint
        agent = Agent.objects.create(token=token, name='old', kind='scanner', scope={'projects': ['sen-a']}, status='active')
        enrollment = SentinelEnrollment.objects.create(token_hash='h' * 64, prefix='senr_old', project=self.pa, created_by=self.dana,
                                                       expires_at=timezone.now(), used_at=timezone.now(), used_by_agent=agent)
        mine = create_token(self.dana, 'my own token')[0]  # not a Sentinel's: left alone
        migration.tie_existing_sentinels(apps, None)
        token.refresh_from_db()
        enrollment.refresh_from_db()
        mine.refresh_from_db()
        self.assertEqual((token.scope, enrollment.token_id, mine.scope), (auth.SCOPE_SENTINEL, token.pk, auth.SCOPE_FULL))


class ScopesCoverageTests(SimpleTestCase):
    def test_every_model_with_a_project_owner_is_scoped_or_deliberately_not(self):
        from django.apps import apps

        from tenancy.scope import SCOPES, UNSCOPED
        owners = ('dashboard.Project', 'dashboard.Org', 'targetApp.Domain', 'startScan.ScanHistory', 'startScan.Subdomain')
        missing = []
        for model in apps.get_models():
            label = model._meta.label
            if label in SCOPES or label in UNSCOPED:
                continue
            if any(f.is_relation and (f.many_to_one or f.one_to_one) and f.related_model._meta.label in owners
                   for f in model._meta.get_fields() if getattr(f, 'related_model', None)):
                missing.append(label)
        self.assertEqual(missing, [], 'add these to tenancy.scope.SCOPES, or to UNSCOPED with the reason')
        self.assertFalse(set(SCOPES) & set(UNSCOPED))


class ScopedManagerTests(TestCase):
    """The newly scoped models: a user sees the rows of their own projects only, and a background job (no request scope) sees them all."""

    @classmethod
    def setUpTestData(cls):
        from dashboard.models import ApiCredential
        now = timezone.now()
        cls.org = Org.objects.create(name='Org', slug='scp-org')
        cls.pa = Project.objects.create(name='A', slug='scp-a', insert_date=now, org=cls.org)
        cls.pb = Project.objects.create(name='B', slug='scp-b', insert_date=now, org=cls.org)
        cls.alice = User.objects.create_user('scp_alice', password='x')
        ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
        InternalRange.objects.create(project=cls.pa, cidr='10.1.0.0/24')
        InternalRange.objects.create(project=cls.pb, cidr='10.2.0.0/24')
        SentinelTask.objects.create(project=cls.pa, kind='nmap', target={})
        SentinelTask.objects.create(project=cls.pb, kind='nmap', target={})
        ApiCredential.objects.create(project=cls.pa, service='shodan', value={'api_key': 'a'})
        ApiCredential.objects.create(project=cls.pb, service='shodan', value={'api_key': 'b'})
        ApiCredential.objects.create(org=cls.org, service='censys', value={'api_key': 'o'})

    def test_a_request_sees_only_its_own_projects_rows(self):
        from dashboard.models import ApiCredential
        from tenancy import scope
        tokens = scope.set_scope({self.pa.pk}, self.alice)
        try:
            self.assertEqual(list(InternalRange.objects.values_list('cidr', flat=True)), ['10.1.0.0/24'])
            self.assertEqual(SentinelTask.objects.count(), 1)
            self.assertEqual(sorted(ApiCredential.objects.values_list('service', flat=True)), ['censys', 'shodan'])  # its own and the organization's
            self.assertEqual(ApiCredential.objects.get(service='shodan').project_id, self.pa.pk)
        finally:
            scope.reset_scope(tokens)

    def test_a_background_job_sees_everything(self):
        self.assertEqual((InternalRange.objects.count(), SentinelTask.objects.count()), (2, 2))


class NetworkAuthorityTests(SentinelBase):
    """Whether a Sentinel sits inside a private network is the server's decision (its enrollment, or an administrator), never the Sentinel's claim."""

    def boot(self, network, caps=('nmap', 'nuclei_light', 'wpscan', 'network:internal')):
        status, out = call(self.t['dana'], 'POST', f'/api/v1/projects/sen-a/sentinels/enroll?format=blob&network={network}')
        self.assertEqual(status, 201, out)
        self.assertEqual(SentinelEnrollment.objects.get(prefix=out['enrollment_token'][:10]).network, network)
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': f'net-{network}',
                                                                           'capabilities': list(caps)})
        self.assertEqual(status, 201, boot)
        return boot

    def test_an_external_enrollment_cannot_declare_its_way_inside(self):
        boot = self.boot('external')
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.network, 'external')
        self.assertIn(sentinels.INTERNAL_CAPABILITY, agent.capabilities)  # what it claimed is kept as a claim ...
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))  # ... and never honoured
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective(agent).caps)

    def test_an_internal_enrollment_is_inside_even_when_the_client_does_not_say_so(self):
        agent = Agent.objects.get(pk=self.boot('internal', caps=('nmap',))['id'])
        self.assertEqual(agent.network, 'internal')
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

    def test_a_declared_capability_later_changes_nothing(self):
        boot = self.boot('external', caps=('nmap',))
        for call_args in (('PUT', '/api/v1/sentinel', {'capabilities': ['nmap', 'network:internal']}),
                          ('POST', '/api/v1/sentinel/heartbeat', {'capabilities': ['nmap', 'network:internal'], 'settings': {'network': 'internal'}})):
            call(boot['token'], *call_args)
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.network, 'external')
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))
        self.assertNotEqual(sentinels.sentinel_settings.effective(agent).get('network'), 'internal')  # the client is never told it is inside

    def test_an_external_sentinel_gets_no_internal_work_and_is_not_eligible(self):
        InternalRange.objects.create(project=self.pa, cidr='10.0.0.0/24')
        boot = self.boot('external')
        Agent.objects.filter(pk=boot['id']).update(status='active', last_seen=timezone.now())
        task = SentinelTask.objects.create(project=self.pa, kind='nuclei_light', target={'targets': ['10.0.0.5'], 'tags': [], 'severities': []}, ips=[])
        self.assertIsNone(call(boot['token'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task'])
        self.assertEqual(sentinels.eligible_sentinels(self.pa, 'nuclei_light', internal=True), [])
        inside = self.boot('internal')
        Agent.objects.filter(pk=inside['id']).update(status='active', last_seen=timezone.now())
        self.assertEqual(call(inside['token'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task']['id'], task.pk)

    def test_only_an_administrator_moves_a_sentinel_across_the_boundary(self):
        agent = Agent.objects.get(pk=self.boot('external')['id'])
        sentinels.sentinel_settings.set_managed(agent, {'network': 'internal'}, self.dana)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'internal')
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))
        sentinels.sentinel_settings.set_managed(agent, {'network': 'external'}, self.dana)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'external')

    def test_reset_of_external_enrollment_revokes_the_admin_internal_grant(self):
        boot = self.boot('external')
        agent = Agent.objects.get(pk=boot['id'])
        sentinels.sentinel_settings.record_reported(agent, {'network': 'internal'})
        sentinels.sentinel_settings.set_managed(agent, {'network': 'internal'}, self.dana)
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

        status, out = call(self.t['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'settings': {'network': None}})
        self.assertEqual(status, 200, out)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'external')
        self.assertNotIn('network', agent.managed_settings)
        self.assertEqual(agent.reported_settings['network']['value'], 'internal')
        self.assertEqual(sentinels.sentinel_settings.effective(agent)['network'], 'external')
        self.assertEqual(sentinels.sentinel_settings.reply(agent)['values']['network'], 'external')
        self.assertEqual(out['settings']['network']['value'], 'external')
        self.assertEqual(out['settings']['network']['server_grant'], 'external')
        self.assertEqual(out['settings']['network']['machine_value'], 'internal')
        self.assertTrue(out['settings']['network']['limited_by_server'])
        self.assertFalse(out['settings']['network']['managed'])
        audit_entry = AuditLog.objects.filter(action='agent.settings').latest('id')
        self.assertEqual((audit_entry.detail['network_grant_before'], audit_entry.detail['network_grant_after']), ('internal', 'external'))
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

    def test_reset_of_internal_enrollment_restores_its_provisioned_grant(self):
        boot = self.boot('internal')
        agent = Agent.objects.get(pk=boot['id'])
        SentinelEnrollment.objects.filter(used_by_agent=agent).update(expires_at=timezone.now() - timedelta(days=1))
        sentinels.sentinel_settings.record_reported(agent, {'network': 'internal'})
        sentinels.sentinel_settings.set_managed(agent, {'network': 'external'}, self.dana)
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

        status, out = call(self.t['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'settings': {'network': None}})
        self.assertEqual(status, 200, out)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'internal')
        self.assertNotIn('network', agent.managed_settings)
        self.assertEqual(sentinels.sentinel_settings.reply(agent)['values']['network'], 'internal')
        self.assertEqual(out['settings']['network']['server_grant'], 'internal')
        self.assertEqual(out['settings']['network']['value'], 'internal')
        self.assertFalse(out['settings']['network']['managed'])
        audit_entry = AuditLog.objects.filter(action='agent.settings').latest('id')
        self.assertEqual((audit_entry.detail['network_grant_before'], audit_entry.detail['network_grant_after']), ('external', 'internal'))
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))
        sentinels.sentinel_settings.record_reported(agent, {'network': 'external'})
        agent.refresh_from_db()
        status, detail = call(self.t['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail['settings']['network']['value'], 'external')
        self.assertEqual(detail['settings']['network']['server_grant'], 'internal')
        self.assertEqual(detail['settings']['network']['machine_value'], 'external')
        self.assertTrue(detail['settings']['network']['limited_by_machine'])
        status, beat = call(boot['token'], 'POST', '/api/v1/sentinel/heartbeat')
        self.assertEqual(status, 200, beat)
        self.assertEqual(beat['settings']['values']['network'], 'external')
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

    def test_reset_without_matching_enrollment_falls_back_to_external(self):
        out = register_sentinel(self.t['dana'], name='no-enrollment')[1]
        agent = Agent.objects.get(pk=out['id'])
        sentinels.sentinel_settings.record_reported(agent, {'network': 'internal'})
        sentinels.sentinel_settings.set_managed(agent, {'network': 'internal'}, self.dana)

        sentinels.sentinel_settings.set_managed(agent, {'network': None}, self.dana)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'external')
        self.assertEqual(sentinels.sentinel_settings.reply(agent)['values']['network'], 'external')
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

    def test_a_sentinel_that_declared_internal_before_the_server_decided_keeps_its_place(self):
        import importlib
        from django.apps import apps
        migration = importlib.import_module('agentapi.migrations.0007_sentinel_network')
        agent = Agent.objects.get(pk=self.boot('external')['id'])  # declared network:internal, enrolled external
        Agent.objects.filter(pk=agent.pk).update(network='external')
        migration.grandfather_internal(apps, None)
        agent.refresh_from_db()
        self.assertEqual(agent.network, 'internal')
