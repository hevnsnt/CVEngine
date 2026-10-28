"""Sentinels: identity, enrollment, scan-stage task queueing/leasing, dispatch-or-local, the admin surface."""
import base64
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import sentinel_broker as sentinels
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call


def reset_rates(tokens):
    from django.core.cache import cache

    from agentapi.auth import hash_token
    from dashboard.models import ApiToken
    for raw in tokens.values():
        for action in set(broker.RATES) | set(sentinels.RATES):
            cache.delete(f'agentapi:{action}:{hash_token(raw)[:16]}')
            cache.delete(f'agentapi:{action}:user:{ApiToken.objects.get(key_hash=hash_token(raw)).user_id}')


def build_world(cls):
    now = timezone.now()
    cls.org1, cls.org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
    cls.pa = Project.objects.create(name='A', slug='sen-a', insert_date=now, org=cls.org1)
    cls.pb = Project.objects.create(name='B', slug='sen-b', insert_date=now, org=cls.org2)
    cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
    cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
    mk = lambda n: User.objects.create_user(n, password='x')
    cls.alice, cls.dana, cls.root = mk('s_alice'), mk('s_dana'), mk('s_root')
    cls.root.is_superuser = True
    cls.root.save()
    ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')  # not an admin: a new agent of alice's starts pending
    OrgMembership.objects.create(user=cls.dana, org=cls.org1, role='admin')
    cls.tokens = {name: create_token(user, name)[1] for name, user in
                 (('alice', cls.alice), ('dana', cls.dana), ('root', cls.root))}
    engine = EngineType.objects.create(engine_name='e-sen', yaml_configuration='x', default_engine=True)
    cls.scan = ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=now, scan_status=1, results_dir='/tmp')
    sub = Subdomain.objects.create(scan_history=cls.scan, name='www.a.example')
    sub.ip_addresses.add(IpAddress.objects.create(address='192.0.2.50'))


def register_sentinel(token, **override):
    body = {'name': 'sentinel-1', 'scope': {'projects': ['sen-a']}, 'capabilities': ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted']}
    approve = override.pop('approve', True)
    body.update(override)
    status, out = call(token, 'PUT', '/api/v1/sentinel', body)
    if approve and status in (200, 201) and out['status'] == 'pending':
        Agent.objects.filter(pk=out['id']).update(status='active')
        out['status'] = 'active'
    return status, out


class SentinelBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        self.t = self.tokens
        reset_rates(self.tokens)


class RegistrationTests(SentinelBase):
    def test_register_forces_kind_scanner(self):
        status, out = register_sentinel(self.t['alice'])
        self.assertEqual(status, 201)
        self.assertEqual(Agent.objects.get(pk=out['id']).kind, 'scanner')

    def test_non_admin_starts_pending_admin_starts_active(self):
        _, alice_out = register_sentinel(self.t['alice'], approve=False)
        self.assertEqual(alice_out['status'], 'pending')
        _, dana_out = register_sentinel(self.t['dana'], approve=False, name='sentinel-dana')
        self.assertEqual(dana_out['status'], 'active')

    def test_cannot_claim_scope_outside_access(self):
        status, body = register_sentinel(self.t['alice'], scope={'projects': ['sen-b']})
        self.assertEqual(status, 403)
        self.assertFalse(Agent.objects.exists())

    def test_capabilities_accept_underscored_kind_names(self):
        status, out = register_sentinel(self.t['alice'], capabilities=['nuclei_light', 'nuclei_targeted'])
        self.assertEqual(status, 201)
        self.assertEqual(out['capabilities'], ['nuclei_light', 'nuclei_targeted'])


class EnrollmentTests(SentinelBase):
    def test_org_admin_can_generate_and_bootstrap_creates_pending_agent_for_non_admin_scope(self):
        # dana (org admin of org1) enrolls a Sentinel for sen-a; the resulting Agent belongs to dana (the enroller),
        # who IS an admin, so it starts active, exactly like dana registering one directly (same _initial_status rule).
        status, out = call(self.t['dana'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        self.assertEqual(status, 201)
        self.assertIn('enrollment_token', out)
        self.assertIn('server_url', out)
        self.assertNotIn('secret', str(out).lower().replace('enrollment_token', '').replace('secret_box', ''))
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'enrolled-1'})
        self.assertEqual(status, 201)
        self.assertEqual(boot['status'], 'active')
        self.assertIn('token', boot)
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.kind, 'scanner')
        self.assertEqual(agent.scope['projects'], ['sen-a'])
        self.assertEqual(agent.token.user, self.dana)

    def test_enrollment_secret_is_single_use(self):
        _, out = call(self.t['dana'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        status1, _ = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'x1'})
        status2, body2 = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'x2'})
        self.assertEqual(status1, 201)
        self.assertEqual(status2, 403)

    def test_unknown_or_bad_secret_is_refused(self):
        status, _ = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': 'senr_not-a-real-one', 'name': 'x'})
        self.assertEqual(status, 403)

    def test_non_admin_cannot_generate_an_enrollment_secret(self):
        status, _ = call(self.t['alice'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        self.assertEqual(status, 403)

    def test_another_orgs_admin_cannot_generate_for_this_project(self):
        bob = User.objects.create_user('s_bob', password='x')
        OrgMembership.objects.create(user=bob, org=self.org2, role='admin')
        token = create_token(bob, 'bob')[1]
        status, _ = call(token, 'POST', '/api/v1/projects/sen-a/sentinels/enroll')
        self.assertIn(status, (403, 404))

    def test_format_blob_packages_the_same_payload_and_still_bootstraps(self):
        # The provisioning blob (the Sentinels page's Provision button, and CVENGINE_SENTINEL_BLOB): generate_enrollment's
        # own contract is unchanged, ?format=blob only adds one opaque {blob} string alongside it.
        status, out = call(self.t['dana'], 'POST', '/api/v1/projects/sen-a/sentinels/enroll?format=blob')
        self.assertEqual(status, 201)
        self.assertIn('blob', out)
        self.assertIn('enrollment_token', out)  # the plain fields are still there: this is presentation, not a new contract
        decoded = sentinels.decode_enrollment_blob(out['blob'])
        self.assertEqual(decoded, {'enrollment_token': out['enrollment_token'], 'server_url': out['server_url'],
                                   'expires_at': out['expires_at'], 'scope': 'project', 'project': out['project']})
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap',
                            {'enrollment_token': decoded['enrollment_token'], 'name': 'blob-sentinel'})
        self.assertEqual(status, 201)
        self.assertIn('token', boot)

    def test_decode_enrollment_blob_rejects_anything_that_is_not_base64_json(self):
        for bad in ('not-base64-at-all-!!!', base64.b64encode(b'"just a json string, not an object"').decode(), '', '   '):
            with self.assertRaises(ValueError):
                sentinels.decode_enrollment_blob(bad)

    def test_encode_decode_blob_round_trips(self):
        payload = {'enrollment_token': 'senr_abc', 'server_url': 'https://cve.example', 'expires_at': '2030-01-01T00:00:00Z',
                   'project': 'sen-a'}
        blob = sentinels.encode_enrollment_blob(payload)
        self.assertEqual(sentinels.decode_enrollment_blob(blob), payload)
        base64.b64decode(blob, validate=True)  # standard base64, no custom framing


class OrgAndInstanceEnrollmentTests(SentinelBase):
    """Enrollment scoped wider than one project: an organization (every project of it, present and future) or,
    App Admin only, the whole instance (every organization and project, present and future)."""

    def test_org_admin_can_generate_org_enrollment_and_bootstrap_resolves_to_org_scope(self):
        status, out = call(self.t['dana'], 'POST', '/api/v1/orgs/one/sentinels/enroll')
        self.assertEqual(status, 201)
        self.assertEqual(out['scope'], 'org')
        self.assertEqual(out['org'], 'one')
        self.assertNotIn('project', out)
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'org-sentinel'})
        self.assertEqual(status, 201)
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.scope['orgs'], ['one'])
        self.assertEqual(agent.scope['projects'], [])
        self.assertFalse(agent.scope['instance'])
        # A project created in org1 after enrollment is covered too: scope.orgs resolves dynamically at claim time.
        from agentapi import agent_scope
        Project.objects.create(name='New', slug='sen-new', insert_date=timezone.now(), org=self.org1)
        self.assertIn('sen-new', agent_scope.project_slugs_in_scope(agent.token.user, agent.scope))

    def test_another_orgs_admin_cannot_generate_org_enrollment(self):
        bob = User.objects.create_user('s_bob3', password='x')
        OrgMembership.objects.create(user=bob, org=self.org2, role='admin')
        token = create_token(bob, 'bob3')[1]
        status, _ = call(token, 'POST', '/api/v1/orgs/one/sentinels/enroll')
        self.assertEqual(status, 403)

    def test_plain_project_member_cannot_generate_org_enrollment(self):
        status, _ = call(self.t['alice'], 'POST', '/api/v1/orgs/one/sentinels/enroll')
        self.assertEqual(status, 403)

    def test_unknown_org_is_404(self):
        status, _ = call(self.t['dana'], 'POST', '/api/v1/orgs/does-not-exist/sentinels/enroll')
        self.assertEqual(status, 404)

    def test_superuser_can_generate_instance_enrollment_and_bootstrap_resolves_to_every_project(self):
        status, out = call(self.t['root'], 'POST', '/api/v1/sentinels/enroll')
        self.assertEqual(status, 201)
        self.assertEqual(out['scope'], 'instance')
        self.assertNotIn('project', out)
        self.assertNotIn('org', out)
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': 'instance-sentinel'})
        self.assertEqual(status, 201)
        agent = Agent.objects.get(pk=boot['id'])
        self.assertTrue(agent.scope['instance'])
        from agentapi import agent_scope
        self.assertEqual(agent_scope.project_slugs_in_scope(agent.token.user, agent.scope), {'sen-a', 'sen-b'})

    def test_org_admin_cannot_generate_instance_enrollment(self):
        status, _ = call(self.t['dana'], 'POST', '/api/v1/sentinels/enroll')
        self.assertEqual(status, 403)

    def test_org_and_instance_blob_formats_round_trip(self):
        status, out = call(self.t['dana'], 'POST', '/api/v1/orgs/one/sentinels/enroll?format=blob')
        self.assertEqual(status, 201)
        decoded = sentinels.decode_enrollment_blob(out['blob'])
        self.assertEqual(decoded['scope'], 'org')
        self.assertEqual(decoded['org'], 'one')
        status, out = call(self.t['root'], 'POST', '/api/v1/sentinels/enroll?format=blob')
        self.assertEqual(status, 201)
        decoded = sentinels.decode_enrollment_blob(out['blob'])
        self.assertEqual(decoded['scope'], 'instance')
        self.assertNotIn('org', decoded)
        self.assertNotIn('project', decoded)

    def test_mcp_tool_rejects_both_project_and_org_given(self):
        err, out = tool_call(self.t['dana'], 'generate_sentinel_enrollment', {'project': 'sen-a', 'org': 'one'})
        self.assertTrue(err, out)

    def test_mcp_tool_generates_org_and_instance_enrollments(self):
        err, out = tool_call(self.t['dana'], 'generate_sentinel_enrollment', {'org': 'one'})
        self.assertFalse(err, out)
        self.assertEqual(out['scope'], 'org')
        self.assertIn('blob', out)
        err, out = tool_call(self.t['root'], 'generate_sentinel_enrollment', {})
        self.assertFalse(err, out)
        self.assertEqual(out['scope'], 'instance')
        self.assertIn('blob', out)
        err, out = tool_call(self.t['dana'], 'generate_sentinel_enrollment', {})
        self.assertTrue(err, out)  # dana is an org admin, not a superuser


class TenancyTests(SentinelBase):
    def test_another_orgs_admin_cannot_see_this_projects_sentinels_or_tasks(self):
        register_sentinel(self.t['dana'], name='dana-sentinel')
        bob = User.objects.create_user('s_bob2', password='x')
        OrgMembership.objects.create(user=bob, org=self.org2, role='admin')
        token = create_token(bob, 'bob2')[1]
        status, body = call(token, 'GET', '/api/v1/agents?kind=scanner')
        self.assertEqual(status, 200)
        self.assertEqual(body['results'], [])
        status, body = call(token, 'GET', '/api/v1/projects/sen-a/sentinel-tasks')
        self.assertEqual(status, 404)  # the project itself is outside bob's access


class ScopeAndClaimTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, self.agent = register_sentinel(self.t['dana'], name='scoped-sentinel')

    def _queue(self, project_slug='sen-a', kind='nmap', target=None):
        project = Project.objects.get(slug=project_slug)
        return SentinelTask.objects.create(project=project, scan=self.scan if project_slug == 'sen-a' else None, kind=kind,
                                           target=target or {'addresses': ['192.0.2.50']}, host='www.a.example', ips=['192.0.2.50'])

    def test_never_offered_or_claimable_outside_scope(self):
        self._queue('sen-b')  # project B task; this Sentinel is scoped to sen-a only
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200)
        self.assertIsNone(out['task'])

    def test_in_scope_task_is_claimable_end_to_end_and_lands_in_port_rows(self):
        task = self._queue('sen-a')
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], task.pk)
        self.assertEqual(out['task']['target'], task.target)
        status, accepted = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        self.assertEqual(status, 200)
        result = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': 'Linux 5.X',
                   'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '9.1'}]}]}
        status, reported = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', result)
        self.assertEqual(status, 200)
        self.assertEqual(reported['task']['status'], 'done')
        # Apply the same way sentinel_dispatch.try_nmap would: through the exact local persistence function.
        from cveFeed.nmap_scan import persist_inventory
        task.refresh_from_db()
        inventory = [{'ip': h['ip'], 'os_guess': h.get('os_guess', ''), 'os_accuracy': None, 'ports': h['ports']} for h in task.result['hosts']]
        persist_inventory(inventory)
        ip = IpAddress.objects.get(address='192.0.2.50')
        port = ip.ports.get(number=22)
        self.assertEqual((port.product, port.version, port.service_name, port.source), ('OpenSSH', '9.1', 'ssh', 'nmap'))

    def test_a_quiet_sentinel_mid_task_is_reaped_and_offline_sentinel_gets_no_new_work(self):
        task = self._queue('sen-a')
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        # No heartbeat, no report: simulate the lease already running out.
        SentinelTask.objects.filter(pk=task.pk).update(lease_expires_at=timezone.now() - timedelta(seconds=1))
        reaped = sentinels.reap_expired()
        self.assertGreaterEqual(reaped, 1)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')
        self.assertIsNone(task.agent_id)

    def test_malformed_or_oversized_result_is_rejected_not_trusted(self):
        task = self._queue('sen-a')
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        status, body = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'hosts': 'not-a-list'})
        self.assertEqual(status, 400)
        status, body = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'nonsense'})
        self.assertEqual(status, 400)

    def test_oversized_and_malicious_strings_are_clipped_never_stored_verbatim(self):
        # Unit-level, on the broker's own validation: a shell-injection-shaped, over-length string must never be
        # trusted or stored as given, whatever an HTTP-layer defense (reNgine.input_guard) also does with it in transit.
        evil = '; rm -rf / #' * 50
        clean = sentinels.clean_result('nmap', {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': evil,
                 'ports': [{'number': 80, 'product': evil, 'version': evil, 'service_name': evil}]}]})
        host = clean['hosts'][0]
        self.assertLessEqual(len(host['os_guess']), 120)
        self.assertLessEqual(len(host['ports'][0]['product']), 120)
        self.assertLessEqual(len(host['ports'][0]['version']), 80)
        self.assertNotEqual(host['os_guess'], evil)  # clipped, not stored verbatim
        self.assertEqual(len(host['os_guess']), 120)  # exactly the declared cap, whatever the content

    def test_result_clipping_over_http_also_succeeds_for_a_benign_oversized_string(self):
        task = self._queue('sen-a')
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        long_value = 'x' * 500
        result = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'os_guess': long_value,
                   'ports': [{'number': 80, 'product': long_value, 'version': long_value, 'service_name': long_value}]}]}
        status, reported = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', result)
        self.assertEqual(status, 200)
        host = reported['task']['result']['hosts'][0]
        self.assertEqual(len(host['os_guess']), 120)
        self.assertEqual(len(host['ports'][0]['product']), 120)
        self.assertEqual(len(host['ports'][0]['version']), 80)

    def test_release_puts_it_back_for_another_sentinel(self):
        task = self._queue('sen-a')
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        status, out = call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/release', {'reason': 'busy'})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')


class AdminSuspendRevokeTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, self.agent = register_sentinel(self.t['dana'], name='admin-target')
        self.aid = self.agent['id']

    def _claim_one(self):
        project = Project.objects.get(slug='sen-a')
        task = SentinelTask.objects.create(project=project, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']},
                                           host='www.a.example', ips=['192.0.2.50'])
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        return task

    def test_suspend_releases_in_flight_work_and_blocks_new_work(self):
        task = self._claim_one()
        status, _ = call(self.t['root'], 'PATCH', f'/api/v1/agents/{self.aid}', {'status': 'suspended'})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 403)

    def test_revoke_releases_in_flight_work_and_blocks_new_work(self):
        task = self._claim_one()
        status, _ = call(self.t['root'], 'PATCH', f'/api/v1/agents/{self.aid}', {'status': 'revoked'})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')
        status, _ = call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 403)

    def test_admin_listing_shows_sentinel_task_counts_and_history(self):
        self._claim_one()
        status, out = call(self.t['root'], 'GET', f'/api/v1/agents/{self.aid}')
        self.assertEqual(status, 200)
        self.assertEqual(len(out['recent_tasks']), 1)
        self.assertEqual(out['recent_tasks'][0]['kind'], 'nmap')


class McpToolTests(SentinelBase):
    """The MCP tools are thin wrappers over the same broker functions the REST routes use; one pass through the real
    JSON-RPC transport per verb proves the wiring (names, argument shapes) is correct, not just importable."""

    def test_register_claim_report_and_admin_tools_over_mcp(self):
        err, out = tool_call(self.t['dana'], 'register_sentinel', {'name': 'mcp-sentinel', 'scope': {'projects': ['sen-a']},
                              'capabilities': ['nmap']})
        self.assertFalse(err, out)
        self.assertEqual(out['kind'], 'scanner')
        agent_id = out['id']

        project = Project.objects.get(slug='sen-a')
        task = SentinelTask.objects.create(project=project, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']},
                                           host='www.a.example', ips=['192.0.2.50'])

        err, out = tool_call(self.t['dana'], 'get_next_sentinel_task', {'wait': 0})
        self.assertFalse(err, out)
        self.assertEqual(out['task']['id'], task.pk)

        err, out = tool_call(self.t['dana'], 'accept_sentinel_task', {'task_id': task.pk})
        self.assertFalse(err, out)

        err, out = tool_call(self.t['dana'], 'report_sentinel_task_result',
                             {'task_id': task.pk, 'outcome': 'done', 'hosts': [{'ip': '192.0.2.50', 'ports': []}]})
        self.assertFalse(err, out)
        self.assertEqual(out['task']['status'], 'done')

        err, out = tool_call(self.t['dana'], 'sentinel_heartbeat', {})
        self.assertFalse(err, out)

        err, out = tool_call(self.t['root'], 'list_sentinels', {})
        self.assertFalse(err, out)
        self.assertIn(agent_id, [a['id'] for a in out['results']])

        err, out = tool_call(self.t['root'], 'suspend_sentinel', {'agent_id': agent_id})
        self.assertFalse(err, out)
        self.assertEqual(out['status'], 'suspended')

    def test_enrollment_and_list_tasks_tools_over_mcp(self):
        err, out = tool_call(self.t['dana'], 'generate_sentinel_enrollment', {'project': 'sen-a'})
        self.assertFalse(err, out)
        self.assertIn('enrollment_token', out)
        # The MCP tool returns the blob and ready-to-run setup steps, not just the raw fields, so an agent with only
        # Docker and shell access to a target machine can provision a Sentinel from this response alone.
        self.assertIn('blob', out)
        self.assertEqual(sentinels.decode_enrollment_blob(out['blob'])['enrollment_token'], out['enrollment_token'])
        for key in ('clone', 'configure', 'run', 'verify'):
            self.assertIn(key, out['setup'])
        self.assertIn('cvengine-sentinel', out['setup']['clone'])
        self.assertIn(out['blob'], out['setup']['configure'])

        err, out = tool_call(self.t['dana'], 'list_sentinel_tasks', {'project': 'sen-a'})
        self.assertFalse(err, out)
        self.assertEqual(out['results'], [])

        err, out = tool_call(self.t['alice'], 'generate_sentinel_enrollment', {'project': 'sen-a'})
        self.assertTrue(err)  # alice is a project member, not an admin


class HeartbeatTests(SentinelBase):
    def test_heartbeat_extends_sentinel_task_lease(self):
        _, agent = register_sentinel(self.t['dana'], name='hb-sentinel')
        project = Project.objects.get(slug='sen-a')
        task = SentinelTask.objects.create(project=project, scan=self.scan, kind='naabu', target={'addresses': ['192.0.2.50']},
                                           host='www.a.example', ips=['192.0.2.50'])
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        call(self.t['dana'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        task.refresh_from_db()
        first_lease = task.lease_expires_at
        status, hb = call(self.t['dana'], 'POST', '/api/v1/sentinel/heartbeat')
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertGreaterEqual(task.lease_expires_at, first_lease)
        self.assertEqual(len(hb['leases']), 1)


class TestsslResultCleanerTests(SimpleTestCase):
    """``sentinel_broker.clean_result('testssl', ...)``: a Sentinel's testssl.sh report, typed and clipped into exactly the
    four fields ``cveFeed.testssl_scan.evaluate`` reads from a local report item."""

    def _body(self, **over):
        item = {'id': 'heartbleed', 'severity': 'HIGH', 'finding': 'VULNERABLE, exploitable', 'cve': 'CVE-2014-0160'}
        item.update(over)
        return {'outcome': 'done', 'items': [item]}

    def test_a_well_formed_item_round_trips(self):
        clean = sentinels.clean_result('testssl', self._body())
        self.assertEqual(clean['items'], [{'id': 'heartbleed', 'severity': 'HIGH', 'finding': 'VULNERABLE, exploitable', 'cve': 'CVE-2014-0160'}])

    def test_an_item_with_no_id_is_dropped(self):
        self.assertEqual(sentinels.clean_result('testssl', self._body(id=''))['items'], [])
        self.assertEqual(sentinels.clean_result('testssl', self._body(id='   '))['items'], [])

    def test_an_unknown_severity_word_is_blanked_not_trusted(self):
        clean = sentinels.clean_result('testssl', self._body(severity='; rm -rf / #'))
        self.assertEqual(clean['items'][0]['severity'], '')

    def test_severity_is_case_normalized(self):
        clean = sentinels.clean_result('testssl', self._body(severity='high'))
        self.assertEqual(clean['items'][0]['severity'], 'HIGH')

    def test_oversized_text_is_clipped_not_stored_verbatim(self):
        evil = 'A' * 5000
        clean = sentinels.clean_result('testssl', self._body(finding=evil, cve=evil))
        self.assertEqual(len(clean['items'][0]['finding']), 600)
        self.assertEqual(len(clean['items'][0]['cve']), 300)

    def test_more_items_than_the_cap_is_rejected_outright(self):
        from agentapi.services import ApiError
        body = self._body()
        body['items'] = body['items'] * (sentinels.MAX_TESTSSL_ITEMS + 1)
        with self.assertRaises(ApiError):
            sentinels.clean_result('testssl', body)

    def test_a_non_dict_item_is_dropped_not_rejected(self):
        body = self._body()
        body['items'].append('not-a-dict')
        clean = sentinels.clean_result('testssl', body)
        self.assertEqual(len(clean['items']), 1)


class NmapUdpResultCleanerTests(SimpleTestCase):
    """``sentinel_broker.clean_result('nmap_udp', ...)``: unlike every other kind, the stored result is raw XML text,
    bounded only by size - parsing it safely is ``cveFeed.nmap_scan.parse_xml``'s job, not the cleaner's."""

    def test_a_well_formed_report_round_trips_untouched(self):
        xml = '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>'
        clean = sentinels.clean_result('nmap_udp', {'outcome': 'done', 'xml': xml})
        self.assertEqual(clean['xml'], xml)

    def test_an_empty_or_missing_xml_is_rejected(self):
        from agentapi.services import ApiError
        with self.assertRaises(ApiError):
            sentinels.clean_result('nmap_udp', {'outcome': 'done', 'xml': ''})
        with self.assertRaises(ApiError):
            sentinels.clean_result('nmap_udp', {'outcome': 'done'})
        with self.assertRaises(ApiError):
            sentinels.clean_result('nmap_udp', {'outcome': 'done', 'xml': 123})

    def test_an_oversized_report_is_rejected_outright(self):
        from agentapi.services import ApiError
        with self.assertRaises(ApiError):
            sentinels.clean_result('nmap_udp', {'outcome': 'done', 'xml': 'A' * (sentinels.MAX_NMAP_UDP_XML + 1)})
