"""A stored sign-in on an external Sentinel (``agentapi.signin_delivery``): opt-in only, never by default. It goes to a Sentinel that is not the built-in
scanner only when its client reports ``secret_read_external``, the credential's owner switched ``allow_external_sentinels`` on, the Sentinel's enrolling
user may manage that sign-in (an App Admin or the organization's admin), the credential is of the task's project and not expired, and the project is in
the Sentinel's scope. The single-use read keeps every guarantee it has for the built-in scanner: one read per task, only by the Sentinel holding it,
decrypted only after the compare-and-set was won, every call audited, the value in no row, message or log."""
from datetime import timedelta
from unittest import mock

from django.test import Client
from django.utils import timezone

from agentapi import sentinel_broker as sentinels
from agentapi import sentinel_dispatch, sentinel_settings, signin_delivery
from agentapi.models import Agent, SentinelTask
from cveFeed.models import AuthCredential
from dashboard.models import ApiToken, AuditLog, ProjectMembership
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_authcheck import COOKIE, SECRET, Fixture as AuthFixture
from tests.test_sentinel_secret_read import SECRETS, SecretBase

READY = {'features': ['credential_filter', 'bbot_keys', signin_delivery.FEATURE], 'contract_version': 11}


class ExternalBase(SecretBase):
    def setUp(self):
        super().setUp()
        for agent in (self.external, self.instance):
            Agent.objects.filter(pk=agent.pk).update(info=READY, capabilities=list(agent.capabilities) + ['route_probe_signed'])
            agent.refresh_from_db()

    def allow(self, on=True, cred=None):
        AuthCredential.objects.filter(pk=(cred or self.cred).pk).update(allow_external_sentinels=on)

    def builtin_off(self):
        """The built-in scanner is not there for this work: offline, as on a Hosted install where it is held off."""
        Agent.objects.filter(pk=self.builtin.pk).update(last_seen=timezone.now() - timedelta(hours=2))

    def ext_task(self, **kw):
        return self.task(agent=self.external, **kw)

    def outcome(self):
        return self.audits()[-1].detail['outcome']

    def refusal(self, agent, task):
        return sentinels.effective(agent).refusal(SentinelTask.objects.select_related('project').get(pk=task.pk))


class OptInTests(ExternalBase):
    def test_the_switch_is_off_by_default(self):
        self.assertFalse(AuthCredential.objects.get(pk=self.cred.pk).allow_external_sentinels)
        task = self.ext_task()
        status, out = self.read('external', task)
        self.assertEqual(status, 403)
        self.assertNotIn('credential', out)
        self.assertIn('signin_external_off', self.outcome())
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)  # a refusal never burns the single use
        self.assertEqual(self.refusal(self.external, task), ('capability', sentinels.SIGNED_IN))

    def test_a_client_without_the_feature_is_refused_like_any_old_client(self):
        self.allow()
        Agent.objects.filter(pk=self.external.pk).update(info={'features': ['credential_filter', 'bbot_keys'], 'contract_version': 11})
        task = self.ext_task()
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertEqual(self.outcome(), 'refused: not the built-in scanner')
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)
        for word in ('secret_read', 'vantage'):  # the built-in image's words do not open the gate for an external Sentinel
            Agent.objects.filter(pk=self.external.pk).update(info={'features': [word, 'credential_filter'], 'contract_version': 11})
            self.assertEqual(self.read('external', self.ext_task())[0], 403, word)

    def test_a_sentinel_whose_enrolling_user_may_not_manage_sign_ins_is_refused(self):
        self.allow()
        ProjectMembership.objects.filter(user=self.alice, project=self.pa).update(role='admin')  # a project admin, not the organization's admin
        ApiToken.objects.filter(pk=self.external.token_id).update(user=self.alice)
        task = self.ext_task()
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertIn('signin_not_owner', self.outcome())
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)

    def test_an_expired_credential_is_refused_and_not_burned(self):
        self.allow()
        AuthCredential.objects.filter(pk=self.cred.pk).update(expires_at=timezone.now() - timedelta(days=1))
        task = self.ext_task()
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertIn('signin_expired', self.outcome())
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)
        self.assertNoSecretAnywhere()

    def test_a_credential_of_another_project_is_refused(self):
        other = Domain.objects.create(name='other.example', project=self.pb, insert_date=timezone.now())
        cred = self.credential(domain=other)
        self.allow(cred=cred)
        task = self.ext_task(ref=sentinels.secret_ref_for(cred.pk))
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertRegex(self.outcome(), r'signin_(wrong_project|gone)')  # the Sentinel's request is tenancy scoped: another project's row is not even seen
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)

    def test_a_project_outside_the_sentinels_scope_is_refused(self):
        other = Domain.objects.create(name='other.example', project=self.pb, insert_date=timezone.now())
        cred = self.credential(domain=other)
        self.allow(cred=cred)
        task = self.task(agent=self.external, project=self.pb, ref=sentinels.secret_ref_for(cred.pk))
        self.assertEqual(self.read('external', task)[0], 403)
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)
        self.assertEqual(self.refusal(self.external, task)[0], 'scope')

    def test_a_kind_that_never_carries_a_sign_in_outside_is_refused(self):
        self.allow()
        task = self.ext_task(kind='nmap')
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertEqual(self.outcome(), 'refused: not the built-in scanner')

    def test_a_queued_task_and_a_task_of_another_sentinel_are_not_readable(self):
        self.allow()
        for task in (self.task(agent=None, status='queued'), self.task(agent=self.instance), self.task()):
            self.assertEqual(self.read('external', task)[0], 403)
            task.refresh_from_db()
            self.assertIsNone(task.secret_read_at)
        for status in ('done', 'failed'):
            task = self.ext_task(status=status)
            self.assertEqual(self.read('external', task)[0], 409, status)
            task.refresh_from_db()
            self.assertIsNone(task.secret_read_at)

    def test_the_switch_turned_off_after_the_gate_is_honoured_when_decrypting(self):
        self.allow(False)
        self.assertIsNone(sentinels._credential_payload(self.cred.pk, self.pa.pk, timezone.now(), external=True))
        self.assertIsNotNone(sentinels._credential_payload(self.cred.pk, self.pa.pk, timezone.now()))  # the built-in scanner's read is unchanged

    def test_the_feature_is_kept_from_a_registration(self):
        self.assertIn(signin_delivery.FEATURE, sentinel_settings.clean_info({'features': [signin_delivery.FEATURE, 'nonsense']})['features'])


class GrantTests(ExternalBase):
    def test_an_opted_in_external_sentinel_reads_it_once_audited_and_leak_free(self):
        self.allow()
        self.builtin_off()
        task = self.ext_task()
        response = Client().post(f'/api/v1/sentinel/tasks/{task.pk}/secret', HTTP_AUTHORIZATION=f'Bearer {self.t["external"]}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Cache-Control'], 'no-store')
        body = response.json()
        self.assertEqual(body['credential']['cookie'], f'sid={SECRETS[1]}')
        self.assertEqual(body['credential']['host'], 'www.a.example')
        task.refresh_from_db()
        self.assertIsNotNone(task.secret_read_at)
        status, out = self.read('external', task)  # single use
        self.assertEqual(status, 409)
        self.assertNotIn('credential', out)
        rows = self.audits()
        self.assertEqual([r.detail['outcome'].split(':')[0] for r in rows], ['granted', 'refused'])
        self.assertEqual(rows[0].detail, {'task_id': task.pk, 'agent_id': self.external.pk, 'secret_ref': task.secret_ref, 'outcome': 'granted'})
        delivered, = AuditLog.objects.filter(action='sentinel.signin.delivered')
        self.assertEqual((delivered.detail['agent_id'], delivered.detail['credential_id'], delivered.org_id), (self.external.pk, self.cred.pk, self.org1.pk))
        self.assertNoSecretAnywhere()

    def test_an_instance_wide_sentinel_an_app_admin_enrolled_qualifies(self):
        self.allow()
        task = self.task(agent=self.instance)
        status, out = self.read('instance', task)
        self.assertEqual(status, 200, out)
        self.assertNoSecretAnywhere()

    def test_the_value_is_not_decrypted_before_the_single_use_is_won(self):
        self.allow()
        task = self.ext_task()
        SentinelTask.objects.filter(pk=task.pk).update(secret_read_at=timezone.now())
        with mock.patch.object(sentinels, '_credential_payload') as payload:
            self.assertEqual(self.read('external', task)[0], 409)
        payload.assert_not_called()

    def test_a_failure_while_reading_leaks_nothing(self):
        self.allow()
        task = self.ext_task()
        with mock.patch.object(sentinels, '_credential_payload', side_effect=ValueError(f'boom {SECRETS[0]} {SECRETS[1]}')):
            status, out = self.read('external', task)
        self.assertEqual(status, 410)
        for secret in SECRETS:
            self.assertNotIn(secret, str(out))
        self.assertFalse(AuditLog.objects.filter(action='sentinel.signin.delivered').exists())
        self.assertNoSecretAnywhere()


class BrokerTests(ExternalBase):
    def test_the_queue_offers_it_only_when_the_owner_allowed_it(self):
        signed = self.task(agent=None, status='queued')
        status, out = call(self.t['external'], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertIsNone(out['task'])  # off by default
        self.assertEqual(sentinels.queued_for(self.external), {})
        self.allow()
        self.builtin_off()
        self.assertEqual(sentinels.queued_for(self.external), {'nuclei_targeted': 1})
        status, out = call(self.t['external'], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertEqual(status, 200, out)
        self.assertEqual(out['task']['id'], signed.pk)
        self.assertIs(out['task']['signed_in'], True)
        for secret in (*SECRETS, 'authcred'):
            self.assertNotIn(secret, str(out))
        self.assertEqual(self.read('external', signed)[0], 200)

    def test_capacity_counts_an_opted_in_external_when_the_builtin_scanner_is_off(self):
        ref = sentinels.secret_ref_for(self.cred.pk)
        flags = sentinel_dispatch.capacity_flags(ref)
        self.assertEqual(flags, {'signin': ref})
        self.builtin_off()
        Agent.objects.filter(pk=self.instance.pk).update(last_seen=timezone.now() - timedelta(hours=2))
        none = sentinels.capacity_state(self.pa, 'nuclei_targeted', why=True, **flags)
        self.assertEqual((none['state'], none['reason']), ('none', 'signin_external_off'))
        self.allow()
        self.assertEqual(sentinels.capacity_state(self.pa, 'nuclei_targeted', **flags)['state'], 'free')
        self.assertEqual([e.agent.pk for e in sentinels.eligible_sentinels(self.pa, 'nuclei_targeted', live_only=True, signin=ref)], [self.external.pk])
        Agent.objects.filter(pk=self.external.pk).update(info={'features': ['credential_filter'], 'contract_version': 11})
        none = sentinels.capacity_state(self.pa, 'nuclei_targeted', why=True, **flags)
        self.assertEqual((none['state'], none['reason']), ('none', 'signin_client_outdated'))

    def test_the_builtin_scanner_keeps_its_path(self):
        ref = sentinels.secret_ref_for(self.cred.pk)
        for agent in (self.external, self.instance):
            Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=2))
        self.assertEqual(sentinels.capacity_state(self.pa, 'nuclei_targeted', signin=ref)['state'], 'free')
        self.assertIsNone(self.refusal(self.builtin, self.task(agent=None, status='queued')))

    def test_the_signed_in_route_check_opens_to_an_opted_in_external_sentinel(self):
        task = self.task(agent=None, status='queued', kind='route_probe_signed', ref='default')
        self.assertEqual(self.refusal(self.external, task), ('capability', sentinels.SIGNED_IN))
        self.allow()
        self.assertIsNone(self.refusal(self.external, task))
        bare = self.task(agent=None, status='queued', kind='route_probe_signed', ref=None)  # with no sign-in it stays the built-in scanner's
        self.assertEqual(self.refusal(self.external, bare), ('capability', sentinels.BUILTIN))


class RestSwitchTests(AuthFixture):
    url = '/api/v1/projects/acp'

    def put(self, who, body):
        return call(self.users.get(who) or self.tokens[who], 'PUT', f'{self.url}/targets/{self.domain.pk}/auth-credential', body)

    def body(self, **extra):
        return {'label': 'staging test account', 'scope': 'host', 'host': 'app.example.test', 'headers': [{'name': 'Authorization', 'secret': SECRET}],
                'cookie_secret': COOKIE, 'expires': 30, **extra}

    def test_the_switch_is_off_by_default_is_set_kept_and_audited(self):
        status, created = self.put('orgadmin', self.body())
        self.assertEqual((status, created['allow_external_sentinels']), (200, False))
        self.assertFalse(AuditLog.objects.filter(action='target.auth_credential.external_sentinels').exists())
        keep = {'headers': [{'name': 'Authorization', 'secret': ''}], 'cookie_secret': ''}
        status, on = self.put('orgadmin', self.body(allow_external_sentinels=True, **keep))
        self.assertEqual((status, on['allow_external_sentinels']), (200, True))
        _status, listed = call(self.tokens['orgadmin'], 'GET', f'{self.url}/auth-credentials')
        self.assertIs(listed['results'][0]['allow_external_sentinels'], True)
        row, = AuditLog.objects.filter(action='target.auth_credential.external_sentinels')
        self.assertEqual((row.actor_name, row.org_id, row.detail['allow_external_sentinels']), ('ac_orgadmin', self.org.pk, True))
        self.put('orgadmin', self.body(**keep))  # left out on a replace: kept, and keeping it adds no audit row
        self.assertTrue(AuthCredential.objects.get().allow_external_sentinels)
        self.assertEqual(AuditLog.objects.filter(action='target.auth_credential.external_sentinels').count(), 1)
        self.put('root', self.body(allow_external_sentinels=False, **keep))
        self.assertFalse(AuthCredential.objects.get().allow_external_sentinels)
        self.assertEqual(AuditLog.objects.filter(action='target.auth_credential.external_sentinels').count(), 2)
        for row in AuditLog.objects.filter(action__startswith='target.auth_credential'):
            self.assertNotIn(SECRET, str(row.detail))

    def test_the_switch_must_be_a_boolean_and_is_admin_only_and_never_set_by_a_token(self):
        for bad in ('yes', 1, None, 'true'):
            status, data = self.put('orgadmin', self.body(allow_external_sentinels=bad))
            self.assertEqual(status, 400, bad)
        for who in ('member', 'pmember', 'auditor'):
            self.assertEqual(self.put(who, self.body(allow_external_sentinels=True))[0], 403, who)
        self.assertEqual(self.put('orgadmin_ro', self.body(allow_external_sentinels=True))[0], 403)
        self.assertEqual(AuthCredential.objects.count(), 0)

    def test_the_mcp_list_shows_the_switch_and_never_a_value(self):
        from tests.test_agentapi import tool_call
        self.make()
        AuthCredential.objects.update(allow_external_sentinels=True)
        error, listed = tool_call(self.tokens['orgadmin'], 'list_auth_credentials', {'project': 'acp'})
        self.assertFalse(error, listed)
        self.assertIs(listed['results'][0]['allow_external_sentinels'], True)
        self.assertNotIn(SECRET, str(listed))
