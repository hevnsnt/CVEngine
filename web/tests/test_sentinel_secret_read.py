"""The single-use secure read of a stored credential (``POST /api/v1/sentinel/tasks/<id>/secret``): only the built-in scanner, only for the one signed-in task
it holds, exactly once, audited on every call, and the value is in no row, message or log. Dormant: nothing dispatches signed-in work yet, so these tests
build the tasks by hand."""
import logging
import os
import tempfile
from datetime import timedelta
from unittest import mock

from django.test import Client, TestCase
from django.utils import timezone

from agentapi import builtin_scanner as builtin
from agentapi import sentinel_broker as sentinels
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed.models import AgentActivity, AuthCredential
from dashboard.models import AuditLog
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_sentinels import build_world, reset_rates

HEADER_SECRET = 'tok-7f3a9c-SECRETVALUE'
COOKIE_SECRET = 'cookie-91ab-SECRETCOOKIE'
SECRETS = (HEADER_SECRET, COOKIE_SECRET)
CAPS = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep']


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage() + ' ' + (self.format(record) if record.exc_info else ''))


class SecretBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '1', 'CVENGINE_SCANNER_BOOTSTRAP_DIR': self.dir.name}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        self.logs = Capture()
        logging.getLogger().addHandler(self.logs)
        self.addCleanup(logging.getLogger().removeHandler, self.logs)
        self.t = dict(self.tokens)
        builtin.ensure()
        with open(builtin.blob_path(), encoding='utf-8') as handle:
            payload = sentinels.decode_enrollment_blob(handle.read())
        status, out = call(None, 'POST', '/api/v1/sentinels/bootstrap',
                           {'enrollment_token': payload['enrollment_token'], 'name': 'x', 'capabilities': CAPS})
        self.assertEqual(status, 201, out)
        self.t['builtin'], self.builtin = out['token'], Agent.objects.get(pk=out['id'])
        self.touch(self.builtin)
        self.external, self.t['external'] = self.enroll(self.t['dana'], '/api/v1/projects/sen-a/sentinels/enroll', 'external-1')
        self.instance, self.t['instance'] = self.enroll(self.t['root'], '/api/v1/sentinels/enroll', 'external-instance')
        self.cred = self.credential()
        reset_rates(self.t)

    def enroll(self, enroller, path, name):
        status, out = call(enroller, 'POST', path)
        self.assertEqual(status, 201, out)
        status, boot = call(None, 'POST', '/api/v1/sentinels/bootstrap', {'enrollment_token': out['enrollment_token'], 'name': name, 'capabilities': CAPS})
        self.assertEqual(status, 201, boot)
        agent = Agent.objects.get(pk=boot['id'])
        self.assertEqual(agent.status, 'active')
        self.touch(agent)
        return agent, boot['token']

    @staticmethod
    def touch(agent):
        Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now())

    def credential(self, project=None, domain=None, expires=None):
        domain = domain or self.da
        return AuthCredential.objects.create(
            project=project or domain.project, domain=domain, host='www.a.example', label='test account', origins=['https:443'],
            secret={'headers': [['Authorization', f'Bearer {HEADER_SECRET}']], 'cookie': f'sid={COOKIE_SECRET}'}, expires_at=expires)

    def task(self, agent='builtin', status='claimed', ref='default', kind='nuclei_targeted', project=None):
        agent = self.builtin if agent == 'builtin' else agent
        return SentinelTask.objects.create(
            project=project or self.pa, scan=self.scan, kind=kind, host='www.a.example', target={'targets': ['www.a.example']}, status=status, agent=agent,
            secret_ref=sentinels.secret_ref_for(self.cred.pk) if ref == 'default' else ref,
            lease_expires_at=timezone.now() + timedelta(minutes=5) if status in ('claimed', 'running') else None)

    def read(self, who, task):
        return call(self.t[who], 'POST', f'/api/v1/sentinel/tasks/{task.pk if hasattr(task, "pk") else task}/secret')

    def audits(self):
        return list(AuditLog.objects.filter(action='sentinel.secret.read').order_by('id'))

    def assertNoSecretAnywhere(self):
        everything = ' '.join([str(list(AuditLog.objects.values())), str(list(SentinelTask.objects.values())),
                               str(list(AgentActivity.objects.values())), ' '.join(self.logs.lines)])
        for secret in SECRETS:
            self.assertNotIn(secret, everything)


class GrantTests(SecretBase):
    def test_the_builtin_scanner_reads_exactly_the_stored_credential_once(self):
        task = self.task()
        response = Client().post(f'/api/v1/sentinel/tasks/{task.pk}/secret', HTTP_AUTHORIZATION=f'Bearer {self.t["builtin"]}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Cache-Control'], 'no-store')
        body = response.json()
        self.assertEqual(body['task_id'], task.pk)
        self.assertEqual(body['credential']['headers'], [['Authorization', f'Bearer {HEADER_SECRET}']])
        self.assertEqual(body['credential']['cookie'], f'sid={COOKIE_SECRET}')
        self.assertEqual(body['credential']['host'], 'www.a.example')
        self.assertEqual(body['credential']['origins'], ['https:443'])
        self.assertEqual(body['credential']['target'], 'a.example')
        task.refresh_from_db()
        self.assertIsNotNone(task.secret_read_at)
        self.cred.refresh_from_db()
        self.assertIsNotNone(self.cred.last_used_at)

    def test_a_running_task_may_read_too(self):
        status, out = self.read('builtin', self.task(status='running'))
        self.assertEqual(status, 200)
        self.assertEqual(out['credential']['cookie'], f'sid={COOKIE_SECRET}')

    def test_a_second_read_is_a_409_and_returns_nothing(self):
        task = self.task()
        self.assertEqual(self.read('builtin', task)[0], 200)
        status, out = self.read('builtin', task)
        self.assertEqual(status, 409)
        self.assertNotIn('credential', out)
        for secret in SECRETS:
            self.assertNotIn(secret, str(out))

    def test_the_reference_is_never_shown_with_the_task(self):
        task = self.task()
        self.assertEqual(self.read('builtin', task)[0], 200)
        status, out = call(self.t['dana'], 'GET', '/api/v1/projects/sen-a/sentinel-tasks')
        self.assertEqual(status, 200)
        self.assertNotIn('secret_ref', str(out))
        self.assertNotIn('authcred', str(out))


class RefusalTests(SecretBase):
    def test_an_external_sentinel_is_refused_and_the_refusal_is_audited(self):
        for who, agent in (('external', self.external), ('instance', self.instance)):
            task = self.task(agent=agent)  # even the Sentinel the task is assigned to
            status, out = self.read(who, task)
            self.assertEqual(status, 403, who)
            self.assertNotIn('credential', out)
            task.refresh_from_db()
            self.assertIsNone(task.secret_read_at)
            row = self.audits()[-1]
            self.assertEqual(row.detail['agent_id'], agent.pk)
            self.assertEqual(row.detail['task_id'], task.pk)
            self.assertTrue(row.detail['outcome'].startswith('refused'))
        self.assertEqual(len(self.audits()), 2)

    def test_the_builtin_scanner_gets_a_404_for_what_is_not_its_own_signed_in_task(self):
        others = self.task(agent=self.external)
        queued = self.task(agent=None, status='queued')
        plain = self.task(ref=None)
        for task in (others, queued, plain, 999999):
            status, out = self.read('builtin', task)
            self.assertEqual(status, 404, task)
            self.assertNotIn('credential', out)
        others.refresh_from_db()
        plain.refresh_from_db()
        self.assertIsNone(others.secret_read_at)
        self.assertIsNone(plain.secret_read_at)

    def test_a_task_that_is_not_claimed_or_running_is_refused(self):
        for status in ('done', 'failed'):
            task = self.task(status=status)
            code, out = self.read('builtin', task)
            self.assertEqual(code, 409, status)
            self.assertNotIn('credential', out)
            task.refresh_from_db()
            self.assertIsNone(task.secret_read_at)

    def test_a_credential_of_another_project_is_refused_and_not_burned(self):
        other = Domain.objects.create(name='other.example', project=self.pb, insert_date=timezone.now())
        task = self.task()
        task.secret_ref = sentinels.secret_ref_for(self.credential(domain=other).pk)
        task.save()
        status, out = self.read('builtin', task)
        self.assertEqual(status, 403)
        self.assertNotIn('credential', out)
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)

    def test_an_expired_or_deleted_credential_is_gone_and_not_burned(self):
        expired = self.task()
        AuthCredential.objects.filter(pk=self.cred.pk).update(expires_at=timezone.now() - timedelta(days=1))
        self.assertEqual(self.read('builtin', expired)[0], 410)
        AuthCredential.objects.all().delete()
        deleted = self.task()
        self.assertEqual(self.read('builtin', deleted)[0], 410)
        for task in (expired, deleted):
            task.refresh_from_db()
            self.assertIsNone(task.secret_read_at)
        self.assertNoSecretAnywhere()

    def test_a_malformed_reference_is_refused(self):
        task = self.task(ref='authcred:abc')
        self.assertEqual(self.read('builtin', task)[0], 410)

    def test_a_suspended_builtin_scanner_is_refused(self):
        task = self.task()
        Agent.objects.filter(pk=self.builtin.pk).update(status='suspended')
        self.assertEqual(self.read('builtin', task)[0], 403)

    def test_a_persons_full_token_and_a_read_only_token_are_refused_and_audited(self):
        task = self.task()
        admin_full = create_token(self.root, 'admin-full')[1]  # the very user that owns the built-in scanner's token
        read_only = create_token(self.root, 'admin-ro', read_only=True)[1]
        inventory = create_token(self.alice, 'inv', scope='inventory', project=self.pa)[1]
        self.t.update(admin_full=admin_full, read_only=read_only, inventory=inventory)
        for who in ('admin_full', 'read_only', 'alice', 'dana'):
            status, out = self.read(who, task)
            self.assertEqual(status, 403, who)
            self.assertNotIn('credential', out)
        self.assertEqual(self.read('inventory', task)[0], 403)  # stopped before the route: the token scope allows no such path
        self.assertEqual(call(None, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/secret')[0], 401)
        task.refresh_from_db()
        self.assertIsNone(task.secret_read_at)
        reasons = [row.detail['outcome'] for row in self.audits()]
        self.assertEqual(len(reasons), 4)
        self.assertTrue(all(r.startswith('refused') for r in reasons))
        self.assertIn('refused: read-only token', reasons)

    def test_only_post_is_routed(self):
        task = self.task()
        self.assertEqual(call(self.t['builtin'], 'GET', f'/api/v1/sentinel/tasks/{task.pk}/secret')[0], 405)


class AuditTests(SecretBase):
    def test_every_call_is_audited_and_no_row_holds_the_value(self):
        task = self.task()
        self.assertEqual(self.read('builtin', task)[0], 200)
        self.assertEqual(self.read('builtin', task)[0], 409)
        self.assertEqual(self.read('external', task)[0], 403)
        self.assertEqual(self.read('builtin', 999999)[0], 404)
        rows = self.audits()
        self.assertEqual([r.detail['outcome'].split(':')[0] for r in rows], ['granted', 'refused', 'refused', 'refused'])
        granted = rows[0]
        self.assertEqual(granted.detail, {'task_id': task.pk, 'agent_id': self.builtin.pk, 'secret_ref': task.secret_ref, 'outcome': 'granted'})
        self.assertEqual(granted.org_id, self.org1.pk)
        self.assertEqual(rows[2].detail['agent_id'], self.external.pk)
        self.assertNoSecretAnywhere()

    def test_a_failure_while_reading_leaks_nothing(self):
        task = self.task()
        with mock.patch.object(sentinels, '_credential_payload', side_effect=ValueError(f'boom {HEADER_SECRET} {COOKIE_SECRET}')):
            status, out = self.read('builtin', task)
        self.assertEqual(status, 410)
        for secret in SECRETS:
            self.assertNotIn(secret, str(out))
        self.assertEqual(self.audits()[-1].detail['outcome'], 'refused: the stored credential could not be read')
        self.assertNoSecretAnywhere()


class BrokerGateTests(SecretBase):
    def test_a_signed_in_task_is_never_offered_to_an_external_sentinel(self):
        signed = self.task(agent=None, status='queued')
        for who in ('external', 'instance'):
            status, out = call(self.t[who], 'POST', '/api/v1/sentinel/tasks/next', {})
            self.assertEqual(status, 200)
            self.assertIsNone(out['task'], who)
        signed.refresh_from_db()
        self.assertEqual(signed.status, 'queued')
        plain = self.task(agent=None, status='queued', ref=None)
        status, out = call(self.t['external'], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertEqual(out['task']['id'], plain.pk)  # ordinary work is unchanged

    def test_the_builtin_scanner_is_offered_it_and_the_offer_carries_no_value(self):
        signed = self.task(agent=None, status='queued')
        status, out = call(self.t['builtin'], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertEqual(out['task']['id'], signed.pk)
        self.assertNotIn('authcred', str(out))
        self.assertEqual(self.read('builtin', signed)[0], 200)

    def test_refusal_and_queue_views(self):
        task = self.task(agent=None, status='queued')
        task = SentinelTask.objects.select_related('project').get(pk=task.pk)
        self.assertEqual(sentinels.effective(self.external).refusal(task), ('capability', sentinels.SIGNED_IN))
        self.assertEqual(sentinels.effective(self.instance).refusal(task), ('capability', sentinels.SIGNED_IN))
        self.assertIsNone(sentinels.effective(self.builtin).refusal(task))
        self.assertEqual(sentinels.queued_for(self.external), {})
        self.assertEqual(sentinels.queued_for(self.builtin), {'nuclei_targeted': 1})

    def test_a_task_forced_onto_an_external_sentinel_is_taken_back_on_accept(self):
        task = self.task(agent=self.external)
        status, out = call(self.t['external'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        self.assertEqual(status, 409)
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')

    def test_eligibility_and_capacity(self):
        kind = 'nuclei_targeted'
        everyone = {e.agent.pk for e in sentinels.eligible_sentinels(self.pa, kind)}
        self.assertEqual(everyone, {self.builtin.pk, self.external.pk, self.instance.pk})
        self.assertEqual([e.agent.pk for e in sentinels.eligible_sentinels(self.pa, kind, builtin_only=True)], [self.builtin.pk])
        Agent.objects.filter(pk=self.builtin.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        self.assertEqual(sentinels.capacity_state(self.pa, kind, builtin_only=True)['state'], 'none')  # live external Sentinels do not count
        self.assertFalse(sentinels.any_scanner_for(self.pa, kind, builtin_only=True))
        self.assertTrue(sentinels.any_scanner_for(self.pa, kind))
        self.touch(self.builtin)
        self.assertEqual(sentinels.capacity_state(self.pa, kind, builtin_only=True)['state'], 'free')

    def test_queued_signed_in_work_does_not_make_external_slots_look_busy(self):
        kind = 'nuclei_targeted'
        for agent in (self.builtin, self.instance):
            Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        Agent.objects.filter(pk=self.external.pk).update(max_concurrent=1)
        self.task(agent=None, status='queued')
        self.assertEqual(sentinels.capacity_state(self.pa, kind)['state'], 'free')
        self.task(agent=None, status='queued', ref=None)
        self.assertEqual(sentinels.capacity_state(self.pa, kind)['state'], 'busy')


class ConcurrencyAndRateTests(SecretBase):
    def test_of_two_overlapping_redemptions_exactly_one_wins(self):
        task = self.task()
        real, inner = sentinels._stored_credential, {}

        def interleaved(*args, **kwargs):
            answer = real(*args, **kwargs)  # the outer request has now passed every check and not yet taken the single use
            if not inner:
                inner['started'] = True  # set first: the second request passes through here too
                inner['result'] = self.read('builtin', task)
            return answer
        with mock.patch.object(sentinels, '_stored_credential', side_effect=interleaved):
            outer = self.read('builtin', task)
        self.assertEqual(inner['result'][0], 200)
        self.assertEqual(outer[0], 409)
        self.assertNotIn('credential', outer[1])
        self.assertEqual(sorted(r.detail['outcome'].split(':')[0] for r in self.audits()), ['granted', 'refused'])

    def test_the_value_is_not_decrypted_before_the_single_use_is_won(self):
        task = self.task()
        SentinelTask.objects.filter(pk=task.pk).update(secret_read_at=timezone.now())
        with mock.patch.object(sentinels, '_credential_payload') as payload:
            self.assertEqual(self.read('builtin', task)[0], 409)
        payload.assert_not_called()

    def test_reads_are_rate_limited(self):
        limit = sentinels.RATES['secret'][0]
        task = self.task()
        codes = [self.read('builtin', task)[0] for _ in range(limit + 3)]
        self.assertEqual(codes[0], 200)
        self.assertEqual(codes[1:limit], [409] * (limit - 1))
        self.assertEqual(codes[limit:], [429] * 3)
        limited = [r for r in self.audits() if r.detail['outcome'] == 'refused: rate limit']
        self.assertEqual(len(limited), 1)  # one audit row per window, so a flood cannot flood the log
        self.assertNoSecretAnywhere()
