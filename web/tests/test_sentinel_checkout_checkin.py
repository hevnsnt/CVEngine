"""Check-out and check-in, one property at a time (1.4.0 tool review): a task is claimed by one Sentinel only, and its result is accepted from that
Sentinel only, once, while its lease is alive. Every refusal is a plain answer and leaves the task and the data as they were."""
from datetime import timedelta

from django.utils import timezone

from agentapi import sentinel_broker as sentinels
from agentapi.auth import create_token
from agentapi.models import SentinelTask
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from tests.test_agentapi import call
from tests.test_sentinels import SentinelBase, register_sentinel

NMAP_HOST = {'ip': '192.0.2.50', 'os_guess': 'Linux', 'ports': [{'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh'}]}


class CheckOutCheckIn(SentinelBase):
    def setUp(self):
        super().setUp()
        from django.contrib.auth.models import User
        from tests.test_sentinels import reset_rates
        self.carol = User.objects.create_user('s_carol', password='x')  # a second Sentinel owner in the same project
        OrgMembership.objects.create(user=self.carol, org=self.org1, role='admin')
        self.bob = User.objects.create_user('s_bob', password='x')  # another tenant's
        OrgMembership.objects.create(user=self.bob, org=self.org2, role='admin')
        ProjectMembership.objects.create(user=self.bob, project=self.pb, role='user')
        self.t = {**self.tokens, 'carol': create_token(self.carol, 'carol')[1], 'bob': create_token(self.bob, 'bob')[1]}
        reset_rates(self.t)
        caps = ['nmap', 'naabu', 'nuclei_light', 'wpscan']
        self.a = register_sentinel(self.t['dana'], name='sentinel-a', capabilities=caps)[1]
        self.b = register_sentinel(self.t['carol'], name='sentinel-b', capabilities=caps)[1]
        self.other = register_sentinel(self.t['bob'], name='sentinel-other-tenant', scope={'projects': ['sen-b']}, capabilities=caps)[1]
        self.task = SentinelTask.objects.create(project=self.pa, scan=self.scan, kind='nmap', target={'addresses': ['192.0.2.50']}, host='www.a.example',
                                                ips=['192.0.2.50'])

    def claim(self, who='dana'):
        return call(self.t[who], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})[1]['task']

    def url(self, what):
        return f'/api/v1/sentinel/tasks/{self.task.pk}/{what}'

    def test_a_task_is_claimed_by_one_sentinel_only(self):
        self.assertEqual(self.claim('dana')['id'], self.task.pk)
        self.assertIsNone(self.claim('carol'))  # the other Sentinel of the project is offered nothing
        self.assertIsNone(self.claim('bob'))
        self.task.refresh_from_db()
        self.assertEqual((self.task.status, self.task.agent_id, self.task.attempts), ('claimed', self.a['id'], 1))

    def test_a_second_claim_of_the_same_row_loses(self):
        """The claim is a conditional update on status=queued, so two Sentinels that both read it as queued cannot both own it."""
        won = SentinelTask.objects.filter(pk=self.task.pk, status='queued').update(status='claimed', agent_id=self.a['id'])
        lost = SentinelTask.objects.filter(pk=self.task.pk, status='queued').update(status='claimed', agent_id=self.b['id'])
        self.assertEqual((won, lost), (1, 0))

    def test_another_sentinel_of_the_project_can_neither_accept_nor_report_nor_release_it(self):
        self.claim('dana')
        for who in ('carol', 'bob'):
            self.assertEqual(call(self.t[who], 'POST', self.url('accept'))[0], 404, who)
            self.assertEqual(call(self.t[who], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})[0], 404, who)
            self.assertEqual(call(self.t[who], 'POST', self.url('release'), {'reason': 'mine'})[0], 404, who)
        self.task.refresh_from_db()
        self.assertEqual((self.task.status, self.task.agent_id, self.task.result), ('claimed', self.a['id'], {}))

    def test_a_task_of_another_tenant_is_not_found_for_a_sentinel_that_never_saw_it(self):
        theirs = SentinelTask.objects.create(project=self.pb, kind='nmap', target={'addresses': ['192.0.2.77']}, host='b', ips=['192.0.2.77'])
        self.assertEqual(self.claim('bob')['id'], theirs.pk)
        for who in ('dana', 'carol'):
            self.assertEqual(call(self.t[who], 'POST', f'/api/v1/sentinel/tasks/{theirs.pk}/result', {'outcome': 'done', 'hosts': []})[0], 404, who)
        theirs.refresh_from_db()
        self.assertEqual((theirs.status, theirs.agent_id), ('claimed', self.other['id']))

    def test_a_replayed_result_changes_nothing(self):
        self.claim('dana')
        call(self.t['dana'], 'POST', self.url('accept'))
        status, first = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})
        self.assertEqual((status, first['duplicate']), (200, False))
        stored = SentinelTask.objects.get(pk=self.task.pk)
        other_host = {**NMAP_HOST, 'ip': '192.0.2.51'}
        status, again = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [other_host]})
        self.assertEqual((status, again['duplicate']), (200, True))
        after = SentinelTask.objects.get(pk=self.task.pk)
        self.assertEqual((after.result, after.finished_at, after.status), (stored.result, stored.finished_at, 'done'))
        status, failed = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'error', 'error': 'late'})  # a replay saying error never turns done into failed
        self.assertEqual(SentinelTask.objects.get(pk=self.task.pk).status, 'done')

    def test_a_result_after_the_lease_ran_out_is_discarded_and_stores_nothing(self):
        self.claim('dana')
        call(self.t['dana'], 'POST', self.url('accept'))
        SentinelTask.objects.filter(pk=self.task.pk).update(lease_expires_at=timezone.now() - timedelta(seconds=5))
        status, out = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})
        self.assertEqual((status, out['duplicate'], out['late']), (200, True, True))  # the report call first expires the lapsed lease, then says late
        task = SentinelTask.objects.get(pk=self.task.pk)
        self.assertEqual((task.status, task.result), ('expired', {}))  # nothing stored: the targets stay due

    def test_a_result_after_the_task_expired_is_discarded_and_marked_late(self):
        self.claim('dana')
        call(self.t['dana'], 'POST', self.url('accept'))
        sentinels.expire(self.task, 'the dispatch wait timed out')
        status, out = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})
        self.assertEqual((status, out['duplicate'], out['late']), (200, True, True))
        task = SentinelTask.objects.get(pk=self.task.pk)
        self.assertEqual((task.status, task.result), ('expired', {}))

    def test_a_result_for_a_host_the_task_did_not_name_is_cut_to_the_task(self):
        self.claim('dana')
        call(self.t['dana'], 'POST', self.url('accept'))
        stranger = {**NMAP_HOST, 'ip': '192.0.2.99'}
        status, out = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST, stranger]})
        self.assertEqual(status, 200)
        task = SentinelTask.objects.get(pk=self.task.pk)
        self.assertEqual([h['ip'] for h in task.result['hosts']], ['192.0.2.50'])
        self.assertEqual(task.result.get('dropped'), 1)

    def test_a_released_task_is_ended_and_its_late_result_is_discarded(self):
        self.claim('dana')
        call(self.t['dana'], 'POST', self.url('accept'))
        self.assertEqual(call(self.t['dana'], 'POST', self.url('release'), {'reason': 'restart'})[0], 200)
        task = SentinelTask.objects.get(pk=self.task.pk)
        self.assertEqual((task.status, task.agent_id), ('expired', None))  # the stage that waited for it dispatches again: the broker never requeues
        status, out = call(self.t['dana'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})
        self.assertEqual((status, out['late']), (200, True))
        self.assertEqual(SentinelTask.objects.get(pk=self.task.pk).result, {})
        self.assertEqual(call(self.t['carol'], 'POST', self.url('result'), {'outcome': 'done', 'hosts': [NMAP_HOST]})[0], 404)  # nor can another Sentinel file it
