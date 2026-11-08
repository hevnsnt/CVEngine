"""The Sentinels page polls every few seconds with 10 to 50 Sentinels (scripts/scale, 3000 targets): what it costs must not grow per Sentinel for facts
that are the same for all of them, and the reads of the task table (30 days of work) must have an index.

Measured on the 3000-target stack, 50 Sentinels, 300,000 task rows: ``/api/v1/sentinels/live`` 326 statements, 570 ms warm; 154 of those statements asked, once
per Sentinel, whether the owner's two-step sign-in is pending (profile, organization and project membership: 3 statements x 51) and the last five finished tasks of
each Sentinel read its whole history (17 ms each).
"""
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_contract
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from agentapi.services import Ctx
from dashboard.models import ProjectMembership
from tests.test_sentinel_capability_policy import PolicyBase


class SentinelPageCostTests(PolicyBase):
    def fleet(self, n):
        """``n`` live Sentinels enrolled by the same person, as a team's fleet is, each with finished work."""
        owner = User.objects.filter(username='fleet-owner').first() or User.objects.create_user('fleet-owner', password='x')
        ProjectMembership.objects.get_or_create(user=owner, project=self.project, defaults={'role': 'user'})
        agents = []
        for i in range(n):
            token, _ = create_token(owner, f'fleet-token-{i}')
            agent = Agent.objects.create(token=token, name=f'fleet-{i}', kind='scanner', status='active', capabilities=['nmap', 'naabu'], last_seen=timezone.now(),
                                         scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, info={'contract_version': sentinel_contract.version()})
            for k in range(3):
                SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=agent, status='done', claimed_at=timezone.now() - timedelta(minutes=k + 5),
                                            accepted_at=timezone.now() - timedelta(minutes=k + 4), finished_at=timezone.now() - timedelta(minutes=k + 3))
            agents.append(agent)
        return agents

    def statements(self):
        with CaptureQueriesContext(connection) as cq:
            out = sb.live_overview(Ctx(user=self.root, token=self.root_token))
        return [q['sql'] for q in cq.captured_queries], out

    def test_the_owners_two_step_check_is_asked_once_for_the_page_not_once_per_sentinel(self):
        self.fleet(12)
        sql, out = self.statements()
        self.assertEqual(len(out['results']), 12)
        asked = [s for s in sql if 'dashboard_orgmembership' in s and 'require_mfa' in s]
        self.assertLessEqual(len(asked), 1, f'{len(asked)} membership checks for 12 Sentinels of one owner')
        self.assertLessEqual(len([s for s in sql if 'FROM "dashboard_userprofile"' in s]), 1)

    def test_each_extra_sentinel_costs_no_more_statements_than_it_does_now(self):
        self.fleet(3)
        few = len(self.statements()[0])
        SentinelTask.objects.all().delete()
        Agent.objects.all().delete()
        self.fleet(11)
        many = len(self.statements()[0])
        self.assertLessEqual((many - few) / 8, 4.6, f'{few} statements for 3 Sentinels, {many} for 11 (it was 6.4 each before the owner check was shared; the rest are the per-Sentinel reads the new indexes make cheap)')


class SentinelTaskIndexTests(PolicyBase):
    def test_the_history_indexes_exist_and_are_partial_where_they_can_be(self):
        with connection.cursor() as c:
            c.execute("select indexname, indexdef from pg_indexes where tablename = 'agentapi_sentineltask'")
            found = dict(c.fetchall())
        done = found['sentineltask_agent_done_idx']
        self.assertIn('agent_id, finished_at DESC, id DESC', done)
        self.assertIn('INCLUDE', done)
        self.assertIn("status", done.split('WHERE')[1])
        self.assertIn('finished_at IS NOT NULL', found['sentineltask_finished_idx'])
        self.assertIn('claimed_at IS NOT NULL', found['sentineltask_claimed_idx'])

    def test_the_last_finished_tasks_of_a_sentinel_are_read_through_the_index(self):
        """With enough rows for the planner to prefer an index, the page's per-Sentinel read stays out of the table's heap order."""
        agent = self.external('Busy')
        rows = [SentinelTask(project=self.project, kind='nmap', target={}, agent=agent, status='done', finished_at=timezone.now() - timedelta(seconds=i)) for i in range(4000)]
        SentinelTask.objects.bulk_create(rows)
        SentinelTask.objects.bulk_create([SentinelTask(project=self.project, kind='nmap', target={}, agent=None, status='queued') for _ in range(2000)])
        with connection.cursor() as c:
            c.execute('ANALYZE agentapi_sentineltask')
            c.execute("EXPLAIN select * from agentapi_sentineltask where agent_id = %s and status in ('done', 'failed') order by finished_at desc, id desc limit 5", [agent.pk])
            plan = '\n'.join(r[0] for r in c.fetchall())
        self.assertIn('sentineltask_agent_done_idx', plan)
        self.assertNotIn('Seq Scan', plan)
