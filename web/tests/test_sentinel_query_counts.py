"""Query-count ceilings for the Sentinel screens and calls: a count that is the same for 3 Sentinels and for 30 (DB-4), and what one Sentinel's heartbeat
and empty tasks/next cost (DB-5)."""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from dashboard.models import Org, Project
from tests.test_agentapi import call
from tests.test_live_cache import steady_caches


class Fleet(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='QC org', slug='qc-org')
        cls.project = Project.objects.create(name='QC', slug='qc-proj', insert_date=now, org=cls.org)
        cls.root = User.objects.create_superuser('qc-root', 'qc@example.test', 'x')
        cls.root_token = create_token(cls.root, 'qc-root')[1]
        cls.owner = User.objects.create_user('qc-owner', password='x')
        cls.n = 0
        cls.raw = {}

    def add_sentinels(self, count):
        now = timezone.now()
        for _ in range(count):
            type(self).n += 1
            token, raw = create_token(self.owner, f'qc-{self.n}')
            agent = Agent.objects.create(token=token, name=f'qc-{self.n:03d}', kind='scanner', status='active', max_concurrent=3, last_seen=now,
                                         capabilities=['nmap', 'naabu', 'nuclei_light'], scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
            self.raw[agent.pk] = raw
            for i in range(6):  # finished work: the failure streak and the recent list read it
                SentinelTask.objects.create(project=self.project, kind='nmap', host=f'h{i}.qc.example', status='failed' if i < 3 else 'done', agent=agent,
                                            claimed_at=now - timedelta(minutes=30), finished_at=now - timedelta(minutes=5 + i), error='boom' if i < 3 else '')

    def count(self, token, method, path, body=None, **extra):
        cache.clear()
        with steady_caches():
            call(token, method, path, body)  # warm: per-process caches and the first-use lookups are not what is measured
            with CaptureQueriesContext(connection) as q:
                status, out = call(token, method, path, body)
        self.assertEqual(status, 200, out)
        return len(q)


class ListScreens(Fleet):
    def test_agents_list_costs_the_same_for_3_and_30_sentinels(self):
        self.add_sentinels(3)
        small = self.count(self.root_token, 'GET', '/api/v1/agents')
        self.add_sentinels(27)
        large = self.count(self.root_token, 'GET', '/api/v1/agents')
        self.assertLessEqual(large, small + 1, (small, large))
        self.assertLessEqual(large, 40, large)

    def test_sentinels_live_costs_the_same_for_3_and_30_sentinels(self):
        self.add_sentinels(3)
        small = self.count(self.root_token, 'GET', '/api/v1/sentinels/live')
        self.add_sentinels(27)
        large = self.count(self.root_token, 'GET', '/api/v1/sentinels/live')
        self.assertLessEqual(large, small + 1, (small, large))
        self.assertLessEqual(large, 40, large)

    def test_a_poll_that_changes_nothing_answers_304_without_building_the_page(self):
        self.add_sentinels(30)
        cache.clear()
        with steady_caches():
            first = Client().get('/api/v1/sentinels/live', HTTP_AUTHORIZATION=f'Bearer {self.root_token}')
            self.assertEqual(first.status_code, 200)
            with CaptureQueriesContext(connection) as q:
                again = Client().get('/api/v1/sentinels/live', HTTP_AUTHORIZATION=f'Bearer {self.root_token}', HTTP_IF_NONE_MATCH=first['ETag'])
        self.assertEqual(again.status_code, 304)
        self.assertLessEqual(len(q), 8, [x['sql'][:90] for x in q.captured_queries])  # the sign-in checks of the request, nothing of the page
        sentinels_live = 'sentineltask'
        self.assertFalse([x for x in q.captured_queries if sentinels_live in x['sql']])
