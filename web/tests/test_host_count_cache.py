"""A count-only Hosts or Search request shares its count for a moment (review finding A4).

``hosts?page_size=0`` and ``search?page_size=0`` are the cheap modes for a poll, a palette or a badge, but each ran the one-row-per-host collapse over
the current inventory for its COUNT, on every request. The count is now a ``cveFeed.snapshot_cache`` snapshot keyed by the scope (the project ids and
the caller's allowed projects) and every parameter that narrows the hosts, kept 15 seconds and dropped by a revision bump. A page of hosts is not cached.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class HostCountSnapshotTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Hc', slug='hc-org')
        cls.tokens, cls.domains = {}, {}
        for slug, n in (('hc-a', 7), ('hc-b', 2)):
            project = Project.objects.create(name=slug, slug=slug, insert_date=now, org=org)
            domain = Domain.objects.create(name=f'{slug}.test', project=project, insert_date=now)
            for i in range(n):
                sub = Subdomain.objects.create(target_domain=domain, name=f'h{i}.{slug}.test', score=i % 3)
                sub.ip_addresses.add(IpAddress.objects.create(address=f'192.0.{2 if slug == "hc-a" else 3}.{i + 1}'))
            user = User.objects.create_user(f'{slug}-user', password='x')
            ProjectMembership.objects.create(user=user, project=project, role='user')
            cls.tokens[slug], cls.domains[slug] = create_token(user, 'agent')[1], domain

    def setUp(self):
        cache.clear()  # the counts are a shared snapshot: a test must not read another one's

    def get(self, slug, path):
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.tokens[slug], 'GET', f'/api/v1/projects/{slug}/{path}')
        self.assertEqual(status, 200, body)
        return body, sum(1 for q in ctx.captured_queries if 'ROW_NUMBER()' in q['sql'])  # the collapse

    def test_a_second_count_only_poll_does_not_run_the_collapse(self):
        for path in ('hosts?page_size=0', 'search?page_size=0'):
            with self.subTest(path=path):
                first, collapsed = self.get('hc-a', path)
                self.assertEqual((first['count'], first['results']), (7, []))
                self.assertGreaterEqual(collapsed, 1)
                again, collapsed = self.get('hc-a', path)
                self.assertEqual((again, collapsed), (first, 0))

    def test_each_scope_and_each_filter_has_its_own_count(self):
        self.get('hc-a', 'search?page_size=0')
        self.get('hc-a', 'hosts?page_size=0')
        self.assertEqual(self.get('hc-b', 'search?page_size=0')[0]['count'], 2)
        self.assertEqual(self.get('hc-b', 'hosts?page_size=0')[0]['count'], 2)
        self.assertEqual(self.get('hc-a', 'search?page_size=0&q=ip:192.0.2.1')[0]['count'], 1)
        self.assertEqual(self.get('hc-a', 'search?page_size=0&names=h1.hc-a.test,h2.hc-a.test')[0]['count'], 2)
        self.assertEqual(self.get('hc-a', 'hosts?page_size=0&q=h3.')[0]['count'], 1)
        self.assertEqual(self.get('hc-a', f'hosts?page_size=0&target_id={self.domains["hc-b"].pk}')[0]['count'], 0)
        self.assertEqual(self.get('hc-a', 'search?page_size=0&archived=only')[0]['count'], 0)

    def test_a_page_of_hosts_counts_afresh(self):
        self.assertEqual(self.get('hc-a', 'hosts?page_size=3')[0]['count'], 7)
        Subdomain.objects.create(target_domain=self.domains['hc-a'], name='new.hc-a.test')
        for path in ('hosts?page_size=3', 'search?page_size=3&facets=none'):
            self.assertEqual(self.get('hc-a', path)[0]['count'], 8)

    def test_a_bad_sort_is_still_refused_in_the_count_only_mode(self):
        self.assertEqual(call(self.tokens['hc-a'], 'GET', '/api/v1/projects/hc-a/hosts?page_size=0&sort=bogus')[0], 400)
