"""A search page says why each row matched; the route and web-archive evidence it reads is looked up once for the page, not once per row
(100 extra queries on a 50-row page of ``q=nginx``)."""
from django.contrib.auth.models import User
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import HostArchive, RouteAuth
from dashboard.models import Org, Project
from reNgine import input_guard, ip_allowlist
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class MatchedReasonsTests(TestCase):
    HOSTS = 12

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='M', slug='sm', insert_date=now, org=Org.objects.create(name='M', slug='sm-org'))
        cls.domain = Domain.objects.create(name='sm.example.test', project=cls.project, insert_date=now)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=EngineType.objects.create(engine_name='sm'), start_scan_date=now, scan_status=2)
        for i in range(cls.HOSTS):
            cls.add(i)
        _, cls.token = create_token(User.objects.create_user('sm-root', password='x', is_superuser=True), 'sm')

    @classmethod
    def add(cls, i):
        name = f'm{i}.sm.example.test'
        sub = Subdomain.objects.create(name=name, target_domain=cls.domain, scan_history=cls.scan, http_status=200)
        sub.ip_addresses.add(IpAddress.objects.create(address=f'192.0.2.{i + 1}'))
        RouteAuth.objects.create(project=cls.project, domain=cls.domain, host=name, url=f'https://{name}/', path='/', auth_state='open',
                                 evidence={'server': 'nginx/1.18', 'cookies': ['nginxsess']})
        HostArchive.objects.create(project=cls.project, domain=cls.domain, host=name, technologies={'nginx': {'count': 3}, 'php': {'count': 1}})

    def setUp(self):
        cache.clear()
        # The perimeter middleware keeps two answers per process for 10 s of wall clock (the IP allowlist switch, the banned addresses),
        # filled by whichever request comes first after they lapse. A 10 s window that ended between the readings of the cost test
        # put 2 queries on one reading and not the other (43 != 45, or the reverse, in about 1 run in 20 that crossed one).
        # Hold both for the whole test: dropped now, read once by the first request, and a clock they cannot see move.
        for guard in (ip_allowlist, input_guard):
            guard.invalidate_cache()
            self.addCleanup(guard.invalidate_cache)
            patcher = mock.patch.object(guard, 'time', mock.Mock(time=lambda: 1e9))
            patcher.start()
            self.addCleanup(patcher.stop)

    def search(self, q):
        with CaptureQueriesContext(connection) as queries:
            status, data = call(self.token, 'GET', f'/api/v1/projects/sm/search?q={q}&facets=none&page_size=50')
        self.assertEqual(status, 200, data)
        self.last_sql = [q['sql'][:160] for q in queries.captured_queries]
        return data, len(queries)

    def test_the_reasons_name_the_route_headers_cookies_and_the_archive(self):
        data, _ = self.search('nginx')
        self.assertEqual(data['count'], self.HOSTS)
        for row in data['results']:
            self.assertIn('Server header nginx/1.18', row['matched'])
            self.assertIn('cookie nginxsess', row['matched'])
            self.assertIn('seen in web archive: nginx (3 URLs)', row['matched'])
            self.assertNotIn('seen in web archive: php (1 URLs)', row['matched'])

    def test_the_cost_does_not_grow_with_the_rows_of_the_page(self):
        # Both readings are of a warm cache: the first search of each state fills it and is thrown away. The version that read the first
        # state warm and the second straight after cache.clear() compared a warm page with a partly cold one, and the few queries a cold
        # cache costs (settings, tunables) made them differ by chance, which failed CI now and then. What must hold is that 20 more rows
        # add no queries.
        self.search('nginx')
        _, base = self.search('nginx')
        base_sql = self.last_sql
        for i in range(self.HOSTS, self.HOSTS + 20):
            self.add(i)
        cache.clear()
        self.search('nginx')
        data, more = self.search('nginx')
        self.assertEqual(data['count'], self.HOSTS + 20)
        from collections import Counter
        extra = list((Counter(self.last_sql) - Counter(base_sql)).elements())
        self.assertEqual(base, more, f'queries only the second reading made: {extra}')

