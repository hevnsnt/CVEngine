"""Search abuse found by review 2 of 2026-11-09 (P4 and P5): one bad address row must not break every organization's ``ip:`` search, and a search
must not be able to ask Postgres to plan a query of a million characters."""
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services
from agentapi.services import ApiError
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain


class IpRangeSearchTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org_a = Org.objects.create(name='A', slug='a-hostile')
        self.org_b = Org.objects.create(name='B', slug='b-hostile')
        self.project = Project.objects.create(name='PA', slug='pa-hostile', insert_date=now, org=self.org_a)
        domain = Domain.objects.create(name='a.example', project=self.project)
        engine = EngineType.objects.first() or EngineType.objects.create(engine_name='h', yaml_configuration='{}')
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
        self.hosts = {}
        for name, address in (('v4.a.example', '10.1.2.3'), ('out4.a.example', '192.0.2.9'), ('v6.a.example', '2001:db8::5'), ('out6.a.example', '2001:db9::1')):
            host = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan)
            host.ip_addresses.add(IpAddress.objects.create(address=address, org=self.org_a))
            self.hosts[name] = host
        # rows that are not addresses, in ANOTHER organization and in this one: each made ``address::inet`` raise for every search
        for bad in ('not-an-address', '1.2.3', '999.1.1.1', '01.2.3.4', '1:2:3', 'fe80::1%eth0', '', ' 10.0.0.1', '10.0.0.1/8', 'g::1', '1:2:3:4:5:6:7:8:9'):
            IpAddress.objects.create(address=bad, org=self.org_b)
        IpAddress.objects.create(address='not-an-address', org=self.org_a)
        host = Subdomain.objects.create(name='junk.a.example', target_domain=domain, scan_history=scan)
        host.ip_addresses.add(IpAddress.objects.create(address='10.9.9.9x', org=self.org_a))

    def names(self, value):
        q = services._ip_filter(value)
        return sorted(Subdomain.objects.filter(target_domain__project=self.project).filter(q).values_list('name', flat=True))

    def test_an_ipv4_range_finds_its_hosts_and_ignores_rows_that_are_not_addresses(self):
        self.assertEqual(self.names('10.0.0.0/8'), ['v4.a.example'])
        self.assertEqual(self.names('10.1.2.0/24'), ['v4.a.example'])
        self.assertEqual(self.names('10.1.2.3/32'), ['v4.a.example'])
        self.assertEqual(self.names('192.0.2.0/25'), ['out4.a.example'])
        self.assertEqual(self.names('172.16.0.0/12'), [])
        self.assertEqual(self.names('0.0.0.0/0'), ['out4.a.example', 'v4.a.example'])

    def test_an_ipv6_range_finds_its_hosts_and_ignores_rows_that_are_not_addresses(self):
        self.assertEqual(self.names('2001:db8::/32'), ['v6.a.example'])
        self.assertEqual(self.names('2001:db8::5/128'), ['v6.a.example'])
        self.assertEqual(self.names('::/0'), ['out6.a.example', 'v6.a.example'])


class SearchBudgetTests(SimpleTestCase):
    def test_a_search_that_would_fan_out_into_thousands_of_subqueries_is_refused(self):
        words = ' '.join('tech:' + ','.join('abcdefghijklmno') for _ in range(15))  # 15 terms of 15 values, 524 characters
        with self.assertRaises(ApiError) as caught:
            services.parse_search(words)
        self.assertEqual(caught.exception.status, 400)
        self.assertIn('at most 40 values', caught.exception.message)

    def test_an_ordinary_search_is_not_touched(self):
        terms = services.parse_search('tech:nginx,apache,tomcat port:443,8443 country:US -tech:iis wordpress 7.1 "a phrase, with a comma"')
        self.assertGreaterEqual(len(terms), 6)
        self.assertEqual(len(services.parse_search(' '.join(f'word{i}' for i in range(15)))), 15)
        services.parse_search('tech:' + ','.join(f't{i}' for i in range(15)) + ' port:' + ','.join(str(i) for i in range(15)))  # 30 values: allowed
