"""The live ticker's counts (hosts, addresses, open ports) cost a fixed handful of queries however many hosts there are, and count each
address and port once however many hosts share it (a nested IN-subquery planned three times was 0.7 s at 3000 hosts)."""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import views
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain


class DiscoveryCountsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='D', slug='dc', insert_date=now, org=Org.objects.create(name='D', slug='dc-org'))
        cls.domain = Domain.objects.create(name='dc.example.test', project=cls.project, insert_date=now)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=EngineType.objects.create(engine_name='dc'), start_scan_date=now, scan_status=2)
        cls.shared = IpAddress.objects.create(address='192.0.2.250')
        cls.shared.ports.add(Port.objects.create(number=443, service_name='https', state='open'), Port.objects.create(number=22, service_name='ssh', state='closed'))
        cls.next_ip = 0

    def host(self, name, shared=False, status=0):
        sub = Subdomain.objects.create(name=f'{name}.dc.example.test', target_domain=self.domain, scan_history=self.scan, http_status=status)
        if shared:
            sub.ip_addresses.add(self.shared)
        elif status == 0:
            DiscoveryCountsTests.next_ip += 1
            ip = IpAddress.objects.create(address=f'198.51.100.{self.next_ip}')
            ip.ports.add(Port.objects.create(number=8000 + self.next_ip, service_name='http', state='open'))
            sub.ip_addresses.add(ip)
        return sub

    def counts(self):
        with CaptureQueriesContext(connection) as q:
            return views.discovery_counts(), len(q)

    def test_each_address_and_open_port_is_counted_once_and_dead_hosts_not_at_all(self):
        self.host('a', shared=True)
        self.host('b', shared=True)
        self.host('c')
        self.host('web', status=200)
        self.host('dead')  # no address, no answer: not a live host
        Subdomain.objects.filter(name='dead.dc.example.test').first().ip_addresses.clear()
        counts, _ = self.counts()
        # a and b answer on the same address, so they are one host (the Hosts page's row); 443 on it and c's own port, not the closed 22
        self.assertEqual(counts, {'hosts': 3, 'ips': 2, 'ports': 2})

    def test_the_cost_does_not_grow_with_the_hosts(self):
        for i in range(5):
            self.host(f'h{i}')
        _, few = self.counts()
        for i in range(5, 40):
            self.host(f'h{i}')
        counts, many = self.counts()
        self.assertEqual(counts['hosts'], 40)
        self.assertEqual(few, many)
        self.assertLessEqual(many, 6)
