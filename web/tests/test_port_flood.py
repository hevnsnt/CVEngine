"""cveFeed.port_flood.findings_for counts only the checked domain's own addresses, and counts each port once."""
from django.test import TestCase
from django.utils import timezone

from cveFeed import port_flood
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain


class PortFloodTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='PF', slug='pf')
        project = Project.objects.create(name='PF', slug='pfp', insert_date=now, org=org)
        self.one = Domain.objects.create(name='one.example.test', project=project, insert_date=now)
        self.two = Domain.objects.create(name='two.example.test', project=project, insert_date=now)

    def flooded_address(self, address, ports):
        ip = IpAddress.objects.create(address=address)
        for number in range(1, ports + 1):
            ip.ports.add(Port.objects.create(number=number, state='open', protocol='tcp'))
        return ip

    def host(self, domain, name, ip):
        sub = Subdomain.objects.create(name=name, target_domain=domain)
        sub.ip_addresses.add(ip)
        return sub

    def test_a_flooded_address_is_found_for_its_own_domain_only(self):
        ip = self.flooded_address('192.0.2.10', port_flood.THRESHOLD + 5)
        self.host(self.one, 'a.one.example.test', ip)
        self.host(self.two, 'b.two.example.test', IpAddress.objects.create(address='192.0.2.11'))
        self.assertEqual([f.host for f in port_flood.findings_for(self.one)], ['a.one.example.test'])
        self.assertEqual(port_flood.findings_for(self.two), [])

    def test_hosts_sharing_an_address_do_not_multiply_its_port_count(self):
        """99 open ports on one address shared by three hosts is 99, not 297: under the threshold, no finding."""
        ip = self.flooded_address('192.0.2.12', port_flood.THRESHOLD - 1)
        for name in ('a', 'b', 'c'):
            self.host(self.one, f'{name}.one.example.test', ip)
        self.assertEqual(port_flood.findings_for(self.one), [])

    def test_an_address_two_domains_share_is_found_for_each(self):
        ip = self.flooded_address('192.0.2.13', port_flood.THRESHOLD)
        self.host(self.one, 'a.one.example.test', ip)
        self.host(self.two, 'a.two.example.test', ip)
        self.assertEqual(len(port_flood.findings_for(self.one)), 1)
        self.assertEqual(len(port_flood.findings_for(self.two)), 1)
