from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import counts, views
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from startScan.models import IpAddress, Subdomain, Vulnerability
from targetApp.models import Domain


class GraphCapTests(TestCase):
    def setUp(self):
        cache.clear()
        now = timezone.now()
        project = Project.objects.create(name='C', slug='cap', insert_date=now, org=Org.objects.create(name='C', slug='cap-org'))
        self.domain = Domain.objects.create(name='cap.test', project=project, insert_date=now)
        for i in range(30):
            sub = Subdomain.objects.create(target_domain=self.domain, name=f'h{i:02d}.cap.test', score=i)
            sub.ip_addresses.add(IpAddress.objects.create(address=f'192.0.2.{i + 1}'))

    def hosts(self, payload):
        return {n['label'] for n in payload['nodes'] if n['kind'] == 'subdomain'}

    def test_past_the_node_cap_the_highest_scored_hosts_are_drawn_and_the_total_is_reported(self):
        with mock.patch.object(views, 'GRAPH_NODE_CAP', 20):
            payload = views.graph_payload()
        drawn = self.hosts(payload)
        self.assertEqual(payload['hosts']['drawn'], len(drawn))
        self.assertEqual(payload['hosts']['total'], 30)
        self.assertLess(len(drawn), 30)
        self.assertIn('h29.cap.test', drawn)  # the top score is always in; the lowest is what the cap drops
        self.assertNotIn('h00.cap.test', drawn)
        with mock.patch.object(views, 'GRAPH_NODE_CAP', 20):
            self.assertEqual(self.hosts(views.graph_payload()), drawn)  # the same hosts on every poll

    def test_under_the_cap_every_host_is_drawn_and_there_is_nothing_to_report(self):
        payload = views.graph_payload()
        self.assertEqual(payload['hosts'], {'drawn': 30, 'total': 30})


class ExposedHostCountTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='E', slug='exp-org')
        self.p1 = Project.objects.create(name='E1', slug='exp1', insert_date=now, org=org)
        self.p2 = Project.objects.create(name='E2', slug='exp2', insert_date=now, org=org)
        self.d1 = Domain.objects.create(name='one.test', project=self.p1, insert_date=now)
        self.d2 = Domain.objects.create(name='two.test', project=self.p2, insert_date=now)

    def test_a_finding_on_a_name_does_not_expose_the_same_name_in_another_project(self):
        a = Subdomain.objects.create(target_domain=self.d1, name='www.shared.test')
        Subdomain.objects.create(target_domain=self.d2, name='www.shared.test')
        Vulnerability.objects.create(subdomain=a, name='v', severity=3)
        self.assertEqual(counts.exposed_host_count(), 1)

    def test_a_finding_on_one_name_exposes_the_host_whose_other_name_shares_its_address(self):
        ip = IpAddress.objects.create(address='192.0.2.50')
        bare = Subdomain.objects.create(target_domain=self.d1, name='one.test')
        www = Subdomain.objects.create(target_domain=self.d1, name='www.one.test')
        bare.ip_addresses.add(ip)
        www.ip_addresses.add(ip)
        Vulnerability.objects.create(subdomain=www, name='v', severity=3)
        self.assertEqual(counts.exposed_host_count(), 1)  # one machine, exposed through either name

    def test_a_ruled_out_match_exposes_nothing(self):
        sub = Subdomain.objects.create(target_domain=self.d1, name='clean.one.test')
        cve = CVEEntry.objects.create(cve_id='CVE-2099-71', affected=[])
        CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='x', ai_verdict='not_affected')
        self.assertEqual(counts.exposed_host_count(), 0)
