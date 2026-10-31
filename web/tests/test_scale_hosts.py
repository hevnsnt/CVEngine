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


class OnePerHostTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='O', slug='oph-org')
        self.p1 = Project.objects.create(name='P1', slug='oph1', insert_date=now, org=org)
        self.p2 = Project.objects.create(name='P2', slug='oph2', insert_date=now, org=org)
        self.d1 = Domain.objects.create(name='site.test', project=self.p1, insert_date=now)
        self.d2 = Domain.objects.create(name='other.test', project=self.p2, insert_date=now)

    def reps(self, **kwargs):
        from agentapi import services
        from startScan.models import Subdomain as S
        return set(services._one_per_host(S.objects.all(), **kwargs).values_list('name', flat=True))

    def test_the_host_ids_are_looked_up_in_an_array_and_not_in_a_subquery_postgres_rescans(self):
        from agentapi import services
        sql = str(services._one_per_host(Subdomain.objects.all()).query)
        self.assertRegex(sql, r'"id" = ANY\(+ARRAY\(')  # id IN (subquery) took 4.8 s at 10,000 hosts, the array 0.1 s

    def test_two_names_on_one_address_are_one_host_and_the_project_own_name_is_the_one_kept(self):
        ip = IpAddress.objects.create(address='192.0.2.77')
        for name in ('www.site.test', 'site.test'):
            Subdomain.objects.create(target_domain=self.d1, name=name).ip_addresses.add(ip)
        self.assertEqual(self.reps(), {'site.test'})

    def test_the_same_name_in_two_projects_is_two_hosts_in_the_all_projects_view(self):
        Subdomain.objects.create(target_domain=self.d1, name='shared.test')
        Subdomain.objects.create(target_domain=self.d2, name='shared.test')
        from startScan.models import Subdomain as S
        from agentapi import services
        self.assertEqual(services._one_per_host(S.objects.all(), per_project=True).count(), 2)

    def test_a_name_without_an_address_stands_alone(self):
        Subdomain.objects.create(target_domain=self.d1, name='a.site.test')
        Subdomain.objects.create(target_domain=self.d1, name='b.site.test')
        self.assertEqual(self.reps(), {'a.site.test', 'b.site.test'})
