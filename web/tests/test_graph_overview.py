from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed.graph_overview import root_for
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for


class GraphOverviewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Graph org', slug='graph-org')
        cls.project = Project.objects.create(name='North', slug='graph-north', org=org, insert_date=now)
        cls.other = Project.objects.create(name='South', slug='graph-south', insert_date=now)
        cls.a = Domain.objects.create(name='example.co.uk', project=cls.project, insert_date=now)
        cls.b = Domain.objects.create(name='other.example.co.uk', project=cls.project, insert_date=now)
        cls.secret = Domain.objects.create(name='secret.test', project=cls.other, insert_date=now)
        cls.host = Subdomain.objects.create(name='api.example.co.uk', target_domain=cls.a)
        Subdomain.objects.create(name='api.example.co.uk', target_domain=cls.a)  # scanless duplicate inventory
        cls.host.ip_addresses.add(IpAddress.objects.create(address='192.0.2.5'))
        cls.extra = Subdomain.objects.create(name='web.other.example.co.uk', target_domain=cls.b)
        Subdomain.objects.create(name='private.secret.test', target_domain=cls.secret)
        Vulnerability.objects.create(name='Open scanner finding', severity=3, target_domain=cls.a,
                                     subdomain=cls.host, open_status=True)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-31')
        CVEMatch.objects.create(cve_entry=cve, subdomain=cls.host, matched_product='fixture')
        cls.viewer = User.objects.create_user('graph-viewer', password='x')
        ProjectMembership.objects.create(user=cls.viewer, project=cls.project, role='audit')

    def test_root_grouping_respects_registrable_domain_and_host_scope(self):
        self.assertEqual(root_for(self.a), 'example.co.uk')
        self.assertEqual(root_for(self.b), 'example.co.uk')
        self.b.scope_mode = Domain.SCOPE_HOST
        self.assertEqual(root_for(self.b), 'other.example.co.uk')

    def test_bubble_graph_groups_only_authorized_project_domains(self):
        client = client_for(self.viewer)
        response = client.get('/cve/api/graph', {'project': '_all'})
        self.assertEqual(response.status_code, 200)
        domains = [node for node in response.json()['nodes'] if node['kind'] == 'domain']
        self.assertTrue(domains)
        self.assertEqual({node['project'] for node in domains}, {self.project.slug})
        self.assertEqual({node['project_name'] for node in domains}, {self.project.name})
        self.assertEqual({node['root'] for node in domains}, {'example.co.uk'})
        self.assertNotIn('secret.test', {node['label'] for node in domains})
        self.assertEqual(client.get('/cve/api/graph', {'project': self.other.slug}).status_code, 404)
