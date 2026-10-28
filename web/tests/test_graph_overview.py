from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed.graph_overview import groups, root_for
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

    def test_overview_counts_distinct_hosts_and_keeps_unscanned_visible(self):
        data = groups(self.project.slug)
        self.assertEqual((data['targets'], data['hosts']), (2, 2))
        root = data['projects'][0]['roots'][0]
        self.assertEqual((root['targets'], root['hosts'], root['findings'], root['cve_candidates']), (2, 2, 1, 1))
        self.assertEqual(root['assessed'], 0)

    def test_a_light_only_nuclei_pass_counts_the_host_as_assessed(self):
        # Most hosts only ever get the light pass (the AI-targeted pass is gated on there being something worth
        # targeting), so a host must count as assessed from that alone, not only once a targeted pass also ran.
        from scanEngine.models import EngineType
        from startScan.models import ScanActivity, ScanHistory
        engine = EngineType.objects.create(engine_name='graph-light', yaml_configuration='x')
        scan = ScanHistory.objects.create(domain=self.extra.target_domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
        self.extra.scan_history = scan
        self.extra.save(update_fields=['scan_history'])
        ScanActivity.objects.create(scan_of=scan, name='nuclei_light_scan', status=2, time=timezone.now())
        self.assertEqual(groups(self.project.slug)['projects'][0]['roots'][0]['assessed'], 1)

    def test_http_scope_and_lazy_host_page(self):
        client = client_for(self.viewer)
        overview = client.get('/cve/api/graph-overview?project=_all')
        self.assertEqual(overview.status_code, 200)
        self.assertEqual([p['slug'] for p in overview.json()['projects']], [self.project.slug])
        root = overview.json()['projects'][0]['roots'][0]['root']
        page = client.get('/cve/api/graph-hosts', {'project': '_all', 'owner': self.project.slug, 'root': root})
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.json()['count'], 2)
        self.assertIn('api.example.co.uk', {item['host'] for item in page.json()['results']})
        self.assertEqual(client.get('/cve/api/graph-hosts', {
            'project': '_all', 'owner': self.other.slug, 'root': 'secret.test'}).status_code, 404)
        self.assertEqual(client.get('/cve/api/graph-hosts', {
            'project': self.project.slug, 'owner': self.other.slug, 'root': 'secret.test'}).status_code, 404)
        self.assertEqual(client.get('/cve/api/graph-overview', {'project': self.other.slug}).status_code, 404)
        self.assertEqual(client.get('/cve/api/graph-hosts', {
            'project': '_all', 'owner': self.project.slug, 'root': root, 'page': 'bad'}).status_code, 400)

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

    def test_overview_is_not_limited_by_force_graph_node_cap(self):
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.example.co.uk', target_domain=self.a)
                                       for i in range(1510)])
        data = groups(self.project.slug)
        self.assertEqual(data['hosts'], 1512)
        client = client_for(self.viewer)
        first = client.get('/cve/api/graph-hosts', {
            'project': '_all', 'owner': self.project.slug, 'root': 'example.co.uk', 'page': 1}).json()
        self.assertEqual(len(first['results']), 100)
        self.assertTrue(first['has_more'])
        last = client.get('/cve/api/graph-hosts', {
            'project': '_all', 'owner': self.project.slug, 'root': 'example.co.uk', 'page': 16}).json()
        self.assertEqual(len(last['results']), 12)
        self.assertFalse(last['has_more'])
        found = client.get('/cve/api/graph-hosts', {
            'project': '_all', 'owner': self.project.slug, 'root': 'example.co.uk', 'q': 'h1509'}).json()
        self.assertEqual([row['host'] for row in found['results']], ['h1509.example.co.uk'])
