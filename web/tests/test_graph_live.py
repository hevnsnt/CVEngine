from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import counts, graph_live
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_tenancy import client_for


class GraphLiveTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Live org', slug='live-org')
        cls.north = Project.objects.create(name='North', slug='live-north', org=org, insert_date=now)
        cls.south = Project.objects.create(name='South', slug='live-south', insert_date=now)
        cls.da = Domain.objects.create(name='north.example', project=cls.north, insert_date=now)
        cls.db = Domain.objects.create(name='north2.example', project=cls.north, insert_date=now)
        cls.ds = Domain.objects.create(name='south.example', project=cls.south, insert_date=now)
        engine = EngineType.objects.create(engine_name='live-engine', yaml_configuration='x')

        def scan(domain, status, minutes_ago=1):
            return ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=status,
                                              start_scan_date=now - timedelta(minutes=minutes_ago))
        cls.running = scan(cls.da, 1)
        cls.other_running = scan(cls.db, 1)
        cls.south_running = scan(cls.ds, 1)
        cls.done = scan(cls.da, 2)
        cls.queued = scan(cls.da, -1)
        cls.stalled = scan(cls.db, 1, minutes_ago=counts.RUNNING_WINDOW.total_seconds() // 60 + 30)
        ScanActivity.objects.create(scan_of=cls.running, title='Port scan', name='nmap_scan', time=now, status=2)
        ScanActivity.objects.create(scan_of=cls.running, title='Nuclei scan', name='nuclei_scan', time=now, status=1)
        Subdomain.objects.create(name='WWW.north.example', target_domain=cls.da, scan_history=cls.running)
        Subdomain.objects.create(name='api.north.example', target_domain=cls.da, scan_history=cls.running)
        Subdomain.objects.create(name='old.north.example', target_domain=cls.da, scan_history=cls.done)
        cls.viewer = User.objects.create_user('live-viewer', password='x')
        ProjectMembership.objects.create(user=cls.viewer, project=cls.north, role='audit')
        cls.root = User.objects.create_superuser('live-root', 'r@x.io', 'x')

    def test_only_running_scans_with_their_step_and_hosts(self):
        data = graph_live.live()
        by_id = {s['id']: s for s in data['scans']}
        self.assertEqual(set(by_id), {self.running.id, self.other_running.id, self.south_running.id})  # not done, queued or stalled
        self.assertEqual(by_id[self.running.id]['stage'], 'Nuclei scan')  # the step running now, not the finished one
        self.assertEqual(by_id[self.other_running.id]['stage'], '')
        self.assertEqual((by_id[self.running.id]['domain'], by_id[self.running.id]['project']), ('north.example', 'live-north'))
        self.assertGreaterEqual(by_id[self.running.id]['elapsed'], 59)
        self.assertEqual(data['hosts'], ['api.north.example', 'www.north.example'])  # lower-cased, only the running scan's rows
        self.assertEqual(data['domains'], sorted({self.da.id, self.db.id, self.ds.id}))
        self.assertEqual(data['counts'], {'running': 3, 'queued': 1})

    def test_project_and_domain_narrow_it(self):
        self.assertEqual({s['project'] for s in graph_live.live('live-north')['scans']}, {'live-north'})
        self.assertEqual(graph_live.live('live-north')['counts'], {'running': 2, 'queued': 1})
        one = graph_live.live(domain_id=self.db.id)
        self.assertEqual([s['id'] for s in one['scans']], [self.other_running.id])
        self.assertEqual(graph_live.live('live-south', self.da.id)['scans'], [])

    def test_a_viewer_only_ever_sees_their_own_projects(self):
        client = client_for(self.viewer)
        for query in ('?project=_all', '?project=live-north', ''):
            response = client.get('/cve/api/graph-live' + query)
            self.assertEqual(response.status_code, 200, query)
            self.assertEqual({s['project'] for s in response.json()['scans']}, {'live-north'}, query)
            self.assertEqual(response['Cache-Control'], 'private, no-cache')  # not no-store: a conditional request has to be possible
        self.assertEqual(client.get('/cve/api/graph-live?project=live-south').status_code, 404)
        self.assertEqual(client.get('/cve/api/graph-live?project=live-north&domain=' + str(self.ds.id)).json()['scans'], [])
        self.assertEqual({s['project'] for s in client_for(self.root).get('/cve/api/graph-live?project=_all').json()['scans']},
                         {'live-north', 'live-south'})

    def test_it_needs_a_login(self):
        from django.test import Client
        self.assertIn(Client().get('/cve/api/graph-live').status_code, (302, 401, 403))

    def test_the_graph_page_offers_soc_mode(self):
        page = client_for(self.viewer).get('/cve/graph/?project=live-north')
        self.assertEqual(page.status_code, 200)
        for marker in (b'id="graph-soc"', b'class="soc-hud"', b'/cve/api/graph-live'):
            self.assertIn(marker, page.content)
