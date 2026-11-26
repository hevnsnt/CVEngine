"""The Internal network entry and page (cveFeed.internal_page): when the rail offers it, what the page counts, and that it never shows another
organization's internal hosts."""
from datetime import timedelta

from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import internal_page, internal_view
from cveFeed.models import InternalRange
from dashboard.models import Project
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_internal_view import ViewBase
from tests.test_tenancy import client_for


def rail(html):
    block = html[html.index('aria-label="Sections"'):html.index('<details class="acct">')]
    import re
    return [label for label, _href in re.findall(r'<a data-nav="([^"]+)" href="([^"]+)"', block)]


class Base(ViewBase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def agent(self, user, scope, network='internal', status='active', revoked=False, seen=True, name='inside-one'):
        token = create_token(user, f'sentinel-{name}')[0]
        if revoked:
            token.revoked = True
            token.save(update_fields=['revoked'])
        return Agent.objects.create(token=token, name=name, kind='scanner', scope=scope, network=network, status=status,
                                    last_seen=timezone.now() if seen else None, capabilities=['nmap', 'discover'])

    def api(self, user, project='ir-a'):
        cache.clear()
        r = client_for(user).get('/cve/api/internal', {'project': project})
        self.assertEqual(r.status_code, 200, r.content[:300])
        return r.json()


class NavTests(Base):
    """The entry follows Hosts when the scope has an internal Sentinel or a declared range, and is absent otherwise."""

    def entries(self, user, path='/cve/ir-a/hosts/'):
        r = client_for(user).get(path)
        self.assertEqual(r.status_code, 200)
        return rail(r.content.decode())

    def test_a_declared_range_alone_shows_it_after_hosts(self):
        labels = self.entries(self.admin)
        self.assertEqual(labels[labels.index('Hosts') + 1], 'Internal network')
        self.assertIn('href="/cve/ir-a/internal/"', client_for(self.admin).get('/cve/ir-a/hosts/').content.decode())

    def test_neither_a_range_nor_an_internal_sentinel_hides_it(self):
        InternalRange.objects.all().delete()
        self.assertNotIn('Internal network', self.entries(self.admin))

    def test_an_internal_sentinel_of_the_project_or_its_organization_shows_it(self):
        InternalRange.objects.all().delete()
        self.agent(self.admin, {'orgs': ['ir-one']})
        self.assertIn('Internal network', self.entries(self.admin))
        Agent.objects.all().delete()
        self.agent(self.root, {'projects': ['ir-a']})
        self.assertIn('Internal network', self.entries(self.member))

    def test_an_external_revoked_or_instance_wide_sentinel_does_not(self):
        InternalRange.objects.all().delete()
        self.agent(self.admin, {'orgs': ['ir-one']}, network='external', name='outside')
        self.agent(self.admin, {'orgs': ['ir-one']}, status='revoked', name='gone')
        self.agent(self.admin, {'orgs': ['ir-one']}, revoked=True, name='token-gone')
        self.agent(self.root, {'instance': True}, name='everywhere')
        self.assertNotIn('Internal network', self.entries(self.admin))

    def test_another_organizations_internal_sentinel_never_shows_it(self):
        InternalRange.objects.all().delete()
        self.agent(self.other, {'orgs': ['ir-two']}, name='theirs')
        self.agent(self.other, {'orgs': ['ir-one'], 'projects': ['ir-a']}, name='claims-ours')  # its owner is not a member here
        self.assertNotIn('Internal network', self.entries(self.admin))
        self.assertNotIn('Internal network', self.entries(self.member))
        self.assertIn('Internal network', self.entries(self.other, '/cve/ir-b/hosts/'))  # their own Sentinel does show it to them
        Agent.objects.all().delete()
        InternalRange.objects.create(project=self.pa, cidr='10.20.0.0/24')
        self.assertNotIn('Internal network', self.entries(self.other, '/cve/ir-b/hosts/'))  # our range does not show it to them

    def test_the_organization_view_shows_it_when_one_of_its_projects_has_one(self):
        Project.objects.create(name='A2', slug='ir-a2', insert_date=timezone.now(), org=self.org1)
        labels = self.entries(self.admin, '/cve/_all/hosts/?org=ir-one')
        self.assertEqual(labels[labels.index('Hosts') + 1], 'Internal network')
        InternalRange.objects.all().delete()
        self.assertNotIn('Internal network', self.entries(self.admin, '/cve/_all/hosts/?org=ir-one'))

    def test_the_check_is_one_statement_however_many_projects(self):
        for i in range(12):
            Project.objects.create(name=f'More {i}', slug=f'ir-more-{i}', insert_date=timezone.now(), org=self.org1)
        rows = list(Project.objects.values('slug', 'org__slug'))
        rows = [{'slug': r['slug'], 'org_slug': r['org__slug']} for r in rows]
        with self.assertNumQueries(1):
            self.assertTrue(internal_page.nav_visible(rows))
        InternalRange.objects.all().delete()
        with self.assertNumQueries(1):
            self.assertFalse(internal_page.nav_visible(rows))
        with self.assertNumQueries(0):
            self.assertFalse(internal_page.nav_visible([]))


class PageTests(Base):
    def test_the_page_answers_for_the_scope_and_is_a_404_for_another_organization(self):
        html = client_for(self.admin).get('/cve/ir-a/internal/').content.decode()
        self.assertIn('<h1>Internal network</h1>', html)
        self.assertIn('href="/cve/ir-a/hosts/?internal=1"', html)
        self.assertIn('href="/cve/ir-a/vulns/?severity=critical&amp;internal=1"', html)
        self.assertIn('href="/cve/ir-a/vulns/?internal=1"', html)
        self.assertEqual(client_for(self.other).get('/cve/ir-a/internal/').status_code, 404)
        self.assertEqual(client_for(self.other).get('/cve/api/internal', {'project': 'ir-a'}).status_code, 404)

    def test_only_internal_hosts_are_counted_and_listed(self):
        out = self.api(self.admin)
        self.assertTrue(out['has'])
        self.assertEqual((out['tiles']['hosts'], out['tiles']['exposed_hosts']), (1, 1))
        self.assertEqual([f['host'] for f in out['findings']['results']], ['10.20.0.7'])  # the outside host's finding is not here
        self.assertEqual(out['findings']['total'], 1)
        net = out['networks'][0]
        self.assertEqual((net['cidr'], net['project'], net['project_name'], net['hosts']), ('10.20.0.0/24', 'ir-a', 'A', 1))

    def test_another_organizations_internal_hosts_never_appear(self):
        now = timezone.now()
        InternalRange.objects.create(project=self.pb, cidr='10.20.0.0/24', description='victim office')
        theirs = Domain.objects.create(name='10.20.0.9', project=self.pb, insert_date=now)
        scan = ScanHistory.objects.create(domain=theirs, scan_type=self.scan_in.scan_type, start_scan_date=now, scan_status=2, results_dir='/tmp',
                                          tasks=['internal_pipeline'])
        sub = Subdomain.objects.create(scan_history=scan, target_domain=theirs, name='10.20.0.9')
        Vulnerability.objects.create(scan_history=scan, target_domain=theirs, subdomain=sub, name='Their finding', severity=4, http_url='https://10.20.0.9/',
                                     open_status=True)
        SentinelTask.objects.create(project=self.pb, kind='discover', host='10.20.0.0/24', status='running')
        internal_view.invalidate()
        for project in ('ir-a', '_all'):
            text = str(self.api(self.admin, project))
            for marker in ('10.20.0.9', 'Their finding', 'victim office', 'ir-b'):
                self.assertNotIn(marker, text, (project, marker))
        self.assertEqual(self.api(self.admin, '_all')['tiles']['hosts'], 1)

    def test_internal_numbers_agree_with_the_overview_rules(self):
        """With every host internal, each tile equals the Overview's own figure; with some outside, each is the internal share of it."""
        from agentapi.services import _finding_sources
        from cveFeed import counts, overview, stats_history
        Vulnerability.objects.create(scan_history=self.scan_in, target_domain=self.inside, subdomain=self.sub_in, name='Critical inside', severity=4,
                                     http_url='https://10.20.0.7/x', open_status=True)
        Vulnerability.objects.create(scan_history=self.scan_out, target_domain=self.outside, subdomain=self.sub_out, name='Critical outside', severity=4,
                                     http_url='https://203.0.113.7/x', open_status=True)
        tiles = self.api(self.admin)['tiles']
        self.assertEqual(tiles['hosts'], internal_view.summary()['hosts'])
        self.assertEqual(tiles['hosts'], 1)
        self.assertEqual(tiles['critical'], 1)
        sources = _finding_sources(self.pa, {'internal': '0', 'severity': 'critical'}, counting=True)
        self.assertEqual(tiles['critical'] + sum(q.count() for q in sources.values()), stats_history._open_findings_and_cve_matches(self.pa)[0]['critical'])
        # now every host is internal: the tiles are the Overview's numbers
        self.outside.delete()
        internal_view.invalidate()
        cache.clear()
        tiles = self.api(self.admin)['tiles']
        self.assertEqual(tiles['hosts'], counts.host_reps().count())
        self.assertEqual(tiles['exposed_hosts'], counts.exposed_host_count())
        self.assertEqual(tiles['critical'], stats_history._open_findings_and_cve_matches(self.pa)[0]['critical'])
        cache.clear()
        self.assertEqual(tiles['needs'], overview.needs_hosts([self.pa.id]))

    def test_the_query_count_does_not_grow_with_the_hosts(self):
        def measure():
            cache.clear()
            internal_view.invalidate()
            client = client_for(self.admin)
            client.get('/cve/api/internal', {'project': 'ir-a'})  # warm the per-process caches
            cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(client.get('/cve/api/internal', {'project': 'ir-a'}).status_code, 200)
            return len(ctx.captured_queries)
        small = measure()
        now = timezone.now()
        for i in range(20, 40):
            d = Domain.objects.create(name=f'10.20.0.{i}', project=self.pa, insert_date=now)
            scan = ScanHistory.objects.create(domain=d, scan_type=self.scan_in.scan_type, start_scan_date=now, scan_status=2, results_dir='/tmp',
                                              tasks=['internal_pipeline'])
            sub = Subdomain.objects.create(scan_history=scan, target_domain=d, name=d.name)
            Vulnerability.objects.create(scan_history=scan, target_domain=d, subdomain=sub, name=f'Finding {i}', severity=3, http_url=f'https://{d.name}/',
                                         open_status=True)
            SentinelTask.objects.create(project=self.pa, kind='nmap', host=d.name, status='queued', scan=scan)
        big = measure()
        self.assertLessEqual(big, small + 2, (small, big))
        self.assertLess(big, 80)


class EdgeStateTests(Base):
    def test_an_offline_sentinel_leaves_the_next_discovery_waiting(self):
        self.agent(self.admin, {'orgs': ['ir-one']}, seen=False)
        net = self.api(self.admin)['networks'][0]
        self.assertEqual(net['sentinel']['state'], 'offline')
        self.assertEqual(net['sentinel']['sentinels'], [{'name': 'inside-one', 'state': 'offline', 'last_seen': None}])
        self.assertEqual(net['next_discovery'], {'at': None, 'state': 'waiting'})

    def test_a_range_never_discovered_is_due_and_one_discovered_is_scheduled(self):
        self.agent(self.admin, {'orgs': ['ir-one']})
        net = self.api(self.admin)['networks'][0]
        self.assertEqual((net['sentinel']['state'], net['last_discovery_at'], net['next_discovery']['state']), ('online', None, 'due'))
        InternalRange.objects.update(last_discovery_at=timezone.now() - timedelta(days=1), last_discovery_hosts=55)
        net = self.api(self.admin)['networks'][0]
        self.assertEqual((net['next_discovery']['state'], net['last_discovery_hosts']), ('scheduled', 55))

    def test_a_discovery_error_is_reported(self):
        InternalRange.objects.update(last_discovery_error='no Sentinel inside the network answered for 10.20.0.0/24')
        self.assertEqual(self.api(self.admin)['networks'][0]['last_discovery_error'], 'no Sentinel inside the network answered for 10.20.0.0/24')

    def test_an_instance_wide_sentinel_is_counted_but_not_named(self):
        self.agent(self.root, {'instance': True}, name='everywhere')
        net = self.api(self.admin)['networks'][0]
        self.assertEqual((net['sentinel']['state'], net['sentinel']['total'], net['sentinel']['sentinels']), ('online', 1, []))

    def test_the_activity_lists_internal_work_only(self):
        SentinelTask.objects.create(project=self.pa, kind='discover', host='10.20.0.0/24', status='running')
        SentinelTask.objects.create(project=self.pa, kind='nmap', host='10.20.0.7', status='queued')
        SentinelTask.objects.create(project=self.pa, kind='nmap', host='203.0.113.7', status='queued')  # an outside host: not internal work
        SentinelTask.objects.create(project=self.pa, kind='testssl', host='10.20.0.7', status='failed', error='timed out', finished_at=timezone.now())
        activity = self.api(self.admin)['activity']
        self.assertEqual(sorted((r['kind'], r['host']) for r in activity['active']), [('discover', '10.20.0.0/24'), ('nmap', '10.20.0.7')])
        self.assertEqual([(r['kind'], r['error']) for r in activity['recent']], [('testssl', 'timed out')])
        self.assertEqual(activity['scans'], {'running': 0, 'queued': 0})
