"""Related-object reads carry the project scope, worker jobs made for one person run under that person's scope, activity lines with no
project reach App Admins only, and administrators without two-step sign-in are reminded (tenancy.scope, tenancy.mfa_nag)."""
import json
import re
from contextlib import contextmanager
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch
from dashboard.models import Org, OrgMembership, Project, ProjectMembership, UserProfile
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from tenancy import roles, scope
from tests.test_agentapi import call
from tests.test_tenancy import client_for

NOW = timezone.now()


@contextmanager
def under(user):
    tokens = scope.set_scope(roles.allowed_project_ids(user), user)
    try:
        yield
    finally:
        scope.reset_scope(tokens)


def related_unscoped():
    """The behaviour before related managers carried the scope: every related manager reads unscoped (``objects`` stays scoped). With
    ``create=True`` it is a no-op on a tree that has no such hook, so an equivalence test runs on both."""
    return mock.patch('tenancy.scope._reached_from_scoped_row', lambda manager: getattr(manager, 'instance', None) is not None, create=True)


class Tenants(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org1, cls.org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
        cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=NOW, org=cls.org1)
        cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=NOW, org=cls.org2)
        cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=NOW)
        cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=NOW)
        cls.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        cls.sa = ScanHistory.objects.create(domain=cls.da, scan_type=cls.engine, scan_status=2, start_scan_date=NOW, tasks=[])
        cls.sb = ScanHistory.objects.create(domain=cls.db, scan_type=cls.engine, scan_status=2, start_scan_date=NOW, tasks=[])
        cls.suba = Subdomain.objects.create(name='www.a.example', target_domain=cls.da, scan_history=cls.sa)
        cls.subb = Subdomain.objects.create(name='www.b.example', target_domain=cls.db, scan_history=cls.sb)
        cls.entry = CVEEntry.objects.create(cve_id='CVE-2099-7001', kev=True, cvss=9.8, title='shared flaw', published_at=NOW)
        cls.ma = CVEMatch.objects.create(cve_entry=cls.entry, subdomain=cls.suba, matched_product='nginx', matched_version='1.18.0')
        cls.mb = CVEMatch.objects.create(cve_entry=cls.entry, subdomain=cls.subb, matched_product='nginx', matched_version='1.18.0')
        cls.tech = Technology.objects.create(name='nginx:1.18.0')
        cls.ip = IpAddress.objects.create(address='203.0.113.70')
        for sub in (cls.suba, cls.subb):
            sub.technologies.add(cls.tech)
            sub.ip_addresses.add(cls.ip)
        mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
        cls.root = mk('root', is_superuser=True, first_name='Rita', last_name='Root')
        cls.alice, cls.bob = mk('alice'), mk('bob')  # alice: a member of A (an analyst); bob: org Two, the outsider to A
        cls.olga = mk('olga', first_name='Olga', last_name='Admin')  # Org Admin of One
        cls.tom = mk('tom', first_name='Tom', last_name='Other')  # Org Admin of Two
        ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
        OrgMembership.objects.create(user=cls.bob, org=cls.org2, role='user')
        OrgMembership.objects.create(user=cls.olga, org=cls.org1, role='admin')
        OrgMembership.objects.create(user=cls.tom, org=cls.org2, role='admin')

    def setUp(self):
        cache.clear()


class RelatedManagerScopeTests(Tenants):
    def test_the_reverse_side_of_a_global_row_lists_only_visible_projects(self):
        with under(self.bob):
            self.assertEqual(CVEMatch.objects.count(), 1)
            self.assertEqual(self.entry.matches.count(), 1)  # was 2: the CVE listed project A's match to an outsider
            self.assertEqual(list(self.entry.matches.values_list('pk', flat=True)), [self.mb.pk])
            self.assertFalse(self.entry.matches.filter(pk=self.ma.pk).exists())
            self.assertEqual(list(self.engine.scanhistory_set.values_list('pk', flat=True)), [self.sb.pk])

    def test_both_sides_of_a_many_to_many_from_a_global_row_list_only_visible_projects(self):
        with under(self.bob):
            self.assertEqual(self.tech.technologies.count(), 1)  # count and exists must not take the link-table shortcut
            self.assertTrue(self.tech.technologies.filter(pk=self.subb.pk).exists())
            self.assertFalse(self.tech.technologies.filter(pk=self.suba.pk).exists())
            self.assertEqual([s.name for s in self.tech.technologies.all()], ['www.b.example'])
            self.assertEqual([s.name for s in self.ip.ip_addresses.all()], ['www.b.example'])

    def test_a_prefetch_through_a_global_row_is_scoped(self):
        with under(self.bob):
            entry = CVEEntry.objects.prefetch_related('matches').get(pk=self.entry.pk)
            self.assertEqual([m.pk for m in entry.matches.all()], [self.mb.pk])
            tech = Technology.objects.prefetch_related('technologies').get(pk=self.tech.pk)
            self.assertEqual([s.pk for s in tech.technologies.all()], [self.subb.pk])

    def test_no_scope_and_an_app_admin_still_read_everything(self):
        self.assertEqual(self.entry.matches.count(), 2)  # a worker or a shell: unrestricted
        self.assertEqual(self.tech.technologies.count(), 2)
        with under(self.root):
            self.assertEqual(self.entry.matches.count(), 2)
            self.assertEqual(self.engine.scanhistory_set.count(), 2)

    def test_children_of_a_project_row_are_read_with_the_same_sql_as_before(self):
        """Reads that start from a row already in scope (a target's hosts, a host's matches) keep their SQL: no extra join on hot paths."""
        reads = (lambda: self.da.subdomain_set.all(), lambda: self.suba.cve_matches.all(), lambda: self.sa.subdomain_set.all(),
                 lambda: self.pa.domain_set.all(), lambda: Subdomain.objects.filter(pk=self.suba.pk).prefetch_related('cve_matches'))
        with under(self.alice):
            for read in reads:
                with related_unscoped():
                    before = str(read().query)
                    with CaptureQueriesContext(connection) as old:
                        list(read())
                with CaptureQueriesContext(connection) as new:
                    rows = list(read())
                self.assertEqual(str(read().query), before)
                self.assertEqual([q['sql'] for q in new.captured_queries], [q['sql'] for q in old.captured_queries])
                self.assertTrue(rows)

    def test_every_scoped_model_and_the_related_managers_built_from_it_carry_the_scope(self):
        from django.apps import apps
        from tenancy.scope import ScopedManagerMixin
        for label in scope.SCOPES:
            self.assertIsInstance(apps.get_model(label)._default_manager, ScopedManagerMixin, label)
        for manager in (self.entry.matches, self.engine.scanhistory_set, self.engine.subscan_set, self.tech.technologies, self.tech.techs,
                        self.ip.ip_addresses, self.root.initiated_scans, self.org1.projects):
            self.assertIsInstance(manager, ScopedManagerMixin)


class EndpointEquivalenceTests(Tenants):
    """Every page and API a person uses today answers the same, with the same queries, with related managers scoped or not."""
    STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(\+00:00|Z)')  # the time of the request itself
    VOLATILE = re.compile(r'"(now|generated_at|generated|server_time|took_ms|elapsed_ms)":\s*("[^"]*"|[0-9.]+)')

    PAGES = ('/cve/proj-a/', '/cve/proj-a/hosts/', '/cve/proj-a/matches/', '/cve/proj-a/vulns/', '/cve/proj-a/scans/', '/cve/proj-a/targets/',
             '/cve/proj-a/changes/', '/cve/proj-a/situations/', '/cve/admin/', '/cve/about/')
    JSON = ('/cve/api/overview?project=proj-a', '/cve/api/stats?project=proj-a', '/cve/api/graph?project=proj-a', '/cve/api/discovery?project=proj-a',
            '/cve/api/feed?project=proj-a', '/cve/api/cves?project=proj-a', '/cve/api/activity?project=proj-a', '/cve/api/admin/orgs',
            '/cve/api/admin/users', '/cve/api/account/me', '/cve/api/overview?project=_all')
    REST = ('/api/v1/projects/proj-a/hosts', '/api/v1/projects/proj-a/matches', '/api/v1/projects/_all/matches', '/api/v1/cves/CVE-2099-7001',
            '/api/v1/projects/proj-a/activity', '/api/v1/projects/proj-a/scans', '/api/v1/projects')

    def _fetch(self, client, url, headers=None):
        cache.clear()
        with CaptureQueriesContext(connection) as ctx:
            response = client.get(url, **(headers or {}))
        body = response.content.decode('utf-8', 'replace')
        if response.get('Content-Type', '').startswith('application/json'):
            body = self.STAMP.sub('T', self.VOLATILE.sub(r'"\1": 0', body))
        else:
            body = re.sub(r'(csrfmiddlewaretoken" value=|name="cvengine-build" content=)"[^"]*"', r'\1""', body)
        return response.status_code, body, len(ctx.captured_queries)

    def _same(self, client, url, headers=None):
        self._fetch(client, url, headers)  # warm the per-process caches (feature indexes) before comparing
        with related_unscoped():
            old = self._fetch(client, url, headers)
        new = self._fetch(client, url, headers)
        self.assertEqual(new[0], old[0], url)
        self.assertEqual(new[2], old[2], f'{url}: query count changed')
        if new[0] == 200:
            self.assertEqual(new[1], old[1], f'{url}: output changed')

    def test_pages_and_web_api_answer_the_same(self):
        for user in (self.alice, self.olga, self.root, self.bob):
            client = client_for(user)
            for url in self.PAGES + self.JSON:
                with self.subTest(user=user.username, url=url):
                    self._same(client, url)

    def test_rest_api_answers_the_same(self):
        for user in (self.alice, self.bob, self.root):
            _, token = create_token(user, f'eq-{user.username}')
            from django.test import Client
            for url in self.REST:
                with self.subTest(user=user.username, url=url):
                    self._same(Client(), url, {'HTTP_AUTHORIZATION': f'Bearer {token}'})


class ProjectlessActivityTests(Tenants):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.line_a = AgentActivity.objects.create(kind='scan', message='Scanned www.a.example', project=cls.pa, status='done')
        cls.line_b = AgentActivity.objects.create(kind='scan', message='Scanned www.b.example', project=cls.pb, status='done')
        cls.line_none = AgentActivity.objects.create(kind='feed', message='Checked 900 CVEs against 4000 hosts', status='done')

    def test_a_line_with_no_project_reaches_only_an_app_admin(self):
        with under(self.alice):
            self.assertEqual(list(AgentActivity.objects.order_by('pk').values_list('pk', flat=True)), [self.line_a.pk])
        with under(self.olga):  # an Org Admin administers an organization, not the instance
            self.assertNotIn(self.line_none.pk, AgentActivity.objects.values_list('pk', flat=True))
        with under(self.root):
            self.assertEqual(AgentActivity.objects.count(), 3)
        self.assertEqual(AgentActivity.objects.count(), 3)  # workers: unrestricted

    def test_the_activity_feed_and_api_leave_it_out_for_a_project_member(self):
        body = json.loads(client_for(self.alice).get('/cve/api/activity?project=proj-a').content)
        messages = [i['message'] for i in body['items']]
        self.assertIn('Scanned www.a.example', messages)
        self.assertNotIn('Checked 900 CVEs against 4000 hosts', messages)
        body = json.loads(client_for(self.root).get('/cve/api/activity?project=_all').content)  # an App Admin's unrestricted view
        self.assertIn('Checked 900 CVEs against 4000 hosts', [i['message'] for i in body['items']])
        body = json.loads(client_for(self.root).get('/cve/api/activity?project=proj-a').content)  # one project's feed: that project's lines
        self.assertEqual([i['message'] for i in body['items']], ['Scanned www.a.example'])
        _, root_token = create_token(self.root, 'act-root')
        self.assertIn('Checked 900 CVEs against 4000 hosts', json.dumps(call(root_token, 'GET', '/api/v1/projects/proj-a/activity')[1]))
        _, token = create_token(self.alice, 'act')
        status, data = call(token, 'GET', '/api/v1/projects/proj-a/activity')
        self.assertEqual(status, 200)
        self.assertNotIn('Checked 900 CVEs against 4000 hosts', json.dumps(data))
        self.assertIn('Scanned www.a.example', json.dumps(data))


class WorkerJobScopeTests(Tenants):
    """A report or a saved search runs in a worker with no request scope; it now runs under its owner's scope as a second guard."""

    def _seen_by_an_unfiltered_query(self):
        return sorted(Domain.objects.values_list('project_id', flat=True))

    def test_a_saved_search_runs_under_its_owner_scope(self):
        from cveFeed import saved_searches
        from cveFeed.models import SavedSearch
        search = SavedSearch.objects.create(project=self.pa, owner=self.alice, name='s', query='port:443')
        seen = []

        def spy(project, terms):
            seen.append(self._seen_by_an_unfiltered_query())
            return {}, False
        with mock.patch.object(saved_searches, 'current_matches', side_effect=spy):
            saved_searches.evaluate(search)
        self.assertEqual(seen, [[self.pa.pk]])
        self.assertIsNone(scope.current_allowed())  # the worker's own scope is back to unrestricted afterwards

    def test_a_report_is_built_under_the_requester_scope(self):
        from agentapi.services import Ctx
        from cveFeed import report_export
        seen = []

        def spy(*args, **kwargs):
            seen.append(self._seen_by_an_unfiltered_query())
            open(args[4], 'wb').close()
            return {'hosts': 0}
        with mock.patch('cveFeed.tasks.generate_report.apply_async', return_value=mock.Mock(id='t')):
            job, _ = report_export.enqueue(Ctx(user=self.alice), 'proj-a')
        with mock.patch.object(report_export, 'build_file', side_effect=spy), \
                mock.patch.dict('os.environ', {'CVENGINE_REPORT_DIR': self._tmp()}):
            result = report_export.execute(job.pk)
        self.assertEqual(result['status'], 'done', result)
        self.assertEqual(seen, [[self.pa.pk]])
        self.assertIsNone(scope.current_allowed())

    def _tmp(self):
        import shutil
        import tempfile
        path = tempfile.mkdtemp(prefix='cvengine-guard-')
        self.addCleanup(shutil.rmtree, path, True)
        return path


class MfaNagTests(Tenants):
    MARK = 'data-mfa-nag'

    def page(self, user, url='/cve/about/', client=None):
        response = (client or client_for(user)).get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.content.decode()

    def enable_mfa(self, user):
        UserProfile.objects.update_or_create(user=user, defaults={'mfa_enabled': True, 'mfa_secret': 'JBSWY3DPEHPK3PXP'})

    def test_an_app_admin_without_mfa_sees_it_on_every_shell_page_with_the_setup_link(self):
        for url in ('/cve/about/', '/cve/admin/', '/cve/proj-a/hosts/'):
            html = self.page(self.root, url)
            self.assertIn(self.MARK, html, url)
            self.assertIn('href="/mfa/setup/"', html)
            self.assertIn('Your administrator account has no two-step sign-in.', html)

    def test_an_org_admin_without_mfa_sees_it(self):
        self.assertIn(self.MARK, self.page(self.olga))

    def test_an_admin_with_mfa_does_not(self):
        self.enable_mfa(self.root)
        self.enable_mfa(self.olga)
        self.assertNotIn(self.MARK, self.page(self.root))
        self.assertNotIn(self.MARK, self.page(self.olga))

    def test_an_analyst_does_not(self):
        self.assertNotIn(self.MARK, self.page(self.alice))
        self.assertNotIn(self.MARK, self.page(self.alice, '/cve/proj-a/hosts/'))

    def test_not_on_the_sign_in_page_nor_where_mfa_is_set_up(self):
        from django.test import Client
        self.assertNotIn(self.MARK, Client().get('/login/').content.decode())
        self.assertNotIn(self.MARK, self.page(self.root, '/cve/account/'))
        self.assertRedirects(client_for(self.root).get('/mfa/setup/'), '/cve/account/#security', fetch_redirect_response=False)

    def test_remind_me_later_hides_it_for_this_session_only(self):
        client = client_for(self.root)
        self.assertIn(self.MARK, self.page(self.root, client=client))
        response = client.post('/mfa/remind-later/', {'next': '/cve/proj-a/hosts/'})
        self.assertRedirects(response, '/cve/proj-a/hosts/', fetch_redirect_response=False)
        self.assertNotIn(self.MARK, self.page(self.root, client=client))
        self.assertNotIn(self.MARK, self.page(self.root, '/cve/admin/', client=client))
        self.assertIn(self.MARK, self.page(self.root))  # another session (the next sign-in) shows it again

    def test_remind_me_later_is_a_post_and_goes_back_only_to_this_site(self):
        client = client_for(self.root)
        self.assertEqual(client.get('/mfa/remind-later/').status_code, 405)
        self.assertIn(self.MARK, self.page(self.root, client=client))
        response = client.post('/mfa/remind-later/', {'next': 'https://evil.example/'})
        self.assertRedirects(response, '/cve/', fetch_redirect_response=False)

    def test_it_never_blocks_anything(self):
        self.assertEqual(client_for(self.root).get('/cve/api/admin/orgs').status_code, 200)
        self.assertEqual(client_for(self.olga).get('/cve/proj-a/hosts/').status_code, 200)

    def test_it_costs_at_most_one_query(self):
        from tenancy import mfa_nag
        for user in (self.root, self.olga):
            client = client_for(user)
            self.page(user, client=client)  # warm
            cache.clear()
            with CaptureQueriesContext(connection) as shown:
                self.assertIn(self.MARK, self.page(user, client=client))
            cache.clear()
            with mock.patch.object(mfa_nag, 'for_request', return_value=None), CaptureQueriesContext(connection) as hidden:
                self.assertNotIn(self.MARK, self.page(user, client=client))
            self.assertLessEqual(len(shown.captured_queries) - len(hidden.captured_queries), 1, user.username)

    def test_administration_lists_the_admins_without_mfa_by_name_only(self):
        self.enable_mfa(self.tom)
        html = self.page(self.root, '/cve/admin/')
        line = re.search(r'<p class="note" id="admin-mfa"[^>]*>(.*?)</p>', html, re.S).group(1)
        self.assertIn('Olga Admin', line)
        self.assertIn('Rita Root', line)
        self.assertNotIn('Tom Other', line)  # has MFA
        self.assertNotIn('alice', line)  # not an administrator
        self.assertNotIn('@', line)

    def test_an_org_admin_sees_only_the_admins_of_their_organizations(self):
        html = self.page(self.olga, '/cve/admin/')
        line = re.search(r'<p class="note" id="admin-mfa"[^>]*>(.*?)</p>', html, re.S).group(1)
        self.assertIn('Olga Admin', line)
        self.assertNotIn('Tom Other', line)  # another tenant's admin
        self.assertNotIn('Rita Root', line)  # the instance's App Admins are not an Org Admin's business
        self.enable_mfa(self.olga)
        self.assertIn('Every administrator has two-step sign-in turned on.', self.page(self.olga, '/cve/admin/'))
