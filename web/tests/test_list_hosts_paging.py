"""Paging of the host list (agentapi.services.list_hosts, REST ``projects/{slug}/hosts`` and the MCP ``list_hosts`` tool): ``has_more`` and
``next_page`` on every answer, a stable order (score, name, id), and the MCP tool's smaller default page and cap (a host row is 20 to 60 KB on a
large project, so 50 rows were about 1 MB and 200 passed the MCP response limit)."""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi import mcp
from agentapi import services as svc
from agentapi.auth import create_token
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import tool_call

HOSTS = 55  # more than the MCP cap (50), so the cap and the default are both seen cutting a page


class ListHostsPagingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='Paging', slug='paging-org')
        cls.project = Project.objects.create(name='Paging', slug='paging-p', insert_date=now, org=cls.org)
        cls.empty = Project.objects.create(name='Empty', slug='paging-empty', insert_date=now, org=cls.org)
        cls.engine = EngineType.objects.create(engine_name='paging-e', yaml_configuration='x')
        cls.user = User.objects.create_user('paging-user', password='x')
        for project in (cls.project, cls.empty):
            ProjectMembership.objects.create(user=cls.user, project=project, role='user')
        cls.ctx = svc.Ctx(user=cls.user)
        _, cls.key = create_token(cls.user, 'paging-agent')
        domain = Domain.objects.create(name='paging.example', project=cls.project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=cls.engine, start_scan_date=now, scan_status=2)
        # no addresses: each name is its own host; scores fall in steps of five so several hosts tie on score and are ordered by name
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i:02d}.paging.example', target_domain=domain, scan_history=scan, score=(i // 5) * 5)
                                       for i in range(HOSTS)])

    def setUp(self):
        cache.clear()  # the count-only answer is cached a moment per scope and filters

    def _names(self, page):
        return [h['host'] for h in page['results']]

    def test_the_first_page_says_more_rows_follow_and_which_page_holds_them(self):
        page = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 10})
        self.assertEqual((page['count'], page['page'], page['page_size'], len(page['results'])), (HOSTS, 1, 10, 10))
        self.assertEqual((page['has_more'], page['next_page']), (True, 2))

    def test_the_last_page_has_no_next_page(self):
        page = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 10, 'page': 6})
        self.assertEqual(len(page['results']), HOSTS - 50)
        self.assertEqual((page['has_more'], page['next_page']), (False, None))
        exact = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 11, 'page': 5})  # a last page that is exactly full
        self.assertEqual((len(exact['results']), exact['has_more'], exact['next_page']), (11, False, None))

    def test_a_page_past_the_end_and_a_project_with_no_hosts_are_empty_with_no_next_page(self):
        past = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 10, 'page': 99})
        self.assertEqual((past['count'], past['results'], past['has_more'], past['next_page']), (HOSTS, [], False, None))
        empty = svc.list_hosts(self.ctx, 'paging-empty', {})
        self.assertEqual((empty['count'], empty['results'], empty['has_more'], empty['next_page']), (0, [], False, None))

    def test_the_count_alone_has_no_next_page(self):
        page = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 0})
        self.assertEqual((page['count'], page['page_size'], page['results'], page['has_more'], page['next_page']), (HOSTS, 0, [], False, None))

    def test_following_next_page_lists_every_host_once_in_score_then_name_order(self):
        stored = dict(Subdomain.objects.values_list('name', 'score'))
        for sort in ('score', 'name'):
            seen, params = [], {'page_size': 7, 'sort': sort}
            while True:
                page = svc.list_hosts(self.ctx, 'paging-p', params)
                seen += [(stored[h['host']], h['host']) for h in page['results']]  # the order reads the stored score
                if not page['has_more']:
                    break
                params = {**params, 'page': page['next_page']}
            self.assertEqual(len(seen), HOSTS)
            self.assertEqual(len(set(seen)), HOSTS)
            key = (lambda r: (-r[0], r[1])) if sort == 'score' else (lambda r: r[1])
            self.assertEqual(seen, sorted(seen, key=key))

    def test_rest_keeps_its_default_of_fifty_and_its_cap_of_two_hundred(self):
        page = svc.list_hosts(self.ctx, 'paging-p', {})
        self.assertEqual((page['page_size'], len(page['results']), page['has_more'], page['next_page']), (svc.PAGE_SIZE_DEFAULT, 50, True, 2))
        above = svc.list_hosts(self.ctx, 'paging-p', {'page_size': 5000})
        self.assertEqual((above['page_size'], len(above['results']), above['has_more']), (svc.PAGE_SIZE_MAX, HOSTS, False))

    def test_mcp_answers_twenty_hosts_by_default(self):
        error, page = tool_call(self.key, 'list_hosts', {'project': 'paging-p'})
        self.assertFalse(error, page)
        self.assertEqual((page['count'], page['page_size'], len(page['results'])), (HOSTS, mcp.HOSTS_MCP_PAGE_SIZE, 20))
        self.assertEqual((page['has_more'], page['next_page']), (True, 2))

    def test_mcp_cuts_a_page_size_above_its_cap_to_fifty(self):
        error, page = tool_call(self.key, 'list_hosts', {'project': 'paging-p', 'page_size': 200})
        self.assertFalse(error, page)
        self.assertEqual((page['page_size'], len(page['results']), page['has_more'], page['next_page']), (mcp.HOSTS_MCP_PAGE_MAX, 50, True, 2))
        error, last = tool_call(self.key, 'list_hosts', {'project': 'paging-p', 'page_size': 200, 'page': 2})
        self.assertFalse(error, last)
        self.assertEqual((len(last['results']), last['has_more'], last['next_page']), (HOSTS - 50, False, None))

    def test_mcp_keeps_the_count_alone_and_a_small_page_as_asked(self):
        error, count = tool_call(self.key, 'list_hosts', {'project': 'paging-p', 'page_size': 0})
        self.assertFalse(error, count)
        self.assertEqual((count['count'], count['results'], count['has_more']), (HOSTS, [], False))
        error, small = tool_call(self.key, 'list_hosts', {'project': 'paging-p', 'page_size': 3, 'page': 2})
        self.assertFalse(error, small)
        self.assertEqual((small['page'], len(small['results']), small['next_page']), (2, 3, 3))

    def test_the_tool_schema_and_description_name_the_default_and_the_cap(self):
        _name, description, schema, _handler, _write = mcp.BY_NAME['list_hosts']
        self.assertIn('20 hosts by default and at most 50', description)
        self.assertIn('has_more', description)
        self.assertIn('20 by default, at most 50', schema['properties']['page_size']['description'])
        self.assertNotIn('page_size', schema.get('required', []))


class ListHostsTieOrderTests(TestCase):
    """Two projects can each hold a host of the same name and score; in the all-projects view the id orders them, so a page boundary between
    them cannot show one twice and the other never."""

    def test_hosts_that_tie_on_score_and_name_are_ordered_by_id(self):
        now = timezone.now()
        engine = EngineType.objects.create(engine_name='tie-e', yaml_configuration='x')
        user = User.objects.create_user('tie-user', password='x')
        ids = []
        for n in range(3):
            org = Org.objects.create(name=f'Tie {n}', slug=f'tie-org-{n}')  # a target name is unique in an organization
            project = Project.objects.create(name=f'Tie {n}', slug=f'tie-{n}', insert_date=now, org=org)
            ProjectMembership.objects.create(user=user, project=project, role='user')
            domain = Domain.objects.create(name='tie.example', project=project, insert_date=now)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
            ids.append(Subdomain.objects.create(name='same.tie.example', target_domain=domain, scan_history=scan, score=10).id)
        seen = []
        for number in (1, 2, 3):
            page = svc.list_hosts(svc.Ctx(user=user), '_all', {'page_size': 1, 'page': number})
            seen += [h['id'] for h in page['results'] if h['host'] == 'same.tie.example']
        self.assertEqual(seen, sorted(ids))
