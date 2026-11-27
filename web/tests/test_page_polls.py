"""The pages and polls the database review found recounting on every request: each answers what it answered before, reads less, and a cache it
uses is keyed by everything the answer depends on and kept seconds, not minutes."""
import re

from django.contrib.auth.models import User
from django.db import connection
from django.test import RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import counts, snapshot_cache, views
from cveFeed.models import CVEEntry, CVEMatch, DiscoveryEvent, McpCall, ProjectSettings
from cveFeed.threat import FIRE, ICE, SMOKE
from dashboard.models import Org, OrgMembership, Project, ProjectMembership, UserProfile
from startScan.models import Subdomain
from tests.test_review_efficiency import Fixture
from tests.test_tenancy import client_for


class CatalogCountsTests(TestCase):
	def setUp(self):
		snapshot_cache.bump_revision()  # the catalogue counts are keyed by the revision: nothing an earlier test stored is read

	def test_the_tiers_are_counted_once_and_a_new_cve_shows_at_once(self):
		for i, kw in enumerate((dict(kev=True), dict(exploit_db=True), dict(cvss=9.8), dict())):
			CVEEntry.objects.create(cve_id=f'CVE-2099-81{i}', published_at=timezone.now(), **kw)
		expected = {FIRE: 0, SMOKE: 0, ICE: 0}
		for e in CVEEntry.objects.all():
			expected[e.threat_tier] += 1
		self.assertEqual(views.tier_counts(), expected)
		with CaptureQueriesContext(connection) as ctx:
			self.assertEqual(views.tier_counts(), expected)
		self.assertEqual([q['sql'][:100] for q in ctx.captured_queries if 'COUNT(' in q['sql'].upper()], [])  # served from the cache
		CVEEntry.objects.create(cve_id='CVE-2099-8199', kev=True, published_at=timezone.now())
		self.assertEqual(views.tier_counts()[FIRE], expected[FIRE] + 1)  # the newest id is part of the key

	def test_a_revision_bump_drops_the_cached_counts(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2099-8201', published_at=timezone.now())
		self.assertEqual(views.tier_counts()[FIRE], 0)
		CVEEntry.objects.filter(pk=cve.pk).update(kev=True)
		snapshot_cache.bump_revision()
		self.assertEqual(views.tier_counts()[FIRE], 1)


class LiveScanCountTests(Fixture):
	def test_one_read_gives_what_the_counting_helpers_give(self):
		for status, hours in ((1, 1), (1, 1), (1, 40), (-1, 0), (2, 1)):
			self.scan(status=status, hours=hours)
		live = views.live_scan_counts()
		self.assertEqual((live['scans_running'], live['scans_queued']), (counts.running_scans().count(), counts.queued_scans().count()))
		self.assertEqual((live['scans_running'], live['scans_queued']), (2, 1))


class DiscoveryCursorTests(Fixture):
	def test_a_cursor_gets_at_most_the_newest_events_past_it_in_order(self):
		scan = self.scan(status=1)
		events = [DiscoveryEvent.objects.create(scan=scan, domain=self.domain, type='DNS_NAME', label=f'n{i}', host=f'n{i}.eff.example') for i in range(250)]
		user = User.objects.create_user('poll-disc', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		got = client_for(user).get(f'/cve/api/discovery?scan={scan.id}&after={events[0].id}').json()['events']
		self.assertEqual(len(got), views.DISCOVERY_AFTER_MAX)
		self.assertEqual([e['id'] for e in got], [e.id for e in events[-views.DISCOVERY_AFTER_MAX:]])  # oldest first, ending at the newest
		few = client_for(user).get(f'/cve/api/discovery?scan={scan.id}&after={events[-3].id}').json()['events']
		self.assertEqual([e['id'] for e in few], [events[-2].id, events[-1].id])


class CveNodeTests(Fixture):
	def test_a_cve_node_lists_a_bounded_number_of_hosts_and_says_how_many_more(self):
		scan = self.scan()
		cve = CVEEntry.objects.create(cve_id='CVE-2099-8301', cvss=9.0, kev=True, affected=[])
		total = views.NODE_CVE_HOSTS + 5
		for i in range(total):
			CVEMatch.objects.create(cve_entry=cve, subdomain=self.host(f'h{i}.eff.example', scan), matched_product='nginx', confidence=.8)
		d = views.node_detail(f'cve:{cve.pk}')
		rows = {r['k']: r for r in d['rows']}
		self.assertEqual(len(rows['Matched hosts']['links']), views.NODE_CVE_HOSTS)
		self.assertEqual(rows['More matched hosts']['v'], '5 more on the matches page')
		self.assertEqual(d['link'], '/cve/eff-one/matches/?cve=CVE-2099-8301')

	def test_a_few_hosts_are_all_listed_with_no_more_row(self):
		scan = self.scan()
		cve = CVEEntry.objects.create(cve_id='CVE-2099-8302', cvss=9.0, affected=[])
		for name in ('a.eff.example', 'b.eff.example'):
			CVEMatch.objects.create(cve_entry=cve, subdomain=self.host(name, scan), matched_product='nginx', confidence=.8)
		rows = {r['k']: r for r in views.node_detail(f'cve:{cve.pk}')['rows']}
		self.assertEqual(sorted(link['text'] for link in rows['Matched hosts']['links']), ['a.eff.example', 'b.eff.example'])
		self.assertNotIn('More matched hosts', rows)


class UsersListTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org = Org.objects.create(name='U', slug='poll-users')
		cls.project = Project.objects.create(name='U1', slug='poll-u1', insert_date=now, org=cls.org)
		cls.root = User.objects.create_superuser('poll-root', 'r@x.io', 'pw-Secret-1')

	def add_users(self, n, start=0):
		for i in range(start, start + n):
			u = User.objects.create_user(f'poll-user-{i:03}', password='pw-Secret-1')
			OrgMembership.objects.create(user=u, org=self.org, role='user')
			ProjectMembership.objects.create(user=u, project=self.project, role='user')
			UserProfile.objects.create(user=u, mfa_enabled=bool(i % 2))

	def list_users(self):
		from cveFeed import admin_api
		request = RequestFactory().get('/cve/api/admin/users')
		return admin_api.users_list(request, self.root)['results']

	def test_the_list_is_what_one_user_at_a_time_gives(self):
		from cveFeed import admin_api
		self.add_users(3)
		listed = self.list_users()
		self.assertEqual(listed, [admin_api.user_dict(self.root, u) for u in User.objects.order_by('username')])

	def test_the_query_count_does_not_grow_with_the_users(self):
		self.add_users(2)
		self.list_users()
		with CaptureQueriesContext(connection) as small:
			self.list_users()
		self.add_users(20, start=2)
		with CaptureQueriesContext(connection) as big:
			self.assertEqual(len(self.list_users()), 23)
		self.assertLessEqual(len(big), len(small) + 2, f'{len(small)} queries for 3 users, {len(big)} for 23')


class ReviewerModesTests(TestCase):
	def test_modes_of_answers_what_mode_of_answers_for_each_project(self):
		from cveFeed import host_review
		now = timezone.now()
		projects = [Project.objects.create(name=f'R{i}', slug=f'poll-r{i}', insert_date=now) for i in range(4)]
		for project, mode in zip(projects, ('auto', 'off', 'nonsense')):
			ProjectSettings.objects.create(project=project, host_review_mode=mode)
		with CaptureQueriesContext(connection) as ctx:
			got = host_review.modes_of(projects)
		self.assertEqual(len(ctx.captured_queries), 1)
		self.assertEqual([mode for _p, mode in got], [host_review.mode_of(p) for p in projects])
		self.assertEqual([mode for _p, mode in got], ['auto', 'off', 'recommend', 'recommend'])


class McpChoicesTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.alice = User.objects.create_user('poll-mcp-alice', password='x')
		cls.admin = User.objects.create_superuser('poll-mcp-admin', password='x')
		McpCall.objects.create(user=cls.alice, username='poll-mcp-alice', token_name='laptop', tool='list_projects')
		McpCall.objects.create(user=cls.admin, username='poll-mcp-admin', token_name='', tool='get_cve')

	def setUp(self):
		from django.core.cache import cache
		cache.delete_many([f'cve:mcp-choices:{u.pk}:{int(u.is_superuser)}' for u in (self.alice, self.admin)])

	def history(self, user):
		from cveFeed import mcp_page
		request = RequestFactory().get('/cve/mcp/')
		request.user = user
		return mcp_page.history(request)

	def test_the_menus_are_read_once_per_viewer_and_never_shared(self):
		first = self.history(self.alice)
		self.assertEqual((first['tools_seen'], first['keys_seen'], first['users_seen']), (['list_projects'], ['laptop'], []))
		with CaptureQueriesContext(connection) as ctx:
			again = self.history(self.alice)
		self.assertEqual([q['sql'][:100] for q in ctx.captured_queries if re.search(r'SELECT DISTINCT', q['sql'])], [])
		self.assertEqual(again['tools_seen'], first['tools_seen'])
		admin = self.history(self.admin)  # another viewer: their own menus, not alice's
		self.assertEqual((admin['tools_seen'], admin['keys_seen']), (['get_cve', 'list_projects'], ['(browser)', 'laptop']))
		self.assertEqual(admin['users_seen'], ['poll-mcp-admin', 'poll-mcp-alice'])


class GuidanceProgressTests(TestCase):
	def test_the_ai_tab_counts_the_catalogue_once_and_a_new_cve_or_budget_shows_at_once(self):
		from unittest import mock

		from cveFeed import detection_author, settings_api
		CVEEntry.objects.create(cve_id='CVE-2099-8401', published_at=timezone.now())
		first = settings_api._guidance_progress()
		self.assertEqual(first, detection_author.progress())
		with mock.patch.object(detection_author, 'progress', side_effect=AssertionError('the catalogue was counted again')):
			self.assertEqual(settings_api._guidance_progress(), first)
		CVEEntry.objects.create(cve_id='CVE-2099-8402', published_at=timezone.now())
		self.assertEqual(settings_api._guidance_progress()['cves'], first['cves'] + 1)  # the newest id is part of the key
		with mock.patch.object(detection_author, 'daily_limit', return_value=first['daily_budget'] + 7):
			self.assertEqual(settings_api._guidance_progress()['daily_budget'], first['daily_budget'] + 7)  # so is the budget
