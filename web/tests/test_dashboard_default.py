"""The Live dashboard defaults to the combined "All projects" view and narrows to one project only when the viewer picks it.
A ?project=<slug> the viewer may see scopes every panel to that project; a slug they may not see (or none) falls back to the
combined view. A viewer with a single project just sees that project, with no All-projects option offered."""
from django.core.cache import cache

from cveFeed import views
from startScan.models import Vulnerability
from tests.test_all_projects import AllProjectsBase
from tests.test_tenancy import client_for


class DashboardDefaultTests(AllProjectsBase):
	def setUp(self):
		cache.clear()
		views._STATS_CACHE.clear()  # the stats cache is a per-process dict keyed by (user, project); clear it between tests

	def _html(self, user, qs=''):
		r = client_for(user).get('/cve/' + qs)
		self.assertEqual(r.status_code, 200)
		return r.content.decode()

	def test_defaults_to_all_projects_for_a_multi_project_viewer(self):
		html = self._html(self.ann)  # ann is an org member: sees Acme and Widgets
		self.assertIn('data-slug="_all"', html)        # every panel spans both projects
		self.assertIn('value="_all" selected', html)   # and the switcher shows All projects selected
		self.assertNotIn('data-slug="acme"', html)     # never silently pinned to the first project

	def test_a_selected_project_scopes_the_shell(self):
		html = self._html(self.ann, '?project=acme')
		self.assertIn('data-slug="acme"', html)
		self.assertIn('value="acme" selected', html)
		self.assertNotIn('value="_all" selected', html)  # All projects is offered but not the current selection

	def test_a_project_the_viewer_cannot_see_is_404(self):
		# gadgets is another org's project: the tenancy layer answers 404 (no existence leak), the same as
		# /cve/gadgets/hosts/ would. The switcher only ever lists projects the viewer can see, so this is only
		# reachable by hand-crafting the URL.
		r = client_for(self.ann).get('/cve/?project=gadgets')
		self.assertEqual(r.status_code, 404)

	def test_single_project_viewer_sees_their_project_and_no_all_option(self):
		html = self._html(self.solo)  # solo is a member of Acme only
		self.assertIn('data-slug="acme"', html)
		self.assertNotIn('value="_all"', html)  # the All projects option needs two or more projects

	def test_stats_endpoint_scopes_to_the_selected_project(self):
		c = client_for(self.ann)
		combined = c.get('/cve/api/stats?project=_all').json()
		acme = c.get('/cve/api/stats?project=acme').json()
		default = c.get('/cve/api/stats').json()
		self.assertEqual(combined['targets'], 2)   # Acme + Widgets
		self.assertEqual(acme['targets'], 1)        # scoped to Acme alone
		self.assertEqual(default['targets'], 2)     # no project selected == All projects

	def test_scanner_findings_counter_matches_default_list_and_is_separate_from_catalog(self):
		Vulnerability.objects.create(name='Informational header', severity=0, target_domain=self.data['acme']['domain'])
		Vulnerability.objects.create(name='Additional low finding', severity=1, target_domain=self.data['widgets']['domain'])
		c = client_for(self.ann)
		stats = c.get('/cve/api/stats?project=_all').json()
		default_list = c.get('/api/v1/projects/_all/vulnerabilities?severity=actionable&page_size=1').json()
		all_list = c.get('/api/v1/projects/_all/vulnerabilities?page_size=1').json()
		self.assertEqual(stats['scanner_findings'], default_list['count'])
		self.assertEqual(stats['scanner_findings'], 3)  # two scanner rows already in Acme org plus this low row
		self.assertEqual(all_list['count'], 4)  # includes informational; never includes the other organization's row
		self.assertEqual(stats['tiers']['fire'], 1)  # the catalog CVE is a separate population
		self.assertEqual(stats['matches'], 2)  # asset CVE correlations are also separate
		self.assertIn('Scanner findings', c.get('/cve/').content.decode())

	def test_stats_rejects_a_project_the_viewer_cannot_see(self):
		r = client_for(self.ann).get('/cve/api/stats?project=gadgets')
		self.assertEqual(r.status_code, 404)


class ScopeCarriesTests(AllProjectsBase):
	"""What the viewer picked in the switcher carries to the pages that name no project (Sentinels, Settings ...), to a bare /cve/
	and to the section links on them; a project the viewer can no longer see is forgotten."""

	def setUp(self):
		cache.clear()
		views._STATS_CACHE.clear()

	def _page(self, c, path):
		r = c.get(path)
		self.assertEqual(r.status_code, 200, path)
		return r.content.decode()

	def test_all_projects_stays_selected_on_a_page_with_no_project(self):
		c = client_for(self.ann)
		self._page(c, '/cve/')  # Live opens on All projects
		html = self._page(c, '/cve/about/')
		self.assertIn('value="_all" selected', html)
		self.assertIn('href="/cve/_all/hosts/"', html)  # and the section links keep it

	def test_a_chosen_project_carries_to_other_pages_and_back_to_live(self):
		c = client_for(self.ann)
		self._page(c, '/cve/widgets/hosts/')
		for path in ('/cve/about/', '/cve/', '/cve/graph/'):
			html = self._page(c, path)
			self.assertIn('value="widgets" selected', html, path)
			self.assertNotIn('value="_all" selected', html, path)
		self.assertIn('data-slug="_all"', self._page(c, '/cve/?project=_all'))  # picking All projects again is remembered too
		self.assertIn('value="_all" selected', self._page(c, '/cve/about/'))

	def test_a_project_the_viewer_cannot_see_any_more_is_forgotten(self):
		c = client_for(self.ann)
		session = c.session
		session[views.SCOPE_KEY] = 'gadgets'  # another org's project
		session.save()
		self.assertIn('value="_all" selected', self._page(c, '/cve/about/'))
