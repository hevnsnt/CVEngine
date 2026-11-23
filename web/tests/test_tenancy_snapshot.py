"""The per-request tenancy snapshot (tenancy.snapshot): fewer queries before the view, the same answers.

Every test builds a fresh user object per simulated request, the way AuthenticationMiddleware and the bearer token check do, so
nothing a test reads is cached on an instance from an earlier request.
"""
import contextlib
import contextvars
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dashboard.models import ApiToken, Org, OrgMembership, Project, ProjectMembership, UserProfile
from tenancy import roles, scope, snapshot
from tenancy.middleware import TenancyMiddleware

NO_SNAPSHOT = mock.patch('tenancy.snapshot.activate', lambda user: contextlib.nullcontext())  # the code as it was before the snapshot


def fresh(user):
	"""A new instance of ``user``, as the next request would load it (no cached profile, no cached snapshot)."""
	return User.objects.get(pk=user.pk)


def run_request(user, path, slug=None, method='get', token=None, in_view=None):
	"""Run ``path`` through TenancyMiddleware (and, for a bearer token, AgentTokenMiddleware before it) up to the view.

	Returns (queries run, outcome) where outcome holds the allowed set the data layer was scoped to, the role the view would see
	and the response the middleware returned instead of the view (None when the view ran)."""
	from agentapi.auth import AgentTokenMiddleware
	request = getattr(RequestFactory(), method)(path, **({'HTTP_AUTHORIZATION': f'Bearer {token}'} if token else {}))
	request.user = user
	request.session = {}
	outcome = {}

	def view(req):
		return HttpResponse('ok')

	tenancy = TenancyMiddleware(None)

	def until_view(req):
		got = tenancy.process_view(req, view, (), {'slug': slug} if slug else {})
		allowed = scope.current_allowed()
		outcome.update(allowed=None if allowed is None else set(allowed), role=getattr(req, 'project_role', None),
		               blocked=None if got is None else got.status_code)
		if got is None and in_view:
			outcome['in_view'] = in_view(req)
		return got or view(req)

	tenancy.get_response = until_view
	chain = AgentTokenMiddleware(tenancy) if token else tenancy
	with CaptureQueriesContext(connection) as ctx:
		response = chain(request)
	outcome.setdefault('blocked', None if response.status_code == 200 else response.status_code)
	return ctx.captured_queries, outcome


class Fixture(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org1 = Org.objects.create(name='One', slug='one')
		cls.org2 = Org.objects.create(name='Two', slug='two')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=cls.org1)
		cls.pa2 = Project.objects.create(name='A2', slug='proj-a2', insert_date=now, org=cls.org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=cls.org2)
		cls.loose = Project.objects.create(name='Loose', slug='proj-loose', insert_date=now, org=None)
		mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
		cls.root = User.objects.create_superuser('root', 'r@x.io', 'x')
		cls.orgadmin = mk('orgadmin')
		cls.member = mk('member')
		cls.auditor = mk('auditor')
		cls.granted = mk('granted')
		cls.mixed = mk('mixed')
		cls.nobody = mk('nobody')
		OrgMembership.objects.create(user=cls.orgadmin, org=cls.org1, role='admin')
		ProjectMembership.objects.create(user=cls.member, project=cls.pa, role='user')
		OrgMembership.objects.create(user=cls.auditor, org=cls.org2, role='audit')
		ProjectMembership.objects.create(user=cls.granted, project=cls.loose, role='pentester')
		UserProfile.objects.create(user=cls.granted, bugbounty_enabled=True)
		OrgMembership.objects.create(user=cls.mixed, org=cls.org1, role='audit')
		ProjectMembership.objects.create(user=cls.mixed, project=cls.pa2, role='user')
		ProjectMembership.objects.create(user=cls.mixed, project=cls.pb, role='audit')
		UserProfile.objects.create(user=cls.member, mfa_enabled=True)
		cls.everyone = [cls.root, cls.orgadmin, cls.member, cls.auditor, cls.granted, cls.mixed, cls.nobody]
		cls.projects = [cls.pa, cls.pa2, cls.pb, cls.loose]

	def setUp(self):
		cache.clear()


class QueryCountTests(Fixture):
	"""What a signed-in request costs before the view runs. The numbers are the tenancy statements only: the session and user rows are
	read by Django's own middlewares before these run and are not counted here."""

	def test_counts_before_the_view(self):
		from agentapi.auth import create_token
		_, raw_member = create_token(self.member, 'count')
		_, raw_mixed = create_token(self.mixed, 'count')
		# (user, path, slug, token, statements now). Before this change the same requests ran 6, 5, 9, 8, 4, 5 and 8 statements; the
		# NO_SNAPSHOT run below cannot show the last two exactly, because the token lookup now also brings the profile in its own join.
		cases = [
			(self.member, '/cve/proj-a/hosts/', 'proj-a', None, 4),
			(self.member, '/cve/', None, None, 3),
			(self.mixed, '/cve/proj-a2/hosts/', 'proj-a2', None, 5),
			(self.mixed, '/cve/', None, None, 4),
			(self.root, '/cve/proj-a/hosts/', 'proj-a', None, 4),
			(self.member, '/api/v1/projects', None, raw_member, 4),
			(self.mixed, '/api/v1/projects', None, raw_mixed, 5),
		]
		for user, path, slug, token, now in cases:
			with self.subTest(user=user.username, path=path, token=bool(token)):
				ApiToken.objects.update(last_used_at=None)  # both runs record the token's use
				with NO_SNAPSHOT:
					old, old_outcome = run_request(fresh(user), path, slug=slug, token=token)
				ApiToken.objects.update(last_used_at=None)
				new, new_outcome = run_request(fresh(user), path, slug=slug, token=token)
				self.assertEqual(new_outcome, old_outcome)
				self.assertLessEqual(len(new), len(old))
				self.assertEqual(len(new), now, [q['sql'] for q in new])

	def test_a_missing_profile_is_read_once(self):
		user = fresh(self.mixed)  # no UserProfile row
		with self.assertNumQueries(1):
			self.assertIsNone(getattr(user, 'tenancy_profile', None))
			self.assertIsNone(getattr(user, 'tenancy_profile', None))
			self.assertIsNone(getattr(user, 'tenancy_profile', None))

	def count(self, user, path, slug=None, token=None):
		queries, _ = run_request(fresh(user), path, slug=slug, token=token)
		return len(queries)

	def test_report_counts(self):
		from agentapi.auth import create_token
		_, raw = create_token(self.member, 'measure')
		_, raw_m = create_token(self.mixed, 'measure')
		rows = {
			'member, project page (slug)': self.count(self.member, '/cve/proj-a/hosts/', slug='proj-a'),
			'member, page without a project': self.count(self.member, '/cve/'),
			'mixed (no MFA, no profile), project page': self.count(self.mixed, '/cve/proj-a/hosts/', slug='proj-a2'),
			'mixed, api call with ?project=': self.count(self.mixed, '/cve/api/hosts?project=proj-b'),
			'mixed, page without a project': self.count(self.mixed, '/cve/'),
			'superuser, project page': self.count(self.root, '/cve/proj-a/hosts/', slug='proj-a'),
			'member, bearer token /api/v1/': self.count(self.member, '/api/v1/projects', token=raw),
			'mixed, bearer token /api/v1/': self.count(self.mixed, '/api/v1/projects', token=raw_m),
		}
		for name, n in rows.items():
			print(f'QUERYCOUNT {n:3d}  {name}')


class SameAnswersTests(Fixture):
	"""Every user of the matrix gets exactly the allowed set, role and refusal the code without the snapshot gives."""

	def requests(self):
		for project in self.projects:
			yield f'/cve/{project.slug}/hosts/', project.slug, 'get'
			yield f'/cve/{project.slug}/hosts/', project.slug, 'post'
			yield f'/cve/api/hosts?project={project.slug}', None, 'get'
		yield '/cve/proj-missing/hosts/', 'proj-missing', 'get'
		yield '/cve/', None, 'get'
		yield '/cve/_all/hosts/', roles.ALL_PROJECTS, 'get'
		yield '/cve/bounty/', None, 'get'
		yield '/cve/settings/', None, 'get'
		yield '/cve/account/', None, 'get'

	def test_middleware_matrix(self):
		for user in self.everyone:
			for path, slug, method in self.requests():
				with self.subTest(user=user.username, path=path, method=method):
					with NO_SNAPSHOT:
						_, old = run_request(fresh(user), path, slug=slug, method=method)
					_, new = run_request(fresh(user), path, slug=slug, method=method)
					self.assertEqual(new, old)

	def test_mfa_matrix(self):
		Org.objects.filter(pk=self.org2.pk).update(require_mfa=True)
		for user in self.everyone:
			for path, slug, method in self.requests():
				with self.subTest(user=user.username, path=path, method=method):
					with NO_SNAPSHOT:
						_, old = run_request(fresh(user), path, slug=slug, method=method)
					_, new = run_request(fresh(user), path, slug=slug, method=method)
					self.assertEqual(new, old)
		_, outcome = run_request(fresh(self.auditor), '/cve/', method='get')
		self.assertEqual(outcome['blocked'], 302)  # org2 requires MFA and the auditor has none
		_, outcome = run_request(fresh(self.mixed), '/cve/', method='get')
		self.assertEqual(outcome['blocked'], 302)  # a direct member of org2's project is covered too

	def test_role_functions_inside_and_outside_a_snapshot(self):
		for user in self.everyone:
			u = fresh(user)
			expected = (roles.allowed_project_ids(u), roles.user_best_role(u), roles.requires_mfa(u),
			            [roles.effective_role(u, p) for p in self.projects])
			with snapshot.activate(u):
				got = (roles.allowed_project_ids(u), roles.user_best_role(u), roles.requires_mfa(u),
				       [roles.effective_role(u, p) for p in self.projects])
				with self.assertNumQueries(0):  # the second round is answered from the snapshot
					again = (roles.allowed_project_ids(u), roles.user_best_role(u), roles.requires_mfa(u),
					         [roles.effective_role(u, p) for p in self.projects])
			self.assertEqual(got, expected, user.username)
			self.assertEqual(again, expected, user.username)

	def test_allowed_set_under_an_active_scope_matches(self):
		"""Inside a view the original reads organization projects through the scoped manager: the snapshot cuts the same way."""
		u = fresh(self.orgadmin)
		narrow = {self.pa.pk, self.pb.pk}
		with NO_SNAPSHOT:
			tokens = scope.set_scope(set(narrow), u)
			try:
				expected = roles.allowed_project_ids(u)
			finally:
				scope.reset_scope(tokens)
		with snapshot.activate(u):
			self.assertEqual(roles.allowed_project_ids(u), {self.pa.pk, self.pa2.pk})
			tokens = scope.set_scope(set(narrow), u)
			try:
				self.assertEqual(roles.allowed_project_ids(u), expected)
			finally:
				scope.reset_scope(tokens)
		self.assertEqual(expected, {self.pa.pk})

	def test_returned_sets_are_never_shared(self):
		u = fresh(self.mixed)
		with snapshot.activate(u):
			first = roles.allowed_project_ids(u)
			first.add(999999)  # scope.allow adds to the set the middleware published
			self.assertNotIn(999999, roles.allowed_project_ids(u))


class FreshnessTests(Fixture):
	"""A change counts from the very next request, and from the next question when it is made inside the request."""

	def test_removed_membership_counts_on_the_next_request(self):
		_, outcome = run_request(fresh(self.member), '/cve/proj-a/hosts/', slug='proj-a')
		self.assertEqual((outcome['role'], outcome['allowed']), ('user', {self.pa.pk}))
		ProjectMembership.objects.filter(user=self.member, project=self.pa).delete()
		_, outcome = run_request(fresh(self.member), '/cve/proj-a/hosts/', slug='proj-a')
		self.assertEqual((outcome['blocked'], outcome['allowed']), (404, set()))

	def test_removed_org_membership_counts_on_the_next_request(self):
		_, outcome = run_request(fresh(self.orgadmin), '/cve/proj-a2/hosts/', slug='proj-a2')
		self.assertEqual(outcome['role'], 'admin')
		OrgMembership.objects.filter(user=self.orgadmin).delete()
		_, outcome = run_request(fresh(self.orgadmin), '/cve/proj-a2/hosts/', slug='proj-a2')
		self.assertEqual((outcome['blocked'], outcome['allowed']), (404, set()))

	def test_role_change_counts_on_the_next_request(self):
		OrgMembership.objects.filter(user=self.orgadmin).update(role='audit')  # a bulk update fires no signal; nothing is kept between requests
		_, outcome = run_request(fresh(self.orgadmin), '/cve/proj-a/hosts/', slug='proj-a', method='post')
		self.assertEqual(outcome['blocked'], 403)

	def test_project_moved_or_deleted_counts_on_the_next_request(self):
		Project.objects.filter(pk=self.pa2.pk).update(org=self.org2)
		_, outcome = run_request(fresh(self.orgadmin), '/cve/', method='get')
		self.assertEqual(outcome['allowed'], {self.pa.pk})
		self.pa.delete()
		_, outcome = run_request(fresh(self.orgadmin), '/cve/', method='get')
		self.assertEqual(outcome['allowed'], set())

	def test_require_mfa_counts_on_the_next_request(self):
		_, outcome = run_request(fresh(self.orgadmin), '/cve/', method='get')
		self.assertIsNone(outcome['blocked'])
		self.org1.require_mfa = True
		self.org1.save()
		_, outcome = run_request(fresh(self.orgadmin), '/cve/', method='get')
		self.assertEqual(outcome['blocked'], 302)
		Org.objects.filter(pk=self.org1.pk).update(require_mfa=False)
		_, outcome = run_request(fresh(self.orgadmin), '/cve/', method='get')
		self.assertIsNone(outcome['blocked'])

	def test_require_mfa_counts_for_a_bearer_token_on_the_next_request(self):
		from agentapi.auth import create_token
		_, raw = create_token(self.orgadmin, 'fresh')
		_, outcome = run_request(fresh(self.orgadmin), '/api/v1/projects', token=raw)
		self.assertIsNone(outcome['blocked'])
		Org.objects.filter(pk=self.org1.pk).update(require_mfa=True)
		_, outcome = run_request(fresh(self.orgadmin), '/api/v1/projects', token=raw)
		self.assertEqual(outcome['blocked'], 403)

	def check_write_in_view(self, write):
		"""``write`` runs inside the view of a request that already asked every question once; the next question must see it."""
		def in_view(req):
			u = req.user
			before = (roles.allowed_project_ids(u), roles.effective_role(u, self.pa))
			write()
			return before, (roles.allowed_project_ids(u), roles.effective_role(u, self.pa), roles.user_best_role(u))
		_, outcome = run_request(fresh(self.orgadmin), '/cve/proj-a/hosts/', slug='proj-a', in_view=in_view)
		return outcome['in_view']

	def test_membership_deleted_inside_the_request(self):
		before, after = self.check_write_in_view(lambda: OrgMembership.objects.get(user=self.orgadmin).delete())
		self.assertEqual(before, ({self.pa.pk, self.pa2.pk}, 'admin'))
		self.assertEqual(after, (set(), None, None))

	def test_bulk_update_inside_the_request(self):
		before, after = self.check_write_in_view(lambda: OrgMembership.objects.filter(user=self.orgadmin).update(role='audit'))
		self.assertEqual(after[1:], ('audit', 'audit'))

	def test_bulk_create_inside_the_request(self):
		before, after = self.check_write_in_view(
			lambda: ProjectMembership.objects.bulk_create([ProjectMembership(user=self.orgadmin, project=self.pb, role='user')]))
		self.assertEqual(after[0], {self.pa.pk, self.pa2.pk, self.pb.pk})

	def test_raw_sql_inside_the_request(self):
		def write():
			with connection.cursor() as cur:
				cur.execute(f'DELETE FROM {OrgMembership._meta.db_table} WHERE user_id = %s', [self.orgadmin.pk])
		before, after = self.check_write_in_view(write)
		self.assertEqual(after, (set(), None, None))

	def test_rolled_back_write_inside_the_request(self):
		from django.db import transaction

		def write():
			try:
				with transaction.atomic():
					OrgMembership.objects.filter(user=self.orgadmin).delete()
					self.assertIsNone(roles.effective_role(fresh(self.orgadmin), self.pa))
					raise RuntimeError('roll back')
			except RuntimeError:
				pass
		before, after = self.check_write_in_view(write)
		self.assertEqual(after, ({self.pa.pk, self.pa2.pk}, 'admin', 'admin'))  # the membership is back, and so is the answer

	def test_write_by_another_request_of_this_process(self):
		u = fresh(self.orgadmin)
		with snapshot.activate(u):
			self.assertEqual(roles.effective_role(u, self.pa), 'admin')
			contextvars.Context().run(lambda: OrgMembership.objects.filter(user=self.orgadmin).delete())  # no snapshot of ours is active there
			self.assertIsNone(roles.effective_role(u, self.pa))
			self.assertEqual(roles.allowed_project_ids(u), set())


class IsolationTests(Fixture):
	"""A snapshot answers only for the user it was read for, and only while its request runs."""

	def test_other_users_are_asked_of_the_database(self):
		me, other = fresh(self.orgadmin), fresh(self.auditor)
		with snapshot.activate(me):
			roles.allowed_project_ids(me)
			self.assertEqual(roles.allowed_project_ids(other), {self.pb.pk})
			self.assertEqual(roles.effective_role(other, self.pb), 'audit')
			self.assertIsNone(roles.effective_role(other, self.pa))
			self.assertEqual(roles.user_best_role(other), 'audit')
			with CaptureQueriesContext(connection) as ctx:
				roles.allowed_project_ids(other)
			self.assertTrue(ctx.captured_queries)

	def test_anonymous_and_unsaved_users_never_match(self):
		from django.contrib.auth.models import AnonymousUser
		with snapshot.activate(fresh(self.orgadmin)):
			self.assertIsNone(snapshot.for_user(AnonymousUser()))
			self.assertIsNone(snapshot.for_user(User(username='ghost')))
			self.assertIsNone(snapshot.for_user(None))

	def test_nothing_is_left_active_after_a_request(self):
		run_request(fresh(self.member), '/cve/proj-a/hosts/', slug='proj-a')
		self.assertIsNone(snapshot._active.get())
		with CaptureQueriesContext(connection) as ctx:
			roles.allowed_project_ids(fresh(self.member))
		self.assertTrue(ctx.captured_queries)

	def test_switching_users_between_requests(self):
		for user in self.everyone + list(reversed(self.everyone)):
			with self.subTest(user=user.username):
				with NO_SNAPSHOT:
					_, old = run_request(fresh(user), '/cve/', method='get')
				_, new = run_request(fresh(user), '/cve/', method='get')
				self.assertEqual(new, old)

	def test_token_user_not_session_user(self):
		"""A bearer token's owner, not the browser session that came with it, is who the snapshot is read for."""
		from agentapi.auth import create_token
		_, raw = create_token(self.auditor, 'other')

		def in_view(req):
			return req.user.pk, roles.allowed_project_ids(req.user), roles.user_best_role(req.user)
		_, outcome = run_request(fresh(self.orgadmin), '/api/v1/projects', token=raw, in_view=in_view)
		self.assertEqual(outcome['in_view'], (self.auditor.pk, {self.pb.pk}, 'audit'))
		self.assertEqual(outcome['allowed'], {self.pb.pk})
