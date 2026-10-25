from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Org, OrgMembership, Project, ProjectMembership, UserProfile
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain
from tenancy import roles, scope
from tenancy.drf import ProjectScopeFilterBackend


def client_for(user):
	c = Client()
	ss = SessionStore()
	ss[SESSION_KEY] = str(user.pk)
	ss[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
	ss[HASH_SESSION_KEY] = user.get_session_auth_hash()
	ss.save()
	c.cookies[settings.SESSION_COOKIE_NAME] = ss.session_key
	return c


class RuleTests(TestCase):
	def test_resolve_role_project_overrides_org(self):
		self.assertEqual(roles.resolve_role('audit', 'admin'), 'audit')
		self.assertEqual(roles.resolve_role(None, 'user'), 'user')
		self.assertEqual(roles.resolve_role(None, None), None)
		self.assertEqual(roles.resolve_role(None, None, is_superuser=True), 'admin')

	def test_check_access(self):
		ok = roles.check_access
		self.assertIsNotNone(ok(None, 'GET', '/scan/x/history/scan'))
		self.assertIsNone(ok('audit', 'GET', '/scan/x/history/scan'))
		self.assertIsNotNone(ok('audit', 'POST', '/scan/x/start/1'))
		self.assertIsNone(ok('user', 'POST', '/scan/x/start/1'))
		self.assertIsNotNone(ok('admin', 'GET', '/scanEngine/x/api_vault'))  # instance-wide: superuser only
		self.assertIsNone(ok('admin', 'GET', '/scanEngine/x/api_vault', is_superuser=True))
		self.assertIsNotNone(ok('user', 'GET', '/scanEngine/x/proxy_settings'))
		self.assertIsNotNone(ok('admin', 'GET', '/scanEngine/x/proxy_settings'))  # global singleton: superuser only
		self.assertIsNone(ok('admin', 'GET', '/scanEngine/x/proxy_settings', is_superuser=True))
		self.assertIsNotNone(ok('admin', 'POST', '/scanEngine/x/delete/3'))  # engines are shared
		self.assertIsNotNone(ok('admin', 'GET', '/cve/settings/'))
		self.assertIsNotNone(ok('user', 'GET', '/x/bountyhub/list/programs', bugbounty_enabled=True))
		self.assertIsNotNone(ok('pentester', 'GET', '/x/bountyhub/list/programs', bugbounty_enabled=False))
		self.assertIsNone(ok('pentester', 'GET', '/x/bountyhub/list/programs', bugbounty_enabled=True))
		self.assertIsNone(ok(None, 'GET', '/login/'))
		self.assertIsNotNone(ok('admin', 'GET', '/proj/admin_interface/'))  # superuser only
		self.assertIsNone(ok('admin', 'GET', '/proj/admin_interface/', is_superuser=True))


class IsolationTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org1, cls.org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=cls.org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=cls.org2)
		cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		cls.sa = ScanHistory.objects.create(domain=cls.da, scan_type=engine, start_scan_date=now)
		cls.sb = ScanHistory.objects.create(domain=cls.db, scan_type=engine, start_scan_date=now)
		mk = lambda n, **kw: User.objects.create_user(n, password='x', **kw)
		cls.alice, cls.bob, cls.carol, cls.dave, cls.erin = (mk(n) for n in ('alice', 'bob', 'carol', 'dave', 'erin'))
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='admin')
		OrgMembership.objects.create(user=cls.bob, org=cls.org2, role='user')
		ProjectMembership.objects.create(user=cls.carol, project=cls.pa, role='audit')
		ProjectMembership.objects.create(user=cls.erin, project=cls.pa, role='pentester')

	def under(self, user):
		return scope.set_scope(roles.allowed_project_ids(user), user)

	def test_allowed_ids(self):
		self.assertEqual(roles.allowed_project_ids(self.alice), {self.pa.id})
		self.assertEqual(roles.allowed_project_ids(self.bob), {self.pb.id})
		self.assertEqual(roles.allowed_project_ids(self.dave), set())
		self.assertIsNone(roles.allowed_project_ids(User.objects.create_superuser('root', 'r@x.io', 'x')))

	def test_org_role_covers_all_org_projects_and_project_role_overrides(self):
		extra = Project.objects.create(name='C', slug='proj-c', insert_date=timezone.now(), org=self.org2)
		self.assertEqual(roles.effective_role(self.bob, extra), 'user')
		ProjectMembership.objects.create(user=self.bob, project=extra, role='audit')
		self.assertEqual(roles.effective_role(self.bob, extra), 'audit')
		self.assertEqual(roles.effective_role(self.bob, self.pb), 'user')

	def test_managers_hide_other_projects(self):
		tokens = self.under(self.alice)
		try:
			self.assertEqual(list(Domain.objects.values_list('name', flat=True)), ['a.example'])
			self.assertEqual(list(Project.objects.values_list('slug', flat=True)), ['proj-a'])
			with self.assertRaises(ScanHistory.DoesNotExist):
				ScanHistory.objects.get(id=self.sb.id)  # lookup by id of another project's scan
			self.assertEqual(ScanHistory.objects.get(id=self.sa.id).pk, self.sa.pk)
		finally:
			scope.reset_scope(tokens)
		self.assertEqual(Domain.objects.count(), 2)  # no scope active: unrestricted (celery, shell)

	def test_host_assessment_rows_are_project_scoped(self):
		from cveFeed.models import HostAssessment
		own = HostAssessment.objects.create(project=self.pa, domain=self.da, host='a.example', status='completed')
		other = HostAssessment.objects.create(project=self.pb, domain=self.db, host='b.example', status='completed')
		tokens = self.under(self.alice)
		try:
			self.assertEqual(list(HostAssessment.objects.values_list('pk', flat=True)), [own.pk])
			with self.assertRaises(HostAssessment.DoesNotExist):
				HostAssessment.objects.get(pk=other.pk)
		finally:
			scope.reset_scope(tokens)

	def test_user_with_no_membership_sees_nothing(self):
		tokens = self.under(self.dave)
		try:
			self.assertEqual(Domain.objects.count(), 0)
			self.assertEqual(ScanHistory.objects.count(), 0)
		finally:
			scope.reset_scope(tokens)

	def test_drf_backend_scopes_import_time_querysets(self):
		queryset = Domain.objects.all()  # built outside any scope, like a class-level viewset queryset
		tokens = self.under(self.bob)
		try:
			out = ProjectScopeFilterBackend().filter_queryset(None, queryset, None)
			self.assertEqual(list(out.values_list('name', flat=True)), ['b.example'])
		finally:
			scope.reset_scope(tokens)

	def test_http_cross_project_is_404_and_roles_enforced(self):
		self.assertEqual(client_for(self.alice).get('/cve/proj-b/hosts/').status_code, 404)
		self.assertEqual(client_for(self.alice).get('/cve/proj-a/hosts/').status_code, 200)
		self.assertEqual(client_for(self.dave).get('/cve/proj-a/hosts/').status_code, 404)
		self.assertEqual(client_for(self.carol).post('/cve/proj-a/hosts/').status_code, 403)  # audit is read only
		self.assertEqual(client_for(self.alice).get('/cve/settings/').status_code, 403)  # instance-wide: app admin only
		self.assertEqual(client_for(self.bob).get('/cve/api/settings/ai').status_code, 403)

	def test_user_management_is_superuser_only_and_grants_membership(self):
		self.assertEqual(client_for(self.alice).get('/cve/api/admin/users').status_code, 403)  # not an org admin
		roles.grant_from_legacy_role(self.dave, 'auditor', org_slug='one')
		self.assertEqual(roles.effective_role(self.dave, self.pa), 'audit')
		roles.grant_from_legacy_role(self.dave, 'sys_admin', org_slug='one')  # update, not duplicate
		self.assertEqual(OrgMembership.objects.filter(user=self.dave).count(), 1)
		self.assertEqual(roles.effective_role(self.dave, self.pa), 'admin')

	def test_new_project_goes_to_creators_org_and_makes_creator_admin(self):
		OrgMembership.objects.create(user=self.dave, org=self.org1, role='admin')
		tokens = self.under(self.dave)
		try:
			project = Project.objects.create(name='N', slug='proj-n', insert_date=timezone.now())
		finally:
			scope.reset_scope(tokens)
		project.refresh_from_db()
		self.assertEqual(project.org_id, self.org1.id)
		self.assertTrue(ProjectMembership.objects.filter(user=self.dave, project=project, role='admin').exists())

	def test_global_role_tracks_best_tenancy_role(self):
		from rolepermissions.roles import get_user_roles
		self.assertEqual([r.get_name() for r in get_user_roles(self.alice)], ['penetration_tester'])  # tenant admin is not instance-wide sys_admin
		self.assertEqual([r.get_name() for r in get_user_roles(self.carol)], ['auditor'])


class MfaUnitTests(TestCase):
	RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'  # ASCII "12345678901234567890"

	def test_rfc6238_vector(self):
		from tenancy import mfa
		self.assertEqual(mfa.hotp(self.RFC_SECRET, 59 // 30, digits=8), '94287082')
		self.assertEqual(mfa.totp(self.RFC_SECRET, for_time=59), '287082')

	def test_verify_window_and_replay(self):
		from tenancy import mfa
		code = mfa.totp(self.RFC_SECRET, for_time=1000)
		step = mfa.verify(self.RFC_SECRET, code, for_time=1000)
		self.assertEqual(step, 1000 // 30)
		self.assertIsNotNone(mfa.verify(self.RFC_SECRET, code, for_time=1030))  # one step of drift
		self.assertIsNone(mfa.verify(self.RFC_SECRET, code, for_time=1200))  # too old
		self.assertIsNone(mfa.verify(self.RFC_SECRET, code, for_time=1000, last_used_step=step))  # replay
		self.assertIsNone(mfa.verify(self.RFC_SECRET, 'abc123', for_time=1000))

	def test_recovery_codes_single_use(self):
		from tenancy import mfa
		plain, hashes = mfa.new_recovery_codes()
		self.assertEqual(len(set(plain)), mfa.RECOVERY_CODE_COUNT)
		rest = mfa.consume_recovery_code(hashes, plain[0].upper())
		self.assertEqual(len(rest), len(hashes) - 1)
		self.assertIsNone(mfa.consume_recovery_code(rest, plain[0]))


class MfaFlowTests(TestCase):
	def setUp(self):
		from django.core.cache import cache
		from tenancy import mfa
		cache.clear()
		self.user = User.objects.create_user('mia', password='pw-12345')
		self.secret = mfa.new_secret()
		self.profile = UserProfile.objects.create(user=self.user, mfa_enabled=True, mfa_secret=self.secret)

	def test_password_alone_does_not_log_in_then_code_does(self):
		from tenancy import mfa
		c = Client()
		r = c.post('/login/', {'username': 'mia', 'password': 'pw-12345'})
		self.assertEqual((r.status_code, r['Location']), (302, '/mfa/verify/'))
		self.assertNotIn(SESSION_KEY, c.session)
		self.assertEqual(c.post('/mfa/verify/', {'code': '000000'}).status_code, 200)  # wrong code
		self.assertNotIn(SESSION_KEY, c.session)
		r = c.post('/mfa/verify/', {'code': mfa.totp(self.secret)})
		self.assertEqual(r.status_code, 302)
		self.assertEqual(c.session[SESSION_KEY], str(self.user.pk))

	def test_lockout_after_repeated_failures(self):
		from tenancy import mfa, views
		c = Client()
		c.post('/login/', {'username': 'mia', 'password': 'pw-12345'})
		for _ in range(views.MAX_FAILURES):
			c.post('/mfa/verify/', {'code': '000000'})
		r = c.post('/mfa/verify/', {'code': mfa.totp(self.secret)})  # even a right code is refused while locked
		self.assertEqual(r.status_code, 200)
		self.assertNotIn(SESSION_KEY, c.session)

	def test_org_requiring_mfa_redirects_users_without_it(self):
		org = Org.objects.create(name='Strict', slug='strict', require_mfa=True)
		other = User.objects.create_user('nomfa', password='x')
		OrgMembership.objects.create(user=other, org=org, role='user')
		r = client_for(other).get('/cve/')
		self.assertEqual((r.status_code, r['Location']), (302, '/cve/account/#security'))
		self.assertEqual(client_for(other).get('/cve/account/').status_code, 200)  # the enrolment page itself stays reachable

	def test_enrol_flow(self):
		from tenancy import mfa
		other = User.objects.create_user('newbie', password='x')
		c = client_for(other)
		start = c.post('/cve/api/account/mfa/start', content_type='application/json')
		self.assertEqual(start.status_code, 200)
		secret = start.json()['secret']
		self.assertEqual(secret, c.session['mfa_setup_secret'])
		self.assertIn('otpauth://totp/', start.json()['uri'])
		bad = c.post('/cve/api/account/mfa/enable', {'code': '000000'}, content_type='application/json')
		self.assertEqual(bad.status_code, 400)
		done = c.post('/cve/api/account/mfa/enable', {'code': mfa.totp(secret)}, content_type='application/json')
		self.assertEqual(done.status_code, 200)
		self.assertTrue(done.json()['mfa_enabled'])
		self.assertEqual(len(done.json()['recovery_codes']), mfa.RECOVERY_CODE_COUNT)
		self.assertNotIn('mfa_setup_secret', c.session)
		profile = UserProfile.objects.get(user=other)
		self.assertTrue(profile.mfa_enabled)
		self.assertEqual(len(profile.recovery_codes), mfa.RECOVERY_CODE_COUNT)
		again = c.post('/cve/api/account/mfa/start', content_type='application/json')
		self.assertEqual(again.status_code, 400)  # already on: no new secret is issued

	def test_enable_needs_a_started_setup(self):
		other = User.objects.create_user('nostart', password='x')
		r = client_for(other).post('/cve/api/account/mfa/enable', {'code': '123456'}, content_type='application/json')
		self.assertEqual(r.status_code, 400)
		self.assertFalse(UserProfile.objects.filter(user=other, mfa_enabled=True).exists())

	def test_disable_needs_a_valid_code_and_honours_the_org_requirement(self):
		from django.core.cache import cache
		from tenancy import mfa
		c = client_for(self.user)
		self.assertEqual(c.post('/cve/api/account/mfa/disable', {'code': '000000'}, content_type='application/json').status_code, 400)
		self.profile.refresh_from_db()
		self.assertTrue(self.profile.mfa_enabled)
		org = Org.objects.create(name='Strict2', slug='strict2', require_mfa=True)
		membership = OrgMembership.objects.create(user=self.user, org=org, role='user')
		r = c.post('/cve/api/account/mfa/disable', {'code': mfa.totp(self.secret)}, content_type='application/json')
		self.assertEqual(r.status_code, 400)
		membership.delete()
		cache.clear()
		r = c.post('/cve/api/account/mfa/disable', {'code': mfa.totp(self.secret)}, content_type='application/json')
		self.assertEqual(r.status_code, 200)
		self.assertFalse(r.json()['mfa_enabled'])
		self.profile.refresh_from_db()
		self.assertFalse(self.profile.mfa_enabled)
		self.assertEqual(self.profile.mfa_secret, '')

	def test_disable_locks_out_after_repeated_failures(self):
		from tenancy import mfa, views
		c = client_for(self.user)
		for _ in range(views.MAX_FAILURES):
			c.post('/cve/api/account/mfa/disable', {'code': '000000'}, content_type='application/json')
		r = c.post('/cve/api/account/mfa/disable', {'code': mfa.totp(self.secret)}, content_type='application/json')
		self.assertEqual(r.status_code, 429)
		self.profile.refresh_from_db()
		self.assertTrue(self.profile.mfa_enabled)

	def test_old_mfa_pages_forward_to_my_account(self):
		c = client_for(self.user)
		for path in ('/mfa/setup/', '/mfa/disable/'):
			r = c.get(path)
			self.assertEqual((r.status_code, r['Location']), (302, '/cve/account/#security'))

	def test_about_page_is_open_to_any_signed_in_user(self):
		nobody = User.objects.create_user('noaccess', password='x')
		r = client_for(nobody).get('/cve/about/')
		self.assertContains(r, 'github.com/hevnsnt/CVEngine')
		self.assertContains(r, 'reNgine')
		self.assertContains(r, 'https://github.com/ACK-J/MailFail')
		self.assertContains(r, 'Black Hills Information Security')


@override_settings(ALLOWED_HOSTS=['cve.example.test'])
class CsrfBehindProxyTests(TestCase):
	"""Django 4+ compares the browser's Origin with the scheme the app sees; nginx terminates TLS, so the app must
	trust X-Forwarded-Proto or every https form POST fails. A foreign Origin must still be refused."""

	def _post_login(self, **headers):
		c = Client(enforce_csrf_checks=True)
		page = c.get('/login/', HTTP_HOST='cve.example.test', HTTP_X_FORWARDED_PROTO='https')
		token = c.cookies['csrftoken'].value
		return c.post('/login/', {'username': 'x', 'password': 'y', 'csrfmiddlewaretoken': token},
					  HTTP_HOST='cve.example.test', **headers)

	def test_https_origin_through_the_proxy_passes_the_csrf_check(self):
		r = self._post_login(HTTP_ORIGIN='https://cve.example.test', HTTP_X_FORWARDED_PROTO='https')
		self.assertNotEqual(r.status_code, 403)  # a wrong password is a 200 re-render, not a CSRF refusal

	def test_foreign_origin_is_still_refused_with_a_helpful_page(self):
		r = self._post_login(HTTP_ORIGIN='https://evil.example', HTTP_X_FORWARDED_PROTO='https')
		self.assertContains(r, 'Could not verify this request', status_code=403)


class SignOutTests(TestCase):
	"""Django 5 signs out on POST only; the app's links must POST, and an old GET link must not be an error."""

	def setUp(self):
		self.user = User.objects.create_user('leaver', password='x', is_superuser=True)
		self.client = Client()
		self.client.force_login(self.user)

	def test_post_signs_out(self):
		self.assertEqual(self.client.post('/logout/').status_code, 302)
		r = self.client.get('/cve/account/')
		self.assertEqual(r.status_code, 302)
		self.assertIn('/login/', r['Location'])  # the session is gone

	def test_get_asks_first_and_keeps_the_session(self):
		r = self.client.get('/logout/')
		self.assertContains(r, 'Sign out?')
		self.assertContains(r, 'method="post"')
		self.assertEqual(self.client.get('/cve/account/').status_code, 200)  # still signed in

	def test_the_shell_signs_out_with_a_form(self):
		r = self.client.get('/cve/account/')
		self.assertNotContains(r, 'href="/logout/"')
		self.assertContains(r, 'action="/logout/"')
