"""CSRF on every state-changing route, and no state change behind a GET.

A signed-in browser session is the credential a page on another site can make the browser send. Every route that changes something must
then refuse a request without the CSRF token (Django's ``CsrfViewMiddleware``; a bearer token is exempt because no cookie is involved), and a
GET, which a link or an image can make, must not change anything. The routes are enumerated from the route tables and from the URL
configuration, so a new route without a line here fails ``test_every_url_pattern_has_a_line``.
"""
import json
import re

from django.conf import settings
from django.contrib.auth.models import User
from django.db import connection, transaction
from django.test import Client, TestCase
from django.urls import get_resolver
from django.utils import timezone

from agentapi import rest
from cveFeed import account_api, admin_api, bounty_api, settings_api, welcome
from dashboard.models import Org, OrgMembership, Project, UserProfile
from tests.test_tenancy import client_for

PATH_ARG = re.compile(r'\(\?P<(\w+)>[^)]*\)')
# tables a request may write whatever it does: the session (saved on every request), usage stamps, the guard's and the audit log, the MCP history
LOG_TABLES = {'django_session', 'dashboard_apitoken', 'dashboard_abusestrike', 'dashboard_auditlog', 'cveFeed_mcpcall', 'agentapi_agent'}

# Every view of the URL configuration (by its dotted name): how it is reached. 'csrf': its non-GET methods are in the lists below and are
# CSRF-checked. 'get': it only reads (any method other than GET and HEAD changes nothing). 'exempt': refuses CSRF on purpose, with the reason.
VIEWS = {
	'agentapi.mcp.endpoint': 'csrf', 'agentapi.rest.dispatch': 'csrf',
	'tenancy.views.admin_login_redirect': 'get', 'django.contrib.admin.sites.index': 'csrf',
	'dashboard.views.home': 'get', 'tenancy.views.verify_view': 'csrf', 'tenancy.views.setup_view': 'csrf', 'tenancy.views.disable_view': 'csrf',
	'tenancy.views.nag_snooze_view': 'csrf',
	'cveFeed.views.dashboard': 'get', 'cveFeed.views.graph': 'get', 'cveFeed.views.welcome_page': 'get', 'cveFeed.views.update_questions_page': 'get',
	'cveFeed.welcome.dispatch': 'csrf', 'cveFeed.views.account_page': 'get', 'cveFeed.views.about_page': 'get', 'cveFeed.views.ai_data_page': 'get',
	'cveFeed.views.mcp_page': 'get', 'cveFeed.views.how_page': 'get', 'cveFeed.views.admin_page': 'get', 'cveFeed.account_api.dispatch': 'csrf',
	'cveFeed.admin_api.dispatch': 'csrf', 'cveFeed.views.bounty_page': 'get', 'cveFeed.bounty_api.dispatch': 'csrf', 'cveFeed.views.settings_page': 'get',
	'cveFeed.settings_api.dispatch': 'csrf', 'cveFeed.views.agents_page': 'get', 'cveFeed.views.scanners_page': 'get', 'cveFeed.views.reports_page': 'get',
	'cveFeed.views.sentinels_page': 'get', 'cveFeed.views.onboarding': 'get', 'cveFeed.views.cve_explorer_page': 'get', 'cveFeed.views.scan_page': 'get',
	'cveFeed.views.host_screenshot': 'get', 'cveFeed.views.host_rdp_screenshot': 'get', 'cveFeed.views.project_page': 'get',
	'cveFeed.views.api_feed': 'get', 'cveFeed.views.api_cves': 'get', 'cveFeed.views.api_cve_detail': 'get', 'cveFeed.views.api_alive': 'get',
	'cveFeed.views.api_stats': 'get', 'cveFeed.views.api_overview': 'get', 'cveFeed.views.api_scanner': 'get', 'cveFeed.views.api_graph': 'get',
	'cveFeed.views.api_graph_live': 'get', 'cveFeed.views.api_node': 'get', 'cveFeed.views.api_activity': 'get', 'cveFeed.views.api_discovery': 'get',
	'cveFeed.views.api_detect': 'csrf', 'cveFeed.views.api_onboarding_save': 'csrf',
	'startScan.views.create_report': 'get', 'startScan.views.export_subdomains': 'get', 'startScan.views.export_endpoints': 'get',
	'startScan.views.export_urls': 'get',
	'tenancy.views.invite_view': 'csrf',
	'cveFeed.report_digest_views.unsubscribe': 'exempt',  # RFC 8058 one-click: the mail client POSTs with no cookie; the signed token is the credential
	'cvengine.client_probe.probe': 'get',
	'tenancy.views.MFALoginView': 'csrf', 'tenancy.views.SignOutView': 'csrf', 'cvengine.views.serve_protected_media': 'get',
	'django.views.static.serve': 'get',
	'django.views.generic.base.RedirectView': 'get',  # the admin's own redirects (a GET answers a redirect and changes nothing)
}
# the views of the URL configuration that take a POST (or PUT, PATCH, DELETE), each with a path to send it to
FORM_POSTS = (
	'/logout/', '/login/', '/mfa/verify/', '/mfa/setup/', '/mfa/disable/', '/mfa/remind-later/', '/invite/x/', '/cve/api/setup/detect',
	'/cve/api/setup/save', '/admin/auth/user/add/', '/mcp/',
)


def _name(callback):
	view = getattr(callback, 'view_class', None) or callback
	return f'{view.__module__}.{view.__qualname__}'


def _patterns(resolver, prefix=''):
	for p in resolver.url_patterns:
		if hasattr(p, 'url_patterns'):
			yield from _patterns(p, prefix + str(p.pattern))
		else:
			yield prefix + str(p.pattern), p.callback


class CsrfEveryRouteTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Csrf', slug='csrf')
		Project.objects.create(name='Csrf', slug='csrf', org=org, insert_date=timezone.now())
		cls.admin = User.objects.create_superuser('csrf-admin', 'csrf@example.com', 'x')
		UserProfile.objects.update_or_create(user=cls.admin, defaults={'must_change_password': False, 'onboarded': True})
		OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

	def _client(self):
		signed_in = client_for(self.admin)
		client = Client(enforce_csrf_checks=True)
		client.cookies = signed_in.cookies
		return client

	def _writes(self):
		with connection.cursor() as cursor:
			cursor.execute('SELECT pg_stat_clear_snapshot()')
			cursor.execute('SELECT relname, n_tup_ins + n_tup_upd + n_tup_del FROM pg_stat_xact_user_tables')
			return dict(cursor.fetchall())

	def _send(self, client, method, path, body='{}'):
		"""(status, tables written other than the log tables). Each request runs in a savepoint rolled back afterwards."""
		with transaction.atomic():
			before = self._writes()
			fn = getattr(client, method.lower())
			response = fn(path) if method in ('GET', 'HEAD') else fn(path, body, content_type='application/json')
			after = self._writes()
			transaction.set_rollback(True)
		return response.status_code, sorted(t for t, n in after.items() if n != before.get(t, 0) and t not in LOG_TABLES)

	def _writes_routes(self):
		fill = lambda pattern: PATH_ARG.sub(lambda m: {'slug': 'csrf', 'org': 'csrf', 'kind': 'match', 'service': 'shodan', 'ref': 't1',
		                                                 'cve_id': 'CVE-2024-0001', 'platform': 'hackerone', 'scope': 'org', 'which': 'seed'}.get(m.group(1), '1'), pattern)
		routes = [(m, '/api/v1/' + fill(p)) for m, p, _s, _f in rest.ROUTES if m != 'GET']
		routes += [(m, '/cve/api/admin/' + fill(p)) for m, p, _f in admin_api.ROUTES if m != 'GET']
		routes += [(m, '/cve/api/settings/' + fill(p)) for m, p, _f in settings_api.ROUTES if m != 'GET']
		routes += [(m, '/cve/api/bounty/' + fill(p)) for m, p, _f in bounty_api.ROUTES if m != 'GET']
		routes += [(m, '/cve/api/account/' + p) for (m, p) in account_api.ROUTES if m != 'GET']
		routes += [(m, '/cve/api/welcome/' + p) for (m, p) in welcome.ROUTES if m != 'GET']
		routes += [('POST', p) for p in FORM_POSTS]
		return routes

	def test_every_url_pattern_has_a_line(self):
		# the Django admin's own views are CSRF-protected by the admin site (and reached only by an App Admin through the two-step sign-in)
		names = {_name(callback) for _pattern, callback in _patterns(get_resolver())}
		names = {n for n in names if not n.startswith(('django.contrib.admin.', 'django.contrib.auth.admin.', 'django.contrib.contenttypes.views.', 'django_celery_beat.admin.'))}
		missing = sorted(names - set(VIEWS))
		self.assertEqual(missing, [], 'a view with no line in VIEWS, say how it is protected: ' + ', '.join(missing))

	def test_a_signed_in_session_without_the_csrf_token_changes_nothing(self):
		client = self._client()
		problems = []
		routes = self._writes_routes()
		self.assertGreater(len(routes), 200)
		for method, path in routes:
			if path == '/api/v1/sentinels/bootstrap':
				continue  # no session involved: the one-time enrollment secret is the credential (below)
			status, wrote = self._send(client, method, path)
			if status != 403 or wrote:
				problems.append(f'{method} {path}: {status} wrote {wrote}')
		self.assertFalse(problems, '\n' + '\n'.join(problems))

	def test_the_routes_that_skip_csrf_need_their_own_secret(self):
		client = self._client()
		status, wrote = self._send(client, 'POST', '/api/v1/sentinels/bootstrap', json.dumps({'enrollment_token': 'senr_not-a-real-one', 'name': 'x'}))
		self.assertIn(status, (400, 401, 403, 404))
		self.assertEqual(wrote, [])
		status, wrote = self._send(client, 'POST', '/unsubscribe/not-a-signed-token/', '')
		self.assertEqual(status, 404)
		self.assertEqual(wrote, [])

	def test_a_bearer_token_is_exempt_and_a_session_with_a_token_header_is_not_confused(self):
		"""A cookie and a forged Authorization header that is not a token: the request is still a session request and still CSRF-checked."""
		client = self._client()
		response = client.post('/api/v1/projects/csrf/targets', json.dumps({'value': 'x.example.com'}), content_type='application/json',
		                       HTTP_AUTHORIZATION='Basic eDp4')
		self.assertEqual(response.status_code, 403)

	def test_no_get_changes_anything(self):
		"""Every GET of the REST API and the pages' JSON, as an App Admin's session: nothing but the log tables is written. A GET can be made
		by a link or an image, so a GET that wrote would be a change another site can make."""
		client = client_for(self.admin)
		fill = lambda pattern: PATH_ARG.sub(lambda m: {'slug': 'csrf', 'org': 'csrf', 'kind': 'match', 'cve_id': 'CVE-2024-0001', 'which': 'seed'}.get(m.group(1), '1'), pattern)
		paths = ['/api/v1/' + fill(p) for m, p, _s, _f in rest.ROUTES if m == 'GET']
		paths += ['/cve/api/admin/' + fill(p) for m, p, _f in admin_api.ROUTES if m == 'GET']
		paths += ['/cve/api/settings/' + fill(p) for m, p, _f in settings_api.ROUTES if m == 'GET']
		paths += ['/cve/api/bounty/' + fill(p) for m, p, _f in bounty_api.ROUTES if m == 'GET']
		paths += ['/cve/api/feed', '/cve/api/cves', '/cve/api/stats', '/cve/api/overview', '/cve/api/scanner', '/cve/api/graph', '/cve/api/activity',
		          '/cve/api/discovery', '/cve/', '/cve/csrf/hosts/', '/cve/settings/', '/cve/admin/', '/mfa/setup/', '/mfa/remind-later/', '/logout/']
		for path in paths:
			client.get(path)  # once first: a settings row read for the first time is created with its defaults, which is not a change anyone asked for
		found = {}
		for path in paths:
			status, wrote = self._send(client, 'GET', path)
			if wrote:
				found[path] = wrote
		self.assertEqual(sorted(found), sorted(GET_WRITES), '\n' + '\n'.join(f'{p}: {t}' for p, t in sorted(found.items())))


# GETs that write, each with why it is not a change another site can use. Empty is the goal.
GET_WRITES = {
	# documented as GET or POST (docs/AGENT-API.md): each GET makes a new one-time enrollment secret. A link can make an admin's browser create
	# one, but the answer goes to that browser, never to the other site, and an unused secret expires (release150/N3b.md, low)
	'/api/v1/projects/csrf/sentinels/enroll': ['agentapi_sentinelenrollment'],
	'/api/v1/orgs/csrf/sentinels/enroll': ['agentapi_sentinelenrollment'],
	'/api/v1/sentinels/enroll': ['agentapi_sentinelenrollment'],
}
