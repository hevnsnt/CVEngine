"""Freezes the behaviour of the URL configuration, the protected media view and the small app glue rewritten from a specification
(upstream code removal, helpers part 2): route order, paths and names, the media access rules and headers, the WSGI entry point, the template
context, Celery's logging hook, the duration phrase and the ChaosAPIKey admin. Every assertion here also held before the rewrite."""
import importlib
import os
import shutil
import sys
import tempfile
import weakref
from unittest import mock

from django.contrib import admin
from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import resolve, reverse


class RootUrlTableTests(SimpleTestCase):
	EXPECTED = [  # (route, include module or view dotted path, name), in order
		('', 'agentapi.urls', None),
		('admin/login/', 'tenancy.views.admin_login_redirect', 'admin_login_redirect'),
		('admin/', 'admin', None),
		('', 'dashboard.urls', None),
		('mfa/', 'tenancy.urls', None),
		('cve/', 'cveFeed.urls', None),
		('scan/', 'startScan.urls', None),
		('invite/<str:token>/', 'tenancy.views.invite_view', 'invite'),
		('unsubscribe/<str:token>/', 'cveFeed.report_digest_views.unsubscribe', 'report_unsubscribe'),
		('client-address-probe/<str:token>/', 'cvengine.client_probe.probe', 'client_address_probe'),
		('login/', 'tenancy.views.MFALoginView', 'login'),
		('logout/', 'tenancy.views.SignOutView', 'logout'),
		('media/<path:path>', 'cvengine.views.serve_protected_media', 'serve_protected_media'),
	]

	@staticmethod
	def describe(entry):
		if hasattr(entry, 'url_patterns'):  # an include
			module = entry.urlconf_name
			target = getattr(module, '__name__', module)
			if getattr(entry, 'app_name', None) == 'admin':
				target = 'admin'
			return str(entry.pattern), target, None
		callback = entry.callback
		view = getattr(callback, 'view_class', None) or callback
		return str(entry.pattern), f'{view.__module__}.{view.__qualname__}', entry.name

	def test_routes_order_targets_and_names(self):
		from cvengine import urls
		self.assertEqual([self.describe(e) for e in urls.urlpatterns[:len(self.EXPECTED)]], self.EXPECTED)

	def test_only_the_debug_static_route_follows(self):
		from cvengine import urls
		self.assertLessEqual(len(urls.urlpatterns) - len(self.EXPECTED), 1)  # static() adds a route in debug mode only

	def test_login_and_logout_templates(self):
		self.assertEqual(resolve('/login/').func.view_initkwargs['template_name'], 'tenancy/login.html')
		self.assertEqual(resolve('/logout/').func.view_initkwargs['template_name'], 'base/logout.html')

	def test_admin_login_is_taken_before_the_stock_admin(self):
		self.assertEqual(resolve('/admin/login/').url_name, 'admin_login_redirect')

	def test_reverse(self):
		self.assertEqual(reverse('invite', args=['t0k']), '/invite/t0k/')
		self.assertEqual(reverse('report_unsubscribe', args=['t0k']), '/unsubscribe/t0k/')
		self.assertEqual(reverse('client_address_probe', args=['t0k']), '/client-address-probe/t0k/')
		self.assertEqual(reverse('serve_protected_media', args=['a_1/b c.png']), '/media/a_1/b%20c.png')
		self.assertEqual((reverse('login'), reverse('logout')), ('/login/', '/logout/'))

	def test_secret_fields_are_masked_once_at_import(self):
		from cvengine import urls
		with mock.patch('cvengine.admin_masking.mask_secret_fields') as mask:
			importlib.reload(urls)
		importlib.reload(urls)
		mask.assert_called_once_with()


class ScanUrlTests(SimpleTestCase):
	def test_report_and_export_routes(self):
		cases = [('create_report', {'id': 7}, '/scan/create_report/7', 'create_report'),
				 ('export_subdomains', {'scan_id': 7}, '/scan/export/subdomains/7', 'export_subdomains'),
				 ('export_endpoints', {'scan_id': 7}, '/scan/export/endpoints/7', 'export_endpoints'),
				 ('export_http_urls', {'scan_id': 7}, '/scan/export/urls/7', 'export_urls')]
		for name, kwargs, url, view in cases:
			self.assertEqual(reverse(name, kwargs=kwargs), url)
			match = resolve(url)
			self.assertEqual((match.func.__module__, match.func.__name__, match.kwargs), ('startScan.views', view, kwargs))
		from startScan import urls
		self.assertEqual(len(urls.urlpatterns), 4)


class ProtectedMediaRulesTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		from dashboard.models import Org, OrgMembership, Project
		from django.utils import timezone
		from scanEngine.models import EngineType
		from startScan.models import ScanHistory
		from targetApp.models import Domain
		now = timezone.now()
		org = Org.objects.create(name='Glue', slug='glue')
		project = Project.objects.create(name='Glue', slug='glue-p', insert_date=now, org=org)
		engine = EngineType.objects.create(engine_name='glue-e', yaml_configuration='x', default_engine=True)
		cls.domain = Domain.objects.create(name='under_score.example.test', project=project, insert_date=now)
		cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=2)
		cls.member = User.objects.create_user('glue-member', password='x')
		OrgMembership.objects.create(user=cls.member, org=org, role='user')
		cls.admin = User.objects.create_superuser('glue-admin', 'g@example.com', 'x')

	def setUp(self):
		self.base = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.base, True)
		self.media = os.path.join(self.base, 'media')
		self.folder = f'under_score.example.test_{self.scan.id}'
		os.makedirs(os.path.join(self.media, self.folder, 'sub'))
		for rel in ('shot.png', 'notes.zzunknown', 'sub/page.html'):
			with open(os.path.join(self.media, self.folder, rel), 'wb') as handle:
				handle.write(b'x')
		with open(os.path.join(self.base, 'outside.txt'), 'wb') as handle:
			handle.write(b'secret')
		os.symlink(os.path.join(self.base, 'outside.txt'), os.path.join(self.media, self.folder, 'escape.txt'))

	def get(self, user, rel):
		client = Client()
		if user is not None:
			client.force_login(user)
		with override_settings(MEDIA_ROOT=self.media):
			return client.get('/media/' + rel)

	def test_a_member_gets_the_internal_redirect_and_type(self):
		response = self.get(self.member, f'{self.folder}/shot.png')
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.content, b'')
		self.assertEqual(response['Content-Type'], 'image/png')
		self.assertEqual(response['X-Accel-Redirect'], f'/protected_media/{self.folder}/shot.png')
		nested = self.get(self.member, f'{self.folder}/sub/page.html')
		self.assertEqual((nested.status_code, nested['Content-Type']), (200, 'text/html'))
		self.assertEqual(nested['X-Accel-Redirect'], f'/protected_media/{self.folder}/sub/page.html')

	def test_an_unknown_type_is_octet_stream(self):
		self.assertEqual(self.get(self.member, f'{self.folder}/notes.zzunknown')['Content-Type'], 'application/octet-stream')

	def test_anonymous_is_sent_to_sign_in(self):
		response = self.get(None, f'{self.folder}/shot.png')
		self.assertEqual(response.status_code, 302)
		self.assertIn('/login/', response['Location'])

	def test_paths_outside_the_root_and_the_root_itself_are_404_even_for_an_admin(self):
		for rel in ('../outside.txt', f'{self.folder}/../../outside.txt', f'{self.folder}/escape.txt', '', '.'):
			self.assertEqual(self.get(self.admin, rel).status_code, 404, rel)

	def test_folder_names_that_are_not_a_visible_scan_are_404_for_a_member(self):
		for folder in (f'under_score.example.test_{self.scan.id}x', f'under_score.example.test_{self.scan.id + 1000}', 'under_score.example.test',
					   f'_{self.scan.id}', f'other.example.test_{self.scan.id}', f'under_score.example.test__{self.scan.id}'):
			os.makedirs(os.path.join(self.media, folder), exist_ok=True)
			with open(os.path.join(self.media, folder, 'shot.png'), 'wb') as handle:
				handle.write(b'x')
			self.assertEqual(self.get(self.member, f'{folder}/shot.png').status_code, 404, folder)
			self.assertEqual(self.get(self.admin, f'{folder}/shot.png').status_code, 200, folder)

	def test_a_null_byte_is_404_not_a_server_error(self):
		# new with the rewrite: os.path.realpath raises ValueError on a null byte, which used to end as a server error
		self.assertEqual(self.get(self.admin, f'{self.folder}/shot%00.png').status_code, 404)

	def test_a_missing_file_and_a_directory_are_404(self):
		for user in (self.member, self.admin):
			self.assertEqual(self.get(user, f'{self.folder}/missing.png').status_code, 404)
			self.assertEqual(self.get(user, f'{self.folder}/sub').status_code, 404)
			self.assertEqual(self.get(user, f'{self.folder}/sub/').status_code, 404)

	def test_a_missing_file_of_a_hidden_scan_looks_like_any_missing_file(self):
		self.assertEqual(self.get(self.member, 'nobody.example.test_999999/missing.png').status_code, 404)
		self.assertEqual(self.get(self.member, 'nobody.example.test_999999/missing.png').content,
						 self.get(self.member, f'{self.folder}/missing.png').content)


class WsgiTests(SimpleTestCase):
	def test_application_and_warmup(self):
		sys.modules.pop('cvengine.wsgi', None)
		with mock.patch('cveFeed.warmup.start') as start, mock.patch.dict(os.environ, {'DJANGO_SETTINGS_MODULE': 'cvengine.settings'}):
			module = importlib.import_module('cvengine.wsgi')
		start.assert_called_once_with('web')
		from django.core.handlers.wsgi import WSGIHandler
		self.assertIsInstance(module.application, WSGIHandler)

	def test_settings_module_is_only_a_default(self):
		sys.modules.pop('cvengine.wsgi', None)
		with mock.patch('cveFeed.warmup.start'), mock.patch.dict(os.environ, {'DJANGO_SETTINGS_MODULE': 'cvengine.settings'}):
			importlib.import_module('cvengine.wsgi')
			self.assertEqual(os.environ['DJANGO_SETTINGS_MODULE'], 'cvengine.settings')
		source = open(sys.modules['cvengine.wsgi'].__file__).read()
		self.assertIn("os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cvengine.settings')", source)
		self.assertLess(source.index('get_wsgi_application()'), source.index("warmup.start('web')"))


class ContextTests(SimpleTestCase):
	@override_settings(CVENGINE_CURRENT_VERSION='v9.8.7', CVENGINE_EDITION='glue-edition')
	def test_version_context(self):
		from cvengine.context_processors import version_context
		self.assertEqual(version_context(None), {'CVENGINE_CURRENT_VERSION': 'v9.8.7', 'CVENGINE_EDITION': 'glue-edition'})
		self.assertIsNot(version_context(None), version_context(None))

	def test_it_is_installed(self):
		from django.conf import settings
		processors = settings.TEMPLATES[0]['OPTIONS']['context_processors']
		self.assertIn('cvengine.context_processors.version_context', processors)


class CeleryLoggingTests(SimpleTestCase):
	def test_celery_uses_the_django_logging_configuration(self):
		from celery.signals import setup_logging
		from cvengine.celery import app
		hooks = [ref() if isinstance(ref, weakref.ReferenceType) else ref for _key, ref in setup_logging.receivers]
		hooks = [hook for hook in hooks if hook is not None and getattr(hook, '__module__', '') == 'cvengine.celery']
		self.assertEqual(len(hooks), 1)
		with mock.patch('logging.config.dictConfig') as configure:
			hooks[0](loglevel='INFO', logfile=None, format='', colorize=False)
		configure.assert_called_once_with(app.conf['LOGGING'])


class SpanTests(SimpleTestCase):
	def test_phrases(self):
		from cveFeed.maintainer_checks import span
		cases = {None: '0 seconds', 0: '0 seconds', 1: '1 seconds', -3: '-3 seconds', 59.9: '59 seconds', 89: '89 seconds', '45': '45 seconds',
				 90: '1 minutes', 119: '1 minutes', 120: '2 minutes', 7199: '119 minutes', 7200: '2 hours', 7259: '2 hours',
				 7260: '2 hours 1 minutes', 35940: '9 hours 59 minutes', 36000: '10 hours', 36060: '10 hours', 90061: '25 hours'}
		for seconds, phrase in cases.items():
			self.assertEqual(span(seconds), phrase, seconds)


class ChaosAdminTests(SimpleTestCase):
	def test_registered_with_the_stock_options(self):
		from dashboard.models import ChaosAPIKey
		self.assertIn(ChaosAPIKey, admin.site._registry)
		model_admin = admin.site._registry[ChaosAPIKey]
		self.assertIsInstance(model_admin, admin.ModelAdmin)
		# the stock options, plus the stored key hidden by cvengine.admin_masking (run when the URL configuration loads)
		self.assertEqual((model_admin.list_display, model_admin.fields), (('__str__',), None))
		self.assertEqual(tuple(model_admin.exclude or ()), ('key',))
