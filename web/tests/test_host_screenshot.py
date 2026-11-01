import os
import tempfile

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Org, OrgMembership, Project
from startScan.models import ScanHistory, Subdomain
from scanEngine.models import EngineType
from targetApp.models import Domain
from tests.test_tenancy import client_for
from django.contrib.auth.models import User


class HostScreenshotTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org_a = Org.objects.create(name='A', slug='a-shot')
		org_b = Org.objects.create(name='B', slug='b-shot')
		cls.project_a = Project.objects.create(name='A', slug='proj-a-shot', insert_date=now, org=org_a)
		cls.project_b = Project.objects.create(name='B', slug='proj-b-shot', insert_date=now, org=org_b)
		cls.domain_a = Domain.objects.create(name='a.example', project=cls.project_a, insert_date=now)
		cls.domain_b = Domain.objects.create(name='b.example', project=cls.project_b, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		cls.scan_a = ScanHistory.objects.create(domain=cls.domain_a, scan_type=engine, start_scan_date=now)
		cls.scan_b = ScanHistory.objects.create(domain=cls.domain_b, scan_type=engine, start_scan_date=now)
		cls.member_a = User.objects.create_user('membera', password='x')
		OrgMembership.objects.create(user=cls.member_a, org=org_a, role='user')

	def setUp(self):
		self.media_root = tempfile.mkdtemp()
		self.addCleanup(lambda: __import__('shutil').rmtree(self.media_root, ignore_errors=True))

	def _plant(self, rel_path, content=b'jpeg-bytes'):
		full = os.path.join(self.media_root, rel_path)
		os.makedirs(os.path.dirname(full), exist_ok=True)
		with open(full, 'wb') as f:
			f.write(content)

	def test_serves_the_screenshot_for_a_member_of_the_project(self):
		rel = 'a.example_1/screenshots/shot.jpeg'
		self._plant(rel)
		sub = Subdomain.objects.create(scan_history=self.scan_a, target_domain=self.domain_a, name='www.a.example', screenshot_path=rel)
		with self.settings(MEDIA_ROOT=self.media_root):
			resp = client_for(self.member_a).get(f'/cve/{self.project_a.slug}/hosts/{sub.id}/screenshot/')
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(b''.join(resp.streaming_content), b'jpeg-bytes')

	def test_404_for_a_subdomain_in_a_project_the_caller_cannot_see(self):
		rel = 'b.example_1/screenshots/shot.jpeg'
		self._plant(rel)
		sub = Subdomain.objects.create(scan_history=self.scan_b, target_domain=self.domain_b, name='www.b.example', screenshot_path=rel)
		with self.settings(MEDIA_ROOT=self.media_root):
			resp = client_for(self.member_a).get(f'/cve/{self.project_b.slug}/hosts/{sub.id}/screenshot/')
		self.assertEqual(resp.status_code, 404)

	def test_404_when_no_screenshot_recorded(self):
		sub = Subdomain.objects.create(scan_history=self.scan_a, target_domain=self.domain_a, name='www.a.example')
		resp = client_for(self.member_a).get(f'/cve/{self.project_a.slug}/hosts/{sub.id}/screenshot/')
		self.assertEqual(resp.status_code, 404)

	def test_path_traversal_in_stored_path_is_refused(self):
		sub = Subdomain.objects.create(scan_history=self.scan_a, target_domain=self.domain_a, name='www.a.example',
			screenshot_path='../../../etc/passwd')
		with self.settings(MEDIA_ROOT=self.media_root):
			resp = client_for(self.member_a).get(f'/cve/{self.project_a.slug}/hosts/{sub.id}/screenshot/')
		self.assertEqual(resp.status_code, 404)

	def test_missing_file_on_disk_is_404_not_a_crash(self):
		sub = Subdomain.objects.create(scan_history=self.scan_a, target_domain=self.domain_a, name='www.a.example',
			screenshot_path='a.example_1/screenshots/gone.jpeg')
		with self.settings(MEDIA_ROOT=self.media_root):
			resp = client_for(self.member_a).get(f'/cve/{self.project_a.slug}/hosts/{sub.id}/screenshot/')
		self.assertEqual(resp.status_code, 404)


class HostScreenshotThumbnailTests(HostScreenshotTests):
	"""?size=thumb on the same route: a cacheable 320px-wide JPEG, with the full image as the fallback."""

	def _plant_image(self, rel_path, size=(1280, 800), fmt='PNG'):
		from PIL import Image
		full = os.path.join(self.media_root, rel_path)
		os.makedirs(os.path.dirname(full), exist_ok=True)
		Image.new('RGB', size, (200, 30, 30)).save(full, fmt)

	def _sub(self, rel):
		return Subdomain.objects.create(scan_history=self.scan_a, target_domain=self.domain_a, name='www.a.example', screenshot_path=rel)

	def _get(self, sub, query='?size=thumb', **headers):
		with self.settings(MEDIA_ROOT=self.media_root):
			return client_for(self.member_a).get(f'/cve/{self.project_a.slug}/hosts/{sub.id}/screenshot/{query}', **headers)

	def test_thumb_is_a_320px_wide_jpeg_written_once_and_cacheable(self):
		from io import BytesIO
		from PIL import Image
		rel = 'a.example_1/screenshots/big.png'
		self._plant_image(rel)
		resp = self._get(self._sub(rel))
		self.assertEqual((resp.status_code, resp['Content-Type']), (200, 'image/jpeg'))
		self.assertEqual(resp['Cache-Control'], 'private, max-age=86400')
		body = b''.join(resp.streaming_content)
		with Image.open(BytesIO(body)) as image:
			self.assertEqual((image.format, image.size), ('JPEG', (320, 200)))
		self.assertLess(len(body), os.path.getsize(os.path.join(self.media_root, rel)))
		self.assertTrue(os.path.isfile(os.path.join(self.media_root, rel + '.thumb-320.jpg')))

	def test_a_matching_etag_is_a_304_and_full_size_is_unchanged(self):
		rel = 'a.example_1/screenshots/big.png'
		self._plant_image(rel)
		sub = self._sub(rel)
		etag = self._get(sub)['ETag']
		self.assertEqual(self._get(sub, HTTP_IF_NONE_MATCH=etag).status_code, 304)
		full = self._get(sub, '')
		self.assertEqual(full['Content-Type'], 'image/png')
		with open(os.path.join(self.media_root, rel), 'rb') as f:
			self.assertEqual(b''.join(full.streaming_content), f.read())

	def test_an_image_already_smaller_than_the_thumb_is_not_enlarged(self):
		from io import BytesIO
		from PIL import Image
		rel = 'a.example_1/screenshots/small.png'
		self._plant_image(rel, size=(200, 100))
		with Image.open(BytesIO(b''.join(self._get(self._sub(rel)).streaming_content))) as image:
			self.assertEqual(image.size, (200, 100))

	def test_a_file_that_is_not_an_image_falls_back_to_the_full_bytes(self):
		rel = 'a.example_1/screenshots/bad.jpeg'
		self._plant(rel, b'not an image')
		resp = self._get(self._sub(rel))
		self.assertEqual((resp.status_code, b''.join(resp.streaming_content)), (200, b'not an image'))

	def test_a_bad_size_is_400_and_tenancy_still_applies_to_thumbs(self):
		rel = 'a.example_1/screenshots/big.png'
		self._plant_image(rel)
		self.assertEqual(self._get(self._sub(rel), '?size=huge').status_code, 400)
		other = 'b.example_1/screenshots/big.png'
		self._plant_image(other)
		sub = Subdomain.objects.create(scan_history=self.scan_b, target_domain=self.domain_b, name='www.b.example', screenshot_path=other)
		with self.settings(MEDIA_ROOT=self.media_root):
			resp = client_for(self.member_a).get(f'/cve/{self.project_b.slug}/hosts/{sub.id}/screenshot/?size=thumb')
		self.assertEqual(resp.status_code, 404)


class ScreenshotNoteTests(TestCase):
	"""The host page says why a host has no screenshot instead of showing nothing, and never tells a person to Rescan host for one."""

	def _sub(self, name='www.a.example', path='', mode='standard', target='a.example'):
		from types import SimpleNamespace
		return SimpleNamespace(screenshot_path=path, name=name, target_domain=SimpleNamespace(name=target, discovery_mode=mode))

	def _note(self, http=None, ips=None, network=None, **kwargs):
		from agentapi import services
		return services._screenshot_note(self._sub(**kwargs), http or {}, ips, network)

	def _ports(self, *numbers, service=''):
		from types import SimpleNamespace
		return {'192.0.2.1': {'ip': None, 'ports': [SimpleNamespace(number=n, service_name=service, product='') for n in numbers]}}

	def test_no_note_when_there_is_a_shot(self):
		self.assertEqual(self._note(path='x/screenshots/a.jpeg', http={'status': 200}), '')

	def test_no_web_page_answered(self):
		self.assertIn('no web page has answered', self._note())

	def test_no_web_port_recorded(self):
		note = self._note(ips=self._ports(22, 3389))
		self.assertIn('no web port', note)
		self.assertNotIn('no web port', self._note(ips=self._ports(22, 443)))  # a web port is open: the generic line instead
		self.assertNotIn('no web port', self._note(ips=self._ports(7000, service='http')))
		self.assertIn('no web page has answered', self._note(ips=self._ports()))  # no ports known at all

	def test_the_front_page_redirects_to_another_host(self):
		note = self._note(http={'url': 'https://www.a.example/', 'status': 301, 'redirect_to': 'https://other.example/home'})
		self.assertIn('redirects to https://other.example/home', note)
		self.assertIn('other.example', note)
		self.assertNotIn('Rescan', note.replace('not by Rescan host', ''))
		# the same host (http to https, a path) is not "another host"
		same = self._note(http={'url': 'http://www.a.example/', 'status': 301, 'redirect_to': 'https://WWW.a.example/'})
		self.assertNotIn('redirects to', same)
		self.assertIn('redirect (HTTP 301)', same)
		self.assertNotIn('redirects to', self._note(http={'url': 'x', 'status': 200, 'redirect_to': '/login'}))  # relative: same host

	def test_a_redirect_status_without_a_known_target(self):
		note = self._note(http={'url': 'https://www.a.example/', 'status': 302})
		self.assertIn('redirect (HTTP 302)', note)

	def test_bare_ip_internal_and_passive_targets(self):
		http = {'url': 'http://192.0.2.9/', 'status': 200}
		self.assertIn('bare IP address', self._note(http=http, name='192.0.2.9', target='192.0.2.9'))
		self.assertIn('bare IP address', self._note(http=http, name='192.0.2.9'))
		self.assertIn('internal network 10.20.0.0/24', self._note(http=http, network='10.20.0.0/24'))
		self.assertIn('passive mode', self._note(http=http, mode='passive'))

	def test_the_default_is_an_honest_statement_of_how_a_shot_is_taken(self):
		note = self._note(http={'status': 200, 'url': 'https://www.a.example/'})
		self.assertEqual(note, 'No screenshot has been captured for this host. Screenshots are only taken by a full (standard or deep) '
		                       'discovery of the target, not by Rescan host.')
		self.assertNotIn('rescan the host to take one', note)
		self.assertNotIn('rediscovered', note)

	def test_the_host_record_carries_the_note(self):
		from agentapi.services import Ctx, list_hosts
		now = timezone.now()
		org = Org.objects.create(name='N', slug='n-shot')
		project = Project.objects.create(name='N', slug='n-shot-p', insert_date=now, org=org)
		domain = Domain.objects.create(name='n.example', project=project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e-n', yaml_configuration='x')
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
		Subdomain.objects.create(scan_history=scan, name='www.n.example', target_domain=domain, http_status=200, http_url='https://www.n.example/')
		Subdomain.objects.create(scan_history=scan, name='shot.n.example', target_domain=domain, http_status=200, http_url='https://shot.n.example/',
		                         screenshot_path='n.example_1/screenshots/s.jpeg')
		user = User.objects.create_user('n-admin', password='x', is_superuser=True)
		hosts = {h['host']: h for h in list_hosts(Ctx(user=user), 'n-shot-p', {})['results']}
		self.assertIn('not by Rescan host', hosts['www.n.example']['screenshot_note'])
		self.assertFalse(hosts['www.n.example']['screenshot'])
		self.assertEqual((hosts['shot.n.example']['screenshot'], hosts['shot.n.example']['screenshot_note']), (True, ''))
