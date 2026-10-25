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
