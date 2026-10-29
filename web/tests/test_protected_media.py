import os
import tempfile

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings


class ProtectedMediaTests(TestCase):
	def test_the_internal_redirect_is_percent_encoded(self):
		root = tempfile.mkdtemp()
		os.makedirs(os.path.join(root, 'a.example_1'))
		name = 'shot 100%?x#y.png'
		with open(os.path.join(root, 'a.example_1', name), 'wb') as handle:
			handle.write(b'x')
		User.objects.create_superuser('media-root', 'r@example.com', 'x')
		client = Client()
		client.force_login(User.objects.get(username='media-root'))
		with override_settings(MEDIA_ROOT=root):
			response = client.get('/media/a.example_1/' + name.replace('%', '%25').replace('?', '%3F').replace('#', '%23'))
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response['X-Accel-Redirect'], '/protected_media/a.example_1/shot%20100%25%3Fx%23y.png')


class ProtectedMediaOwnershipTests(TestCase):
	"""Only the ``<domain>_<scan id>/`` layout is served to a non-admin, and only for a scan of a project the caller can see."""

	@classmethod
	def setUpTestData(cls):
		from dashboard.models import Org, OrgMembership, Project
		from django.utils import timezone
		from scanEngine.models import EngineType
		from startScan.models import ScanHistory
		from targetApp.models import Domain
		now = timezone.now()
		cls.org, cls.other_org = Org.objects.create(name='PM', slug='pm'), Org.objects.create(name='PM other', slug='pm-other')
		cls.project = Project.objects.create(name='PM', slug='pmp', insert_date=now, org=cls.org)
		cls.other_project = Project.objects.create(name='PM other', slug='pmp-other', insert_date=now, org=cls.other_org)
		cls.domain = Domain.objects.create(name='a.example.test', project=cls.project, insert_date=now)
		cls.foreign = Domain.objects.create(name='b.example.test', project=cls.other_project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=2)
		cls.foreign_scan = ScanHistory.objects.create(domain=cls.foreign, scan_type=engine, start_scan_date=now, scan_status=2)
		cls.member = User.objects.create_user('media-member', password='x')
		OrgMembership.objects.create(user=cls.member, org=cls.org, role='user')
		cls.root = User.objects.create_superuser('media-admin', 'a@example.com', 'x')

	def setUp(self):
		self.media = tempfile.mkdtemp()
		for folder in (f'a.example.test_{self.scan.id}', 'a.example.test', f'b.example.test_{self.foreign_scan.id}', 'b.example.test'):
			os.makedirs(os.path.join(self.media, folder))
			with open(os.path.join(self.media, folder, 'shot.png'), 'wb') as handle:
				handle.write(b'x')

	def get(self, user, folder):
		client = Client()
		client.force_login(user)
		with override_settings(MEDIA_ROOT=self.media):
			return client.get(f'/media/{folder}/shot.png').status_code

	def test_a_member_is_served_the_scan_folder_of_their_own_project(self):
		self.assertEqual(self.get(self.member, f'a.example.test_{self.scan.id}'), 200)

	def test_a_member_is_never_served_the_bare_domain_folder(self):
		self.assertEqual(self.get(self.member, 'a.example.test'), 404)  # a target of their own project, but not a scan's folder

	def test_a_member_is_not_served_another_projects_folders(self):
		self.assertEqual(self.get(self.member, f'b.example.test_{self.foreign_scan.id}'), 404)
		self.assertEqual(self.get(self.member, 'b.example.test'), 404)
		self.assertEqual(self.get(self.member, f'a.example.test_{self.foreign_scan.id}'), 404)  # the scan id of another project under a name of theirs

	def test_an_app_admin_still_sees_everything(self):
		for folder in (f'a.example.test_{self.scan.id}', 'a.example.test', f'b.example.test_{self.foreign_scan.id}', 'b.example.test'):
			self.assertEqual(self.get(self.root, folder), 200, folder)
