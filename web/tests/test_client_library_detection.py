"""The shared detection record of a CVE in a client-side JavaScript library (cveFeed.js_libraries.LIBRARIES): the version is read from the
script files a page loads (the html-libraries read), never by nmap, and only system-wide packages are checked on the host."""
import json
import os
import re
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import detection, detection_author
from cveFeed.models import CVEDetection, CVEEntry

# CVE-2020-11023 as the feed gives it (cvelistV5 and OSV merged): the library under several names and two packagings of it
JQUERY_11023 = [
	{'vendor': 'jquery', 'product': 'jQuery', 'ranges': [{'fixed': '3.5.0', 'introduced': '1.0.3'}]},
	{'package': 'jquery', 'ranges': [{'fixed': '3.5.0', 'introduced': '1.0.3'}]},
	{'package': 'jquery-rails', 'ranges': [{'fixed': '4.4.0', 'introduced': '0'}]},
	{'package': 'jQuery', 'ranges': [{'fixed': '3.5.0', 'introduced': '1.0.3'}]},
	{'package': 'org.webjars.npm:jquery', 'ranges': [{'fixed': '3.5.0', 'introduced': '1.0.3'}]},
	{'package': 'components/jquery', 'ranges': [{'fixed': '3.5.0', 'introduced': '1.0.3'}]},
]
VECTOR = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N'
GOLDEN = os.path.join(os.path.dirname(__file__), 'fixtures', 'detection_non_library_records.json')


def jquery_cve(**kw):
	return CVEEntry(cve_id='CVE-2020-11023', title='Potential XSS vulnerability in jQuery', affected=JQUERY_11023, cvss_vector=VECTOR, **kw)


def record(cve, templates=()):
	return detection.finalize(detection.rules_strategy(cve, list(templates)), cve.cvss_vector)


def old_record():
	"""The record the rules wrote before 1.3.3 for CVE-2020-11023 (an nmap banner check and OS package checks for every packaging)."""
	strategy, _ = detection.validate_strategy({
		'summary': 'Potential XSS vulnerability in jQuery', 'identify': 'Affects jQuery from 1.0.3 before 3.5.0.',
		'remote_checks': [
			{'id': 'version-jquery', 'kind': 'version_banner', 'confidence': 'medium', 'description': 'jQuery reports a version inside an affected range',
			 'params': {'product': 'jQuery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}], 'source': 'any'}},
			{'id': 'version-components-jquery', 'kind': 'version_banner', 'confidence': 'medium', 'description': 'components/jquery reports a version',
			 'params': {'product': 'components/jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}], 'source': 'any'}}],
		'local_checks': [
			{'id': 'package-jquery', 'kind': 'package_version', 'confidence': 'high', 'description': 'the installed jquery package is older',
			 'params': {'ecosystem': 'any', 'package': 'jquery', 'affected_below': '3.5.0'}},
			{'id': 'package-components-jquery', 'kind': 'package_version', 'confidence': 'high', 'description': 'components/jquery is older',
			 'params': {'ecosystem': 'any', 'package': 'components/jquery', 'affected_below': '3.5.0'}}],
		'confirm_steps': ['Find the exact jQuery version on the host (the Services tab shows what cvENGINE saw).']})
	return detection.finalize(strategy, VECTOR)


class ClientLibraryRecordTests(TestCase):
	def test_the_jquery_record_reads_the_script_file_and_never_names_nmap(self):
		strategy = record(jquery_cve())
		self.assertNotIn('nmap', json.dumps(strategy).lower())
		self.assertEqual([c['kind'] for c in strategy['remote_checks']], ['script_version'])
		check = strategy['remote_checks'][0]
		self.assertEqual(check['params'], {'product': 'jQuery', 'library': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]})
		self.assertEqual(check['how']['tool'], 'html-libraries probe')
		decide = check['how']['decide']
		for words in ('from the file itself', '?ver=', 'file name', 'effective', 'shadowed', 'not that the page is exploitable',
					  'attacker-controlled HTML', 'up to 300 KB'):
			self.assertIn(words, decide)
		self.assertNotIn('head -c', decide)
		profile = strategy['validation']
		self.assertEqual(profile['recommended_tools'], ['html-libraries probe', 'package manager', 'dependency tree', 'grep'])
		self.assertEqual((profile['remote_determinable'], profile['max_remote_state']), ('partial', 'likely'))
		self.assertIn('not that the page is exploitable', profile['remote_note'])
		self.assertTrue(any('jQuery version a script file' in t for t in profile['needs_validation_when']))
		self.assertTrue(any('redirect alias' in t for t in profile['likely_false_positive_when']))

	def test_only_system_wide_packages_with_their_real_names_are_checked_on_the_host(self):
		strategy = record(jquery_cve())
		# the system-wide packages with their real names are checked with the OS package manager; every packaging the advisory names
		# (npm, RubyGems, Maven/WebJars, Composer) in the application's dependency tree, never with dpkg, rpm or apk
		os_packages = [(c['params']['ecosystem'], c['params']['package'], c['params']['affected_below']) for c in strategy['local_checks']
					   if c['kind'] == 'package_version' and c['params']['ecosystem'] in ('dpkg', 'rpm', 'apk')]
		self.assertEqual(os_packages, [('dpkg', 'libjs-jquery', '3.5.0'), ('dpkg', 'node-jquery', '3.5.0'), ('rpm', 'js-jquery', '3.5.0')])
		commands = [cmd['command'] for c in strategy['local_checks'] for cmd in c['commands']]
		self.assertTrue(any("dpkg-query -W -f='${Version}' libjs-jquery" in cmd for cmd in commands))
		self.assertFalse(any('apk ' in cmd for cmd in commands))
		for check in strategy['local_checks']:
			if check['params'].get('package') in ('components/jquery', 'jquery-rails', 'org.webjars.npm:jquery'):
				self.assertTrue(all(cmd['platform'] == 'app' and not re.search(r'\b(dpkg|rpm|apk)\b', cmd['command']) for cmd in check['commands']))
		self.assertEqual({c['params'].get('package') for c in strategy['local_checks'] if c['params'].get('ecosystem') in ('gem', 'maven', 'composer')},
						 {'jquery-rails', 'org.webjars.npm:jquery', 'components/jquery'})
		self.assertTrue(all('a copy a website bundles is not a package' in t for t in strategy['validation']['validated_when']
							if t.startswith('on the host, the system-wide')))

	def test_the_guidance_says_how_the_version_is_read_and_what_makes_a_match_false(self):
		strategy = record(jquery_cve())
		steps = ' '.join(strategy['confirm_steps'])
		self.assertIn('html-libraries', steps)
		self.assertIn('?ver=', steps)
		self.assertNotIn('Services tab', steps)
		false_signs = ' '.join(strategy['false_positive_signs'])
		for words in ('redirect alias', 'shadowed by a later copy', '?ver='):
			self.assertIn(words, false_signs)
		self.assertTrue(any('CDN URL' in t for t in strategy['true_positive_signs']))
		self.assertIn('bundled', strategy['identify'])
		self.assertLessEqual(len(strategy['confirm_steps']), detection.GUIDANCE_LISTS['confirm_steps'][0])

	def test_every_library_cvengine_reads_gets_the_script_check_and_nothing_else_does(self):
		from cveFeed.js_libraries import LIBRARIES
		for key, (product, _stems, _dirs) in LIBRARIES.items():
			cve = CVEEntry(cve_id='CVE-2099-9', title=f'{product} XSS', affected=[{'product': product, 'ranges': [{'fixed': '9.9.9'}]}])
			strategy = record(cve)
			self.assertEqual([(c['kind'], c['params']['library']) for c in strategy['remote_checks']], [('script_version', key)], product)
			self.assertNotIn('nmap', strategy['validation']['recommended_tools'], product)
		self.assertEqual(detection.library_key('Vue.js'), 'vue')
		self.assertEqual(detection.library_key('jquery_ui'), 'jquery-ui')
		self.assertEqual(detection.library_key('org.webjars.npm:jquery'), 'jquery')
		for name in ('jquery-validation', 'jquery-rails', '@angular/core', 'angular', 'nginx', 'react-native', ''):
			self.assertEqual(detection.library_key(name), '', name)

	def test_a_non_library_cve_record_is_unchanged_byte_for_byte(self):
		with open(GOLDEN) as handle:
			golden = json.load(handle)
		cases = {
			'nginx': (CVEEntry(cve_id='CVE-2099-1', title='nginx bug', affected=[{'vendor': 'f5', 'product': 'nginx', 'package': 'nginx',
					  'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}], cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), ['CVE-2099-1']),
			'validation_plugin': (CVEEntry(cve_id='CVE-2099-2', title='jquery-validation ReDoS', affected=[
				{'package': 'jquery-validation', 'ranges': [{'introduced': '0', 'fixed': '1.19.3'}]},
				{'vendor': 'jqueryvalidation', 'product': 'jquery-validation', 'ranges': [{'fixed': '1.19.3'}]}],
				cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), []),
			'angular2': (CVEEntry(cve_id='CVE-2099-3', title='Angular XSRF token leak', affected=[
				{'package': '@angular/common', 'ranges': [{'introduced': '19.0.0', 'fixed': '19.2.16'}]},
				{'vendor': 'angular', 'product': 'angular', 'ranges': [{'introduced': '19.0.0', 'fixed': '19.2.16'}]}], cvss_vector=''), []),
		}
		for name, (cve, templates) in cases.items():
			self.assertEqual(json.dumps(record(cve, templates), sort_keys=True), golden[name], name)

	def test_a_package_of_one_bootstrap_line_is_checked_only_for_a_range_of_that_line(self):
		def packages(ranges):
			cve = CVEEntry(cve_id='CVE-2099-11', title='Bootstrap XSS', affected=[{'product': 'Bootstrap', 'ranges': ranges}])
			return {c['params']['package']: c['params']['affected_below'] for c in record(cve)['local_checks']
					if c['kind'] == 'package_version' and c['params']['ecosystem'] in ('dpkg', 'rpm', 'apk')}
		self.assertEqual(packages([{'introduced': '4.0.0', 'fixed': '4.3.1'}]), {'libjs-bootstrap4': '4.3.1'})
		self.assertEqual(packages([{'fixed': '3.4.1'}]), {'libjs-bootstrap': '3.4.1'})
		self.assertEqual(packages([{'introduced': '3.0.0', 'fixed': '3.4.1'}, {'introduced': '4.0.0', 'fixed': '4.3.1'}]),
						 {'libjs-bootstrap': '3.4.1', 'libjs-bootstrap4': '4.3.1'})
		self.assertEqual(packages([{'introduced': '5.0.0', 'fixed': '5.3.0'}]), {'libjs-bootstrap5': '5.3.0', 'node-bootstrap': '5.3.0'})
		ui = record(CVEEntry(cve_id='CVE-2099-12', title='x', affected=[{'product': 'jQuery UI', 'ranges': [{'fixed': '1.13.0'}]}]))
		self.assertEqual([(c['params']['ecosystem'], c['params']['package']) for c in ui['local_checks'] if c['kind'] == 'package_version'],
						 [('dpkg', 'libjs-jquery-ui'), ('rpm', 'js-jquery-ui')])

	def test_a_separate_package_named_after_the_library_keeps_its_own_checks(self):
		# CVE-2019-10744: lodash and lodash.merge / lodash.defaultsdeep are separate npm packages with their own versions
		affected = [{'package': 'lodash', 'ranges': [{'fixed': '4.17.12'}]}, {'package': 'lodash.merge', 'ranges': [{'fixed': '4.6.2'}]},
					{'package': 'lodash.defaultsdeep', 'ranges': [{'fixed': '4.6.1'}]}]
		strategy = record(CVEEntry(cve_id='CVE-2019-10744', title='lodash prototype pollution', affected=affected))
		self.assertEqual([c['kind'] for c in strategy['remote_checks']], ['script_version', 'version_banner', 'version_banner'])
		self.assertEqual({c['params'].get('package') for c in strategy['local_checks']} & {'lodash.merge', 'lodash.defaultsdeep'},
						 {'lodash.merge', 'lodash.defaultsdeep'})
		self.assertIn('lodash.merge', strategy['identify'])

	def test_a_library_cve_that_also_names_another_product_keeps_that_products_checks(self):
		affected = JQUERY_11023[:1] + [{'vendor': 'oracle', 'product': 'WebLogic Server', 'package': 'weblogic', 'ranges': [{'fixed': '14.1.2'}]}]
		strategy = record(CVEEntry(cve_id='CVE-2099-10', title='x', affected=affected))
		self.assertEqual([c['kind'] for c in strategy['remote_checks']], ['script_version', 'version_banner'])
		self.assertEqual(strategy['remote_checks'][1]['params']['product'], 'WebLogic Server')
		self.assertIn('weblogic', [c['params'].get('package') for c in strategy['local_checks']])
		self.assertIn('WebLogic Server', strategy['identify'])
		self.assertTrue(any('WebLogic Server' in step for step in strategy['confirm_steps']))

	def test_the_schema_takes_the_new_kind_and_refuses_what_is_not_a_library(self):
		check = {'id': 'script-jquery', 'kind': 'script_version', 'description': 'd', 'confidence': 'medium',
				 'params': {'library': 'jquery', 'product': 'whatever', 'ranges': [{'fixed': '3.5.0'}]}}
		strategy, problems = detection.validate_strategy({'remote_checks': [check]})
		self.assertEqual(problems, [])
		self.assertEqual(strategy['remote_checks'][0]['params']['product'], 'jQuery')  # the library's own name, never the input's
		for bad in ({'library': 'nginx', 'ranges': [{'fixed': '1'}]}, {'library': 'jquery', 'ranges': []},
					{'library': 'jquery', 'ranges': [{'fixed': '3.5.0'}], 'url': 'http://x'}):
			strategy, _ = detection.validate_strategy({'remote_checks': [dict(check, params=bad)]})
			self.assertIsNone(strategy, bad)
		self.assertIn('script_version', detection_author.SYSTEM_PROMPT)

	def test_an_ai_or_manual_version_banner_for_a_library_is_rendered_as_the_script_read(self):
		strategy, _ = detection.validate_strategy({'remote_checks': [
			{'id': 'ai-jq', 'kind': 'version_banner', 'description': 'd', 'params': {'product': 'jquery', 'ranges': [{'fixed': '3.5.0'}]}}]})
		final = detection.finalize(strategy, VECTOR)
		self.assertEqual(final['remote_checks'][0]['how']['tool'], 'html-libraries probe')
		self.assertEqual(final['validation']['recommended_tools'], ['html-libraries probe'])

	def test_the_ai_prompt_and_the_page_are_told_how_the_version_was_read(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', title='x', affected=JQUERY_11023, cvss_vector=VECTOR, published_at=timezone.now())
		CVEDetection.objects.create(cve_entry=cve, source='rules', strategy=record(cve))
		guidance = detection.prompt_guidance(CVEEntry.objects.get(pk=cve.pk))
		self.assertIn('script file', guidance['how_checked'])
		self.assertIn('not that the page is exploitable', guidance['how_checked'])
		with open(os.path.join(os.path.dirname(__file__), '..', 'static', 'cve', 'app.js')) as handle:
			self.assertIn('profile.remote_note', handle.read())


class ClientLibraryBackfillTests(TestCase):
	def cve(self, cve_id='CVE-2020-11023', affected=JQUERY_11023):
		return CVEEntry.objects.create(cve_id=cve_id, title='Potential XSS vulnerability in jQuery', affected=affected, cvss_vector=VECTOR,
									   published_at=timezone.now())

	def stale(self, cve, **kw):
		long_ago = timezone.now() - timezone.timedelta(days=30)
		row = CVEDetection.objects.create(cve_entry=cve, strategy=kw.pop('strategy', old_record()), rules_at=timezone.now(), **kw)
		CVEDetection.objects.filter(pk=row.pk).update(updated_at=long_ago)
		return CVEDetection.objects.get(pk=row.pk)

	def test_an_existing_rules_record_is_rewritten_once_without_a_manual_step(self):
		row = self.stale(self.cve())
		nginx = self.cve('CVE-2099-1', [{'product': 'nginx', 'package': 'nginx', 'ranges': [{'fixed': '1.20.0'}]}])
		nginx_row = self.stale(nginx, strategy=record(nginx), schema_version=detection.SCHEMA_VERSION)  # a current record
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			out = detection_author.author_pending(None)
		self.assertEqual(out['regenerated'] + out['libraries'], 1)  # the old rules record is rewritten once, by whichever lane comes first
		row.refresh_from_db()
		self.assertNotIn('nmap', json.dumps(row.strategy).lower())
		self.assertEqual([c['kind'] for c in row.strategy['remote_checks']], ['script_version'])
		self.assertIn('html-libraries', row.strategy['revision_note'])
		self.assertGreater(row.updated_at, timezone.now() - timezone.timedelta(minutes=1))
		before = nginx_row.strategy
		nginx_row.refresh_from_db()
		self.assertEqual(nginx_row.strategy, before)
		self.assertLess(nginx_row.updated_at, timezone.now() - timezone.timedelta(days=1))
		# a second pass, even from the start, finds nothing left to change
		from cveFeed.models import BackgroundCursor
		BackgroundCursor.objects.filter(lane=detection_author.LIBRARY_LANE).update(last_pk=0)
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			self.assertEqual(detection_author.refresh_client_library_records(), 0)

	def test_a_manual_record_is_never_touched(self):
		row = self.stale(self.cve(), source='manual')
		self.assertEqual(detection_author.refresh_client_library_records(), 0)
		before = row.strategy
		row.refresh_from_db()
		self.assertEqual(row.strategy, before)

	def test_an_ai_record_keeps_the_models_part_and_is_queued_for_its_own_revision(self):
		old = old_record()
		ai_check = {'id': 'ai-banner', 'kind': 'version_banner', 'confidence': 'low', 'description': 'the model\'s banner check',
					'params': {'product': 'jQuery', 'ranges': [{'fixed': '3.5.0'}], 'source': 'any'}}
		strategy, _ = detection.validate_strategy({**{k: v for k, v in old.items() if k != 'validation'},
												   'remote_checks': old['remote_checks'] + [ai_check],
												   'confirm_steps': ['The model\'s own step.'], 'summary': 'The model\'s summary.'})
		attempted = timezone.now() - timezone.timedelta(days=2)
		row = self.stale(self.cve(), source='ai', ai_model='anthropic:m', ai_attempted_at=attempted, strategy=detection.finalize(strategy, VECTOR))
		self.assertEqual(detection_author.refresh_client_library_records(), 1)
		row.refresh_from_db()
		ids = [c['id'] for c in row.strategy['remote_checks']]
		self.assertEqual(ids, ['script-jquery', 'ai-banner'])  # the rules' part is the rules' to refresh; the model's check stays
		self.assertEqual(row.strategy['remote_checks'][1]['how']['tool'], 'html-libraries probe')
		self.assertEqual(row.strategy['confirm_steps'], ['The model\'s own step.'])  # the model's words are not overwritten
		self.assertEqual(row.strategy['summary'], 'The model\'s summary.')
		self.assertEqual((row.source, row.ai_model), ('ai', 'anthropic:m'))
		self.assertIsNone(row.ai_attempted_at)  # the model revises its own part through the usual revision pass, within the budget
		self.assertNotIn('nmap', row.strategy['validation']['recommended_tools'])

	def test_a_record_imported_later_from_an_old_seed_is_picked_up_too(self):
		self.cve('CVE-2099-1', [{'product': 'nginx', 'ranges': [{'fixed': '1.20.0'}]}])
		self.assertEqual(detection_author.refresh_client_library_records(), 0)
		row = self.stale(self.cve())
		self.assertEqual(detection_author.refresh_client_library_records(), 1)
		row.refresh_from_db()
		self.assertEqual(row.strategy['remote_checks'][0]['kind'], 'script_version')
