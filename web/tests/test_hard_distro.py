import importlib
import io
import json
import unittest
from unittest import mock

from django.apps import apps
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, distro, distro_sync
from cveFeed.autofire import fire_for_cve, keep_match
from cveFeed.models import CVEEntry, CVEMatch, DistroFix
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

# fixed package versions as the trackers publish them (Ubuntu OSV UBUNTU-CVE-2024-6387, Debian tracker DSA-5662-1 / DSA-5729-1)
SSH_FIXES = [{'release': '22.04', 'fixed_version': '1:8.9p1-3ubuntu0.10', 'status': 'fixed'},
	{'release': '24.04', 'fixed_version': '1:9.6p1-3ubuntu13.3', 'status': 'fixed'}]
APACHE_31122 = [{'release': '11', 'fixed_version': '2.4.59-1~deb11u1', 'status': 'fixed'},
	{'release': '12', 'fixed_version': '2.4.59-1~deb12u1', 'status': 'fixed'}]
APACHE_38476 = [{'release': '11', 'fixed_version': '2.4.61-1~deb11u1', 'status': 'fixed'},
	{'release': '12', 'fixed_version': '2.4.61-1~deb12u1', 'status': 'fixed'}]


class ParseDistroTests(unittest.TestCase):
	def test_ubuntu_openssh_from_nmap(self):
		info = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0',
			['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux'])
		self.assertEqual((info['distro'], info['package'], info['package_release'], info['upstream_version']),
			('ubuntu', 'openssh', '8.9p1-3ubuntu0.6', '8.9p1'))

	def test_the_ubuntu_release_comes_from_the_os_cpe(self):
		info = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux', ['cpe:/o:canonical:ubuntu_linux:22.04'])
		self.assertEqual(info['release'], '22.04')

	def test_debian_revision_gives_the_release(self):
		info = distro.parse_distro('OpenSSH', '9.2p1 Debian 2+deb12u3', 'protocol 2.0')
		self.assertEqual((info['distro'], info['release'], info['package_release']), ('debian', '12', '9.2p1-2+deb12u3'))

	def test_debian_apache_with_a_package_release_and_without(self):
		self.assertEqual(distro.parse_distro('Apache httpd', '2.4.57-2', '(Debian)')['package_release'], '2.4.57-2')
		bare = distro.parse_distro('Apache httpd', '2.4.57', '(Debian)')
		self.assertEqual((bare['distro'], bare['package'], bare['package_release']), ('debian', 'apache2', ''))

	def test_no_distro_information_is_empty(self):
		self.assertEqual(distro.parse_distro('nginx', '1.18.0', '')['distro'], '')
		self.assertEqual(distro.parse_distro('', '', '')['distro'], '')

	def test_rhel_and_its_package_name(self):
		info = distro.parse_distro('Apache httpd', '2.4.37', '(Red Hat Enterprise Linux)')
		self.assertEqual((info['distro'], info['package']), ('rhel', 'httpd'))

	def test_versioned_package_names(self):
		self.assertEqual(distro.package_for('MySQL', 'ubuntu', '8.0.35'), 'mysql-8.0')
		self.assertEqual(distro.package_for('PostgreSQL DB', 'debian', '14.9'), '')  # "PostgreSQL DB" is not a known product string
		self.assertEqual(distro.package_for('PostgreSQL', 'debian', '14.9'), 'postgresql-14')
		self.assertEqual(distro.package_for('Exim smtpd', 'debian', '4.94'), 'exim4')
		self.assertEqual(distro.package_for('mystery', 'debian', '1'), '')


class VersionOrderTests(unittest.TestCase):
	def test_dpkg(self):
		for a, b, want in [('1:8.9p1-3ubuntu0.6', '1:8.9p1-3ubuntu0.10', -1), ('1:8.9p1-3ubuntu0.10', '1:8.9p1-3ubuntu0.10', 0),
				('2.4.62-1~deb12u2', '2.4.61-1~deb12u1', 1), ('2.4.57-2', '2.4.59-1~deb12u1', -1), ('1.0~rc1', '1.0', -1),
				('1.0-1', '1.0-1', 0), ('2.4.57-2+deb12u1', '2.4.57-2', 1), ('1:1.0', '2.0', 1), ('1.0a', '1.0', 1), ('1.10', '1.9', 1)]:
			self.assertEqual(distro.dpkg_vercmp(a, b), want, (a, b))

	def test_a_banner_without_the_epoch_takes_the_fixed_versions_epoch(self):
		self.assertEqual(distro.compare_package_release('ubuntu', '8.9p1-3ubuntu0.6', '1:8.9p1-3ubuntu0.10'), -1)
		self.assertEqual(distro.compare_package_release('ubuntu', '8.9p1-3ubuntu0.10', '1:8.9p1-3ubuntu0.10'), 0)
		self.assertIsNone(distro.compare_package_release('alpine', '1.0-r1', '1.0-r2'))
		self.assertIsNone(distro.compare_package_release('ubuntu', '', '1:8.9p1-3ubuntu0.10'))

	def test_rpm(self):
		for a, b, want in [('8.0p1-19.el8_6', '8.0p1-19.el8_7', -1), ('1.0-1.el8', '1.0-1.el8', 0), ('2.4.37-1.el8', '2.4.37-10.el8', -1),
				('1:1.0-1', '2.0-1', 1), ('1.0~rc1-1', '1.0-1', -1), ('1.0^git1-1', '1.0-1', 1)]:
			self.assertEqual(distro.rpm_vercmp(a, b), want, (a, b))


class JudgeTests(unittest.TestCase):
	def _info(self, version, extrainfo, product='OpenSSH', cpes=()):
		return {**distro.parse_distro(product, version, extrainfo, cpes), 'package': distro.package_for(product, 'ubuntu', '8.9p1')
			if product == 'OpenSSH' else distro.package_for(product, 'debian', '2.4.57')}

	def test_ubuntu_patched_and_vulnerable_without_a_known_release(self):
		patched = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		vulnerable = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0')
		self.assertEqual(distro.judge(patched, SSH_FIXES), (distro.PATCHED, '1:8.9p1-3ubuntu0.10'))
		self.assertEqual(distro.judge(vulnerable, SSH_FIXES), (distro.VULNERABLE, '1:8.9p1-3ubuntu0.10'))

	def test_a_known_release_uses_its_own_row(self):
		info = distro.parse_distro('OpenSSH', '9.6p1 Ubuntu 3ubuntu13.3', 'Ubuntu Linux', ['cpe:/o:canonical:ubuntu_linux:24.04'])
		self.assertEqual(distro.judge(info, SSH_FIXES), (distro.PATCHED, '1:9.6p1-3ubuntu13.3'))

	def test_debian_apache(self):
		old = distro.parse_distro('Apache httpd', '2.4.57-2', '(Debian)')
		new = distro.parse_distro('Apache httpd', '2.4.62-1~deb12u2', '(Debian)')
		self.assertEqual(distro.judge(old, APACHE_31122)[0], distro.VULNERABLE)
		self.assertEqual(distro.judge(new, APACHE_38476), (distro.PATCHED, '2.4.61-1~deb12u1'))

	def test_no_rows_or_no_package_release_is_unknown_and_no_distro_is_no_data(self):
		info = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux')
		self.assertEqual(distro.judge(info, [])[0], distro.UNKNOWN)
		bare = distro.parse_distro('Apache httpd', '2.4.57', '(Debian)')
		self.assertEqual(distro.judge(bare, APACHE_31122)[0], distro.UNKNOWN)  # a Debian banner that hides the package release
		self.assertEqual(distro.judge(distro.parse_distro('nginx', '1.18.0', ''), APACHE_31122)[0], distro.NO_DATA)

	def test_not_affected_and_undetermined_rows(self):
		info = distro.parse_distro('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux', ['cpe:/o:canonical:ubuntu_linux:22.04'])
		self.assertEqual(distro.judge(info, [{'release': '22.04', 'fixed_version': '0', 'status': 'fixed'}]), (distro.PATCHED, '0'))
		self.assertEqual(distro.judge(info, [{'release': '22.04', 'fixed_version': '', 'status': 'vulnerable'}]), (distro.VULNERABLE, ''))
		self.assertEqual(distro.judge(info, [{'release': '22.04', 'fixed_version': '', 'status': 'undetermined'}])[0], distro.UNKNOWN)

	def test_labels(self):
		self.assertEqual(distro.label_for('patched', '1:8.9p1-3ubuntu0.10'), 'patched by distro (fixed in 1:8.9p1-3ubuntu0.10)')
		self.assertEqual(distro.label_for('unknown'), 'version-only, distro unknown')
		self.assertEqual(distro.label_for('no_data'), 'version-only, distro unknown')


SSH_CVE = [{'vendor': 'openbsd', 'product': 'openssh', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}]
APACHE_CVE = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.58'}]}]
APACHE_38476_CVE = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.60'}]}]
NGINX_CVE = [{'vendor': 'f5', 'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


class Fixture(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='d.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.d.test', target_domain=self.domain, scan_history=self.scan)
		self.ip = IpAddress.objects.create(address='192.0.2.60')
		self.sub.ip_addresses.add(self.ip)

	def cve(self, cve_id, affected, cvss=8.1, kev=False):
		return CVEEntry.objects.create(cve_id=cve_id, kev=kev, cvss=cvss, published_at=timezone.now(), affected=affected)

	def port(self, product, version, extrainfo='', number=22, cpe=''):
		self.ip.ports.clear()
		port = Port.objects.create(number=number, product=product, version=version, service_extra=extrainfo, cpe=cpe)
		self.ip.ports.add(port)
		return port

	def correlate(self, cves, lookup, min_confidence=0.4):
		by_id = {c.id: c for c in cves}
		subs = Subdomain.objects.filter(pk=self.sub.pk).prefetch_related('technologies', 'ip_addresses__ports')
		correlation.correlate_subdomains(subs, correlation.build_product_index(cves), by_id, min_confidence=min_confidence, fix_lookup=lookup)
		return list(CVEMatch.objects.filter(subdomain=self.sub))


class DistroCorrelationTests(Fixture):
	"""Review 1.6: a distro-patched match is kept and labelled, never dropped; with no distro data it stays version-only."""

	def lookup_for(self, table):
		return lambda dist, package, cve_id: table.get((dist, package, cve_id), [])

	def test_ubuntu_patched_is_kept_at_low_confidence_and_labelled(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		(match,) = self.correlate([cve], self.lookup_for({('ubuntu', 'openssh', 'CVE-2024-6387'): SSH_FIXES}))
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence, match.distro_fixed_version),
			(True, 'patched', 0.2, '1:8.9p1-3ubuntu0.10'))

	def test_ubuntu_vulnerable_is_the_strongest_evidence(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0')
		(match,) = self.correlate([cve], self.lookup_for({('ubuntu', 'openssh', 'CVE-2024-6387'): SSH_FIXES}))
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence), (True, 'vulnerable', 0.95))

	def test_debian_apache_vulnerable_and_patched(self):
		old, new = self.cve('CVE-2023-31122', APACHE_CVE), self.cve('CVE-2024-38476', APACHE_38476_CVE)
		lookup = self.lookup_for({('debian', 'apache2', 'CVE-2023-31122'): APACHE_31122, ('debian', 'apache2', 'CVE-2024-38476'): APACHE_38476})
		self.port('Apache httpd', '2.4.57-2', '(Debian)', 80)
		by_cve = {m.cve_entry.cve_id: m for m in self.correlate([old, new], lookup)}
		self.assertEqual(by_cve['CVE-2023-31122'].distro_status, 'vulnerable')
		self.assertEqual(by_cve['CVE-2024-38476'].distro_status, 'vulnerable')  # 2.4.57-2 predates both fixes
		self.port('Apache httpd', '2.4.62-1~deb12u2', '(Debian)', 80)
		# 2.4.62 is past the upstream range of CVE-2023-31122 (fixed 2.4.58), so only CVE-2024-38476 is judged on its own range
		again = {m.cve_entry.cve_id: m for m in self.correlate([old, new], lookup)}
		self.assertEqual(again['CVE-2023-31122'].ai_verdict, 'not_affected')  # retained as closed history
		self.assertEqual(again['CVE-2023-31122'].confidence, 0.0)

	def test_debian_patched_backport_inside_the_upstream_range(self):
		cve = self.cve('CVE-2024-38476', [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.63'}]}])
		self.port('Apache httpd', '2.4.62-1~deb12u2', '(Debian)', 80)
		(match,) = self.correlate([cve], self.lookup_for({('debian', 'apache2', 'CVE-2024-38476'): APACHE_38476}))
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence), (True, 'patched', 0.2))

	def test_no_distro_data_keeps_todays_behaviour(self):
		cve = self.cve('CVE-2099-1', NGINX_CVE, cvss=7.5)
		self.port('nginx', '1.18.0', '', 80)
		(match,) = self.correlate([cve], self.lookup_for({}))
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence, match.distro_fixed_version),
			(True, 'no_data', 0.85, ''))
		self.assertEqual(distro.label_for(match.distro_status), 'version-only, distro unknown')

	def test_a_known_distro_with_no_fix_data_is_unknown_and_unchanged(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0')
		(match,) = self.correlate([cve], self.lookup_for({}))
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence), (True, 'unknown', 0.85))

	def test_a_patched_row_survives_a_high_minimum_confidence(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		rows = self.correlate([cve], self.lookup_for({('ubuntu', 'openssh', 'CVE-2024-6387'): SSH_FIXES}), min_confidence=0.7)
		self.assertEqual([m.distro_status for m in rows], ['patched'])

	def test_a_tech_match_has_no_distro_and_out_of_range_is_still_dropped(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '9.9p1 Ubuntu 3ubuntu0.1', 'Ubuntu Linux; protocol 2.0')  # past the upstream fix
		self.assertEqual(self.correlate([cve], self.lookup_for({('ubuntu', 'openssh', 'CVE-2024-6387'): SSH_FIXES})), [])

	def test_the_default_lookup_reads_distrofix_rows(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		for row in SSH_FIXES:
			DistroFix.objects.create(distro='ubuntu', package='openssh', cve_id='CVE-2024-6387', **row)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		(match,) = self.correlate([cve], None)
		self.assertEqual(match.distro_status, 'patched')

	def test_a_change_in_distro_status_re_judges_an_inherited_verdict(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		self.correlate([cve], self.lookup_for({}))  # unknown
		CVEMatch.objects.filter(subdomain=self.sub).update(ai_verdict='affected', ai_reason='x', ai_model='m')
		(match,) = self.correlate([cve], self.lookup_for({('ubuntu', 'openssh', 'CVE-2024-6387'): SSH_FIXES}))
		self.assertEqual((match.distro_status, match.ai_verdict), ('patched', ''))

	def test_nmap_persists_the_distro_on_the_port(self):
		from cveFeed import nmap_scan
		nmap_scan.persist_inventory([{'ip': '192.0.2.61', 'ports': [
			{'number': 22, 'state': 'open', 'product': 'OpenSSH', 'version': '8.9p1 Ubuntu 3ubuntu0.6',
			 'service_extra': 'Ubuntu Linux; protocol 2.0', 'cpe': 'cpe:/a:openbsd:openssh:8.9p1',
			 'cpes': ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux:22.04']}]}])
		port = IpAddress.objects.get(address='192.0.2.61').ports.get(number=22)
		self.assertEqual((port.distro, port.distro_release, port.package_release, port.upstream_version),
			('ubuntu', '22.04', '8.9p1-3ubuntu0.6', '8.9p1'))


class PatchedConsequencesTests(Fixture):
	def _patched_match(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE, cvss=9.1, kev=True)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.10', 'Ubuntu Linux; protocol 2.0')
		self.correlate([cve], lambda d, p, c: SSH_FIXES)
		return cve

	def test_a_patched_match_is_not_auto_fired(self):
		cve = self._patched_match()
		calls = []
		run = fire_for_cve(cve, test_dispatcher=lambda *a: calls.append(a), correlated=True)
		self.assertEqual(calls, [])
		self.assertEqual(run.status, 'no_targets')
		self.assertEqual(run.matches_found, 1)  # still a match, just not a target

	def test_a_vulnerable_match_is_auto_fired(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE, cvss=9.1, kev=True)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0')
		self.correlate([cve], lambda d, p, c: SSH_FIXES)
		calls = []
		fire_for_cve(cve, test_dispatcher=lambda *a: calls.append(a), correlated=True)
		self.assertEqual([c[1] for c in calls], [['www.d.test']])

	def test_keep_match(self):
		self.assertFalse(keep_match('affected', 0.95, 'patched'))
		self.assertTrue(keep_match('', 0.95, 'vulnerable'))
		self.assertTrue(keep_match('', 0.85))

	def test_cve_checks_skip_a_patched_match(self):
		from cveFeed import nuclei_scan
		self._patched_match()
		seen = []
		out = nuclei_scan.run_cve_checks(self.scan, [self.sub], None, cve_runner=lambda cve, hosts, **kw: seen.append(hosts) or {'results': []})
		self.assertEqual((seen, out['cves']), ([], 0))

	def test_the_host_reads_as_ice_with_the_label(self):
		from agentapi.services import _heat_reasons, _host_heat
		self._patched_match()
		sub = Subdomain.objects.prefetch_related('cve_matches__cve_entry').get(pk=self.sub.pk)
		(reason,) = _heat_reasons(sub)
		self.assertEqual(reason['temp'], 'ice')
		self.assertIn('patched by distro (fixed in 1:8.9p1-3ubuntu0.10)', reason['detail'])
		self.assertEqual(_host_heat(sub), 'ice')

	def test_the_api_exposes_status_and_label(self):
		from agentapi.services import _match
		self._patched_match()
		item = _match(CVEMatch.objects.select_related('cve_entry', 'subdomain').get())
		self.assertEqual((item['distro_status'], item['distro_label'], item['cve']['tier']),
			('patched', 'patched by distro (fixed in 1:8.9p1-3ubuntu0.10)', 'ice'))

	def test_the_ai_may_clear_a_patched_match_but_not_a_vulnerable_one(self):
		from cveFeed.correlation import ai_confirm_match
		provider = mock.Mock(model='m')
		provider.name = 'test'
		provider.complete.return_value = '{"classification": "likely_false_positive", "reason": "backported fix"}'
		self._patched_match()
		with mock.patch('cveFeed.activity.log', return_value=None):
			patched = ai_confirm_match(CVEMatch.objects.select_related('cve_entry', 'subdomain').get(), provider=provider)
			self.assertEqual(patched.ai_verdict, 'not_affected')
			CVEMatch.objects.update(distro_status='vulnerable')
			vulnerable = ai_confirm_match(CVEMatch.objects.select_related('cve_entry', 'subdomain').get(), provider=provider)
		self.assertEqual(vulnerable.ai_verdict, 'affected')  # the distribution's own tracker lists it: hard evidence, confirmed


# --- the sync ---------------------------------------------------------------------------------------------------------

DEBIAN_JSON = json.dumps({
	'apache2': {
		'CVE-2023-31122': {'description': 'x', 'releases': {
			'bookworm': {'status': 'resolved', 'repositories': {'bookworm': '2.4.57-2'}, 'fixed_version': '2.4.59-1~deb12u1', 'urgency': 'low'},
			'bullseye': {'status': 'resolved', 'fixed_version': '2.4.59-1~deb11u1'},
			'trixie': {'status': 'open'}, 'sid': {'status': 'resolved', 'fixed_version': '2.4.58-1'}}},
		'CVE-2000-0001': {'releases': {'bookworm': {'status': 'resolved', 'fixed_version': '1'}}}},
	'linux': {'CVE-2023-31122': {'releases': {'bookworm': {'status': 'open'}}}},  # not a package we map
	'openssh': {'CVE-2024-6387': {'releases': {'bookworm': {'status': 'resolved', 'fixed_version': '1:9.2p1-2+deb12u3'},
		'bullseye': {'status': 'undetermined'}}}}})

OSV_UBUNTU = {'id': 'UBUNTU-CVE-2024-6387', 'upstream': ['CVE-2024-6387'], 'affected': [
	{'package': {'name': 'openssh', 'ecosystem': 'Ubuntu:22.04:LTS'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [
		{'introduced': '0'}, {'fixed': '1:8.9p1-3ubuntu0.10'}]}]},
	{'package': {'name': 'openssh', 'ecosystem': 'Ubuntu:24.04:LTS'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [
		{'introduced': '0'}, {'fixed': '1:9.6p1-3ubuntu13.3'}]}]},
	{'package': {'name': 'openssh', 'ecosystem': 'Ubuntu:Pro:18.04:LTS'}, 'ranges': []},
	{'package': {'name': 'linux', 'ecosystem': 'Ubuntu:22.04:LTS'}, 'ranges': []}]}


class FakeFetcher:
	def __init__(self, debian=DEBIAN_JSON, osv=None, fail=()):
		self.debian, self.osv, self.fail = debian, osv or {}, set(fail)
		self.posts, self.gets = [], []

	def stream(self, url):
		if 'debian' in self.fail:
			raise ConnectionError('tracker unreachable')
		data = self.debian.encode()
		for i in range(0, len(data), 37):  # awkward chunk size: splits tokens and multibyte characters
			yield data[i:i + 37]

	def post_json(self, url, payload):
		if 'osv' in self.fail:
			raise ConnectionError('osv unreachable')
		self.posts.append(payload)
		return {'results': [{'vulns': [{'id': 'UBUNTU-CVE-2024-6387'}]} for _ in payload['queries']]}

	def get_json(self, url):
		if 'osv' in self.fail:
			raise ConnectionError('osv unreachable')
		self.gets.append(url)
		return self.osv.get(url.rsplit('/', 1)[-1])


class StreamParserTests(unittest.TestCase):
	def test_members_come_out_one_at_a_time_across_chunk_boundaries(self):
		data = json.dumps({'a': {'x': [1, 2, {'y': 'é☃'}]}, 'b': 'str', 'c': {}, 'd': [1]}).encode()
		for size in (1, 3, 7, 1000):
			chunks = [data[i:i + size] for i in range(0, len(data), size)]
			self.assertEqual(dict(distro_sync.iter_json_object(chunks)), json.loads(data), size)

	def test_a_large_file_is_streamed_without_holding_it_whole(self):
		members = ',\n'.join(f'"pkg{i}": {{"CVE-2020-{i}": {{"releases": {{}}}}}}' for i in range(20000))
		data = ('{' + members + '}').encode()
		seen = 0
		for _key, _value in distro_sync.iter_json_object((data[i:i + 65536] for i in range(0, len(data), 65536)), max_buffer=600000):
			seen += 1
		self.assertEqual(seen, 20000)

	def test_malformed_and_oversized_input_raise(self):
		with self.assertRaises(ValueError):
			list(distro_sync.iter_json_object([b'{"a": {"b": ']))
		with self.assertRaises(ValueError):
			list(distro_sync.iter_json_object([b'[1, 2]']))
		with self.assertRaises(ValueError):
			list(distro_sync.iter_json_object([b'{"a": "' + b'x' * 5000 + b'"}'], max_buffer=1000))

	def test_a_runaway_download_is_cut_off(self):
		with self.assertRaises(ValueError):
			list(distro_sync.limited([b'x' * 10] * 5, 30))


class ParseSourcesTests(unittest.TestCase):
	def test_debian_rows_keep_only_mapped_packages_wanted_cves_and_numbered_releases(self):
		members = distro_sync.iter_json_object([DEBIAN_JSON.encode()])
		rows = list(distro_sync.debian_fixes(members, {'CVE-2023-31122', 'CVE-2024-6387'}))
		keyed = {(r['package'], r['cve_id'], r['release']): (r['status'], r['fixed_version']) for r in rows}
		self.assertEqual(keyed, {
			('apache2', 'CVE-2023-31122', '12'): ('fixed', '2.4.59-1~deb12u1'),
			('apache2', 'CVE-2023-31122', '11'): ('fixed', '2.4.59-1~deb11u1'),
			('apache2', 'CVE-2023-31122', '13'): ('vulnerable', ''),
			('openssh', 'CVE-2024-6387', '12'): ('fixed', '1:9.2p1-2+deb12u3'),
			('openssh', 'CVE-2024-6387', '11'): ('undetermined', '')})

	def test_the_row_cap_bounds_the_output(self):
		members = distro_sync.iter_json_object([DEBIAN_JSON.encode()])
		self.assertEqual(len(list(distro_sync.debian_fixes(members, {'CVE-2023-31122'}, max_rows=2))), 2)

	def test_osv_record_to_rows(self):
		rows = distro_sync.osv_fixes(OSV_UBUNTU)
		self.assertEqual([(r['release'], r['package'], r['cve_id'], r['fixed_version'], r['status']) for r in rows], [
			('22.04', 'openssh', 'CVE-2024-6387', '1:8.9p1-3ubuntu0.10', 'fixed'),
			('24.04', 'openssh', 'CVE-2024-6387', '1:9.6p1-3ubuntu13.3', 'fixed')])

	def test_ecosystems(self):
		self.assertEqual(distro_sync.parse_ecosystem('Ubuntu:22.04:LTS'), ('ubuntu', '22.04'))
		self.assertEqual(distro_sync.parse_ecosystem('Debian:12'), ('debian', '12'))
		self.assertIsNone(distro_sync.parse_ecosystem('Ubuntu:Pro:18.04:LTS'))
		self.assertIsNone(distro_sync.parse_ecosystem('npm'))
		self.assertEqual(distro_sync.osv_ecosystem('ubuntu', '22.04'), 'Ubuntu:22.04:LTS')
		self.assertEqual(distro_sync.osv_ecosystem('ubuntu', '23.10'), 'Ubuntu:23.10')
		self.assertEqual(distro_sync.osv_ecosystem('debian', '12'), 'Debian:12')
		self.assertIsNone(distro_sync.osv_ecosystem('rhel', '9'))


class SyncRunTests(Fixture):
	def _matches(self):
		cve = self.cve('CVE-2023-31122', APACHE_CVE)
		ssh = self.cve('CVE-2024-6387', SSH_CVE)
		self.port('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0', 22, 'cpe:/a:openbsd:openssh:8.9p1')
		Port.objects.filter(number=22).update(distro='ubuntu', distro_release='22.04', package_release='8.9p1-3ubuntu0.6', upstream_version='8.9p1')
		self.correlate([cve, ssh], lambda d, p, c: [])
		return cve, ssh

	def test_both_sources_fill_distrofix_and_the_next_correlation_judges(self):
		self._matches()
		fetcher = FakeFetcher(osv={'UBUNTU-CVE-2024-6387': OSV_UBUNTU})
		result = distro_sync.sync_distro_fixes(fetcher)
		self.assertEqual(result['sources'], {'debian': 'ok', 'osv': 'ok'})
		self.assertTrue(DistroFix.objects.filter(distro='ubuntu', release='22.04', package='openssh', cve_id='CVE-2024-6387',
			fixed_version='1:8.9p1-3ubuntu0.10').exists())
		self.assertTrue(DistroFix.objects.filter(distro='debian', release='12', package='openssh', cve_id='CVE-2024-6387').exists())
		# the question to OSV carries the epoch the banner never shows, and the ecosystem
		query = fetcher.posts[0]['queries'][0]
		self.assertEqual((query['package'], query['version']), ({'name': 'openssh', 'ecosystem': 'Ubuntu:22.04:LTS'}, '1:8.9p1-3ubuntu0.6'))
		cve = CVEEntry.objects.get(cve_id='CVE-2024-6387')
		(match,) = [m for m in self.correlate([cve], None) if m.cve_entry_id == cve.id]
		self.assertEqual(match.distro_status, 'vulnerable')

	def test_an_unreachable_source_is_skipped_not_fatal(self):
		self._matches()
		result = distro_sync.sync_distro_fixes(FakeFetcher(fail={'debian'}, osv={'UBUNTU-CVE-2024-6387': OSV_UBUNTU}))
		self.assertIn('tracker unreachable', result['sources']['debian'])
		self.assertEqual(result['sources']['osv'], 'ok')
		self.assertTrue(DistroFix.objects.filter(distro='ubuntu').exists())
		both = distro_sync.sync_distro_fixes(FakeFetcher(fail={'debian', 'osv'}))
		self.assertTrue(all(v != 'ok' for v in both['sources'].values()))

	def test_nothing_to_look_up_makes_no_request(self):
		fetcher = FakeFetcher()
		self.assertEqual(distro_sync.sync_distro_fixes(fetcher)['cves'], 0)
		self.assertEqual((fetcher.posts, fetcher.gets), ([], []))

	def test_fresh_rows_are_not_fetched_again_until_the_ttl_passes(self):
		self._matches()
		distro_sync.sync_distro_fixes(FakeFetcher(osv={'UBUNTU-CVE-2024-6387': OSV_UBUNTU}))
		self.assertEqual(distro_sync.cves_needing_data(), [])  # everything just synced is fresh
		DistroFix.objects.update(synced_at=timezone.now() - distro_sync.TTL - distro_sync.timedelta(hours=1))
		self.assertIn('CVE-2024-6387', distro_sync.cves_needing_data())

	def test_the_run_is_bounded(self):
		self._matches()
		for n in range(5):
			cve = self.cve(f'CVE-2099-{n}', NGINX_CVE)
			CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, matched_product=f'p{n}', distro_status='unknown')
		with mock.patch.object(distro_sync, 'MAX_CVES', 2):
			self.assertEqual(len(distro_sync.cves_needing_data(limit=2)), 2)
		with mock.patch.object(distro_sync, 'MAX_PAIRS', 1):
			Port.objects.create(number=23, product='OpenSSH', version='8.9p1 Ubuntu 3ubuntu0.7', distro='ubuntu', distro_release='22.04',
				package_release='8.9p1-3ubuntu0.7', upstream_version='8.9p1')
			self.assertEqual(len(distro_sync.package_release_pairs(limit=1)), 1)

	def test_the_task_wraps_the_sync_and_is_non_fatal(self):
		from cveFeed.tasks import sync_distro_fixes_task
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=True), \
				mock.patch.object(distro_sync, 'sync_distro_fixes', side_effect=RuntimeError('boom')):
			self.assertEqual(sync_distro_fixes_task(), {'error': 'boom'})
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
			self.assertIn('skipped', sync_distro_fixes_task())
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=True), \
				mock.patch.object(distro_sync, 'sync_distro_fixes', return_value={'changed': 3}), \
				mock.patch('cveFeed.tasks.correlate_cves.delay') as redo:
			sync_distro_fixes_task()
			redo.assert_called_once()

	def test_the_beat_migration_schedules_the_sync_once(self):
		from django_celery_beat.models import PeriodicTask
		module = importlib.import_module('cveFeed.migrations.0033_distro_sync_schedule')
		module.schedule_distro_sync(apps, None)
		module.schedule_distro_sync(apps, None)
		task = PeriodicTask.objects.get(name='cvengine-distro-fix-sync')
		self.assertEqual((task.task, task.queue, task.enabled), ('sync_distro_fixes', 'cve_feed_queue', True))
		module.unschedule(apps, None)
		self.assertFalse(PeriodicTask.objects.filter(name='cvengine-distro-fix-sync').exists())
