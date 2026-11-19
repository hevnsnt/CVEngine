"""Distribution banners read as exact package builds (cveFeed.distro.parse_distro, cveFeed.distro_releases), so a match is judged by the
distribution's own fixed build: real-shaped banners of each distribution, an Ubuntu backport judged by its release, a banner that names only
the distribution, a hostile banner, search, the host payload, the match explanation and the upgrade backfill."""
import io
import json
import re
import unittest
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import correlation, distro, distro_releases, distro_sync, match_explain, port_inventory, upgrade_backfills
from cveFeed.models import CVEEntry, CVEMatch, DistroFix
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call

NOW = timezone.now()
SSH_CVE = [{'vendor': 'openbsd', 'product': 'openssh', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}]
APACHE_CVE = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.60'}]}]
# Ubuntu's fixed builds of CVE-2024-6387 (USN-6859-1; OSV UBUNTU-CVE-2024-6387): jammy 1:8.9p1-3ubuntu0.10, noble 1:9.6p1-3ubuntu13.3
SSH_FIXES = [('22.04', '1:8.9p1-3ubuntu0.10', 'fixed'), ('24.04', '1:9.6p1-3ubuntu13.3', 'fixed')]


def parse(product, version, extrainfo='', cpes=(), banner=''):
	return distro.parse_distro(product, version, extrainfo, list(cpes), banner)


class RealBannerTests(unittest.TestCase):
	"""What each distribution's banners say, read as (distribution, release, source package, exact build)."""

	def reading(self, *args, **kwargs):
		info = parse(*args, **kwargs)
		return (info['distro'], info['release'], info['package'], info['package_release'])

	def test_ubuntu_openssh_from_nmap_names_jammy_without_a_versioned_cpe(self):
		info = parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu Linux; protocol 2.0', ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux'])
		self.assertEqual((info['distro'], info['release'], info['codename'], info['package'], info['package_release'], info['release_basis']),
			('ubuntu', '22.04', 'jammy', 'openssh', '8.9p1-3ubuntu0.6', 'table'))
		self.assertEqual(info['reading'], 'package')
		self.assertEqual(self.reading('OpenSSH', '9.6p1 Ubuntu 3ubuntu13.5', 'Ubuntu Linux; protocol 2.0'), ('ubuntu', '24.04', 'openssh', '9.6p1-3ubuntu13.5'))
		self.assertEqual(self.reading('OpenSSH', '8.2p1 Ubuntu 4ubuntu0.11', 'Ubuntu Linux; protocol 2.0'), ('ubuntu', '20.04', 'openssh', '8.2p1-4ubuntu0.11'))

	def test_a_later_update_the_table_has_not_seen_is_placed_by_its_prefix(self):
		self.assertEqual(self.reading('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.99', 'Ubuntu Linux')[1], '22.04')

	def test_the_ssh_identification_string_gives_the_build(self):
		self.assertEqual(self.reading('OpenSSH', '8.9p1', '', banner='SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\nProtocol mismatch.\r\n'),
			('ubuntu', '22.04', 'openssh', '8.9p1-3ubuntu0.6'))
		self.assertEqual(self.reading('OpenSSH', '', '', banner='SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'), ('debian', '12', 'openssh', '9.2p1-2+deb12u3'))
		# the banner's build must be the version's: another upstream version is another service
		self.assertEqual(parse('OpenSSH', '9.6p1', '', banner='SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')['package_release'], '')

	def test_debian(self):
		self.assertEqual(self.reading('OpenSSH', '9.2p1 Debian 2+deb12u3', 'protocol 2.0'), ('debian', '12', 'openssh', '9.2p1-2+deb12u3'))
		self.assertEqual(parse('OpenSSH', '9.2p1 Debian 2+deb12u3', 'protocol 2.0')['codename'], 'bookworm')
		self.assertEqual(self.reading('OpenSSH', '8.4p1 Debian 5+deb11u3', 'protocol 2.0')[1], '11')
		bare = parse('OpenSSH', '9.2p1 Debian 2', 'protocol 2.0')  # the build bookworm shipped: no +deb suffix, the table places it
		self.assertEqual((bare['release'], bare['release_basis']), ('12', 'table'))
		self.assertEqual(self.reading('PHP', '7.4.33-1+deb11u5'), ('debian', '11', 'php7.4', '7.4.33-1+deb11u5'))

	def test_ubuntu_builds_that_name_their_release(self):
		self.assertEqual(self.reading('MySQL', '8.0.35-0ubuntu0.22.04.1'), ('ubuntu', '22.04', 'mysql-8.0', '8.0.35-0ubuntu0.22.04.1'))
		self.assertEqual(parse('MySQL', '8.0.35-0ubuntu0.22.04.1')['release_basis'], 'package')
		self.assertEqual(self.reading('PHP', '8.1.2-1ubuntu2.14'), ('ubuntu', '22.04', 'php8.1', '8.1.2-1ubuntu2.14'))
		self.assertEqual(self.reading('OpenSSL', '1.1.1-1ubuntu2.1~18.04.23')[1], '18.04')
		# BIND's version.bind ends with the distribution's name
		self.assertEqual(self.reading('ISC BIND', '9.18.18-0ubuntu0.22.04.2-Ubuntu'), ('ubuntu', '22.04', 'bind9', '9.18.18-0ubuntu0.22.04.2'))
		self.assertEqual(self.reading('ISC BIND', '9.18.28-1~deb12u2-Debian'), ('debian', '12', 'bind9', '9.18.28-1~deb12u2'))

	def test_red_hat_family(self):
		self.assertEqual(self.reading('OpenSSH', '8.7p1-38.el9_4.4'), ('rhel', '9', 'openssh', '8.7p1-38.el9_4.4'))
		self.assertEqual(self.reading('Apache httpd', '2.4.57', '(Rocky Linux)'), ('rhel', '', 'httpd', ''))
		self.assertEqual(self.reading('Apache httpd', '2.4.57', '(AlmaLinux)'), ('rhel', '', 'httpd', ''))
		self.assertEqual(self.reading('Apache httpd', '2.4.6', '(CentOS)'), ('centos', '', 'httpd', ''))

	def test_amazon_linux_suse_alpine_and_freebsd_are_read_and_marked_unsynced(self):
		amzn = parse('OpenSSH', '7.4p1-22.amzn2.0.9')
		self.assertEqual((amzn['distro'], amzn['release'], amzn['package_release'], amzn['tracker']), ('amzn', '2', '7.4p1-22.amzn2.0.9', 'not_synced'))
		self.assertEqual(parse('Apache httpd', '2.4.62', '(Amazon Linux)')['distro'], 'amzn')
		self.assertEqual(parse('Apache httpd', '2.4.62', '', banner='Server: AmazonS3')['distro'], '')  # an Amazon service, not the OS
		suse = parse('Apache httpd', '2.4.51-150400.6.11.1')
		self.assertEqual((suse['distro'], suse['release'], suse['tracker']), ('suse', '15.4', 'not_synced'))
		self.assertEqual(parse('Apache httpd', '2.4.51', '(Linux/SUSE)')['distro'], 'suse')
		self.assertEqual(self.reading('nginx', '1.24.0-r16', 'Alpine'), ('alpine', '', 'nginx', '1.24.0-r16'))
		bsd = parse('OpenSSH', '9.4', 'FreeBSD 20230316; protocol 2.0', ['cpe:/o:freebsd:freebsd'])
		self.assertEqual((bsd['distro'], bsd['package_release'], bsd['upstream_version'], bsd['tracker']), ('freebsd', 'FreeBSD-20230316', '9.4', 'not_synced'))
		self.assertEqual(parse('OpenSSH', '9.4', '', banner='SSH-2.0-OpenSSH_9.4 FreeBSD-20230316')['package_release'], 'FreeBSD-20230316')

	def test_another_publishers_build_is_named(self):
		sury = parse('PHP', '8.2.12-1+ubuntu22.04.1+deb.sury.org+1')
		self.assertEqual((sury['distro'], sury['release'], sury['third_party']), ('ubuntu', '22.04', 'sury'))
		self.assertEqual(parse('nginx', '1.24.0-1~jammy', 'Ubuntu')['third_party'], 'vendor')  # nginx.org's package
		self.assertEqual(parse('OpenSSL', '3.0.15-1~bpo12+1', '(Debian)')['third_party'], 'backports')
		self.assertNotIn('third_party', parse('OpenSSL', '3.0.15-1~deb12u1'))  # a Debian security update of a new upstream version

	def test_a_marker_alone_names_the_release_only_when_one_release_shipped_that_version(self):
		apache = parse('Apache httpd', '2.4.52', '(Ubuntu)')
		self.assertEqual((apache['release'], apache['release_basis'], apache['reading'], apache['package_release']), ('22.04', 'table', 'marker', ''))
		self.assertEqual(parse('nginx', '1.18.0', 'Ubuntu')['release'], '')  # focal and jammy both ship nginx 1.18.0
		self.assertEqual(parse('Apache httpd', '2.4.62', '(Debian)')['release'], '')  # bullseye and bookworm both have 2.4.62

	def test_codenames(self):
		self.assertEqual(distro_releases.codename('ubuntu', '22.04'), 'jammy')
		self.assertEqual(distro_releases.from_codename('Bookworm'), ('debian', '12'))
		self.assertIsNone(distro_releases.from_codename('nonsense'))


class TableTests(unittest.TestCase):
	def test_every_release_the_table_names_is_cited(self):
		table = distro_releases.table()
		self.assertTrue(table.get('ubuntu', {}).get('openssh'))
		cites = table['citations']
		for family in ('ubuntu', 'debian'):
			for package, versions in table[family].items():
				for upstream, revisions in versions.items():
					for revision, releases in revisions.items():
						for release in releases:
							self.assertIn(release, distro_releases.CODENAMES[family], (family, package, upstream, revision))
							url = cites.get(f'{family}/{release}/{package}', '')
							self.assertTrue(url, (family, release, package))
		for url in cites.values():
			self.assertRegex(url, r'^https://(launchpad\.net/ubuntu/[a-z]+/\+source/|tracker\.debian\.org/pkg/)[a-z0-9.+-]+$')
		self.assertEqual(distro_releases.citation('ubuntu', '22.04', 'openssh'), 'https://launchpad.net/ubuntu/jammy/+source/openssh')

	def test_the_known_defaults(self):
		for family, package, upstream, revision, want in [
				('ubuntu', 'openssh', '8.9p1', '3ubuntu0.6', '22.04'), ('ubuntu', 'openssh', '9.6p1', '3ubuntu13.5', '24.04'),
				('ubuntu', 'openssh', '8.2p1', '4ubuntu0.11', '20.04'), ('ubuntu', 'openssh', '7.6p1', '4ubuntu0.7', '18.04'),
				('ubuntu', 'apache2', '2.4.52', '1ubuntu4.6', '22.04'), ('ubuntu', 'nginx', '1.18.0', '0ubuntu1.4', '20.04'),
				('ubuntu', 'nginx', '1.18.0', '6ubuntu14.4', '22.04'), ('debian', 'openssh', '9.2p1', '2', '12'),
				('debian', 'openssh', '8.4p1', '5+deb11u3', '11')]:
			self.assertEqual(distro_releases.release_from_table(family, package, upstream, revision), want, (family, package, upstream, revision))
		self.assertEqual(distro_releases.release_from_table('ubuntu', 'nginx', '1.18.0'), '')
		self.assertEqual(distro_releases.release_from_table('ubuntu', 'nonesuch', '1.0'), '')


class HostileBannerTests(unittest.TestCase):
	def test_control_characters_and_escapes_never_reach_a_reading(self):
		info = parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6\x1b[31m\x00', 'Ubuntu Linux‮; protocol 2.0')
		self.assertEqual(info['package_release'], '8.9p1-3ubuntu0.6')
		for value in info.values():
			self.assertFalse(re.search(r'[\x00-\x1f\x7f‮]', str(value)), info)

	def test_text_after_the_build_is_not_part_of_it(self):
		info = parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6;rm -rf /', 'Ubuntu Linux')
		self.assertEqual(info['package_release'], '')  # not a build: the reading is a marker
		self.assertEqual(info['reading'], 'marker')

	def test_two_distributions_at_once_name_none(self):
		self.assertEqual(parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6', 'Ubuntu\r\nRed Hat Enterprise Linux')['distro'], '')
		self.assertEqual(parse('Apache httpd', '2.4.37', '(Red Hat Enterprise Linux) (FreeBSD)')['distro'], '')

	def test_a_huge_banner_is_clipped_and_a_long_build_dropped(self):
		info = parse('X' * 100000, '8.9p1 Ubuntu ' + '3ubuntu0.' + '9' * 5000, 'Ubuntu ' * 50000, ['cpe:/o:canonical:ubuntu_linux'] * 5000, 'SSH-2.0-' + 'a' * 100000)
		self.assertEqual(info['package_release'], '')
		self.assertTrue(all(len(str(v)) <= 64 for v in info.values()), info)
		self.assertEqual(parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.' + '1' * 70, 'Ubuntu Linux')['package_release'], '')  # never clipped into another build

	def test_a_marker_never_judges_a_build_fixed(self):
		marker = parse('Apache httpd', '2.4.52', '(Ubuntu)')
		rows = [{'release': '22.04', 'fixed_version': '0', 'status': 'not_affected'}]
		self.assertEqual(distro.judge(marker, rows)[0], distro.UNKNOWN)
		self.assertEqual(distro.judge(marker, [{'release': '22.04', 'fixed_version': '', 'status': 'vulnerable'}])[0], distro.VULNERABLE)
		self.assertEqual(distro.judge(marker, [{'release': '22.04', 'fixed_version': '2.4.52-1ubuntu4.10', 'status': 'fixed'}])[0], distro.UNKNOWN)

	def test_a_build_nobody_tracks_keeps_the_version_only_answer(self):
		rows = [{'release': '22.04', 'fixed_version': '8.2.99-1ubuntu1', 'status': 'fixed'}]
		sury = {**parse('PHP', '8.2.12-1+ubuntu22.04.1+deb.sury.org+1'), 'package': 'php8.2'}
		self.assertEqual(distro.judge(sury, rows)[0], distro.NO_DATA)
		self.assertEqual(distro.judge(parse('OpenSSH', '7.4p1-22.amzn2.0.9'), rows)[0], distro.NO_DATA)


class Fixture(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pa', insert_date=NOW, org=org)
		self.domain = Domain.objects.create(name='d.test', project=self.project, insert_date=NOW)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=NOW)
		self.sub = Subdomain.objects.create(name='www.d.test', target_domain=self.domain, scan_history=self.scan)
		self.ip = IpAddress.objects.create(address='192.0.2.70')
		self.sub.ip_addresses.add(self.ip)

	def cve(self, cve_id, affected, cvss=8.1, kev=False):
		return CVEEntry.objects.create(cve_id=cve_id, kev=kev, cvss=cvss, published_at=NOW, affected=affected)

	def ingest(self, rec):
		"""One nmap service record through the ingest every scan result takes (``persist_inventory``)."""
		self.ip.ports.clear()
		port_inventory.persist_inventory([{'ip': self.ip.address, 'ports': [{'number': 22, 'state': 'open', 'method': 'probed', **rec}]}])
		return self.ip.ports.get(number=rec.get('number', 22))

	def fixes(self, package, cve_id, rows, distro_name='ubuntu'):
		for release, fixed, status in rows:
			DistroFix.objects.create(distro=distro_name, release=release, package=package, cve_id=cve_id, fixed_version=fixed, status=status)

	def correlate(self, cves):
		by_id = {c.id: c for c in cves}
		subs = Subdomain.objects.filter(pk=self.sub.pk).prefetch_related('technologies', 'ip_addresses__ports')
		correlation.correlate_subdomains(subs, correlation.build_product_index(cves), by_id, min_confidence=0.4)
		return {m.cve_entry.cve_id: m for m in CVEMatch.objects.filter(subdomain=self.sub).select_related('cve_entry', 'subdomain')}


JAMMY_SSH = {'product': 'OpenSSH', 'service_name': 'ssh', 'service_extra': 'Ubuntu Linux; protocol 2.0',
			 'cpe': 'cpe:/a:openbsd:openssh:8.9p1', 'cpes': ['cpe:/a:openbsd:openssh:8.9p1', 'cpe:/o:canonical:ubuntu_linux']}


class UbuntuBackportTests(Fixture):
	"""CVE-2024-6387 is fixed upstream in 9.8p1 and by Ubuntu 22.04 in 1:8.9p1-3ubuntu0.10: judged by Ubuntu's own build, not the upstream one."""

	def test_fixed_at_3ubuntu0_10_is_not_affected_and_3ubuntu0_6_is(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE, kev=False)
		self.fixes('openssh', 'CVE-2024-6387', SSH_FIXES)
		port = self.ingest({**JAMMY_SSH, 'version': '8.9p1 Ubuntu 3ubuntu0.10'})
		self.assertEqual((port.distro, port.distro_release, port.package_release, port.extra['distro']['codename']),
			('ubuntu', '22.04', '8.9p1-3ubuntu0.10', 'jammy'))
		match = self.correlate([cve])['CVE-2024-6387']
		self.assertEqual((match.version_in_range, match.distro_status, match.distro_fixed_version, match.confidence),
			(True, 'patched', '1:8.9p1-3ubuntu0.10', 0.2))
		self.assertEqual(match.evidence['distro']['release'], '22.04')
		self.ingest({**JAMMY_SSH, 'version': '8.9p1 Ubuntu 3ubuntu0.6'})
		match = self.correlate([cve])['CVE-2024-6387']
		self.assertEqual((match.version_in_range, match.distro_status, match.confidence), (True, 'vulnerable', 0.95))
		explained = match_explain.explain(match)
		self.assertEqual(explained['distro']['installed'], '8.9p1-3ubuntu0.6')
		self.assertIn("Judged by Ubuntu 22.04 (jammy)'s own fixed build 1:8.9p1-3ubuntu0.10: the installed openssh 8.9p1-3ubuntu0.6 is older.",
			explained['distro']['text'])
		self.assertIn('Ubuntu 22.04 (jammy)', explained['why'])

	def test_the_release_decides_when_releases_disagree(self):
		# jammy's build was never affected, noble's has a fix: only jammy's row speaks for a jammy build, and a release-less reading could not pick it
		cve = self.cve('CVE-2099-0001', SSH_CVE)
		rows = [('22.04', '0', 'not_affected'), ('24.04', '1:9.6p1-3ubuntu13.3', 'fixed')]
		self.fixes('openssh', 'CVE-2099-0001', rows)
		self.ingest({**JAMMY_SSH, 'version': '8.9p1 Ubuntu 3ubuntu0.13'})
		self.assertEqual(self.correlate([cve])['CVE-2099-0001'].distro_status, 'patched')
		before = {**parse('OpenSSH', '8.9p1 Ubuntu 3ubuntu0.13', 'Ubuntu Linux'), 'release': ''}  # as the previous parser read it
		self.assertEqual(distro.judge(before, [{'release': r, 'fixed_version': f, 'status': s} for r, f, s in rows])[0], distro.UNKNOWN)

	def test_a_parsed_marker_never_widens_a_match(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.fixes('openssh', 'CVE-2024-6387', [('24.04', '', 'vulnerable')])
		self.ingest({**JAMMY_SSH, 'version': '9.9p1 Ubuntu 3ubuntu3', 'cpe': ''})  # past the upstream fix: no match, whatever the tracker says
		self.assertEqual(self.correlate([cve]), {})

	def test_the_osv_question_now_asks_about_ports_whose_release_the_build_names(self):
		self.ingest({**JAMMY_SSH, 'version': '8.9p1 Ubuntu 3ubuntu0.6'})
		pairs = distro_sync.package_release_pairs()
		self.assertIn({'distro': 'ubuntu', 'release': '22.04', 'package': 'openssh', 'ecosystem': 'Ubuntu:22.04:LTS', 'version': '1:8.9p1-3ubuntu0.6'}, pairs)


class MarkerAndUntrackedTests(Fixture):
	def test_a_marker_only_port_is_never_patched(self):
		cve = self.cve('CVE-2099-0002', APACHE_CVE)
		self.fixes('apache2', 'CVE-2099-0002', [('22.04', '0', 'not_affected'), ('24.04', '0', 'not_affected')])
		port = self.ingest({'number': 80, 'product': 'Apache httpd', 'version': '2.4.52', 'service_extra': '(Ubuntu)', 'service_name': 'http'})
		self.assertEqual((port.distro, port.distro_release, port.package_release, port.extra['distro']['reading']), ('ubuntu', '22.04', '', 'marker'))
		match = self.correlate([cve])['CVE-2099-0002']
		self.assertEqual((match.version_in_range, match.distro_status), (True, 'unknown'))
		self.assertNotEqual(match.confidence, 0.2)
		self.assertIn('a hint, never proof of a fix', match_explain.explain(match)['distro']['text'])

	def test_a_technology_on_an_ubuntu_host_is_judged_as_a_hint(self):
		from startScan.models import Technology
		cve = self.cve('CVE-2099-0003', APACHE_CVE)
		self.fixes('apache2', 'CVE-2099-0003', [('22.04', '0', 'not_affected')])
		self.ip.ports.clear()
		Subdomain.objects.filter(pk=self.sub.pk).update(webserver='Apache/2.4.52 (Ubuntu)')
		self.sub.technologies.add(Technology.objects.create(name='Apache HTTP Server:2.4.52'))
		match = self.correlate([cve])['CVE-2099-0003']
		self.assertEqual((match.source, match.distro_status), ('tech', 'unknown'))
		self.assertEqual((match.evidence['distro']['distro'], match.evidence['distro']['release'], match.evidence['distro']['reading']),
			('ubuntu', '22.04', 'marker'))

	def test_an_unsynced_distribution_keeps_todays_behaviour(self):
		cve = self.cve('CVE-2024-6387', [{'vendor': 'openbsd', 'product': 'openssh', 'ranges': [{'introduced': '7.0p1', 'fixed': '9.8p1'}]}])
		self.ingest({'product': 'OpenSSH', 'version': '7.4p1-22.amzn2.0.9', 'service_name': 'ssh'})
		match = self.correlate([cve])['CVE-2024-6387']
		self.assertEqual((match.distro_status, match.confidence), ('no_data', 0.85))
		self.assertEqual((match.evidence['distro']['distro'], match.evidence['distro']['tracker']), ('amzn', 'not_synced'))
		self.assertIn('keeps no fix data', match_explain.explain(match)['distro']['text'])

	def test_a_hostile_banner_is_stored_safely(self):
		port = self.ingest({'product': 'OpenSSH', 'version': '8.9p1 Ubuntu 3ubuntu0.6\x1b[2J', 'service_extra': 'Ubuntu Linux' + 'A' * 5000,
							'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\x00' + 'B' * 100000, 'service_name': 'ssh'})
		self.assertEqual((port.distro, port.package_release), ('ubuntu', '8.9p1-3ubuntu0.6'))
		self.assertTrue(all(len(str(v)) <= 64 for v in port.extra['distro'].values()))


class SearchAndPayloadTests(Fixture):
	def setUp(self):
		super().setUp()
		user = User.objects.create_user('db-user', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, self.token = create_token(user, 'db')
		self.ingest({**JAMMY_SSH, 'version': '8.9p1 Ubuntu 3ubuntu0.6'})
		other = Subdomain.objects.create(name='deb.d.test', target_domain=self.domain, scan_history=self.scan)
		ip = IpAddress.objects.create(address='192.0.2.71')
		other.ip_addresses.add(ip)
		port_inventory.persist_inventory([{'ip': ip.address, 'ports': [
			{'number': 22, 'state': 'open', 'product': 'OpenSSH', 'version': '9.2p1 Debian 2+deb12u3', 'service_extra': 'protocol 2.0'}]}])

	def names(self, q, status=200):
		got, data = call(self.token, 'GET', '/api/v1/projects/pa/search?' + urlencode({'q': q}))
		self.assertEqual(got, status, data)
		return sorted(h['host'] for h in data['results']) if status == 200 else data

	def test_distro_search(self):
		self.assertEqual(self.names('distro:jammy'), ['www.d.test'])
		self.assertEqual(self.names('distro:ubuntu@22.04'), ['www.d.test'])
		self.assertEqual(self.names('distro:ubuntu@22'), ['www.d.test'])
		self.assertEqual(self.names('distro:bookworm'), ['deb.d.test'])
		self.assertEqual(self.names('distro:debian'), ['deb.d.test'])
		self.assertEqual(self.names('distro:any'), ['deb.d.test', 'www.d.test'])
		self.assertEqual(self.names('distro:rhel'), [])
		self.assertEqual(self.names('-distro:jammy distro:any'), ['deb.d.test'])

	def test_package_search(self):
		self.assertEqual(self.names('pkg:openssh'), ['deb.d.test', 'www.d.test'])
		self.assertEqual(self.names('pkg:openssh@1:8.9p1-3ubuntu0.6'), ['www.d.test'])
		self.assertEqual(self.names('pkg:openssh@8.9p1-3ubuntu0.6'), ['www.d.test'])
		self.assertEqual(self.names('pkg:openssh@8.9p1-3ubuntu0'), ['www.d.test'])  # every jammy update
		self.assertEqual(self.names('pkg:openssh@8.9p1-3ubuntu0.1'), [])  # never 0.10 or 0.13 for 0.1
		self.assertEqual(self.names('pkg:openssh@9.2p1'), ['deb.d.test'])

	def test_the_results_say_what_matched(self):
		got, data = call(self.token, 'GET', '/api/v1/projects/pa/search?' + urlencode({'q': 'pkg:openssh@8.9p1-3ubuntu0.6'}))
		self.assertIn('port 22 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (openssh 8.9p1-3ubuntu0.6, Ubuntu 22.04 (jammy))', data['results'][0]['matched'])

	def test_bad_values_say_what_is_taken(self):
		for q in ('distro:windows', 'distro:ubuntu@x', 'pkg:Open_SSH', 'pkg:openssh@;drop', 'pkg:' + 'a' * 100):
			self.assertIn(self.names(q, 400)['error'][:4], ('dist', 'pkg:'), q)

	def test_the_host_payload_names_the_release_package_and_build(self):
		got, data = call(self.token, 'GET', '/api/v1/projects/pa/hosts?page_size=50')
		self.assertEqual(got, 200, data)
		host = next(h for h in data['results'] if h['host'] == 'www.d.test')
		port = host['ips'][0]['ports'][0]
		self.assertEqual(port['distro'], {'distro': 'ubuntu', 'name': 'Ubuntu', 'release': '22.04', 'codename': 'jammy', 'package': 'openssh',
										  'build': '8.9p1-3ubuntu0.6', 'release_basis': 'table', 'reading': 'package'})


class BackfillTests(Fixture):
	def old_row(self, **fields):
		port = Port.objects.create(number=fields.pop('number', 22), **fields)
		self.ip.ports.add(port)
		return port

	def test_it_is_registered_before_the_rescore(self):
		names = list(upgrade_backfills.BACKFILLS)
		self.assertIn('backfill_distro_readings', names)
		self.assertLess(names.index('backfill_distro_readings'), names.index('rerate_findings'))

	def test_stored_banners_are_read_again_and_their_hosts_rejudged(self):
		cve = self.cve('CVE-2024-6387', SSH_CVE)
		self.fixes('openssh', 'CVE-2024-6387', [('22.04', '', 'vulnerable'), ('24.04', '1:9.6p1-3ubuntu13.3', 'fixed')])
		# as the previous release stored them: the build without its release, and a raw SSH identification string never read
		ssh = self.old_row(product='OpenSSH', version='8.9p1 Ubuntu 3ubuntu0.13', service_extra='Ubuntu Linux; protocol 2.0', distro='ubuntu',
						   package_release='8.9p1-3ubuntu0.13', upstream_version='8.9p1', extra={'cpes': ['cpe:/o:canonical:ubuntu_linux']})
		raw = self.old_row(number=2222, product='OpenSSH', version='9.6p1', banner='SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n')
		untouched = self.old_row(number=80, product='nginx', version='1.24.0')
		CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source='port', matched_product='OpenSSH', matched_version='8.9p1 Ubuntu 3ubuntu0.13',
								version_in_range=True, confidence=0.85, distro_status='unknown', evidence={'source': 'port', 'source_id': ssh.id})
		out = io.StringIO()
		call_command('backfill_distro_readings', stdout=out)
		self.assertIn('dry run: 2 of 3 service records would be rewritten', out.getvalue())
		self.assertEqual(Port.objects.get(pk=ssh.pk).distro_release, '')  # a dry run writes nothing
		call_command('backfill_distro_readings', apply=True, stdout=out)
		ssh, raw, untouched = (Port.objects.get(pk=p.pk) for p in (ssh, raw, untouched))
		self.assertEqual((ssh.distro_release, ssh.extra['distro']['codename'], ssh.extra['cpes']), ('22.04', 'jammy', ['cpe:/o:canonical:ubuntu_linux']))
		self.assertEqual((raw.distro, raw.distro_release, raw.package_release), ('ubuntu', '24.04', '9.6p1-3ubuntu13.5'))
		self.assertEqual((untouched.distro, untouched.extra), ('', {}))
		statuses = sorted(m.distro_status for m in CVEMatch.objects.filter(subdomain=self.sub, cve_entry=cve).exclude(confidence=0.0))
		self.assertIn('vulnerable', statuses)
		again = io.StringIO()
		call_command('backfill_distro_readings', stdout=again)
		self.assertIn('dry run: 0 of 3 service records would be rewritten', again.getvalue())
