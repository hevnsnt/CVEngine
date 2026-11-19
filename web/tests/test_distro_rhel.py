"""Red Hat distribution data: a RHEL (CentOS, Rocky, Alma) host's version-only matches are judged against Red Hat's own fix data.

The records under ``tests/fixtures/redhat`` were recorded from the Red Hat Security Data API (``/hydra/rest/securitydata/cve/<CVE>.json``,
trimmed to the fields cvENGINE reads) and from OSV (``RHSA-2024:4720``, trimmed to three packages). Nothing here touches the network.
"""
import json
import os
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, distro, distro_sync
from cveFeed.models import CVEEntry, CVEMatch, DistroFix
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'redhat')


def record(name):
	with open(os.path.join(FIXTURES, name + '.json')) as fh:
		return json.load(fh)


# What the recorded Red Hat records say for the packages cvENGINE maps, per RHEL major release, as DistroFix rows
# (``test_the_recorded_records_give_these_rows`` holds the parser to it). RHEL 8 ships httpd as the module stream httpd:2.4, whose fixed
# rpm build comes from the advisory's OSV record.
HTTPD_38475 = [  # RHSA-2024:4720 (RHEL 8), RHSA-2024:4726 (RHEL 9); RHEL 6 and 10 not affected
	{'release': '6', 'package': 'httpd', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''},
	{'release': '7', 'package': 'httpd', 'status': 'fixed', 'fixed_version': '0:2.4.6-99.el7_9.2', 'advisory': 'RHSA-2024:4943'},
	{'release': '8', 'package': 'httpd:2.4', 'status': 'fixed', 'fixed_version': '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1',
	 'advisory': 'RHSA-2024:4720'},
	{'release': '9', 'package': 'httpd', 'status': 'fixed', 'fixed_version': '0:2.4.57-11.el9_4', 'advisory': 'RHSA-2024:4726'},
	{'release': '10', 'package': 'httpd', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''}]
HTTPD_40898 = [{'release': r, 'package': 'httpd:2.4' if r == '8' else 'httpd', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''}
	for r in ('6', '7', '8', '9', '10')]
HTTPD_24795 = [  # RHEL 8: Will not fix
	{'release': '6', 'package': 'httpd', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''},
	{'release': '7', 'package': 'httpd', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''},
	{'release': '8', 'package': 'httpd:2.4', 'status': 'vulnerable', 'fixed_version': '', 'advisory': ''},
	{'release': '9', 'package': 'httpd', 'status': 'fixed', 'fixed_version': '0:2.4.62-1.el9', 'advisory': 'RHSA-2024:9306'},
	{'release': '10', 'package': 'httpd', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''}]
OPENSSL_4304 = [  # RHSA-2023:1405 (RHEL 8)
	{'release': '6', 'package': 'openssl', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''},
	{'release': '7', 'package': 'openssl', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''},
	{'release': '8', 'package': 'openssl', 'status': 'fixed', 'fixed_version': '1:1.1.1k-9.el8_7', 'advisory': 'RHSA-2023:1405'},
	{'release': '9', 'package': 'openssl', 'status': 'fixed', 'fixed_version': '1:3.0.1-47.el9_1', 'advisory': 'RHSA-2023:0946'}]
OPENSSL_9143 = [{'release': '6', 'package': 'openssl', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''}] + [
	{'release': r, 'package': 'openssl', 'status': 'not_affected', 'fixed_version': '0', 'advisory': ''} for r in ('7', '8', '9', '10')]
OPENSSL_0464 = [  # RHEL 8: Will not fix
	{'release': '6', 'package': 'openssl', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''},
	{'release': '7', 'package': 'openssl', 'status': 'undetermined', 'fixed_version': '', 'advisory': ''},
	{'release': '8', 'package': 'openssl', 'status': 'vulnerable', 'fixed_version': '', 'advisory': ''},
	{'release': '9', 'package': 'openssl', 'status': 'fixed', 'fixed_version': '1:3.0.7-16.el9_2', 'advisory': 'RHSA-2023:3722'}]
ROWS = {'CVE-2024-38475': HTTPD_38475, 'CVE-2024-40898': HTTPD_40898, 'CVE-2024-24795': HTTPD_24795, 'CVE-2022-4304': OPENSSL_4304,
	'CVE-2024-9143': OPENSSL_9143, 'CVE-2023-0464': OPENSSL_0464}

APACHE = [{'vendor': 'apache', 'product': 'http_server', 'ranges': [{'introduced': '2.4.0', 'fixed': '2.4.63'}]}]
OPENSSL = [{'vendor': 'openssl', 'product': 'openssl', 'ranges': [{'introduced': '1.1.1', 'fixed': '1.1.1zb'}]}]
RHEL_BANNER = '(Red Hat Enterprise Linux)'
RHEL8_CPES = ['cpe:/a:apache:http_server:2.4.37', 'cpe:/o:redhat:enterprise_linux:8']
SERVER_HEADER = 'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k'
FIXED_BUILD = 'httpd-2.4.37-65.module+el8.10.0+22069+b47f5c72.1'


def lookup(distro_name, package, cve_id):
	"""The rows a Red Hat family host reads (as ``correlation.DbFixLookup`` returns them): Red Hat's, the package and its module streams."""
	if distro_name != 'rhel':
		return []
	return [r for r in ROWS.get(cve_id, []) if r['package'] == package or r['package'].startswith(package + ':')]


class Host(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pr', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='d.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='media.d.test', target_domain=self.domain, scan_history=self.scan)
		self.ip = IpAddress.objects.create(address='192.0.2.80')
		self.sub.ip_addresses.add(self.ip)

	def cve(self, cve_id, affected=APACHE, cvss=7.5, kev=False):
		return CVEEntry.objects.create(cve_id=cve_id, kev=kev, cvss=cvss, published_at=timezone.now(), affected=affected)

	def port(self, version='2.4.37', extrainfo=RHEL_BANNER, cpes=RHEL8_CPES, product='Apache httpd', number=443):
		port = Port.objects.create(number=number, product=product, version=version, service_extra=extrainfo, cpe=cpes[0] if cpes else '',
			extra={'cpes': list(cpes), 'method': 'probed'})
		self.ip.ports.add(port)
		return port

	def correlate(self, cves, fix_lookup=lookup):
		by_id = {c.id: c for c in cves}
		subs = Subdomain.objects.filter(pk=self.sub.pk).prefetch_related('technologies', 'ip_addresses__ports')
		correlation.correlate_subdomains(subs, correlation.build_product_index(cves), by_id, min_confidence=0.4, fix_lookup=fix_lookup)
		return {m.cve_entry.cve_id: m for m in CVEMatch.objects.filter(subdomain=self.sub).select_related('cve_entry')}


class NotAffectedTests(Host):
	def test_not_affected_on_rhel_8_closes_as_patched(self):
		"""Apache 2.4.37 on RHEL 8 (nmap's OS CPE) and a CVE Red Hat lists as not affected for httpd:2.4 on RHEL 8: patched, the way a
		Debian or Ubuntu "not affected" is (low confidence, ice, no triage floor, not auto-fired, the AI may clear it)."""
		from cveFeed import threat, triage
		from cveFeed.autofire import keep_match
		cve = self.cve('CVE-2024-40898', cvss=9.1, kev=True)
		self.port()
		match = self.correlate([cve])['CVE-2024-40898']
		self.assertEqual((match.version_in_range, match.distro_status, match.distro_fixed_version, match.confidence),
			(True, 'patched', '0', 0.2))
		self.assertEqual(distro.label_for(match.distro_status, match.distro_fixed_version), 'patched by distro (not affected)')
		self.assertEqual(threat.match_heat(match), 'ice')
		self.assertFalse(keep_match('', match.confidence, match.distro_status))
		self.assertEqual(triage.hard_evidence('cve_match', {'version_in_range': True, 'distro_status': match.distro_status})[0], '')
		self.assertEqual(match.evidence['distro']['release'], '8')

	def test_the_ai_may_clear_it(self):
		from cveFeed import triage
		from tests import ai_queue
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = json.dumps({'classification': 'likely_false_positive', 'reason': 'Red Hat: not affected'})
		cve = self.cve('CVE-2024-40898')
		self.port()
		self.correlate([cve])
		with mock.patch('cveFeed.activity.log', return_value=None):
			ai_queue.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		self.assertEqual(CVEMatch.objects.get().ai_verdict, 'not_affected')


class BackportTests(Host):
	def _match(self, kev=True):
		cve = self.cve('CVE-2024-38475', cvss=9.1, kev=kev)
		self.port()
		return self.correlate([cve])['CVE-2024-38475']

	def test_a_fix_for_rhel_8_with_no_build_known_is_backport(self):
		match = self._match()
		self.assertEqual((match.version_in_range, match.distro_status, match.distro_fixed_version),
			(True, 'backport', '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1'))
		self.assertLessEqual(match.confidence, 0.5)
		fix = match.evidence['distro_fix']
		self.assertEqual((fix['source'], fix['release'], fix['package'], fix['advisory'], fix['fixed_build']),
			('redhat', '8', 'httpd:2.4', 'RHSA-2024:4720', FIXED_BUILD))
		self.assertEqual(distro.label_for(match.distro_status, match.distro_fixed_version, fix),
			f'distro fix available, confirm the installed build (fixed in {FIXED_BUILD}, RHSA-2024:4720)')

	def test_it_is_needs_validation_at_most_and_never_fire(self):
		from cveFeed import match_policy, threat, triage
		match = self._match()
		self.assertTrue(match_policy.is_version_only(match))
		self.assertFalse(match_policy.version_proven(match))
		facts = {'version_in_range': True, 'distro_status': 'backport', 'version_only': True}
		self.assertEqual(triage.hard_evidence('cve_match', facts)[0], 'needs_validation')
		limit, text = triage.ceiling('cve_match', facts)
		self.assertEqual(limit, 'needs_validation')
		self.assertIn('confirm the installed package build', text)
		said = triage.apply_rules('cve_match', facts, {'classification': 'confirmed', 'reason': 'version in range', 'impact': '',
			'severity_adjust': 0, 'severity_reason': '', 'remediation': '', 'validation_steps': []})
		self.assertEqual(said['classification'], 'needs_validation')
		# on the KEV, yet smoke: fire needs proof of the flaw, under either heat policy and whatever the version-only cap
		self.assertEqual((threat.match_heat(match), threat.validation_heat(match)), ('smoke', 'fire'))
		rank = CVEMatch.objects.annotate(r=threat.match_heat_rank_expr()).get(pk=match.pk).r
		self.assertEqual(rank, threat.HEAT_RANK['smoke'])
		with mock.patch.dict(os.environ, {threat.HEAT_POLICY_ENV: 'legacy', threat.VERSION_ONLY_MAX_HEAT_ENV: 'fire'}), \
				mock.patch('cveFeed.threat.heat_policy', return_value=threat.LEGACY_POLICY):
			self.assertEqual(threat.match_heat(match), 'smoke')
			self.assertEqual(CVEMatch.objects.annotate(r=threat.match_heat_rank_expr()).get(pk=match.pk).r, threat.HEAT_RANK['smoke'])

	def test_it_ranks_after_a_match_with_no_distro_answer(self):
		from cveFeed import triage
		backport = self._match()
		other = self.cve('CVE-2099-0001', cvss=9.1)
		plain = CVEMatch.objects.create(cve_entry=other, subdomain=self.sub, matched_product='Apache httpd', matched_version='2.4.37',
			version_in_range=True, confidence=0.85, source='port', evidence={'source': 'port'})
		described = {m.pk: triage.describe_cve_match(m) for m in (backport, plain)}
		self.assertGreater(described[backport.pk]['priority'], described[plain.pk]['priority'])
		self.assertEqual(described[backport.pk]['payload']['distro_fix']['advisory'], 'RHSA-2024:4720')

	def test_the_api_names_the_build_and_the_advisory(self):
		from agentapi.services import _match
		self._match()
		item = _match(CVEMatch.objects.select_related('cve_entry', 'subdomain').get())
		self.assertEqual(item['distro_status'], 'backport')
		self.assertIn(FIXED_BUILD, item['distro_label'])
		self.assertIn('RHSA-2024:4720', item['distro_label'])
		self.assertEqual(item['evidence']['distro_fix']['advisory'], 'RHSA-2024:4720')


class KnownBuildTests(Host):
	def test_a_known_el8_build_older_than_the_fix_is_vulnerable_newer_is_patched(self):
		old = distro.parse_distro('Apache httpd', '2.4.37-43.module+el8.5.0+13806+b30d9eec', RHEL_BANNER)
		new = distro.parse_distro('Apache httpd', '2.4.37-65.module+el8.10.0+22069+b47f5c72.3', RHEL_BANNER)
		self.assertEqual((old['release'], old['package_release']), ('8', '2.4.37-43.module+el8.5.0+13806+b30d9eec'))
		rows = lookup('rhel', 'httpd', 'CVE-2024-38475')
		self.assertEqual(distro.judge(old, rows), ('vulnerable', '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1'))
		self.assertEqual(distro.judge(new, rows), ('patched', '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1'))

	def test_an_rpm_release_without_its_epoch_takes_the_fixed_builds_epoch(self):
		info = lambda v: {'distro': 'rhel', 'release': '8', 'package': 'openssl', 'package_release': v, 'upstream_version': '1.1.1k'}  # noqa: E731
		rows = lookup('rhel', 'openssl', 'CVE-2022-4304')
		self.assertEqual(distro.judge(info('1.1.1k-7.el8_6'), rows), ('vulnerable', '1:1.1.1k-9.el8_7'))
		self.assertEqual(distro.judge(info('1.1.1k-12.el8_9'), rows), ('patched', '1:1.1.1k-9.el8_7'))
		self.assertEqual(distro.judge(info('1:1.1.1k-9.el8_7'), rows), ('patched', '1:1.1.1k-9.el8_7'))

	def test_a_host_inventory_package_is_judged_exactly(self):
		"""A Rocky Linux 8 host's own report lists the rpm build: Red Hat's rows judge it, through the same lookup and comparison."""
		from cveFeed import inventory_match
		for build, want in (('2.4.37-43.module+el8.5.0+13806+b30d9eec', 'vulnerable'), ('2.4.37-65.module+el8.10.0+22069+b47f5c72.1', 'patched')):
			info = inventory_match._info({'id': 'rocky', 'version': '8.9'}, {'n': 'httpd', 'v': build, 'e': 'rpm', 's': 'httpd'})
			self.assertEqual((info['distro'], info['release'], distro.fix_distro(info['distro'])), ('rhel', '8', 'rhel'))
			status, fixed, _row = distro.judge_row(info, lookup(distro.fix_distro(info['distro']), info['package'], 'CVE-2024-38475'))
			self.assertEqual(status, want, build)
		info = inventory_match._info({'id': 'centos', 'version': '8'}, {'n': 'openssl', 'v': '1:1.1.1k-7.el8_6', 'e': 'rpm', 's': 'openssl'})
		self.assertEqual(distro.judge(info, lookup(distro.fix_distro(info['distro']), 'openssl', 'CVE-2022-4304'))[0], 'vulnerable')

	def test_a_port_with_its_package_release_is_judged_exactly(self):
		cve = self.cve('CVE-2024-38475')
		port = self.port()
		Port.objects.filter(pk=port.pk).update(distro='rhel', distro_release='8', package_release='2.4.37-43.module+el8.5.0+13806+b30d9eec',
			upstream_version='2.4.37')
		self.assertEqual(self.correlate([cve])['CVE-2024-38475'].distro_status, 'vulnerable')
		Port.objects.filter(pk=port.pk).update(package_release='2.4.37-65.module+el8.10.0+22069+b47f5c72.1')
		self.assertEqual(self.correlate([cve])['CVE-2024-38475'].distro_status, 'patched')


class WillNotFixTests(Host):
	def test_will_not_fix_stays_open(self):
		cves = [self.cve('CVE-2024-24795'), self.cve('CVE-2023-0464', OPENSSL)]
		self.port()
		self.port(version='1.1.1k', extrainfo='', cpes=['cpe:/a:openssl:openssl:1.1.1k', 'cpe:/o:redhat:enterprise_linux:8'],
			product='OpenSSL', number=8443)
		by_cve = self.correlate(cves)
		for cve_id in ('CVE-2024-24795', 'CVE-2023-0464'):
			match = by_cve[cve_id]
			self.assertEqual((match.distro_status, match.distro_fixed_version), ('vulnerable', ''), cve_id)
			self.assertNotEqual(match.ai_verdict, 'not_affected')
			self.assertEqual(distro.label_for(match.distro_status, match.distro_fixed_version), 'vulnerable per distro tracker (no fix yet)')


class FamilyTests(Host):
	def test_a_centos_banner_reads_red_hats_data(self):
		cve = self.cve('CVE-2024-40898')
		self.port(extrainfo='(CentOS)', cpes=['cpe:/a:apache:http_server:2.4.37', 'cpe:/o:centos:centos:8'])
		match = self.correlate([cve])['CVE-2024-40898']
		self.assertEqual((match.evidence['distro']['distro'], match.distro_status), ('centos', 'patched'))

	def test_a_rocky_banner_reads_red_hats_data(self):
		cve = self.cve('CVE-2024-38475')
		self.port(version='2.4.37', extrainfo='(Rocky Linux)', cpes=['cpe:/a:apache:http_server:2.4.37', 'cpe:/o:rocky:rocky:8'])
		match = self.correlate([cve])['CVE-2024-38475']
		self.assertEqual((match.distro_status, match.evidence['distro_fix']['advisory']), ('backport', 'RHSA-2024:4720'))

	def test_the_default_lookup_maps_centos_to_red_hat_rows(self):
		for row in HTTPD_40898:
			DistroFix.objects.create(distro='rhel', cve_id='CVE-2024-40898', **row)
		cve = self.cve('CVE-2024-40898')
		self.port(extrainfo='(CentOS)', cpes=['cpe:/a:apache:http_server:2.4.37', 'cpe:/o:centos:centos:8'])
		self.assertEqual(self.correlate([cve], None)['CVE-2024-40898'].distro_status, 'patched')


class NoReleaseTests(Host):
	def test_disagreeing_releases_are_unknown(self):
		"""No release known (nmap's OS CPE without a version): RHEL 8 will not fix, RHEL 9 has a fix in 2.4.62 and RHEL 10 is not affected.
		No row's fixed build is the host's 2.4.37, so nothing names the release: unknown, never a guess."""
		info = distro.parse_distro('Apache httpd', '2.4.37', RHEL_BANNER, ['cpe:/o:redhat:enterprise_linux'])
		self.assertEqual((info['distro'], info['release']), ('rhel', ''))
		self.assertEqual(distro.judge(info, lookup('rhel', 'httpd', 'CVE-2024-24795')), ('unknown', ''))
		synthetic = [{'release': '8', 'package': 'httpd:2.4', 'status': 'vulnerable', 'fixed_version': ''},
			{'release': '9', 'package': 'httpd', 'status': 'not_affected', 'fixed_version': '0'}]
		self.assertEqual(distro.judge(info, synthetic)[0], 'unknown')

	def test_releases_that_agree_decide(self):
		info = distro.parse_distro('OpenSSL', '1.1.1k', '', ['cpe:/o:redhat:enterprise_linux'])
		self.assertEqual(distro.judge(info, lookup('rhel', 'openssl', 'CVE-2024-9143')), ('patched', '0'))

	def test_the_release_whose_fixed_build_is_the_hosts_version_names_it(self):
		info = distro.parse_distro('Apache httpd', '2.4.37', RHEL_BANNER)
		self.assertEqual(distro.judge(info, lookup('rhel', 'httpd', 'CVE-2024-38475')),
			('backport', '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1'))


class ServerHeaderTests(Host):
	"""The reported host: httpx saw ``Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k`` and stored Apache and OpenSSL as technologies,
	so every match came from a technology, with no distribution, and read no_data."""

	def setUp(self):
		super().setUp()
		Subdomain.objects.filter(pk=self.sub.pk).update(webserver=SERVER_HEADER)
		for name in ('Apache HTTP Server:2.4.37', 'OpenSSL:1.1.1k'):
			self.sub.technologies.add(Technology.objects.create(name=name))

	def test_technologies_are_judged_against_red_hat(self):
		cves = [self.cve('CVE-2024-9143', OPENSSL), self.cve('CVE-2022-4304', OPENSSL), self.cve('CVE-2024-38475', cvss=9.1, kev=True)]
		by_cve = self.correlate(cves)
		self.assertEqual({c: m.source for c, m in by_cve.items()}, {c.cve_id: 'tech' for c in cves})
		self.assertEqual(by_cve['CVE-2024-9143'].distro_status, 'patched')  # not affected on every release Red Hat lists
		ssl = by_cve['CVE-2022-4304']
		self.assertEqual((ssl.distro_status, ssl.distro_fixed_version, ssl.evidence['distro_fix']['advisory']),
			('backport', '1:1.1.1k-9.el8_7', 'RHSA-2023:1405'))
		self.assertEqual(ssl.evidence['distro_fix']['fixed_build'], 'openssl-1:1.1.1k-9.el8_7')
		self.assertEqual(ssl.evidence['distro']['basis'], 'host')
		self.assertEqual(by_cve['CVE-2024-38475'].distro_status, 'backport')

	def test_the_release_from_the_hosts_os_report(self):
		IpAddress.objects.filter(pk=self.ip.pk).update(os_guess='Red Hat Enterprise Linux 8.9 (Ootpa)')
		by_cve = self.correlate([self.cve('CVE-2024-24795')])
		self.assertEqual((by_cve['CVE-2024-24795'].distro_status, by_cve['CVE-2024-24795'].evidence['distro']['release']), ('vulnerable', '8'))

	def test_a_host_that_also_shows_another_distribution_is_not_guessed(self):
		self.port(version='8.9p1 Ubuntu 3ubuntu0.6', extrainfo='Ubuntu Linux; protocol 2.0', cpes=['cpe:/o:canonical:ubuntu_linux'],
			product='OpenSSH', number=22)
		self.assertEqual(correlation.host_distro(Subdomain.objects.get(pk=self.sub.pk)), {})
		by_cve = self.correlate([self.cve('CVE-2024-9143', OPENSSL)])
		self.assertEqual(by_cve['CVE-2024-9143'].distro_status, 'no_data')


# --- the sync ---------------------------------------------------------------------------------------------------------

class FakeFetcher:
	"""Serves the recorded records by URL; anything else is a 404. Records every URL asked."""

	def __init__(self, fail=False):
		self.urls, self.fail = [], fail

	def get_json_capped(self, url, limit):
		self.urls.append(url)
		if self.fail:
			raise ConnectionError('access.redhat.com unreachable')
		name = url.rsplit('/', 1)[-1].replace('.json', '').replace(':', '_')
		if url.startswith('https://api.osv.dev/'):
			name = 'osv-' + name
		path = os.path.join(FIXTURES, name + '.json')
		return record(name) if os.path.exists(path) else None

	def stream(self, url):
		raise AssertionError('no Debian question for a Red Hat host')

	def post_json(self, url, payload):
		raise AssertionError('no OSV package question for a Red Hat host')

	def get_json(self, url):
		raise AssertionError('no Ubuntu or Debian record for a Red Hat host')


class RedHatSyncTests(Host):
	def test_the_recorded_records_give_these_rows(self):
		for cve_id, want in ROWS.items():
			got = [{k: r[k] for k in ('release', 'package', 'status', 'fixed_version', 'advisory')} for r in distro_sync.redhat_fixes(record(cve_id))]
			module = {r['release']: r for r in want}
			for row in got:
				expected = module[row['release']]
				if row['status'] == 'fixed' and row['package'].count(':'):  # a module build names no rpm build until its OSV record is read
					self.assertEqual(row['fixed_version'], '', cve_id)
					row['fixed_version'] = expected['fixed_version']
			self.assertEqual(sorted(got, key=lambda r: int(r['release'])), sorted(want, key=lambda r: int(r['release'])), cve_id)
		# JBoss Core Services, EUS/AUS channels and packages cvENGINE does not map are left out
		self.assertEqual({r['package'] for r in distro_sync.redhat_fixes(record('CVE-2022-4304'))}, {'openssl'})
		self.assertEqual(distro_sync.osv_module_fixes(record('osv-RHSA-2024_4720'), '8', 'httpd'), '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1')
		self.assertEqual(distro_sync.redhat_package('httpd:2.4-8100020240712114234.489197e6'),
			('httpd', '2.4', '', 'httpd:2.4-8100020240712114234.489197e6'))

	def _open_match(self):
		cves = [self.cve('CVE-2024-38475', cvss=9.1, kev=True), self.cve('CVE-2024-40898')]
		self.port()
		self.correlate(cves, lambda *a: [])
		return cves

	def test_the_sync_fills_red_hat_rows_and_the_next_correlation_judges(self):
		cves = self._open_match()
		self.assertEqual(sorted(distro_sync.rhel_cves_needing_data()), ['CVE-2024-38475', 'CVE-2024-40898'])
		self.assertEqual(distro_sync.cves_needing_data(), [])  # a Red Hat host's CVEs are not asked of Debian or Ubuntu
		fetcher = FakeFetcher()
		result = distro_sync.sync_distro_fixes(fetcher)
		self.assertEqual((result['sources'], result['redhat_cves']), ({'redhat': 'ok'}, 2))
		# only the CVE and advisory ids leave the server: never a host, a domain or a project
		self.assertEqual(sorted(fetcher.urls), [
			'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-38475.json',
			'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-40898.json',
			'https://api.osv.dev/v1/vulns/RHSA-2024:4720'])
		row = DistroFix.objects.get(distro='rhel', release='8', package='httpd:2.4', cve_id='CVE-2024-38475')
		self.assertEqual((row.status, row.fixed_version, row.advisory), ('fixed', '0:2.4.37-65.module+el8.10.0+22069+b47f5c72.1', 'RHSA-2024:4720'))
		by_cve = self.correlate(cves, None)
		self.assertEqual((by_cve['CVE-2024-38475'].distro_status, by_cve['CVE-2024-40898'].distro_status), ('backport', 'patched'))
		self.assertEqual(by_cve['CVE-2024-38475'].evidence['distro_fix']['fixed_build'], FIXED_BUILD)

	def test_an_answer_is_kept_for_the_ttl_and_a_cve_red_hat_has_no_record_of_too(self):
		self._open_match()
		CVEMatch.objects.filter(cve_entry__cve_id='CVE-2024-40898').update(remediation_status='fixed')
		CVEEntry.objects.filter(cve_id='CVE-2024-38475').update(cve_id='CVE-2099-0003')  # Red Hat has no record of it: a 404
		self.assertEqual(distro_sync.rhel_cves_needing_data(), ['CVE-2099-0003'])  # a closed match is not asked about
		distro_sync.sync_distro_fixes(FakeFetcher())
		self.assertTrue(DistroFix.objects.filter(distro='rhel', release='', package='', cve_id='CVE-2099-0003').exists())
		self.assertEqual(distro_sync.rhel_cves_needing_data(), [])
		DistroFix.objects.update(synced_at=timezone.now() - distro_sync.TTL - distro_sync.timedelta(hours=1))
		self.assertEqual(distro_sync.rhel_cves_needing_data(), ['CVE-2099-0003'])

	def test_an_unreachable_red_hat_is_skipped_not_fatal(self):
		self._open_match()
		result = distro_sync.sync_distro_fixes(FakeFetcher(fail=True))
		self.assertIn('unreachable', result['sources']['redhat'])
		self.assertFalse(DistroFix.objects.exists())

	def test_a_download_is_cut_off_at_the_size_cap(self):
		resp = mock.MagicMock(status_code=200)
		resp.__enter__.return_value = resp
		resp.iter_content.return_value = iter([b'{"name": "' + b'x' * 1024] * 8)
		with mock.patch('requests.get', return_value=resp) as get:
			with self.assertRaises(ValueError):
				distro_sync.Fetcher().get_json_capped(distro_sync.REDHAT_CVE_URL.format(id='CVE-2024-38475'), 4096)
		self.assertEqual(get.call_args.kwargs['timeout'], distro_sync.HTTP_TIMEOUT)
		resp.status_code = 404
		with mock.patch('requests.get', return_value=resp):
			self.assertIsNone(distro_sync.Fetcher().get_json_capped(distro_sync.REDHAT_CVE_URL.format(id='CVE-2024-38475'), 4096))
