"""The evidence policy of CVE matching: a match needs the same product AND a version inside a bounded range; a product seen without a
version is a lead (an unverified product), never a match; operating systems and kernel flaws are decided by the host, not by a name.

The corpus mirrors shapes seen in a real inventory with synthetic records (example.test hosts, invented CVE ids): generic nginx next to
ingress-nginx and nginx-ui advisories, Next.js with no version, the Cloudflare CDN tag next to a WordPress plugin of the same name,
jquery-ui-rails next to jQuery UI, php next to phpmyadmin, Linux kernel CNA records and Windows records next to an Ubuntu fingerprint
and a Windows Communication Foundation technology.
"""
import time
import unittest

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, locality, match_policy
from cveFeed.correlation import _match_candidates, _norm, _record_matches, build_product_index, parse_version
from cveFeed.models import CVEEntry, CVEMatch
from cveFeed.tasks import correlate_cves, reconcile_invalid_correlations
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


class Cve:
	"""The columns correlation reads, without a database."""
	def __init__(self, pk, affected, kev=False, cve_id=None):
		self.id, self.pk, self.affected, self.kev, self.cve_id = pk, pk, affected, kev, cve_id or f'CVE-2099-{pk}'
		self.epss_reached = self.exploit_db = self.cvss = None


def affected(product, introduced='1.0.0', fixed='9.0.0', vendor='', package=None):
	item = {'product': product, 'ranges': [{'introduced': introduced, 'fixed': fixed}]}
	if vendor:
		item['vendor'] = vendor
	if package:
		item['package'] = package
	return [item]


NGINX = Cve(1, affected('nginx', '1.0.0', '1.20.0', 'f5'))
INGRESS = Cve(2, affected('ingress-nginx', '1.0.0', '1.12.1', 'kubernetes'))
NGINX_UI = Cve(3, affected('nginx-ui', '1.0.0', '2.1.0', 'example'))
NGINX_CONTROLLER = Cve(4, affected('NGINX Ingress Controller', '1.0.0', '1.12.1', 'f5'))
NGINX_PROXY_MANAGER = Cve(5, affected('Nginx Proxy Manager', '1.0.0', '2.9.0', 'example'))
NEXT = Cve(6, affected('Next.js', '13.0.0', '13.5.9', 'vercel', package='next'))
CLOUDFLARE_PLUGIN = Cve(7, affected('Cloudflare Image Resizing', '0.0.1', '1.4.0', 'example'))
JQUERY_UI = Cve(8, affected('jQuery UI', '1.0.0', '1.13.2', 'jquery'))
JQUERY = Cve(9, affected('jQuery', '1.0.0', '3.5.0', 'jquery'))
PHPMYADMIN = Cve(10, affected('phpMyAdmin', '1.0.0', '5.2.2', 'phpmyadmin'))
PHP = Cve(11, affected('PHP', '8.0.0', '8.2.99', 'php'))
WP_PLUGIN = Cve(12, affected('WordPress Popular Posts', '1.0.0', '7.3.0', 'example'))
WORDPRESS = Cve(13, affected('WordPress', '5.0.0', '6.5.0', 'wordpress'))
TOMCAT = Cve(14, affected('Tomcat', '9.0.0', '9.0.90', 'apache'))
LOG4J = Cve(15, affected('Log4j', '2.0.0', '2.17.0', 'apache'))
HTTPD = Cve(16, affected('HTTP Server', '2.4.0', '2.4.58', 'apache'))
KERNEL = Cve(17, [{'vendor': 'Linux', 'product': 'Linux', 'ranges': [{'type': 'GIT', 'introduced': '1da177e4c3f4', 'fixed': 'aabbccddeeff'}]}])
UBUNTU_PRODUCT = Cve(18, affected('Ubuntu', '22.04', '23.04', 'canonical'))
WINDOWS = Cve(19, affected('Windows', '10.0.0', '10.0.99999', 'microsoft'))
PRODUCT_WIDE = Cve(20, [{'product': 'nginx', 'vendor': 'f5', 'ranges': []}])
UNBOUNDED = Cve(21, [{'product': 'nginx', 'vendor': 'f5', 'ranges': [{'introduced': '1.0.0'}]}])
ALL = [NGINX, INGRESS, NGINX_UI, NGINX_CONTROLLER, NGINX_PROXY_MANAGER, NEXT, CLOUDFLARE_PLUGIN, JQUERY_UI, JQUERY, PHPMYADMIN, PHP,
       WP_PLUGIN, WORDPRESS, TOMCAT, LOG4J, HTTPD, KERNEL, UBUNTU_PRODUCT, WINDOWS]


def sighting(name, version, pool=ALL, cpe=''):
	"""The CVE ids ``_record_matches`` writes for one product seen on a host."""
	class Sub:
		id, scan_history_id = 5, 7
	rows = []
	_record_matches(Sub, name, version, _norm(name), 'tech', build_product_index(pool), {c.id: c for c in pool}, 0.0, None, rows, cpe=cpe)
	return sorted(row['cve_entry_id'] for row in rows)


def identity(name, version, pool=ALL):
	"""The CVE ids whose advisory names the same product, whatever the version result."""
	index = build_product_index(pool)
	return sorted(cve.id for cve, _p, _r in _match_candidates(name, parse_version(version), _norm(name), index, {c.id: c for c in pool}))


class ProductIdentityTests(unittest.TestCase):
	def test_nginx_is_nginx_and_not_a_product_that_contains_its_name(self):
		self.assertEqual(identity('nginx', '1.10.0'), [1])
		self.assertEqual(sighting('nginx', '1.10.0'), [1])  # 1.10 is also inside ingress-nginx's 1.x ranges: that is another product

	def test_a_version_is_never_compared_with_another_products_ranges(self):
		wrong = [INGRESS, NGINX_UI, NGINX_CONTROLLER, NGINX_PROXY_MANAGER]
		self.assertEqual(identity('nginx', '1.10.0', wrong), [])
		self.assertEqual(sighting('nginx', '1.10.0', wrong), [])
		self.assertEqual(sighting('nginx', '1.1.0', wrong), [])

	def test_the_longer_product_still_matches_itself(self):
		self.assertEqual(sighting('ingress-nginx', '1.10.0'), [2])
		self.assertEqual(sighting('nginx-ui', '2.0.0'), [3])
		self.assertEqual(sighting('Nginx Proxy Manager', '2.0.0'), [5])

	def test_descriptive_words_do_not_make_another_product(self):
		self.assertEqual(sighting('nginx web server', '1.10.0'), [1])
		self.assertEqual(sighting('F5 NGINX', '1.10.0'), [1])
		self.assertEqual(sighting('Apache Tomcat', '9.0.10'), [14])
		self.assertEqual(sighting('Apache HTTP Server', '2.4.50'), [16])

	def test_cloudflare_the_cdn_is_not_a_cloudflare_plugin(self):
		self.assertEqual(identity('Cloudflare', '1.0.0'), [])
		self.assertEqual(sighting('Cloudflare', '1.0.0'), [])
		self.assertEqual(sighting('Cloudflare Image Resizing', '1.0.0'), [7])

	def test_php_is_not_phpmyadmin_and_wordpress_is_not_its_plugins(self):
		self.assertEqual(sighting('PHP', '8.1.0'), [11])
		self.assertEqual(sighting('phpMyAdmin', '5.1.0'), [10])
		self.assertEqual(sighting('PHP-FPM', '8.1.0'), [11])
		self.assertEqual(sighting('WordPress', '6.0.0'), [13])
		self.assertEqual(sighting('WordPress Popular Posts', '7.0.0'), [12])
		self.assertEqual(sighting('WordPress', '1.5.0', [WP_PLUGIN]), [])
		self.assertEqual(sighting('WordPress Popular Posts', '7.0.0', [WORDPRESS]), [])

	def test_nextjs_and_the_next_package_are_one_product(self):
		self.assertEqual(sighting('next.js', '13.1.0'), [6])
		self.assertEqual(sighting('Next.js', '13.1.0', [Cve(30, affected('next', '13.0.0', '13.5.9'))]), [30])

	def test_a_wrapper_package_version_is_not_the_wrapped_librarys(self):
		# jquery-ui-rails 3.5.1 is the gem's version: it says nothing about the jQuery UI it ships
		self.assertEqual(sighting('jquery-ui-rails', '3.5.1'), [])
		self.assertEqual(sighting('jquery-ui-rails', '1.2.0', [JQUERY_UI, JQUERY]), [])
		self.assertEqual(sighting('jQuery UI', '1.12.1'), [8])
		self.assertEqual(sighting('jQuery', '3.4.1'), [9])

	def test_a_bare_apache_banner_is_not_tomcat_or_log4j(self):
		self.assertEqual(sighting('Apache', '2.4.50', [TOMCAT, LOG4J]), [])
		self.assertEqual(sighting('Apache', '2.4.50', [HTTPD]), [16])


class EvidencePolicyTests(unittest.TestCase):
	def test_a_product_with_a_version_inside_a_bounded_range_matches(self):
		self.assertEqual(sighting('nginx', '1.18.0'), [1])

	def test_the_same_product_without_a_version_matches_nothing(self):
		for name in ('nginx', 'next.js', 'PHP', 'jQuery UI', 'WordPress'):
			self.assertEqual(sighting(name, ''), [], name)
		self.assertEqual(sighting('nginx', 'unknown'), [])

	def test_an_advisory_with_no_usable_version_bound_is_no_evidence(self):
		self.assertEqual(sighting('nginx', '1.18.0', [PRODUCT_WIDE]), [])
		self.assertEqual(sighting('nginx', '1.18.0', [UNBOUNDED]), [21])  # an open-ended "introduced 1.0.0" is a real bound

	def test_a_version_outside_the_range_matches_nothing(self):
		self.assertEqual(sighting('nginx', '1.26.0'), [])

	def test_an_end_of_life_release_older_than_every_fixed_branch_stays_a_match(self):
		branches = Cve(40, [{'product': 'PHP', 'ranges': [{'introduced': '8.1', 'fixed': '8.1.30'}, {'introduced': '8.2', 'fixed': '8.2.24'}]}],
					   kev=True)  # a cold CVE is never flagged: see correlation._match_candidates
		self.assertEqual(sighting('PHP', '5.6.40', [branches]), [40])

	def test_a_version_in_the_cpe_is_a_version(self):
		self.assertEqual(sighting('nginx', '', cpe='cpe:/a:f5:nginx:1.18.0'), [1])
		self.assertEqual(sighting('nginx', '', cpe='cpe:/a:f5:nginx'), [])


class OperatingSystemTests(unittest.TestCase):
	def test_an_os_fingerprint_never_matches_by_name(self):
		for name, version in (('Ubuntu', '22.04'), ('Ubuntu', ''), ('Linux', '5.15'), ('Windows Server 2019', '10.0.17763'),
							  ('Microsoft Windows', '10.0.19045'), ('Debian', '12')):
			self.assertEqual(sighting(name, version), [], name)

	def test_an_os_cpe_never_matches(self):
		self.assertEqual(sighting('Ubuntu', '22.04', cpe='cpe:/o:canonical:ubuntu_linux:22.04'), [])
		self.assertEqual(sighting('anything', '5.15', cpe='cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*'), [])

	def test_windows_communication_foundation_is_not_windows(self):
		self.assertEqual(identity('Windows Communication Foundation', '4.8.0', [WINDOWS]), [])
		self.assertEqual(sighting('Windows Communication Foundation', '4.8.0', [WINDOWS]), [])

	def test_os_names_are_recognised_and_applications_are_not(self):
		for name in ('Ubuntu', 'Ubuntu Linux', 'Debian GNU/Linux', 'Windows', 'Windows Server 2022', 'macOS', 'linux_kernel', 'Red Hat Enterprise Linux'):
			self.assertTrue(match_policy.is_os_sighting(name), name)
		for name in ('nginx', 'Windows Communication Foundation', 'Linux telnetd', 'OpenSSH', 'Ubuntu One'):
			self.assertFalse(match_policy.is_os_sighting(name), name)


class LocalityRulesTests(unittest.TestCase):
	def test_a_kernel_cna_record_is_host_only_whatever_its_vector(self):
		text = 'In the Linux kernel, the following vulnerability has been resolved: wifi: ath11k: fix a leak'
		for vector in ('', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'):
			self.assertTrue(locality.classify(vector, text, '', KERNEL.affected)[0], vector)
		self.assertTrue(locality.classify('', 'In the Linux kernel, the following vulnerability has been resolved: ksmbd: fix a bug')[0])

	def test_a_record_naming_only_the_kernel_is_host_only(self):
		self.assertTrue(locality.classify('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'A flaw in ksmbd.', '', [{'product': 'linux_kernel'}])[0])

	def test_a_windows_component_with_no_vector_and_no_network_is_host_only(self):
		self.assertTrue(locality.classify('', 'An elevation of privilege vulnerability exists in the Windows kernel.', '', WINDOWS.affected)[0])
		self.assertTrue(locality.classify('', 'A denial of service vulnerability exists when Windows improperly handles objects in memory.',
										  '', WINDOWS.affected)[0])

	def test_a_remote_windows_flaw_and_ordinary_products_are_not(self):
		self.assertFalse(locality.classify('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'The HTTP protocol stack allows remote code execution.',
										   '', WINDOWS.affected)[0])
		self.assertFalse(locality.classify('', 'A remote attacker can run code in the web server.', '', NGINX.affected)[0])
		self.assertFalse(locality.classify('', 'A flaw in the request parser.', '', NGINX.affected)[0])

	def test_the_model_cannot_call_a_kernel_record_external(self):
		class Record:
			cvss_vector, title, affected = '', '', KERNEL.affected
			original_description = 'In the Linux kernel, the following vulnerability has been resolved: rtc: fix ioctl'
			pk = 1
		self.assertFalse(locality.apply_scope(Record, 'external'))


class PerformanceTests(unittest.TestCase):
	def test_correlating_a_large_catalogue_stays_linear_in_the_index(self):
		pool = []
		for i in range(38000):
			pool.append(Cve(i + 1000, affected(f'product{i % 9000} component{i % 11}', '1.0.0', '2.0.0', f'vendor{i % 700}')))
		pool.extend(ALL)
		started = time.monotonic()
		index = build_product_index(pool)
		built = time.monotonic() - started
		by_id = {c.id: c for c in pool}
		names = [f'Product{i} Component{i % 11}' for i in range(150)] + ['nginx', 'next.js', 'Cloudflare', 'jQuery UI', 'PHP', 'WordPress']
		started = time.monotonic()
		for name in names:
			list(_match_candidates(name, (1, 5), _norm(name), index, by_id))
		matched = time.monotonic() - started
		print(f'\n  match policy perf: index of {len(pool)} CVEs built in {built:.2f}s, {len(names)} products matched in {matched:.2f}s')
		self.assertLess(built, 10)
		self.assertLess(matched, 10)


class Fixture(TestCase):
	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='Policy', slug='policy')
		self.project = Project.objects.create(name='P', slug='policy-p', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.example.test', target_domain=self.domain, scan_history=self.scan)
		self.ip = IpAddress.objects.create(address='192.0.2.80')
		self.sub.ip_addresses.add(self.ip)

	def cve(self, entry, **fields):
		return CVEEntry.objects.create(cve_id=entry.cve_id, kev=True, cvss=9.8, published_at=timezone.now(), affected=entry.affected, **fields)

	def tech(self, name):
		tech = Technology.objects.create(name=name)
		self.sub.technologies.add(tech)
		return tech

	def port(self, product, version='', number=443, cpe=''):
		port = Port.objects.create(number=number, product=product, version=version, cpe=cpe)
		self.ip.ports.add(port)
		return port

	def correlate(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		return correlate_cves()

	def match_for(self, cve, source='tech', product='nginx', version='', in_range=None, **fields):
		evidence = fields.pop('evidence', {'source': source})
		fields.setdefault('confidence', 0.5)
		return CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source=source, matched_product=product, matched_version=version,
									   version_in_range=in_range, evidence=evidence, **fields)


class CorrelationEndToEndTests(Fixture):
	def test_a_version_less_fleet_makes_no_matches_and_keeps_its_technologies(self):
		for entry in (NGINX, INGRESS, NGINX_UI, NEXT, CLOUDFLARE_PLUGIN):
			self.cve(entry)
		for name in ('nginx', 'next.js', 'Cloudflare'):
			self.tech(name)
		self.port('nginx')
		self.correlate()
		self.assertEqual(CVEMatch.objects.count(), 0)
		self.assertEqual(self.sub.technologies.count(), 3)  # the metadata is kept
		self.assertEqual({lead['name'] for lead in match_policy.unversioned_products(self.sub)}, {'nginx', 'next.js', 'Cloudflare'})

	def test_a_version_makes_exactly_the_same_product_match(self):
		for entry in (NGINX, INGRESS, NGINX_UI, NEXT):
			self.cve(entry)
		self.tech('nginx:1.18.0')
		self.tech('next.js')
		self.correlate()
		matches = list(CVEMatch.objects.all())
		self.assertEqual([(m.cve_entry.cve_id, m.version_in_range, m.matched_version) for m in matches], [('CVE-2099-1', True, '1.18.0')])
		self.assertEqual([lead['name'] for lead in match_policy.unversioned_products(self.sub)], ['next.js'])

	def test_the_kernel_and_os_cases_never_reach_a_host_from_an_ubuntu_fingerprint(self):
		kernel = self.cve(KERNEL, original_description='In the Linux kernel, the following vulnerability has been resolved: spi: fix')
		self.cve(UBUNTU_PRODUCT)
		self.cve(WINDOWS)
		locality.refresh()
		kernel.refresh_from_db()
		self.assertTrue(kernel.local_only)
		self.tech('Ubuntu:22.04')
		self.tech('Windows Communication Foundation:4.8.0')
		self.port('OpenSSH', '8.9p1', 22, cpe='cpe:/o:canonical:ubuntu_linux')
		self.correlate()
		self.assertEqual(CVEMatch.objects.count(), 0)

	def test_a_closed_candidate_is_not_resurrected_by_the_next_correlation(self):
		cve = self.cve(NGINX)
		self.tech('nginx')
		match = self.match_for(cve)
		self.assertEqual(match_policy.close_policy_matches(), 1)
		for _ in range(2):
			self.correlate()
			match.refresh_from_db()
			self.assertEqual((match.ai_verdict, match.confidence), ('not_affected', 0.0))
		self.assertTrue(match.ai_reason.startswith('Closed automatically: no version evidence'))

	def test_a_version_found_later_reopens_the_closed_match_with_new_evidence(self):
		cve = self.cve(NGINX)
		tech = self.tech('nginx')
		match = self.match_for(cve)
		match_policy.close_policy_matches()
		tech.name = 'nginx:1.18.0'
		tech.save()
		self.correlate()
		match.refresh_from_db()
		self.assertEqual((match.version_in_range, match.matched_version, match.ai_verdict), (True, '1.18.0', ''))


class ExistingDataCleanupTests(Fixture):
	def setUp(self):
		super().setUp()
		self.nginx = self.cve(NGINX)

	def _verdict(self, match):
		match.refresh_from_db()
		return match.ai_verdict

	def test_version_less_candidates_close_with_a_stored_reason_and_the_host_is_rescored(self):
		other = self.cve(NGINX_UI)
		a, b = self.match_for(self.nginx), self.match_for(other, product='nginx-ui')
		self.sub.score = 90
		self.sub.save()
		self.assertEqual(match_policy.close_policy_matches(), 2)
		for match in (a, b):
			match.refresh_from_db()
			self.assertEqual((match.ai_verdict, match.confidence, match.ai_model), ('not_affected', 0.0, 'deterministic-policy'))
			self.assertIn('no version evidence', match.ai_reason)
			self.assertIn('Unverified products', match.ai_reason)
		self.sub.refresh_from_db()
		self.assertLess(self.sub.score, 90)

	def test_it_is_idempotent_and_bounded(self):
		cves = [self.cve(Cve(100 + i, affected('nginx'))) for i in range(5)]
		for cve in cves:
			self.match_for(cve)
		self.assertEqual(match_policy.close_policy_matches(limit=3), 3)
		self.assertEqual(match_policy.close_policy_matches(limit=3), 2)
		self.assertEqual(match_policy.close_policy_matches(limit=3), 0)

	def test_a_product_wide_advisory_with_a_version_closes_too(self):
		cve = self.cve(PRODUCT_WIDE)
		match = self.match_for(cve, version='1.18.0', in_range=None)
		match_policy.close_policy_matches()
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'not_affected')
		self.assertIn('no version bound', match.ai_reason)

	def test_matches_with_evidence_or_a_person_s_decision_are_kept(self):
		keep = {
			'worked': self.match_for(self.nginx, remediation_status='in_progress'),
			'template': self.match_for(self.cve(NGINX_UI), template_result='vulnerable', product='nginx-ui'),
			'distro': self.match_for(self.cve(INGRESS), distro_status='vulnerable', product='ingress-nginx'),
			'runzero': self.match_for(self.cve(NEXT), evidence={'source': 'tech', 'runzero': True}, product='Next.js'),
			'in_range': self.match_for(self.cve(PHP), version='8.1.0', in_range=True, product='PHP'),
			'branch': self.match_for(self.cve(WORDPRESS), version='4.0', in_range=None, product='WordPress',
									 evidence={'source': 'tech', 'branch_unlisted': True}),
			'host': self.match_for(self.cve(KERNEL), source='host', product='Linux'),
		}
		self.assertEqual(match_policy.close_policy_matches(), 0)
		for name, match in keep.items():
			self.assertEqual(self._verdict(match), '', name)

	def test_a_wrong_product_match_in_range_closes_through_the_identity_sweep(self):
		ingress = self.cve(INGRESS)
		tech = self.tech('nginx:1.10.0')
		wrong = self.match_for(ingress, product='ingress-nginx', version='1.10.0', in_range=True, confidence=0.85,
							   evidence={'source': 'tech', 'source_id': tech.id})
		right = self.match_for(self.nginx, version='1.10.0', in_range=True, evidence={'source': 'tech', 'source_id': tech.id})
		self.assertEqual(reconcile_invalid_correlations(limit=100)['closed'], 1)
		self.assertEqual(self._verdict(wrong), 'not_affected')
		self.assertEqual(self._verdict(right), '')
		wrong.refresh_from_db()
		self.assertIn('invalid product correlation', wrong.ai_reason)

	def test_an_os_fingerprint_match_closes_through_the_identity_sweep(self):
		windows = self.cve(WINDOWS)
		tech = self.tech('Ubuntu:22.04')
		match = self.match_for(windows, product='Windows', version='22.04', in_range=True, evidence={'source': 'tech', 'source_id': tech.id})
		tech.name = 'Windows Server 2019:10.0.17763'
		tech.save()
		reconcile_invalid_correlations(limit=100)
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'not_affected')
		self.assertIn('operating-system fingerprint', match.ai_reason)

	def test_a_worked_wrong_product_row_is_not_closed_by_a_recorrelation(self):
		tech = self.tech('nginx')
		match = self.match_for(self.nginx, remediation_status='accepted_risk', evidence={'source': 'tech', 'source_id': tech.id})
		self.correlate()
		self.assertEqual(self._verdict(match), '')

	def test_the_ai_cannot_reopen_nor_overrule_the_closure(self):
		match = self.match_for(self.nginx)
		match_policy.close_policy_matches()
		self.assertFalse(correlation.close_invalid_correlation(CVEMatch.objects.get(pk=match.pk)))

	def test_triage_no_longer_blocks_the_closure_of_an_unknown_range(self):
		from cveFeed import triage
		match = self.match_for(self.nginx, version='1.18.0', in_range=None)
		pairs = triage.track([match])
		row, _ = pairs[0]
		from cveFeed.models import TriageVerdict
		verdict = TriageVerdict.objects.create(kind='cve_match', signature=row.signature, classification='not_applicable', reason='different product',
											   model='test')
		triage._apply(verdict, pairs)
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'not_affected')
		hard = self.match_for(self.cve(PHP), product='PHP', version='8.1.0', in_range=True)
		pairs = triage.track([hard])
		verdict = TriageVerdict.objects.create(kind='cve_match', signature=pairs[0][0].signature, classification='not_applicable',
											   reason='different product', model='test')
		triage._apply(verdict, pairs)
		hard.refresh_from_db()
		self.assertEqual(hard.ai_verdict, 'uncertain')


class UnverifiedProductsTests(Fixture):
	def test_leads_cover_technologies_and_ports_once_each_and_skip_the_versioned_and_os(self):
		self.tech('nginx')
		self.tech('PHP:8.2.30')
		self.tech('PHP')
		self.tech('Ubuntu')
		self.tech('Cloudflare')
		self.port('nginx', '1.18.0', 443)
		self.port('Apache httpd', '', 8080)
		self.port('OpenSSH', '', 22, cpe='cpe:/a:openbsd:openssh:8.9p1')
		leads = match_policy.unversioned_products(self.sub)
		self.assertEqual(sorted((lead['name'], lead['source']) for lead in leads), [('Apache httpd', 'port'), ('Cloudflare', 'tech')])
		port_lead = next(lead for lead in leads if lead['source'] == 'port')
		self.assertEqual((port_lead['port'], port_lead['ip']), (8080, '192.0.2.80'))

	def test_the_host_record_lists_unverified_products(self):
		from agentapi import services
		self.tech('next.js')
		self.tech('nginx:1.18.0')
		record = services.host_group(self.project, self.sub)
		self.assertEqual([(u['name'], u['source']) for u in record['unverified_products']], [('next.js', 'tech')])
		self.assertEqual(record['cve_matches'], 0)


class ScoringTests(Fixture):
	def test_unverified_products_add_nothing_to_the_score(self):
		from cveFeed import scoring
		self.cve(NGINX)
		self.tech('nginx')
		self.correlate()
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		self.sub.refresh_from_db()
		self.assertFalse(any('CVE' in line['label'] for line in self.sub.score_detail))


class HotCveTemplateTestTests(Fixture):
	"""A fire CVE is still tested on a host that runs its product with no version found: the template is the hard check."""

	def test_a_version_less_host_gets_the_template_test_but_no_match(self):
		from cveFeed.autofire import fire_for_cve
		cve = self.cve(NGINX)
		self.port('nginx', '', 80)
		calls = []
		run = fire_for_cve(cve, test_dispatcher=lambda pk, hosts, project: calls.append((pk, list(hosts), project)))
		self.assertEqual(CVEMatch.objects.count(), 0)
		self.assertEqual((run.matches_found, run.targets), (0, ['example.test']))
		self.assertEqual(calls, [(cve.pk, ['www.example.test'], self.project.id)])

	def test_a_host_with_another_product_is_not_a_target(self):
		from cveFeed.autofire import fire_for_cve
		cve = self.cve(NGINX)
		self.port('ingress-nginx', '', 80)
		self.port('Caddy', '', 8080)
		calls = []
		fire_for_cve(cve, test_dispatcher=lambda *args: calls.append(args))
		self.assertEqual(calls, [])

	def test_one_walk_serves_the_whole_batch(self):
		from cveFeed.autofire import correlate_hot_cves, fire_for_cve
		first, second = self.cve(NGINX), self.cve(NEXT)
		self.port('nginx', '', 80)
		self.tech('next.js')
		leads = correlate_hot_cves([first, second])
		self.assertEqual(leads, {first.id: {(self.domain.id, 'www.example.test')}, second.id: {(self.domain.id, 'www.example.test')}})
		calls = []
		fire_for_cve(first, correlated=True, leads=leads[first.id], test_dispatcher=lambda pk, hosts, project: calls.append((pk, hosts)))
		self.assertEqual(calls, [(first.pk, ['www.example.test'])])
