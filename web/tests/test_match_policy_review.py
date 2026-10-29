"""Regression tests for the review of the evidence policy (tests/test_match_policy.py is the policy itself).

The records and names are the shapes the review found in a real inventory and in the real CVE feed: F5's "NGINX Open Source" (CVE-2026-27654,
CVE-2026-9256), nmap's service-suffixed products ("Postfix smtpd"), the editions and vendor prefixes real advisories use, Exchange's
CU-numbered product of the KEV record CVE-2021-26855, a CPE stored as a technology name, the KEV advisories that give no version bound
(Apache HTTP Server CVE-2021-41773, Jenkins CVE-2024-23897, Grafana CVE-2021-43798) and the remote kernel flaws CVE-2019-11477 and CVE-2022-0435.
"""
import unittest
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User

from cveFeed import correlation, locality, match_policy, triage
from cveFeed.correlation import split_name_version
from cveFeed.models import CVEEntry, CVEMatch, FindingComment, MatchVerdict, OnDemandValidation, Triage, TriageVerdict
from cveFeed.tasks import reconcile_invalid_correlations
from startScan.models import Subdomain, Technology
from tests.test_match_policy import Cve, Fixture, affected, sighting

F5_OSS = Cve(101, [{'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.29.7'}]}],
			 kev=False, cve_id='CVE-2026-27654')
F5_BOTH = Cve(102, [{'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.29.7'}]},
					{'vendor': 'F5', 'product': 'NGINX Plus', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.29.7'}]}],
			  kev=False, cve_id='CVE-2026-9256')
EXCHANGE = Cve(103, [{'vendor': 'Microsoft', 'product': 'Microsoft Exchange Server 2016 Cumulative Update 14',
					  'ranges': [{'introduced': '15.1.0', 'fixed': '15.1.2308.8'}]}], kev=True, cve_id='CVE-2021-26855')
OPENSSH_SCP = Cve(104, [{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': [{'introduced': '0', 'lastAffected': '8.3p1'}]}],
				  cve_id='CVE-2020-15778')
OPENSSH_REGRESSHION = Cve(105, [{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}],
						  kev=True, cve_id='CVE-2024-6387')
OPENSSH_TERRAPIN = Cve(106, [{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': [{'introduced': '9.5p1', 'fixed': '9.9p2'}]}],
					   cve_id='CVE-2025-26466')


class RealNameTests(unittest.TestCase):
	def test_f5_names_its_nginx_records_open_source_and_plus(self):
		for name in ('nginx', 'F5 NGINX', 'NGINX Plus', 'NGINX Open Source'):
			self.assertEqual(sighting(name, '1.24.0', [F5_OSS]), [101], name)
			self.assertEqual(sighting(name, '1.29.5', [F5_BOTH]), [102], name)
		self.assertEqual(sighting('nginx', '1.29.7', [F5_OSS]), [])  # the fixed release is outside the range

	def test_nginx_siblings_are_still_other_products(self):
		siblings = ('nginx-ui', 'ingress-nginx', 'Nginx Proxy Manager', 'NGINX Ingress Controller', 'NGINX Instance Manager', 'nginx-rails')
		for product in siblings:
			pool = [Cve(110, affected(product, '1.0.0', '9.0.0'))]
			for name in ('nginx', 'NGINX Plus', 'NGINX Open Source'):
				self.assertEqual(sighting(name, '1.24.0', pool), [], f'{name} / {product}')
		self.assertEqual(sighting('NGINX Ingress Controller', '1.5.0', [Cve(111, affected('NGINX Ingress Controller', '1.0.0', '9.0.0'))]), [111])

	def test_nmap_service_suffixes_name_the_same_product(self):
		for seen, product in (('Postfix smtpd', 'Postfix'), ('Dovecot imapd', 'Dovecot'), ('Dovecot pop3d', 'Dovecot'),
							  ('Samba smbd', 'Samba'), ('Squid http proxy', 'Squid'), ('Redis key-value store', 'Redis'),
							  ('Elasticsearch REST API', 'Elasticsearch'), ('PostgreSQL DB', 'PostgreSQL'), ('Dropbear sshd', 'Dropbear')):
			self.assertEqual(sighting(seen, '2.0.0', [Cve(120, affected(product, '1.0.0', '9.0.0'))]), [120], seen)

	def test_editions_and_packagings_name_the_same_product(self):
		for seen, product in (('Grafana OSS', 'Grafana'), ('GitLab CE/EE', 'GitLab'), ('GitLab Community Edition', 'GitLab'),
							  ('GitLab Enterprise Edition', 'GitLab'), ('Splunk Enterprise', 'Splunk'),
							  ('Jira Software Data Center', 'Jira'), ('Zimbra Collaboration Suite', 'Zimbra'),
							  ('Roundcube Webmail', 'Roundcube'), ('Magento Open Source', 'Magento'), ('Twitter Bootstrap', 'Bootstrap'),
							  ('NetScaler ADC', 'NetScaler'), ('NetScaler', 'NetScaler ADC')):
			self.assertEqual(sighting(seen, '2.0.0', [Cve(130, affected(product, '1.0.0', '9.0.0'))]), [130], seen)

	def test_an_edition_word_does_not_make_a_sibling_product(self):
		for seen, product in (('Grafana OSS', 'Grafana Loki'), ('GitLab CE', 'GitLab Runner'), ('Splunk Enterprise', 'Splunk Universal Forwarder'),
							  ('Magento Open Source', 'Magento Page Builder')):
			self.assertEqual(sighting(seen, '2.0.0', [Cve(131, affected(product, '1.0.0', '9.0.0'))]), [], seen)

	def test_vendor_prefixes_name_the_same_product(self):
		for seen, product in (('Palo Alto Networks PAN-OS', 'PAN-OS'), ('Fortinet FortiOS', 'FortiOS'), ('MikroTik RouterOS', 'RouterOS'),
							  ('JFrog Artifactory', 'Artifactory'), ('FortiOS', 'Fortinet FortiOS')):
			self.assertEqual(sighting(seen, '2.0.0', [Cve(140, affected(product, '1.0.0', '9.0.0'))]), [140], seen)

	def test_package_and_coordinate_names_name_the_same_product(self):
		for seen, record in (
				('openssl-libs', {'product': 'OpenSSL'}), ('gitlab-ce', {'product': 'GitLab'}),
				('symfony/symfony', {'product': 'Symfony', 'package': 'symfony/symfony'}),
				('Symfony', {'product': 'symfony/symfony'}),
				('Log4j', {'package': 'org.apache.logging.log4j:log4j-core'}),
				('org.apache.logging.log4j:log4j-core', {'product': 'Log4j'})):
			pool = [Cve(150, [{**record, 'ranges': [{'introduced': '1.0.0', 'fixed': '9.0.0'}]}])]
			self.assertEqual(sighting(seen, '2.0.0', pool), [150], seen)

	def test_exchange_names_in_every_form_match_the_cu_numbered_record(self):
		for seen in ('Microsoft Exchange Server', 'Exchange Server', 'Microsoft Exchange', 'Microsoft Exchange Server 2016 Cumulative Update 14'):
			self.assertEqual(sighting(seen, '15.1.2044.4', [EXCHANGE]), [103], seen)
		self.assertEqual(sighting('Microsoft SharePoint Server', '15.1.2044.4', [EXCHANGE]), [])

	def test_a_cpe_stored_as_a_technology_is_the_product_and_version(self):
		self.assertEqual(split_name_version('cpe:/a:openbsd:openssh:7.2p2'), ('openssh', '7.2p2'))
		self.assertEqual(split_name_version('cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*'), ('nginx', '1.24.0'))
		self.assertEqual(split_name_version('cpe:/a:apache:http_server'), ('http server', ''))
		self.assertEqual(split_name_version('cpe:/a:apache:http_server:-'), ('http server', ''))

	def test_a_banner_token_is_the_product_and_version(self):
		self.assertEqual(split_name_version('OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'), ('OpenSSH', '9.6p1'))
		self.assertEqual(split_name_version('OpenSSH_for_Windows_8.1'), ('OpenSSH for Windows', '8.1'))
		self.assertEqual(split_name_version('nginx:1.18.0'), ('nginx', '1.18.0'))
		self.assertEqual(split_name_version('jQuery UI'), ('jQuery UI', ''))
		self.assertEqual(split_name_version('Node_Exporter'), ('Node_Exporter', ''))  # no digit after the underscore: still a name


class OsFingerprintNameTests(unittest.TestCase):
	def test_an_application_with_an_os_only_cpe_is_not_an_os_fingerprint(self):
		self.assertFalse(match_policy.is_os_sighting('Microsoft HTTPAPI httpd', 'cpe:/o:microsoft:windows'))
		self.assertFalse(match_policy.is_os_sighting('Linux telnetd', 'cpe:/o:linux:linux_kernel'))
		self.assertFalse(match_policy.is_os_sighting('OpenSSH', 'cpe:/o:canonical:ubuntu_linux'))

	def test_the_os_cpe_still_decides_when_the_name_says_nothing(self):
		for name in ('', 'unknown', 'server', 'tcpwrapped'):
			self.assertTrue(match_policy.is_os_sighting(name, 'cpe:/o:linux:linux_kernel:5.15'), name)
		self.assertTrue(match_policy.is_os_sighting('Ubuntu', 'cpe:/o:canonical:ubuntu_linux:22.04'))


class WorkedMatchGuardTests(Fixture):
	"""The identity sweep and the policy sweep never close a match somebody vouches for."""

	def f5_match(self, **fields):
		cve = self.cve(F5_OSS)
		tech = self.tech('nginx:1.24.0')
		return self.match_for(cve, product='NGINX Open Source', version='1.24.0', in_range=True, confidence=0.95,
							  evidence={'source': 'tech', 'source_id': tech.id}, **fields)

	def verdict(self, match):
		match.refresh_from_db()
		return match.ai_verdict

	def test_a_fixed_in_range_f5_nginx_match_is_not_closed_and_writes_no_shared_verdict(self):
		match = self.f5_match(remediation_status='fixed')
		reconcile_invalid_correlations(limit=100)
		match_policy.close_policy_matches()
		self.assertEqual(self.verdict(match), '')
		self.assertEqual((MatchVerdict.objects.count(), TriageVerdict.objects.count()), (0, 0))

	def test_an_open_in_range_f5_nginx_match_stays_a_match(self):
		match = self.f5_match()
		self.assertEqual(correlation.invalid_identity_reason(match), '')

	def test_every_kind_of_standing_protects_a_wrong_product_match(self):
		user = User.objects.create(username='someone')
		for number, (label, change) in enumerate((('in progress', lambda m: CVEMatch.objects.filter(pk=m.pk).update(remediation_status='in_progress')),
							  ('fixed', lambda m: CVEMatch.objects.filter(pk=m.pk).update(remediation_status='fixed')),
							  ('accepted', lambda m: CVEMatch.objects.filter(pk=m.pk).update(remediation_status='accepted_risk')),
							  ('assigned', lambda m: CVEMatch.objects.filter(pk=m.pk).update(assignee=user)),
							  ('commented', lambda m: FindingComment.objects.create(project=self.project, finding_kind='match',
																					 finding_id=m.pk, text='looking into it')),
							  ('validation asked', lambda m: OnDemandValidation.objects.create(match=m, project=self.project, source='manual')),
							  ('ai affirmed', lambda m: CVEMatch.objects.filter(pk=m.pk).update(ai_verdict='affected', ai_model='test')))):
			CVEMatch.objects.all().delete()
			ingress = self.cve(Cve(160 + number, affected('ingress-nginx', '1.0.0', '1.12.1', 'kubernetes')))
			tech = self.tech('nginx:1.10.0')
			match = self.match_for(ingress, product='ingress-nginx', version='1.10.0', in_range=True,
								   evidence={'source': 'tech', 'source_id': tech.id})
			change(match)
			match.refresh_from_db()
			self.assertEqual(correlation.invalid_identity_reason(match), '', label)
			reconcile_invalid_correlations(limit=100)
			self.assertNotEqual(self.verdict(match), 'not_affected', label)

	def test_a_queued_validation_request_protects_a_match_but_the_one_running_re_reads_its_identity(self):
		ingress = self.cve(Cve(172, affected('ingress-nginx', '1.0.0', '1.12.1', 'kubernetes')))
		tech = self.tech('nginx:1.10.0')
		match = self.match_for(ingress, product='ingress-nginx', version='1.10.0', in_range=True, evidence={'source': 'tech', 'source_id': tech.id})
		request = OnDemandValidation.objects.create(match=match, project=self.project, source='manual', status='queued')
		self.assertEqual(correlation.invalid_identity_reason(match), '')
		OnDemandValidation.objects.filter(pk=request.pk).update(status='running')
		self.assertIn('different product', correlation.invalid_identity_reason(match))

	def test_the_same_wrong_product_match_with_nobody_behind_it_closes_without_a_shared_verdict(self):
		ingress = self.cve(Cve(170, affected('ingress-nginx', '1.0.0', '1.12.1', 'kubernetes')))
		tech = self.tech('nginx:1.10.0')
		match = self.match_for(ingress, product='ingress-nginx', version='1.10.0', in_range=True,
							   evidence={'source': 'tech', 'source_id': tech.id})
		reconcile_invalid_correlations(limit=100)
		self.assertEqual(self.verdict(match), 'not_affected')
		self.assertEqual((MatchVerdict.objects.count(), TriageVerdict.objects.count()), (0, 0))  # another host's evidence is its own
		self.assertEqual(Triage.objects.get(match=match).classification, 'not_applicable')

	def test_a_wrong_product_verdict_without_a_range_is_still_shared(self):
		nginx_ui = self.cve(Cve(171, affected('nginx-ui', '1.0.0', '2.1.0')))
		tech = self.tech('nginx')
		match = self.match_for(nginx_ui, product='nginx-ui', evidence={'source': 'tech', 'source_id': tech.id})
		reconcile_invalid_correlations(limit=100)
		self.assertEqual(self.verdict(match), 'not_affected')
		self.assertEqual(MatchVerdict.objects.count(), 1)

	def test_an_in_progress_grafana_match_with_no_bound_is_kept_by_both_sweeps(self):
		grafana = self.cve(Cve(180, [{'vendor': 'Grafana Labs', 'product': 'Grafana', 'ranges': []}], cve_id='CVE-2021-43798'))
		tech = self.tech('Grafana:8.2.0')
		match = self.match_for(grafana, product='Grafana', version='8.2.0', in_range=None, remediation_status='in_progress',
							   evidence={'source': 'tech', 'source_id': tech.id})
		reconcile_invalid_correlations(limit=100)
		self.assertEqual(match_policy.close_policy_matches(), 0)
		self.assertEqual(self.verdict(match), '')

	def test_the_policy_sweep_keeps_assigned_commented_and_validation_requested_matches(self):
		user = User.objects.create(username='owner')
		kept = {
			'assignee': self.match_for(self.cve(Cve(190, affected('nginx'))), assignee=user),
			'comment': self.match_for(self.cve(Cve(191, affected('nginx'))), product='nginx'),
			'validation': self.match_for(self.cve(Cve(192, affected('nginx'))), product='nginx'),
			'ai': self.match_for(self.cve(Cve(193, affected('nginx'))), ai_verdict='affected', ai_model='test'),
		}
		FindingComment.objects.create(project=self.project, finding_kind='match', finding_id=kept['comment'].pk, text='note')
		OnDemandValidation.objects.create(match=kept['validation'], project=self.project, source='manual')
		self.assertEqual(match_policy.close_policy_matches(), 0)
		for name, match in kept.items():
			self.assertNotEqual(self.verdict(match), 'not_affected', name)

	def test_the_policy_update_applies_the_guard_again_to_the_rows_it_writes(self):
		match = self.match_for(self.cve(Cve(195, affected('nginx'))))
		real, calls = match_policy.closable, []

		def person_acts_between_the_read_and_the_write(qs):
			calls.append(1)
			if len(calls) == 2:  # the first call picks the ids, the second guards the UPDATE
				CVEMatch.objects.filter(pk=match.pk).update(remediation_status='in_progress')
			return real(qs)
		with mock.patch.object(match_policy, 'closable', person_acts_between_the_read_and_the_write):
			self.assertEqual(match_policy.close_policy_matches(), 0)
		self.assertEqual(self.verdict(match), '')

	def test_the_ai_cannot_close_a_branch_unlisted_match(self):
		php = self.cve(Cve(196, [{'product': 'PHP', 'ranges': [{'introduced': '8.1', 'fixed': '8.1.30'}, {'introduced': '8.2', 'fixed': '8.2.24'}]}]))
		match = self.match_for(php, product='PHP', version='5.6.40', in_range=None, evidence={'source': 'tech', 'branch_unlisted': True})
		pairs = triage.track([match])
		verdict = TriageVerdict.objects.create(kind='cve_match', signature=pairs[0][0].signature, classification='not_applicable',
											   reason='different product', model='test')
		triage._apply(verdict, pairs)
		self.assertEqual(self.verdict(match), 'uncertain')


class KevWithoutABoundTests(Fixture):
	"""A KEV advisory with no usable version bound is kept for a versioned sighting as a low-confidence candidate."""

	RECORDS = (
		('CVE-2021-41773', {'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server', 'ranges': []}, 'Apache httpd', '2.4.49'),
		('CVE-2021-42013', {'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server', 'ranges': []}, 'Apache httpd', '2.4.50'),
		('CVE-2024-23897', {'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': [{'introduced': 'unspecified'}]}, 'Jenkins', '2.426.2'),
		('CVE-2021-22205', {'vendor': 'GitLab', 'product': 'GitLab', 'ranges': [{'introduced': 'unspecified', 'fixed': 'unspecified'}]},
		 'GitLab CE/EE', '13.10.2'),
		('CVE-2021-43798', {'vendor': 'Grafana Labs', 'product': 'Grafana', 'ranges': []}, 'Grafana', '8.2.0'),
		('CVE-2022-22965', {'vendor': 'VMware', 'product': 'Spring Framework', 'ranges': []}, 'Spring Framework', '5.3.17'),
		('CVE-2022-26134', {'vendor': 'Atlassian', 'product': 'Confluence Server', 'ranges': []}, 'Confluence Server', '7.18.0'),
		('CVE-2018-7600', {'vendor': 'Drupal', 'product': 'Drupal', 'ranges': [{'type': 'GIT', 'introduced': 'abc1234'}]}, 'Drupal', '7.57'),
	)

	def test_each_unbounded_kev_record_keeps_a_candidate_that_needs_validation(self):
		for cve_id, record, seen, version in self.RECORDS:
			rows, leads = [], {}
			entry = Cve(200, [record], kev=True, cve_id=cve_id)
			index = correlation.build_product_index([entry])

			class Sub:
				id, scan_history_id, target_domain_id, name = 5, 7, 3, 'www.example.test'
			correlation._record_matches(Sub, seen, version, correlation._norm(seen), 'tech', index, {200: entry}, 0.0, None, rows, leads=leads)
			self.assertEqual([(r['cve_entry_id'], r['version_in_range'], r['evidence'].get('unbounded')) for r in rows], [(200, None, True)], cve_id)
			self.assertLessEqual(rows[0]['confidence'], 0.5, cve_id)
			self.assertEqual(leads, {200: {(3, 'www.example.test')}}, cve_id)

	def test_a_cve_that_is_not_in_the_kev_list_is_not_kept_but_the_host_is_a_lead(self):
		rows, leads = [], {}
		entry = Cve(201, [{'vendor': 'Grafana Labs', 'product': 'Grafana', 'ranges': []}], kev=False, cve_id='CVE-2099-1')

		class Sub:
			id, scan_history_id, target_domain_id, name = 5, 7, 3, 'www.example.test'
		correlation._record_matches(Sub, 'Grafana', '8.2.0', 'grafana', 'tech', correlation.build_product_index([entry]), {201: entry},
									0.0, None, rows, leads=leads)
		self.assertEqual((rows, leads), ([], {201: {(3, 'www.example.test')}}))

	def test_correlation_stores_it_unjudged_and_the_sweeps_keep_it(self):
		entry = self.cve(Cve(210, [{'vendor': 'Apache Software Foundation', 'product': 'Apache HTTP Server', 'ranges': []}],
							 cve_id='CVE-2021-41773'))
		self.port('Apache httpd', '2.4.49', 80)
		self.correlate()
		match = CVEMatch.objects.get(cve_entry=entry)
		self.assertEqual((match.version_in_range, match.ai_verdict, match.evidence.get('unbounded')), (None, '', True))
		self.assertEqual(correlation.invalid_identity_reason(match), '')
		self.assertEqual(match_policy.close_policy_matches(), 0)
		self.correlate()
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, '')

	def test_a_match_closed_before_the_exception_is_reopened_by_the_next_correlation(self):
		entry = self.cve(Cve(211, [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}], cve_id='CVE-2024-23897'))
		self.tech('Jenkins:2.426.2')
		old = self.match_for(entry, product='Jenkins', version='2.426.2', in_range=None, ai_verdict='not_affected', ai_model='deterministic-policy',
							 ai_reason=match_policy.REASON_NO_BOUND, confidence=0.0)
		MatchVerdict.objects.create(cve_entry=entry, matched_product='Jenkins', matched_version='2.426.2', version_in_range=None,
									source='tech', ai_verdict='not_affected', ai_reason=match_policy.REASON_NO_BOUND, ai_model='deterministic-correlation')
		self.correlate()
		old.refresh_from_db()
		self.assertEqual((old.ai_verdict, old.evidence.get('unbounded')), ('', True))

	def test_a_new_host_is_not_seeded_closed_from_an_older_closure(self):
		entry = self.cve(Cve(212, [{'vendor': 'Jenkins Project', 'product': 'Jenkins', 'ranges': []}], cve_id='CVE-2024-23897'))
		self.tech('Jenkins:2.426.2')
		MatchVerdict.objects.create(cve_entry=entry, matched_product='Jenkins', matched_version='2.426.2', version_in_range=None,
									source='tech', ai_verdict='not_affected', ai_reason=match_policy.REASON_NO_BOUND, ai_model='deterministic-correlation')
		self.correlate()
		self.assertEqual(CVEMatch.objects.get(cve_entry=entry).ai_verdict, '')

	def test_an_unversioned_fire_cve_host_and_an_unbounded_one_are_both_tested(self):
		from cveFeed.autofire import correlate_hot_cves, fire_for_cve
		entry = self.cve(Cve(213, [{'vendor': 'Grafana Labs', 'product': 'Grafana', 'ranges': []}], cve_id='CVE-2021-43798'), kev=False)
		other = Subdomain.objects.create(name='two.example.test', target_domain=self.domain, scan_history=self.scan)
		tech = Technology.objects.create(name='Grafana:8.2.0')
		other.technologies.add(tech)
		self.tech('Grafana')
		leads = correlate_hot_cves([entry])
		self.assertEqual(leads, {entry.id: {(self.domain.id, 'www.example.test'), (self.domain.id, 'two.example.test')}})
		calls = []
		fire_for_cve(entry, correlated=True, leads=leads[entry.id], test_dispatcher=lambda pk, hosts, project: calls.append(sorted(hosts)))
		self.assertEqual(calls, [['two.example.test', 'www.example.test']])


class CorrelatedNamesTests(Fixture):
	"""The real-shape names reach a match end to end."""

	def test_f5_nginx_on_a_tech_and_on_an_nmap_port_matches_both_records(self):
		first, second = self.cve(F5_OSS, kev=False), self.cve(F5_BOTH, kev=False)
		self.tech('nginx:1.24.0')
		self.port('nginx', '1.29.5', 443, cpe='cpe:/a:igor_sysoev:nginx:1.29.5')
		self.correlate()
		found = sorted((m.cve_entry.cve_id, m.source, m.version_in_range) for m in CVEMatch.objects.all())
		self.assertEqual(found, [('CVE-2026-27654', 'port', True), ('CVE-2026-27654', 'tech', True),
								 ('CVE-2026-9256', 'port', True), ('CVE-2026-9256', 'tech', True)])
		self.assertTrue(all(m.ai_verdict == '' for m in CVEMatch.objects.all()))
		self.assertEqual(first.cve_id, 'CVE-2026-27654')
		self.assertEqual(second.cve_id, 'CVE-2026-9256')

	def test_exchange_matches_by_every_name_a_scanner_gives_it(self):
		self.cve(EXCHANGE)
		for name in ('Microsoft Exchange Server:15.1.2044.4', 'Exchange Server:15.1.2044.4'):
			self.tech(name)
		self.port('Microsoft Exchange', '15.1.2044.4', 443)
		self.correlate()
		self.assertEqual(sorted(CVEMatch.objects.values_list('source', flat=True)), ['port', 'tech'])  # both tech names are one product
		self.assertEqual(CVEMatch.objects.filter(version_in_range=True).count(), CVEMatch.objects.count())

	def test_openssh_stored_as_a_cpe_or_a_banner_matches(self):
		for entry in (OPENSSH_SCP, OPENSSH_REGRESSHION, OPENSSH_TERRAPIN):
			self.cve(entry, kev=entry.kev)
		self.tech('cpe:/a:openbsd:openssh:7.2p2')
		self.correlate()
		self.assertEqual([m.cve_entry.cve_id for m in CVEMatch.objects.all()], ['CVE-2020-15778'])
		CVEMatch.objects.all().delete()
		Technology.objects.all().delete()
		self.tech('OpenSSH_9.6p1 Ubuntu-3ubuntu13.5')
		self.correlate()
		self.assertEqual(sorted(m.cve_entry.cve_id for m in CVEMatch.objects.all()), ['CVE-2024-6387', 'CVE-2025-26466'])

	def test_an_application_with_an_os_cpe_is_a_lead_not_dropped_as_an_os(self):
		self.port('Microsoft HTTPAPI httpd', '', 5985, cpe='cpe:/o:microsoft:windows')
		self.port('Linux telnetd', '', 23, cpe='cpe:/o:linux:linux_kernel')
		self.assertEqual(sorted(lead['name'] for lead in match_policy.unversioned_products(self.sub)), ['Linux telnetd', 'Microsoft HTTPAPI httpd'])


class LocalityReviewTests(Fixture):
	SACK = ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
			'Jonathan Looney discovered that the TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow in the Linux kernel '
			'when handling TCP Selective Acknowledgments (SACKs). A remote attacker could use this to cause a denial of service.')
	TIPC = ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
			'A stack overflow flaw was found in the Linux kernel\'s TIPC protocol functionality in the way a user sends a packet with '
			'malicious content where the number of domain member nodes is higher than the 64 allowed.')
	KERNEL_AFFECTED = [{'vendor': 'Linux', 'product': 'Linux Kernel', 'ranges': []}]
	CNA = 'In the Linux kernel, the following vulnerability has been resolved: spi: fix a leak'

	def test_remote_kernel_flaws_stay_remote(self):
		for vector, text in (self.SACK, self.TIPC):
			self.assertFalse(locality.classify(vector, text, '', self.KERNEL_AFFECTED)[0], text[:40])
		self.assertFalse(locality.classify('', self.SACK[1], '', self.KERNEL_AFFECTED)[0])  # the wording alone says remote

	def test_a_network_vector_on_a_kernel_cna_record_is_not_local(self):
		self.assertFalse(locality.classify(self.TIPC[0], self.CNA, '', self.KERNEL_AFFECTED)[0])

	def test_a_kev_kernel_record_is_not_host_only_unless_its_vector_is_local(self):
		self.assertFalse(locality.classify('', self.CNA, '', self.KERNEL_AFFECTED, kev=True)[0])
		self.assertTrue(locality.classify('', self.CNA, '', self.KERNEL_AFFECTED, kev=False)[0])
		self.assertTrue(locality.classify('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', self.CNA, '', self.KERNEL_AFFECTED, kev=True)[0])

	def test_refresh_reclassifies_a_record_the_old_rule_flagged(self):
		sack = CVEEntry.objects.create(cve_id='CVE-2019-11477', cvss_vector=self.SACK[0], original_description=self.SACK[1],
									   affected=self.KERNEL_AFFECTED, local_only=True, locality_at=locality.RULES_AT - timedelta(days=1))
		locality.refresh()
		sack.refresh_from_db()
		self.assertFalse(sack.local_only)

	def local_match(self, **fields):
		entry = CVEEntry.objects.create(cve_id=f'CVE-2099-{CVEEntry.objects.count() + 1}', cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
										kev=False, local_only=True, affected=self.KERNEL_AFFECTED)
		return self.match_for(entry, product='Linux', source=fields.pop('source', 'tech'), **fields)

	def test_a_local_only_match_with_no_standing_closes_and_its_triage_row_follows(self):
		match = self.local_match()
		triage.track([match])
		self.assertEqual(locality.close_local_matches(), 1)
		match.refresh_from_db()
		self.assertEqual(match.ai_verdict, 'not_affected')
		row = Triage.objects.get(match=match)
		self.assertEqual((row.classification, row.status), ('not_applicable', 'triaged'))
		self.assertIn('local-only', row.reason)

	def test_the_stats_revision_moves_when_matches_close(self):
		from cveFeed import views
		self.local_match()
		with mock.patch.object(views, 'bump_stats_revision') as bump:
			locality.close_local_matches()
			locality.close_local_matches()  # nothing left to close: no second bump
		self.assertEqual(bump.call_count, 1)

	def test_a_local_only_match_somebody_vouches_for_is_kept(self):
		user = User.objects.create(username='triager')
		kept = {
			'template': self.local_match(template_result='vulnerable'),
			'distro': self.local_match(distro_status='vulnerable'),
			'in progress': self.local_match(remediation_status='in_progress'),
			'assigned': self.local_match(assignee=user),
			'host report': self.local_match(source='host'),
			'ai affirmed': self.local_match(ai_verdict='affected', ai_model='test'),
		}
		commented = self.local_match()
		FindingComment.objects.create(project=self.project, finding_kind='match', finding_id=commented.pk, text='checked by hand')
		kept['comment'] = commented
		requested = self.local_match()
		OnDemandValidation.objects.create(match=requested, project=self.project, source='manual')
		kept['validation'] = requested
		self.assertEqual(locality.close_local_matches(), 0)
		for name, match in kept.items():
			match.refresh_from_db()
			self.assertNotEqual(match.ai_verdict, 'not_affected', name)

	def test_a_local_cve_with_a_template_hit_is_not_closed_by_the_identity_sweep(self):
		match = self.local_match(template_result='vulnerable')
		match = CVEMatch.objects.select_related('cve_entry').get(pk=match.pk)
		self.assertEqual(correlation.invalid_identity_reason(match), '')

	def test_the_sweep_closes_in_chunks_until_nothing_is_left(self):
		matches = [self.local_match() for _ in range(5)]
		with mock.patch.object(locality, 'CLOSE_CHUNK', 2):
			self.assertEqual(locality.close_local_matches(), 5)
		self.assertEqual(CVEMatch.objects.filter(ai_verdict='not_affected').count(), len(matches))
		self.assertEqual(locality.close_local_matches(), 0)


class PolicyClosureTriageTests(Fixture):
	def test_a_policy_closure_settles_the_triage_row_and_moves_the_stats(self):
		from cveFeed import views
		match = self.match_for(self.cve(Cve(220, affected('nginx'))))
		triage.track([match])
		self.assertEqual(Triage.objects.get(match=match).classification, '')
		with mock.patch.object(views, 'bump_stats_revision') as bump:
			self.assertEqual(match_policy.close_policy_matches(), 1)
		row = Triage.objects.get(match=match)
		self.assertEqual((row.classification, row.status), ('not_applicable', 'triaged'))
		self.assertTrue(row.reason.startswith('Closed automatically: no version evidence'))
		bump.assert_called_once()


class ClosureWordingTests(Fixture):
	"""A closure says what happened (a different product, which one) and never calls the data "invalid"."""

	def wrong_product_match(self):
		ingress = self.cve(Cve(173, affected('ingress-nginx', '1.0.0', '1.12.1', 'kubernetes')))
		tech = self.tech('nginx:1.10.0')
		return self.match_for(ingress, product='ingress-nginx', version='1.10.0', in_range=True,
							  evidence={'source': 'tech', 'source_id': tech.id})

	def test_the_reason_names_the_recorded_product_and_the_one_the_advisory_covers(self):
		reason = correlation.invalid_identity_reason(self.wrong_product_match())
		self.assertTrue(reason.startswith(correlation.DIFFERENT_PRODUCT), reason)
		self.assertIn('"nginx"', reason)
		self.assertIn('"ingress-nginx"', reason)
		self.assertNotIn('invalid', reason.lower())
		self.assertIn('absent elsewhere on the host', reason)

	def test_the_activity_line_carries_the_reason_not_a_fixed_phrase(self):
		match = self.wrong_product_match()
		with mock.patch('cveFeed.activity.log') as log:
			self.assertTrue(correlation.close_invalid_correlation(match))
		line = log.call_args.args[1]
		self.assertIn(match.cve_entry.cve_id, line)
		self.assertIn('different product', line)
		self.assertIn('"ingress-nginx"', line)
		self.assertNotIn('invalid', line.lower())

	def test_a_local_only_or_no_evidence_closure_is_not_called_a_product_mismatch(self):
		self.assertEqual(correlation.closure_summary(match_policy.NO_EVIDENCE + ' (no version, no usable range). It stays closed.'),
						 'no version evidence (no version, no usable range)')
		self.assertTrue(correlation.closure_summary('Closed automatically: local-only vulnerability (AV:L). An attacker needs to be on the host.')
						.startswith('local-only vulnerability'))

	def test_a_row_closed_under_the_first_wording_is_still_an_automatic_closure(self):
		legacy = 'Closed automatically: invalid product correlation; the recorded product identity does not match an affected product in the advisory.'
		self.assertTrue(legacy.startswith(correlation.AUTO_CLOSED))

	def test_the_migration_rewrites_the_first_wording_in_stored_rows(self):
		from importlib import import_module
		from django.apps import apps
		migration = import_module('cveFeed.migrations.0092_reword_different_product_closures')
		match = self.wrong_product_match()
		old = ('Closed automatically: invalid product correlation; the recorded product identity does not match an affected product '
			   'in the advisory. This closes this candidate match only.')
		CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=old)
		migration.reword(apps, None)
		match.refresh_from_db()
		self.assertNotIn('invalid', match.ai_reason)
		self.assertTrue(match.ai_reason.startswith('Closed automatically: different product; the recorded product is not one the advisory covers'))
		self.assertTrue(match.ai_reason.endswith('This closes this candidate match only.'))
