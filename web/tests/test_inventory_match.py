"""CVE matches from what a host reported about itself: how a local-only CVE becomes a finding (and only from the host's own report),
how distribution backports are judged, and that a stale report creates and closes nothing."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from cveFeed import correlation, host_inventory, inventory_match, inventory_schema as schema, locality
from cveFeed.models import CVEEntry, CVEMatch, DistroFix, HostInventory, ProjectSettings
from tests.test_host_inventory import Base, report
from startScan.models import ScanHistory, Subdomain, Technology
from tests.test_agentapi import call

LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
NETWORK = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
WINDOWS_11 = {'family': 'windows', 'id': 'windows', 'name': 'Windows 11 Pro', 'version': '23H2', 'build': '10.0.22631.4460',
	'pretty': 'Windows 11 Pro 23H2 (build 10.0.22631.4460)', 'arch': 'AMD64'}


def windows_report(build='10.0.22631.4460', release='23H2', name='Windows 11 Pro', software=()):
	return report(os={**WINDOWS_11, 'build': build, 'version': release, 'name': name},
		packages=[{'n': n, 'v': v, 'e': 'win'} for n, v in software], services=[], runtime={'reboot_required': False}, security={})


def cve(cve_id, product, introduced, fixed, vector=LOCAL, local=True, kev=False, vendor='Vendor', **extra):
	return CVEEntry.objects.create(
		cve_id=cve_id, status='PUBLISHED', published_at=timezone.now(), cvss=7.8, cvss_vector=vector, local_only=local, kev=kev,
		original_description='x', affected=[{'vendor': vendor, 'product': product, 'ranges': [{'introduced': introduced, 'fixed': fixed}]}], **extra)


class ComponentTests(SimpleTestCase):
	def test_windows_product_names_are_the_ones_the_feed_uses(self):
		self.assertEqual(inventory_match.windows_names(WINDOWS_11), ['Windows 11 Version 23H2', 'Windows 11'])
		server = {'name': 'Windows Server 2022 Datacenter', 'version': '21H2'}
		self.assertEqual(inventory_match.windows_names(server), ['Windows Server 2022'])
		self.assertEqual(inventory_match.windows_names({'name': 'Windows 10 Enterprise', 'version': '22H2'}), ['Windows 10 Version 22H2', 'Windows 10'])
		self.assertEqual(inventory_match.windows_names({'name': 'Plan 9'}), [])

	def test_the_kernel_of_a_backporting_distribution_is_not_assessed(self):
		for ident, like in (('ubuntu', ['debian']), ('debian', []), ('rhel', ['fedora']), ('rocky', ['rhel', 'centos', 'fedora']), ('linuxmint', ['ubuntu', 'debian'])):
			block = {'family': 'linux', 'id': ident, 'id_like': like, 'kernel': '5.15.0-91-generic'}
			self.assertEqual(inventory_match.os_components(block), [], ident)
		for ident in ('arch', 'alpine', 'fedora'):
			block = {'family': 'linux', 'id': ident, 'id_like': [], 'kernel': '6.5.7-arch1-1'}
			self.assertEqual(inventory_match.os_components(block)[0]['version'], '6.5.7', ident)

	def test_packages_are_looked_up_by_source_then_name_without_a_trailing_version(self):
		pkg = {'n': 'libssl3', 'v': '3.0.2-0ubuntu1.10', 'e': 'dpkg', 's': 'openssl'}
		self.assertEqual(inventory_match._names_of(pkg), ['openssl', 'libssl3', 'libssl'])
		self.assertEqual(inventory_match._names_of({'n': 'php8.1-cli', 'v': '8.1.2', 'e': 'dpkg', 's': 'php8.1'}), ['php8.1', 'php', 'php8.1-cli'])
		self.assertEqual(inventory_match._names_of({'n': 'ab', 'v': '1', 'e': 'dpkg'}), [])  # too short to name a product

	def test_kernel_packages_and_versionless_ones_make_no_component(self):
		packages = [{'n': 'linux-image-5.15.0-91-generic', 'v': '5.15.0-91.101', 'e': 'dpkg', 's': 'linux-signed'},
			{'n': 'linux-libc-dev', 'v': '5.15.0-91.101', 'e': 'dpkg', 's': 'linux'}, {'n': 'nginx', 'v': '', 'e': 'dpkg'},
			{'n': 'curl', 'v': '7.81.0-1ubuntu1.15', 'e': 'dpkg'}]
		names = [c['names'][0] for c in inventory_match.package_components({'id': 'ubuntu'}, packages)]
		self.assertEqual(names, ['curl'])

	def test_the_distro_record_for_a_package_is_only_built_for_tracked_distributions(self):
		pkg = {'n': 'openssh-server', 'v': '1:8.9p1-3ubuntu0.6', 'e': 'dpkg', 's': 'openssh'}
		info = inventory_match._info({'id': 'ubuntu', 'version': '22.04'}, pkg)
		self.assertEqual((info['distro'], info['release'], info['package'], info['upstream_version']), ('ubuntu', '22.04', 'openssh', '8.9p1'))
		self.assertEqual(inventory_match._info({'id': 'debian', 'version': '12.5'}, pkg)['release'], '12')
		self.assertIsNone(inventory_match._info({'id': 'alpine', 'version': '3.19'}, {**pkg, 'e': 'apk'}))
		self.assertIsNone(inventory_match._info({'id': 'opensuse-leap', 'version': '15.5'}, {**pkg, 'e': 'rpm'}))
		self.assertEqual(inventory_match._info({'id': 'ubuntu', 'version': '22.04'}, {**pkg, 's': 'nano'})['package'], '')


class MatchBase(Base):
	def setUp(self):
		super().setUp()
		correlation._INDEX_CACHE.update(key=None, value=None)
		correlation._LOCAL_CACHE.update(key=None, value=None)

	def inventory(self, rep, name='web01.example.test', sub=True):
		if sub:
			self.sub = self.scanned(name, ['192.0.2.10'])
		inv, _ = host_inventory.ingest(self.project, schema.validate(rep))
		correlation._LOCAL_CACHE.update(key=None, value=None)
		return inv

	def refresh(self, inv, days=14, **kw):
		return inventory_match.refresh(inv, days, **kw)

	def host_matches(self, **filters):
		return CVEMatch.objects.filter(source='host', **filters)


class LocalFindingTests(MatchBase):
	def test_a_local_only_cve_becomes_a_finding_only_from_the_hosts_own_report(self):
		kernel_bug = cve('CVE-2099-1001', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602')
		inv = self.inventory(windows_report())
		self.assertNotIn(kernel_bug.id, correlation.cve_pool()[0])  # the external correlation never sees it
		result = self.refresh(inv)
		self.assertEqual((result['status'], result['local'], result['external']), ('done', 1, 0))
		match = self.host_matches().get()
		self.assertEqual(match.cve_entry_id, kernel_bug.id)
		self.assertEqual((match.source, match.version_in_range, match.matched_version, match.confidence), ('host', True, '10.0.22631.4460', 0.95))
		self.assertTrue(match.evidence['host_reported'])
		self.assertEqual((match.evidence['scope'], match.evidence['inventory_id']), ('local', inv.id))
		self.assertEqual(match.subdomain_id, self.sub.id)
		self.assertEqual(match.remediation_status, 'open')

	def test_the_external_correlation_still_never_matches_it(self):
		cve('CVE-2099-1002', 'nginx', '1.0.0', '1.20.0')
		sub = self.scanned('www.example.test')
		sub.technologies.add(Technology.objects.create(name='nginx:1.18.0'))
		cve_by_id, index = correlation.cve_pool()
		correlation.correlate_subdomain(sub, index, cve_by_id)
		self.assertFalse(CVEMatch.objects.exists())

	def test_a_patched_build_a_different_release_and_a_range_less_record_match_nothing(self):
		cve('CVE-2099-1003', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4460')  # fixed in the very build the host runs
		cve('CVE-2099-1004', 'Windows 11 Version 22H2', '10.0.0', '10.0.22621.9999')  # another release
		CVEEntry.objects.create(cve_id='CVE-2099-1005', status='PUBLISHED', cvss_vector=LOCAL, local_only=True, original_description='x',
			affected=[{'vendor': 'Microsoft', 'product': 'Windows 11', 'ranges': []}])  # names the product, no version bound
		inv = self.inventory(windows_report())
		self.assertEqual(self.refresh(inv)['local'], 0)
		self.assertFalse(CVEMatch.objects.exists())

	def test_a_generic_product_name_does_not_match_every_windows_host(self):
		CVEEntry.objects.create(cve_id='CVE-2099-1006', status='PUBLISHED', cvss_vector=LOCAL, local_only=True, original_description='x',
			affected=[{'vendor': 'Microsoft', 'product': 'Windows', 'ranges': [{'introduced': '0', 'fixed': '99.0'}]}])
		inv = self.inventory(windows_report())
		self.assertEqual(self.refresh(inv)['local'], 0)

	def test_installed_software_is_matched_by_exact_name(self):
		cve('CVE-2099-1010', '7-Zip', '0', '24.0', vector=LOCAL, local=True)
		cve('CVE-2099-1011', 'PuTTY', '0.50', '0.80', vector=NETWORK, local=False)
		inv = self.inventory(windows_report(software=[('7-Zip', '23.01'), ('PuTTY release 0.79', '0.79'), ('Notepad++ (64-bit x64)', '8.5')]))
		result = self.refresh(inv)
		self.assertEqual({m.cve_entry.cve_id for m in self.host_matches()}, {'CVE-2099-1010'})  # "PuTTY release 0.79" is not the product "PuTTY"
		self.assertEqual(result['local'], 1)

	def test_a_kev_listing_raises_the_confidence_a_little(self):
		cve('CVE-2099-1012', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602', kev=True)
		self.refresh(self.inventory(windows_report()))
		self.assertEqual(self.host_matches().get().confidence, 1.0)

	def test_a_linux_kernel_of_an_upstream_tracking_distribution_is_assessed_but_ubuntus_is_not(self):
		cve('CVE-2099-1020', 'Linux Kernel', '5.15', '5.15.134', vendor='Linux')
		arch = report(os={'family': 'linux', 'id': 'arch', 'name': 'Arch Linux', 'kernel': '5.15.100-1-lts', 'arch': 'x86_64'}, packages=[])
		inv = self.inventory(arch)
		self.assertEqual(self.refresh(inv)['local'], 1)
		self.assertEqual(self.host_matches().get().confidence, 0.8)
		CVEMatch.objects.all().delete()
		inv = self.inventory(report(packages=[]), sub=False)
		inv.host = self.sub.name
		inv.save()
		HostInventory.objects.exclude(pk=inv.pk).delete()
		result = self.refresh(inv)
		self.assertEqual(result['local'], 0)
		self.assertTrue(any('kernel was not assessed' in n for n in result['notes']))

	def test_a_package_on_a_distribution_is_moderate_confidence_without_tracker_data(self):
		cve('CVE-2099-1030', 'sudo', '1.8.0', '1.9.5p2')
		sudo = [{'n': 'sudo', 'v': '1.8.31-1ubuntu1.2', 'e': 'dpkg', 'a': 'amd64'}]
		inv = self.inventory(report(packages=sudo))
		self.assertEqual(self.refresh(inv)['local'], 1)
		match = self.host_matches().get()
		self.assertEqual((match.confidence, match.distro_status, match.matched_version), (0.6, 'no_data', '1.8.31-1ubuntu1.2'))
		self.assertEqual(match.evidence['purl'], 'pkg:deb/ubuntu/sudo@1.8.31-1ubuntu1.2?arch=amd64&distro=ubuntu-22.04')

	def test_the_distributions_own_fixed_version_settles_a_package(self):
		openssh = cve('CVE-2099-1040', 'OpenSSH', '8.5', '9.8', vector=NETWORK, local=False)
		packages = [{'n': 'openssh-server', 'v': '1:8.9p1-3ubuntu0.6', 'e': 'dpkg', 's': 'openssh'}]
		inv = self.inventory(report(packages=packages))
		DistroFix.objects.create(distro='ubuntu', release='22.04', package='openssh', cve_id='CVE-2099-1040', fixed_version='1:8.9p1-3ubuntu0.10', status='fixed')
		self.refresh(inv)
		match = self.host_matches().get()
		self.assertEqual((match.distro_status, match.confidence), ('vulnerable', 0.95))  # older than the fixed package release
		DistroFix.objects.update(fixed_version='1:8.9p1-3ubuntu0.6')
		self.refresh(inv)
		match.refresh_from_db()
		self.assertEqual((match.distro_status, match.confidence), ('patched', 0.2))  # kept and labelled, like an external match
		self.assertEqual(openssh.id, match.cve_entry_id)

	def test_a_name_that_only_contains_the_product_does_not_match(self):
		cve('CVE-2099-1050', 'phpMyAdmin', '4.0', '5.2.1', vector=NETWORK, local=False)
		packages = [{'n': 'php8.1-cli', 'v': '8.1.2-1ubuntu2.14', 'e': 'dpkg', 's': 'php8.1'}, {'n': 'phpmyadmin', 'v': '4.9.5-1', 'e': 'dpkg'}]
		inv = self.inventory(report(packages=packages))
		self.refresh(inv)
		self.assertEqual({m.matched_product for m in self.host_matches()}, {'phpMyAdmin'})
		self.assertEqual(self.host_matches().count(), 1)  # php8.1 is not phpMyAdmin

	def test_a_cve_an_external_scan_already_matched_gets_the_hosts_evidence_not_a_second_row(self):
		nginx = cve('CVE-2099-1060', 'nginx', '1.0.0', '1.20.0', vector=NETWORK, local=False)
		inv = self.inventory(report(packages=[{'n': 'nginx', 'v': '1.18.0-6ubuntu14.4', 'e': 'dpkg', 'a': 'amd64'}]))
		external = CVEMatch.objects.create(cve_entry=nginx, subdomain=self.sub, source='port', matched_product='nginx', matched_version='1.18.0',
			version_in_range=True, confidence=0.85, evidence={'source': 'port'})
		result = self.refresh(inv)
		self.assertEqual((result['local'], result['external'], result['confirmed']), (0, 0, 1))
		self.assertEqual(CVEMatch.objects.count(), 1)
		external.refresh_from_db()
		self.assertEqual(external.confidence, 0.85)  # the host's 0.6 for a distribution package does not lower it
		self.assertEqual(external.evidence['host_reported']['inventory_id'], inv.id)
		self.assertEqual(external.evidence['source'], 'port')

	def test_a_package_cve_that_no_scan_saw_is_a_host_reported_external_match(self):
		cve('CVE-2099-1061', 'nginx', '1.0.0', '1.20.0', vector=NETWORK, local=False)
		inv = self.inventory(report(packages=[{'n': 'nginx', 'v': '1.18.0-6ubuntu14.4', 'e': 'dpkg'}]))
		result = self.refresh(inv)
		self.assertEqual((result['local'], result['external']), (0, 1))
		self.assertEqual(self.host_matches().get().evidence['scope'], 'external')

	def test_an_old_scan_match_does_not_consume_the_current_hosts_report(self):
		nginx = cve('CVE-2099-1062', 'nginx', '1.0.0', '1.20.0', vector=NETWORK, local=False)
		old = self.scanned('web01.example.test', ['192.0.2.10'])
		prior = CVEMatch.objects.create(cve_entry=nginx, subdomain=old, source='port', matched_product='nginx',
			matched_version='1.18.0', version_in_range=True, confidence=0.85, evidence={'source': 'port'})
		inv = self.inventory(report(packages=[{'n': 'nginx', 'v': '1.18.0-6ubuntu14.4', 'e': 'dpkg'}]), sub=False)
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2,
			start_scan_date=timezone.now(), tasks=['x'])
		current = Subdomain.objects.create(name=old.name, target_domain=self.domain, scan_history=scan)
		self.assertEqual(inventory_match.current_row(self.project.id, old.name).pk, current.pk)
		result = self.refresh(inv)
		self.assertEqual((result['external'], result['confirmed']), (1, 0))
		self.assertEqual(self.host_matches(subdomain=current).count(), 1)
		prior.refresh_from_db()
		self.assertNotIn('host_reported', prior.evidence)

	def test_a_different_product_under_one_cve_keeps_its_own_host_match(self):
		shared = cve('CVE-2099-1063', 'nginx', '1.0.0', '1.20.0', vector=NETWORK, local=False)
		shared.affected.append({'vendor': 'Vendor', 'product': 'ingress-nginx',
			'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]})
		shared.save(update_fields=['affected'])
		inv = self.inventory(report(packages=[{'n': 'nginx', 'v': '1.18.0-6ubuntu14.4', 'e': 'dpkg'}]))
		other = CVEMatch.objects.create(cve_entry=shared, subdomain=self.sub, source='tech', matched_product='ingress-nginx',
			matched_version='1.18.0', version_in_range=True, confidence=0.85, evidence={'source': 'tech'})
		result = self.refresh(inv)
		self.assertEqual((result['external'], result['confirmed']), (1, 0))
		self.assertEqual(self.host_matches().get().matched_product, 'nginx')
		other.refresh_from_db()
		self.assertNotIn('host_reported', other.evidence)

	def test_one_host_report_annotates_every_current_matching_external_sighting(self):
		nginx = cve('CVE-2099-1064', 'nginx', '1.0.0', '1.20.0', vector=NETWORK, local=False)
		inv = self.inventory(report(packages=[{'n': 'nginx', 'v': '1.18.0-6ubuntu14.4', 'e': 'dpkg'}]))
		matches = [CVEMatch.objects.create(cve_entry=nginx, subdomain=self.sub, source=source, matched_product='nginx',
			matched_version='1.18.0', version_in_range=True, confidence=0.85, evidence={'source': source})
			for source in ('port', 'tech')]
		self.assertEqual(self.refresh(inv)['confirmed'], 1)
		self.assertFalse(self.host_matches().exists())
		for match in matches:
			match.refresh_from_db()
			self.assertEqual(match.evidence['host_reported']['inventory_id'], inv.id)


class StalenessAndClosureTests(MatchBase):
	def setUp(self):
		super().setUp()
		self.bug = cve('CVE-2099-2001', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602')
		self.inv = self.inventory(windows_report())
		self.refresh(self.inv)

	def test_a_stale_report_creates_nothing_and_closes_nothing(self):
		later = timezone.now() + timedelta(days=15)
		self.assertEqual(self.refresh(self.inv, now=later), {'status': 'skipped', 'reason': 'stale'})
		self.assertEqual(self.host_matches(ai_verdict='').count(), 1)  # still open
		fixed = windows_report(build='10.0.22631.4602')
		stale = self.inventory(fixed, sub=False)
		HostInventory.objects.filter(pk=stale.pk).update(reported_at=timezone.now() - timedelta(days=30))
		stale.refresh_from_db()
		self.assertEqual(self.refresh(stale)['reason'], 'stale')
		self.assertEqual(self.host_matches(ai_verdict='').count(), 1)  # an old report that says it is fixed closes nothing either

	def test_staleness_follows_the_projects_setting(self):
		ProjectSettings.objects.create(project=self.project, inventory_stale_days=30)
		HostInventory.objects.filter(pk=self.inv.pk).update(reported_at=timezone.now() - timedelta(days=20))
		self.inv.refresh_from_db()
		self.assertEqual(host_inventory.run_correlation(self.inv.id)['status'], 'done')
		ProjectSettings.objects.update(inventory_stale_days=7)
		self.assertEqual(host_inventory.run_correlation(self.inv.id)['reason'], 'stale')

	def test_a_fresh_report_without_the_affected_version_closes_the_match_and_a_return_reopens_it(self):
		patched = self.inventory(windows_report(build='10.0.22631.4602'), sub=False)
		result = self.refresh(patched)
		self.assertEqual(result['local'], 0)
		match = self.host_matches().get()
		self.assertEqual((match.ai_verdict, match.ai_model), ('not_affected', 'deterministic-inventory'))
		self.assertTrue(match.ai_reason.startswith('Closed automatically:'))
		self.assertEqual(self.refresh(patched)['status'], 'done')  # the same report again is stable
		regressed = self.inventory(windows_report(build='10.0.22631.4460'), sub=False)
		self.refresh(regressed)
		match.refresh_from_db()
		self.assertEqual((match.ai_verdict, match.ai_model), ('', ''))

	def test_a_match_a_person_worked_keeps_their_remediation_when_it_closes(self):
		CVEMatch.objects.update(remediation_status='accepted_risk', remediation_note='known')
		self.refresh(self.inventory(windows_report(build='10.0.22631.4602'), sub=False))
		match = self.host_matches().get()
		self.assertEqual((match.ai_verdict, match.remediation_status, match.remediation_note), ('not_affected', 'accepted_risk', 'known'))

	def test_the_locality_sweep_closes_scan_matches_of_local_cves_but_not_the_hosts_own(self):
		external = CVEMatch.objects.create(cve_entry=self.bug, subdomain=self.sub, source='tech', matched_product='Windows', confidence=0.5)
		self.assertEqual(locality.close_local_matches(), 1)
		external.refresh_from_db()
		self.assertEqual(external.ai_verdict, 'not_affected')
		self.assertEqual(self.host_matches(ai_verdict='').count(), 1)
		self.assertEqual(correlation.invalid_identity_reason(self.host_matches().get()), '')
		self.assertTrue(correlation.invalid_identity_reason(external))  # the existing rule for everything else

	def test_only_the_hosts_newest_report_drives_its_matches(self):
		older = HostInventory.objects.get(pk=self.inv.pk)
		newer, _ = host_inventory.ingest(self.project, schema.validate({**windows_report(), 'host': {'hostname': 'twin', 'machine_id': 'b' * 64, 'ips': ['192.0.2.10']}}))
		self.assertEqual(newer.host, '')  # a second machine does not take a host another one reports for: only an administrator ties it
		host_inventory.adopt(newer, older.host)
		self.assertEqual(self.refresh(older)['reason'], 'superseded')
		self.assertEqual(self.refresh(newer)['status'], 'done')

	def test_an_unmatched_report_or_a_host_no_scan_has_seen_is_skipped(self):
		lone, _ = host_inventory.ingest(self.project, schema.validate({**windows_report(), 'host': {'hostname': 'lone', 'machine_id': 'c' * 64, 'ips': ['192.0.2.200']}}))
		self.assertEqual(self.refresh(lone)['reason'], 'unmatched')
		lone.host = 'ghost.example.test'
		self.assertEqual(self.refresh(lone)['reason'], 'no scanned host')

	def test_a_new_scan_brings_the_matches_to_the_new_host_row_with_their_remediation(self):
		CVEMatch.objects.update(remediation_status='in_progress', remediation_note='ticket 4')
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now(), tasks=['x'])
		newer = Subdomain.objects.create(name='web01.example.test', target_domain=self.domain, scan_history=scan)
		with mock.patch('cveFeed.tasks.correlate_host_inventory.delay', side_effect=host_inventory.run_correlation) as queued:
			host_inventory.refresh_scope(scan=scan)
		queued.assert_called_once_with(self.inv.id)
		fresh = self.host_matches(subdomain=newer).get()
		self.assertEqual((fresh.remediation_status, fresh.remediation_note), ('in_progress', 'ticket 4'))

	def test_the_correlation_task_runs_the_hosts_own_reports_too(self):
		from cveFeed.tasks import correlate_cves
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now(), tasks=['x'])
		Subdomain.objects.create(name='web01.example.test', target_domain=self.domain, scan_history=scan)
		with mock.patch('cveFeed.host_inventory.refresh_scope') as refresh:
			correlate_cves(scan_history_id=scan.id)
		refresh.assert_called_once()
		self.assertEqual(refresh.call_args.kwargs['scan'].id, scan.id)

	def test_run_correlation_records_what_it_found_on_the_report(self):
		result = host_inventory.run_correlation(self.inv.id)
		self.assertEqual(result['local'], 1)
		self.inv.refresh_from_db()
		self.assertEqual(self.inv.details['assessment']['local'], 1)
		self.assertEqual(host_inventory.findings_summary(self.inv), {'total': 1, 'local_only': 1})


class ValidationSweepTests(MatchBase):
	def test_outside_validation_is_not_queued_for_what_only_the_host_can_see(self):
		from cveFeed import hot_validation, triage
		bug = cve('CVE-2099-4001', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602', kev=True)
		self.refresh(self.inventory(windows_report()))
		external = CVEMatch.objects.create(cve_entry=bug, subdomain=self.sub, source='port', matched_product='Windows', confidence=0.5)
		triage.track(list(CVEMatch.objects.all()))
		for lane in (hot_validation.FIRE, hot_validation.SMOKE, hot_validation.ICE):
			sources = {t.match.source for t in hot_validation._candidate_rows(lane)}
			self.assertNotIn('host', sources, lane)
		self.assertIn(external.id, {t.match_id for t in hot_validation._candidate_rows(hot_validation.FIRE)})


class SurfaceTests(MatchBase):
	def test_the_api_labels_a_host_reported_match(self):
		cve('CVE-2099-3001', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602')
		self.refresh(self.inventory(windows_report()))
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/matches')
		self.assertEqual(status, 200)
		row = data['results'][0]
		self.assertEqual((row['source'], row['host_reported'], row['cve']['local_only']), ('host', True, True))
		self.assertEqual(row['evidence']['scope'], 'local')
		_, detail = call(self.t_alice, 'GET', f'/api/v1/projects/proj-a/findings/match/{row["id"]}')
		self.assertTrue(detail['host_reported'])
		steps = {s['label']: s['value'] for s in detail['how_found']['steps']}
		self.assertIn('reported by the host itself', steps['Observed'])
		self.assertIn('only usable from the host itself', steps['Found by'])
		_, all_findings = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/findings?type=cve')
		self.assertIn('(reported by the host)', all_findings['results'][0]['note'])

	def test_another_project_never_sees_the_match(self):
		cve('CVE-2099-3002', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602')
		self.refresh(self.inventory(windows_report()))
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-a/matches')[0], 404)
		_, mine = call(self.t_bob, 'GET', '/api/v1/projects/proj-b/matches')
		self.assertEqual(mine['count'], 0)

	def test_the_host_page_record_counts_the_match(self):
		cve('CVE-2099-3003', 'Windows 11 Version 23H2', '10.0.0', '10.0.22631.4602')
		self.refresh(self.inventory(windows_report()))
		host = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/hosts')[1]['results'][0]
		self.assertEqual(host['cve_matches'], 1)
		self.assertIsNotNone(host['inventory'])
