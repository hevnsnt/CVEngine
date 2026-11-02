"""Review follow-ups of the KEV heat policy (PR #386).

- A service banner proves a version only for a vendor-built product: a distribution-packaged one (OpenSSH, Apache httpd, nginx, OpenSSL, ...)
  or one the operating system services (IIS) keeps printing the upstream version after a backported fix, and most of them print no
  distribution marker at all (RHEL, SUSE, Amazon Linux).
- A match is paged as fire once per finding, not once per scan: a rescan's copy carries the page of the copy before it.
- Proof that arrives through correlation, and a CVE that joins the KEV or gains an exploit, page once (and rescore the host); the policy
  switch itself pages nothing (the baseline), and neither does the first correlation that records the new provenance on old rows.
- The database form agrees with the Python form on odd JSON values.
- A scanner finding that names CVEs follows the CVE rule under the KEV policy.
"""
import importlib
import os
from unittest import mock

from django.apps import apps
from django.utils import timezone

from agentapi import services
from cveFeed import autofire, intel, match_policy, notify, threat
from cveFeed.models import AutoFireRun, BackgroundCursor, CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from cveFeed.views import graph_payload
from scanEngine.models import EngineType
from startScan.models import CveId, Port, ScanHistory, Subdomain, Vulnerability, VulnerabilityTags
from tests.test_heat_policy import LEGACY, Policy
from tests.test_match_policy import Fixture, affected

JENKINS = affected('jenkins', '1.0', '2.442')  # a vendor-built server: the version in its banner is the version that runs


class Base(Policy, Fixture):
	def setUp(self):
		super().setUp()
		self.sends = []
		send = mock.patch.object(notify, '_send', side_effect=lambda text, flag, channels=(): self.sends.append(text) or True)
		send.start()
		self.addCleanup(send.stop)

	def probed(self, product, version, extra='', number=443, method='probed'):
		port = Port.objects.create(number=number, product=product, version=version, service_extra=extra, extra={'method': method})
		self.ip.ports.add(port)
		return port

	def entry(self, cve_id, aff, **flags):
		flags.setdefault('kev', True)
		flags.setdefault('cvss', 5.0)
		return CVEEntry.objects.create(cve_id=cve_id, published_at=timezone.now(), affected=aff, **flags)

	def parity(self):
		"""{pk: (Python rank, database rank)} of every match."""
		sql = dict(CVEMatch.objects.annotate(h=threat.match_heat_rank_expr()).values_list('pk', 'h'))
		return {m.pk: (HEAT_RANK[threat.match_heat(m)], sql[m.pk]) for m in CVEMatch.objects.select_related('cve_entry', 'triage')}

	def only_match(self, **filters):
		return CVEMatch.objects.select_related('cve_entry', 'triage').get(**filters)

	def rescan(self):
		"""The next scan of the same host: hosts are stored once per scan, so a new host row with the same name."""
		engine = EngineType.objects.first()
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		sub = Subdomain.objects.create(name=self.sub.name, target_domain=self.domain, scan_history=scan)
		sub.ip_addresses.add(self.ip)
		return scan, sub


class BannerProofTests(Base):
	"""Item 2: a probed banner of a distribution-packaged or OS-serviced product is no proof (smoke, not fire)."""

	PACKAGED = [
		('OpenSSH', '7.4', 'protocol 2.0', affected('OpenSSH', '1.0', '7.8', 'openbsd')),  # RHEL/CentOS 7: no distro marker
		('Apache httpd', '2.4.51', '(Linux/SUSE)', affected('HTTP Server', '2.4.0', '2.4.58', 'apache')),
		('Apache httpd', '2.4.57', '() OpenSSL/1.0.2k-fips', affected('HTTP Server', '2.4.0', '2.4.58', 'apache')),  # Amazon Linux
		('nginx', '1.20.1', '', affected('nginx', '1.0.0', '1.21.0', 'f5')),  # nginx on RHEL prints no distro
		('Microsoft IIS httpd', '10.0', '', affected('Internet Information Services', '7.0', '10.1', 'microsoft')),  # Windows Update
	]

	def test_a_probed_banner_of_a_distribution_packaged_or_os_serviced_product_is_smoke(self):
		for i, (product, version, extra, aff) in enumerate(self.PACKAGED):
			with self.subTest(product=product, extra=extra):
				CVEMatch.objects.all().delete()
				CVEEntry.objects.all().delete()
				self.ip.ports.clear()
				self.entry(f'CVE-2099-610{i}', aff, kev=False, exploit_db=True)
				self.probed(product, version, extra, number=8000 + i)
				self.correlate()
				m = self.only_match()
				self.assertEqual(m.evidence.get('method'), 'probed')
				self.assertFalse(match_policy.version_proven(m))
				self.assertEqual(threat.match_heat(m), SMOKE)
				self.assertEqual(self.parity()[m.pk], (HEAT_RANK[SMOKE], HEAT_RANK[SMOKE]))

	def test_a_probed_banner_of_a_vendor_built_product_is_fire(self):
		self.entry('CVE-2099-6110', JENKINS)
		self.probed('Jenkins', '2.440')
		self.correlate()
		m = self.only_match()
		self.assertTrue(match_policy.version_proven(m))
		self.assertEqual(threat.match_heat(m), FIRE)
		self.assertEqual(threat.heat_reason(m), 'on the KEV; version proven: read from the service banner by nmap')
		self.assertEqual(self.parity()[m.pk], (HEAT_RANK[FIRE], HEAT_RANK[FIRE]))

	def test_the_same_vendor_banner_from_the_port_table_is_smoke(self):
		self.entry('CVE-2099-6111', JENKINS)
		self.probed('Jenkins', '2.440', method='table')
		self.correlate()
		m = self.only_match()
		self.assertEqual(threat.match_heat(m), SMOKE)
		self.assertEqual(self.parity()[m.pk], (HEAT_RANK[SMOKE], HEAT_RANK[SMOKE]))

	def test_a_banner_row_written_before_the_packaging_was_recorded_is_no_proof(self):
		cve = self.entry('CVE-2099-6112', JENKINS)
		m = self.match_for(cve, source='port', product='jenkins', version='2.440', in_range=True,
						   evidence={'source': 'port', 'method': 'probed'}, ai_verdict='uncertain')
		self.assertEqual(self.parity()[m.pk], (HEAT_RANK[SMOKE], HEAT_RANK[SMOKE]))

	def test_the_product_lists(self):
		for name in ('OpenSSH', 'Apache httpd', 'nginx', 'MySQL', 'PHP', 'Exim smtpd', 'ISC BIND', 'Dovecot imapd', 'OpenSSL', 'Postfix smtpd',
					 'PostgreSQL DB', 'Samba smbd', 'ProFTPD', 'vsftpd', 'Microsoft IIS httpd', 'Microsoft HTTPAPI httpd'):
			self.assertTrue(match_policy.distro_packaged(name), name)
		for name in ('Jenkins', 'FortiGate httpd', 'Citrix NetScaler', 'Ivanti Connect Secure', 'Atlassian Confluence', ''):
			self.assertFalse(match_policy.distro_packaged(name), name)


class JsonParityTests(Base):
	"""Item 6: JSONB orders true, arrays and objects above numbers; the database form reads only a number as a confidence."""

	def test_odd_version_confidence_values_agree(self):
		entry = self.entry('CVE-2099-6201', [])
		banner = {'source': 'tech', 'version_source': 'body', 'copy_state': 'effective'}
		odd = {'true': True, 'list': [1], 'object': {'x': 1}, 'string': '0.9', 'null': None, 'one': 1, 'high': 0.9}
		rows = {}
		for i, (name, value) in enumerate(odd.items()):
			m = CVEMatch.objects.create(cve_entry=entry, subdomain=self.sub, matched_product=f'p{i}', matched_version='1', version_in_range=True,
										evidence={**banner, 'version_confidence': value}, ai_verdict='uncertain')
			rows[m.pk] = name
		got = {rows[pk]: pair for pk, pair in self.parity().items()}
		for name, (python, sql) in got.items():
			self.assertEqual(python, sql, name)
		for name in ('true', 'list', 'object', 'string', 'null'):
			self.assertEqual(got[name][0], HEAT_RANK[SMOKE], name)
		self.assertEqual((got['one'][0], got['high'][0]), (HEAT_RANK[FIRE], HEAT_RANK[FIRE]))


class RescanPagingTests(Base):
	"""Item 3: a finding is paged as fire once, not once per scan; the policy switch pages nothing."""

	def test_a_rescan_does_not_page_the_same_match_again(self):
		self.entry('CVE-2099-6301', JENKINS)
		self.probed('Jenkins', '2.440')
		self.correlate()
		self.assertTrue(notify.fire_matches(self.scan.start_scan_date, self.scan))
		self.assertEqual(len(self.sends), 1)
		scan2, sub2 = self.rescan()
		self.correlate()
		fresh = CVEMatch.objects.get(subdomain=sub2)
		self.assertIsNotNone(fresh.fire_notified_at)  # carried from the copy on the earlier scan
		self.assertFalse(notify.fire_matches(scan2.start_scan_date, scan2))
		self.assertEqual(len(self.sends), 1)

	def test_a_finding_that_turns_fire_on_a_rescan_is_paged_once(self):
		self.entry('CVE-2099-6302', JENKINS)
		port = self.probed('Jenkins', '2.440', method='table')
		self.correlate()
		notify.fire_matches(self.scan.start_scan_date, self.scan)
		self.assertEqual(self.sends, [])  # smoke
		port.extra = {'method': 'probed'}
		port.save()
		scan2, sub2 = self.rescan()
		self.correlate()
		self.assertTrue(notify.fire_matches(scan2.start_scan_date, scan2))
		self.assertEqual(len(self.sends), 1)
		self.assertIn('1 new fire-tier CVE match on 1 host', self.sends[0])

	def test_the_baseline_marks_what_is_fire_now_once_and_again_when_the_policy_changes(self):
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		fire_cve, smoke_cve = self.entry('CVE-2099-6303', []), self.entry('CVE-2099-6304', [])
		fire = self.match_for(fire_cve, version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		smoke = self.match_for(smoke_cve, version='1', in_range=True, ai_verdict='uncertain')
		self.assertEqual(notify.baseline_heat_policy(), 1)
		self.assertIsNotNone(CVEMatch.objects.get(pk=fire.pk).fire_notified_at)
		self.assertIsNone(CVEMatch.objects.get(pk=smoke.pk).fire_notified_at)  # smoke: still pageable when proof arrives
		self.assertEqual(notify.baseline_heat_policy(), 0)  # once per policy
		self.assertEqual(self.sends, [])
		legacy_fire = self.match_for(self.entry('CVE-2099-6305', [], kev=False, cvss=9.8), version='1', in_range=True,
									 distro_status='vulnerable', ai_verdict='uncertain')
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.baseline_heat_policy(), 1)  # the switch to legacy: what legacy rates fire is baselined, not paged
		self.assertIsNotNone(CVEMatch.objects.get(pk=legacy_fire.pk).fire_notified_at)
		self.assertEqual(self.sends, [])

	def test_the_migration_and_the_workers_run_the_baseline(self):
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		m = self.match_for(self.entry('CVE-2099-6306', []), version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		migration = importlib.import_module('cveFeed.migrations.0137_heat_policy_baseline')
		migration.baseline(apps, None)
		self.assertIsNotNone(CVEMatch.objects.get(pk=m.pk).fire_notified_at)
		from cveFeed import tasks
		from reNgine import celery
		with mock.patch('cveFeed.notify.baseline_heat_policy') as baseline:
			celery.baseline_heat_pages()
			tasks.report_resources()
		self.assertEqual(baseline.call_count, 2)

	def test_the_first_scan_after_the_upgrade_pages_no_historic_match(self):
		self.entry('CVE-2099-6307', JENKINS)
		self.probed('Jenkins', '2.440')
		self.correlate()
		# the row as the code before the policy left it: no packaging recorded, never paged
		old = CVEMatch.objects.get()
		old.evidence = {k: v for k, v in old.evidence.items() if k != 'vendor_banner'}
		old.fire_notified_at = None
		old.save()
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		notify.baseline_heat_policy()  # the upgrade (migration 0137): the old row reads smoke, so it is not marked
		self.assertIsNone(CVEMatch.objects.get(pk=old.pk).fire_notified_at)
		scan2, sub2 = self.rescan()
		self.correlate()
		self.assertEqual(threat.match_heat(self.only_match(subdomain=sub2)), FIRE)
		self.assertFalse(notify.fire_matches(scan2.start_scan_date, scan2))
		self.assertEqual(self.sends, [])


class CorrelationProofTests(Base):
	"""Item 4: proof that arrives through correlation rescored the host and pages once; a provenance backfill pages nothing."""

	def setUp(self):
		super().setUp()
		self.rescored = []
		patcher = mock.patch('cveFeed.scoring._rescore_name_pairs', side_effect=lambda pairs, seen=None: self.rescored.extend(n for n, _p in pairs))
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_proof_from_a_later_probe_pages_once_and_rescores(self):
		self.entry('CVE-2099-6401', JENKINS)
		port = self.probed('Jenkins', '2.440', method='table')
		self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), SMOKE)
		self.rescored.clear()
		port.extra = {'method': 'probed'}
		port.save()
		with self.captureOnCommitCallbacks(execute=True):  # the page follows the committed write
			self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), FIRE)
		self.assertIn(self.sub.name, self.rescored)
		self.assertEqual(len(self.sends), 1)
		self.assertIn('confirmed, now fire-tier', self.sends[0])
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(len(self.sends), 1)

	def test_recording_the_packaging_on_an_old_row_pages_nothing_but_rescores(self):
		self.entry('CVE-2099-6402', JENKINS)
		self.probed('Jenkins', '2.440')
		self.correlate()
		old = CVEMatch.objects.get()
		old.evidence = {k: v for k, v in old.evidence.items() if k != 'vendor_banner'}
		old.fire_notified_at = None
		old.save()
		self.rescored.clear()
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		m = self.only_match()
		self.assertEqual(threat.match_heat(m), FIRE)
		self.assertIn(self.sub.name, self.rescored)
		self.assertEqual(self.sends, [])
		self.assertIsNotNone(m.fire_notified_at)  # baselined: a later copy does not page it either

	def test_proof_on_an_ice_cve_or_under_legacy_pages_nothing(self):
		self.entry('CVE-2099-6403', JENKINS, kev=False, cvss=9.8)
		port = self.probed('Jenkins', '2.440', method='table')
		self.correlate()
		port.extra = {'method': 'probed'}
		port.save()
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), ICE)
		self.assertEqual(self.sends, [])
		CVEEntry.objects.update(kev=True)
		port.extra = {'method': 'table'}
		port.save()
		self.correlate()
		port.extra = {'method': 'probed'}
		port.save()
		with mock.patch.dict(os.environ, LEGACY), self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(self.sends, [])


class FeedTurnsHotTests(Base):
	"""Item 5: a CVE that joins the KEV or gains an exploit after its match exists pages its proven matches once."""

	def setUp(self):
		super().setUp()
		self.rescored = []
		patcher = mock.patch('cveFeed.scoring._rescore_name_pairs', side_effect=lambda pairs, seen=None: self.rescored.extend(n for n, _p in pairs))
		patcher.start()
		self.addCleanup(patcher.stop)

	def matches(self):
		proven_cve = self.entry('CVE-2099-6501', JENKINS, kev=False, exploit_db=False, cvss=9.8)
		smoke_cve = self.entry('CVE-2099-6502', affected('confluence', '1.0', '9.0'), kev=False, exploit_db=False)
		self.probed('Jenkins', '2.440')
		self.probed('Confluence', '8.5', number=8090, method='table')
		self.correlate()
		self.assertEqual({threat.match_heat(m) for m in CVEMatch.objects.select_related('cve_entry')}, {ICE})
		return proven_cve, smoke_cve

	def test_reconcile_reports_the_cves_that_turned_hot(self):
		proven_cve, smoke_cve = self.matches()
		turned = []
		intel.reconcile({'cisa_kev': {proven_cve.cve_id: {'dateAdded': '2026-11-01'}},
						 'exploit_db': {smoke_cve.cve_id: [{'id': '1'}]}}, turned_hot=turned)
		self.assertEqual(sorted(turned), sorted([proven_cve.pk, smoke_cve.pk]))
		intel.reconcile({'cisa_kev': {proven_cve.cve_id: {'dateAdded': '2026-11-01'}}}, turned_hot=turned)
		self.assertEqual(len(turned), 2)  # already hot: not again

	def test_the_threat_intel_task_pages_the_proven_match_once_and_rescores(self):
		proven_cve, smoke_cve = self.matches()
		from cveFeed import tasks

		def run():
			CVEEntry.objects.filter(pk__in=[proven_cve.pk, smoke_cve.pk]).update(kev=True)
			return {'imported': [], 'signals_changed': [proven_cve.pk, smoke_cve.pk], 'signals_turned_hot': [proven_cve.pk, smoke_cve.pk],
					'errors': {}, 'sources': {}}
		with mock.patch('cveFeed.intel.run', side_effect=run), mock.patch('cveFeed.activity.log'):
			tasks.sync_threat_intel()
		self.assertEqual(len(self.sends), 1)
		self.assertIn('CVE-2099-6501', self.sends[0])
		self.assertNotIn('CVE-2099-6502', self.sends[0])  # smoke: not paged
		self.assertIn(self.sub.name, self.rescored)
		self.assertEqual({threat.match_heat(m) for m in CVEMatch.objects.select_related('cve_entry')}, {FIRE, SMOKE})
		with mock.patch('cveFeed.intel.run', side_effect=run), mock.patch('cveFeed.activity.log'):
			tasks.sync_threat_intel()
		self.assertEqual(len(self.sends), 1)

	def test_a_feed_refresh_that_adds_an_exploit_pages_and_rescores(self):
		import datetime

		from cveFeed import tasks
		proven_cve, _smoke = self.matches()
		CVEEntry.objects.filter(pk=proven_cve.pk).update(synced_at=timezone.now() - datetime.timedelta(days=2))
		client = mock.Mock()
		client.iter_entries.return_value = iter([])
		client.get_entry.return_value = {'id': proven_cve.cve_id, 'affected': JENKINS, 'severity': {'cvss': 9.8},
										 'exploitation': {'kev': False, 'exploitDb': True}}
		self.rescored.clear()
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.correlate_refreshed_cves.delay'):
			tasks.sync_cve_now_feed(refresh_max=1)
		self.assertTrue(CVEEntry.objects.get(pk=proven_cve.pk).exploit_db)
		self.assertEqual(len(self.sends), 1)
		self.assertIn('CVE-2099-6501', self.sends[0])
		self.assertIn(self.sub.name, self.rescored)

	def test_the_policy_switch_itself_pages_nothing(self):
		proven_cve, _smoke = self.matches()
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.cves_turned_hot([proven_cve.pk]), False)  # legacy: unchanged, no page from this path
		self.assertEqual(self.sends, [])


class ScannerFindingHeatTests(Base):
	"""Spec: a scanner finding that names CVEs follows the CVE rule under the KEV policy; any other finding keeps its severity heat."""

	def finding(self, name, severity, source, cves=(), tags=()):
		v = Vulnerability.objects.create(name=name, severity=severity, source=source, subdomain=self.sub, target_domain=self.domain,
										 scan_history=self.scan, open_status=True)
		for cve in cves:
			v.cve_ids.add(CveId.objects.create(name=cve))
		for tag in tags:
			v.tags.add(VulnerabilityTags.objects.create(name=tag))
		return v

	def heats(self, capped=True):
		"""{finding id: (Python heat, database heat)}"""
		sub = Subdomain.objects.prefetch_related('cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set__triage',
												 'vulnerability_set__cve_ids', 'vulnerability_set__tags').get(pk=self.sub.pk)
		python = {r['id']: r['temp'] for r in services._heat_reasons(sub, capped=capped) if r['kind'] == 'finding'}
		names = {rank: heat for heat, rank in HEAT_RANK.items()}
		sql = dict(Vulnerability.objects.annotate(h=threat.finding_heat_rank_expr(capped=capped)).values_list('pk', 'h'))
		return {pk: (python.get(pk), names.get(sql[pk])) for pk in sql}

	def test_the_cve_rule_for_scanner_findings(self):
		self.entry('CVE-2099-6601', [], kev=False, exploit_db=False, cvss=9.8)
		self.entry('CVE-2099-6602', [], kev=True)
		self.entry('CVE-2099-6603', [], kev=False, exploit_db=True)
		cold = self.finding('CVE-2099-6601: template', 4, 'nuclei-cve', ['CVE-2099-6601'])
		hot = self.finding('CVE-2099-6602: template', 2, 'nuclei-cve', ['CVE-2099-6602'])
		unconfirmed = self.finding('OpenVAS: CVE-2099-6603', 4, 'openvas', ['CVE-2099-6603'], ['openvas', 'qod-unconfirmed'])
		confirmed = self.finding('OpenVAS: CVE-2099-6603 active', 3, 'openvas', ['CVE-2099-6603'], ['openvas', 'qod-confirmed'])
		wpscan = self.finding('Plugin x', 3, 'wpscan', ['CVE-2099-6602'])
		unknown = self.finding('CVE-2099-6699: template', 4, 'nuclei', ['CVE-2099-6699'])  # a CVE this instance does not store
		exposure = self.finding('Exposed .git', 3, 'nuclei')  # names no CVE: severity heat
		info = self.finding('CVE-2099-6602 detected', 0, 'nuclei', ['CVE-2099-6602'])  # informational: no heat
		heats = self.heats()
		self.assertEqual(heats[cold.pk], (ICE, ICE))
		self.assertEqual(heats[hot.pk], (FIRE, FIRE))
		self.assertEqual(heats[unconfirmed.pk], (SMOKE, SMOKE))
		self.assertEqual(heats[confirmed.pk], (FIRE, FIRE))
		self.assertEqual(heats[wpscan.pk], (SMOKE, SMOKE))
		self.assertEqual(heats[unknown.pk], (ICE, ICE))
		self.assertEqual(heats[exposure.pk], (FIRE, FIRE))
		self.assertEqual(heats[info.pk], (None, None))
		uncapped = self.heats(capped=False)
		self.assertEqual((uncapped[unconfirmed.pk], uncapped[wpscan.pk], uncapped[cold.pk]), ((FIRE, FIRE), (FIRE, FIRE), (ICE, ICE)))
		# a validation hit confirms an unconfirmed finding
		Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='vulnerability', vulnerability=unconfirmed,
							  classification='needs_validation', status='triaged', validation_status='hit')
		self.assertEqual(self.heats()[unconfirmed.pk], (FIRE, FIRE))

	def test_a_template_confirmed_cve_that_is_not_hot_leaves_the_host_ice(self):
		cve = self.entry('CVE-2099-6611', [], kev=False, exploit_db=False, cvss=9.8)
		self.match_for(cve, version='1.20.1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		self.finding('CVE-2099-6611: template', 4, 'nuclei-cve', ['CVE-2099-6611'])
		self.assertEqual(services._host_heat(self.sub), ICE)
		node = {n['label']: n for n in graph_payload(self.domain.id)['nodes'] if n['kind'] == 'subdomain'}[self.sub.name]
		self.assertEqual(node['heat'], ICE)
		facets = services._finding_sources(self.project, {})
		self.assertEqual(set(facets['scanner'].values_list('heat_rank', flat=True)), {HEAT_RANK[ICE]})
		CVEEntry.objects.filter(pk=cve.pk).update(kev=True)
		self.assertEqual(services._host_heat(self.sub), FIRE)
		node = {n['label']: n for n in graph_payload(self.domain.id)['nodes'] if n['kind'] == 'subdomain'}[self.sub.name]
		self.assertEqual(node['heat'], FIRE)

	def test_legacy_keeps_the_severity_heat(self):
		self.entry('CVE-2099-6621', [], kev=False, exploit_db=False, cvss=9.8)
		v = self.finding('CVE-2099-6621: template', 4, 'nuclei-cve', ['CVE-2099-6621'])
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(self.heats()[v.pk], (FIRE, FIRE))


class AutoFireWordingTests(Base):
	"""Cosmetic: auto-fire tests a CVE by its signals (attention tier); the run and its log say so, not "ICE"."""

	def test_an_attention_only_cve_is_not_logged_as_ice(self):
		cve = self.entry('CVE-2099-6701', [], kev=False, exploit_db=False, cvss=9.8)
		with mock.patch('cveFeed.activity.log', return_value=None) as log, mock.patch('cveFeed.activity.settle'):
			autofire.fire_for_cve(cve, test_dispatcher=None)
		self.assertEqual(AutoFireRun.objects.get(cve_entry=cve).tier, FIRE)  # what auto-fire acted on: its signals
		first = log.call_args_list[0].args[1]
		self.assertNotIn('is ICE', first)
		self.assertIn('ice under the heat policy', first)
