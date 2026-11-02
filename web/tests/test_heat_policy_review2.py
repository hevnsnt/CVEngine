"""Second review of the KEV heat policy (PR #386 at 1b38a62): the reviewer's probes (rv386b), as regression tests.

- A page, or a quiet mark, is about one heat rule: what was marked under legacy never holds back a page that is new under the KEV rule, and
  the other way round (round trips both ways).
- A policy switch during a scan leaves that scan's new matches to be paged at its end.
- The upgrade guard is quiet only when the old row was already proven but for the field the update added; new proof pages.
- A probed banner proves a version only for a product on the vendor allow-list (fail safe: an unknown product is no proof).
- Real nuclei output carries CVE ids (``cve-id``), so a nuclei finding follows the CVE rule.
- The database form of a finding's heat trims CVE names and skips empty ones, as Python does.
- A CVE that turns hot pages every proven match, however many, and the forced cve.now backfill pages too.
- A scanner finding's validation lane and its share of the host score follow its heat.
"""
import importlib
import os
from datetime import timedelta
from unittest import mock

from django.apps import apps
from django.utils import timezone

from agentapi import services
from cveFeed import hot_validation, match_policy, notify, scoring, threat, triage
from cveFeed.models import BackgroundCursor, CVEEntry, CVEMatch, Triage
from cveFeed.threat import FIRE, HEAT_RANK, ICE, SMOKE
from reNgine.tasks import parse_nuclei_result, save_vulnerability
from startScan.models import CveId, ScanHistory, Subdomain, Vulnerability
from tests.test_heat_policy import LEGACY
from tests.test_heat_policy_review import JENKINS, Base
from tests.test_match_policy import affected

LEGACY_CAP_FIRE = {**LEGACY, threat.VERSION_ONLY_MAX_HEAT_ENV: 'fire'}


def old(match_id, minutes=24 * 60):
	"""Make a match older than the baseline's grace: it existed well before the switch."""
	CVEMatch.objects.filter(pk=match_id).update(created_at=timezone.now() - timedelta(minutes=minutes))


class Switching(Base):
	def setUp(self):
		super().setUp()
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		notify.baseline_heat_policy()  # the KEV rule in force (the update)


class PerRuleAnnouncementTests(Switching):
	"""Item 1: the announced state is per heat rule."""

	def test_kev_legacy_kev_round_trip_still_pages_when_the_cve_joins_the_kev(self):
		cve = self.entry('CVE-2099-7001', [], kev=False, exploit_db=False, cvss=9.8)
		m = self.match_for(cve, version='1', in_range=True, distro_status='vulnerable', ai_verdict='uncertain')
		old(m.pk)
		self.assertEqual(threat.match_heat(self.only_match()), ICE)
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.baseline_heat_policy(), 1)  # fire under legacy: marked for legacy, quietly
		notify.baseline_heat_policy()  # back to the KEV rule: ice there, nothing to mark
		CVEEntry.objects.filter(pk=cve.pk).update(kev=True)
		self.assertTrue(notify.cves_turned_hot([cve.pk]))
		self.assertEqual(len(self.sends), 1)
		self.assertIn('CVE-2099-7001', self.sends[0])

	def test_without_a_round_trip_the_same_page_goes_out(self):
		cve = self.entry('CVE-2099-7002', [], kev=False, exploit_db=False, cvss=9.8)
		self.match_for(cve, version='1', in_range=True, distro_status='vulnerable', ai_verdict='uncertain')
		CVEEntry.objects.filter(pk=cve.pk).update(kev=True)
		self.assertTrue(notify.cves_turned_hot([cve.pk]))
		self.assertEqual(len(self.sends), 1)

	def test_a_mark_under_the_legacy_cap_does_not_hold_back_proof_under_kev(self):
		self.entry('CVE-2099-7003', JENKINS)
		port = self.probed('Jenkins', '2.440', method='table')  # a KEV match whose version is only guessed: smoke under the KEV rule
		self.correlate()
		old(CVEMatch.objects.get().pk)
		with mock.patch.dict(os.environ, LEGACY_CAP_FIRE):
			self.assertEqual(notify.baseline_heat_policy(), 1)  # the legacy cap set to fire rates it fire: marked for that rule
		notify.baseline_heat_policy()
		port.extra = {'method': 'probed'}
		port.save()
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), FIRE)
		self.assertEqual(len(self.sends), 1)
		self.assertIn('confirmed, now fire-tier', self.sends[0])

	def test_legacy_kev_legacy_round_trip_pages_what_is_new_under_legacy(self):
		with mock.patch.dict(os.environ, LEGACY):
			notify.baseline_heat_policy()  # legacy in force
		cve = self.entry('CVE-2099-7004', [], kev=True, cvss=5.0)
		banner = {'source': 'tech', 'version_source': 'body', 'version_confidence': 0.9, 'copy_state': 'effective'}
		m = self.match_for(cve, version='1', in_range=True, evidence=banner, ai_verdict='uncertain')
		old(m.pk)
		notify.baseline_heat_policy()  # to the KEV rule: the library's own file proves it, fire there: marked for kev
		self.assertIsNotNone(CVEMatch.objects.get(pk=m.pk).fire_notified_at)
		with mock.patch.dict(os.environ, LEGACY):
			notify.baseline_heat_policy()  # back to legacy: version-only, smoke there: not marked for legacy
			CVEMatch.objects.filter(pk=m.pk).update(evidence={**banner, 'runzero': True})  # hard evidence arrives under legacy
			self.assertTrue(notify.fire_confirmed([m.pk]))
		self.assertEqual(len(self.sends), 1)

	def test_a_match_paged_once_is_not_paged_again_after_a_round_trip(self):
		self.entry('CVE-2099-7005', JENKINS, cvss=9.8)
		self.probed('Jenkins', '2.440')
		self.correlate()
		CVEMatch.objects.update(template_result='vulnerable')  # fire under both rules
		self.assertTrue(notify.fire_matches(self.scan.start_scan_date, self.scan))
		old(CVEMatch.objects.get().pk)
		with mock.patch.dict(os.environ, LEGACY):
			notify.baseline_heat_policy()
			self.assertFalse(notify.fire_matches(self.scan.start_scan_date - timedelta(days=2), self.scan))
		notify.baseline_heat_policy()
		self.assertFalse(notify.fire_matches(self.scan.start_scan_date - timedelta(days=2), self.scan))
		self.assertEqual(len(self.sends), 1)


class InFlightTests(Switching):
	"""Item 2: the baseline leaves matches that are still waiting for their page."""

	def test_a_switch_during_a_scan_leaves_its_new_fire_matches_to_the_scan_end(self):
		cve = self.entry('CVE-2099-7501', [], kev=True, cvss=9.8)
		m = self.match_for(cve, version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		CVEMatch.objects.filter(pk=m.pk).update(scan_history=self.scan)
		old(m.pk, minutes=24 * 60)  # a long scan: the match is old, its scan is not finished
		ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=1)
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.baseline_heat_policy(), 0)
			ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=2)
			self.assertTrue(notify.fire_matches(self.scan.start_scan_date - timedelta(days=2), self.scan))
		self.assertEqual(len(self.sends), 1)

	def test_a_match_made_just_before_the_switch_is_left_for_its_page(self):
		cve = self.entry('CVE-2099-7502', [], kev=True, cvss=9.8)
		since = timezone.now() - timedelta(minutes=1)
		m = self.match_for(cve, version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')  # the feed sync made it
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.baseline_heat_policy(), 0)
			self.assertTrue(notify.fire_matches(since, cve_ids=[cve.pk]))
		self.assertIsNotNone(CVEMatch.objects.get(pk=m.pk).fire_notified_at)

	def test_matches_from_before_the_switch_are_still_baselined(self):
		cve = self.entry('CVE-2099-7503', [], kev=True, cvss=9.8)
		m = self.match_for(cve, version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		old(m.pk)
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(notify.baseline_heat_policy(), 1)
		self.assertEqual(self.sends, [])


class UpgradeGuardTests(Base):
	"""Item 3: quiet only when the old row was already proven except for the field the update records."""

	def _old_row(self, method):
		self.entry('CVE-2099-7101', JENKINS)
		port = self.probed('Jenkins', '2.440', method=method)
		self.correlate()
		row = CVEMatch.objects.get()
		row.evidence = {k: v for k, v in row.evidence.items() if k != 'vendor_banner'}  # written before the update
		row.fire_notified_at, row.fire_notified_rule = None, ''
		row.save()
		old(row.pk)
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		notify.baseline_heat_policy()  # migration 0137
		return port

	def test_new_probe_proof_on_the_first_rescan_after_the_update_pages(self):
		port = self._old_row('table')  # a port-table guess: smoke before and after the update
		port.extra = {'method': 'probed'}  # nmap now really probes the service: new proof
		port.save()
		scan2, sub2 = self.rescan()
		self.correlate()
		self.assertEqual(threat.match_heat(self.only_match(subdomain=sub2)), FIRE)
		self.assertTrue(notify.fire_matches(scan2.start_scan_date, scan2))
		self.assertEqual(len(self.sends), 1)

	def test_new_probe_proof_on_recorrelation_after_the_update_pages(self):
		port = self._old_row('table')
		port.extra = {'method': 'probed'}
		port.save()
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), FIRE)
		self.assertEqual(len(self.sends), 1)
		self.assertIn('confirmed, now fire-tier', self.sends[0])

	def test_an_old_row_that_was_already_probed_stays_quiet(self):
		self._old_row('probed')
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(threat.match_heat(self.only_match()), FIRE)
		scan2, _sub2 = self.rescan()
		self.correlate()
		self.assertFalse(notify.fire_matches(scan2.start_scan_date, scan2))
		self.assertEqual(self.sends, [])

	def test_a_version_that_changed_is_new_proof(self):
		port = self._old_row('probed')
		port.version = '2.441'
		port.save()
		with self.captureOnCommitCallbacks(execute=True):
			self.correlate()
		self.assertEqual(len(self.sends), 1)


class VendorBannerTests(Base):
	"""Item 5: only a product on the vendor allow-list proves its version by its banner; anything else (a distribution-packaged or
	OS-serviced daemon, or a product cvENGINE does not know) is no proof, so it stays smoke."""

	VENDOR = ('Apache ActiveMQ', 'Apache Solr', 'Apache Spark', 'ApacheDS LDAP', 'Jenkins', 'Jenkins httpd', 'FortiGate httpd', 'Citrix NetScaler',
			  'Ivanti Connect Secure', 'Pulse Secure', 'Atlassian Confluence', 'Oracle WebLogic admin httpd', 'VMware vCenter', 'GitLab',
			  'Zimbra', 'Progress MOVEit', 'Openfire', 'Apache OFBiz')
	NOT_PROOF = ('Apache httpd', 'Apache Tomcat', 'Apache Mina sshd', 'Apache Traffic Server', 'PhpStorm IDE', 'PowerDNS Recursor',
				 'Asterisk PBX', 'MIT Kerberos', 'Heimdal Kerberos', 'Erlang Port Mapper Daemon', 'libssh', 'Microsoft ESMTP', 'Microsoft ftpd',
				 'Microsoft IIS httpd', 'OpenSSH', 'nginx', 'OpenResty web app server', 'Exim smtpd', 'Postfix smtpd', 'Pure-FTPd',
				 'Linux telnetd', 'GNU Gatekeeper', 'Werkzeug httpd', 'Python SimpleHTTPServer', 'Jetty', 'Some Unknown Daemon', '')

	def test_the_allow_list(self):
		for name in self.VENDOR:
			self.assertTrue(match_policy.vendor_built(name), name)
		for name in self.NOT_PROOF:
			self.assertFalse(match_policy.vendor_built(name), name)

	def test_a_probed_activemq_banner_proves_cve_2023_46604(self):
		self.entry('CVE-2023-46604', affected('activemq', '5.0.0', '5.15.16', 'apache'), kev=True, cvss=10.0)
		self.probed('Apache ActiveMQ', '5.15.15', number=61616)
		self.correlate()
		m = self.only_match()
		self.assertTrue(m.evidence['vendor_banner'])
		self.assertEqual(threat.match_heat(m), FIRE)
		self.assertEqual(self.parity()[m.pk], (HEAT_RANK[FIRE], HEAT_RANK[FIRE]))

	def test_a_probed_powerdns_banner_is_smoke(self):
		self.entry('CVE-2099-7601', affected('PowerDNS Recursor', '4.0', '4.9'), kev=True)
		self.probed('PowerDNS Recursor', '4.8.1', number=53)
		self.correlate()
		m = self.only_match()
		self.assertFalse(m.evidence['vendor_banner'])
		self.assertEqual(self.parity()[m.pk], (HEAT_RANK[SMOKE], HEAT_RANK[SMOKE]))


class FindingParityTests(Base):
	"""Item 6: odd CVE names agree in Python (host card) and SQL (lists, reports, graph)."""

	def test_odd_cve_names(self):
		self.entry('CVE-2099-7401', [], kev=True)
		self.entry('CVE-2099-7402', [], kev=False, exploit_db=False, cvss=9.8)
		cases = {'lower hot': (['cve-2099-7401'], FIRE), 'space hot': ([' CVE-2099-7401 '], FIRE), 'newline hot': (['CVE-2099-7401\n'], FIRE),
				 'empty': ([''], FIRE), 'blank': (['  '], FIRE), 'empty+hot': (['', 'CVE-2099-7401'], FIRE), 'space cold': (['CVE-2099-7402\n'], ICE)}
		ids = {}
		for label, (names, _want) in cases.items():
			v = Vulnerability.objects.create(name=label, severity=4, source='nuclei', subdomain=self.sub, target_domain=self.domain,
											 scan_history=self.scan, open_status=True)
			for n in names:
				v.cve_ids.add(CveId.objects.create(name=n))
			ids[v.pk] = label
		sub = Subdomain.objects.prefetch_related('vulnerability_set__cve_ids', 'vulnerability_set__tags', 'vulnerability_set__triage').get(pk=self.sub.pk)
		py = {r['id']: r['temp'] for r in services._heat_reasons(sub) if r['kind'] == 'finding'}
		names = {rank: heat for heat, rank in HEAT_RANK.items()}
		sql = {pk: names.get(h) for pk, h in Vulnerability.objects.annotate(h=threat.finding_heat_rank_expr()).values_list('pk', 'h')}
		for pk, label in ids.items():
			self.assertEqual((py[pk], sql[pk]), (cases[label][1], cases[label][1]), label)


class TurnedHotTests(Base):
	"""Item 7 and (e): every proven match is paged, beyond the per-statement cap; legacy sends nothing; the forced backfill pages too."""

	def matches(self, n=3):
		cve = self.entry('CVE-2099-7201', [], kev=False, exploit_db=False, cvss=9.8)
		for i in range(n):
			self.match_for(cve, product=f'p{i}', version='1', in_range=True, distro_status='vulnerable', ai_verdict='uncertain')
		CVEEntry.objects.filter(pk=cve.pk).update(kev=True)
		return cve

	def test_more_than_the_cap_are_all_paged_in_one_message(self):
		cve = self.matches()
		with mock.patch.object(notify, 'MAX_MARK', 2):
			self.assertTrue(notify.cves_turned_hot([cve.pk]))
		self.assertEqual(len(self.sends), 1)
		self.assertIn('3 CVE matches turned fire-tier', self.sends[0])
		self.assertFalse(CVEMatch.objects.filter(fire_notified_at__isnull=True).exists())

	def test_what_one_run_cannot_page_is_paged_by_the_next(self):
		cve = self.matches()
		with mock.patch.object(notify, 'MAX_MARK', 2), mock.patch.object(notify, 'MAX_TURNED_HOT_ROUNDS', 1):
			notify.cves_turned_hot([cve.pk])
			self.assertEqual(CVEMatch.objects.filter(fire_notified_at__isnull=True).count(), 1)
			notify.cves_turned_hot([])  # the next run carries the rest
		self.assertEqual(len(self.sends), 2)
		self.assertFalse(CVEMatch.objects.filter(fire_notified_at__isnull=True).exists())

	def test_legacy_sends_nothing_from_this_path(self):
		cve = self.matches(1)
		self.assertEqual(threat.match_heat(CVEMatch.objects.select_related('cve_entry').get()), FIRE)
		with mock.patch.dict(os.environ, LEGACY):
			self.assertEqual(threat.match_heat(CVEMatch.objects.select_related('cve_entry').get()), FIRE)  # fire there too
			self.assertFalse(notify.cves_turned_hot([cve.pk]))
		self.assertEqual(self.sends, [])
		self.assertTrue(notify.cves_turned_hot([cve.pk]))

	def test_the_forced_backfill_pages_a_cve_that_turned_hot(self):
		from cveFeed import tasks
		cve = self.entry('CVE-2099-7202', JENKINS, kev=False, exploit_db=False, cvss=9.8)
		self.probed('Jenkins', '2.440')
		self.correlate()
		client = mock.Mock()
		client.get_entry.return_value = {'id': cve.cve_id, 'affected': JENKINS, 'severity': {'cvss': 9.8}, 'exploitation': {'kev': True}}
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.auto_fire_new_cves.delay'):
			tasks.backfill_cve_now_feed(ids=[cve.cve_id], pause=0)
		self.assertTrue(CVEEntry.objects.get(pk=cve.pk).kev)
		self.assertEqual(len(self.sends), 1)
		self.assertIn('CVE-2099-7202', self.sends[0])


class NucleiCveTests(Base):
	"""Item 4: nuclei writes ``classification.cve-id``; a finding of a real nuclei line carries its CVE ids and follows the CVE rule."""

	def line(self, cve_id, key='cve-id', value=None):
		return {'host': 'https://www.example.test', 'matched-at': 'https://www.example.test/x', 'template-id': cve_id,
				'template': f'http/cves/2099/{cve_id}.yaml', 'type': 'http',
				'info': {'name': 'Thing RCE', 'severity': 'critical', 'tags': ['cve', 'rce'],
						 'classification': {key: value if value is not None else [cve_id.lower()], 'cwe-id': ['cwe-77'], 'cvss-score': 9.8}}}

	def save(self, line):
		data = parse_nuclei_result(line)
		vuln, _ = save_vulnerability(target_domain=self.domain, scan_history=self.scan, subdomain=self.sub, http_url=line['matched-at'], **data)
		return vuln

	def heat(self):
		sub = Subdomain.objects.prefetch_related('vulnerability_set__cve_ids', 'vulnerability_set__tags', 'vulnerability_set__triage').get(pk=self.sub.pk)
		return services._host_heat(sub)

	def test_the_real_key_and_its_spellings(self):
		for key, value, want in (('cve-id', ['cve-2099-1'], ['CVE-2099-1']), ('cve_id', ['CVE-2099-2'], ['CVE-2099-2']),
								 ('cve-id', 'CVE-2099-3', ['CVE-2099-3']), ('cve-id', 'cve-2099-4, CVE-2099-5', ['CVE-2099-4', 'CVE-2099-5']),
								 ('cve-id', None, [])):
			line = self.line('x', key, value)
			if value is None:
				line['info']['classification'] = {}
			self.assertEqual(parse_nuclei_result(line)['cve_ids'], want, (key, value))
			self.assertEqual(parse_nuclei_result(line)['cwe_ids'], ['CWE-77'] if value is not None else [], (key, value))

	def test_a_non_kev_critical_cve_finding_reads_ice_and_a_kev_one_fire(self):
		self.entry('CVE-2099-7301', [], kev=False, exploit_db=False, cvss=9.8)
		vuln = self.save(self.line('CVE-2099-7301'))
		self.assertEqual(list(vuln.cve_ids.values_list('name', flat=True)), ['CVE-2099-7301'])
		self.assertEqual(self.heat(), ICE)
		CVEEntry.objects.filter(cve_id='CVE-2099-7301').update(kev=True)
		self.assertEqual(self.heat(), FIRE)

	def test_a_sentinel_finding_carries_the_cve_ids_it_reports(self):
		from agentapi import sentinel_broker, sentinel_dispatch
		findings, _dropped = sentinel_broker._clean_findings([{'template_id': 'CVE-2099-7302', 'name': 'x', 'severity': 'critical',
															   'host': 'www.example.test', 'matched_at': 'https://www.example.test/',
															   'cve_ids': ['cve-2099-7302', 'not a cve', 7]}])
		self.assertEqual(findings[0]['cve_ids'], ['CVE-2099-7302'])
		line = sentinel_dispatch._finding_to_nuclei_line(findings[0])
		self.assertEqual(parse_nuclei_result(line)['cve_ids'], ['CVE-2099-7302'])
		self.assertEqual(sentinel_broker._clean_findings([{'template_id': 't', 'severity': 'low'}])[0][0]['cve_ids'], [])


class FindingLaneAndScoreTests(Base):
	"""(b) and (c): a scanner finding that names CVEs takes its validation lane and its share of the host score from its heat."""

	def finding(self, severity, cves=(), source='nuclei'):
		v = Vulnerability.objects.create(name=f'finding {severity}', severity=severity, source=source, subdomain=self.sub, target_domain=self.domain,
										 scan_history=self.scan, open_status=True)
		for cve in cves:
			v.cve_ids.add(CveId.objects.create(name=cve))
		return v

	def test_the_validation_lane_follows_the_finding_heat(self):
		self.entry('CVE-2099-7701', [], kev=False, exploit_db=False, cvss=9.8)
		self.entry('CVE-2099-7702', [], kev=True)
		cold, hot, plain = self.finding(4, ['CVE-2099-7701']), self.finding(2, ['CVE-2099-7702']), self.finding(3)
		triage.track([cold, hot, plain])
		lane = {r.vulnerability_id: hot_validation.tier_for(r) for r in Triage.objects.filter(vulnerability__isnull=False)}
		self.assertEqual((lane[cold.pk], lane[hot.pk], lane[plain.pk]), (None, FIRE, FIRE))
		fire = {r.vulnerability_id for r in hot_validation._candidate_rows(FIRE) if r.vulnerability_id}
		smoke = {r.vulnerability_id for r in hot_validation._candidate_rows(SMOKE) if r.vulnerability_id}
		self.assertEqual(fire, {hot.pk, plain.pk})
		self.assertNotIn(cold.pk, fire | smoke)
		with mock.patch.dict(os.environ, LEGACY):
			lane = {r.vulnerability_id: hot_validation.tier_for(r) for r in Triage.objects.filter(vulnerability__isnull=False)}
			self.assertEqual((lane[cold.pk], lane[hot.pk], lane[plain.pk]), (FIRE, SMOKE, FIRE))

	def test_the_host_score_counts_a_cve_finding_by_its_heat(self):
		self.entry('CVE-2099-7703', [], kev=False, exploit_db=False, cvss=9.8)
		self.finding(4, ['CVE-2099-7703'])
		scoring.rescore_hosts(self.project.id, [self.sub.name])
		detail = Subdomain.objects.get(pk=self.sub.pk).score_detail
		line = [d for d in detail if 'finding' in d['label']]
		self.assertEqual(line[0]['points'], scoring.FINDING_HEAT_POINTS[ICE])  # ice, not 25 for its critical severity
		with mock.patch.dict(os.environ, LEGACY):
			scoring.rescore_hosts(self.project.id, [self.sub.name])
		detail = Subdomain.objects.get(pk=self.sub.pk).score_detail
		self.assertEqual([d for d in detail if 'finding' in d['label']][0]['points'], 25)
		self.assertEqual(scoring.score_host({'findings': [{'severity': 4, 'name': 'x', 'heat': ICE}]})[0], scoring.FINDING_HEAT_POINTS[ICE])
		self.assertLess(scoring.FINDING_HEAT_POINTS[ICE], scoring.CVE_POINTS[SMOKE])  # it no longer outranks a KEV host with a version inferred


class MigrationTests(Base):
	"""(d): migration 0137 is self-contained (it does not call live code) and baselines the KEV rule."""

	def test_the_migration_marks_what_is_fire_under_the_kev_rule_and_tags_old_pages(self):
		BackgroundCursor.objects.filter(lane=notify.BASELINE_LANE).delete()
		fire = self.match_for(self.entry('CVE-2099-7801', []), version='1', in_range=True, template_result='vulnerable', ai_verdict='uncertain')
		smoke = self.match_for(self.entry('CVE-2099-7802', []), version='1', in_range=True, ai_verdict='uncertain')
		paged = self.match_for(self.entry('CVE-2099-7803', [], kev=False, cvss=9.8), version='1', in_range=True, distro_status='vulnerable',
							   ai_verdict='uncertain', fire_notified_at=timezone.now())
		for m in (fire, smoke, paged):
			old(m.pk)
		migration = importlib.import_module('cveFeed.migrations.0137_heat_policy_baseline')
		source = open(migration.__file__).read()
		self.assertNotIn('from cveFeed', source)  # frozen: later code cannot change what it did
		migration.baseline(apps, None)
		rows = {m.pk: (m.fire_notified_at is not None, m.fire_notified_rule) for m in CVEMatch.objects.all()}
		self.assertEqual(rows[fire.pk], (True, 'kev'))
		self.assertEqual(rows[smoke.pk], (False, ''))
		self.assertEqual(rows[paged.pk], (True, 'legacy:smoke'))  # paged under the rule before the update
		self.assertEqual(notify.baseline_heat_policy(), 0)  # the workers find the rule already baselined
