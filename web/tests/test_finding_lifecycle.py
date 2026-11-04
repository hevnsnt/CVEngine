"""1.3.5 finding lifecycle: a fixed version closes a finding (item 23), rescans update instead of filing copies (24), redirect aliases fold
into their target (25), and CVEs fixed by one upgrade are one remediation item (26). Every fixture is synthetic: the shape of the stored
inputs that went wrong, on example.com names and documentation addresses."""
import io
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import closure, finding_lifecycle, hygiene, wpscan_scan
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, FindingComment, HygieneFinding, ProbeObservation, RouteAuth
from dashboard.models import Org, Project, ProjectMembership
from reNgine.tasks import save_vulnerability
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call


class LifecycleBase(TestCase):
	def setUp(self):
		now = timezone.now()
		self.org = Org.objects.create(name='Org', slug='org')
		self.project = Project.objects.create(name='P', slug='p', insert_date=now, org=self.org)
		self.other_project = Project.objects.create(name='Q', slug='q', insert_date=now, org=Org.objects.create(name='Other', slug='other'))
		self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.person = User.objects.create_user('person', password='x')

	def _scan(self, domain=None):
		return ScanHistory.objects.create(domain=domain or self.domain, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now())

	def _host(self, name, scan, domain=None, http_url=None):
		return Subdomain.objects.create(name=name, target_domain=domain or self.domain, scan_history=scan, http_url=http_url)

	def _vuln(self, sub, **kw):
		data = dict(target_domain=sub.target_domain, scan_history=sub.scan_history, subdomain=sub, source='nuclei', template_id='ssh-terrapin',
					name='SSH Terrapin Attack', http_url=f'{sub.name}:22', matcher_name='', severity=2, discovered_date=timezone.now())
		data.update(kw)
		return Vulnerability.objects.create(**data)


# --------------------------------------------------------------------------------------------------- 23: fixed version closes

def wp_report(core, vulns=(), outdated=False):
	return {'version': {'number': core, 'status': 'outdated' if outdated else 'latest', 'vulnerabilities': list(vulns)}}


def advisory(title, fixed):
	return {'title': title, 'fixed_in': fixed, 'cvss': {'score': 7.5}, 'references': {'cve': ['2026-0001']}}


class FixedVersionClosesTests(LifecycleBase):
	"""A WordPress site scanned at 6.5.2 (advisories fixed in 7.1.4 and 7.2.0, core outdated), then at 7.1.4."""

	def setUp(self):
		super().setUp()
		self.old_scan = self._scan()
		self.old_sub = self._host('blog.example.com', self.old_scan)
		wpscan_scan.persist_report(self.old_scan, self.old_sub, 'https://blog.example.com/', wp_report(
			'6.5.2', [advisory('Upgrade race to RCE', '7.1.4'), advisory('Stored XSS in blocks', '7.2.0')], outdated=True))
		self.rows = {v.name: v for v in Vulnerability.objects.filter(source='wpscan')}

	def _rescan(self, report):
		scan = self._scan()
		sub = self._host('blog.example.com', scan)
		wpscan_scan.persist_report(scan, sub, 'https://blog.example.com/', report)
		return scan

	def test_a_later_scan_reading_the_fixed_version_closes_the_old_rows_as_fixed_automatically(self):
		race = self.rows['WordPress 6.5.2: Upgrade race to RCE']
		outdated = self.rows['WordPress 6.5.2 is outdated']
		xss = self.rows['WordPress 6.5.2: Stored XSS in blocks']
		scan = self._rescan(wp_report('7.1.4', [advisory('Stored XSS in blocks', '7.2.0')]))
		race.refresh_from_db()
		outdated.refresh_from_db()
		xss.refresh_from_db()
		self.assertEqual((race.remediation_status, race.remediation_by_id), ('fixed', None))
		self.assertIn('7.1.4', race.remediation_note)
		self.assertIn(f'scan #{scan.pk}', race.remediation_note)
		note, user, _when, automatic = closure.closure_of('vulnerability', race)
		self.assertTrue(automatic)
		self.assertIsNone(user)
		self.assertTrue(note.startswith(finding_lifecycle.FIXED_VERSION))
		self.assertEqual(outdated.remediation_status, 'fixed')  # 7.1.4 is no longer outdated
		# still affected at 7.1.4: not fixed, but the 7.1.4 row is that finding now, so the 6.5.2 copy is folded into it
		current = Vulnerability.objects.get(name='WordPress 7.1.4: Stored XSS in blocks')
		self.assertEqual((xss.remediation_status, xss.open_status), ('open', False))
		self.assertIn(f'#{current.pk}', xss.remediation_note)
		self.assertTrue(closure.closure_of('vulnerability', xss)[3])
		self.assertTrue(current.open_status)
		# the actionable list of the host is the one live advisory
		live = [v.name for v in Vulnerability.objects.filter(source='wpscan') if v.open_status and v.remediation_status not in closure.CLOSED]
		self.assertEqual(live, ['WordPress 7.1.4: Stored XSS in blocks'])

	def test_a_finding_a_person_set_or_closed_otherwise_is_never_touched(self):
		race = self.rows['WordPress 6.5.2: Upgrade race to RCE']
		Vulnerability.objects.filter(pk=race.pk).update(remediation_status='in_progress', remediation_by=self.person)
		xss = self.rows['WordPress 6.5.2: Stored XSS in blocks']
		Vulnerability.objects.filter(pk=xss.pk).update(remediation_status='accepted_risk', remediation_by=self.person, remediation_note='waf rule')
		self._rescan(wp_report('7.2.1'))
		race.refresh_from_db()
		xss.refresh_from_db()
		self.assertEqual((race.remediation_status, race.remediation_by_id), ('in_progress', self.person.id))
		self.assertEqual((xss.remediation_status, xss.remediation_note), ('accepted_risk', 'waf rule'))

	def test_a_version_still_in_range_or_not_read_closes_nothing(self):
		self._rescan(wp_report('7.0.0', [advisory('Upgrade race to RCE', '7.1.4')]))
		race = Vulnerability.objects.get(pk=self.rows['WordPress 6.5.2: Upgrade race to RCE'].pk)
		self.assertEqual(race.remediation_status, 'open')
		self._rescan({'version': {}})  # WPScan could not read the core version: no evidence about any advisory
		self.assertFalse(Vulnerability.objects.filter(remediation_status='fixed', name__startswith='WordPress 6.5.2: Upgrade').exists())

	def test_an_engine_closure_is_undone_when_a_scan_reports_the_finding_again(self):
		self._rescan(wp_report('7.1.4'))
		race = Vulnerability.objects.get(pk=self.rows['WordPress 6.5.2: Upgrade race to RCE'].pk)
		self.assertEqual(race.remediation_status, 'fixed')
		self._rescan(wp_report('6.5.2', [advisory('Upgrade race to RCE', '7.1.4')]))  # rolled back
		race.refresh_from_db()
		self.assertEqual((race.remediation_status, race.open_status), ('open', True))
		self.assertTrue(race.remediation_note.startswith(finding_lifecycle.REOPENED_NOTE))

	def test_a_person_fixed_status_still_sticks_when_the_scan_sees_it_again(self):
		race = self.rows['WordPress 6.5.2: Upgrade race to RCE']
		Vulnerability.objects.filter(pk=race.pk).update(remediation_status='fixed', remediation_by=self.person, remediation_note='patched')
		self._rescan(wp_report('6.5.2', [advisory('Upgrade race to RCE', '7.1.4')]))
		race.refresh_from_db()
		self.assertEqual((race.remediation_status, race.remediation_note), ('fixed', 'patched'))
		self.assertFalse(closure.closure_of('vulnerability', race)[3])

	def test_backfill_closes_from_the_last_stored_versions_and_is_a_dry_run_by_default(self):
		ProbeObservation.objects.create(project=self.project, domain=self.domain, host='blog.example.com', probe='wpscan-core', port=0,
										kind='version', product='WordPress', version='7.1.4', outcome='found', source='wpscan')
		out = io.StringIO()
		call_command('close_fixed_findings', stdout=out)
		self.assertIn('would close 1 ', out.getvalue())
		self.assertFalse(Vulnerability.objects.filter(remediation_status='fixed').exists())
		call_command('close_fixed_findings', '--apply', stdout=io.StringIO())
		self.assertEqual(list(Vulnerability.objects.filter(remediation_status='fixed').values_list('name', flat=True)),
						 ['WordPress 6.5.2: Upgrade race to RCE'])  # the outdated row is left to the next scan


# --------------------------------------------------------------------------------------------------- 24: rescans update, duplicates merge

class RescanUpdatesTests(LifecycleBase):
	def test_a_rescan_moves_the_finding_instead_of_filing_a_copy(self):
		rows = set()
		for _ in range(3):
			scan = self._scan()
			sub = self._host('ssh.example.com', scan)
			vuln, _created = save_vulnerability(target_domain=self.domain, scan_history=scan, subdomain=sub, source='nuclei',
												 template_id='ssh-terrapin', name='SSH Terrapin Attack', http_url='ssh.example.com:22', severity=2)
			rows.add(vuln.pk)
		self.assertEqual(len(rows), 1)
		vuln = Vulnerability.objects.get()
		self.assertEqual((vuln.scan_history_id, vuln.subdomain_id, vuln.open_status), (scan.id, sub.id, True))

	def test_the_same_host_under_two_targets_of_one_project_is_one_finding_but_another_project_keeps_its_own(self):
		apex_scan = self._scan()
		own = Domain.objects.create(name='api.example.com', project=self.project, insert_date=timezone.now())
		other = Domain.objects.create(name='api.example.com', project=self.other_project, insert_date=timezone.now())
		for domain in (self.domain, own, other):
			scan = apex_scan if domain is self.domain else self._scan(domain)
			sub = self._host('api.example.com', scan, domain=domain)
			save_vulnerability(target_domain=domain, scan_history=scan, subdomain=sub, source='nuclei', template_id='ssh-terrapin',
							   name='SSH Terrapin Attack', http_url='api.example.com:22', severity=2)
		self.assertEqual(Vulnerability.objects.filter(target_domain__project=self.project).count(), 1)
		self.assertEqual(Vulnerability.objects.filter(target_domain__project=self.other_project).count(), 1)

	def test_hygiene_for_one_host_under_two_targets_is_filed_once(self):
		own = Domain.objects.create(name='api.example.com', project=self.project, insert_date=timezone.now())
		other = Domain.objects.create(name='api.example.com', project=self.other_project, insert_date=timezone.now())
		finding = lambda days: hygiene.Finding('tls_expiring', 2, f'Certificate expires in {days} days', host='api.example.com:443',
											   evidence={'not_after': '2026-11-18T23:59:59+00:00', 'days_left': days})
		hygiene.store_findings(own, [finding(16)], across_targets=True)
		hygiene.store_findings(self.domain, [finding(15)], across_targets=True)
		hygiene.store_findings(other, [finding(15)], across_targets=True)
		mine = HygieneFinding.objects.filter(domain__project=self.project)
		self.assertEqual(mine.count(), 1)
		self.assertEqual((mine.get().domain_id, mine.get().evidence['days_left']), (own.id, 15))
		self.assertEqual(HygieneFinding.objects.filter(domain__project=self.other_project).count(), 1)


class DedupeCommandTests(LifecycleBase):
	"""Terrapin open on one host:22 from three scans, one of them loaded twice under a second host row; a hygiene pair under two targets."""

	def setUp(self):
		super().setUp()
		self.scans = [self._scan() for _ in range(3)]
		subs = [self._host('ssh.example.com', scan) for scan in self.scans]
		self.copies = [self._vuln(sub, discovered_date=timezone.now() - timedelta(days=9 - i)) for i, sub in enumerate(subs)]
		twin = self._host('ssh.example.com', self.scans[1], domain=Domain.objects.create(
			name='ssh.example.com', project=self.project, insert_date=timezone.now()))
		self.copies.append(self._vuln(twin))
		Vulnerability.objects.filter(pk=self.copies[0].pk).update(assignee=self.person)
		FindingComment.objects.create(project=self.project, finding_kind='vulnerability', finding_id=self.copies[1].pk, author=self.person, text='seen')
		FindingAuditEvent.objects.create(project=self.project, finding_kind='vulnerability', finding_id=self.copies[0].pk, event='assignee',
										 actor=self.person, before={}, after={'assignee': 'person'})
		self.closed = self._vuln(subs[0], name='SSH Terrapin Attack', http_url='ssh.example.com:22', template_id='ssh-terrapin',
								 matcher_name='x', remediation_status='false_positive', remediation_by=self.person)
		# another project with the very same rows is never merged with this one
		elsewhere = Domain.objects.create(name='example.com', project=self.other_project, insert_date=timezone.now())
		for _ in range(2):
			self._vuln(self._host('ssh.example.com', self._scan(elsewhere), domain=elsewhere))
		self.second_target = Domain.objects.create(name='api.example.com', project=self.project, insert_date=timezone.now())
		self.h1 = HygieneFinding.objects.create(domain=self.second_target, host='api.example.com:443', check_name='tls_expiring', severity=2,
												title='Certificate expires', evidence={'not_after': '2026-11-18'})
		self.h2 = HygieneFinding.objects.create(domain=self.domain, host='api.example.com:443', check_name='tls_expiring', severity=2,
												title='Certificate expires', evidence={'not_after': '2026-11-18'})

	def test_dry_run_reports_and_changes_nothing(self):
		out = io.StringIO()
		call_command('dedupe_findings', stdout=out)
		self.assertIn('p: scanner_groups 1, scanner_closed 3, hygiene_groups 1, hygiene_closed 1', out.getvalue())
		self.assertIn('q: scanner_groups 1, scanner_closed 1', out.getvalue())
		self.assertEqual(Vulnerability.objects.filter(open_status=True).count(), 7)

	def test_apply_keeps_the_current_copy_with_the_history_and_closes_the_rest(self):
		call_command('dedupe_findings', '--apply', '--project', 'p', stdout=io.StringIO())
		live = Vulnerability.objects.filter(target_domain__project=self.project, open_status=True, remediation_status='open')
		keeper = live.get()
		self.assertEqual(keeper.scan_history_id, self.scans[2].id)  # the host's current scan
		self.assertEqual(keeper.assignee_id, self.person.id)  # from the oldest copy
		self.assertEqual(keeper.discovered_date, Vulnerability.objects.get(pk=self.copies[0].pk).discovered_date)
		self.assertEqual(FindingComment.objects.get().finding_id, keeper.pk)
		self.assertEqual(FindingAuditEvent.objects.get().finding_id, keeper.pk)
		for dup in Vulnerability.objects.filter(pk__in=[c.pk for c in self.copies]).exclude(pk=keeper.pk):
			self.assertFalse(dup.open_status)
			self.assertTrue(dup.remediation_note.startswith(finding_lifecycle.DUPLICATE))
			self.assertIn(f'#{keeper.pk}', dup.remediation_note)
			self.assertTrue(closure.closure_of('vulnerability', dup)[3])
		self.closed.refresh_from_db()
		self.assertEqual(self.closed.remediation_status, 'false_positive')  # closed for another reason: untouched
		self.assertEqual(Vulnerability.objects.filter(target_domain__project=self.other_project, open_status=True).count(), 2)
		self.h1.refresh_from_db()
		self.h2.refresh_from_db()
		self.assertEqual((self.h1.status, self.h2.status), ('open', 'resolved'))
		self.assertIn(f'#{self.h1.pk}', self.h2.remediation_note)
		# a second run finds nothing, and the next rescan updates the copy that stayed
		again = io.StringIO()
		call_command('dedupe_findings', '--apply', '--project', 'p', stdout=again)
		self.assertIn('closed 0 duplicate scanner finding(s) and 0 duplicate hygiene', again.getvalue())
		scan = self._scan()
		vuln, created = save_vulnerability(target_domain=self.domain, scan_history=scan, subdomain=self._host('ssh.example.com', scan),
										   source='nuclei', template_id='ssh-terrapin', name='SSH Terrapin Attack', http_url='ssh.example.com:22',
										   matcher_name='', severity=2)
		self.assertEqual((vuln.pk, created), (keeper.pk, False))
		hygiene.store_findings(self.domain, [hygiene.Finding('tls_expiring', 2, 'Certificate expires', host='api.example.com:443')], across_targets=True)
		self.h2.refresh_from_db()
		self.assertEqual(self.h2.status, 'resolved')  # a folded copy stays folded; the row that stayed is the finding

	def test_copies_people_worked_differently_are_left_for_a_person(self):
		other = User.objects.create_user('other', password='x')
		Vulnerability.objects.filter(pk=self.copies[1].pk).update(assignee=other)
		out = io.StringIO()
		call_command('dedupe_findings', '--apply', '--project', 'p', stdout=out)
		self.assertIn('1 left open', out.getvalue())
		self.assertTrue(Vulnerability.objects.get(pk=self.copies[1].pk).open_status)


# --------------------------------------------------------------------------------------------------- 25: redirect aliases

class RedirectAliasTests(LifecycleBase):
	def setUp(self):
		super().setUp()
		self.scan = self._scan()
		self.apex = self._host('example.com', self.scan, http_url='https://example.com')
		self.www = self._host('www.example.com', self.scan, http_url='https://www.example.com')
		self._root('www.example.com', 'https://www.example.com/', 301, 'https://example.com/')
		self._root('example.com', 'https://example.com/', 200, '')

	def _root(self, host, url, status, location):
		return RouteAuth.objects.update_or_create(project=self.project, url=url, defaults=dict(
			domain=self.domain, host=host, path='/', auth_state='redirect' if location else 'open', http_status=status,
			redirect_to=location, checked_at=timezone.now()))[0]

	def _pair(self, template='missing-hsts', name='HSTS Missing'):
		shared = dict(source='nuclei', template_id=template, name=name)
		return (self._vuln(self.apex, http_url='https://example.com/', **shared), self._vuln(self.www, http_url='https://www.example.com/', **shared))

	def test_a_host_that_only_redirects_is_folded_into_its_target(self):
		apex_row, www_row = self._pair()
		own = self._vuln(self.www, template_id='www-only', name='Only on www', http_url='https://www.example.com/')
		cert = dict(check_name='tls_expiring', severity=2, title='Certificate expires', evidence={'not_after': '2026-11-18'})
		h_apex = HygieneFinding.objects.create(domain=self.domain, host='example.com:443', **cert)
		h_www = HygieneFinding.objects.create(domain=self.domain, host='www.example.com:443', **cert)
		out = io.StringIO()
		call_command('fold_alias_findings', stdout=out)
		self.assertIn('p: aliases 1, vulnerability 1, hygiene 1', out.getvalue())
		self.assertTrue(Vulnerability.objects.get(pk=www_row.pk).open_status)  # a dry run
		call_command('fold_alias_findings', '--apply', stdout=io.StringIO())
		www_row.refresh_from_db()
		h_www.refresh_from_db()
		self.assertFalse(www_row.open_status)
		self.assertTrue(www_row.remediation_note.startswith(finding_lifecycle.ALIAS))
		self.assertIn(f'#{apex_row.pk}', www_row.remediation_note)
		self.assertTrue(closure.closure_of('vulnerability', www_row)[3])
		self.assertEqual(h_www.status, 'resolved')
		self.assertIn(f'#{h_apex.pk}', h_www.remediation_note)
		self.assertTrue(Vulnerability.objects.get(pk=own.pk).open_status)  # only the alias has it: its own finding
		self.assertTrue(Vulnerability.objects.get(pk=apex_row.pk).open_status)

	def test_a_temporary_redirect_or_a_redirect_out_of_the_project_is_not_an_alias(self):
		_apex_row, www_row = self._pair()
		self._root('www.example.com', 'https://www.example.com/', 302, 'https://example.com/')
		self.assertEqual(finding_lifecycle.fold_aliases(self.project.pk)['vulnerability'], 0)
		self._root('www.example.com', 'https://www.example.com/', 301, 'https://example.net/')
		self.assertEqual(finding_lifecycle.fold_aliases(self.project.pk)['vulnerability'], 0)
		self.assertTrue(Vulnerability.objects.get(pk=www_row.pk).open_status)

	def test_a_folded_copy_stays_folded_on_rescan_and_reopens_when_the_host_serves_its_own_page(self):
		_apex_row, www_row = self._pair()
		finding_lifecycle.fold_aliases(self.project.pk)
		scan = self._scan()
		sub = self._host('www.example.com', scan, http_url='https://www.example.com')
		vuln, _ = save_vulnerability(target_domain=self.domain, scan_history=scan, subdomain=sub, source='nuclei', template_id='missing-hsts',
									 name='HSTS Missing', http_url='https://www.example.com/', matcher_name='', severity=2)
		self.assertEqual(vuln.pk, www_row.pk)
		self.assertFalse(Vulnerability.objects.get(pk=www_row.pk).open_status)
		self._root('www.example.com', 'https://www.example.com/', 200, '')
		self.assertEqual(finding_lifecycle.fold_aliases(self.project.pk)['reopened'], 1)
		self.assertTrue(Vulnerability.objects.get(pk=www_row.pk).open_status)

	def test_a_cname_to_the_apex_gets_no_mail_findings_of_its_own(self):
		cname = {'www.example.com'}
		names = hygiene.email_domains(self.domain, lambda name, rtype: True, cname=lambda name: name in cname)
		self.assertEqual(names, ['example.com'])
		self.assertNotIn('www.example.com', names)


# --------------------------------------------------------------------------------------------------- 26: one item per upgrade

class OneItemPerUpgradeTests(LifecycleBase):
	def setUp(self):
		super().setUp()
		ProjectMembership.objects.create(user=self.person, project=self.project, role='user')
		_, self.token = create_token(self.person, 'agent')
		sub = Subdomain.objects.create(name='www.example.com', target_domain=self.domain)
		jquery = lambda fixed: [{'product': 'jquery', 'ranges': [{'introduced': '1.2.0', 'fixed': fixed}]}]
		now = timezone.now()
		for cve_id, fixed, cvss in (('CVE-2020-11022', '3.5.0', 6.1), ('CVE-2020-11023', '3.5.0', 6.9), ('CVE-2099-0001', '3.6.0', 5.0)):
			cve = CVEEntry.objects.create(cve_id=cve_id, cvss=cvss, title=cve_id, published_at=now, affected=jquery(fixed))
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9, matched_product='jquery', matched_version='3.4.1',
									version_in_range=True, source='tech')

	def test_cves_fixed_by_the_same_upgrade_are_one_item(self):
		status, data = call(self.token, 'GET', '/api/v1/projects/p/work')
		self.assertEqual(status, 200)
		self.assertEqual((data['count'], data['matches']), (2, 3))
		items = {tuple(sorted(i['cves'])): i for i in data['results']}
		self.assertEqual(set(items), {('CVE-2020-11022', 'CVE-2020-11023'), ('CVE-2099-0001',)})
		pair = items[('CVE-2020-11022', 'CVE-2020-11023')]
		self.assertEqual(pair['upgrade_to'], '3.5.0')
		self.assertEqual(len(pair['match_ids']), 2)
		self.assertEqual(set(CVEMatch.objects.values_list('id', flat=True)),
						 {m for i in data['results'] for m in i['match_ids']})  # every match is still there, each with its own row

	def test_the_upgrade_is_the_lowest_fix_above_the_version(self):
		from agentapi.services import _upgrade_to
		self.assertEqual(_upgrade_to('3.4.1', ['1.12.0', '3.5.0', '4.0.0']), '3.5.0')
		self.assertEqual(_upgrade_to('', ['3.5.0']), '3.5.0')
		self.assertEqual(_upgrade_to('', ['2.2.0', '3.5.0']), '')
