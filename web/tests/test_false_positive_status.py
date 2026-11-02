"""The false_positive closure status and the closure note (cveFeed.closure): every surface that sets, lists, filters, counts, exports or
reports a finding's remediation status knows false_positive, treats it as closed exactly like fixed and accepted_risk, and carries the
note a person wrote when closing (or the reason the engine stored when it closed a CVE match on its own)."""
import json

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import closure, counts
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, FindingAuditEvent, HygieneFinding, Supplier, SupplierFinding
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc, tool_call


class ClosureDefinitionTests(SimpleTestCase):
	def test_every_model_and_count_uses_the_one_list_of_statuses(self):
		self.assertEqual(closure.STATUSES, ('open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive'))
		self.assertEqual(closure.CLOSED, ('fixed', 'accepted_risk', 'false_positive'))
		self.assertEqual(tuple(CVEMatch.REMEDIATION_STATUSES), closure.STATUSES)
		self.assertEqual(tuple(Vulnerability.REMEDIATION_STATUSES), closure.STATUSES)
		self.assertEqual(tuple(HygieneFinding.REMEDIATION_STATUSES), closure.STATUSES)
		self.assertEqual(counts.CLOSED, closure.CLOSED)
		self.assertEqual(tuple(SupplierFinding.STATUSES), closure.SUPPLIER_STATUSES)
		self.assertEqual(closure.label('false_positive'), 'False positive')

	def test_the_status_fits_the_columns(self):
		for model, field in ((CVEMatch, 'remediation_status'), (Vulnerability, 'remediation_status'), (HygieneFinding, 'remediation_status'),
		                     (SupplierFinding, 'status')):
			self.assertGreaterEqual(model._meta.get_field(field).max_length, len('false_positive'), model)
		self.assertGreaterEqual(SupplierFinding._meta.get_field('status_note').max_length, closure.NOTE_MAX)

	def test_a_note_is_stripped_cleaned_and_bounded(self):
		self.assertIsNone(closure.clean_note(None))
		self.assertEqual(closure.clean_note('  only a redirect  '), 'only a redirect')
		self.assertEqual(closure.clean_note('a\x00b\x1bc\u202ed\r\ne\tf'), 'abcd\ne\tf')
		self.assertEqual(closure.clean_note('x' * 2000), 'x' * 2000)
		self.assertEqual(closure.clean_note('  ' + 'x' * 2000 + '\n'), 'x' * 2000)  # bounded after stripping
		with self.assertRaises(closure.NoteError):
			closure.clean_note('x' * 2001)
		for bad in (5, ['a'], {'a': 1}):
			with self.assertRaises(closure.NoteError):
				closure.clean_note(bad)


class Fixture:
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org = Org.objects.create(name='FP', slug='fp-org')
		cls.proj = Project.objects.create(name='FP Project', slug='fp-proj', insert_date=now, org=org)
		cls.domain = Domain.objects.create(name='fp.example', project=cls.proj, insert_date=now)
		mk = lambda n: User.objects.create_user(n, password='x')
		cls.alice, cls.viewer, cls.admin = mk('fpalice'), mk('fpviewer'), mk('fpadmin')
		ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
		ProjectMembership.objects.create(user=cls.viewer, project=cls.proj, role='audit')
		OrgMembership.objects.create(user=cls.admin, org=org, role='admin')
		_, cls.t_alice = create_token(cls.alice, 'agent')
		_, cls.t_ro = create_token(cls.alice, 'readonly', read_only=True)
		_, cls.t_viewer = create_token(cls.viewer, 'viewer')
		_, cls.t_admin = create_token(cls.admin, 'admin')
		cls.sub = Subdomain.objects.create(name='www.fp.example', target_domain=cls.domain)
		cls.cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', cvss=6.9, title='jQuery XSS', published_at=now)
		cls.kev = CVEEntry.objects.create(cve_id='CVE-2099-7', cvss=9.8, kev=True, title='critical', published_at=now)
		cls.match = CVEMatch.objects.create(cve_entry=cls.cve, subdomain=cls.sub, confidence=0.9, matched_product='jquery', matched_version='3.4.1',
		                                    version_in_range=True, source='tech')
		cls.hot = CVEMatch.objects.create(cve_entry=cls.kev, subdomain=cls.sub, confidence=0.9, matched_product='nginx', matched_version='1.1',
		                                  version_in_range=True, source='port')
		cls.vuln = Vulnerability.objects.create(name='Reflected XSS', severity=3, subdomain=cls.sub, target_domain=cls.domain,
		                                        open_status=True, http_url='https://www.fp.example/', source='nuclei')
		cls.hyg = HygieneFinding.objects.create(domain=cls.domain, host='www.fp.example', check_name='spf_missing', severity=2, title='No SPF')

	base = '/api/v1/projects/fp-proj'


class RestTests(Fixture, TestCase):
	def test_a_finding_of_each_kind_closes_as_a_false_positive_with_a_note(self):
		for kind, obj in (('match', self.match), ('vulnerability', self.vuln), ('hygiene', self.hyg)):
			status, data = call(self.t_alice, 'PATCH', f'{self.base}/findings/{kind}/{obj.id}',
			                    {'status': 'false_positive', 'note': ' the host only redirects to another site '})
			self.assertEqual(status, 200, (kind, data))
			self.assertEqual((data['remediation_status'], data['remediation_note']), ('false_positive', 'the host only redirects to another site'))
			self.assertEqual(data['closure_note'], 'the host only redirects to another site')
			self.assertEqual(data['closed_by']['username'], 'fpalice')
			self.assertIsNotNone(data['closed_at'])
			self.assertFalse(data['closed_automatically'])
			obj.refresh_from_db()
			self.assertEqual(obj.remediation_status, 'false_positive')

	def test_the_matches_route_takes_it_too(self):
		status, data = call(self.t_alice, 'PATCH', f'{self.base}/matches/{self.match.id}', {'status': 'false_positive', 'note': 'jQuery is not loaded'})
		self.assertEqual((status, data['remediation_status'], data['closure_note']), (200, 'false_positive', 'jQuery is not loaded'))

	def test_every_closing_status_carries_its_note_and_an_open_one_has_none(self):
		url = f'{self.base}/findings/vulnerability/{self.vuln.id}'
		for status in ('fixed', 'accepted_risk', 'false_positive'):
			data = call(self.t_alice, 'PATCH', url, {'status': status, 'note': f'why {status}'})[1]
			self.assertEqual((data['closure_note'], data['closed_by']['username']), (f'why {status}', 'fpalice'))
		data = call(self.t_alice, 'PATCH', url, {'status': 'in_progress'})[1]
		self.assertEqual((data['remediation_note'], data['closure_note'], data['closed_by'], data['closed_at']), ('why false_positive', None, None, None))

	def test_the_api_accepts_a_false_positive_without_a_note(self):
		status, data = call(self.t_alice, 'PATCH', f'{self.base}/findings/hygiene/{self.hyg.id}', {'status': 'false_positive'})
		self.assertEqual((status, data['remediation_status'], data['closure_note']), (200, 'false_positive', ''))

	def test_a_note_is_cleaned_and_a_bad_one_changes_nothing(self):
		url = f'{self.base}/findings/vulnerability/{self.vuln.id}'
		data = call(self.t_alice, 'PATCH', url, {'status': 'false_positive', 'note': 'scanner\x00 matched\u202e a\r\nplaceholder'})[1]
		self.assertEqual(data['remediation_note'], 'scanner matched a\nplaceholder')
		for bad in ('x' * 2001, 42, ['a']):
			status, err = call(self.t_alice, 'PATCH', url, {'status': 'fixed', 'note': bad})
			self.assertEqual(status, 400, bad)
		self.vuln.refresh_from_db()
		self.assertEqual((self.vuln.remediation_status, self.vuln.remediation_note), ('false_positive', 'scanner matched a\nplaceholder'))
		self.assertEqual(call(self.t_alice, 'PATCH', url, {'status': 'fixed', 'note': 'x' * 2000})[0], 200)

	def test_viewers_and_read_only_tokens_cannot_close(self):
		for token in (self.t_viewer, self.t_ro):
			self.assertEqual(call(token, 'PATCH', f'{self.base}/findings/match/{self.match.id}', {'status': 'false_positive', 'note': 'x'})[0], 403)
			self.assertEqual(call(token, 'POST', f'{self.base}/findings/status',
			                      {'items': [{'kind': 'hygiene', 'id': self.hyg.id}], 'status': 'false_positive', 'note': 'x'})[0], 403)
		self.match.refresh_from_db()
		self.hyg.refresh_from_db()
		self.assertEqual((self.match.remediation_status, self.hyg.remediation_status), ('open', 'open'))
		self.assertFalse(FindingAuditEvent.objects.exists())

	def test_every_change_is_audited_with_who_before_after_and_the_note(self):
		url = f'{self.base}/findings/match/{self.match.id}'
		call(self.t_alice, 'PATCH', url, {'status': 'false_positive', 'note': 'library file never served'})
		trail = call(self.t_alice, 'GET', f'{url}/audit')[1]['results']
		self.assertEqual(len(trail), 1)
		self.assertEqual((trail[0]['event'], trail[0]['actor']['username']), ('status', 'fpalice'))
		self.assertEqual((trail[0]['before'], trail[0]['after']), ({'status': 'open'}, {'status': 'false_positive', 'note': 'library file never served'}))
		line = AgentActivity.objects.filter(kind='remediation').latest('id')
		self.assertIn('marked false_positive', line.message)
		self.assertEqual((line.detail['after'], line.detail['before'], line.detail['note']), ('false_positive', 'open', 'library file never served'))

	def test_a_bulk_close_puts_the_note_on_every_finding_and_audits_each(self):
		items = [{'kind': 'match', 'id': self.match.id}, {'kind': 'vulnerability', 'id': self.vuln.id}, {'kind': 'hygiene', 'id': self.hyg.id}]
		status, data = call(self.t_alice, 'POST', f'{self.base}/findings/status', {'items': items, 'status': 'false_positive', 'note': '  same page on every host '})
		self.assertEqual((status, data['updated'], data['failed']), (200, 3, []))
		for obj in (self.match, self.vuln, self.hyg):
			obj.refresh_from_db()
			self.assertEqual((obj.remediation_status, obj.remediation_note, obj.remediation_by_id), ('false_positive', 'same page on every host', self.alice.id))
		events = FindingAuditEvent.objects.filter(event='status')
		self.assertEqual(sorted(e.finding_kind for e in events), ['hygiene', 'match', 'vulnerability'])
		self.assertTrue(all(e.after == {'status': 'false_positive', 'note': 'same page on every host'} for e in events))
		line = AgentActivity.objects.filter(kind='remediation').latest('id')
		self.assertIn('marked 3 finding(s) on 1 host(s) false_positive', line.message)
		self.assertEqual(line.detail['note'], 'same page on every host')

	def test_a_bulk_close_with_a_bad_note_is_refused_before_anything_is_written(self):
		items = [{'kind': 'match', 'id': self.match.id}]
		self.assertEqual(call(self.t_alice, 'POST', f'{self.base}/findings/status', {'items': items, 'status': 'false_positive', 'note': 'x' * 2001})[0], 400)
		self.match.refresh_from_db()
		self.assertEqual(self.match.remediation_status, 'open')

	def test_unknown_status_is_still_refused(self):
		self.assertEqual(call(self.t_alice, 'PATCH', f'{self.base}/findings/match/{self.match.id}', {'status': 'false-positive'})[0], 400)


class ListAndCountTests(Fixture, TestCase):
	def close(self, kind, obj, status='false_positive', note='not real'):
		self.assertEqual(call(self.t_alice, 'PATCH', f'{self.base}/findings/{kind}/{obj.id}', {'status': status, 'note': note})[0], 200)
		obj.refresh_from_db()

	def test_a_false_positive_leaves_the_actionable_list_and_shows_under_closed_and_everything(self):
		before = call(self.t_alice, 'GET', f'{self.base}/findings')[1]['counts']
		self.close('match', self.match)
		self.close('vulnerability', self.vuln)
		self.close('hygiene', self.hyg, status='fixed')
		after = call(self.t_alice, 'GET', f'{self.base}/findings')[1]
		self.assertEqual((after['counts']['cve'], after['counts']['scanner'], after['counts']['hygiene']), (before['cve'] - 1, 0, 0))
		every = call(self.t_alice, 'GET', f'{self.base}/findings?status=all')[1]
		row = next(r for r in every['results'] if r['type'] == 'cve' and r['id'] == self.match.id)
		self.assertEqual((row['status'], row['closure_note'], row['closed_by']['username']), ('false_positive', 'not real', 'fpalice'))
		closed = call(self.t_alice, 'GET', f'{self.base}/findings?status=closed')[1]
		self.assertEqual(sorted((r['type'], r['status']) for r in closed['results']), [('cve', 'false_positive'), ('hygiene', 'fixed'), ('scanner', 'false_positive')])
		only = call(self.t_alice, 'GET', f'{self.base}/findings?status=false_positive')[1]
		self.assertEqual(sorted(r['type'] for r in only['results']), ['cve', 'scanner'])
		for bad in ('bogus', 'open', 'in_progress'):  # open would read as actionable but is not: only the closing statuses stand alone
			self.assertEqual(call(self.t_alice, 'GET', f'{self.base}/findings?status={bad}')[0], 400, bad)

	def test_the_matches_list_filters_by_it_and_by_closed(self):
		self.close('match', self.match)
		rows = call(self.t_alice, 'GET', f'{self.base}/matches?status=false_positive')[1]['results']
		self.assertEqual([(r['id'], r['closure_note']) for r in rows], [(self.match.id, 'not real')])
		self.assertEqual([r['id'] for r in call(self.t_alice, 'GET', f'{self.base}/matches?status=closed')[1]['results']], [self.match.id])
		err, data = tool_call(self.t_alice, 'list_cve_matches', {'project': 'fp-proj', 'status': 'false_positive'})
		self.assertEqual((err, [r['id'] for r in data['results']]), (False, [self.match.id]))

	def test_detail_carries_the_closure(self):
		self.close('hygiene', self.hyg, note='SPF is set on the parent zone')
		d = call(self.t_alice, 'GET', f'{self.base}/findings/hygiene/{self.hyg.id}')[1]
		self.assertEqual((d['remediation']['status'], d['remediation']['closure_note'], d['closure_note']),
		                 ('false_positive', 'SPF is set on the parent zone', 'SPF is set on the parent zone'))
		self.assertEqual(d['closed_by']['username'], 'fpalice')

	def test_live_counts_heat_and_scores_leave_it_out(self):
		self.assertTrue(counts.match_is_live(self.hot))
		self.close('match', self.hot)
		self.assertFalse(counts.match_is_live(self.hot))
		self.assertNotIn(self.hot.id, set(counts.exposed_matches().values_list('id', flat=True)))
		self.close('vulnerability', self.vuln)
		self.assertFalse(counts.finding_is_live(self.vuln))
		self.assertEqual(counts.actionable_findings(Vulnerability.objects.filter(pk=self.vuln.pk)).count(), 0)
		self.close('hygiene', self.hyg)
		self.assertEqual(counts.actionable_hygiene(HygieneFinding.objects.filter(pk=self.hyg.pk)).count(), 0)
		from cveFeed import stats_history
		open_findings, heats = stats_history._open_findings_and_cve_matches(self.proj)
		self.assertEqual(sum(heats.values()), 1)  # only the jQuery match is left
		self.assertEqual(sum(open_findings.values()), 1)

	def test_host_heat_reasons_leave_it_out(self):
		host = call(self.t_alice, 'GET', f'{self.base}/hosts?q=www.fp.example')[1]['results'][0]
		self.assertIn('CVE-2099-7', json.dumps(host['heat_reasons']))
		self.close('match', self.hot)
		host = call(self.t_alice, 'GET', f'{self.base}/hosts?q=www.fp.example')[1]['results'][0]
		self.assertNotIn('CVE-2099-7', json.dumps(host['heat_reasons']))

	def test_remediation_work_fire_paging_and_openvas_leave_it_out(self):
		from unittest import mock

		from cveFeed import notify, openvas_scan
		self.assertIn('www.fp.example', openvas_scan.hot_names(self.proj.id))
		self.close('match', self.hot)
		self.close('vulnerability', self.vuln)
		err, work = tool_call(self.t_alice, 'get_remediation_work', {'project': 'fp-proj'})
		self.assertFalse(err)
		self.assertNotIn(self.hot.id, [i['id'] for i in work['results']])
		self.assertIn(self.match.id, [i['id'] for i in work['results']])
		self.assertNotIn('www.fp.example', openvas_scan.hot_names(self.proj.id))
		twin = CVEMatch.objects.create(cve_entry=self.kev, subdomain=self.sub, confidence=0.9, matched_product='nginx plus', matched_version='1.1',
		                               version_in_range=True, source='port', template_result='no_match', distro_status='vulnerable')
		with mock.patch('cveFeed.notify._send', return_value=True) as sent:
			notify.fire_confirmed([self.hot.id, twin.id])
		self.hot.refresh_from_db()
		self.assertIsNone(self.hot.fire_notified_at)  # never paged as fire
		if sent.called:
			self.assertIn('1 CVE match confirmed', sent.call_args[0][0])

	def test_a_closed_match_carried_onto_a_rescan_is_not_paged_as_new_fire(self):
		from datetime import timedelta
		from unittest import mock

		from cveFeed import notify
		since = timezone.now() - timedelta(minutes=1)
		CVEMatch.objects.filter(pk=self.hot.pk).update(distro_status='vulnerable', remediation_status='false_positive', created_at=timezone.now())
		with mock.patch('cveFeed.notify._send', return_value=True) as sent:
			notify.fire_matches(since)
		sent.assert_not_called()
		CVEMatch.objects.filter(pk=self.hot.pk).update(remediation_status='open')
		with mock.patch('cveFeed.notify._send', return_value=True) as sent:
			notify.fire_matches(since)
		sent.assert_called_once()  # the same match, open, is paged: the closed status was the only difference

	def test_a_report_lists_it_only_with_closed_findings_and_prints_the_note(self):
		from cveFeed import report_data, report_pdf
		self.close('match', self.hot, note='the port answers with a decoy banner')
		shown = report_data.collect(self.proj)
		self.assertNotIn('CVE-2099-7', json.dumps(shown['findings']))
		everything = report_data.collect(self.proj, include_closed=True)
		entry = next(f for f in everything['findings'] if 'CVE-2099-7' in f['title'])
		self.assertEqual((entry['tracking']['status'], entry['tracking']['note'], entry['tracking']['closed']),
		                 ('False positive', 'the port answers with a decoy banner', True))
		self.assertEqual(everything['summary']['status_counts'].get('False positive'), 1)
		html = report_pdf.build_html(everything)
		self.assertIn('False positive', html)
		self.assertIn('the port answers with a decoy banner', html)
		self.assertIn('Why it was closed', html)
		self.assertIn('false-positive findings are left out', report_pdf.build_html(shown))  # the cover says what was left out


class AutomaticClosureTests(Fixture, TestCase):
	def test_an_engine_closure_reads_back_as_an_automatic_closure_note_and_is_not_a_false_positive(self):
		from cveFeed import correlation
		correlation.close_invalid_correlation(self.match, 'Closed automatically: different product (the host only redirects to another site).')
		self.match.refresh_from_db()
		self.assertEqual((self.match.remediation_status, self.match.ai_verdict), ('open', 'not_affected'))
		row = call(self.t_alice, 'GET', f'{self.base}/matches?verdict=not_affected')[1]['results'][0]
		self.assertEqual(row['remediation_status'], 'open')
		self.assertTrue(row['closed_automatically'])
		self.assertTrue(row['closure_note'].startswith('Closed automatically: different product'))
		self.assertIsNone(row['closed_by'])
		d = call(self.t_alice, 'GET', f'{self.base}/findings/match/{self.match.id}')[1]
		self.assertTrue(d['remediation']['closed_automatically'])

	def test_a_persons_closure_wins_over_the_engines(self):
		CVEMatch.objects.filter(pk=self.match.pk).update(ai_verdict='not_affected', ai_reason='Closed automatically: no version evidence')
		data = call(self.t_alice, 'PATCH', f'{self.base}/findings/match/{self.match.id}', {'status': 'false_positive', 'note': 'checked by hand'})[1]
		self.assertEqual((data['closure_note'], data['closed_automatically']), ('checked by hand', False))

	def test_scanner_and_hygiene_findings_the_pipeline_closed_say_so(self):
		Vulnerability.objects.filter(pk=self.vuln.pk).update(open_status=False)
		HygieneFinding.objects.filter(pk=self.hyg.pk).update(status='resolved', resolved_at=timezone.now())
		v = call(self.t_alice, 'GET', f'{self.base}/findings/vulnerability/{self.vuln.id}')[1]
		h = call(self.t_alice, 'GET', f'{self.base}/findings/hygiene/{self.hyg.id}')[1]
		self.assertEqual((v['closure_note'], v['closed_automatically']), (closure.VULNERABILITY_GONE, True))
		self.assertEqual((h['closure_note'], h['closed_automatically']), (closure.HYGIENE_RESOLVED, True))
		self.assertIsNotNone(h['closed_at'])


class McpTests(Fixture, TestCase):
	def tools(self):
		return {t['name']: t for t in rpc(self.t_alice, 'tools/list')[1]['result']['tools']}

	def test_every_status_tool_offers_false_positive_and_says_what_the_note_is(self):
		tools = self.tools()
		for name in ('update_remediation_status', 'update_finding_status', 'bulk_update_finding_status'):
			schema = tools[name]['inputSchema']['properties']
			self.assertIn('false_positive', schema['status']['enum'], name)
			self.assertIn('false_positive', tools[name]['description'], name)
			self.assertIn('2000', schema['note']['description'], name)
		self.assertIn('false_positive', tools['set_supplier_finding_status']['inputSchema']['properties']['status']['enum'])
		self.assertIn('false_positive', tools['list_supplier_findings']['inputSchema']['properties']['status']['enum'])
		self.assertIn('false_positive', tools['list_findings']['inputSchema']['properties']['status']['enum'])
		self.assertIn('closed', tools['list_findings']['inputSchema']['properties']['status']['enum'])

	def test_the_tools_close_with_a_note(self):
		err, data = tool_call(self.t_alice, 'update_remediation_status', {'project': 'fp-proj', 'match_id': self.match.id, 'status': 'false_positive', 'note': 'n1'})
		self.assertEqual((err, data['remediation_status'], data['closure_note']), (False, 'false_positive', 'n1'))
		err, data = tool_call(self.t_alice, 'update_finding_status', {'project': 'fp-proj', 'kind': 'hygiene', 'id': self.hyg.id, 'status': 'false_positive', 'note': 'n2'})
		self.assertEqual((err, data['closure_note']), (False, 'n2'))
		err, data = tool_call(self.t_alice, 'bulk_update_finding_status', {'project': 'fp-proj', 'items': [{'kind': 'vulnerability', 'id': self.vuln.id}],
		                                                                  'status': 'false_positive', 'note': 'n3'})
		self.assertEqual((err, data['updated']), (False, 1))
		err, data = tool_call(self.t_alice, 'list_findings', {'project': 'fp-proj', 'status': 'false_positive'})
		self.assertEqual((err, data['total']), (False, 3))
		err, _ = tool_call(self.t_viewer, 'update_finding_status', {'project': 'fp-proj', 'kind': 'hygiene', 'id': self.hyg.id, 'status': 'fixed'})
		self.assertTrue(err)


class SupplierTests(Fixture, TestCase):
	def setUp(self):
		self.supplier = Supplier.objects.create(project=self.proj, name='Acme', tier='normal', domains=['portal.vendor.test'], added_by=self.admin)
		self.row = SupplierFinding.objects.create(supplier=self.supplier, domain='portal.vendor.test', check_name='hsts_missing', severity=2,
		                                          title='No HSTS', category='web')
		self.url = f'{self.base}/suppliers/findings/{self.row.id}'

	def test_a_supplier_finding_closes_as_a_false_positive_with_a_note_audited(self):
		self.assertEqual(call(self.t_alice, 'PATCH', self.url, {'status': 'false_positive'})[0], 403)  # needs the org admin, as accepting does
		self.assertEqual(call(self.t_viewer, 'PATCH', self.url, {'status': 'false_positive'})[0], 403)
		status, data = call(self.t_admin, 'PATCH', self.url, {'status': 'false_positive', 'note': ' HSTS is set on the apex \x07'})
		self.assertEqual(status, 200, data)
		self.assertEqual((data['status'], data['status_note'], data['closure_note'], data['closed_by']['username']),
		                 ('false_positive', 'HSTS is set on the apex', 'HSTS is set on the apex', 'fpadmin'))
		self.assertIsNotNone(data['closed_at'])
		entry = AuditLog.objects.filter(action='project.supplier.finding').latest('id')
		self.assertEqual((entry.detail['status'], entry.detail['before'], entry.detail['note']), ('false_positive', 'open', 'HSTS is set on the apex'))
		get = lambda q='': call(self.t_alice, 'GET', f'{self.base}/suppliers/findings{q}')[1]['count']
		self.assertEqual((get(), get('?status=false_positive'), get('?status=all')), (0, 1, 1))
		self.assertEqual(call(self.t_admin, 'PATCH', self.url, {'status': 'accepted', 'note': 'x' * 2001})[0], 400)
		self.assertEqual(call(self.t_admin, 'PATCH', self.url, {'status': 'accepted', 'note': 'y' * 2000})[0], 200)

	def test_the_supplier_list_counts_false_positives_apart(self):
		call(self.t_admin, 'PATCH', self.url, {'status': 'false_positive'})
		rows = call(self.t_alice, 'GET', f'{self.base}/suppliers')[1]['results']
		self.assertEqual((rows[0]['findings']['open'], rows[0]['findings']['false_positive']), (0, 1))

	def test_mcp_closes_a_supplier_finding_as_a_false_positive(self):
		err, data = tool_call(self.t_admin, 'set_supplier_finding_status', {'project': 'fp-proj', 'finding': self.row.id, 'status': 'false_positive', 'note': 'n'})
		self.assertEqual((err, data['status'], data['closure_note']), (False, 'false_positive', 'n'))
