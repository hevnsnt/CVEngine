"""The same script on sibling subdomains is one finding: the grouped Findings list (cveFeed.finding_groups, list_findings group=cve)."""
from django.contrib.auth.models import User
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import finding_groups as fg
from cveFeed.models import CVEEntry, CVEMatch, FindingAuditEvent, Triage
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()
SIBLINGS = ('www', 'blog', 'info', 'careers', 'bgu', 'givinggrace')
SHA_A, SHA_B = 'a' * 64, 'b' * 64


class RegistrableDomainTests(SimpleTestCase):
	def test_sibling_hosts_share_their_registrable_domain(self):
		self.assertEqual(fg.registrable_domain('givinggrace.mybluegrace.com'), 'mybluegrace.com')
		self.assertEqual(fg.registrable_domain('WWW.MyBlueGrace.com.'), 'mybluegrace.com')
		self.assertEqual(fg.registrable_domain('a.b.example.co.uk'), 'example.co.uk')
		self.assertEqual(fg.registrable_domain('shop.example.com.au'), 'example.com.au')

	def test_tenants_of_a_shared_domain_and_addresses_are_their_own_site(self):
		self.assertEqual(fg.registrable_domain('acme.github.io'), 'acme.github.io')
		self.assertEqual(fg.registrable_domain('acme.azurewebsites.net'), 'acme.azurewebsites.net')
		self.assertEqual(fg.registrable_domain('10.0.0.5'), '10.0.0.5')
		self.assertEqual(fg.registrable_domain('intranet'), 'intranet')

	def test_an_unknown_suffix_uses_the_last_two_labels(self):
		self.assertEqual(fg.registrable_domain('a.corp.local'), 'corp.local')

	def test_script_identity_prefers_the_hash_then_the_path_then_the_library(self):
		row = {'script_sha256': SHA_A.upper(), 'script_url': 'https://www.x.com/js/jq.js'}
		self.assertEqual(fg.script_identity(row, 'x.com'), ('sha256', SHA_A))
		self.assertEqual(fg.script_identity({'script_url': 'https://www.x.com/js/jq.js?ver=1'}, 'x.com'), ('script_path', '/js/jq.js'))
		self.assertEqual(fg.script_identity({'script_url': 'https://code.jquery.com/jquery-3.2.1.min.js'}, 'x.com'),
						 ('script_url', 'code.jquery.com/jquery-3.2.1.min.js'))
		self.assertEqual(fg.script_identity({'script_sha256': 'not-a-hash'}, 'x.com'), ('library', ''))
		self.assertEqual(fg.script_identity({}, 'x.com'), ('library', ''))

	def test_only_version_based_web_fingerprints_without_hard_evidence_group(self):
		base = {'source': 'tech', 'matched_version': '3.2.1', 'subdomain__name': 'www.x.com', 'subdomain__target_domain__project_id': 1}
		self.assertTrue(fg.is_groupable(base))
		for change in ({'source': 'port'}, {'source': 'host'}, {'source': 'cpe'}, {'matched_version': ''}, {'subdomain__name': ''},
					   {'template_result': 'vulnerable'}, {'triage__validation_status': 'hit'}, {'triage__classification': 'confirmed'}):
			self.assertFalse(fg.is_groupable({**base, **change}), change)
		for fine in ({'template_result': 'no_match'}, {'triage__validation_status': 'clean'}, {'triage__classification': 'needs_validation'}):
			self.assertTrue(fg.is_groupable({**base, **fine}), fine)


class GroupedFindingsTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.org = Org.objects.create(name='Grace', slug='grace')
		cls.other_org = Org.objects.create(name='Zebra', slug='zebra-org')
		cls.pa = Project.objects.create(name='Bluegrace', slug='fg-a', insert_date=NOW, org=cls.org)
		cls.pb = Project.objects.create(name='Sibling project', slug='fg-b', insert_date=NOW, org=cls.org)
		cls.pz = Project.objects.create(name='Zebra', slug='fg-z', insert_date=NOW, org=cls.other_org)
		cls.da = Domain.objects.create(name='mybluegrace.com', project=cls.pa, insert_date=NOW)
		cls.dao = Domain.objects.create(name='othersite.org', project=cls.pa, insert_date=NOW)
		cls.db = Domain.objects.create(name='sister.mybluegrace.com', project=cls.pb, insert_date=NOW)  # one name per organization
		cls.dz = Domain.objects.create(name='mybluegrace.com', project=cls.pz, insert_date=NOW)
		cls.c23 = CVEEntry.objects.create(cve_id='CVE-2020-11023', cvss=6.1, title='jQuery', published_at=NOW)
		cls.c22 = CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.1, title='jQuery', published_at=NOW)
		cls.hosts = {name: Subdomain.objects.create(name=f'{name}.mybluegrace.com', target_domain=cls.da) for name in SIBLINGS}
		cls.m23 = {name: cls.jq(cls.c23, sub) for name, sub in cls.hosts.items()}
		cls.m22 = {name: cls.jq(cls.c22, sub) for name, sub in cls.hosts.items()}
		cls.elsewhere = cls.jq(cls.c23, Subdomain.objects.create(name='www.othersite.org', target_domain=cls.dao))
		cls.port = CVEMatch.objects.create(cve_entry=cls.c23, subdomain=cls.hosts['www'], matched_product='jquery', matched_version='3.2.1',
										   source='port')
		cls.vuln = Vulnerability.objects.create(name='Exposed admin', severity=2, subdomain=cls.hosts['www'], target_domain=cls.da,
												open_status=True, discovered_date=NOW, http_url='https://www.mybluegrace.com/')
		# hosts of the same site in a sibling project, and the same names in another organization
		for domain, names in ((cls.db, ('a.sister', 'b.sister')), (cls.dz, ('www', 'blog'))):
			for name in names:
				cls.jq(cls.c23, Subdomain.objects.create(name=f'{name}.mybluegrace.com', target_domain=domain))
		cls.alice, cls.auditor, cls.root = (User.objects.create_user('fg-alice', password='x'), User.objects.create_user('fg-audit', password='x'),
											User.objects.create_superuser('fg-root', 'r@x.io', 'x'))
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=cls.auditor, project=cls.pa, role='audit')
		_, cls.token = create_token(cls.alice, 'fg')
		_, cls.audit_token = create_token(cls.auditor, 'fg-audit')
		_, cls.root_token = create_token(cls.root, 'fg-root')

	@staticmethod
	def jq(cve, sub, **evidence):
		return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='jquery', matched_version='3.2.1', source='tech',
									   evidence={'source': 'tech', 'raw_version': '3.2.1', **evidence})

	def get(self, project='fg-a', token=None, **params):
		query = '&'.join(f'{k}={v}' for k, v in params.items())
		status, body = call(token or self.token, 'GET', f'/api/v1/projects/{project}/findings?{query}')
		self.assertEqual(status, 200, body)
		return body

	def groups(self, body):
		return [r for r in body['results'] if r.get('group')]

	def group_of(self, body, cve_id):
		found = [r for r in self.groups(body) if r['title'] == cve_id]
		self.assertEqual(len(found), 1, [r['title'] for r in self.groups(body)])
		return found[0]['group']

	def test_the_default_stays_one_row_per_host(self):
		body = self.get(type='cve')
		self.assertEqual(len(body['results']), 14)  # 6 + 6 siblings, othersite, the port match
		self.assertNotIn('group', body)
		self.assertFalse(any('group' in r for r in body['results']))

	def test_one_script_on_six_sibling_hosts_is_one_row_per_cve(self):
		body = self.get(type='cve', group='cve')
		self.assertEqual(body['group'], 'cve')
		self.assertEqual(body['counts']['cve'], 14)  # still per host finding
		self.assertEqual(body['findings_total'], 14)
		self.assertEqual(body['row_counts']['cve'], 4)  # the two groups, othersite on its own, the port match on its own
		self.assertEqual((body['total'], body['count'], len(body['results'])), (4, 4, 4))
		self.assertEqual((body['groups'], body['grouped_findings']), (2, 12))
		for cve_id, matches in (('CVE-2020-11023', self.m23), ('CVE-2020-11022', self.m22)):
			group = self.group_of(body, cve_id)
			self.assertEqual(sorted(group['member_ids']), sorted(m.id for m in matches.values()))
			self.assertEqual((group['hosts'], group['findings']), (6, 6))
			self.assertEqual(group['registrable_domain'], 'mybluegrace.com')
			self.assertEqual(group['identity'], 'library')
			self.assertEqual({m['host'] for m in group['members']}, {f'{n}.mybluegrace.com' for n in SIBLINGS})
			self.assertEqual(group['status_counts'], {'open': 6})
			self.assertIsNotNone(group['first_seen'])
		singles = [r for r in body['results'] if not r.get('group')]
		self.assertEqual({r['id'] for r in singles}, {self.elsewhere.id, self.port.id})

	def test_each_member_keeps_its_own_status_and_the_group_shows_the_split(self):
		hot = self.m23['blog']
		hot.cve_entry = CVEEntry.objects.create(cve_id='CVE-2099-0001', cvss=9.8, kev=True, title='t', published_at=NOW)
		hot.save()
		other = self.m23['info']
		other.remediation_status = 'in_progress'
		other.save()
		body = self.get(type='cve', group='cve')
		group = self.group_of(body, 'CVE-2020-11023')
		self.assertEqual(group['findings'], 5)  # a different CVE is a different finding
		self.assertEqual(group['status_counts'], {'open': 4, 'in_progress': 1})
		self.assertEqual(next(m for m in group['members'] if m['id'] == other.id)['status'], 'in_progress')

	def test_the_representative_is_the_hottest_member(self):
		self.c23.kev = True  # every member is hot ...
		self.c23.save()
		careers = self.m23['careers']  # ... but the distribution patched the others, which reads as ice: careers is the hottest
		CVEMatch.objects.filter(pk__in=[m.id for n, m in self.m23.items() if n != 'careers']).update(distro_status='patched')
		body = self.get(type='cve', group='cve')
		row = next(r for r in self.groups(body) if r['title'] == 'CVE-2020-11023')
		self.assertEqual(row['id'], careers.id)
		self.assertEqual(row['host'], 'careers.mybluegrace.com')
		heats = {m['id']: m['heat'] for m in row['group']['members']}
		self.assertEqual(heats.pop(careers.id), row['heat'])
		self.assertEqual(set(heats.values()), {'ice'})
		self.assertNotEqual(row['heat'], 'ice')
		self.assertEqual(row['group']['heat_counts']['ice'], 5)

	def test_a_host_with_hard_evidence_is_never_folded_in(self):
		proven = self.m23['bgu']
		proven.template_result = 'vulnerable'
		proven.save()
		Triage.objects.create(project=self.pa, domain=self.da, host='givinggrace.mybluegrace.com', kind='cve_match',
							  match=self.m23['givinggrace'], status='triaged', classification='confirmed', validation_status='hit')
		body = self.get(type='cve', group='cve')
		group = self.group_of(body, 'CVE-2020-11023')
		self.assertEqual(group['findings'], 4)
		self.assertNotIn(proven.id, group['member_ids'])
		self.assertNotIn(self.m23['givinggrace'].id, group['member_ids'])
		singles = {r['id'] for r in body['results'] if not r.get('group')}
		self.assertTrue({proven.id, self.m23['givinggrace'].id} <= singles)

	def test_different_script_files_are_different_groups(self):
		CVEMatch.objects.filter(pk__in=[self.m23[n].id for n in ('www', 'blog', 'info')]).update(
			evidence={'source': 'tech', 'script_sha256': SHA_A, 'script_url': 'https://www.mybluegrace.com/js/jquery.js'})
		CVEMatch.objects.filter(pk__in=[self.m23[n].id for n in ('careers', 'bgu')]).update(
			evidence={'source': 'tech', 'script_sha256': SHA_B})
		body = self.get(type='cve', group='cve')
		by_identity = {tuple(sorted(r['group']['member_ids'])): r['group'] for r in self.groups(body) if r['title'] == 'CVE-2020-11023'}
		self.assertIn(tuple(sorted(self.m23[n].id for n in ('www', 'blog', 'info'))), by_identity)
		self.assertIn(tuple(sorted(self.m23[n].id for n in ('careers', 'bgu'))), by_identity)
		self.assertEqual({g['identity'] for g in by_identity.values()}, {'sha256'})
		# givinggrace has neither field: it stays on its own, it is not joined to either file
		self.assertIn(self.m23['givinggrace'].id, {r['id'] for r in body['results'] if not r.get('group')})

	def test_the_same_path_on_sibling_hosts_is_one_file_and_another_path_is_not(self):
		for name in ('www', 'blog'):
			CVEMatch.objects.filter(pk=self.m23[name].id).update(evidence={'source': 'tech', 'script_url': f'https://{name}.mybluegrace.com/js/jq.js?ver=6.1'})
		CVEMatch.objects.filter(pk=self.m23['info'].id).update(evidence={'source': 'tech', 'script_url': 'https://info.mybluegrace.com/old/jq.js'})
		body = self.get(type='cve', group='cve')
		paths = {r['group']['script']: sorted(r['group']['member_ids']) for r in self.groups(body) if r['group']['identity'] == 'script_path'}
		self.assertEqual(paths, {'/js/jq.js': sorted([self.m23['www'].id, self.m23['blog'].id])})

	def test_a_group_never_crosses_projects_or_organizations(self):
		body = self.get(project='_all', token=self.root_token, type='cve', group='cve')
		for row in self.groups(body):
			projects = set(CVEMatch.objects.filter(pk__in=row['group']['member_ids'])
						   .values_list('subdomain__target_domain__project__slug', flat=True))
			self.assertEqual(projects, {row['project']})
		grouped_projects = sorted(r['project'] for r in self.groups(body) if r['title'] == 'CVE-2020-11023')
		self.assertEqual(grouped_projects, ['fg-a', 'fg-b', 'fg-z'])
		# a member of one project never sees another project's members in a group
		mine = self.get(project='_all', type='cve', group='cve')
		self.assertEqual({r['project'] for r in mine['results']}, {'fg-a'})
		visible = {i for r in self.groups(mine) for i in r['group']['member_ids']}
		self.assertFalse(visible & set(CVEMatch.objects.exclude(subdomain__target_domain__project=self.pa).values_list('id', flat=True)))

	def test_other_types_and_paging_mix_with_the_groups(self):
		body = self.get(group='cve')
		self.assertEqual(body['counts'], {'cve': 14, 'scanner': 1, 'hygiene': 0})
		self.assertEqual(body['row_counts'], {'cve': 4, 'scanner': 1, 'hygiene': 0})
		self.assertEqual(body['total'], 5)
		keys = [(r['type'], r['id']) for r in body['results']]
		first, second = self.get(group='cve', page_size=2), self.get(group='cve', page_size=2, page=2)
		self.assertEqual([(r['type'], r['id']) for r in first['results'] + second['results']], keys[:4])
		self.assertEqual(self.get(group='cve', page_size=0)['results'], [])

	def test_past_the_pass_cap_the_rest_stay_one_row_each_and_it_says_so(self):
		from unittest import mock
		full = [(r['type'], r['id']) for r in self.get(type='cve')['results']]  # the per-host order
		with mock.patch.object(fg, 'GROUP_SCAN_MAX', 4):
			body = self.get(type='cve', group='cve')
		self.assertTrue(body['group_scan_truncated'])
		read = full[:4]
		self.assertEqual(body['row_counts']['cve'], body['total'])
		listed = [(r['type'], r['id']) for r in body['results']]
		self.assertEqual(listed[-(14 - 4):], full[4:])  # the matches past the cap follow, one row each, in the list's order
		self.assertEqual(sum(len(r['group']['member_ids']) if r.get('group') else 1 for r in body['results']), 14)
		self.assertTrue(set(read) <= {(r['type'], i) for r in body['results'] for i in (r['group']['member_ids'] if r.get('group') else [r['id']])})

	def test_bad_group_is_400(self):
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/fg-a/findings?group=host')[0], 400)

	def test_queries_do_not_grow_with_hosts_or_groups(self):
		def count():
			with CaptureQueriesContext(connection) as ctx:
				self.get(type='cve', group='cve', page_size=50)
			return len(ctx.captured_queries)
		count()  # warm the per-process caches (access rules, internal ranges) so both measures see the same
		before = count()
		extra = CVEEntry.objects.create(cve_id='CVE-2099-0002', cvss=6.1, title='t', published_at=NOW)
		for i in range(30):
			sub = Subdomain.objects.create(name=f'h{i}.mybluegrace.com', target_domain=self.da)
			self.jq(self.c23, sub)
			self.jq(extra, sub)
			CVEMatch.objects.create(cve_entry=extra, subdomain=sub, matched_product='openssh', matched_version='8.0', source='port')
		self.assertEqual(count(), before)

	def test_mcp_list_findings_takes_group(self):
		error, body = tool_call(self.token, 'list_findings', {'project': 'fg-a', 'type': 'cve', 'group': 'cve'})
		self.assertFalse(error, body)
		self.assertEqual((body['groups'], body['row_counts']['cve'], body['counts']['cve']), (2, 4, 14))
		error, body = tool_call(self.token, 'list_findings', {'project': 'fg-a', 'type': 'cve'})
		self.assertFalse(error)
		self.assertNotIn('groups', body)

	def test_acting_on_a_group_goes_through_each_member_with_its_own_audit(self):
		group = self.group_of(self.get(type='cve', group='cve'), 'CVE-2020-11023')
		items = [{'kind': 'match', 'id': i} for i in group['member_ids']]
		status, body = call(self.token, 'POST', '/api/v1/projects/fg-a/findings/status', {'items': items, 'status': 'accepted_risk'})
		self.assertEqual(status, 200, body)
		self.assertEqual((body['updated'], body['failed']), (6, []))
		self.assertEqual(set(CVEMatch.objects.filter(pk__in=group['member_ids']).values_list('remediation_status', flat=True)), {'accepted_risk'})
		self.assertEqual(CVEMatch.objects.get(pk=self.m22['www'].id).remediation_status, 'open')  # the sibling CVE is its own group
		events = FindingAuditEvent.objects.filter(finding_kind='match', finding_id__in=group['member_ids'], event='status')
		self.assertEqual(sorted(events.values_list('finding_id', flat=True)), sorted(group['member_ids']))
		# accepted is no longer actionable: the group leaves the default list, and one host can be reopened on its own
		self.assertEqual(self.get(type='cve', group='cve')['groups'], 1)
		call(self.token, 'PATCH', f'/api/v1/projects/fg-a/findings/match/{self.m23["www"].id}', {'status': 'open'})
		self.assertEqual(CVEMatch.objects.get(pk=self.m23['blog'].id).remediation_status, 'accepted_risk')

	def test_the_role_gate_and_tenancy_hold_for_group_members(self):
		group = self.group_of(self.get(type='cve', group='cve'), 'CVE-2020-11023')
		items = [{'kind': 'match', 'id': i} for i in group['member_ids']]
		status, _ = call(self.audit_token, 'POST', '/api/v1/projects/fg-a/findings/status', {'items': items, 'status': 'fixed'})
		self.assertIn(status, (403, 404))
		self.assertEqual(set(CVEMatch.objects.filter(pk__in=group['member_ids']).values_list('remediation_status', flat=True)), {'open'})
		# another project's member ids posted under this project fail one by one, exactly like missing ones
		foreign = list(CVEMatch.objects.filter(subdomain__target_domain__project__in=[self.pb, self.pz]).values_list('id', flat=True))
		status, body = call(self.token, 'POST', '/api/v1/projects/fg-a/findings/status',
							{'items': [{'kind': 'match', 'id': i} for i in foreign], 'status': 'fixed'})
		self.assertEqual(status, 200)
		self.assertEqual((body['updated'], len(body['failed'])), (0, len(foreign)))
		self.assertFalse(CVEMatch.objects.filter(pk__in=foreign, remediation_status='fixed').exists())


class DashboardGroupCountTests(TestCase):
	def test_the_headline_keeps_host_findings_and_adds_the_grouped_count(self):
		from cveFeed.views import stats_payload
		org = Org.objects.create(name='Dash', slug='dash')
		project = Project.objects.create(name='Dash', slug='fg-dash', insert_date=NOW, org=org)
		domain = Domain.objects.create(name='example.com', project=project, insert_date=NOW)
		cve = CVEEntry.objects.create(cve_id='CVE-2020-11023', cvss=6.1, title='t', published_at=NOW)
		for name in ('www', 'blog', 'info'):
			GroupedFindingsTests.jq(cve, Subdomain.objects.create(name=f'{name}.example.com', target_domain=domain))
		payload = stats_payload()
		self.assertEqual(payload['matches'], 3)
		self.assertEqual(payload['match_groups'], 1)
