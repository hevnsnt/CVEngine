from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc

NOW = timezone.now()


class UnifiedFindingsTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Widgets', slug='widgets')
		cls.pa = Project.objects.create(name='Acme', slug='uf-a', insert_date=NOW, org=org)
		cls.pb = Project.objects.create(name='Other', slug='uf-b', insert_date=NOW, org=org)
		cls.da = Domain.objects.create(name='acme.example', project=cls.pa, insert_date=NOW)
		cls.db = Domain.objects.create(name='other.example', project=cls.pb, insert_date=NOW)
		cls.www = Subdomain.objects.create(name='www.acme.example', target_domain=cls.da)
		cls.api = Subdomain.objects.create(name='api.acme.example', target_domain=cls.da)
		kev = CVEEntry.objects.create(cve_id='CVE-2099-7001', kev=True, cvss=9.8, title='t', published_at=NOW)
		mild = CVEEntry.objects.create(cve_id='CVE-2099-7002', cvss=5.0, title='t', published_at=NOW)
		cls.fire_match = CVEMatch.objects.create(cve_entry=kev, subdomain=cls.www, matched_product='nginx', matched_version='1.18.0')
		cls.ice_match = CVEMatch.objects.create(cve_entry=mild, subdomain=cls.api, matched_product='php')
		cls.ruled_out = CVEMatch.objects.create(cve_entry=mild, subdomain=cls.www, ai_verdict='not_affected')

		def vuln(name, severity, sub=cls.www, domain=cls.da, open_status=True):
			return Vulnerability.objects.create(name=name, severity=severity, subdomain=sub, target_domain=domain,
												open_status=open_status, discovered_date=NOW, http_url=f'https://{sub.name}/')
		cls.high = vuln('Exposed admin panel', 3)
		cls.medium = vuln('Directory listing', 2, sub=cls.api)
		cls.info = vuln('Server banner', 0)
		cls.closed = vuln('Old XSS', 4, open_status=False)
		cls.weak_dmarc = HygieneFinding.objects.create(domain=cls.da, host='acme.example', check_name='dmarc_none', severity=2,
													   title='DMARC policy is none', status='open')
		cls.hyg_info = HygieneFinding.objects.create(domain=cls.da, host='acme.example', check_name='mta_sts_missing',
													 severity=0, title='No MTA-STS', status='open')
		other = Subdomain.objects.create(name='www.other.example', target_domain=cls.db)
		vuln('Other project finding', 4, sub=other, domain=cls.db)
		cls.alice, cls.root = User.objects.create_user('uf-alice', password='x'), User.objects.create_superuser('uf-root', 'r@x.io', 'x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		_, cls.token = create_token(cls.alice, 'uf')
		_, cls.root_token = create_token(cls.root, 'uf-root')

	def get(self, project='uf-a', token=None, **params):
		query = '&'.join(f'{k}={v}' for k, v in params.items())
		status, body = call(token or self.token, 'GET', f'/api/v1/projects/{project}/findings?{query}')
		self.assertEqual(status, 200, body)
		return body

	def keys(self, body):
		return [(r['type'], r['id']) for r in body['results']]

	def test_actionable_merges_the_three_types_hottest_first(self):
		body = self.get()
		# heat, then severity, then newest first: the hygiene finding was seen after the scanner finding of equal rank
		self.assertEqual(self.keys(body), [('cve', self.fire_match.id), ('scanner', self.high.id), ('hygiene', self.weak_dmarc.id),
										   ('scanner', self.medium.id), ('cve', self.ice_match.id)])
		self.assertEqual([r['heat'] for r in body['results']], ['fire', 'fire', 'smoke', 'smoke', 'ice'])
		self.assertEqual(body['counts'], {'cve': 2, 'scanner': 2, 'hygiene': 1})
		self.assertEqual((body['count'], body['total'], body['truncated']), (5, 5, False))
		first = body['results'][0]
		self.assertEqual((first['kind'], first['title'], first['host'], first['severity']), ('match', 'CVE-2099-7001', 'www.acme.example', 'critical'))
		self.assertIn('triage', first)

	def test_the_heat_counts_reconcile_with_the_host_card(self):
		from agentapi.services import _heat_reasons
		for sub in (self.www, self.api):
			card = sorted(r['temp'] for r in _heat_reasons(Subdomain.objects.get(pk=sub.pk)))
			listed = sorted(r['heat'] for r in self.get(host=sub.name, type='all')['results'] if r['type'] != 'hygiene')
			self.assertEqual(listed, card, sub.name)

	def test_status_all_adds_informational_closed_and_ruled_out(self):
		body = self.get(status='all')
		found = set(self.keys(body))
		self.assertTrue({('scanner', self.info.id), ('scanner', self.closed.id), ('cve', self.ruled_out.id),
						 ('hygiene', self.hyg_info.id)} <= found)
		self.assertEqual(body['total'], 9)

	def test_facets_compose(self):
		self.assertEqual(self.keys(self.get(type='scanner')), [('scanner', self.high.id), ('scanner', self.medium.id)])
		self.assertEqual(self.keys(self.get(heat='smoke')), [('hygiene', self.weak_dmarc.id), ('scanner', self.medium.id)])
		self.assertEqual(self.keys(self.get(severity='critical')), [('cve', self.fire_match.id)])
		self.assertEqual(self.keys(self.get(type='hygiene', status='all', severity='info')), [('hygiene', self.hyg_info.id)])
		self.assertEqual(self.get(heat='fire')['counts'], {'cve': 1, 'scanner': 1, 'hygiene': 0})
		self.assertEqual(self.keys(self.get(host='api.')), [('scanner', self.medium.id), ('cve', self.ice_match.id)])

	def test_pages_split_the_merged_order(self):
		first, second = self.get(page_size=2), self.get(page_size=2, page=2)
		self.assertEqual(self.keys(first) + self.keys(second), self.keys(self.get())[:4])

	def test_a_member_sees_only_their_project_and_all_projects_tags_rows(self):
		status, _ = call(self.token, 'GET', '/api/v1/projects/uf-b/findings')
		self.assertIn(status, (403, 404))
		mine = self.get(project='_all')
		self.assertEqual({r['project'] for r in mine['results']}, {'uf-a'})
		everything = self.get(project='_all', token=self.root_token)
		self.assertEqual({r['project'] for r in everything['results']}, {'uf-a', 'uf-b'})
		self.assertEqual(everything['counts']['scanner'], 3)

	def test_bad_facets_are_400_and_mcp_lists_the_same(self):
		for param in ('type=nope', 'heat=warm', 'severity=huge', 'status=open', 'page=x'):
			self.assertEqual(call(self.token, 'GET', f'/api/v1/projects/uf-a/findings?{param}')[0], 400, param)
		status, body = rpc(self.token, 'tools/call', {'name': 'list_findings', 'arguments': {'project': 'uf-a'}})
		self.assertEqual(status, 200)
		self.assertIn('CVE-2099-7001', str(body))

	def test_the_cap_bounds_the_pages_not_the_counts(self):
		from unittest import mock
		with mock.patch('agentapi.services.MAX_FINDINGS', 3):
			body = self.get(page_size=2, page=2)
			beyond = self.get(page_size=2, page=3)
		self.assertEqual((body['count'], body['total'], body['truncated'], len(body['results'])), (3, 5, True, 1))
		self.assertEqual(beyond['results'], [])
