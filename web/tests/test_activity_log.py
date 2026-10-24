import json

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project, ProjectMembership
from tests.test_agentapi import call, rpc
from tests.test_tenancy import client_for


class ActivityLogTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org1, org2 = Org.objects.create(name='One', slug='one'), Org.objects.create(name='Two', slug='two')
		cls.pa = Project.objects.create(name='A', slug='act-a', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='act-b', insert_date=now, org=org2)
		cls.alice = User.objects.create_user('act-alice', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
		_, cls.tok = create_token(cls.alice, 'agent')
		for i in range(45):
			AgentActivity.objects.create(kind='scan' if i % 3 == 0 else 'feed', message=f'a line {i}', project=cls.pa,
			                             detail={'scan_id': 7} if i == 44 else {})
		AgentActivity.objects.create(kind='feed', message='system wide line', project=None)
		AgentActivity.objects.create(kind='feed', message='secret of project b', project=cls.pb)

	def get(self, query=''):
		return call(self.tok, 'GET', f'/api/v1/projects/act-a/activity{query}')

	def test_scoped_to_project_plus_system_rows(self):
		status, data = self.get('?page_size=100')
		self.assertEqual(status, 200)
		messages = [r['message'] for r in data['results']]
		self.assertIn('system wide line', messages)
		self.assertNotIn('secret of project b', messages)
		self.assertEqual(data['count'], 46)

	def test_other_project_is_not_visible(self):
		self.assertEqual(call(self.tok, 'GET', '/api/v1/projects/act-b/activity')[0], 404)

	def test_newest_first_and_paged(self):
		first = self.get('?page_size=20')[1]
		self.assertEqual(first['count'], 46)
		ids = [r['id'] for r in first['results']]
		self.assertEqual(len(ids), 20)
		self.assertEqual(ids, sorted(ids, reverse=True))
		self.assertEqual(first['results'][0]['message'], 'system wide line')
		self.assertIsNone(first['results'][0]['project'])
		third = self.get('?page_size=20&page=3')[1]
		self.assertEqual(len(third['results']), 6)
		self.assertLess(max(r['id'] for r in third['results']), min(ids))

	def test_kind_filter_and_validation(self):
		data = self.get('?kind=scan&page_size=100')[1]
		self.assertEqual(data['count'], 15)
		self.assertTrue(all(r['kind'] == 'scan' for r in data['results']))
		self.assertEqual(self.get('?kind=nope')[0], 400)

	def test_scan_id_and_repeat_exposed(self):
		AgentActivity.objects.filter(message='a line 44').update(repeat=3)
		row = next(r for r in self.get('?page_size=100')[1]['results'] if r['message'] == 'a line 44')
		self.assertEqual((row['scan_id'], row['repeat']), (7, 3))

	def test_mcp_tool(self):
		listed = rpc(self.tok, 'tools/list')[1]['result']['tools']
		self.assertIn('list_activity', [t['name'] for t in listed])
		status, body = rpc(self.tok, 'tools/call', {'name': 'list_activity', 'arguments': {'project': 'act-a', 'kind': 'scan'}})
		self.assertEqual(status, 200)
		self.assertFalse(body['result']['isError'])
		self.assertEqual(json.loads(body['result']['content'][0]['text'])['count'], 15)

	def test_activity_section_renders_for_members_only(self):
		c = client_for(self.alice)
		page = c.get('/cve/act-a/activity/')
		self.assertEqual(page.status_code, 200)
		self.assertContains(page, 'data-kind="activity"')
		self.assertContains(page, 'Activity')
		self.assertEqual(c.get('/cve/act-b/activity/').status_code, 404)
		self.assertEqual(Client().get('/cve/act-a/activity/').status_code, 302)

	def test_dashboard_starts_at_latest_100_then_polls_forward(self):
		AgentActivity.objects.bulk_create([
			AgentActivity(kind='validate', message=f'history {i}', project=self.pa) for i in range(150)
		])
		c = client_for(self.alice)
		initial = c.get('/cve/api/activity?after=0&project=act-a').json()['items']
		self.assertEqual(len(initial), 100)
		self.assertEqual([r['id'] for r in initial], sorted(r['id'] for r in initial))
		self.assertEqual(initial[0]['message'], 'history 50')
		self.assertEqual(initial[-1]['message'], 'history 149')
		cursor = initial[-1]['id']
		entry = AgentActivity.objects.create(kind='validate', message='running new check', project=self.pa, status='running')
		changed = c.get(f'/cve/api/activity?after={cursor}&project=act-a').json()['items']
		self.assertEqual([(r['id'], r['status']) for r in changed], [(entry.id, 'running')])
		entry.status = 'done'
		entry.finished_at = timezone.now()
		entry.save(update_fields=['status', 'finished_at'])
		settled = c.get(f'/cve/api/activity?after={entry.id}&running={entry.id}&project=act-a').json()
		self.assertEqual(settled['items'], [])
		self.assertEqual([(r['id'], r['status']) for r in settled['settled']], [(entry.id, 'done')])
		self.assertFalse(any(r['message'] == 'secret of project b' for r in initial + changed))

	def test_dashboard_empty_and_project_switch_are_scoped(self):
		c = client_for(self.alice)
		AgentActivity.objects.all().delete()
		self.assertEqual(c.get('/cve/api/activity?after=0&project=act-a').json()['items'], [])
		self.assertEqual(c.get('/cve/api/activity?project=act-b').status_code, 404)
