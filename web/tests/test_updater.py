import json
import os
import tempfile

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings

from cveFeed import updater
from cveFeed.models import UpdateSettings
from tests.test_tenancy import client_for

OLD, NEW = 'a' * 40, 'b' * 40


class FakeResp:
	def __init__(self, status, data=None):
		self.status_code, self._data = status, data or {}

	def json(self):
		return self._data


def fake_github(head=NEW, compare=None, head_status=200, compare_status=200):
	def get(url, headers=None, timeout=None):
		if '/compare/' in url:
			return FakeResp(compare_status, compare or {})
		return FakeResp(head_status, {'sha': head, 'html_url': f'https://github.com/o/r/commit/{head}',
									  'commit': {'message': 'Fix the thing\n\nbody', 'committer': {'date': '2026-10-23T10:00:00Z'}}})
	return get


class FetchTests(TestCase):
	def test_head_and_compare(self):
		compare = {'status': 'ahead', 'ahead_by': 2, 'commits': [  # GitHub lists oldest first
			{'sha': 'd' * 40, 'commit': {'message': 'older'}}, {'sha': 'c' * 40, 'commit': {'message': 'newer'}}]}
		found = updater.fetch_latest('o/r', 'master', installed=OLD, get=fake_github(compare=compare))
		self.assertEqual((found['sha'], found['message'], found['behind_by']), (NEW, 'Fix the thing', 2))
		self.assertEqual([c['message'] for c in found['commits']], ['newer', 'older'])  # shown newest first

	def test_installed_is_latest_or_ahead(self):
		self.assertEqual(updater.fetch_latest('o/r', 'm', installed=NEW, get=fake_github())['behind_by'], 0)
		self.assertEqual(updater.fetch_latest('o/r', 'm', installed=OLD, get=fake_github(compare={'status': 'behind'}))['behind_by'], 0)

	def test_unknown_installed_and_errors(self):
		self.assertIsNone(updater.fetch_latest('o/r', 'm', get=fake_github())['behind_by'])
		for status, text in ((404, 'not found'), (403, 'refused'), (500, '500')):
			with self.assertRaises(updater.UpdateError) as ctx:
				updater.fetch_latest('o/r', 'm', get=fake_github(head_status=status))
			self.assertIn(text, str(ctx.exception))

	def test_names_are_validated_before_any_request(self):
		def boom(*a, **k):
			raise AssertionError('no request expected')
		for repo, branch in (('../x/y', 'm'), ('o/r', '../main'), ('o/r;rm', 'm'), ('o', 'm'), ('o/r', '-x'), ('o/r', 'a b')):
			with self.assertRaises(updater.UpdateError):
				updater.fetch_latest(repo, branch, get=boom)


class StateTests(TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		override = override_settings(BASE_DIR=self.dir)
		override.enable()
		self.addCleanup(override.disable)
		self.admin = User.objects.create_superuser('root', 'r@x.test', 'x')

	def install(self, sha):
		with open(os.path.join(self.dir, '.commit'), 'w') as f:
			f.write(sha + '\n')

	def test_check_approve_apply_cycle(self):
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertEqual(updater.state(row)['status'], 'available')
		updater.approve(row, self.admin)
		self.assertEqual(updater.state(row)['status'], 'approved')
		with open(os.path.join(self.dir, '.update-approved')) as f:
			self.assertEqual(f.read().strip(), NEW)
		self.install(NEW)  # the host script finished
		row = updater.check(row, get=fake_github())
		self.assertEqual(updater.state(row)['status'], 'up_to_date')
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
		self.assertEqual(row.approved_sha, '')

	def test_approve_needs_something_newer(self):
		self.install(NEW)
		row = updater.check(get=fake_github())
		with self.assertRaises(updater.UpdateError):
			updater.approve(row, self.admin)
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))

	def test_dismiss_hides_until_a_newer_commit(self):
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		updater.dismiss(row)
		self.assertEqual(updater.state(row)['status'], 'dismissed')
		row = updater.check(row, get=fake_github(head='c' * 40, compare={'status': 'ahead', 'ahead_by': 2, 'commits': []}))
		self.assertEqual(updater.state(row)['status'], 'available')

	def test_failed_check_keeps_the_last_result_and_reports(self):
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		row = updater.check(row, get=fake_github(head_status=500))
		self.assertEqual(row.latest_sha, NEW)
		self.assertIn('500', updater.state(row)['last_error'])

	def test_installed_unknown_still_offers_the_latest(self):
		row = updater.check(get=fake_github())
		state = updater.state(row)
		self.assertEqual((state['status'], state['installed_known']), ('available', False))


class UpdatesApiTests(TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		override = override_settings(BASE_DIR=self.dir)
		override.enable()
		self.addCleanup(override.disable)
		self.admin = User.objects.create_superuser('root', 'r@x.test', 'x')
		self.member = User.objects.create_user('member', password='x')

	def test_superuser_only_and_token_is_write_only(self):
		anon, member, admin = Client(), client_for(self.member), client_for(self.admin)
		self.assertEqual(anon.get('/cve/api/settings/updates').status_code, 302)  # login middleware redirects anonymous users
		self.assertEqual(member.get('/cve/api/settings/updates').status_code, 403)
		put = admin.put('/cve/api/settings/updates', json.dumps({'repo': 'o/r', 'branch': 'main', 'token': 'ghp_secret'}), content_type='application/json')
		self.assertEqual(put.status_code, 200)
		self.assertNotIn('ghp_secret', put.content.decode())
		self.assertTrue(put.json()['has_token'])
		self.assertEqual(UpdateSettings.current().token, 'ghp_secret')
		bad = admin.put('/cve/api/settings/updates', json.dumps({'repo': 'not a repo'}), content_type='application/json')
		self.assertEqual(bad.status_code, 400)

	def test_approve_without_an_update_is_refused(self):
		admin = client_for(self.admin)
		self.assertEqual(admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json').status_code, 400)
