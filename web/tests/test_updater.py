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

	def heartbeat(self, age, raw=None):
		import time
		with open(os.path.join(self.dir, '.updater-heartbeat'), 'w') as f:
			f.write(raw if raw is not None else json.dumps({'at': time.time() - age}))

	def test_the_host_updater_is_reported_alive_stale_or_never_seen(self):
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertEqual(updater.state(row)['host_updater'], {'seen': False, 'alive': False, 'age_seconds': None})  # no file: never reported
		self.heartbeat(5)
		hu = updater.state(row)['host_updater']
		self.assertEqual((hu['seen'], hu['alive']), (True, True))
		self.assertLess(hu['age_seconds'], 30)
		self.heartbeat(updater.HEARTBEAT_ALIVE_SECONDS + 120)
		hu = updater.state(row)['host_updater']
		self.assertEqual((hu['seen'], hu['alive']), (True, False))  # it was there and stopped

	def test_a_heartbeat_file_that_is_not_the_expected_shape_counts_as_never_seen(self):
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		for raw in ('not json', '{}', '{"at": "soon"}', '{"at": 1e999}', '{"at": ' + str(10 ** 12) + '}', '[]'):
			self.heartbeat(0, raw=raw)
			self.assertFalse(updater.state(row)['host_updater']['seen'], raw)  # includes a time in the future

	def test_check_approve_apply_cycle(self):
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertEqual(updater.state(row)['status'], 'available')
		updater.approve(row, self.admin)
		self.assertEqual(updater.state(row)['status'], 'approved')
		with open(os.path.join(self.dir, '.update-approved')) as f:
			self.assertEqual(f.read().strip(), NEW)
		with open(os.path.join(self.dir, '.update-branch')) as f:  # the host moves its checkout to the branch chosen in Settings
			self.assertEqual(f.read().strip(), row.branch)
		self.install(NEW)  # the host script finished
		row = updater.check(row, get=fake_github())
		self.assertEqual(updater.state(row)['status'], 'up_to_date')
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-branch')))
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

	def test_state_defaults_to_an_idle_phase_with_no_phase_file(self):
		self.install(OLD)
		row = updater.check(get=fake_github())
		state = updater.state(row)
		self.assertEqual((state['phase'], state['phase_detail'], state['phase_scans_running'], state['phase_changed_at']),
						  ('idle', '', None, None))
		self.assertFalse(state['scans_paused_by_update'])

	def test_state_reads_the_phase_file_apply_update_sh_writes(self):
		self.install(OLD)
		row = updater.check(get=fake_github())
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			json.dump({'phase': 'draining', 'detail': 'waiting for 2 scan(s) to finish', 'scans_running': 2, 'changed_at': 1_800_000_000}, f)
		state = updater.state(row)
		self.assertEqual((state['phase'], state['phase_detail'], state['phase_scans_running']), ('draining', 'waiting for 2 scan(s) to finish', 2))
		self.assertTrue(state['phase_changed_at'].startswith('2027-01-15'))

	def test_a_malformed_or_unrecognized_phase_file_falls_back_to_idle(self):
		self.install(OLD)
		row = updater.check(get=fake_github())
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			f.write('not json')
		self.assertEqual(updater.state(row)['phase'], 'idle')
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			json.dump({'phase': 'not-a-real-phase'}, f)
		self.assertEqual(updater.state(row)['phase'], 'idle')

	def test_scans_paused_by_update_reads_scancontrol_live_not_the_phase_file(self):
		from cveFeed.models import ScanControl
		self.install(OLD)
		row = updater.check(get=fake_github())
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			json.dump({'phase': 'draining', 'detail': '', 'scans_running': 1, 'changed_at': 1_800_000_000}, f)
		self.assertFalse(updater.state(row)['scans_paused_by_update'])  # no row yet: not paused
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': True})
		self.assertTrue(updater.state(row)['scans_paused_by_update'])
		# an operator's own pause is not the update's pause, even while the phase file still says draining
		ScanControl.objects.update_or_create(pk=1, defaults={'paused': True, 'paused_by_update': False})
		self.assertFalse(updater.state(row)['scans_paused_by_update'])


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
