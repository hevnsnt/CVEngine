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

	MINE = 'c' * 40

	def host_state(self, **fields):
		"""What scripts/update-state.py upstream publishes for the build in .commit."""
		import time
		row = UpdateSettings.current()
		data = {'repo': row.repo, 'branch': row.branch, 'installed': self.MINE, 'upstream': NEW, 'base': OLD, 'ahead': 1, 'behind': 1, 'at': time.time(), **fields}
		with open(os.path.join(self.dir, '.upstream-state.json'), 'w') as f:
			json.dump(data, f)

	def github(self, ahead_by=1, known=(OLD,)):
		"""A GitHub that has the branch head and knows only the commits in ``known``."""
		asked = []

		def get(url, headers=None, timeout=None):
			asked.append(url)
			if '/compare/' in url:
				base = url.split('/compare/')[1].split('...')[0]
				if base not in known:
					return FakeResp(404)
				return FakeResp(200, {'status': 'ahead' if ahead_by else 'identical', 'ahead_by': ahead_by, 'commits': []})
			return FakeResp(200, {'sha': NEW, 'html_url': 'u', 'commit': {'message': 'm', 'committer': {'date': ''}}})
		get.asked = asked
		return get

	def test_a_server_with_commits_of_its_own_is_compared_by_the_commit_it_shares_with_the_branch(self):
		self.install(self.MINE)
		self.host_state(ahead=1, behind=0, base=NEW)  # the fork carries one commit and has merged everything upstream has
		get = self.github(ahead_by=0, known=(NEW,))
		row = updater.check(UpdateSettings.current(), get=get)
		self.assertEqual(row.behind_by, 0)  # the branch head is the commit they share: nothing to ask GitHub about
		state = updater.state(row)
		self.assertEqual((state['status'], state['local_commits'], state['installed']), ('up_to_date', 1, self.MINE[:7]))
		self.assertFalse(row.reference_unknown)

	def test_a_server_with_commits_of_its_own_and_a_branch_that_moved_is_diverged_and_cannot_be_approved(self):
		self.install(self.MINE)
		self.host_state()  # one commit of its own, one it lacks
		row = updater.check(UpdateSettings.current(), get=self.github(ahead_by=1))
		state = updater.state(row)
		self.assertEqual((state['status'], state['behind_by'], state['local_commits'], state['common']), ('diverged', 1, 1, OLD[:7]))
		with self.assertRaises(updater.UpdateError) as caught:
			updater.approve(row, self.admin)
		self.assertIn('merge', str(caught.exception))
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))

	def test_automatic_mode_does_not_approve_what_cannot_be_fast_forwarded(self):
		self.install(self.MINE)
		self.host_state()
		self.mode_file('auto')
		row = updater.check(UpdateSettings.current(), get=self.github(ahead_by=1))
		self.assertFalse(updater.auto_approve(row))
		self.assertEqual(row.approved_sha, '')

	def test_a_build_github_has_never_seen_is_unknown_not_behind(self):
		self.install(self.MINE)  # no host answer: nothing says which commit it shares with the branch
		row = updater.check(UpdateSettings.current(), get=self.github(ahead_by=1, known=()))
		state = updater.state(row)
		self.assertEqual(state['status'], 'unknown')
		self.assertTrue(row.reference_unknown)
		with self.assertRaises(updater.UpdateError):
			updater.approve(row, self.admin)
		self.assertFalse(updater.auto_approve(row))

	def test_a_failed_comparison_is_not_unknown_the_installed_commit_is_still_offered_the_latest(self):
		self.install(OLD)
		def get(url, headers=None, timeout=None):
			if '/compare/' in url:
				return FakeResp(502)
			return FakeResp(200, {'sha': NEW, 'html_url': 'u', 'commit': {'message': 'm', 'committer': {'date': ''}}})
		row = updater.check(UpdateSettings.current(), get=get)
		self.assertEqual((updater.state(row)['status'], row.reference_unknown), ('available', False))

	def test_the_check_tells_the_host_what_it_tracks(self):
		self.install(OLD)
		row = UpdateSettings.current()
		updater.check(row, get=self.github())
		with open(os.path.join(self.dir, '.update-source')) as f:
			self.assertEqual(f.read(), f'{row.repo} {row.branch}\n')

	def test_the_hosts_answer_is_used_only_when_it_is_about_this_source_and_this_build_and_recent(self):
		import time
		self.install(self.MINE)
		row = UpdateSettings.current()
		self.host_state()
		self.assertEqual(updater.upstream_state(row)[0]['ahead'], 1)
		self.host_state(branch='other')
		self.assertEqual(updater.upstream_state(row), (None, ''))
		self.host_state(repo='someone/else')
		self.assertEqual(updater.upstream_state(row), (None, ''))
		self.host_state(installed=OLD)  # the build before this one
		self.assertEqual(updater.upstream_state(row), (None, ''))
		self.host_state(at=time.time() - 4 * 86400)
		self.assertIn('days', updater.upstream_state(row)[1])
		self.host_state(ahead=-1)
		self.assertEqual(updater.upstream_state(row), (None, ''))
		self.host_state(base='zz')
		self.assertEqual(updater.upstream_state(row), (None, ''))

	def test_a_comparison_the_host_could_not_make_is_explained_not_guessed(self):
		self.install(self.MINE)
		self.host_state(error='could not fetch hevnsnt/CVEngine master (network, a private repository, or no such branch)')
		state = updater.state(UpdateSettings.current())
		self.assertIn('could not fetch', state['host_comparison'])
		self.assertIsNone(state['local_commits'])

	def heartbeat(self, age, raw=None):
		import time
		with open(os.path.join(self.dir, '.updater-heartbeat'), 'w') as f:
			f.write(raw if raw is not None else json.dumps({'at': time.time() - age}))

	def mode_file(self, text):
		with open(os.path.join(self.dir, '.update-mode'), 'w') as f:
			f.write(text)

	def test_updates_are_manual_unless_the_administrator_chose_automatic(self):
		self.assertEqual(updater.read_mode(), 'manual')  # no file: the default
		for odd in ('', 'AUTO', 'auto please', 'yes', 'manual', '1'):
			self.mode_file(odd)
			self.assertEqual(updater.read_mode(), 'manual', odd)
		updater.set_mode('auto')
		self.assertEqual(updater.read_mode(), 'auto')
		updater.set_mode('manual')
		self.assertEqual(updater.read_mode(), 'manual')
		with self.assertRaises(updater.UpdateError):
			updater.set_mode('whenever')
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertEqual(updater.state(row)['mode'], 'manual')

	def test_a_failure_left_by_an_earlier_update_is_not_shown_for_a_new_approval(self):
		import time
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			json.dump({'phase': 'failed', 'detail': 'approved commit is not on master', 'scans_running': None, 'changed_at': time.time() - 600}, f)
		self.assertEqual(updater.state(row)['phase'], 'failed')  # nothing approved since: the last result stands
		updater.approve(row, self.admin)
		state = updater.state(row)
		self.assertEqual((state['phase'], state['phase_detail']), ('idle', ''))  # this approval has not been acted on yet
		with open(os.path.join(self.dir, '.update-phase.json'), 'w') as f:
			json.dump({'phase': 'draining', 'detail': 'waiting', 'scans_running': 1, 'changed_at': time.time() + 1}, f)
		self.assertEqual(updater.state(row)['phase'], 'draining')  # the host has since reported on it

	def test_a_found_update_is_never_approved_in_manual_mode(self):
		self.install(OLD)
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertFalse(updater.auto_approve(row))
		self.assertEqual(updater.state(row)['status'], 'available')
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))

	def test_a_found_update_is_approved_for_them_in_automatic_mode(self):
		self.install(OLD)
		updater.set_mode('auto')
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertTrue(updater.auto_approve(row))
		state = updater.state(row)
		self.assertEqual((state['status'], row.approved_by), ('approved', 'automatic'))
		with open(os.path.join(self.dir, '.update-approved')) as f:
			self.assertEqual(f.read().strip(), NEW)
		self.assertFalse(updater.auto_approve(row))  # already approved: nothing more to do

	def test_a_dismissed_update_is_not_approved_even_in_automatic_mode(self):
		self.install(OLD)
		updater.set_mode('auto')
		row = updater.check(get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		updater.dismiss(row)
		self.assertFalse(updater.auto_approve(row))

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

	def put(self, client, **body):
		return client.put('/cve/api/settings/updates', json.dumps(body), content_type='application/json')

	def test_the_mode_is_set_in_settings_audited_and_defaults_to_manual(self):
		from dashboard.models import AuditLog
		admin = client_for(self.admin)
		self.assertEqual(admin.get('/cve/api/settings/updates').json()['mode'], 'manual')
		self.assertEqual(self.put(admin, mode='auto').json()['mode'], 'auto')
		self.assertEqual(updater.read_mode(), 'auto')
		self.assertTrue(AuditLog.objects.filter(action='update.mode_changed', target='auto').exists())
		self.assertEqual(self.put(admin, mode='sometimes').status_code, 400)
		self.assertEqual(updater.read_mode(), 'auto')  # a bad value changes nothing
		self.assertEqual(self.put(client_for(self.member), mode='auto').status_code, 403)
		self.assertEqual(self.put(admin, mode='manual').json()['mode'], 'manual')

	def test_taking_control_back_withdraws_an_approval_nobody_gave(self):
		self.install = lambda sha: open(os.path.join(self.dir, '.commit'), 'w').write(sha + '\n')
		self.install(OLD)
		admin = client_for(self.admin)
		self.put(admin, mode='auto')
		row = UpdateSettings.current()
		updater.check(row, get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertTrue(updater.auto_approve(row))
		self.assertTrue(os.path.exists(os.path.join(self.dir, '.update-approved')))
		self.assertEqual(self.put(admin, mode='manual').json()['status'], 'available')
		self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
		# an approval a person gave stays when they switch the mode
		updater.approve(UpdateSettings.current(), self.admin)
		self.put(admin, mode='auto')
		self.put(admin, mode='manual')
		self.assertTrue(os.path.exists(os.path.join(self.dir, '.update-approved')))

	def test_the_scheduled_check_approves_only_in_automatic_mode(self):
		from unittest import mock
		from cveFeed import tasks
		open(os.path.join(self.dir, '.commit'), 'w').write(OLD + '\n')
		compare = {'status': 'ahead', 'ahead_by': 1, 'commits': []}
		with mock.patch.object(updater.requests, 'get', fake_github(compare=compare)):
			self.assertEqual(tasks.check_for_updates()['status'], 'available')
			self.assertFalse(os.path.exists(os.path.join(self.dir, '.update-approved')))
			updater.set_mode('auto')
			self.assertEqual(tasks.check_for_updates()['status'], 'approved')
			self.assertTrue(os.path.exists(os.path.join(self.dir, '.update-approved')))

	def test_a_branch_that_is_not_a_release_branch_is_warned_about_and_audited_but_not_refused(self):
		from dashboard.models import AuditLog
		self.assertEqual(updater.branch_warning('master'), '')
		self.assertEqual(updater.branch_warning('main'), '')
		self.assertIn('"develop"', updater.branch_warning('develop'))
		self.assertIn('not a release branch', updater.branch_warning('my-fork/feature'))
		open(os.path.join(self.dir, '.commit'), 'w').write(OLD + '\n')
		admin = client_for(self.admin)
		self.put(admin, repo='o/r', branch='develop')
		row = UpdateSettings.current()
		updater.check(row, get=fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []}))
		self.assertIn('"develop"', admin.get('/cve/api/settings/updates').json()['branch_warning'])
		done = admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json')
		self.assertEqual(done.status_code, 200)  # a warning, not a refusal
		self.assertEqual(done.json()['status'], 'approved')
		entry = AuditLog.objects.get(action='update.approved')
		self.assertEqual((entry.detail['branch'], entry.detail['release_branch']), ('develop', False))
		self.put(admin, branch='master')
		self.assertEqual(admin.get('/cve/api/settings/updates').json()['branch_warning'], '')

	def test_approve_without_an_update_is_refused(self):
		admin = client_for(self.admin)
		self.assertEqual(admin.post('/cve/api/settings/updates/approve', '{}', content_type='application/json').status_code, 400)
