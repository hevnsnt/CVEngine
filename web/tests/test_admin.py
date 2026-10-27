import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership, SystemTimings, UserProfile
from targetApp.models import Domain
from tests.test_tenancy import client_for


def api(client, method, path, body=None):
	fn = getattr(client, method.lower())
	url = f'/cve/api/admin/{path}'
	r = fn(url, json.dumps(body) if body is not None else None, content_type='application/json') if method != 'GET' else fn(url)
	return r.status_code, (r.json() if r.content else None)


class AdminMatrixTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org_a, cls.org_b = Org.objects.create(name='Alpha', slug='alpha'), Org.objects.create(name='Beta', slug='beta')
		cls.pa = Project.objects.create(name='A1', slug='a1', insert_date=now, org=cls.org_a)
		cls.pb = Project.objects.create(name='B1', slug='b1', insert_date=now, org=cls.org_b)
		mk = lambda n, **kw: User.objects.create_user(n, password='pw-Secret-1', **kw)
		cls.root = User.objects.create_superuser('root', 'r@x.io', 'pw-Secret-1')
		cls.admin_a, cls.admin_b = mk('adminA'), mk('adminB')
		cls.member_a, cls.pm_a, cls.audit_a, cls.member_b = mk('memberA'), mk('pmA'), mk('auditA'), mk('memberB')
		OrgMembership.objects.create(user=cls.admin_a, org=cls.org_a, role='admin')
		OrgMembership.objects.create(user=cls.admin_b, org=cls.org_b, role='admin')
		OrgMembership.objects.create(user=cls.member_a, org=cls.org_a, role='user')
		ProjectMembership.objects.create(user=cls.pm_a, project=cls.pa, role='user')
		OrgMembership.objects.create(user=cls.audit_a, org=cls.org_a, role='audit')
		OrgMembership.objects.create(user=cls.member_b, org=cls.org_b, role='user')
		UserProfile.objects.create(user=cls.member_a, mfa_enabled=True, mfa_secret='X')

	def test_only_admins_get_in(self):
		for u in (self.member_a, self.pm_a, self.audit_a):
			self.assertEqual(api(client_for(u), 'GET', 'users')[0], 403, u.username)
			self.assertEqual(client_for(u).get('/cve/admin/').status_code, 403)
		self.assertEqual(client_for(self.admin_a).get('/cve/admin/').status_code, 200)
		self.assertEqual(client_for(self.root).get('/cve/admin/').status_code, 200)
		self.assertEqual(Client().get('/cve/api/admin/users').status_code, 302)

	def test_an_impossible_date_filter_is_a_400_not_a_server_error(self):
		root = client_for(self.root)
		for value in ('2026-13-45T00:00:00%2B00:00', '2026-02-30T10:00:00Z', 'yesterday'):
			status, body = api(root, 'GET', f'activity?from={value}')
			self.assertEqual(status, 400, value)
			self.assertIn('ISO timestamp', body['error'])
		self.assertEqual(root.get('/cve/api/activity?after=1&since=2026-13-45T00:00:00Z').status_code, 200)  # the feed ignores it

	def test_a_malformed_feed_date_does_not_stop_the_sync(self):
		from cveFeed.models import _feed_time
		self.assertIsNone(_feed_time('2026-13-45T00:00:00Z'))
		self.assertIsNone(_feed_time(''))
		self.assertEqual(_feed_time('2026-10-24T12:00:00Z').year, 2026)

	def test_activity_log_is_paged_scoped_filterable_and_redacted(self):
		from cveFeed.models import AgentActivity
		AgentActivity.objects.bulk_create([
			AgentActivity(kind='validate', message=f'project A activity {i}', project=self.pa)
			for i in range(120)
		])
		AgentActivity.objects.create(kind='confirm', status='failed', project=self.pa,
			message='Authorization: Bearer sk-ant-private-token password=hidden',
			detail={'stage': 'ai_triage', 'job_id': 7, 'finding_id': 33,
				'diagnostic': {'id': 'safe-id', 'category': 'parse_error', 'stack': 'tasks.py:42 automatic_validate_finding',
				               'token': 'never-share'}})
		AgentActivity.objects.create(kind='validate', status='failed', project=self.pb, message='project B private error')
		AgentActivity.objects.create(kind='feed', message='system status')
		root = client_for(self.root)
		status, first = api(root, 'GET', 'activity?page_size=100')
		self.assertEqual((status, first['count'], len(first['results'])), (200, 123, 100))
		self.assertEqual(api(root, 'GET', 'activity?page=2&page_size=100')[1]['results'][-1]['message'], 'project A activity 0')
		status, filtered = api(root, 'GET', 'activity?errors=1&stage=ai_triage&job_id=7&finding_id=33')
		self.assertEqual((status, filtered['count']), (200, 1))
		row = filtered['results'][0]
		self.assertNotIn('sk-ant-private-token', str(row))
		self.assertNotIn('hidden', str(row))
		self.assertNotIn('never-share', str(row))
		self.assertEqual(row['diagnostic']['category'], 'parse_error')
		self.assertIn('tasks.py:42', row['diagnostic']['stack'])
		admin = client_for(self.admin_a)
		self.assertEqual(api(admin, 'GET', 'activity?errors=1')[1]['count'], 1)
		self.assertIn(api(admin, 'GET', 'activity?project=b1')[0], (403, 404))
		self.assertEqual(api(client_for(self.member_a), 'GET', 'activity')[0], 403)
		self.assertEqual(api(admin, 'GET', 'activity?page_size=201')[0], 400)

	def test_scheduler_health_tells_a_running_beat_from_a_silent_or_unknown_one(self):
		import time
		inspector = mock.Mock(active_queues=mock.Mock(return_value={}), active=mock.Mock(return_value={}))
		def beat(value):
			with mock.patch('reNgine.celery.app.control.inspect', return_value=inspector), \
					mock.patch('cveFeed.scan_control.beat_heartbeat', return_value=value):
				return api(client_for(self.root), 'GET', 'health')[1]['beat']
		self.assertEqual(beat(time.time() - 20)['state'], 'running')
		self.assertEqual(beat(time.time() - 900)['state'], 'silent')
		self.assertEqual(beat(None), {'state': 'unknown', 'seconds_since_tick': None})

	def test_scheduler_health_is_app_admin_only_and_never_returns_task_arguments(self):
		from datetime import timedelta
		from django_celery_beat.models import IntervalSchedule, PeriodicTask
		interval = IntervalSchedule.objects.create(every=5, period='minutes')
		PeriodicTask.objects.create(name='test-hot-sweep', task='hot_validation_sweep', interval=interval,
			queue='cve_feed_queue', last_run_at=timezone.now() - timedelta(minutes=15), total_run_count=4)
		inspector = mock.Mock()
		inspector.active_queues.return_value = {
			'cve_feed_worker@local': [{'name': 'cve_feed_queue'}],
			'validation_priority_worker@local': [{'name': 'validation_priority_queue'}]}
		inspector.active.return_value = {'cve_feed_worker@local': [{'args': 'sk-ant-secret-marker'}]}
		with mock.patch('reNgine.celery.app.control.inspect', return_value=inspector):
			status, data = api(client_for(self.root), 'GET', 'health')
		self.assertEqual(status, 200)
		self.assertEqual(data['workers_state'], 'degraded')
		self.assertIn('Missing or unconfirmed', data['worker_note'])
		self.assertEqual(next(w for w in data['workers'] if w['worker'] == 'cve_feed_worker')['active'], 1)
		self.assertIsNone(next(w for w in data['workers'] if w['worker'] == 'discovery_worker')['consuming'])
		hot = next(s for s in data['schedules'] if s['name'] == 'test-hot-sweep')
		self.assertIsNotNone(hot['next_due'])
		self.assertEqual(hot['next_due_state'], 'past_due_unconfirmed')
		self.assertNotIn('sk-ant-secret-marker', str(data))
		self.assertEqual(api(client_for(self.admin_a), 'GET', 'health')[0], 403)
		self.assertEqual(api(client_for(self.member_a), 'GET', 'health')[0], 403)
		with mock.patch('reNgine.celery.app.control.inspect', side_effect=OSError('broker down')):
			unknown = api(client_for(self.root), 'GET', 'health')[1]
			self.assertEqual(unknown['workers_state'], 'unknown')
			self.assertIn('broker connection', unknown['worker_note'])
			self.assertNotIn('broker down', str(unknown))
		inspector.active_queues.return_value = None
		with mock.patch('reNgine.celery.app.control.inspect', return_value=inspector):
			unknown = api(client_for(self.root), 'GET', 'health')[1]
			self.assertEqual(unknown['workers_state'], 'unknown')
			self.assertIn('did not return queue', unknown['worker_note'])

	def test_worker_inspection_accepts_celery_at_worker_names(self):
		inspector = mock.Mock()
		inspector.active_queues.return_value = {
			'celery@discovery_worker': [{'name': 'discovery_queue'}],
			'celery@cve_feed_worker': [{'name': 'cve_feed_queue'}],
			'celery@validation_priority_worker': [{'name': 'validation_priority_queue'}],
			'celery@classic_worker': [{'name': 'api_queue'}]}
		inspector.active.return_value = {'celery@cve_feed_worker': [{'args': 'private-secret-marker'}]}
		with mock.patch('reNgine.celery.app.control.inspect', return_value=inspector):
			status, data = api(client_for(self.root), 'GET', 'health')
		self.assertEqual(status, 200)
		self.assertEqual(data['workers_state'], 'responding')
		self.assertTrue(all(row['consuming'] for row in data['workers']))
		self.assertEqual(next(row for row in data['workers'] if row['worker'] == 'cve_feed_worker')['active'], 1)
		self.assertNotIn('private-secret-marker', str(data))

	def test_assessment_review_status_is_app_admin_only_and_bounded(self):
		from datetime import timedelta
		from cveFeed.models import AssessmentReview, AssessmentReviewDecision
		now = timezone.now()
		review = AssessmentReview.objects.create(period_start=now-timedelta(hours=3), period_end=now,
			status='completed', total_projects=2, reviewed_projects=2, queued_actions=1,
			performance={'status': 'no_change', 'reason': 'Insufficient telemetry'})
		AssessmentReviewDecision.objects.create(review=review, project=self.pa, action='triage', status='queued',
			reason='pending findings')
		with mock.patch('reNgine.celery.app.control.inspect') as inspector:
			inspector.return_value.active_queues.return_value = {}
			status, data = api(client_for(self.root), 'GET', 'health')
		self.assertEqual(status, 200)
		self.assertEqual(data['assessment_review']['id'], review.id)
		self.assertEqual(data['assessment_review']['recent_decisions'][0]['project'], self.pa.slug)
		self.assertEqual(api(client_for(self.admin_a), 'GET', 'health')[0], 403)

	def test_archive_rediscovery_health_reports_real_progress(self):
		from cveFeed.models import ArchiveRediscovery, HostState
		domain = Domain.objects.create(name='health-archive.example', project=self.pa, insert_date=timezone.now())
		HostState.objects.create(project=self.pa, domain=domain, host=domain.name, archived_at=timezone.now())
		run = ArchiveRediscovery.objects.create(day=timezone.now().date(), status='queued', total=3, checked=2, deferred=1)
		with mock.patch('reNgine.celery.app.control.inspect') as inspector:
			inspector.return_value.active_queues.return_value = {}
			status, data = api(client_for(self.root), 'GET', 'health')
		self.assertEqual(status, 200)
		self.assertEqual(data['archive_rediscovery']['run_id'], run.pk)
		self.assertEqual((data['archive_rediscovery']['archived_hosts'], data['archive_rediscovery']['checked']), (1, 2))
		self.assertEqual(api(client_for(self.admin_a), 'GET', 'health')[0], 403)

	def test_org_admin_sees_only_their_orgs_people_and_mfa_status(self):
		status, data = api(client_for(self.admin_a), 'GET', 'users')
		names = {u['username']: u for u in data['results']}
		self.assertEqual(set(names), {'adminA', 'memberA', 'pmA', 'auditA'})  # nobody from Beta, no app admin
		self.assertTrue(names['memberA']['mfa_enabled'])
		self.assertFalse(names['pmA']['mfa_enabled'])
		self.assertEqual(names['pmA']['role_label'], 'Project Member')
		self.assertEqual(names['memberA']['role_label'], 'Org Member')
		self.assertEqual(names['auditA']['role_label'], 'Audit (organization)')
		self.assertEqual(len(api(client_for(self.root), 'GET', 'users')[1]['results']), User.objects.count())

	def test_org_admin_cannot_touch_other_orgs_or_app_admins(self):
		c = client_for(self.admin_a)
		for method, path, body in (('PATCH', f'users/{self.member_b.id}', {'first_name': 'x'}), ('POST', f'users/{self.member_b.id}/reset-password', None),
				('POST', f'users/{self.member_b.id}/reset-mfa', None), ('POST', f'users/{self.root.id}/reset-password', None),
				('PATCH', f'orgs/{self.org_b.id}', {'name': 'Hacked'}), ('DELETE', f'projects/{self.pb.id}', {'confirm': 'B1'}),
				('POST', 'projects', {'org_id': self.org_b.id, 'name': 'Sneaky'}),
				('POST', 'memberships', {'user_id': self.member_a.id, 'scope': 'org', 'scope_id': self.org_b.id, 'role': 'user'}),
				('POST', 'memberships', {'user_id': self.member_a.id, 'scope': 'project', 'scope_id': self.pb.id, 'role': 'user'}),
				('POST', 'users', {'username': 'intruder', 'scope': 'org', 'scope_id': self.org_b.id, 'role': 'user'})):
			self.assertEqual(api(c, method, path, body)[0], 404, f'{method} {path}')
		self.assertTrue(Project.objects.filter(pk=self.pb.pk).exists())
		self.assertFalse(User.objects.filter(username='intruder').exists())
		self.assertEqual(Org.objects.get(pk=self.org_b.pk).name, 'Beta')

	def test_an_org_admin_cannot_take_over_a_bug_bounty_account_by_resetting_it(self):
		UserProfile.objects.filter(user=self.member_a).update(bugbounty_enabled=True)
		c = client_for(self.admin_a)
		before = User.objects.get(pk=self.member_a.pk).password
		for path in ('reset-password', 'reset-mfa'):
			self.assertEqual(api(c, 'POST', f'users/{self.member_a.id}/{path}')[0], 403, path)
		self.assertEqual(api(c, 'PATCH', f'users/{self.member_a.id}', {'is_active': False})[0], 403)
		self.assertEqual(User.objects.get(pk=self.member_a.pk).password, before)
		self.assertEqual(api(client_for(self.root), 'POST', f'users/{self.member_a.id}/reset-password')[0], 200)  # an App Admin still can
		self.assertEqual(api(c, 'PATCH', f'users/{self.member_a.id}', {'first_name': 'Fine'})[0], 200)  # ordinary edits are unaffected

	def test_an_org_admin_adopts_only_unused_accounts_that_belong_nowhere(self):
		from django.utils import timezone as tz
		fresh = User.objects.create_user('fresh', password='pw-Secret-1')  # created by an App Admin, never signed in
		used = User.objects.create_user('used', password='pw-Secret-1')  # signed in once, then removed from its organization
		User.objects.filter(pk=used.pk).update(last_login=tz.now())
		bounty = User.objects.create_user('bountyhunter', password='pw-Secret-1')
		UserProfile.objects.create(user=bounty, bugbounty_enabled=True)
		c = client_for(self.admin_a)
		grant = lambda user: api(c, 'POST', 'memberships', {'user_id': user.id, 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0]
		self.assertEqual(grant(used), 404)
		self.assertEqual(grant(bounty), 404)
		self.assertEqual(grant(fresh), 200)
		self.assertFalse(OrgMembership.objects.filter(user__in=[used, bounty]).exists())
		self.assertEqual(api(client_for(self.root), 'POST', 'memberships',
							{'user_id': used.id, 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0], 200)  # an App Admin can place it

	def test_org_admin_cannot_do_app_admin_things(self):
		c = client_for(self.admin_a)
		self.assertEqual(api(c, 'POST', 'orgs', {'name': 'New'})[0], 403)
		self.assertEqual(api(c, 'DELETE', f'orgs/{self.org_a.id}', {'confirm': 'Alpha', 'delete_projects': True})[0], 403)
		self.assertEqual(api(c, 'PUT', 'timings', {'cve_sync_minutes': 10})[0], 403)
		self.assertEqual(api(c, 'DELETE', f'users/{self.member_a.id}')[0], 403)
		self.assertTrue(User.objects.filter(pk=self.member_a.pk).exists())

	def test_org_admin_manages_their_people(self):
		c = client_for(self.admin_a)
		status, data = api(c, 'POST', 'users', {'username': 'newbie', 'first_name': 'New', 'last_name': 'Bie', 'email': 'n@x.io', 'scope': 'org',
		                                         'scope_id': self.org_a.id, 'role': 'user'})
		self.assertEqual(status, 201)
		temp = data['temporary_password']
		self.assertTrue(temp and User.objects.get(username='newbie').check_password(temp))
		self.assertTrue(UserProfile.objects.get(user__username='newbie').must_change_password)
		self.assertEqual(data['role_label'], 'Org Member')
		# project level account
		status, data = api(c, 'POST', 'users', {'username': 'projonly', 'scope': 'project', 'scope_id': self.pa.id, 'role': 'user'})
		self.assertEqual((status, data['role_label']), (201, 'Project Member'))
		self.assertEqual(api(c, 'POST', 'users', {'username': 'newbie', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0], 409)
		self.assertEqual(api(c, 'POST', 'users', {'username': 'x', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0], 400)  # too short
		self.assertEqual(api(c, 'POST', 'users', {'username': 'okname', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'root'})[0], 400)
		# reset password: new temp password, old one stops working, flag set
		old = User.objects.get(pk=self.member_a.pk).password
		status, data = api(c, 'POST', f'users/{self.member_a.id}/reset-password')
		self.assertEqual(status, 200)
		self.member_a.refresh_from_db()
		self.assertNotEqual(self.member_a.password, old)
		self.assertTrue(self.member_a.check_password(data['temporary_password']))
		self.assertTrue(UserProfile.objects.get(user=self.member_a).must_change_password)
		# reset MFA
		status, data = api(c, 'POST', f'users/{self.member_a.id}/reset-mfa')
		self.assertFalse(data['mfa_enabled'])
		self.assertEqual(UserProfile.objects.get(user=self.member_a).mfa_secret, '')
		# disable, but never yourself
		self.assertEqual(api(c, 'PATCH', f'users/{self.member_a.id}', {'is_active': False})[1]['is_active'], False)
		self.assertEqual(api(c, 'PATCH', f'users/{self.admin_a.id}', {'is_active': False})[0], 409)

	def test_memberships_and_self_protection(self):
		c = client_for(self.admin_a)
		status, data = api(c, 'POST', 'memberships', {'user_id': self.audit_a.id, 'scope': 'project', 'scope_id': self.pa.id, 'role': 'user'})
		self.assertEqual(status, 200)
		self.assertTrue(ProjectMembership.objects.filter(user=self.audit_a, project=self.pa, role='user').exists())
		self.assertEqual(api(c, 'POST', 'memberships', {'user_id': self.audit_a.id, 'scope': 'project', 'scope_id': self.pa.id, 'role': 'admin'})[0], 400)  # not assignable
		# an org admin cannot reach into another org to "claim" one of its members (account-takeover guard)
		self.assertEqual(api(c, 'POST', 'memberships', {'username': 'memberB', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'audit'})[0], 404)
		self.assertFalse(OrgMembership.objects.filter(user=self.member_b, org=self.org_a).exists())
		# but a brand-new, unaffiliated account by name can be added to the org (onboarding)
		fresh = User.objects.create_user('freshuser', password='pw-Secret-1')
		self.assertEqual(api(c, 'POST', 'memberships', {'username': 'freshuser', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'audit'})[0], 200)
		self.assertTrue(OrgMembership.objects.filter(user=fresh, org=self.org_a).exists())
		# and a user already inside one of the actor's own managed orgs can still be re-scoped within it
		self.assertEqual(api(c, 'POST', 'memberships', {'user_id': self.pm_a.id, 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'audit'})[0], 200)
		self.assertEqual(api(c, 'POST', 'memberships', {'username': 'ghost', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'audit'})[0], 404)
		self.assertEqual(api(c, 'POST', 'memberships', {'username': 'root', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0], 404)  # app admins are above orgs
		# cannot demote or remove yourself
		self.assertEqual(api(c, 'POST', 'memberships', {'user_id': self.admin_a.id, 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})[0], 409)
		mine = OrgMembership.objects.get(user=self.admin_a, org=self.org_a)
		self.assertEqual(api(c, 'DELETE', f'memberships/org/{mine.id}')[0], 409)
		other = OrgMembership.objects.get(user=self.member_a, org=self.org_a)
		self.assertEqual(api(c, 'DELETE', f'memberships/org/{other.id}')[0], 200)
		foreign = OrgMembership.objects.get(user=self.member_b, org=self.org_b)
		self.assertEqual(api(c, 'DELETE', f'memberships/org/{foreign.id}')[0], 404)

	def test_projects_org_admin_creates_and_deletes_only_in_their_org(self):
		c = client_for(self.admin_a)
		status, data = api(c, 'POST', 'projects', {'org_id': self.org_a.id, 'name': 'Fresh Project'})
		self.assertEqual((status, data['slug']), (201, 'fresh-project'))
		pid = data['id']
		Domain.objects.create(name='fresh.test', project=Project.objects.get(pk=pid), insert_date=timezone.now())
		self.assertEqual(api(c, 'DELETE', f'projects/{pid}', {'confirm': 'wrong'})[0], 400)
		self.assertEqual(api(c, 'DELETE', f'projects/{pid}', {'confirm': 'Fresh Project'})[0], 200)
		self.assertFalse(Domain.objects.filter(name='fresh.test').exists())  # deleting a project takes its data with it
		names = [p['name'] for p in api(c, 'GET', 'projects')[1]['results']]
		self.assertEqual(names, ['A1'])
		self.assertEqual(api(c, 'PATCH', f'orgs/{self.org_a.id}', {'require_mfa': True})[1]['require_mfa'], True)

	def test_app_admin_does_everything(self):
		c = client_for(self.root)
		status, data = api(c, 'POST', 'orgs', {'name': 'Gamma Corp'})
		self.assertEqual((status, data['slug']), (201, 'gamma-corp'))
		gid = data['id']
		self.assertEqual(api(c, 'POST', 'projects', {'org_id': gid, 'name': 'G1'})[0], 201)
		self.assertEqual(api(c, 'DELETE', f'orgs/{gid}', {'confirm': 'Gamma Corp'})[0], 409)  # has a project
		self.assertEqual(api(c, 'DELETE', f'orgs/{gid}', {'confirm': 'nope', 'delete_projects': True})[0], 400)
		status, data = api(c, 'DELETE', f'orgs/{gid}', {'confirm': 'Gamma Corp', 'delete_projects': True})
		self.assertEqual((status, data['projects_deleted']), (200, 1))
		self.assertEqual(api(c, 'POST', f'users/{self.member_b.id}/reset-password')[0], 200)
		self.assertEqual(api(c, 'DELETE', f'users/{self.member_b.id}')[0], 200)
		self.assertEqual(api(c, 'DELETE', f'users/{self.root.id}')[0], 409)  # not yourself

	def test_timings_validate_and_apply_to_beat(self):
		from django_celery_beat.models import PeriodicTask
		c = client_for(self.root)
		self.assertEqual(api(c, 'PUT', 'timings', {'cve_sync_minutes': 1})[0], 400)
		self.assertEqual(api(c, 'PUT', 'timings', {'discovery_timeout_hours': 'lots'})[0], 400)
		status, data = api(c, 'PUT', 'timings', {'cve_sync_minutes': 15, 'hygiene_hour_utc': 5, 'discovery_timeout_hours': 8})
		self.assertEqual((status, data['cve_sync_minutes'], data['discovery_timeout_hours']), (200, 15, 8))
		self.assertEqual(SystemTimings.current().nuclei_timeout_hours, 4)  # untouched fields keep their default
		self.assertEqual(PeriodicTask.objects.get(name='cvengine-cve-sync').interval.every, 15)
		self.assertEqual(PeriodicTask.objects.get(name='cvengine-hygiene-daily').crontab.hour, '5')
		from cveFeed import discovery
		self.assertEqual(discovery.discovery_timeout(), 8 * 3600)

	def test_audit_log_is_scoped_to_what_the_admin_manages(self):
		api(client_for(self.admin_a), 'POST', f'users/{self.member_a.id}/reset-mfa')
		api(client_for(self.admin_a), 'POST', 'users', {'username': 'audited', 'scope': 'org', 'scope_id': self.org_a.id, 'role': 'user'})
		api(client_for(self.admin_b), 'PATCH', f'orgs/{self.org_b.id}', {'name': 'Beta 2'})
		a = {r['action'] for r in api(client_for(self.admin_a), 'GET', 'audit')[1]['results']}
		self.assertEqual(a, {'user.create', 'user.reset_mfa'})  # the reset is tagged with the user's organization; adminB's change is not visible to adminA
		root_actions = {r['action'] for r in api(client_for(self.root), 'GET', 'audit')[1]['results']}
		self.assertTrue({'user.create', 'user.reset_mfa', 'org.update'} <= root_actions)
		self.assertTrue(AuditLog.objects.filter(action='user.create', actor_name='adminA').exists())

	def test_credential_events_reach_the_admins_of_every_organization_of_the_user(self):
		both = User.objects.create_user('both', password='pw-Secret-1')
		OrgMembership.objects.create(user=both, org=self.org_a, role='user')
		OrgMembership.objects.create(user=both, org=self.org_b, role='user')
		api(client_for(self.root), 'POST', f'users/{both.id}/reset-password')
		api(client_for(self.root), 'PATCH', f'users/{both.id}', {'is_active': False})
		for admin in (self.admin_a, self.admin_b):
			actions = {r['action'] for r in api(client_for(admin), 'GET', 'audit')[1]['results']}
			self.assertTrue({'user.reset_password', 'user.update'} <= actions, admin.username)
		loner = User.objects.create_user('loner', password='pw-Secret-1')  # in no organization: App Admins only
		api(client_for(self.root), 'POST', f'users/{loner.id}/reset-password')
		self.assertTrue(AuditLog.objects.filter(action='user.reset_password', target='loner', org__isnull=True).exists())
		self.assertNotIn('loner', {r['target'] for r in api(client_for(self.admin_a), 'GET', 'audit')[1]['results']})

	def test_deleting_an_account_is_visible_to_its_organizations_admins(self):
		api(client_for(self.root), 'DELETE', f'users/{self.member_a.id}')
		self.assertIn('user.delete', {r['action'] for r in api(client_for(self.admin_a), 'GET', 'audit')[1]['results']})


class AccountAndPasswordTests(TestCase):
	def setUp(self):
		self.org = Org.objects.create(name='Acme', slug='acme')
		self.user = User.objects.create_user('jane', password='pw-Secret-1', first_name='Jane', last_name='Doe', email='jane@acme.test')
		OrgMembership.objects.create(user=self.user, org=self.org, role='audit')  # audit can still manage their own account

	def post(self, c, path, body):
		return c.post(f'/cve/api/account/{path}', json.dumps(body), content_type='application/json')

	def test_account_shows_who_you_are(self):
		c = client_for(self.user)
		page = c.get('/cve/account/')
		self.assertEqual(page.status_code, 200)
		data = c.get('/cve/api/account/me').json()
		self.assertEqual((data['name'], data['username'], data['email'], data['role']), ('Jane Doe', 'jane', 'jane@acme.test', 'Audit (organization)'))
		self.assertEqual(data['access'], [{'scope': 'Organization', 'name': 'Acme', 'role': 'Audit (organization)', 'mfa_required': False}])
		root = client_for(User.objects.create_superuser('boss', 'b@x.io', 'pw-Secret-1')).get('/cve/api/account/me').json()
		self.assertEqual((root['role'], root['is_admin']), ('App Admin', True))

	def test_edit_profile_and_validation(self):
		c = client_for(self.user)
		r = c.patch('/cve/api/account/profile', json.dumps({'first_name': 'Janet', 'email': 'janet@acme.test'}), content_type='application/json')
		self.assertEqual((r.status_code, r.json()['name']), (200, 'Janet Doe'))
		r = c.patch('/cve/api/account/profile', json.dumps({'email': 'not an email'}), content_type='application/json')
		self.assertEqual(r.status_code, 400)

	def test_change_password_rules_and_flag(self):
		c = client_for(self.user)
		UserProfile.objects.create(user=self.user, must_change_password=True)
		# while the temp password is active everything but the account page is blocked
		self.assertEqual(c.get('/cve/').status_code, 302)
		self.assertEqual(c.get('/cve/').headers['Location'], '/cve/account/')
		self.assertEqual(c.get('/cve/api/stats').status_code, 403)
		self.assertEqual(c.get('/cve/account/').status_code, 200)
		self.assertEqual(self.post(c, 'password', {'current': 'wrong', 'new': 'Another-Pass-9'}).status_code, 400)
		self.assertEqual(self.post(c, 'password', {'current': 'pw-Secret-1', 'new': 'pw-Secret-1'}).status_code, 400)
		self.assertEqual(self.post(c, 'password', {'current': 'pw-Secret-1', 'new': '12345678'}).status_code, 400)  # too common / numeric
		self.assertEqual(self.post(c, 'password', {'current': 'pw-Secret-1', 'new': 'Another-Pass-9'}).status_code, 200)
		self.user.refresh_from_db()
		self.assertTrue(self.user.check_password('Another-Pass-9'))
		self.assertFalse(UserProfile.objects.get(user=self.user).must_change_password)
		self.assertEqual(c.get('/cve/api/account/me').status_code, 200)  # session survived the change
		self.assertEqual(c.get('/cve/').status_code, 200)

	def test_anonymous_cannot_use_account_api(self):
		self.assertEqual(Client().get('/cve/api/account/me').status_code, 302)  # login required
	def test_a_users_own_credential_changes_are_in_the_organizations_audit_log(self):
		from tenancy import mfa
		admin = User.objects.create_user('orgadmin', password='pw-Secret-1')
		OrgMembership.objects.create(user=admin, org=self.org, role='admin')
		c = client_for(self.user)
		self.assertEqual(self.post(c, 'password', {'current': 'pw-Secret-1', 'new': 'Another-Pass-9'}).status_code, 200)
		secret = self.post(c, 'mfa/start', {}).json()['secret']
		self.assertEqual(self.post(c, 'mfa/enable', {'code': mfa.totp(secret)}).status_code, 200)
		made = c.post('/api/v1/tokens', json.dumps({'name': 'zz-token-name'}), content_type='application/json')
		self.assertEqual(c.delete('/api/v1/tokens/%d' % made.json()['id']).status_code, 200)
		seen = {r['action'] for r in api(client_for(admin), 'GET', 'audit')[1]['results']}
		self.assertTrue({'account.password_change', 'account.mfa_enable', 'token.create', 'token.revoke'} <= seen, seen)
		self.assertTrue(all(r.actor_name == 'jane' for r in AuditLog.objects.filter(action__startswith='token.')))
		self.assertNotIn('zz-token-name', json.dumps(list(AuditLog.objects.values_list('detail', 'target'))))  # no token name or secret



class ClassicRetiredTests(TestCase):
	def setUp(self):
		self.user = User.objects.create_user('legacy', password='x')
		OrgMembership.objects.create(user=self.user, org=Org.objects.create(name='L', slug='l'), role='user')

	def test_classic_pages_forward_to_the_new_ones(self):
		c = client_for(self.user)
		expected = {'/scan/p1/history/scan': '/cve/p1/scans/', '/scan/p1/detail/7': '/cve/p1/scans/7/', '/target/p1/list': '/cve/p1/targets/',
		            '/p1/dashboard/': '/cve/dashboard/' if False else '/cve/', '/p1/profile/': '/cve/account/', '/p1/admin_interface/': '/cve/admin/',
		            '/scanEngine/p1/': '/cve/settings/', '/scanEngine/p1/api_vault': '/cve/settings/', '/scan/p1/all/subdomains': '/cve/p1/hosts/',
		            '/recon_note/p1/todo': '/cve/'}
		for path, target in expected.items():
			r = c.get(path)
			self.assertEqual((r.status_code, r.headers['Location']), (302, target), path)

	def test_classic_writes_are_refused_and_downloads_kept(self):
		c = client_for(self.user)
		self.assertEqual(c.post('/scan/p1/start/1').status_code, 410)
		self.assertEqual(c.post('/target/p1/add/target').status_code, 410)
		self.assertNotEqual(c.get('/scan/export/subdomains/1').status_code, 302)  # exports are still served (or 404), never redirected
		self.assertEqual(c.get('/cve/').status_code, 200)
		self.assertEqual(c.get('/api/v1/me').status_code, 200)
