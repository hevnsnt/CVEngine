"""Email reports: who may create and see them, validation, the schedule arithmetic, that every period is sent once, failures and retries, the message,
attachments, unsubscribe links, test sends, the preview and MCP. No real SMTP: the mail connection is replaced by Django's in-memory backend (or a
test backend that refuses an address); the PDF layout step is replaced by a stub."""
import datetime
import os
import smtplib
from datetime import timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.core.mail.backends.locmem import EmailBackend as LocmemBackend
from django.test import Client, TestCase
from django.utils import timezone

from agentapi import report_scope
from agentapi.auth import create_token
from cveFeed import mailer, report_digest, report_digests, report_pdf, report_schedule
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, ReportDelivery, ReportSubscription, SmtpSettings
from dashboard.models import AuditLog, OrgMembership, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from tests.test_agentapi import call, tool_call
from tests.test_reporting import ReportingBase, stub_render
from tests.test_tenancy import client_for

UTC = dt_timezone.utc
GOOD = {'enabled': True, 'host': 'smtp.example.org', 'port': 587, 'security': 'starttls', 'username': 'relay', 'password': 'relay-secret-value',
        'from_address': 'cvengine@example.org', 'from_name': 'cvENGINE', 'link_base': 'https://cve.example.org'}
NOW = timezone.now()
HOSTILE_HOST = '<img src=x onerror=1>.example'


class RefusingBackend(LocmemBackend):
    """The in-memory backend, except that it refuses the recipient 'bad@example.org' as a mail server would."""

    def send_messages(self, messages):
        for m in messages:
            if 'bad@example.org' in m.to:
                raise smtplib.SMTPRecipientsRefused({'bad@example.org': (550, b'no such user')})
        return super().send_messages(messages)


def configure(**changes):
    cfg = SmtpSettings.objects.first() or SmtpSettings()
    for key, value in {**GOOD, **changes}.items():
        setattr(cfg, key, value)
    cfg.save()
    return cfg


class SubBase(ReportingBase):
    def setUp(self):
        cache.clear()
        mail.outbox = []
        configure()
        self.backend = mock.patch.object(mailer, '_connection', side_effect=lambda cfg: LocmemBackend())
        self.backend.start()
        self.addCleanup(self.backend.stop)
        self.render = mock.patch.object(report_pdf, 'render_pdf', side_effect=stub_render)
        self.render.start()
        self.addCleanup(self.render.stop)
        self.queue = mock.patch('cveFeed.tasks.send_report_test.apply_async')
        self.queued = self.queue.start()
        self.addCleanup(self.queue.stop)

    def make(self, owner=None, project='web', org=None, **kw):
        fields = {'name': 'Weekly report', 'recipients': ['a@example.org', 'b@example.org'], 'cadence': 'weekly', 'weekday': 0, 'send_time': datetime.time(8, 0),
                  'timezone': 'UTC', 'next_run_at': NOW - timedelta(hours=1), **kw}
        scope = {'org': self.org_a} if org else {'project': getattr(self, project)}
        owner = owner or self.org_admin
        return ReportSubscription.objects.create(**scope, owner=owner, created_by=owner, **fields)

    def body(self, **kw):
        return {'name': 'Weekly', 'project': 'acme-web', 'recipients': ['a@example.org'], **kw}


class ScheduleTests(TestCase):
    def sub(self, **kw):
        return SimpleNamespace(**{'cadence': 'weekly', 'weekday': 0, 'day_of_month': 1, 'send_time': datetime.time(8, 0), 'timezone': 'UTC', **kw})

    def test_the_weekly_slot_is_the_next_weekday_at_the_time(self):
        slot = report_schedule.next_slot(self.sub(), datetime.datetime(2026, 11, 21, 12, tzinfo=UTC))  # a Saturday
        self.assertEqual(slot, datetime.datetime(2026, 11, 23, 8, tzinfo=UTC))
        self.assertEqual(report_schedule.next_slot(self.sub(), slot), datetime.datetime(2026, 11, 30, 8, tzinfo=UTC))  # strictly after

    def test_the_monthly_slot_on_day_28_and_day_1(self):
        month = self.sub(cadence='monthly', day_of_month=28)
        self.assertEqual(report_schedule.next_slot(month, datetime.datetime(2026, 1, 28, 8, tzinfo=UTC)), datetime.datetime(2026, 2, 28, 8, tzinfo=UTC))
        first = self.sub(cadence='monthly', day_of_month=1)
        end = report_schedule.next_slot(first, datetime.datetime(2026, 11, 5, tzinfo=UTC))
        self.assertEqual(end, datetime.datetime(2026, 12, 1, 8, tzinfo=UTC))
        self.assertEqual(report_schedule.period_label(report_schedule.previous_slot(first, end), end, 'UTC', monthly=True), 'November 2026')

    def test_monday_8_in_london_stays_8_local_across_the_march_change(self):
        london = self.sub(timezone='Europe/London')
        before = report_schedule.next_slot(london, datetime.datetime(2026, 3, 20, tzinfo=UTC))
        after = report_schedule.next_slot(london, before)
        self.assertEqual((before.hour, after.hour), (8, 7))  # the UTC hour moves from 08 to 07
        self.assertEqual(report_schedule.previous_slot(london, after), before)  # and the step back round-trips

    def test_labels_and_the_summary_sentence(self):
        london = self.sub(timezone='Europe/London')
        end = datetime.datetime(2026, 11, 23, 8, tzinfo=UTC)
        self.assertEqual(report_schedule.period_label(report_schedule.previous_slot(london, end), end, 'Europe/London'), 'Nov 16 to Nov 23, 2026')
        self.assertEqual(report_schedule.summary(london), 'Weekly, Mondays 08:00 (Europe/London)')
        self.assertEqual(report_schedule.summary(self.sub(cadence='monthly', day_of_month=1)), 'Monthly, day 1 at 08:00 (UTC)')

    def test_the_summary_reads_the_way_the_page_script_pins_it(self):
        # static/cve/reports-logic.js scheduleSummary writes the same words; tests/test_reports_logic.mjs pins 'Weekly, Mondays 08:00 (Europe/London)'
        words = report_schedule.summary(self.sub(timezone='Europe/London', weekday=6, send_time=datetime.time(17, 30)))
        self.assertEqual(words, 'Weekly, Sundays 17:30 (Europe/London)')

    def test_a_bad_zone_is_a_value_error(self):
        for bad in ('', 'Nowhere/Land', '../etc/passwd', '/etc/localtime'):
            with self.assertRaises(ValueError, msg=bad):
                report_schedule.zone(bad)


class PermissionTests(SubBase):
    def call(self, user, method, path, body=None):
        return call(user, method, path, body)

    def test_creating_follows_the_matrix(self):
        _, ro = create_token(self.org_member, 'ro', read_only=True)
        project = {self.root: 201, self.org_admin: 201, self.org_member: 201, self.web_user: 201, self.web_audit: 403, self.org_audit: 403, self.outsider: 404}
        for user, status in project.items():
            cache.clear()
            got, data = self.call(user, 'POST', '/api/v1/report-subscriptions', self.body())
            self.assertEqual(got, status, (user.username, data))
        self.assertEqual(call(ro, 'POST', '/api/v1/report-subscriptions', self.body())[0], 403)
        organization = {self.root: 201, self.org_admin: 201, self.org_member: 403, self.org_audit: 403, self.web_user: 404, self.outsider: 404}
        for user, status in organization.items():
            got, data = self.call(user, 'POST', '/api/v1/report-subscriptions', self.body(project=None, org='acme-org', name=f'Org {user.username}'))
            self.assertEqual(got, status, (user.username, data))
        self.assertIn('Org Admin', self.call(self.org_member, 'POST', '/api/v1/report-subscriptions', self.body(project=None, org='acme-org'))[1]['error'])
        self.assertEqual(self.call(self.web_audit, 'POST', '/api/v1/report-subscriptions', self.body())[1]['error'], 'audit role is read only')

    def test_reading_changing_deleting_and_testing_follow_the_matrix(self):
        project_sub, org_sub = self.make(project='web'), self.make(org=True, name='Org weekly')
        views = {self.org_member: (200, 200), self.web_audit: (200, 404), self.web_user: (200, 404), self.org_audit: (200, 200), self.outsider: (404, 404)}
        for user, (p, o) in views.items():
            self.assertEqual(self.call(user, 'GET', f'/api/v1/report-subscriptions/{project_sub.pk}')[0], p, user.username)
            self.assertEqual(self.call(user, 'GET', f'/api/v1/report-subscriptions/{org_sub.pk}')[0], o, user.username)
        for user, status in {self.web_audit: 403, self.org_audit: 403, self.outsider: 404}.items():
            self.assertEqual(self.call(user, 'PATCH', f'/api/v1/report-subscriptions/{project_sub.pk}', {'name': 'x'})[0], status, user.username)
            self.assertEqual(self.call(user, 'DELETE', f'/api/v1/report-subscriptions/{project_sub.pk}')[0], status, user.username)
            self.assertEqual(self.call(user, 'POST', f'/api/v1/report-subscriptions/{project_sub.pk}/test')[0], status, user.username)
        self.assertEqual(self.call(self.org_member, 'PATCH', f'/api/v1/report-subscriptions/{org_sub.pk}', {'name': 'x'})[0], 403)
        self.assertEqual(self.call(self.org_admin, 'PATCH', f'/api/v1/report-subscriptions/{org_sub.pk}', {'name': 'Renamed'})[0], 200)
        self.assertEqual(self.call(self.web_user, 'DELETE', f'/api/v1/report-subscriptions/{project_sub.pk}')[0], 200)  # any manager of the scope, not only its creator

    def test_a_read_only_token_reads_but_never_writes(self):
        sub = self.make(project='web')
        _, ro = create_token(self.org_admin, 'ro', read_only=True)
        self.assertEqual(call(ro, 'GET', f'/api/v1/report-subscriptions/{sub.pk}')[0], 200)
        self.assertEqual(call(ro, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {'name': 'x'})[0], 403)
        self.assertEqual(call(ro, 'DELETE', f'/api/v1/report-subscriptions/{sub.pk}')[0], 403)
        self.assertEqual(call(ro, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')[0], 403)

    def test_the_list_shows_what_the_caller_may_see_and_can_create_says_what_they_may_add(self):
        self.make(project='web'), self.make(org=True, name='Org weekly')
        status, body = self.call(self.web_user, 'GET', '/api/v1/report-subscriptions')
        self.assertEqual((status, [s['name'] for s in body['results']], body['mail_ready']), (200, ['Weekly report'], True))
        status, body = self.call(self.org_member, 'GET', '/api/v1/report-subscriptions')
        self.assertEqual(sorted(s['name'] for s in body['results']), ['Org weekly', 'Weekly report'])
        self.assertTrue(self.call(self.org_member, 'GET', '/api/v1/report-subscriptions?project=acme-web')[1]['can_create'])
        self.assertFalse(self.call(self.org_member, 'GET', '/api/v1/report-subscriptions?org=acme-org')[1]['can_create'])
        self.assertTrue(self.call(self.org_admin, 'GET', '/api/v1/report-subscriptions?org=acme-org')[1]['can_create'])
        self.assertEqual(self.call(self.web_user, 'GET', '/api/v1/report-subscriptions?org=acme-org')[0], 404)
        self.assertFalse(self.call(self.web_audit, 'GET', '/api/v1/report-subscriptions?project=acme-web')[1]['can_create'])


class ValidationTests(SubBase):
    def post(self, **kw):
        return call(self.org_admin, 'POST', '/api/v1/report-subscriptions', self.body(**kw))

    def test_good_values_are_saved_and_the_first_slot_is_set(self):
        status, body = self.post(recipients=['A@Example.org', 'a@example.org', ' b@example.org '], cadence='monthly', day_of_month=1, send_time='09:15',
                                 timezone='Europe/London', attach='csv')
        self.assertEqual(status, 201, body)
        self.assertEqual(body['recipients'], ['a@example.org', 'b@example.org'])  # lower-cased, duplicates collapsed
        self.assertEqual((body['schedule'], body['attach'], body['owner']['username']), ('Monthly, day 1 at 09:15 (Europe/London)', 'csv', 'orgadmin'))
        self.assertGreater(ReportSubscription.objects.get(pk=body['id']).next_run_at, timezone.now())

    def test_each_bad_value_is_a_400_that_names_it(self):
        cases = [({'recipients': ['not-an-address']}, 'not an email address'), ({'recipients': [f'u{i}@example.org' for i in range(11)]}, 'from 1 to 10'),
                 ({'recipients': []}, 'from 1 to 10'), ({'timezone': 'Nowhere/Land'}, 'timezone'), ({'weekday': 7}, 'weekday'), ({'day_of_month': 29}, 'day_of_month'),
                 ({'send_time': '08:07'}, 'send_time'), ({'cadence': 'daily'}, 'cadence'), ({'attach': 'doc'}, 'attach'), ({'enabled': 'yes'}, 'enabled'),
                 ({'colour': 'red'}, 'unknown field'), ({'name': '   '}, 'name'), ({'weekday': True}, 'weekday')]
        for extra, word in cases:
            status, body = self.post(**extra)
            self.assertEqual(status, 400, extra)
            self.assertIn(word, body['error'], extra)

    def test_the_scope_cannot_change(self):
        sub = self.make(project='web')
        for key, value in (('project', 'acme-api'), ('org', 'acme-org')):
            status, body = call(self.org_admin, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {key: value})
            self.assertEqual(status, 400)
            self.assertIn('cannot change', body['error'])

    def test_the_caps_per_scope_and_per_person(self):
        for i in range(ReportSubscription.MAX_PER_SCOPE):
            self.make(name=f'n{i}', owner=self.root)
        status, body = self.post(name='one too many')
        self.assertEqual((status, 'already has 20' in body['error']), (400, True))
        ReportSubscription.objects.all().delete()
        extra = Project.objects.create(name='Acme Extra', slug='acme-extra', insert_date=NOW, org=self.org_a)
        scopes = [{'project': self.web}] * 20 + [{'project': self.api}] * 20 + [{'org': self.org_a}] * 10  # each under its scope cap, 50 for one person
        ReportSubscription.objects.bulk_create([ReportSubscription(**scope, owner=self.org_admin, created_by=self.org_admin, name=f'p{i}', recipients=['a@example.org'],
                                                                   send_time=datetime.time(8, 0)) for i, scope in enumerate(scopes)])
        status, body = self.post(name='fifty one', project='acme-extra')
        self.assertEqual((status, 'you already run 50' in body['error']), (400, True), body)

    def test_pausing_resuming_and_changing_the_schedule_move_the_next_slot(self):
        sub = self.make(project='web', next_run_at=NOW + timedelta(days=1))
        status, body = call(self.org_admin, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {'enabled': False})
        self.assertEqual((status, body['next_run_at'], body['enabled']), (200, None, False))
        status, body = call(self.org_admin, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {'enabled': True})
        self.assertIsNotNone(body['next_run_at'])
        before = ReportSubscription.objects.get(pk=sub.pk).next_run_at
        call(self.org_admin, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {'weekday': (before.weekday() + 2) % 7})
        self.assertNotEqual(ReportSubscription.objects.get(pk=sub.pk).next_run_at, before)

    def test_saving_makes_the_saver_the_owner_and_every_change_is_audited(self):
        sub = self.make(project='web', owner=self.org_admin)
        call(self.web_user, 'PATCH', f'/api/v1/report-subscriptions/{sub.pk}', {'name': 'Mine now'})
        self.assertEqual(ReportSubscription.objects.get(pk=sub.pk).owner, self.web_user)
        row = AuditLog.objects.filter(action='report.subscription.update').first()
        self.assertEqual((row.actor, row.detail['recipients']), (self.web_user, ['a@example.org', 'b@example.org']))
        self.post(name='created')
        self.assertTrue(AuditLog.objects.filter(action='report.subscription.create').exists())


class SendTests(SubBase):
    def run_due(self, now=None):
        return report_digests.send_due(now or NOW)

    def test_a_due_report_is_sent_once_to_every_recipient(self):
        sub = self.make()
        self.assertEqual(self.run_due(), {'sent': 1, 'partial': 0, 'failed': 0, 'skipped': 0, 'disabled': 0})
        self.assertEqual(sorted(m.to[0] for m in mail.outbox), ['a@example.org', 'b@example.org'])
        self.assertEqual(self.run_due(), {'sent': 0, 'partial': 0, 'failed': 0, 'skipped': 0, 'disabled': 0})  # the slot moved: a second run sends nothing
        self.assertEqual((len(mail.outbox), ReportDelivery.objects.filter(subscription=sub).count()), (2, 1))
        sub.refresh_from_db()
        self.assertEqual((sub.last_status, sub.last_error), ('sent', ''))
        self.assertGreater(sub.next_run_at, NOW)
        self.assertEqual(ReportDelivery.objects.get().status, 'sent')

    def test_a_stale_copy_of_the_subscription_sends_nothing(self):
        sub = self.make()
        stale = ReportSubscription.objects.get(pk=sub.pk)
        self.assertEqual(report_digests.deliver_period(sub, NOW), 'sent')
        self.assertEqual(report_digests.deliver_period(stale, NOW), '')  # its next_run_at is not the stored one any more
        self.assertEqual(len(mail.outbox), 2)

    def test_an_existing_delivery_for_the_period_blocks_a_second_send(self):
        sub = self.make()
        end = sub.next_run_at
        ReportDelivery.objects.create(subscription=sub, period_start=report_schedule.previous_slot(sub, end), period_end=end, status='sent')
        self.assertEqual(report_digests.deliver_period(sub, NOW), '')
        self.assertEqual(len(mail.outbox), 0)

    def test_a_long_outage_sends_only_the_latest_period_once(self):
        sub = self.make(next_run_at=NOW - timedelta(days=50))
        self.run_due()
        self.run_due()
        self.assertEqual(ReportDelivery.objects.filter(subscription=sub).count(), 1)
        self.assertEqual(len(mail.outbox), 2)

    def test_without_outgoing_mail_a_skipped_delivery_is_recorded_and_the_slot_moves_on(self):
        configure(enabled=False)
        sub = self.make()
        self.assertEqual(self.run_due()['skipped'], 1)
        self.assertEqual(len(mail.outbox), 0)
        sub.refresh_from_db()
        self.assertEqual((sub.last_status, 'not set up' in sub.last_error, sub.next_run_at > NOW), ('skipped', True, True))
        self.assertEqual(ReportDelivery.objects.get().status, 'skipped')
        self.assertEqual(self.run_due()['skipped'], 0)  # nothing piles up

    def test_an_owner_who_lost_access_or_was_removed_switches_the_report_off_with_a_reason(self):
        sub = self.make(project='web', owner=self.web_user)
        ProjectMembership.objects.filter(user=self.web_user).delete()
        self.assertEqual(self.run_due()['disabled'], 1)
        sub.refresh_from_db()
        self.assertEqual((sub.enabled, sub.next_run_at, sub.last_status), (False, None, 'disabled'))
        self.assertIn('no longer has access to Acme Web', sub.last_error)
        self.assertTrue(AuditLog.objects.filter(action='report.subscription.disabled').exists())
        orphan = self.make(name='Orphan', owner=self.org_admin)
        User.objects.filter(pk=self.org_admin.pk).delete()
        self.assertEqual(self.run_due()['disabled'], 1)
        orphan.refresh_from_db()
        self.assertIn('was removed', orphan.last_error)
        self.assertEqual(len(mail.outbox), 0)

    def test_a_connection_failure_is_retried_for_the_failed_recipients_only(self):
        sub = self.make()
        with mock.patch.object(mailer, '_connection', side_effect=OSError('down')):
            self.assertEqual(self.run_due()['failed'], 1)
        d = ReportDelivery.objects.get()
        self.assertEqual((d.status, d.attempts, d.next_retry_at is not None), ('failed', 1, True))
        self.assertTrue(all(r['transient'] for r in d.recipients))
        self.assertEqual(len(mail.outbox), 0)
        self.run_due(d.next_retry_at + timedelta(minutes=1))
        d.refresh_from_db()
        self.assertEqual((d.status, d.attempts, len(mail.outbox)), ('sent', 2, 2))
        self.assertEqual(ReportDelivery.objects.filter(subscription=sub).count(), 1)  # the same period, not a new one

    def test_a_refused_address_is_a_partial_send_and_is_never_retried(self):
        self.make(recipients=['good@example.org', 'bad@example.org'])
        with mock.patch.object(mailer, '_connection', side_effect=lambda cfg: RefusingBackend()):
            self.assertEqual(self.run_due()['partial'], 1)
        d = ReportDelivery.objects.get()
        self.assertEqual(sorted((r['email'], r['status']) for r in d.recipients), [('bad@example.org', 'refused'), ('good@example.org', 'sent')])
        self.assertIsNone(d.next_retry_at)
        sub = d.subscription
        self.assertEqual((sub.last_status, sub.last_error.startswith('1 of 2 failed')), ('partial', True))
        self.assertEqual([m.to[0] for m in mail.outbox], ['good@example.org'])

    def test_a_send_a_dead_worker_left_half_done_is_unknown_and_not_retried(self):
        sub = self.make()
        old = ReportDelivery.objects.create(subscription=sub, period_start=NOW - timedelta(days=8), period_end=NOW - timedelta(days=1), status='sending')
        ReportDelivery.objects.filter(pk=old.pk).update(created_at=NOW - timedelta(hours=3))
        report_digests.expire_stuck(NOW)
        old.refresh_from_db()
        self.assertEqual(old.status, 'unknown')
        self.assertIn('not retried', old.error)
        report_digests.retry_failed(NOW + timedelta(days=1))
        self.assertEqual(len(mail.outbox), 0)

    def test_an_organization_report_writes_an_audit_line_and_no_project_less_activity_row(self):
        from cveFeed.models import AgentActivity
        before = AgentActivity.objects.count()
        self.make(org=True, name='Org weekly')
        self.assertEqual(self.run_due()['sent'], 1)
        self.assertEqual(AgentActivity.objects.count(), before)
        self.assertTrue(AuditLog.objects.filter(action='report.subscription.sent').exists())
        project = self.make(project='web', name='Project weekly')
        self.run_due()
        self.assertTrue(AgentActivity.objects.filter(kind='report_digest', project=self.web).exists())
        self.assertNotIn('Acme Org', ' '.join(AgentActivity.objects.values_list('message', flat=True)))


class MessageTests(SubBase):
    def test_headers_unsubscribe_links_and_both_parts(self):
        sub = self.make()
        report_digests.deliver_period(sub, NOW)
        first, second = sorted(mail.outbox, key=lambda m: m.to[0])
        for m in (first, second):
            self.assertTrue(m.extra_headers['List-Unsubscribe'].startswith('<https://cve.example.org/unsubscribe/'))
            self.assertEqual(m.extra_headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click')
            self.assertEqual(m.extra_headers['Auto-Submitted'], 'auto-generated')
            self.assertIn('Acme Web', m.subject)
            self.assertTrue(m.body.strip())
            self.assertEqual(m.alternatives[0][1], 'text/html')
        self.assertNotEqual(first.extra_headers['List-Unsubscribe'], second.extra_headers['List-Unsubscribe'])
        self.assertIn(f'sub-{sub.pk}.reports.cve.example.org', first.extra_headers['List-Id'])
        self.assertIn(first.extra_headers['List-Unsubscribe'].strip('<>'), first.body)

    def test_the_html_stays_under_the_gmail_clip_with_fifty_findings_and_a_hostile_host_is_inert(self):
        domain = self.domains['acme-web']
        Vulnerability.objects.bulk_create([Vulnerability(subdomain=self.www, target_domain=domain, scan_history=self.scans['acme-web'], name=f'Finding number {i}',
                                                         severity=3, source='nuclei', http_url='https://www.acme.test/', discovered_date=NOW) for i in range(50)])
        sub_row = Subdomain.objects.create(target_domain=domain, scan_history=self.scans['acme-web'], name=HOSTILE_HOST, score=1)
        Vulnerability.objects.create(subdomain=sub_row, target_domain=domain, scan_history=self.scans['acme-web'], name='Hostile <b>title</b>', severity=4,
                                     source='nuclei', http_url='https://x.test/', discovered_date=NOW)
        AssetChange.objects.create(project=self.web, domain=domain, host=HOSTILE_HOST, kind='host_new', detected_at=NOW - timedelta(days=1))
        sub = self.make(next_run_at=NOW - timedelta(hours=1))
        report_digests.deliver_period(sub, NOW)
        html = mail.outbox[0].alternatives[0][0]
        self.assertLess(len(html.encode('utf-8')), 100_000)
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;img src=x onerror=1&gt;.example', html)
        self.assertNotIn('<b>title</b>', html)
        self.assertIn('Hostile &lt;b&gt;title&lt;/b&gt;', html)
        self.assertNotIn('onerror=1>', mail.outbox[0].body.replace('<img src=x onerror=1>.example', ''))  # the text part names it once, as text

    def test_the_html_is_table_based_with_no_external_resources(self):
        sub = self.make()
        report_digests.deliver_period(sub, NOW)
        html = mail.outbox[0].alternatives[0][0]
        for needle in ('role="presentation"', 'max-width:600px', 'prefers-color-scheme:dark', '@media (max-width:620px)', 'At a glance', 'Top findings', 'New hosts', 'Hygiene'):
            self.assertIn(needle, html)
        for forbidden in ('<img', '<script', '<link', 'src="http', "url(http", '@import'):
            self.assertNotIn(forbidden, html)
        with open(os.path.join(os.path.dirname(report_digest.__file__), 'templates/cveFeed/email/report_digest.html'), encoding='utf-8') as fh:
            self.assertNotIn('|safe', fh.read())

    def test_the_numbers_and_the_first_report_note(self):
        sub = self.make()
        report_digests.deliver_period(sub, NOW)
        body = mail.outbox[0].body
        self.assertIn('First report: no comparison yet', body)
        self.assertIn('Open findings:', body)
        self.assertIn('Fire 1', body)
        self.assertIn('/cve/acme-web/vulns/', body)

    def test_a_comparison_with_an_earlier_snapshot_says_up_or_down(self):
        from cveFeed.models import StatsSnapshot
        StatsSnapshot.objects.create(project=self.web, date=(NOW - timedelta(days=9)).date(), hosts=1, exposed_hosts=3, open_findings={'critical': 1, 'high': 5, 'medium': 0, 'low': 0})
        sub = self.make()
        report_digests.deliver_period(sub, NOW)
        body = mail.outbox[0].body
        self.assertIn('since last week', body)
        self.assertNotIn('First report', body)

    def test_the_subject_and_the_threat_slot(self):
        start = NOW - timedelta(days=7)
        digest = report_digest.build(report_scope.resolve(SimpleNamespace(user=self.org_admin, token=None), project='acme-web'), start, NOW, 'weekly', NOW)
        self.assertEqual(digest['threats'], [])
        subject = report_digest.subject(digest)
        self.assertTrue(subject.startswith('cvENGINE weekly report: Acme Web ('))
        self.assertLessEqual(len(subject), 120)
        digest['threats'] = [{'source': 'zero_wire', 'title': 'A <b>briefing</b>', 'summary': 'Update now.', 'link': 'https://radar.cloudflare.com/zero-wire/x', 'badges': ['Cloudflare Zero Wire'],
                              'cve_ids': [], 'impact_line': '3 of your hosts match by version', 'impact': 'matched', 'fixed_in': ['1.2.3']}]
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        self.assertIn("most important vulnerabilities", html)
        self.assertIn('A &lt;b&gt;briefing&lt;/b&gt;', html)
        self.assertIn('3 of your hosts match by version', text)


class AttachmentTests(SubBase):
    def test_a_pdf_under_the_cap_is_attached_with_the_right_type(self):
        sub = self.make(attach='pdf')
        report_digests.deliver_period(sub, NOW)
        name, content, mimetype = mail.outbox[0].attachments[0]
        self.assertTrue(name.startswith('cvengine-report-acme-web-') and name.endswith('.pdf'))
        self.assertEqual(mimetype, 'application/pdf')
        self.assertTrue(content.startswith(b'%PDF'))
        self.assertEqual(ReportDelivery.objects.get().attachment, 'pdf')
        self.assertIn('attached', mail.outbox[0].body)

    def test_a_csv_is_attached(self):
        sub = self.make(attach='csv')
        report_digests.deliver_period(sub, NOW)
        name, content, mimetype = mail.outbox[0].attachments[0]
        self.assertEqual((name.endswith('.csv'), mimetype), (True, 'text/csv'))
        self.assertIn('Kind,Heat,Severity', content if isinstance(content, str) else content.decode('utf-8'))

    def test_over_the_cap_there_is_no_attachment_and_the_body_says_so(self):
        sub = self.make(attach='pdf')
        with mock.patch.object(report_scope, 'attach_max_mb', return_value=0):
            report_digests.deliver_period(sub, NOW)
        self.assertEqual(mail.outbox[0].attachments, [])
        self.assertIn('over the 0 MB attachment limit', mail.outbox[0].body)
        self.assertEqual(ReportDelivery.objects.get().attachment, 'too_large')

    def test_a_report_that_cannot_be_made_is_replaced_by_a_note_and_the_email_still_goes(self):
        sub = self.make(attach='pdf')
        with mock.patch.object(report_pdf, 'render_pdf', side_effect=report_pdf.RenderError('no')):
            report_digests.deliver_period(sub, NOW)
        self.assertEqual((len(mail.outbox), mail.outbox[0].attachments), (2, []))
        self.assertIn('could not be attached', mail.outbox[0].body)
        self.assertEqual(ReportDelivery.objects.get().attachment, 'failed')

    def test_the_cap_comes_from_the_environment_within_its_range(self):
        for value, expected in (('', 10), ('3', 3), ('0', 1), ('99', 25), ('x', 10)):
            with mock.patch.dict('os.environ', {'CVENGINE_REPORT_EMAIL_MAX_MB': value}):
                self.assertEqual(report_scope.attach_max_mb(), expected, value)


class UnsubscribeTests(SubBase):
    def link(self, sub, email='a@example.org'):
        return f'/unsubscribe/{report_digests.unsubscribe_token(sub, email)}/'

    def test_get_changes_nothing_and_post_removes_the_address(self):
        sub = self.make()
        client = Client()
        page = client.get(self.link(sub))
        self.assertEqual(page.status_code, 200)
        self.assertIn('a•••@example.org', page.content.decode())
        sub.refresh_from_db()
        self.assertEqual(sub.recipients, ['a@example.org', 'b@example.org'])
        self.assertEqual(client.post(self.link(sub)).status_code, 200)
        sub.refresh_from_db()
        self.assertEqual(sub.recipients, ['b@example.org'])
        self.assertEqual([o['email'] for o in sub.opted_out], ['a@example.org'])
        self.assertTrue(sub.enabled)
        row = AuditLog.objects.get(action='report.subscription.unsubscribe')
        self.assertEqual((row.actor, row.actor_name), (None, 'a@example.org'))
        self.assertEqual(client.post(self.link(sub)).status_code, 404)  # the link is spent
        self.assertIn('not valid', client.get(self.link(sub)).content.decode())

    def test_the_last_recipient_switches_the_report_off(self):
        sub = self.make(recipients=['a@example.org'])
        Client().post(self.link(sub))
        sub.refresh_from_db()
        self.assertEqual((sub.enabled, sub.next_run_at, sub.last_error), (False, None, 'every recipient unsubscribed'))

    def test_one_click_post_without_a_csrf_token_works_for_an_anonymous_client(self):
        sub = self.make()
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post(self.link(sub), 'List-Unsubscribe=One-Click', content_type='application/x-www-form-urlencoded').status_code, 200)
        sub.refresh_from_db()
        self.assertEqual(sub.recipients, ['b@example.org'])

    def test_forged_foreign_and_rotated_tokens_get_the_same_404(self):
        sub, other = self.make(), self.make(name='Other')
        good = self.link(sub)
        client = Client()
        for bad in ('/unsubscribe/not-a-token/', good[:-6] + 'xxxxx/', f'/unsubscribe/{report_digests.unsubscribe_token(sub, "stranger@example.org")}/'):
            self.assertEqual(client.post(bad).status_code, 404, bad)
        swapped = report_digests.unsubscribe_token(other, 'a@example.org')
        ReportSubscription.objects.filter(pk=other.pk).update(unsubscribe_key='f' * 32)
        self.assertEqual(client.post(f'/unsubscribe/{swapped}/').status_code, 404)  # a rotated key voids old links
        sub.refresh_from_db()
        self.assertEqual(sub.recipients, ['a@example.org', 'b@example.org'])

    def test_the_link_of_a_test_send_says_it_is_a_test(self):
        page = Client().post('/unsubscribe/test/')
        self.assertIn('This was a test email', page.content.decode())
        self.make()
        self.assertEqual(ReportSubscription.objects.first().recipients, ['a@example.org', 'b@example.org'])

    def test_re_adding_an_address_that_unsubscribed_needs_confirmation(self):
        sub = self.make()
        Client().post(self.link(sub))
        url = f'/api/v1/report-subscriptions/{sub.pk}'
        status, body = call(self.org_admin, 'PATCH', url, {'recipients': ['a@example.org', 'b@example.org']})
        self.assertEqual(status, 400)
        self.assertIn('unsubscribed on', body['error'])
        self.assertIn('confirm_opted_out', body['error'])
        status, body = call(self.org_admin, 'PATCH', url, {'recipients': ['a@example.org', 'b@example.org'], 'confirm_opted_out': True})
        self.assertEqual((status, body['recipients'], body['opted_out']), (200, ['a@example.org', 'b@example.org'], []))


class TestSendTests(SubBase):
    def test_a_test_goes_only_to_the_caller_and_queues_the_task(self):
        sub = self.make()
        status, body = call(self.org_admin, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')
        self.assertEqual((status, body), (202, {'status': 'queued', 'to': 'orgadmin@example.test'}))
        self.queued.assert_called_once()
        self.assertEqual(self.queued.call_args.kwargs['args'], [sub.pk, self.org_admin.pk])
        result = report_digests.send_test_by_id(sub.pk, self.org_admin.pk)
        self.assertEqual(result['status'], 'sent')
        self.assertEqual([m.to for m in mail.outbox], [['orgadmin@example.test']])
        self.assertTrue(mail.outbox[0].subject.startswith('[Test] cvENGINE weekly report'))
        self.assertIn('/unsubscribe/test/', mail.outbox[0].extra_headers['List-Unsubscribe'])
        d = ReportDelivery.objects.get()
        self.assertEqual((d.test, d.requested_by), (True, self.org_admin))
        sub.refresh_from_db()
        self.assertEqual(sub.last_status, '')  # a test never touches the report's own last result
        again = report_digests.send_test(sub, self.org_admin)
        self.assertEqual(ReportDelivery.objects.filter(test=True).count(), 2)  # not bound by the one-per-period rule
        self.assertEqual(again.status, 'sent')

    def test_a_second_test_within_a_minute_is_429_and_a_caller_without_an_address_is_400(self):
        sub = self.make()
        self.assertEqual(call(self.org_admin, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')[0], 202)
        self.assertEqual(call(self.org_admin, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')[0], 429)
        User.objects.filter(pk=self.org_member.pk).update(email='')
        self.assertEqual(call(self.org_member, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')[0], 400)

    def test_without_outgoing_mail_a_test_is_409(self):
        configure(enabled=False)
        sub = self.make()
        self.assertEqual(call(self.org_admin, 'POST', f'/api/v1/report-subscriptions/{sub.pk}/test')[0], 409)

    def test_a_person_who_lost_access_gets_no_test(self):
        sub = self.make(project='web')
        OrgMembership.objects.filter(user=self.org_member).delete()
        self.assertEqual(report_digests.send_test_by_id(sub.pk, self.org_member.pk)['status'], 'skipped')
        self.assertEqual(len(mail.outbox), 0)


class PreviewTests(SubBase):
    def test_the_html_preview_is_a_sandboxed_page_that_may_be_framed_by_this_site(self):
        sub = self.make()
        response = client_for(self.org_admin).get(f'/api/v1/report-subscriptions/{sub.pk}/preview?format=html')
        self.assertEqual(response.status_code, 200)
        policy = response['Content-Security-Policy']
        self.assertIn("frame-ancestors 'self'", policy)
        self.assertIn('sandbox', policy)
        self.assertIn("default-src 'none'", policy)
        self.assertEqual((response['X-Content-Type-Options'], response['Cache-Control']), ('nosniff', 'private, no-store'))
        self.assertIn('At a glance', response.content.decode())

    def test_text_and_json_previews_give_the_subject_and_the_digest(self):
        sub = self.make()
        status, body = call(self.org_admin, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/preview?format=json')
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {'subject', 'text', 'digest'})
        self.assertEqual(body['digest']['scope_name'], 'Acme Web')
        self.assertEqual(call(self.org_admin, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/preview?format=pdf')[0], 400)
        self.assertEqual(len(mail.outbox), 0)  # a preview sends nothing

    def test_a_project_member_cannot_preview_an_organization_report(self):
        sub = self.make(org=True, name='Org weekly')
        self.assertEqual(call(self.web_user, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/preview?format=json')[0], 404)
        status, body = call(self.org_member, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/preview?format=json')
        self.assertEqual((status, body['digest']['scope_kind']), (200, 'org'))

    def test_unsaved_settings_can_be_previewed(self):
        status, body = call(self.org_member, 'GET', '/api/v1/reporting/digest-preview?project=acme-web&cadence=monthly&format=json')
        self.assertEqual((status, body['digest']['cadence']), (200, 'monthly'))
        self.assertEqual(call(self.web_user, 'GET', '/api/v1/reporting/digest-preview?org=acme-org&format=json')[0], 404)
        self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/digest-preview?cadence=weekly')[0], 400)
        self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/digest-preview?project=acme-web&cadence=daily')[0], 400)

    def test_deliveries_list_the_last_sends(self):
        sub = self.make()
        report_digests.deliver_period(sub, NOW)
        status, body = call(self.org_admin, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/deliveries')
        self.assertEqual((status, body['results'][0]['status'], body['results'][0]['sent']), (200, 'sent', 2))
        self.assertEqual(call(self.outsider, 'GET', f'/api/v1/report-subscriptions/{sub.pk}/deliveries')[0], 404)


class McpTests(SubBase):
    def test_create_list_update_pause_delete_round_trip(self):
        _, token = create_token(self.org_admin, 'agent')
        error, data = tool_call(token, 'create_report_subscription', {'project': 'acme-web', 'name': 'Agent weekly', 'recipients': ['a@example.org']})
        self.assertFalse(error, data)
        sub_id = data['id']
        error, data = tool_call(token, 'list_report_subscriptions', {'project': 'acme-web'})
        self.assertEqual([s['id'] for s in data['results']], [sub_id])
        error, data = tool_call(token, 'update_report_subscription', {'id': sub_id, 'enabled': False})
        self.assertEqual((error, data['enabled']), (False, False))
        error, data = tool_call(token, 'get_report_subscription', {'id': sub_id})
        self.assertEqual(data['next_run_at'], None)
        error, data = tool_call(token, 'preview_report_subscription', {'id': sub_id})
        self.assertEqual(set(data), {'subject', 'text', 'digest'})
        error, data = tool_call(token, 'list_report_deliveries', {'id': sub_id})
        self.assertEqual(data['results'], [])
        error, data = tool_call(token, 'send_report_subscription_test', {'id': sub_id})
        self.assertEqual((error, data['status']), (False, 'queued'))
        error, _ = tool_call(token, 'delete_report_subscription', {'id': sub_id})
        self.assertFalse(error)
        self.assertFalse(ReportSubscription.objects.exists())

    def test_a_read_only_token_is_refused_on_the_write_tools_only(self):
        sub = self.make()
        _, ro = create_token(self.org_admin, 'ro', read_only=True)
        for name, args in (('create_report_subscription', {'project': 'acme-web', 'name': 'x', 'recipients': ['a@example.org']}),
                           ('update_report_subscription', {'id': sub.pk, 'name': 'x'}), ('delete_report_subscription', {'id': sub.pk}),
                           ('send_report_subscription_test', {'id': sub.pk})):
            error, text = tool_call(ro, name, args)
            self.assertTrue(error, name)
        for name, args in (('list_report_subscriptions', {}), ('get_report_subscription', {'id': sub.pk}), ('preview_report_subscription', {'id': sub.pk}),
                           ('list_report_deliveries', {'id': sub.pk})):
            error, _ = tool_call(ro, name, args)
            self.assertFalse(error, name)
        self.assertTrue(ReportSubscription.objects.filter(pk=sub.pk).exists())


class TenancyTests(TestCase):
    def test_the_models_are_listed_where_the_coverage_test_expects_them(self):
        from tenancy import scope
        self.assertIn('cveFeed.ReportSubscription', scope.UNSCOPED)
        self.assertNotIn('cveFeed.ReportSubscription', scope.SCOPES)
        self.assertIn('cveFeed.ReportExport', scope.NULLABLE)
        from tenancy import roles
        self.assertTrue(roles.ALWAYS_OPEN.match('/unsubscribe/abc/'))
