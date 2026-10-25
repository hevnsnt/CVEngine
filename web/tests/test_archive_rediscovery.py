from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.archive_rediscovery import check_one, observe, run_page
from cveFeed.models import ArchiveRediscovery, HostExclusion, HostState
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class ArchivedRediscoveryTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='Archived', slug='archived-org')
        self.project = Project.objects.create(name='Archived', slug='archived', org=self.org, insert_date=now)
        self.other = Project.objects.create(name='Other', slug='archive-other', insert_date=now)
        self.domain = Domain.objects.create(name='archive.example', project=self.project, insert_date=now)
        self.user = User.objects.create_user('archive-user', password='x')
        self.auditor = User.objects.create_user('archive-auditor', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
        _, self.token = create_token(self.user, 'archive-test')
        _, self.audit_token = create_token(self.auditor, 'archive-audit')
        self.engine = EngineType.objects.create(engine_name='archive-engine', yaml_configuration='x', default_engine=True)

    def state(self, name, **fields):
        Subdomain.objects.create(target_domain=self.domain, name=name)
        return HostState.objects.create(project=self.project, domain=self.domain, host=name,
                                        archived_at=timezone.now() - timedelta(days=31), **fields)

    def test_daily_schedule_and_all_pages_resume_without_first_batch_truncation(self):
        from django_celery_beat.models import PeriodicTask
        schedule = PeriodicTask.objects.get(name='cvengine-daily-archived-rediscovery')
        self.assertEqual((schedule.task, schedule.queue, schedule.interval.every, schedule.interval.period),
                         ('rediscover_archived_hosts', 'cve_feed_queue', 1, 'days'))
        for i in range(57):
            self.state(f'h{i}.archive.example')
        resolver = lambda name: ('absent', set())
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.rediscover_archived_hosts.apply_async') as continue_task:
            first = run_page(resolver=resolver)
            self.assertEqual(first['checked'], 25)
            second = run_page(first['run_id'], resolver=resolver)
            final = run_page(first['run_id'], resolver=resolver)
        self.assertEqual((second['checked'], final['checked']), (50, 57))
        self.assertEqual(continue_task.call_count, 2)
        self.assertEqual(ArchiveRediscovery.objects.get(pk=first['run_id']).status, 'completed')
        self.assertEqual(run_page(resolver=resolver)['skipped'], 'already completed today')

    def test_dns_reappearance_queues_scoped_assessment_and_keeps_history(self):
        row = self.state('back.archive.example')
        def resolver(name):
            return ('absent', set()) if name.startswith('cvengine-nonexistent-') else ('resolved', {'8.8.8.8'})
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
            sender.return_value.id = 'back-task'
            self.assertEqual(check_one(row, resolver=resolver), 'reactivated')
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertEqual(row.archive_check_status, 'rediscovered_dns')
        self.assertIsNotNone(row.archive_assessment_id)
        self.assertEqual(row.archive_assessment.host, row.host)
        self.assertEqual(row.archive_assessment.status, 'queued')

    def test_a_manual_archive_is_never_lifted_by_rediscovery_or_a_new_scan(self):
        from cveFeed.changes import record_scan_changes
        row = self.state('kept.archive.example', archived_by_user=True, state={'ips': {'8.8.8.8': {'ports': {}}}})
        resolver = lambda name: ('resolved', {'8.8.8.8'})  # noqa: E731
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.tasks.assess_host.apply_async') as sender, \
             mock.patch('cveFeed.tasks.rediscover_archived_hosts.apply_async'):
            self.assertEqual(check_one(row, resolver=resolver), 'checked')
            self.assertEqual(run_page(resolver=resolver)['checked'], 0)  # not even visited by the daily run
        sender.assert_not_called()
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2)
        sub = Subdomain.objects.create(target_domain=self.domain, scan_history=scan, name=row.host)
        sub.ip_addresses.add(IpAddress.objects.create(address='8.8.8.8'))
        with mock.patch('cveFeed.retest.queue_retests'):
            record_scan_changes(scan.pk, resolver=lambda names: set())
        row.refresh_from_db()
        self.assertIsNotNone(row.archived_at)
        self.assertTrue(row.archived_by_user)

    def test_any_enqueue_failure_puts_the_archive_back(self):
        row = self.state('flaky.archive.example')
        archived = row.archived_at
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
             mock.patch('cveFeed.host_assessment.enqueue', side_effect=OSError('database went away')), \
             self.assertLogs('cveFeed.archive_rediscovery', 'ERROR'):
            self.assertEqual(check_one(row, resolver=lambda name: ('absent', set()) if name.startswith('cvengine-nonexistent-')
                                       else ('resolved', {'8.8.8.8'})), 'error')
        row.refresh_from_db()
        self.assertEqual(row.archived_at, archived)
        self.assertEqual((row.archive_check_status, row.archive_check_error), ('error', 'OSError'))

    def test_dns_failures_wildcard_and_blocked_addresses_do_not_reactivate(self):
        row = self.state('uncertain.archive.example')
        for resolver, status in (
                (lambda name: ('error', set()), 'error'),
                (lambda name: ('resolved', {'8.8.8.8'}), 'ambiguous_wildcard'),
                (lambda name: ('resolved', {'127.0.0.1'}) if not name.startswith('cvengine-') else ('absent', set()), 'blocked')):
            self.assertEqual(observe(row, resolver=resolver)['status'], status)
            with mock.patch('cveFeed.scan_control.pause_requested', return_value=False), \
                 mock.patch('cveFeed.tasks.assess_host.apply_async') as sender:
                check_one(row, resolver=resolver)
                sender.assert_not_called()
            row.refresh_from_db()
            self.assertIsNotNone(row.archived_at)

    def test_ip_asset_needs_a_known_answering_port_not_dns(self):
        domain = Domain.objects.create(name='8.8.4.4', project=self.project, insert_date=timezone.now())
        row = HostState.objects.create(project=self.project, domain=domain, host='8.8.4.4', archived_at=timezone.now(),
            state={'ips': {'8.8.4.4': {'ports': {'443/tcp': {'service': 'https'}}}}})
        self.assertEqual(observe(row, tcp_probe=lambda ip, port: False)['status'], 'unobserved')
        self.assertEqual(observe(row, tcp_probe=lambda ip, port: port == 443)['status'], 'rediscovered_ip')
        row.state = {'ips': {'8.8.4.4': {'ports': {}}}}
        self.assertEqual(observe(row, tcp_probe=lambda ip, port: True)['status'], 'no_safe_liveness_probe')

    def test_exclusion_pause_and_cross_project_scope_prevent_reactivation(self):
        row = self.state('blocked.archive.example')
        HostExclusion.objects.create(org=self.org, host=row.host)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row, resolver=lambda name: ('resolved', {'8.8.8.8'})), 'deferred')
        row.refresh_from_db()
        self.assertIsNotNone(row.archived_at)
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            self.assertEqual(check_one(row), 'paused')
        row.project = self.other
        row.save(update_fields=['project'])
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(check_one(row), 'deferred')

    def test_manual_archive_pin_restore_access_and_scanner_scheduling_gate(self):
        name = 'manual.archive.example'
        sub = Subdomain.objects.create(target_domain=self.domain, name=name)
        base = f'/api/v1/projects/archived/hosts/{name}'
        self.assertEqual(call(self.audit_token, 'POST', base + '/archive', {})[0], 403)
        status, pinned = call(self.token, 'POST', base + '/pin', {'pinned': True})
        self.assertEqual(status, 200)
        self.assertTrue(pinned['pinned'])
        self.assertEqual(call(self.token, 'POST', base + '/archive', {})[0], 409)
        call(self.token, 'POST', base + '/pin', {'pinned': False})
        status, archived = call(self.token, 'POST', base + '/archive', {'reason': 'Owner review'})
        self.assertEqual(status, 200)
        self.assertIsNotNone(archived['archived_at'])
        self.assertTrue(HostState.objects.get(project=self.project, host=sub.name).archived_by_user)
        from cveFeed.fullscan import candidates
        ip = IpAddress.objects.create(address='8.8.8.8')
        sub.ip_addresses.add(ip)
        self.assertFalse(candidates().filter(pk=ip.pk).exists())
        self.assertEqual(call(self.token, 'POST', '/api/v1/projects/archived/host-assessments', {'host_id': sub.pk})[0], 409)
        status, restored = call(self.token, 'POST', base + '/restore', {})
        self.assertEqual(status, 200)
        self.assertIsNone(restored['archived_at'])
        self.assertFalse(HostState.objects.get(project=self.project, host=sub.name).archived_by_user)
        self.assertTrue(candidates().filter(pk=ip.pk).exists())
        self.assertEqual(call(self.token, 'POST', f'/api/v1/projects/archive-other/hosts/{name}/restore', {})[0], 404)

    def test_shared_ip_full_sweep_uses_only_active_projects(self):
        from cveFeed.fullscan import _project_of, active_attached, candidates
        archived = self.state('shared.archive.example')
        other_domain = Domain.objects.create(name='active.other.example', project=self.other, insert_date=timezone.now())
        archived_sub = Subdomain.objects.get(target_domain=self.domain, name=archived.host)
        active_sub = Subdomain.objects.create(target_domain=other_domain, name=other_domain.name)
        ip = IpAddress.objects.create(address='8.8.8.8')
        archived_sub.ip_addresses.add(ip)
        active_sub.ip_addresses.add(ip)
        self.assertEqual(list(active_attached(ip).values_list('name', flat=True)), [active_sub.name])
        self.assertEqual(_project_of(ip), self.other.pk)
        self.assertTrue(candidates().filter(pk=ip.pk).exists())

    def test_new_positive_scan_evidence_reactivates_without_erasing_history(self):
        from cveFeed.changes import record_scan_changes
        from cveFeed.models import AssetChange
        row = self.state('seen.archive.example', state={'ips': {'8.8.8.8': {'ports': {}}}})
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine,
                                          start_scan_date=timezone.now(), scan_status=2)
        sub = Subdomain.objects.create(target_domain=self.domain, scan_history=scan, name=row.host)
        sub.ip_addresses.add(IpAddress.objects.create(address='8.8.8.8'))
        with mock.patch('cveFeed.retest.queue_retests'):
            record_scan_changes(scan.pk, resolver=lambda names: set())
        row.refresh_from_db()
        self.assertIsNone(row.archived_at)
        self.assertEqual(row.archive_check_status, 'rediscovered_scan')
        self.assertTrue(AssetChange.objects.filter(project=self.project, host=row.host, kind='host_returned').exists())
