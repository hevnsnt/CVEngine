import subprocess
import time
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import discovery
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project, ProjectMembership
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call, rpc


class ScansListAndStopTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='SS', slug='ss')
        cls.p = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=org)
        cls.other = Project.objects.create(name='Other', slug='ss-other', insert_date=now, org=org)
        EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        cls.user, cls.audit = User.objects.create_user('ssuser', password='x'), User.objects.create_user('ssaudit', password='x')
        ProjectMembership.objects.create(user=cls.user, project=cls.p, role='user')
        ProjectMembership.objects.create(user=cls.audit, project=cls.p, role='audit')
        _, cls.tok = create_token(cls.user, 'w')
        _, cls.tok_ro = create_token(cls.user, 'r', read_only=True)
        _, cls.tok_audit = create_token(cls.audit, 'a')

    def bulk(self, n=5, project='acme'):
        text = '\n'.join(f'h{i}.acme.example' for i in range(n))
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
            status, data = call(self.tok, 'POST', f'/api/v1/projects/{project}/targets/bulk', {'text': text})
        self.assertEqual(status, 201)
        return data['scan_ids']

    def scans(self, **q):
        from urllib.parse import urlencode
        status, data = call(self.tok, 'GET', '/api/v1/projects/acme/scans?' + urlencode(q))
        self.assertEqual(status, 200, data)
        return data

    # -- the empty list -----------------------------------------------------------------------------------------------
    def test_scans_started_by_a_bulk_add_are_listed_with_their_status_including_queued(self):
        ids = self.bulk(5)
        ScanHistory.objects.filter(pk=ids[1]).update(scan_status=1)  # one is running
        data = self.scans()
        self.assertEqual(data['count'], 5)
        by_id = {s['id']: s for s in data['results']}
        self.assertEqual((by_id[ids[1]]['status'], by_id[ids[0]]['status'], by_id[ids[0]]['queue_position']), (1, -1, 0))
        self.assertEqual(self.scans(status='queued')['count'], 4)
        self.assertEqual(self.scans(status='running')['count'], 1)

    def test_running_scans_come_first_then_queued_next_up_first_then_the_rest_newest_first(self):
        ids = self.bulk(6)
        ScanHistory.objects.filter(pk=ids[4]).update(scan_status=1)
        ScanHistory.objects.filter(pk=ids[2]).update(scan_status=2)
        ScanHistory.objects.filter(pk=ids[0]).update(scan_status=3)
        order = [s['id'] for s in self.scans()['results']]
        self.assertEqual(order, [ids[4], ids[1], ids[3], ids[5], ids[2], ids[0]])

    def test_the_list_costs_a_fixed_number_of_queries_however_many_hosts_and_findings_a_scan_has(self):
        ids = self.bulk(30)
        scan = ScanHistory.objects.get(pk=ids[0])
        for i in range(40):
            sub = Subdomain.objects.create(scan_history=scan, target_domain=scan.domain, name=f's{i}.acme.example')
            Vulnerability.objects.create(name=f'v{i}', severity=2, subdomain=sub, target_domain=scan.domain, scan_history=scan, http_url='x')
        with CaptureQueriesContext(connection) as ctx:
            data = self.scans(page_size=50)
        self.assertLess(len(ctx), 25)
        first = next(s for s in data['results'] if s['id'] == ids[0])
        self.assertEqual((first['hosts'], first['findings'], first['top_severity']), (40, 40, 'medium'))

    # -- stop ---------------------------------------------------------------------------------------------------------
    def test_stopping_a_queued_scan_aborts_it_and_the_pipeline_skips_it(self):
        ids = self.bulk(2)
        with mock.patch('reNgine.celery.app.control.revoke') as revoke:
            status, data = call(self.tok, 'POST', f'/api/v1/projects/acme/scans/{ids[0]}/stop')
        self.assertEqual((status, data), (200, {'stopped': 1, 'scan_ids': [ids[0]]}))
        scan = ScanHistory.objects.get(pk=ids[0])
        self.assertEqual(scan.scan_status, 3)
        self.assertIsNotNone(scan.stop_scan_date)
        self.assertEqual(set(ScanActivity.objects.filter(scan_of=scan).values_list('status', flat=True)), {3})
        revoke.assert_not_called()  # a queued task has no id yet; it is skipped when a worker reaches it
        ran = []
        out = discovery.run_pipeline(ids[0], stream=lambda *a, **k: ran.append(1) or iter([]))
        self.assertEqual((out['status'], ran), ('aborted', []))
        self.assertEqual(ScanHistory.objects.get(pk=ids[1]).scan_status, -1)  # the next one is untouched
        self.assertEqual(call(self.tok, 'POST', f'/api/v1/projects/acme/scans/{ids[0]}/stop')[0], 409)  # already stopped
        self.assertEqual(self.scans(status='aborted')['count'], 1)

    def test_stopping_a_running_scan_revokes_its_task_raises_the_flag_and_aborts_its_activities(self):
        ids = self.bulk(1)
        ScanHistory.objects.filter(pk=ids[0]).update(scan_status=1, celery_ids=['task-1'])
        ScanActivity.objects.filter(scan_of_id=ids[0]).update(status=1)
        with mock.patch('reNgine.celery.app.control.revoke') as revoke:
            self.assertEqual(call(self.tok, 'POST', f'/api/v1/projects/acme/scans/{ids[0]}/stop')[0], 200)
        revoke.assert_called_once_with('task-1', terminate=True, signal='SIGTERM')
        self.assertTrue(resources.abort_requested(ids[0]))
        self.assertEqual(ScanHistory.objects.get(pk=ids[0]).scan_status, 3)
        self.assertEqual(set(ScanActivity.objects.filter(scan_of_id=ids[0]).values_list('status', flat=True)), {3})
        self.assertTrue(AgentActivity.objects.filter(message__contains=f'(scan #{ids[0]})', message__startswith='Stopped').exists())
        resources.clear_abort(ids[0])

    def test_stop_all_stops_running_and_queued_scans_of_this_project_only(self):
        ids = self.bulk(4)
        ScanHistory.objects.filter(pk=ids[0]).update(scan_status=1)
        ScanHistory.objects.filter(pk=ids[3]).update(scan_status=2)
        domain = Domain.objects.create(name='else.example', project=self.other, insert_date=timezone.now())
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
            theirs = discovery.start_discovery(domain)
        with mock.patch('reNgine.celery.app.control.revoke'):
            status, data = call(self.tok, 'POST', '/api/v1/projects/acme/scans/stop')
        self.assertEqual((status, data['stopped'], sorted(data['scan_ids'])), (200, 3, sorted(ids[:3])))
        self.assertEqual(ScanHistory.objects.get(pk=ids[3]).scan_status, 2)  # finished stays finished
        self.assertEqual(ScanHistory.objects.get(pk=theirs.id).scan_status, -1)
        for i in ids[:3]:
            resources.clear_abort(i)

    def test_stopping_needs_write_access(self):
        ids = self.bulk(1)
        self.assertEqual(call(self.tok_ro, 'POST', f'/api/v1/projects/acme/scans/{ids[0]}/stop')[0], 403)
        self.assertEqual(call(self.tok_ro, 'POST', '/api/v1/projects/acme/scans/stop')[0], 403)
        self.assertEqual(call(self.tok_audit, 'POST', '/api/v1/projects/acme/scans/stop')[0], 403)
        self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/ss-other/scans/stop')[0], 404)
        self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/acme/scans/999999/stop')[0], 404)
        self.assertEqual(ScanHistory.objects.get(pk=ids[0]).scan_status, -1)

    def test_the_stop_tools_exist_in_mcp(self):
        ids = self.bulk(2)
        with mock.patch('reNgine.celery.app.control.revoke'):
            status, data = rpc(self.tok, 'tools/call', {'name': 'stop_scan', 'arguments': {'project': 'acme', 'scan_id': ids[0]}})
            self.assertEqual(status, 200)
            status, data = rpc(self.tok, 'tools/call', {'name': 'stop_all_scans', 'arguments': {'project': 'acme'}})
        self.assertEqual(set(ScanHistory.objects.filter(pk__in=ids).values_list('scan_status', flat=True)), {3})
        _, listing = rpc(self.tok_ro, 'tools/list')
        self.assertIn('stop_all_scans', str(listing))
        err = rpc(self.tok_ro, 'tools/call', {'name': 'stop_all_scans', 'arguments': {'project': 'acme'}})[1]
        self.assertIn('read only', str(err))

    # -- the pipeline and the scanner processes -----------------------------------------------------------------------
    def test_the_pipeline_checks_for_a_stop_between_stages_and_exits_cleanly(self):
        from agentapi import services
        ids = self.bulk(1)
        scan = ScanHistory.objects.get(pk=ids[0])
        events = [{'type': 'DNS_NAME', 'id': 'D1', 'data': 'h0.acme.example', 'host': 'h0.acme.example', 'module': 'SEED',
                   'resolved_hosts': ['192.0.2.1'], 'parent': 'S'}]
        later = []

        def nmap_runner(*a, **k):
            services._abort_scan(scan)  # a person presses Stop while nmap runs
            return ''
        with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('reNgine.celery.app.control.revoke'), \
                mock.patch('cveFeed.tasks.run_hygiene_task.delay') as hygiene:
            out = discovery.run_pipeline(scan.id, stream=lambda *a, **k: iter(events), nmap_runner=nmap_runner,
                light_stream=lambda path, **k: later.append('light') or iter([]), targeted_stream=lambda path, **k: later.append('t') or iter([]),
                db_exposure_checks={}, provider=None, route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
        self.assertEqual(out['status'], 'aborted')
        self.assertEqual(later, [])  # nothing after the stage that was running
        hygiene.assert_not_called()
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, 3)  # not overwritten with finished
        self.assertFalse(ScanActivity.objects.filter(scan_of=scan, name='nuclei_light_scan').exists())
        resources.clear_abort(scan.id)

    def test_stopping_kills_the_scanner_process_and_releases_the_memory_reservation(self):
        store = resources.MemoryStore()
        proc = None
        with mock.patch.object(resources, 'HEARTBEAT_SECONDS', 0.05):
            with self.assertRaises(resources.ScanAborted):
                with resources.scan_context(987001):
                    with resources.heavy_job('nmap', label='x', store=store, state_fn=lambda: {
                            'available_mb': 4000, 'limit_mb': 4000, 'total_mb': 4000, 'used_mb': 0}) as job:
                        proc = subprocess.Popen(['sleep', '60'], start_new_session=True)
                        job.attach(proc)
                        resources.request_abort(987001)
                        for _ in range(100):
                            if proc.poll() is not None:
                                break
                            time.sleep(0.05)
                        job.raise_if_killed()
        self.assertIsNotNone(proc.poll())  # the process is gone
        self.assertEqual(store.live(time.time()), [])  # and so is its reservation: the next queued job can start
        resources.clear_abort(987001)

    def test_a_job_waiting_for_memory_gives_up_when_its_scan_is_stopped(self):
        store = resources.MemoryStore()
        store.reserve('hog', 3000, 'hog', 3500, time.time())
        with resources.scan_context(987002):
            resources.request_abort(987002)
            with self.assertRaises(resources.ScanAborted):
                with resources.heavy_job('nuclei', label='x', store=store, state_fn=lambda: {
                        'available_mb': 100, 'limit_mb': 4000, 'total_mb': 4000, 'used_mb': 3900}, sleep=lambda s: None):
                    self.fail('must not start')
        resources.clear_abort(987002)

    def test_the_task_records_its_id_so_a_running_scan_can_be_revoked(self):
        from cveFeed.tasks import run_bbot_discovery
        ids = self.bulk(1)
        with mock.patch('cveFeed.discovery.run_pipeline', return_value={}):
            run_bbot_discovery.apply(args=[ids[0], 'passive'], task_id='abc-123')
        self.assertEqual(ScanHistory.objects.get(pk=ids[0]).celery_ids, ['abc-123'])
