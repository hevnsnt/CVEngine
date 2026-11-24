"""Explicit state machines (cvengine.lifecycle, cvengine.state_machines): the tables are consistent, a move happens only from an allowed state,
and the scan lifecycle keeps a person's Stop whatever finishes afterwards."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from cvengine import lifecycle
from cvengine.lifecycle import Machine, Refused
from cvengine.state_machines import ABORTED, FAILED, QUEUED, RUNNING, SCAN, SUCCESS
from tests.test_internal_scan import NMAP_RESULT, Base, iter_none


class TableTests(TestCase):
    def test_a_table_naming_an_unknown_state_is_refused_when_defined(self):
        with self.assertRaises(ValueError):
            Machine('x', 'status', label='X', states={'a': ('a', 'A', '')}, moves={'a': ('b',)}, initial=('a',))

    def test_every_registered_table_is_consistent(self):
        for machine in lifecycle.REGISTRY.values():
            keys = [k for k, *_ in machine.states.values()]
            self.assertEqual(len(keys), len(set(keys)), machine.name)  # stable names are unique
            for value in machine.states:
                for nxt in machine.next_states(value):
                    self.assertIn(value, machine.sources(nxt))

    def test_a_stopped_scan_is_final_and_says_why_it_cannot_move(self):
        self.assertTrue(SCAN.is_final(ABORTED))
        self.assertFalse(SCAN.allowed(ABORTED, SUCCESS))
        with self.assertRaises(Refused) as caught:
            SCAN.check(ABORTED, SUCCESS)
        self.assertIn('aborted', str(caught.exception))
        self.assertIn('final', str(caught.exception))

    def test_a_failed_scan_may_still_finish(self):
        # the reaper can close a scan that was still running; its own finish is the truth
        self.assertTrue(SCAN.allowed(FAILED, SUCCESS))
        self.assertFalse(SCAN.allowed(SUCCESS, FAILED))

    def test_the_legend_names_each_state_once_with_its_meaning(self):
        legend = {s['key']: s for s in SCAN.legend()['states']}
        self.assertEqual(legend['aborted']['value'], ABORTED)
        self.assertEqual(legend['aborted']['label'], 'Stopped')
        self.assertTrue(legend['aborted']['final'])
        self.assertEqual(legend['queued']['next'], ['running', 'success', 'failed', 'aborted'])
        self.assertTrue(all(s['meaning'] for s in legend.values()))


class ScanRows(Base):
    def scan_in(self, status):
        scan = self.queued_scan()
        type(scan).objects.filter(pk=scan.pk).update(scan_status=status)
        return scan

    def test_move_changes_only_rows_in_an_allowed_state(self):
        from startScan.models import ScanHistory
        running, stopped = self.scan_in(RUNNING), self.scan_in(ABORTED)
        moved = SCAN.move(ScanHistory.objects.filter(pk__in=[running.pk, stopped.pk]), SUCCESS, stop_scan_date=timezone.now())
        self.assertEqual(moved, 1)
        self.assertEqual(ScanHistory.objects.get(pk=running.pk).scan_status, SUCCESS)
        self.assertEqual(ScanHistory.objects.get(pk=stopped.pk).scan_status, ABORTED)
        self.assertIsNone(ScanHistory.objects.get(pk=stopped.pk).stop_scan_date)  # nothing else was written either

    def test_a_move_with_no_possible_source_is_a_programming_error(self):
        from startScan.models import ScanHistory
        with self.assertRaises(ValueError):
            SCAN.move(ScanHistory.objects.all(), QUEUED)

    def test_a_stage_a_person_stopped_keeps_its_stopped_state_after_the_stage_returns(self):
        from agentapi import services
        from cveFeed import discovery
        from startScan.models import ScanActivity
        scan = self.scan_in(RUNNING)
        out = discovery._stage(scan, 'Example stage', 'example_stage', lambda: (services._abort_scan(scan), {'n': 1})[1])
        self.assertEqual(out, {'n': 1})
        self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='example_stage').status, ABORTED)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED)

    def test_a_stop_during_an_internal_scan_is_not_overwritten_by_its_finish(self):
        from agentapi import services
        from startScan.models import ScanActivity, ScanHistory
        from cveFeed import internal_scan
        scan = self.queued_scan()

        def stop_while_correlating(**kwargs):
            services._abort_scan(ScanHistory.objects.get(pk=scan.pk))  # a person presses Stop while a stage runs
            return {'subdomains': 1, 'matches': 0}
        with mock.patch('cveFeed.tasks.correlate_cves', side_effect=stop_while_correlating):
            out = internal_scan.run(scan.id, dispatch=lambda *a, **k: NMAP_RESULT, nuclei_stream=lambda kind: iter_none, provider=None)
        self.assertEqual(out['status'], 'aborted', out)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED)
        self.assertEqual(scan.error_message, 'Stopped by a person')
        self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='cve_correlation').status, ABORTED)

    def test_a_duplicate_delivery_keeps_the_running_tasks_id(self):
        from cveFeed.tasks import _add_celery_id
        from startScan.models import ScanHistory
        scan = self.scan_in(RUNNING)
        rows = ScanHistory.objects.filter(pk=scan.pk)
        _add_celery_id(rows, 'live-task')
        _add_celery_id(rows, 'duplicate-delivery')
        _add_celery_id(rows, 'duplicate-delivery')  # the same message again adds nothing
        self.assertEqual(ScanHistory.objects.get(pk=scan.pk).celery_ids, ['live-task', 'duplicate-delivery'])

    def test_rest_and_mcp_scan_rows_carry_the_state_name_next_to_the_code(self):
        from agentapi import services
        from startScan.models import ScanHistory
        scan = self.scan_in(ABORTED)
        row = services._scan(ScanHistory.objects.select_related('domain', 'scan_type').get(pk=scan.pk))
        self.assertEqual((row['status'], row['state']), (ABORTED, 'aborted'))


class DescribeStatesTests(TestCase):
    def setUp(self):
        from agentapi.auth import create_token
        from tests.test_sentinels import reset_rates
        self.user = get_user_model().objects.create_user('states-reader', password='x')
        self.token = create_token(self.user, 'states')[1]
        reset_rates({'t': self.token})

    def test_rest_lists_every_table(self):
        from tests.test_agentapi import call
        status, out = call(self.token, 'GET', '/api/v1/states')
        self.assertEqual(status, 200, out)
        names = {m['name'] for m in out['results']}
        self.assertIn('scan', names)
        scan = next(m for m in out['results'] if m['name'] == 'scan')
        self.assertEqual(scan['field'], 'scan_status')

    def test_mcp_describe_states_is_read_only_and_matches_rest(self):
        from agentapi import mcp
        tool = next(t for t in mcp.TOOLS if t[0] == 'describe_states')
        self.assertFalse(tool[-1])  # not a write tool
        from tests.test_authcheck import tool_call
        error, out = tool_call(self.token, 'describe_states', {})
        self.assertFalse(error, out)
        self.assertIn('scan', {m['name'] for m in out['results']})
