"""What the system status's probes waited on, and the checks that it stays fixed.

On a 3-core install the small probes (one statement each) took 1.4 to 3 s while the inventory's counting ran: the counting thread holds the interpreter's lock and a
thread that waits on the database or Redis got it back only at the 5 ms switch interval (queues: 69 Redis reads one after another, signals, work, autotune, udp_scan,
ai); feeds counted the whole CVE catalogue twice; the UDP counts read the ports table twice; the finding counts built the list's related rows, comment counts and review subqueries to throw them away.
"""
import sys
import time
from unittest import mock

from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext

from agentapi import status_probes, system_status
from agentapi.status_probes import Probe
from tests.test_status_shared_counts import World


class SwitchIntervalTests(SimpleTestCase):
    def test_the_probes_run_with_a_short_switch_interval_and_it_is_restored(self):
        before, seen = sys.getswitchinterval(), []
        status_probes.run([Probe('p', lambda p, n, d: seen.append(sys.getswitchinterval()) or 1, db=False)])
        self.assertEqual(seen, [status_probes.SWITCH_INTERVAL])
        self.assertLess(status_probes.SWITCH_INTERVAL, before)
        self.assertEqual(sys.getswitchinterval(), before)

    def test_overlapping_status_calls_restore_it_only_after_the_last(self):
        before = sys.getswitchinterval()
        with status_probes.responsive_switching():
            with status_probes.responsive_switching():
                self.assertEqual(sys.getswitchinterval(), status_probes.SWITCH_INTERVAL)
            self.assertEqual(sys.getswitchinterval(), status_probes.SWITCH_INTERVAL)
        self.assertEqual(sys.getswitchinterval(), before)

    def test_a_probe_that_fails_still_restores_it(self):
        before = sys.getswitchinterval()
        status_probes.run([Probe('boom', lambda p, n, d: 1 / 0, db=False)])
        self.assertEqual(sys.getswitchinterval(), before)

    def test_a_waiting_thread_is_not_held_behind_a_counting_thread(self):
        """The shape of the incident: one probe counts in Python for a while, another waits on a socket (a sleep stands for it) sixty times in a row."""
        stop = time.monotonic() + 1.2

        def count(p, n, d):
            x = 0
            while time.monotonic() < stop:
                for i in range(2000):
                    x += i * i
            return x

        def wait_often(p, n, d):
            started = time.monotonic()
            for _ in range(60):
                time.sleep(0.001)
            return time.monotonic() - started
        run = status_probes.run([Probe('count', count, db=False), Probe('wait', wait_often, db=False)], budget=5)
        self.assertEqual(run.results['wait'].state, 'ok')
        self.assertLess(run.results['wait'].value, 0.22)  # sixty hand-backs of the lock behind a busy thread: 0.38 s at the default 5 ms interval, 0.10 s at 0.5 ms


class QueuesTests(SimpleTestCase):
    def test_the_queue_depths_are_one_round_trip(self):
        calls = []

        class Pipe:
            def llen(self, name):
                calls.append(name)

            def hlen(self, name):
                calls.append(name)

            def execute(self):
                calls.append('execute')
                return [1] * (len(calls) - 1)

        client = mock.Mock()
        client.pipeline.return_value = Pipe()
        with mock.patch.object(system_status, '_broker_client', lambda: client):
            out = system_status._queues()
        client.llen.assert_not_called()
        client.hlen.assert_not_called()
        self.assertEqual(calls.count('execute'), 1)
        self.assertEqual(len(calls), len(system_status.QUEUES) * len(system_status.PRIORITY_SUFFIXES) + 2)
        self.assertEqual(out['waiting']['discovery_queue'], len(system_status.PRIORITY_SUFFIXES))  # each step's depth added up, as before
        self.assertEqual((out['waiting_total'], out['unacknowledged']), (len(system_status.QUEUES) * len(system_status.PRIORITY_SUFFIXES), 1))

    def test_the_depths_are_those_of_the_broker(self):
        from reNgine import resources
        client = resources.redis_client()
        names = ['bucketscan_queue', 'bucketscan_queue' + system_status.PRIORITY_SUFFIXES[2]]
        client.delete(*names)
        self.addCleanup(client.delete, *names)
        client.rpush(names[0], 'a', 'b')
        client.rpush(names[1], 'c')
        out = system_status._queues()
        self.assertEqual(out['waiting']['bucketscan_queue'], 3)


class FeedsAndUdpTests(World):
    def statements(self, fn):
        with CaptureQueriesContext(connection) as captured:
            fn()
        return [q['sql'] for q in captured.captured_queries]

    def test_feeds_counts_the_catalogue_once(self):
        sql = self.statements(system_status._feeds)
        plain = [q for q in sql if 'COUNT' in q and 'FROM "cveFeed_cveentry"' in q and 'JOIN' not in q]
        self.assertEqual(len(plain), 1, plain)  # the guidance progress counts them (with how many are local only); the probe reuses it
        self.assertEqual(system_status._feeds()['cve_entries'], 2)

    def test_the_udp_counts_read_the_ports_once(self):
        from cveFeed import udp_scan
        from startScan.models import Port
        Port.objects.create(number=161, protocol='udp', state='open')
        Port.objects.create(number=123, protocol='udp', state='open')
        Port.objects.create(number=500, protocol='udp', state=udp_scan.OPEN_FILTERED)
        sql = self.statements(lambda: self.assertEqual(
            {k: v for k, v in udp_scan.status().items() if k in ('open_udp_ports', 'unanswered_udp_ports')}, {'open_udp_ports': 2, 'unanswered_udp_ports': 1}))
        self.assertEqual(len([q for q in sql if 'FROM "startScan_port"' in q]), 1)


class CountingSourcesTests(World):
    def test_the_counting_sources_have_the_filters_of_the_list_and_none_of_its_columns(self):
        from agentapi import services
        full = services._finding_sources(services.AllProjects([p.id for p in self.projects]), {'status': 'actionable'})
        counting = services._finding_sources(services.AllProjects([p.id for p in self.projects]), {'status': 'actionable'}, counting=True)
        self.assertEqual(set(full), set(counting))
        for kind in full:
            self.assertEqual(sorted(full[kind].values_list('pk', flat=True)), sorted(counting[kind].values_list('pk', flat=True)), kind)  # the same rows
            sql = str(counting[kind].query)
            self.assertEqual(counting[kind].query.order_by, ())  # no order of its own
            self.assertNotIn('findingreview', sql.lower())  # the newest-review subquery is the list's
            self.assertNotIn('comment', sql.lower())

    def test_the_counts_are_unchanged(self):
        from cveFeed import stats_history
        ids = [p.id for p in self.projects]
        shared = stats_history.shared_finding_counts(ids)
        for project in self.projects:
            self.assertEqual(shared[project.id], stats_history._open_findings_and_cve_matches(project), project.slug)


class WordpressCountingTests(World):
    def test_the_counts_of_every_state_are_those_of_the_full_rows(self):
        from cveFeed import wpscan_scan
        from cveFeed.models import ProbeObservation
        from targetApp.models import Domain
        rows = [('wpscan', 'found', {'state': 'scanned', 'findings': 3}), ('wpscan', 'hidden', {'state': 'blocked', 'reason': 'x'}), ('wpscan', 'found', {'state': ''}),
                ('wpscan', 'hidden', {'state': 'not_wordpress'}), ('wpscan', 'hidden', {}), ('wordpress-detect', 'found', {'hint': 'h'}),
                ('wordpress-detect', 'challenged', {}), ('wordpress-detect', 'absent', {}), ('wordpress-signals', 'found', {'signals': ['a', 'b']}),
                (wpscan_scan.THOROUGH_PROBE, 'found', {'state': 'scanned', 'plugins': 2}), (wpscan_scan.THOROUGH_PROBE, 'found', {'state': None})]
        project = self.projects[0]
        domain = Domain.objects.filter(project=project).first()
        for i, (probe, outcome, evidence) in enumerate(rows):
            for host in (f'h{i}.a.test', f'h{i}.b.test'):
                ProbeObservation.objects.create(project=project, domain=domain, host=host, probe=probe, kind='wordpress', product='WordPress', outcome=outcome, evidence=evidence,
                                                source='header:x' if outcome == 'found' else '')
        # a host with several probe rows, which is the common case
        for probe, outcome, evidence in (('wordpress-detect', 'found', {}), ('wpscan', 'found', {'state': 'scanned'}), (wpscan_scan.THOROUGH_PROBE, 'found', {'state': 'queued'})):
            ProbeObservation.objects.create(project=project, domain=domain, host='multi.a.test', probe=probe, kind='wordpress', product='WordPress', outcome=outcome, evidence=evidence)
        ids = [p.id for p in self.projects]
        self.assertEqual(wpscan_scan.status_counts_by_project(ids), {pid: wpscan_scan.status_counts([pid]) for pid in ids})
        self.assertGreater(wpscan_scan.status_counts([project.id])['hosts'], 5)

    def test_the_evidence_of_a_scan_is_not_read_to_count_it(self):
        from cveFeed import wpscan_scan
        with CaptureQueriesContext(connection) as captured:
            wpscan_scan.status_counts_by_project([p.id for p in self.projects])
        select = captured.captured_queries[0]['sql'].split(' FROM ')[0]
        self.assertNotIn('"cveFeed_probeobservation"."evidence"', select.replace('"cveFeed_probeobservation"."evidence" ->', ''))


class WebHostsTests(World):
    def test_the_web_hosts_read_the_addresses_inside_the_database(self):
        from cveFeed import inventory_counts
        with CaptureQueriesContext(connection) as captured:
            out = inventory_counts.web_hosts_by_project()
        self.assertEqual(len(captured), 2)  # the names with a URL, and the names behind the addresses with a web port (it was three: the addresses were read first and sent back as a list)
        self.assertTrue(all(len(q['sql']) < 3000 for q in captured.captured_queries))
        self.assertTrue(out)
