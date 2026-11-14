"""TL-9, TL-13, SN-6 on the server (contract 5): cuts are recorded, the server's own caps are counted the same way, and the user is shown them."""
import json  # noqa: F401
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as sd
from agentapi import sentinel_stream
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import result_cuts
from tests.test_sentinels import build_world


class CutsAreBoundedAndWorded(SimpleTestCase):
    def test_a_bad_cut_is_dropped_and_the_numbers_are_clamped(self):
        rows = result_cuts.clean([{'what': 'ports', 'kind': 'items', 'limit': 500, 'dropped': 10 ** 12}, {'what': 'Bad Name', 'kind': 'items'}, {'what': 'x', 'kind': 'weird'},
                                  {'what': 'time_limit', 'kind': 'time', 'limit': 900, 'dropped': 5}, 'text', {'what': 'a', 'kind': 'chars', 'dropped': -1, 'target': 't' * 999}] * 20)
        self.assertEqual([r['what'] for r in rows[:3]], ['ports', 'time_limit', 'a'])  # the bad ones are dropped, the rest keep their order
        self.assertEqual(rows[0]['dropped'], 10 ** 9)
        self.assertEqual(rows[1], {'what': 'time_limit', 'kind': 'time', 'limit': 900})
        self.assertEqual(len(rows[2]['target']), 260)
        self.assertNotIn('dropped', rows[2])
        self.assertEqual(result_cuts.clean('x'), [])
        self.assertEqual(len(result_cuts.clean([{'what': 'ports', 'kind': 'items'}] * 60)), result_cuts.MAX_CUTS)

    def test_the_words_say_what_and_how_many(self):
        self.assertEqual(result_cuts.words({'what': 'findings', 'kind': 'items', 'limit': 500, 'dropped': 120}), 'findings: 120 dropped (limit 500)')
        self.assertEqual(result_cuts.words({'what': 'time_limit', 'kind': 'time', 'limit': 900}), 'stopped at its time limit (900 s)')
        self.assertEqual(result_cuts.words({'what': 'events', 'kind': 'items', 'limit': 5000, 'dropped': 12}), 'events: 12 dropped (limit 5000)')

    def test_the_servers_cut_and_the_sentinels_are_one_row(self):
        cuts = [{'what': 'findings', 'kind': 'items', 'limit': 500, 'dropped': 7}]
        result_cuts.add(cuts, 'findings', 400, 3)
        self.assertEqual(cuts, [{'what': 'findings', 'kind': 'items', 'limit': 400, 'dropped': 10}])


class FindingsAndSecretsAreCountedWhenCut(SimpleTestCase):
    def findings(self, n):
        return [{'template_id': f't{i}', 'name': 'n', 'severity': 'low' if i % 2 else 'info', 'host': 'a.example', 'matched_at': 'https://a.example/'} for i in range(n)]

    def test_a_nuclei_result_over_the_cap_records_the_cut_and_keeps_the_old_counter(self):
        out = sb.clean_result('nuclei_light', {'outcome': 'done', 'findings': self.findings(620), 'cuts': [{'what': 'description', 'kind': 'chars', 'limit': 500, 'dropped': 9}]})
        self.assertEqual((len(out['findings']), out['dropped_findings']), (500, 120))
        self.assertEqual(sorted(c['what'] for c in out['cuts']), ['description', 'findings'])
        self.assertIn('findings: 120 dropped (limit 500)', result_cuts.summary(out))
        self.assertTrue(result_cuts.partial(out))

    def test_an_old_result_with_only_the_counter_is_still_worded(self):
        self.assertEqual(result_cuts.summary({'findings': [], 'dropped_findings': 5}), ['findings: 5 dropped (only the strongest are kept)'])
        self.assertEqual(result_cuts.summary({'findings': [], 'dropped': 2}), ['2 entries about hosts or ports the task did not name were ignored'])
        self.assertEqual(result_cuts.summary({'findings': []}), [])
        self.assertFalse(result_cuts.partial({'findings': []}))

    def test_a_secrets_result_over_its_caps_records_them(self):
        from cveFeed import secrets_scan
        fetched = [{'url': f'https://a.example/{i}.js', 'kind': 'script', 'status': 200, 'bytes': 1} for i in range(secrets_scan.MAX_FETCHED + 3)]
        out = secrets_scan.clean_result({'findings': [], 'fetched': fetched, 'references': []})
        self.assertEqual(out['cuts'], [{'what': 'fetched', 'kind': 'items', 'limit': secrets_scan.MAX_FETCHED, 'dropped': 3}])
        again = secrets_scan.clean_result(out)  # filed a second time, after binding to the task: the same cuts, not doubled
        self.assertEqual(again['cuts'], out['cuts'])

    def test_a_discovered_address_with_more_than_five_names_says_so(self):
        out = sb.clean_result('discover', {'outcome': 'done', 'hosts': [{'ip': '192.0.2.5', 'hostnames': [f'h{i}.example' for i in range(8)]}]})
        self.assertEqual(len(out['hosts'][0]['hostnames']), 5)
        self.assertEqual(out['cuts'], [{'what': 'names', 'kind': 'items', 'limit': 5, 'dropped': 3, 'target': '192.0.2.5'}])

    def test_a_bbot_final_result_keeps_its_cuts(self):
        out = sb.clean_result('bbot_discovery', {'outcome': 'done', 'partials': 0, 'mode': 'standard', 'cuts': [{'what': 'events', 'kind': 'items', 'limit': 5000, 'dropped': 12}]})
        self.assertEqual(out['cuts'], [{'what': 'events', 'kind': 'items', 'limit': 5000, 'dropped': 12}])
        self.assertNotIn('cuts', sb.clean_result('bbot_discovery', {'outcome': 'done', 'partials': 0, 'mode': 'standard'}))


class BbotFindingKeepsItsPort(SimpleTestCase):
    def test_a_finding_with_a_port_keeps_it_and_one_without_is_unchanged(self):
        scope = mock.Mock()
        scope.host.side_effect = lambda h: h.lower()
        scope.url.side_effect = lambda u: u
        base = {'name': 'Open port', 'informational': False, 'severity': 2, 'host': 'a.example', 'url': '', 'description': 'd', 'module': 'portscan'}
        self.assertEqual(sentinel_stream._finding({**base, 'port': 8443}, scope)['port'], 8443)
        self.assertNotIn('port', sentinel_stream._finding(base, scope))
        for bad in (0, 70000, '443', True):
            self.assertNotIn('port', sentinel_stream._finding({**base, 'port': bad}, scope))


class ResultAndTaskShowTheCut(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def task(self, result, kind='nuclei_light'):
        agent_user = User.objects.get(username='s_alice')
        token, _raw = create_token(agent_user, 'cuts-agent')
        agent = Agent.objects.create(token=token, name='cutter', kind='scanner', status='active', capabilities=[kind], last_seen=timezone.now())
        return SentinelTask.objects.create(project=self.pa, scan=self.scan, kind=kind, target={'targets': ['a.example']}, host='a.example', ips=[], agent=agent,
                                           status='done', result=result), agent

    def test_the_task_brief_carries_the_notes_the_release_and_whether_it_was_partial(self):
        task, _ = self.task({'outcome': 'done', 'findings': [], 'dropped_findings': 120, 'templates_release': 'v10.5.2', 'cuts': [{'what': 'findings', 'kind': 'items', 'limit': 500, 'dropped': 120}]})
        brief = sb.task_brief(task)
        self.assertEqual(brief['cut_notes'], ['findings: 120 dropped (limit 500)'])
        self.assertEqual((brief['partly_checked'], brief['templates_release']), (True, 'v10.5.2'))

    def test_a_plain_result_has_no_notes(self):
        task, _ = self.task({'outcome': 'done', 'findings': []})
        brief = sb.task_brief(task)
        self.assertEqual((brief['cut_notes'], brief['partly_checked'], brief['templates_release']), ([], False, None))

    def test_filing_a_cut_result_writes_one_activity_line_on_the_scan(self):
        from cveFeed.models import AgentActivity
        task, agent = self.task({'outcome': 'done'})
        sb._note_cuts(task, agent, {'outcome': 'done', 'findings': [], 'dropped_findings': 120, 'cuts': [{'what': 'findings', 'kind': 'items', 'limit': 500, 'dropped': 120}]})
        line = AgentActivity.objects.filter(detail__sentinel_task_id=task.pk).get()
        self.assertEqual(line.detail['scan_id'], self.scan.pk)
        self.assertIn('findings: 120 dropped (limit 500)', line.message)
        sb._note_cuts(task, agent, {'outcome': 'done', 'findings': []})
        self.assertEqual(AgentActivity.objects.filter(detail__sentinel_task_id=task.pk).count(), 1)

    def test_checks_left_out_on_purpose_are_one_plain_sentence_per_scan_not_a_warning(self):
        from django.core.cache import cache
        from cveFeed.models import AgentActivity
        cache.delete_many([f'cvengine:cut-info:{self.scan.pk}:templates_with_credentials', f'cvengine:cut-info:{self.scan.pk}:templates_unreadable'])
        cuts = [{'what': 'templates_with_credentials', 'kind': 'items', 'limit': 0, 'dropped': 377}, {'what': 'templates_unreadable', 'kind': 'items', 'limit': 0, 'dropped': 1}]
        first, agent = self.task({'outcome': 'done', 'cuts': cuts})
        second, _ = self.task({'outcome': 'done', 'cuts': cuts})
        sb._note_cuts(first, agent, {'outcome': 'done', 'findings': [], 'cuts': cuts})
        sb._note_cuts(second, agent, {'outcome': 'done', 'findings': [], 'cuts': cuts})  # another chunk of the same scan: not said again
        lines = list(AgentActivity.objects.filter(detail__scan_id=self.scan.pk).values_list('message', 'status'))
        self.assertEqual(len(lines), 2, lines)
        text = ' '.join(m for m, _s in lines)
        self.assertIn("377 checks that send a fixed credential were left out; turn on 'Allow checks that send credentials' to run them", text)
        self.assertIn('1 installed check that could not be read or parsed was left out', text)
        self.assertNotIn('cut its', text)  # not the "cut its result" line of a loss
        self.assertEqual({st for _m, st in lines}, {'done'})
        self.assertFalse(result_cuts.partial({'cuts': cuts}))  # not a partly checked result
        brief = sb.task_brief(first)
        self.assertEqual(brief['cut_notes'][0], "377 checks that send a fixed credential were left out; turn on 'Allow checks that send credentials' to run them")
        self.assertFalse(brief['partly_checked'])
        self.assertEqual(result_cuts.summary({'cuts': cuts}, losses_only=True), [])

    def test_the_sentinels_page_row_of_a_finished_task_has_the_notes(self):
        task, _ = self.task({'outcome': 'done', 'templates_release': 'v10.5.2', 'cuts': [{'what': 'time_limit', 'kind': 'time', 'limit': 900}]})
        row = sb._live_task(task, None)
        self.assertEqual((row['cut_notes'], row['templates_release']), (['stopped at its time limit (900 s)'], 'v10.5.2'))
        hidden = sb._live_task(task, set())
        self.assertNotIn('cut_notes', hidden)

    def test_a_chunk_cut_at_its_time_limit_leaves_its_targets_due(self):
        chunk = ['a.example', 'b.example']
        result = sd.Result({'findings': [], 'cuts': [{'what': 'time_limit', 'kind': 'time', 'limit': 900}]})
        rows = sd._cut_check_of(result, chunk, [{'target': 'a.example', 'reason': 'its own'}])
        self.assertEqual([r['target'] for r in rows], ['b.example'])
        self.assertIn('stopped at its time limit', rows[0]['reason'])
        self.assertEqual(sd._cut_check_of(sd.Result({'findings': []}), chunk), [])
        dropped = sd._cut_check_of(sd.Result({'findings': [], 'dropped_findings': 120}), chunk)
        self.assertEqual(len(dropped), 2)
        self.assertIn('120 dropped', dropped[0]['reason'])
        self.assertEqual(sd._cut_check_of(sd.Result({'findings': [], 'cuts': [{'what': 'description', 'kind': 'chars', 'limit': 500, 'dropped': 9}]}), chunk), [])
