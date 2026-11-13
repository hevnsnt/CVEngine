"""Contract 5 on the server: what a Sentinel's nmap pass reports reaches the host (TL-1), a cut result says it was cut (TL-9, TL-13, SN-6), the port of a bbot
finding is kept, and a Sentinel on stale tools is told so (SN-4). A contract 4 Sentinel, which sends none of it, keeps working unchanged: both shapes are tested.
The v5 payload is the Sentinel's own fixture (``fixtures/sentinel_results/nmap.json``, made from its lab XML)."""
import json
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as sd
from agentapi import sentinel_settings, sentinel_stream, sentinel_tools
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from agentapi.services import ApiError
from cveFeed import cleartext, result_cuts
from startScan.models import IpAddress
from tests.test_sentinels import build_world

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_results'
V5 = json.loads((FIXTURES / 'nmap.json').read_text())
V4 = json.loads((FIXTURES / 'v4' / 'nmap.json').read_text())
HOST = '192.0.2.11'


class Chunks:
    """``dispatch_many`` as try_nmap sees it: the cleaned result for chunk 0."""
    def __init__(self, cleaned):
        self.cleaned = cleaned

    def __call__(self, project, kind, chunks, **kwargs):
        def gen():
            for index, _chunk in enumerate(chunks):
                yield index, sd.Result(self.cleaned)
        return gen()


class NmapDetailReachesTheHost(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def run_pass(self, payload, addresses=(HOST, '192.0.2.12')):
        for address in addresses:
            IpAddress.objects.get_or_create(address=address)
        cleaned = sb.clean_result('nmap', payload)
        with mock.patch.object(sd, 'dispatch_many', Chunks(cleaned)), mock.patch.object(sd, 'any_scanner_for', return_value=True):
            try:
                return sd.try_nmap(self.pa, self.scan, list(addresses))
            except Exception as exc:  # the second host timed out: it stays due, which the caller is told
                self.assertEqual(type(exc).__name__, 'ScannerUnavailable')

    def port(self, number, address=HOST):
        return IpAddress.objects.get(address=address).ports.get(number=number)

    def test_the_tls_mark_and_the_certificate_of_a_v5_result_are_stored(self):
        self.run_pass(V5)
        https = self.port(443)
        self.assertEqual(https.extra['tunnel'], 'ssl')  # 443 is no longer stored as plain http
        self.assertEqual(https.service_name, 'http')
        self.assertIn('commonName=web.example.test', https.tls['subject'])
        self.assertEqual(https.tls['fingerprint_sha1'], 'fedcba9876543210fedcba9876543210fedcba98')
        self.assertIn('http-title', https.extra['scripts'])

    def test_ftp_with_tls_is_not_plain_ftp_and_the_one_without_is(self):
        self.run_pass(V5)
        with_tls, without = self.port(21), self.port(2121)
        self.assertTrue(with_tls.tls and cleartext.offers_tls(with_tls))
        self.assertEqual(with_tls.banner, '220 (vsFTPd 3.0.5)')
        found = cleartext.evaluate('host.example', [(HOST, with_tls), (HOST, without)])
        shown = json.dumps([getattr(f, '__dict__', str(f)) for f in found], default=str)
        self.assertIn('2121', shown)
        self.assertNotIn('21/tcp', shown.replace('2121/tcp', ''))

    def test_cpes_service_extra_and_the_os_detail_are_stored(self):
        self.run_pass(V5)
        ssh = self.port(22)
        self.assertEqual(ssh.cpe, 'cpe:/a:openbsd:openssh:9.6p1')
        self.assertEqual(ssh.extra['cpes'], ['cpe:/a:openbsd:openssh:9.6p1', 'cpe:/o:linux:linux_kernel'])
        self.assertEqual(ssh.service_extra, 'Ubuntu Linux; protocol 2.0')
        self.assertEqual(ssh.extra['method'], 'probed')
        ip = IpAddress.objects.get(address=HOST)
        self.assertEqual(ip.os_accuracy, 97)
        self.assertEqual([m['name'] for m in ip.fingerprint['os_matches']], ['Linux 5.15 - 6.1', 'Linux 4.15'])
        self.assertIn('smb-os-discovery', ip.fingerprint['scripts'])

    def test_the_closed_port_nmap_used_is_kept_so_the_path_check_has_a_candidate(self):
        self.run_pass(V5)
        fingerprint = IpAddress.objects.get(address=HOST).fingerprint
        self.assertEqual(fingerprint['closed_tcp'], 1)
        self.assertIn('closed_tcp_at', fingerprint)

    def test_a_port_that_was_scanned_and_is_not_open_now_is_closed_by_the_next_pass(self):
        self.run_pass(V5)
        self.assertEqual(self.port(80).state, 'open')
        second = json.loads(json.dumps(V5))
        second['hosts'][0]['ports'] = [p for p in second['hosts'][0]['ports'] if p['number'] != 80]  # 80 is inside scanned_ranges and no longer answers
        self.run_pass(second)
        self.assertEqual(self.port(80).state, 'closed')
        self.assertEqual(self.port(443).state, 'open')

    def test_a_port_outside_what_the_run_probed_is_left_alone(self):
        self.run_pass(V5)
        from startScan.models import Port
        extra = Port.objects.create(number=9999, protocol='tcp', state='open', service_name='custom')
        IpAddress.objects.get(address=HOST).ports.add(extra)
        self.run_pass(V5)
        extra.refresh_from_db()
        self.assertEqual(extra.state, 'open')

    def test_a_host_nmap_gave_up_on_is_stored_as_nothing(self):
        self.run_pass(V5)
        self.assertEqual(IpAddress.objects.get(address='192.0.2.12').ports.count(), 0)

    def test_a_contract_4_result_is_stored_as_before(self):
        self.run_pass(V4, addresses=('192.0.2.10',))
        ssh = self.port(22, '192.0.2.10')
        self.assertEqual((ssh.product, ssh.version, ssh.state), ('OpenSSH', '9.6', 'open'))
        self.assertNotIn('tunnel', ssh.extra or {})
        self.assertFalse(ssh.tls)
        fingerprint = IpAddress.objects.get(address='192.0.2.10').fingerprint or {}
        self.assertNotIn('closed_tcp', fingerprint)
        self.assertNotIn('result_cuts', fingerprint)
        # nothing was said about what was probed: a port stored earlier is not closed by it
        from startScan.models import Port
        other = Port.objects.create(number=80, protocol='tcp', state='open', service_name='http')
        IpAddress.objects.get(address='192.0.2.10').ports.add(other)
        self.run_pass(V4, addresses=('192.0.2.10',))
        other.refresh_from_db()
        self.assertEqual(other.state, 'open')

    def test_what_the_pass_cut_for_a_host_is_on_the_host_and_cleared_by_a_pass_that_cut_nothing(self):
        payload = json.loads(json.dumps(V5))
        payload['cuts'] = [{'what': 'banner', 'kind': 'chars', 'limit': 1024, 'dropped': 30, 'target': HOST}, {'what': 'host_timeout', 'kind': 'time', 'limit': 480, 'target': '192.0.2.12'}]
        self.run_pass(payload)
        notes = [result_cuts.words(c) for c in IpAddress.objects.get(address=HOST).fingerprint['result_cuts']['nmap']]
        self.assertEqual(notes, ['banner text on 192.0.2.11: 30 characters clipped (limit 1024)'])
        self.run_pass(V5)
        self.assertNotIn('result_cuts', IpAddress.objects.get(address=HOST).fingerprint)


class NmapCleaning(SimpleTestCase):
    def host(self, **fields):
        return {'hosts': [{'ip': HOST, 'ports': [{'number': 80, **fields}]}]}

    def stored(self, body):
        return sb.clean_result('nmap', {'outcome': 'done', **body})

    def test_the_v5_fixture_goes_through_whole(self):
        self.assertEqual(self.stored({k: v for k, v in V5.items() if k != 'outcome'}), V5)

    def test_hostile_text_is_bounded_and_cleaned_like_the_old_fields(self):
        evil = 'A' * 5000 + '\x00\x07'
        port = self.stored(self.host(banner='x\n' + evil, service_extra=evil, hostname=evil, ostype=evil, devicetype=evil,
                                     scripts={'banner': 'ok\x00' + evil, 'Bad Id': 'x', 'x' * 80: 'y'}, tunnel='tls', method='guess', confidence='99'))['hosts'][0]['ports'][0]
        self.assertEqual(len(port['banner']), 1024)
        self.assertNotIn('\x00', port['banner'])
        self.assertIn('\n', port['banner'])
        self.assertEqual((len(port['service_extra']), len(port['hostname']), len(port['ostype']), len(port['devicetype'])), (200, 255, 40, 64))
        self.assertEqual(list(port['scripts']), ['banner'])
        self.assertEqual(len(port['scripts']['banner']), 4000)
        for dropped in ('tunnel', 'method', 'confidence'):
            self.assertNotIn(dropped, port)

    def test_script_output_is_held_to_sixteen_thousand_characters_and_twenty_four_ids(self):
        scripts = {f's{i}': 'z' * 4000 for i in range(30)}
        kept = self.stored(self.host(scripts=scripts))['hosts'][0]['ports'][0]['scripts']
        self.assertEqual((len(kept), sum(len(v) for v in kept.values())), (4, 16000))
        many = self.stored(self.host(scripts={f's{i}': 'z' for i in range(40)}))['hosts'][0]['ports'][0]['scripts']
        self.assertEqual(len(many), 24)

    def test_cpes_are_bounded_and_must_be_cpes(self):
        port = self.stored(self.host(cpes=['cpe:/a:x:y:1'] * 12 + ['http://evil', 7], cpe='javascript:alert(1)'))['hosts'][0]['ports'][0]
        self.assertEqual(len(port['cpes']), 8)
        self.assertNotIn('cpe', port)

    def test_a_certificate_keeps_only_its_known_fields_and_real_digests(self):
        tls = self.stored(self.host(tls={'subject': 'cn=a', 'issuer': 'i' * 999, 'sans': ['a'] * 90, 'fingerprint_sha1': 'XYZ', 'fingerprint_md5': 'a' * 32,
                                          'evil': '<script>'}))['hosts'][0]['ports'][0]['tls']
        self.assertEqual((len(tls['issuer']), len(tls['sans']), tls['fingerprint_md5']), (300, 40, 'a' * 32))
        self.assertNotIn('fingerprint_sha1', tls)
        self.assertNotIn('evil', tls)
        self.assertNotIn('tls', self.stored(self.host(tls={'issuer': 'no subject'}))['hosts'][0]['ports'][0])

    def test_the_host_fields_are_bounded(self):
        body = {'hosts': [{'ip': HOST, 'ports': [], 'os_accuracy': 400, 'os_matches': [{'name': 'n' * 300, 'accuracy': 5}] * 6, 'closed_tcp': 70000,
                           'scanned_ranges': [[1, 5], [9, 3], [0, 4], ['a', 2], [1, 2, 3]] + [[7, 7]] * 5000, 'hostscripts': {'nbstat': 'x'}, 'status': 'sideways',
                           'extraports': ['closed'] * 12}]}
        row = self.stored(body)['hosts'][0]
        for dropped in ('os_accuracy', 'closed_tcp', 'status'):
            self.assertNotIn(dropped, row)
        self.assertEqual(len(row['os_matches']), 3)
        self.assertEqual(len(row['os_matches'][0]['name']), 100)
        self.assertEqual(len(row['scanned_ranges']), 4096 - 4)  # the first 4096 entries are looked at, four of them are not ranges
        self.assertEqual(row['scanned_ranges'][0], [1, 5])
        self.assertEqual(len(row['extraports']), 8)

    def test_scanned_ranges_never_expand_past_the_port_space(self):
        self.assertEqual(len(sd.scanned_ports([[1, 65535], [1, 65535]] * 3)), 65535)
        self.assertIsNone(sd.scanned_ports(None))

    def test_more_ports_than_the_cap_say_so_in_cuts(self):
        ports = [{'number': n} for n in range(1, 520)]
        out = self.stored({'hosts': [{'ip': HOST, 'ports': ports}]})
        self.assertEqual(len(out['hosts'][0]['ports']), sb.MAX_PORTS_PER_HOST)
        self.assertEqual(out['cuts'], [{'what': 'ports', 'kind': 'items', 'limit': 500, 'dropped': 19, 'target': HOST}])

    def test_a_result_with_no_cuts_has_none(self):
        self.assertNotIn('cuts', self.stored({'hosts': [{'ip': HOST, 'ports': [{'number': 22}]}]}))


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


class ToolsBehind(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('tools-owner', password='x')

    def agent(self, info=None):
        token, _raw = create_token(self.user, f'tools-{Agent.objects.count()}')
        return Agent.objects.create(token=token, name=f'tools{Agent.objects.count()}', kind='scanner', status='active', capabilities=['nmap'], info=info or {}, last_seen=timezone.now())

    def test_the_info_of_a_registration_keeps_known_tools_and_clips_the_version(self):
        info = sentinel_settings.clean_info({'tool_versions': {'nuclei': '3.10.0' + 'x' * 60, 'nmap': '7.993', 'mystery': '1.0'}})
        self.assertEqual(info['tool_versions'], {'nuclei': ('3.10.0' + 'x' * 60)[:40], 'nmap': '7.993'})
        self.assertNotIn('tool_versions', sentinel_settings.clean_info({'version': 'abc1234'}))

    def test_a_bad_tool_versions_is_a_400(self):
        for bad in ('x', [1], {'Bad Name': '1'}, {'nuclei': 3}, {f't{i}': '1' for i in range(20)}):
            with self.assertRaises(ApiError, msg=bad):
                sentinel_settings.clean_info({'tool_versions': bad})

    def test_older_tools_are_behind_and_the_row_says_which(self):
        shipped = sentinel_tools.expected()
        agent = self.agent({'tool_versions': {'nuclei': '3.10.0', 'nmap': shipped['nmap'], 'testssl': 'v99.0'}})
        state = sentinel_tools.state(agent)
        self.assertEqual(state['status'], 'behind')
        self.assertEqual(state['behind'], [{'tool': 'nuclei', 'running': '3.10.0', 'current': shipped['nuclei']}])
        self.assertTrue(state['flagged'])
        self.assertIn('nuclei 3.10.0', state['detail'])

    def test_current_newer_and_unreadable_versions_are_not_behind(self):
        shipped = sentinel_tools.expected()
        self.assertEqual(sentinel_tools.state(self.agent({'tool_versions': {'nuclei': shipped['nuclei'], 'bbot': '99.0.0', 'nmap': 'unreadable'}}))['status'], 'current')

    def test_a_contract_4_sentinel_that_sends_none_is_unknown_never_behind(self):
        for info in ({}, {'version': 'abc1234'}, {'tool_versions': {}}):
            state = sentinel_tools.state(self.agent(info))
            self.assertEqual((state['status'], state['behind'], state['flagged']), ('unknown', [], False))

    def test_the_version_compare_reads_numbers_only(self):
        self.assertTrue(sentinel_tools.older('7.97', '7.993'))
        self.assertTrue(sentinel_tools.older('3.2', '3.2.5'))
        self.assertFalse(sentinel_tools.older('v3.11.1', '3.11.1'))
        self.assertFalse(sentinel_tools.older('garbage', '3.11.1'))

    def test_the_agent_row_of_rest_and_mcp_carries_tools_state(self):
        from agentapi import agent_broker
        agent = self.agent({'tool_versions': {'nuclei': '3.0.0'}})
        row = agent_broker.agent_dict(Agent.objects.select_related('token__user').get(pk=agent.pk), counts={})
        self.assertEqual(row['tools_state']['status'], 'behind')
        self.assertEqual(row['tools_state']['behind'][0]['tool'], 'nuclei')
        plain = agent_broker.agent_dict(Agent.objects.select_related('token__user').get(pk=self.agent().pk), counts={})
        self.assertEqual(plain['tools_state']['status'], 'unknown')

    def test_recording_the_info_stores_the_versions_audits_once_and_a_report_without_them_clears_them(self):
        from dashboard.models import AuditLog
        agent = self.agent({'contract_version': 4})
        sentinel_settings.record_info(agent, {'contract_version': 5, 'tool_versions': {'nuclei': '3.10.0'}})
        agent.refresh_from_db()
        self.assertEqual(agent.info['tool_versions'], {'nuclei': '3.10.0'})
        sentinel_settings.record_info(agent, {'contract_version': 5, 'tool_versions': {'nuclei': '3.10.0'}})  # the next heartbeat: the same, no second notice
        self.assertEqual(AuditLog.objects.filter(action='sentinel.tools_behind').count(), 1)
        sentinel_settings.record_info(agent, {'contract_version': 5})
        agent.refresh_from_db()
        self.assertNotIn('tool_versions', agent.info)

    def tearDown(self):
        cache.clear()
