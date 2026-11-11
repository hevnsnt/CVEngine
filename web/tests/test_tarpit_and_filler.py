"""A host that answers on tens of thousands of ports is a result with a note (not a failure), the scan-error and AI reviewer lines say only what is
true, and no placeholder text reaches a person."""
import ast
import os
import re
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from cveFeed import filler, hot_validation, port_flood, reviewer
from cveFeed.hygiene import INFO
from cveFeed.models import AdminAlert, AgentActivity
from tests.test_fullscan import FullScanBase, sweep_ip_with, xml
from tests.test_reviewer import Fixture
from tests.test_sentinel_dispatch import DispatchBase

NOTE = 'port list truncated: this host answers on an unusually large number of ports (tarpit or filtering device)'
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def sentinel_cut_report(ip, kept=100, seen=65535):
    """What a Sentinel with the tarpit handling sends: the first ports and the note element."""
    ports = ''.join(f'<port protocol="tcp" portid="{n}"><state state="open"/></port>' for n in range(1, kept + 1))
    return (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host>'
            f'<cvengine-note kind="port-list-truncated" open-ports="{seen}" kept="{kept}" exact="1">{NOTE}</cvengine-note>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')


class NmapHostsTarpitTests(SimpleTestCase):
    def test_a_sentinels_note_marks_the_host_and_keeps_its_ports(self):
        hosts = dispatch.nmap_hosts(sentinel_cut_report('192.0.2.7'), '192.0.2.7')
        self.assertEqual(len(hosts[0]['ports']), 100)
        self.assertTrue(hosts[0]['port_list_truncated'])
        self.assertEqual(hosts[0]['open_ports_seen'], 65535)

    def test_a_long_report_from_a_sentinel_without_the_note_is_cut_here(self):
        hosts = dispatch.nmap_hosts(xml('192.0.2.7', [(n, 'unknown') for n in range(1, 3001)]), '192.0.2.7')
        self.assertEqual([p['number'] for p in hosts[0]['ports']], list(range(1, 101)))
        self.assertEqual((hosts[0]['port_list_truncated'], hosts[0]['open_ports_seen']), (True, 3000))

    def test_an_ordinary_host_is_untouched(self):
        hosts = dispatch.nmap_hosts(xml('192.0.2.7', [(22, 'ssh'), (443, 'https')]), '192.0.2.7')
        self.assertEqual(len(hosts[0]['ports']), 2)
        self.assertNotIn('port_list_truncated', hosts[0])

    def test_exactly_the_limit_is_not_truncated(self):
        hosts = dispatch.nmap_hosts(xml('192.0.2.7', [(n, 'x') for n in range(1, 101)]), '192.0.2.7')
        self.assertNotIn('port_list_truncated', hosts[0])

    def test_the_result_contract_is_unchanged_the_note_travels_inside_the_xml(self):
        from agentapi.sentinel_broker import _clean_nmap_report
        text = sentinel_cut_report('192.0.2.7')
        self.assertEqual(_clean_nmap_report({'xml': text}), {'xml': text})


class FullSweepTarpitTests(FullScanBase):
    def test_a_tarpit_sweep_is_a_success_with_a_capped_list_and_no_failure_count(self):
        ip = self.ip('192.0.2.7', scanned=None)
        fingerprinted = []
        out = sweep_ip_with(ip, lambda t, f, h: xml(t[0], [(n, 'unknown') for n in range(1, 5001)]),
                            fingerprint_runner=lambda *a: fingerprinted.append(a) or xml('x', []), pipeline=lambda d, n: None)
        ip.refresh_from_db()
        self.assertTrue(out['ok'])
        self.assertTrue(out['port_list_truncated'])
        self.assertEqual((ip.full_scan_failures, ip.full_scan_retry_at), (0, None))
        self.assertIsNotNone(ip.full_scanned_at)
        self.assertEqual(ip.ports.filter(state='open').count(), 100)
        self.assertEqual(fingerprinted, [])  # a tarpit's ports are not looked into one by one
        line = AgentActivity.objects.filter(kind='run_check').order_by('-id').first()
        self.assertEqual(line.status, 'done')
        self.assertIn(NOTE, line.message)

    def test_a_normal_sweep_is_unchanged(self):
        ip = self.ip('192.0.2.8', scanned=None)
        out = sweep_ip_with(ip, lambda t, f, h: xml(t[0], [(22, 'ssh')]), fingerprint_runner=lambda *a: xml('192.0.2.8', [(22, 'ssh')]),
                            pipeline=lambda d, n: None)
        self.assertTrue(out['ok'])
        self.assertNotIn('port_list_truncated', out)


class PortFloodFindingTests(FullScanBase):
    def test_one_info_finding_stands_for_a_host_with_a_capped_list(self):
        ip = self.ip('192.0.2.7', name='tar.fs.test', ports=range(1, 101))
        self.ip('192.0.2.9', name='ok.fs.test', ports=range(1, 100))
        found = port_flood.findings_for(self.domain)
        self.assertEqual([(f.check, f.severity, f.host) for f in found], [(port_flood.CHECK, INFO, 'tar.fs.test')])
        self.assertIn(NOTE, found[0].detail)
        self.assertEqual(found[0].evidence['addresses'], [ip.address])

    def test_it_can_be_turned_off(self):
        self.ip('192.0.2.7', name='tar.fs.test', ports=range(1, 101))
        with mock.patch.dict(os.environ, {'CVENGINE_HYGIENE_PORTFLOOD': '0'}):
            self.assertEqual(port_flood.findings_for(self.domain), [])

    def test_the_finding_is_info_so_it_carries_no_score(self):
        self.assertEqual(INFO, 0)  # cveFeed.scoring reads hygiene findings with severity__gte=1


class TargetCausedFailureTests(DispatchBase):
    def setUp(self):
        super().setUp()
        self.agent = self.make_sentinel(['nmap_full'])

    def finish(self, status, error='', ago=1):
        SentinelTask.objects.create(project=self.project, kind='nmap_full', target={}, agent=self.agent, status=status, error=error,
                                    finished_at=timezone.now() - timedelta(minutes=ago))

    def test_oversized_output_from_a_host_never_pauses_the_kind(self):
        big = 'nmap wrote more than 4194304 bytes of output; the run was stopped'
        for ago in (4, 3, 2, 1):
            self.finish('failed', big, ago)
        self.assertEqual(sb.failing_kinds(self.agent), {})

    def test_it_neither_adds_to_nor_breaks_a_streak_of_real_failures(self):
        big = 'nmap wrote more than 4194304 bytes of output; the run was stopped'
        self.finish('failed', 'nmap exited with status 1', 5)
        self.finish('failed', big, 4)
        self.finish('failed', 'nmap exited with status 1', 3)
        self.assertEqual(sb.failing_kinds(self.agent), {})
        self.finish('failed', 'nmap exited with status 1', 2)
        self.assertIn('nmap_full', sb.failing_kinds(self.agent))

    def test_three_real_failures_still_pause_it(self):
        for ago in (3, 2, 1):
            self.finish('failed', 'nmap exited with status 1', ago)
        self.assertIn('nmap_full', sb.failing_kinds(self.agent))


class ValidationLineWordsTests(SimpleTestCase):
    def test_only_a_check_or_review_that_really_failed_is_a_failed_line(self):
        self.assertEqual(hot_validation.line_status(True, True), 'failed')
        self.assertEqual(hot_validation.line_status(True, False), 'done')  # held by scope or policy, or the day's cap
        self.assertEqual(hot_validation.line_status(False, False), 'done')

    def test_the_words_say_why(self):
        self.assertEqual(hot_validation.outcome_words(False, False, False), 'completed')
        self.assertEqual(hot_validation.outcome_words(True, True, False), 'failed')
        self.assertIn('daily cap', hot_validation.outcome_words(True, False, True))
        self.assertIn('blocked by scope or policy', hot_validation.outcome_words(True, False, False))


class FillerTests(SimpleTestCase):
    def test_filler_is_recognised(self):
        for text in ('Placeholder', 'placeholder.', 'TBD', 'N/A', '<diagnosis>', '[your diagnosis here]', '...', 'none', '', 'Lorem ipsum dolor sit amet', 'sample text'):
            self.assertTrue(filler.is_placeholder(text), text)

    def test_real_text_is_not(self):
        for text in ('The scanner ran out of memory; give it more.', 'Restart the nuclei worker', 'Check docker compose logs celery'):
            self.assertFalse(filler.is_placeholder(text), text)

    def test_the_reviewer_container_agrees(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('guard', os.path.join(ROOT, 'reviewer', 'cvengine_reviewer', 'guard.py'))
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        for text in ('Placeholder', 'TBD', '<diagnosis>', 'sample text', 'Lorem ipsum dolor sit amet'):
            self.assertTrue(guard.is_filler(text), text)
        self.assertFalse(guard.is_filler('Give the Sentinel more memory.'))


class AlertPlaceholderTests(Fixture):
    def checks(self):
        return [reviewer._check('system', 'problem', 'cvENGINE reports problems', 'a problem', {'n': 1})]

    def report(self, diagnosis):
        with mock.patch('cveFeed.reviewer.ops_checks', return_value=self.checks()):
            reviewer.apply_ops_report({'alerts': [{'code': 'system', 'severity': 'warning', 'diagnosis': diagnosis}], 'actions': [], 'model': 'claude-haiku-5-5'})
        return AdminAlert.objects.get(code='system', resolved_at__isnull=True)

    def test_a_placeholder_diagnosis_is_not_stored_and_no_model_name_shows_without_a_line(self):
        alert = self.report('Placeholder')
        self.assertEqual((alert.ai_detail, alert.ai_model), ('', ''))
        row = reviewer.open_alerts()[0]
        self.assertEqual((row['ai_detail'], row['ai_model']), ('', ''))

    def test_a_real_diagnosis_is_kept_with_its_model(self):
        alert = self.report('Give the Sentinel more memory, then check docker stats.')
        self.assertEqual(alert.ai_model, 'claude-haiku-5-5')
        self.assertIn('more memory', reviewer.open_alerts()[0]['ai_detail'])

    def test_a_row_stored_before_this_fix_is_not_shown_either(self):
        reviewer.sync_alerts(self.checks())
        AdminAlert.objects.filter(code='system').update(ai_detail='Placeholder', ai_model='claude-haiku-5-5')
        row = reviewer.open_alerts()[0]
        self.assertEqual((row['ai_detail'], row['ai_model']), ('', ''))

    def test_a_verdict_note_that_is_filler_is_dropped(self):
        self.assertEqual(reviewer.usable_note('Placeholder'), '')
        self.assertEqual(reviewer.usable_note('The version is patched.'), 'The version is patched.')

    def test_the_status_and_alert_generators_never_produce_placeholder_words(self):
        for check in reviewer.ops_checks():
            self.assertFalse(re.search(r'placeholder|lorem|\btbd\b|todo', ' '.join([check['title'], check['detail']]), re.I), check['code'])

    def test_the_source_of_the_generators_has_no_placeholder_text(self):
        """Every string literal in the status and alert generators, the reviewer's prompts and the alert bar, scanned for filler words."""
        files = ['web/cveFeed/reviewer.py', 'web/agentapi/scanner_state.py', 'reviewer/cvengine_reviewer/prompts.py', 'reviewer/cvengine_reviewer/jobs.py']
        bad = re.compile(r'placeholder|lorem ipsum|\btbd\b|\btodo\b|\bfixme\b', re.I)
        found = []
        for name in files:
            with open(os.path.join(ROOT, name), encoding='utf-8') as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and bad.search(node.value):
                    found.append((name, node.lineno, node.value[:60]))
        with open(os.path.join(ROOT, 'web/static/cve/alertbar.js'), encoding='utf-8') as handle:
            if bad.search(handle.read()):
                found.append(('alertbar.js', 0, ''))
        self.assertEqual(found, [])
