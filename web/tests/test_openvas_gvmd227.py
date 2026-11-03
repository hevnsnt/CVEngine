"""Issue #394: on gvmd 22.7 (Docker Desktop, python-gvm 27.10.1) every finished OpenVAS scan was imported as "no scanned host", with 0 results,
while the task's report held 118.

Why, from gvmd's own source (src/gmp.c handle_get_results and src/gmp_get.c send_get_end; print_report_xml_start in src/manage_sql.c; read at
v22.7.0 and at v26.43.0, which speaks GMP 22.7):

* ``get_results`` sends each ``<result>`` as a direct child of ``<get_results_response>``; the ``<results start=".." max=".."/>`` after them is an
  empty marker. ``findall('./results/result')`` therefore found nothing on any gvmd, and the fake gvmd the tests used wrapped them, so no test
  could see it;
* ``get_reports`` with ``details=0`` prints only counts (``<hosts><count>``), never a ``<host>``; and with ``details=1`` a host appears only when
  it has a result unless the filter says ``result_hosts_only=0``. So a scanned host with no result was always "not scanned";
* the task was then deleted with its report (``ultimate``), so nothing was left to look at.

The recorded answers below are in the shapes those printers produce; the flow tests run python-gvm unmodified against tests/fake_gvmd.py, which
now answers in the same shapes."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from lxml import etree

from cveFeed import openvas_scan as ov
from cveFeed.models import AgentActivity, OpenvasRun, ProbeObservation, ServiceRun
from startScan.models import Vulnerability
from tests.test_openvas import APACHE, LOG, OID_APACHE, Fixture

REPORT = 'f0a1b2c3-0000-4000-8000-000000000394'
TASK = 'a1b2c3d4-0000-4000-8000-000000000394'


def results_answer(results):
    """``get_results`` as gvmd prints it: the results first, then the filter, the sort, the empty <results/> marker and the counts."""
    body = ''.join(etree.tostring(r, encoding='unicode') for r in results)
    return etree.fromstring(
        f'<get_results_response status="200" status_text="OK">{body}<filters id=""><term>task_id={TASK} apply_overrides=0 min_qod=0 levels=chmlg '
        'sort-reverse=severity first=1 rows=100</term></filters><sort><field>severity<order>descending</order></field></sort>'
        f'<results start="1" max="100"/><result_count>{len(results)}<filtered>{len(results)}</filtered><page>{len(results)}</page></result_count>'
        '</get_results_response>')


def report_answer(results=(), hosts=(), details=True, total=None, first=1):
    """``get_reports`` for one report as print_report_xml_start writes it, inside gvmd's envelope ``<report>``."""
    total = len(results) if total is None else total
    inner = (f'<report id="{REPORT}"><gmp><version>22.7</version></gmp><sort><field>severity<order>descending</order></field></sort>'
             f'<filters id=""><term>apply_overrides=0 min_qod=0 levels=chmlg</term></filters><scan_run_status>Done</scan_run_status>'
             f'<hosts><count>{len(hosts)}</count></hosts><closed_cves><count>0</count></closed_cves><vulns><count>24</count></vulns>'
             '<os><count>1</count></os><apps><count>9</count></apps><ssl_certs><count>1</count></ssl_certs>'
             + ('' if details else '<ports><count>5</count></ports>')
             + f'<task id="{TASK}"><name>cvengine-run-2</name><comment>cvENGINE weekly sweep</comment><target id="t"><trash>0</trash><name>x</name></target>'
             '<progress>-1</progress></task><timestamp>2026-11-02T10:00:00Z</timestamp><scan_start>2026-11-02T10:00:00Z</scan_start>'
             '<timezone>Coordinated Universal Time</timezone><timezone_abbrev>UTC</timezone_abbrev>')
    if details:
        inner += f'<results start="{first}" max="100">' + ''.join(etree.tostring(r, encoding='unicode') for r in results) + '</results>'
    inner += (f'<result_count>{total}<full>{total}</full><filtered>{total}</filtered><critical><full>6</full><filtered>6</filtered></critical>'
              "<hole deprecated='1'><full>5</full><filtered>5</filtered></hole><high><full>5</full><filtered>5</filtered></high>"
              '<log><full>90</full><filtered>90</filtered></log></result_count><severity><full>10.0</full><filtered>10.0</filtered></severity>')
    if details:
        for ip, start, end in hosts:
            inner += (f'<host><ip>{ip}</ip><asset asset_id=""/><start>{start}</start><end>{end}</end><port_count><page>5</page></port_count>'
                      '<result_count><page>118</page><critical><page>6</page></critical></result_count>'
                      f'<detail><name>hostname</name><value>www.rt.test</value><source><type>nvt</type></source></detail></host>')
    inner += '<scan_end>2026-11-02T11:23:00Z</scan_end><errors><count>0</count></errors></report>'
    return etree.fromstring(
        f'<get_reports_response status="200" status_text="OK"><report id="{REPORT}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" '
        f'content_type="text/xml"><owner><name>admin</name></owner><name>2026-11-02T10:00:00Z</name><task id="{TASK}"><name>cvengine-run-2</name></task>'
        f'<report_format id="a994b278-1f62-11e1-96ac-406186ea4fc5"><name>XML</name></report_format>{inner}</report>'
        '<filters id=""><term/></filters><sort><field>name<order>ascending</order></field></sort><reports start="1" max="1"/>'
        '<report_count>1<filtered>1</filtered><page>1</page></report_count></get_reports_response>')


def task_answer(report=REPORT, counts=(6, 5, 13, 4, 90), status='Done'):
    c = ''.join(f'<{k}>{v}</{k}>' for k, v in zip(('critical', 'high', 'medium', 'low', 'log'), counts))
    last = (f'<last_report><report id="{report}"><timestamp>2026-11-02T10:00:00Z</timestamp><scan_start>2026-11-02T10:00:00Z</scan_start>'
            f"<scan_end>2026-11-02T11:23:00Z</scan_end><result_count>{c}<hole deprecated='1'>{counts[1]}</hole><info deprecated='1'>{counts[3]}</info>"
            f"<warning deprecated='1'>{counts[2]}</warning><false_positive>0</false_positive></result_count><severity>10.0</severity></report></last_report>"
            if report else '')
    return etree.fromstring(f'<get_tasks_response status="200" status_text="OK"><task id="{TASK}"><name>cvengine-run-2</name><status>{status}</status>'
                            f'<progress>-1</progress>{last}</task></get_tasks_response>')


class RecordedGmp:
    """Answers recorded in gvmd 22.7's shapes; records what was asked."""

    def __init__(self, results, hosts, results_too=True):
        self.results, self.hosts, self.results_too, self.asked = list(results), hosts, results_too, []

    def get_report(self, report_id, filter_string=None, details=True, **kw):
        self.asked.append(('get_report', filter_string, details))
        words = dict(w.split('=', 1) for w in (filter_string or '').split() if '=' in w)
        first, rows = int(words.get('first', 1)), int(words.get('rows', 100))
        shown = self.hosts if words.get('result_hosts_only') == '0' else [h for h in self.hosts if any(r.findtext('host').strip() == h[0] for r in self.results)]
        return report_answer(self.results[first - 1:first - 1 + rows], shown, details=bool(details), total=len(self.results), first=first)

    def get_results(self, filter_string=None, details=None, **kw):
        self.asked.append(('get_results', filter_string, details))
        words = dict(w.split('=', 1) for w in (filter_string or '').split() if '=' in w)
        first, rows = int(words.get('first', 1)), int(words.get('rows', 100))
        return results_answer(self.results[first - 1:first - 1 + rows] if self.results_too else [])


def many(n, address='192.0.2.10'):
    """``n`` results in gvmd's ``<result>`` shape (tests/fake_gvmd.py's), one in three naming a CVE."""
    import os

    from tests.fake_gvmd import FakeGvmd
    gvmd = FakeGvmd()
    os.rmdir(gvmd.tmp)  # only its result printer is used: no socket
    for i in range(n):
        gvmd.add_result('t', address, '443/tcp', f'1.3.6.1.4.1.25623.1.0.{300000 + i}', f'Check {i}', 5.0, 80,
                        cves=(f'CVE-2024-{1000 + i}',) if i % 3 == 0 else ())
    return [etree.fromstring(x) for x in gvmd.results['t']]


class RecordedShapeTests(SimpleTestCase):
    HOSTS = [('192.0.2.10', '2026-11-02T10:00:00Z', '2026-11-02T11:23:00Z')]

    def test_the_old_reader_saw_nothing_in_gvmds_get_results_answer(self):
        answer = results_answer(many(3))
        self.assertEqual(answer.findall('./results/result'), [])  # what fetch_results looked for: the bug
        self.assertEqual(len(ov._results_of(answer)), 3)

    def test_without_details_a_report_names_no_host(self):
        answer = report_answer(many(2), self.HOSTS, details=False)
        self.assertEqual(answer.findall('.//report/host'), [])  # what scanned_addresses read before: a scanned host was never seen
        self.assertEqual(ov._text(ov._report_element(answer), 'hosts/count'), '1')

    def test_the_report_is_read_page_by_page_with_its_hosts_and_count(self):
        gmp = RecordedGmp(many(118), self.HOSTS)
        out = ov.read_report(gmp, REPORT)
        self.assertEqual((len(out['items']) + out['unusable'], out['count']), (118, 118))
        self.assertEqual(out['no_cve'], 118 - 40)
        self.assertEqual(out['hosts'], {'192.0.2.10': {'start': '2026-11-02T10:00:00Z', 'end': '2026-11-02T11:23:00Z'}})
        self.assertEqual([a[0] for a in gmp.asked], ['get_report', 'get_report'])  # 118 results: two pages of 100, no third call
        for _kind, filter_string, details in gmp.asked:
            self.assertTrue(details)
            for word in ('result_hosts_only=0', 'min_qod=0', 'apply_overrides=0', 'levels=chmlg', 'rows=100'):
                self.assertIn(word, filter_string)

    def test_a_scanned_host_without_a_result_counts_as_scanned(self):
        gmp = RecordedGmp([], self.HOSTS)
        out = ov.read_report(gmp, REPORT)
        self.assertEqual(ov.scanned_addresses(gmp, task_answer(), out['items'], hosts=out['hosts']), {'192.0.2.10'})
        self.assertEqual(ov.scanned_addresses(gmp, task_answer(), []), {'192.0.2.10'})  # asked on its own: details and result_hosts_only=0
        self.assertTrue(all(details for _k, _f, details in gmp.asked))

    def test_a_host_whose_scan_never_ended_is_not_scanned(self):
        self.assertEqual(ov.scanned_addresses(None, None, [], hosts={'192.0.2.10': {'start': '2026-11-02T10:00:00Z', 'end': ''}}), set())

    def test_the_count_gvmd_gives_for_the_task_is_read_without_the_deprecated_duplicates(self):
        self.assertEqual(ov.gvm_result_count(task_answer()), 118)
        self.assertIsNone(ov.gvm_result_count(task_answer(report=None)))
        self.assertEqual(ov.report_id_of(task_answer()), REPORT)

    def test_a_task_without_a_report_id_falls_back_to_get_results(self):
        gmp = RecordedGmp(many(5), self.HOSTS)
        out = ov.task_results(gmp, task_answer(report=None), TASK)
        self.assertEqual(len(out['items']), 5)
        self.assertEqual([a[0] for a in gmp.asked], ['get_results'])

    def test_how_long_gvmd_spent_on_each_host(self):
        self.assertEqual(ov.host_minutes({'192.0.2.10': {'start': '2026-11-02T10:00:00Z', 'end': '2026-11-02T11:23:00Z'}}), {'192.0.2.10': 83})
        self.assertEqual(ov.host_minutes({'192.0.2.10': {'start': '', 'end': ''}}), {})


class Gvmd227FlowTests(Fixture, TestCase):
    """The whole sweep against the fake gvmd, which answers in gvmd 22.7's shapes."""

    def setUp(self):
        super().setUp()
        self.link.hosts, self.link.forced_hosts = ['www.rt.test'], ['www.rt.test']
        self.link.save()

    def test_a_finished_scan_imports_its_results_and_its_host(self):
        out = self.run_scan([APACHE, {**APACHE, 'oid': '1.3.6.1.4.1.25623.1.0.999', 'cves': [], 'qod': 80}])
        self.assertEqual((out['status'], out['results'], out['hosts_scanned'], out['findings']), ('done', 2, 1, 1))
        self.assertEqual(out['gvm_results'], 2)
        self.assertTrue(Vulnerability.objects.filter(template_id=f'openvas:{OID_APACHE}', open_status=True).exists())
        self.assertEqual(self.gvmd.sent('get_results'), [])  # read from the report
        self.assertEqual(self.gvmd.tasks, {})  # a conclusive import removes the task

    def test_a_scanned_host_with_nothing_found_is_scanned_not_inconclusive(self):
        self.run_scan([APACHE])
        ServiceRun.objects.all().delete()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.extra_report_hosts = {'93.184.216.5'}  # gvmd scanned www and found nothing (no result, no <host> without details)
        self.gvmd.set_status(run.task_id, 'Done', 100)
        out = self.tick()
        self.assertEqual((out['hosts_scanned'], out['inconclusive']), (1, False))
        self.assertFalse(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)  # a complete scan no longer finds it
        self.assertTrue(ServiceRun.objects.filter(service=ov.SERVICE, asset='www.rt.test').exists())

    def test_an_inconclusive_run_keeps_its_task_and_says_how_long_gvm_spent(self):
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.set_status(run.task_id, 'Done', 100)  # no result, no host in the report
        out = self.tick()
        run.refresh_from_db()
        self.assertTrue(out['inconclusive'])
        self.assertIn(run.task_id, self.gvmd.tasks)  # kept for a person to look at
        self.assertEqual(self.gvmd.sent('delete_task'), [])
        self.assertIn('kept_task_until', run.summary)
        line = AgentActivity.objects.filter(detail__openvas_run=run.pk, message__contains=ov.INCONCLUSIVE).get()
        self.assertIn(f'OpenVAS run {run.pk} on www.rt.test (GVM task cvengine-run-{run.pk})', line.message)
        self.assertIn('gvmd counts 0 result(s) for the task', line.message)
        self.assertIn('kept for 7 days', line.message)
        with self.factory() as gmp:  # before the time is over nothing is removed; after it, the task goes
            self.assertEqual(ov.remove_kept_tasks(gmp), 0)
            self.assertEqual(ov.remove_kept_tasks(gmp, now=timezone.now() + timedelta(days=8)), 1)
        self.assertNotIn(run.task_id, self.gvmd.tasks)
        run.refresh_from_db()
        self.assertNotIn('kept_task_until', run.summary)

    def test_the_inconclusive_line_names_the_time_per_host(self):
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.report_hosts[run.task_id] = {'93.184.216.5'}
        self.gvmd.host_times['93.184.216.5'] = ((timezone.now() - timedelta(minutes=125)).isoformat(), '')  # gvmd began the host and never finished it
        self.gvmd.set_status(run.task_id, 'Done', 100)
        self.assertTrue(self.tick()['inconclusive'])
        line = AgentActivity.objects.filter(detail__openvas_run=run.pk, message__contains=ov.INCONCLUSIVE).get()
        self.assertIn('GVM spent www.rt.test 2 h 5 min', line.message)

    def test_results_gvmd_counts_but_none_read_resolve_nothing_and_keep_the_task(self):
        self.run_scan([APACHE])
        ServiceRun.objects.all().delete()
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.add_result(run.task_id, **LOG)
        self.gvmd.set_status(run.task_id, 'Done', 100)
        empty = {'items': [], 'no_cve': 0, 'unusable': 0, 'hosts': {'93.184.216.5': {'start': 'a', 'end': 'b'}}, 'count': 118}
        with mock.patch.object(ov, 'read_report', return_value=empty):  # a gvmd whose answer this client cannot read
            out = self.tick()
        run.refresh_from_db()
        self.assertTrue(out['read_mismatch'])
        self.assertEqual(run.error, ov.READ_MISMATCH)
        self.assertTrue(Vulnerability.objects.get(template_id=f'openvas:{OID_APACHE}').open_status)  # nothing closed by an unread report
        self.assertEqual(ProbeObservation.objects.get(host='www.rt.test').outcome, 'found')
        self.assertIn(run.task_id, self.gvmd.tasks)

    def test_a_failed_import_keeps_the_task(self):
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.set_status(run.task_id, 'Done', 100)
        with mock.patch.object(ov, '_apply_import', side_effect=RuntimeError('boom')):
            self.assertEqual(self.tick()['status'], 'failed')
        run.refresh_from_db()
        self.assertIn(run.task_id, self.gvmd.tasks)
        self.assertIn('kept_task_until', run.summary)

    def test_the_activity_names_the_run_its_hosts_and_task_and_follows_its_progress(self):
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        line = AgentActivity.objects.get(detail__openvas_run=run.pk, detail__progress_line=True)
        self.assertEqual((line.status, line.detail['hosts'], line.detail['gvm_task']), ('running', ['www.rt.test'], f'cvengine-run-{run.pk}'))
        self.assertEqual(line.message, f'OpenVAS run {run.pk} on www.rt.test (GVM task cvengine-run-{run.pk}): started')
        self.gvmd.set_status(run.task_id, 'Running', 42)
        self.tick()
        line.refresh_from_db()
        self.assertEqual((line.message.rsplit(': ', 1)[1], line.detail['progress']), ('Running, 42 %', 42))
        self.gvmd.add_result(run.task_id, **APACHE)
        self.gvmd.set_status(run.task_id, 'Done', 100)
        self.tick()
        line.refresh_from_db()
        self.assertEqual(line.status, 'done')
        self.assertIn(': finished after', line.message)

    def test_a_stopped_run_settles_its_progress_line(self):
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.memory_state['available_mb'] = 100
        self.assertEqual(self.tick()['status'], 'stopped')
        line = AgentActivity.objects.get(detail__openvas_run=run.pk, detail__progress_line=True)
        self.assertEqual(line.status, 'done')
        self.assertIn('stopped after', line.message)
        self.assertIn('memory ran critically low', line.message)


class SidecarMemoryTests(SimpleTestCase):
    """Issue #394: the guard read the celery container's cgroup (a 4 GB limit) while the Docker VM where the scanner runs had 12.6 GB free."""

    def test_the_guard_reads_the_machine_not_the_celery_cgroup(self):
        import tempfile
        from pathlib import Path

        from reNgine import resources
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'memory.max').write_text(str(4 << 30))
            (root / 'memory.current').write_text(str(3990 << 20))
            (root / 'memory.stat').write_text('inactive_file 0\n')
            info = root / 'meminfo'
            info.write_text('MemTotal: 16357376 kB\nMemAvailable: 13212672 kB\n')  # the VM: 15.6 GB, 12.6 GB available
            self.assertLess(resources.memory_state(str(root), str(info))['available_mb'], 200)  # the celery container: nearly full
            state = resources.memory_state(str(root), str(info), host=True)
            self.assertEqual((state['limit_mb'], state['available_mb']), (None, 12903))
        with mock.patch('reNgine.resources.memory_state', side_effect=lambda *a, **k: {'total_mb': 15974, 'limit_mb': None, 'used_mb': 0,
                                                                                       'available_mb': 12903} if k.get('host') else
                        {'total_mb': 4096, 'limit_mb': 4096, 'used_mb': 4000, 'available_mb': 96}):
            self.assertEqual(ov.resource_guard(store=resources.MemoryStore(), now=1000.0), (True, ''))
            self.assertFalse(ov.memory_critical())

    def test_a_gvmd_on_another_machine_is_not_measured_here(self):
        from reNgine import resources
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_HOST': 'gvm.example.test'}), \
                mock.patch('reNgine.resources.memory_state', side_effect=AssertionError('not this machine')):
            self.assertEqual(ov.resource_guard(store=resources.MemoryStore()), (True, ''))
            self.assertFalse(ov.memory_critical())

    def test_the_override_still_applies(self):
        from reNgine import resources
        state = {'total_mb': 15974, 'limit_mb': None, 'used_mb': 0, 'available_mb': 3294}
        self.assertFalse(ov.resource_guard(state_fn=lambda: state, store=resources.MemoryStore(), now=1000.0)[0])
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_MIN_AVAILABLE_MB': '2048'}):
            self.assertTrue(ov.resource_guard(state_fn=lambda: state, store=resources.MemoryStore(), now=1000.0)[0])


class TaskReportCommandTests(Fixture, TestCase):
    def test_the_command_reads_a_live_task_without_changing_anything(self):
        import json
        from io import StringIO

        from django.core.management import call_command
        from gvm.connections import UnixSocketConnection
        self.tick()
        run = OpenvasRun.objects.get(status='running')
        self.gvmd.add_result(run.task_id, **APACHE)
        self.gvmd.add_result(run.task_id, **LOG)
        self.gvmd.extra_report_hosts = {'93.184.216.9'}
        self.gvmd.set_status(run.task_id, 'Done', 100)
        out = StringIO()
        with mock.patch.object(ov, '_connection', lambda: UnixSocketConnection(path=self.gvmd.path, timeout=5)):
            call_command('openvas_task_report', run=run.pk, stdout=out)
        got = json.loads(out.getvalue())
        self.assertEqual((got['gvm_result_count'], got['results_read'], got['with_cve'], got['without_cve']), (2, 2, 1, 1))
        self.assertEqual(got['scanned'], ['93.184.216.5', '93.184.216.6', '93.184.216.9'])
        self.assertEqual(got['get_results_first_page'], {'read_as_in_1_3_2': 0, 'sent_by_gvmd': 2})
        self.assertEqual(got['name'], f'cvengine-run-{run.pk}')
        self.assertNotIn(self.gvmd.password, out.getvalue())
        run.refresh_from_db()
        self.assertEqual(run.status, 'running')  # nothing imported, nothing deleted
        self.assertIn(run.task_id, self.gvmd.tasks)
        self.assertEqual(self.gvmd.sent('delete_task'), [])
