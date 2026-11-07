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
now answers in the same shapes. The result counts gvmd 22.x to 24.x print are named ``hole``, ``warning``, ``info``, ``log`` and
``false_positive`` only; ``critical``, ``high``, ``medium`` and ``low`` first appear in gvmd 25.0.0, which keeps the old names as deprecated
duplicates (``task_answer_25``)."""

from lxml import etree


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


def report_answer(results=(), hosts=(), details=True, total=None, first=1, counted=True):
    """``get_reports`` for one report as gvmd 22.7's print_report_xml_start writes it, inside gvmd's envelope ``<report>``. ``counted=False``
    leaves out ``<result_count>`` (a gvmd that gives no count)."""
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
    if counted:  # gvmd 22.7: hole, info, log, warning, false_positive (no critical/high/medium/low before gvmd 25)
        inner += (f'<result_count>{total}<full>{total}</full><filtered>{total}</filtered><hole><full>11</full><filtered>11</filtered></hole>'
                  '<info><full>4</full><filtered>4</filtered></info><log><full>90</full><filtered>90</filtered></log>'
                  '<warning><full>13</full><filtered>13</filtered></warning><false_positive><full>0</full><filtered>0</filtered></false_positive>'
                  '</result_count>')
    inner += '<severity><full>10.0</full><filtered>10.0</filtered></severity>'
    if details:
        for ip, start, end in hosts:
            inner += (f'<host><ip>{ip}</ip><asset asset_id=""/><start>{start}</start><end>{end}</end><port_count><page>5</page></port_count>'
                      '<result_count><page>118</page><hole><page>11</page></hole><warning><page>13</page></warning><info><page>4</page></info>'
                      '<log><page>90</page></log><false_positive><page>0</page></false_positive></result_count>'
                      f'<detail><name>hostname</name><value>www.rt.test</value><source><type>nvt</type></source></detail></host>')
    inner += '<scan_end>2026-11-02T11:23:00Z</scan_end><errors><count>0</count></errors></report>'
    return etree.fromstring(
        f'<get_reports_response status="200" status_text="OK"><report id="{REPORT}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" '
        f'content_type="text/xml"><owner><name>admin</name></owner><name>2026-11-02T10:00:00Z</name><task id="{TASK}"><name>cvengine-run-2</name></task>'
        f'<report_format id="a994b278-1f62-11e1-96ac-406186ea4fc5"><name>XML</name></report_format>{inner}</report>'
        '<filters id=""><term/></filters><sort><field>name<order>ascending</order></field></sort><reports start="1" max="1"/>'
        '<report_count>1<filtered>1</filtered><page>1</page></report_count></get_reports_response>')


def _task(report, counts, status):
    last = (f'<last_report><report id="{report}"><timestamp>2026-11-02T10:00:00Z</timestamp><scan_start>2026-11-02T10:00:00Z</scan_start>'
            f'<scan_end>2026-11-02T11:23:00Z</scan_end><result_count>{counts}</result_count><severity>10.0</severity></report></last_report>'
            if report else '')
    return etree.fromstring(f'<get_tasks_response status="200" status_text="OK"><task id="{TASK}"><name>cvengine-run-2</name><status>{status}</status>'
                            f'<progress>-1</progress>{last}</task></get_tasks_response>')


def task_answer(report=REPORT, counts=(11, 13, 4, 90), status='Done'):
    """``get_tasks`` as gvmd 22.4 to 24.x print its ``last_report`` (src/gmp.c at v22.7.0): ``hole``, ``info``, ``log``, ``warning`` and
    ``false_positive``, nothing else. ``counts`` is (hole, warning, info, log)."""
    hole, warning, info, log = counts
    return _task(report, f'<hole>{hole}</hole><info>{info}</info><log>{log}</log><warning>{warning}</warning><false_positive>0</false_positive>', status)


def task_answer_25(report=REPORT, counts=(6, 5, 13, 4, 90), status='Done'):
    """``get_tasks`` as gvmd 25.0.0 and later print its ``last_report``: ``critical``, ``high``, ``medium``, ``low`` and ``log``, with ``hole``,
    ``info`` and ``warning`` kept as deprecated duplicates of high, low and medium. ``counts`` is (critical, high, medium, low, log)."""
    critical, high, medium, low, log = counts
    return _task(report, f"<critical>{critical}</critical><hole deprecated='1'>{high}</hole><high>{high}</high><info deprecated='1'>{low}</info>"
                         f"<low>{low}</low><log>{log}</log><warning deprecated='1'>{medium}</warning><medium>{medium}</medium>"
                         '<false_positive>0</false_positive>', status)


class RecordedGmp:
    """Answers recorded in gvmd 22.7's shapes; records what was asked. ``max_rows`` is gvmd's "Max Rows Per Page" setting (manage_max_rows
    clamps every ``rows`` to it); ``total`` is the count gvmd gives when it differs from the results it has, ``None`` the real count."""

    def __init__(self, results, hosts, results_too=True, max_rows=1000, total=None, counted=True):
        self.results, self.hosts, self.results_too, self.asked = list(results), hosts, results_too, []
        self.max_rows, self.total, self.counted = max_rows, total, counted

    def _page(self, filter_string):
        words = dict(w.split('=', 1) for w in (filter_string or '').split() if '=' in w)
        first, rows = int(words.get('first', 1)), min(int(words.get('rows', 100)), self.max_rows)
        return words, first, self.results[first - 1:first - 1 + rows]

    def get_report(self, report_id, filter_string=None, details=True, **kw):
        self.asked.append(('get_report', filter_string, details))
        words, first, page = self._page(filter_string)
        shown = self.hosts if words.get('result_hosts_only') == '0' else [h for h in self.hosts if any(r.findtext('host').strip() == h[0] for r in self.results)]
        total = len(self.results) if self.total is None else self.total
        return report_answer(page, shown, details=bool(details), total=total, first=first, counted=self.counted)

    def get_results(self, filter_string=None, details=None, **kw):
        self.asked.append(('get_results', filter_string, details))
        _words, _first, page = self._page(filter_string)
        answer = results_answer(page if self.results_too else [])
        total = len(self.results) if self.total is None else self.total
        answer.find('result_count').text, answer.find('result_count/filtered').text = str(total), str(total)
        if not self.counted:
            answer.remove(answer.find('result_count'))
        return answer


class EndlessGmp:
    """A gvmd that always answers a full page (``rows`` results, its "Max Rows Per Page"), whatever ``first`` says."""

    def __init__(self, total=None, rows=100):
        self.page, self.total, self.asked = many(rows), total, []

    def get_report(self, report_id, filter_string=None, details=True, **kw):
        self.asked.append(filter_string)
        return report_answer(self.page, [], total=self.total or 0, counted=self.total is not None)

    def get_results(self, filter_string=None, details=None, **kw):
        self.asked.append(filter_string)
        answer = results_answer(self.page)
        if self.total is None:
            answer.remove(answer.find('result_count'))
        else:
            answer.find('result_count').text, answer.find('result_count/filtered').text = str(self.total), str(self.total)
        return answer


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








