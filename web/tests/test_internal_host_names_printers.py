"""Internal hosts are shown as ``name (address)``, and a printer is scanned gently.

Names come from the Sentinel's ``discover`` sweep inside the network (reverse DNS, then mDNS, then NetBIOS) and are kept on the target row
(``targetApp.Domain.display_name``); the address stays the identity. A host whose fingerprint shows a printer is marked and gets only the
read-only web pass: no TLS audit, no UDP sweep, no targeted pass, no OpenVAS, and nuclei never gets a raw tcp target or a print port.
"""
from unittest import mock

from django.test import SimpleTestCase

from agentapi import sentinel_dispatch
from cveFeed import host_names, internal_discovery as idisc, internal_scan, internal_view, nuclei_scan, openvas_scan
from cveFeed.discovery import SUCCESS
from cveFeed.models import InternalRange
from startScan.models import ScanActivity
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_internal_scan import NMAP_RESULT, Base, iter_none

# The Brother printer of the live network (192.168.1.71 there), as the fingerprint pass reported it, moved into the test range.
PRINTER_RESULT = {'hosts': [{'ip': '10.20.0.7', 'os_guess': 'Brother printer (VxWorks)', 'ports': [
    {'number': 80, 'protocol': 'tcp', 'state': 'open', 'method': 'probed', 'service_name': 'http', 'product': 'Debut embedded httpd',
     'devicetype': 'printer', 'service_extra': 'Brother/HP printer http admin'},
    {'number': 443, 'protocol': 'tcp', 'state': 'open', 'method': 'table', 'service_name': 'https'},
    {'number': 515, 'protocol': 'tcp', 'state': 'open', 'method': 'table', 'service_name': 'printer'},
    {'number': 631, 'protocol': 'tcp', 'state': 'open', 'method': 'probed', 'service_name': 'http', 'product': 'Debut embedded httpd',
     'devicetype': 'printer'},
    {'number': 9100, 'protocol': 'tcp', 'state': 'open', 'method': 'table', 'service_name': 'jetdirect'}]}]}


class PickAndLabelTests(Base):
    def test_reverse_dns_comes_first_then_mdns_then_netbios(self):
        self.assertEqual(host_names.pick({'hostnames': ['brwa8934a937f17.lan'], 'names': {'mdns': 'x.local', 'netbios': 'X'}}),
                         ('brwa8934a937f17', 'rdns'))
        self.assertEqual(host_names.pick({'hostnames': [], 'names': {'mdns': 'Living-Room.local', 'netbios': 'X'}}), ('Living-Room', 'mdns'))
        self.assertEqual(host_names.pick({'hostnames': [], 'names': {'netbios': 'COGSWELL'}}), ('COGSWELL', 'netbios'))
        self.assertEqual(host_names.pick({'hostnames': ['files.example.com']}), ('files.example.com', 'rdns'))  # a real domain is kept whole
        self.assertEqual(host_names.pick({'hostnames': []}), ('', ''))

    def test_a_value_that_is_not_a_host_name_is_not_used(self):
        self.assertEqual(host_names.pick({'hostnames': ['<script>.lan', '10.20.0.7'], 'names': {'netbios': 'bad name with spaces'}}), ('', ''))

    def test_the_label_is_name_then_address(self):
        self.assertEqual(host_names.label('brwa8934a937f17', '192.168.1.71'), 'brwa8934a937f17 (192.168.1.71)')
        self.assertEqual(host_names.label('', '192.168.1.71'), '192.168.1.71')
        self.assertEqual(host_names.label('192.168.1.71', '192.168.1.71'), '192.168.1.71')


class DiscoverStoresNamesTests(Base):
    def setUp(self):
        super().setUp()
        self.range = InternalRange.objects.get(project=self.pa, cidr='10.20.0.0/24')
        internal_view.invalidate()

    def sweep(self, hosts):
        def dispatch(project, kind, target, **kwargs):
            return {'hosts': hosts}
        with mock.patch('cveFeed.internal_scan.sweep'):
            return idisc.discover_range(self.range.pk, dispatch=dispatch)

    def test_each_sweep_stores_and_refreshes_the_name_and_the_address_stays_the_identity(self):
        out = self.sweep([{'ip': '10.20.0.7', 'hostnames': ['nas.lan']}, {'ip': '10.20.0.9', 'hostnames': [], 'names': {'netbios': 'COGSWELL'}}])
        self.assertEqual(out['named'], 2)
        row = Domain.objects.get(project=self.pa, name='10.20.0.7')
        self.assertEqual((row.display_name, row.display_name_source), ('nas', 'rdns'))
        self.assertEqual(Domain.objects.get(project=self.pa, name='10.20.0.9').display_name, 'COGSWELL')
        self.assertEqual(internal_view.host_label(self.pa.id, '10.20.0.7'), 'nas (10.20.0.7)')
        # the next sweep: one name changed, one host answered no name this time and keeps the one it had
        self.sweep([{'ip': '10.20.0.7', 'hostnames': ['storage.lan']}, {'ip': '10.20.0.9', 'hostnames': []}])
        self.assertEqual(Domain.objects.get(project=self.pa, name='10.20.0.7').display_name, 'storage')
        self.assertEqual(Domain.objects.get(project=self.pa, name='10.20.0.9').display_name, 'COGSWELL')
        self.assertEqual(internal_view.host_label(self.pa.id, '10.20.0.7'), 'storage (10.20.0.7)')
        self.assertEqual(Domain.objects.filter(project=self.pa, name__in=['10.20.0.7', '10.20.0.9']).count(), 2)

    def test_the_broker_keeps_the_hosts_own_names_and_nothing_else(self):
        from agentapi import sentinel_broker
        got = sentinel_broker._clean_discover_result({'hosts': [
            {'ip': '10.20.0.7', 'hostnames': ['nas.lan'], 'names': {'mdns': 'nas.local', 'netbios': 'NAS', 'other': 'x'}, 'extra': 1},
            {'ip': '10.20.0.9', 'hostnames': [], 'names': 'not a dict'}]})
        self.assertEqual(got['hosts'], [{'ip': '10.20.0.7', 'hostnames': ['nas.lan'], 'names': {'mdns': 'nas.local', 'netbios': 'NAS'}},
                                        {'ip': '10.20.0.9', 'hostnames': []}])

    def test_a_name_is_never_shown_for_another_projects_host(self):
        self.sweep([{'ip': '10.20.0.7', 'hostnames': ['nas.lan']}])
        self.assertEqual(internal_view.host_label(self.pb.id, '10.20.0.7'), '10.20.0.7')
        self.assertEqual(internal_view.display_name(self.pb.id, '10.20.0.7'), '')


class HostRowTests(Base):
    def test_the_hosts_list_and_the_host_page_carry_the_label(self):
        Domain.objects.filter(pk=self.domain.pk).update(display_name='nas', display_name_source='rdns')
        internal_view.invalidate()
        scan = self.queued_scan()
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            internal_scan.run(scan.id, dispatch=lambda project, kind, target, **kw: NMAP_RESULT if kind == 'nmap' else None,
                              nuclei_stream=lambda kind: iter_none, provider=None)
        status, out = call(self.t['admin'], 'GET', '/api/v1/projects/ir-a/hosts?page_size=50')
        self.assertEqual(status, 200, out)
        row = next(r for r in out['results'] if r['host'] == '10.20.0.7')
        self.assertEqual((row['host_label'], row['display_name'], row['printer']), ('nas (10.20.0.7)', 'nas', ''))

    def test_a_finding_row_carries_the_label_and_an_external_one_its_own_name(self):
        from agentapi import services
        Domain.objects.filter(pk=self.domain.pk).update(display_name='nas')
        internal_view.invalidate()
        self.assertEqual(services._host_label(self.pa.id, '10.20.0.7'), 'nas (10.20.0.7)')
        self.assertEqual(services._host_label(self.pa.id, 'www.example.com'), 'www.example.com')
        self.assertIsNone(services._host_label(self.pa.id, None))

    def test_the_internal_page_keeps_the_label(self):
        from cveFeed import internal_page
        rows = {'total': 1, 'counts': {}, 'results': [{'type': 'scanner', 'kind': 'scanner', 'id': 1, 'title': 't', 'host': '10.20.0.7',
                                                       'host_label': 'nas (10.20.0.7)', 'heat': 'smoke', 'severity': 'high', 'status': 'open'}]}
        with mock.patch('agentapi.services.list_findings', return_value=rows):
            out = internal_page._findings(None, 'ir-a')
        self.assertEqual(out['results'][0]['host_label'], 'nas (10.20.0.7)')


class PrinterTests(Base):
    def run_scan(self, nmap_answer):
        scan = self.queued_scan()
        kinds, streams = [], []

        def dispatch(project, kind, target, **kw):
            kinds.append(kind)
            return nmap_answer if kind == 'nmap' else None

        def stream_for(kind):
            def stream(path, **kwargs):
                with open(path, encoding='utf-8') as handle:
                    streams.append((kind, handle.read().split(), kwargs))
                return iter(())
            return stream
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            out = internal_scan.run(scan.id, dispatch=dispatch, nuclei_stream=stream_for, provider=None)
        return scan, out, kinds, streams

    def test_a_printer_is_marked_and_scanned_gently(self):
        scan, out, kinds, streams = self.run_scan(PRINTER_RESULT)
        self.assertEqual(out['status'], SUCCESS, out)
        self.assertEqual(kinds, ['nmap'])  # no testssl, no nmap_udp
        row = Domain.objects.get(pk=self.domain.pk)
        self.assertTrue(row.printer)
        self.assertIn('raw print port 9100', row.printer_evidence)
        self.assertEqual([s[0] for s in streams], ['nuclei_light'])  # no targeted pass
        _kind, targets, kwargs = streams[0]
        self.assertEqual(kwargs, {'printer': True})
        self.assertNotIn('10.20.0.7:9100', targets)
        self.assertFalse(any(t.endswith((':515', ':9100')) for t in targets))
        self.assertFalse(any(t.count(':') == 1 and '://' not in t for t in targets))  # never a raw host:port target
        stages = set(ScanActivity.objects.filter(scan_of=scan).values_list('name', flat=True))
        self.assertTrue(stages.isdisjoint(internal_scan.PRINTER_SKIPPED), stages)
        self.assertEqual(internal_view.printer_of(self.pa.id, '10.20.0.7'), row.printer_evidence)

    def test_a_host_that_stops_looking_like_a_printer_loses_the_mark(self):
        self.run_scan(PRINTER_RESULT)
        self.assertTrue(Domain.objects.get(pk=self.domain.pk).printer)
        _scan, _out, kinds, _streams = self.run_scan(NMAP_RESULT)
        self.assertFalse(Domain.objects.get(pk=self.domain.pk).printer)
        self.assertIn('testssl', kinds)

    def test_printer_targets_keep_only_web_ports_as_urls(self):
        got = nuclei_scan.printer_targets(['10.20.0.7', '10.20.0.7:631', '10.20.0.7:9100', '10.20.0.7:515', '10.20.0.7:8080',
                                           'http://10.20.0.7:9100/', 'https://10.20.0.7/'], (80, 443, 631))
        self.assertEqual(got, ['10.20.0.7', 'http://10.20.0.7:631', 'https://10.20.0.7/'])

    def test_the_printer_task_asks_for_the_read_only_set_and_no_service_labels(self):
        with mock.patch('cveFeed.validation.credential_checks_allowed', return_value=True), \
                mock.patch('cveFeed.nuclei_scan.policy_rev', return_value='all-5-cred'):
            normal = sentinel_dispatch._nuclei_target('nuclei_light', ['10.20.0.7', '10.20.0.7:8080'], {}, labels={'10.20.0.7:8080': 'unknown'},
                                                      internal=True)
            gentle = sentinel_dispatch._nuclei_target('nuclei_light', ['10.20.0.7', 'http://10.20.0.7:631'], {'printer': True},
                                                      labels={'10.20.0.7:8080': 'unknown'}, internal=True)
        self.assertTrue(normal['allow_credential_checks'])
        self.assertNotIn('allow_credential_checks', gentle)
        self.assertEqual(gentle['template_policy']['rev'], nuclei_scan.TEMPLATE_POLICY_REV)
        self.assertTrue(gentle['template_policy']['read_only'])
        self.assertNotIn('services', gentle)
        self.assertIn('default-login', gentle['etags'])

    def test_openvas_leaves_a_printer_out_even_when_a_person_names_it(self):
        Domain.objects.filter(pk=self.domain.pk).update(printer=True, printer_evidence='raw print port 9100 (JetDirect) open')
        internal_view.invalidate()
        _ready, verdicts = openvas_scan.assess(self.pa.id, {'10.20.0.7'}, forced={'10.20.0.7'}, internal=True)
        self.assertFalse(verdicts['10.20.0.7']['ready'])
        self.assertIn('a printer', verdicts['10.20.0.7']['reason'])


class PrinterBadgeTextTests(SimpleTestCase):
    """The Hosts list has room for one word on a row, so its printer badge reads "Printer" with the full sentence in its tooltip; the host page shows the sentence."""

    def setUp(self):
        from pathlib import Path
        self.src = (Path(__file__).resolve().parents[1] / 'static' / 'cve' / 'app.js').read_text()

    def test_the_badge_keeps_the_full_sentence_and_a_short_form(self):
        start = self.src.index('const printerBadge =')
        body = self.src[start:self.src.index('};', start)]
        self.assertIn('const PRINTER_LABEL = "Printer: scanned gently";', self.src)
        self.assertIn('short ? "Printer" : PRINTER_LABEL', body)
        self.assertIn('${PRINTER_LABEL}. ${why}', body)  # the short badge's tooltip starts with the full sentence

    def test_the_list_row_uses_the_short_form_and_the_host_page_the_full_one(self):
        self.assertIn('if (h.printer) meta.append(printerBadge(h.printer, true));', self.src)
        self.assertIn('if (h.printer) head.append(printerBadge(h.printer));', self.src)
        self.assertEqual(self.src.count('printerBadge(h.printer'), 2)
