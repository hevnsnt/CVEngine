"""Check coverage of a host inside a declared internal network: it is judged by what the internal scan runs, not by the external pipeline."""
from types import SimpleNamespace

from django.test import SimpleTestCase

from agentapi import sentinel_broker as sb
from cveFeed import check_coverage as cc
from cveFeed import internal_view
from cveFeed.models import ServiceRun
from startScan.models import Subdomain
from tests.test_internal_scan import NMAP_RESULT, TLS_ITEMS, UDP_XML, Base, iter_none
from unittest import mock

from cveFeed import internal_scan
from django.utils import timezone

# the checks the internal scan runs; every other check does not apply to an internal host
RUN_BY_THE_INTERNAL_SCAN = {'nmap', 'udp', 'nuclei-tech', 'nuclei', 'tls-audit', 'wpscan', 'cve-correlation', 'openvas'}


def internal_facts(**kw):
    kw.setdefault('target_name', '10.20.0.7')
    return cc.HostFacts('10.20.0.7', 1, addresses=[cc.Addr('10.20.0.7', ports=kw.pop('ports', ()))], internal='10.20.0.0/24', **kw)


class RuleTests(SimpleTestCase):
    def rows(self, host, ev=None):
        ev = ev or cc.Evidence()
        ev.sentinels[host.project_id] = True  # a live internal Sentinel: no "no Sentinel" note
        out = cc.coverage(host, ev)
        return out, {c['id']: c for c in out['checks']}

    def test_only_the_checks_the_internal_scan_runs_can_apply(self):
        out, rows = self.rows(internal_facts())
        self.assertEqual(out['internal'], '10.20.0.0/24')
        for check_id, row in rows.items():
            if check_id not in RUN_BY_THE_INTERNAL_SCAN:
                self.assertEqual(row['state'], 'not_applicable', check_id)
                self.assertEqual(row['detail'], cc.INTERNAL_REASON, check_id)

    def test_the_four_scan_checks_are_due_until_they_have_run(self):
        _out, rows = self.rows(internal_facts(ports=[SimpleNamespace(number=443, service_name='https', protocol='tcp', product='', extra={}, state='open')]))
        for check_id in ('nmap', 'udp', 'nuclei-tech', 'nuclei', 'tls-audit'):
            self.assertEqual(rows[check_id]['state'], 'due', check_id)
        self.assertEqual(rows['wpscan']['state'], 'not_applicable')
        self.assertEqual(rows['wpscan']['detail'], 'no sign of WordPress')

    def test_the_external_rules_still_decide_for_a_host_outside_a_declared_network(self):
        host = cc.HostFacts('www.example.test', 1, addresses=[cc.Addr('203.0.113.10')], target_name='example.test', target_is_domain=True)
        out = cc.coverage(host, cc.Evidence())
        self.assertIsNone(out['internal'])
        self.assertNotIn(cc.INTERNAL_REASON, [c['detail'] for c in out['checks']])

    def test_a_wordpress_tech_tag_makes_wpscan_apply(self):
        _out, rows = self.rows(internal_facts(techs=['WordPress']))
        self.assertEqual(rows['wpscan']['state'], 'due')

    def test_nothing_applies_to_a_paused_internal_host(self):
        out = cc.coverage(internal_facts(excluded=True), cc.Evidence())
        self.assertEqual((out['applicable'], out['paused']), (0, 'excluded'))


class RecordedRunsTests(Base):
    """The internal driver records the runs the coverage reads, and the coverage of the stored host reads them back."""

    def run_scan(self, answers):
        scan = self.queued_scan()
        with mock.patch('cveFeed.tasks.correlate_cves', return_value={'subdomains': 1, 'matches': 0}):
            internal_scan.run(scan.id, dispatch=lambda p, k, t, **kw: answers.get(k), nuclei_stream=lambda kind: iter_none, provider=None)
        return scan

    def coverage(self, scan):
        internal_view.invalidate()
        sub = Subdomain.objects.get(scan_history=scan, name='10.20.0.7')
        ev = cc.load([(sub, [], self.pa.id)])
        return {c['id']: c for c in cc.for_host(ev, sub, [], self.pa.id)['checks']}, cc.for_host(ev, sub, [], self.pa.id)

    def test_nmap_tls_and_udp_runs_are_recorded_and_judged_done(self):
        scan = self.run_scan({'nmap': NMAP_RESULT, 'testssl': TLS_ITEMS, 'nmap_udp': {'xml': UDP_XML}})
        kinds = set(ServiceRun.objects.values_list('service', flat=True))
        self.assertTrue({'nmap-fast', 'testssl', 'udp-scan'} <= kinds, kinds)
        self.assertTrue(ServiceRun.objects.filter(service='testssl', asset='10.20.0.7:443', project_id=self.pa.id, status='done').exists())
        rows, whole = self.coverage(scan)
        self.assertEqual(whole['internal'], '10.20.0.0/24')
        for check_id in ('nmap', 'udp', 'tls-audit'):
            self.assertEqual(rows[check_id]['state'], 'done', (check_id, rows[check_id]))
        for check_id in ('naabu', 'web-routes', 'version-probes', 'certificates', 'full-ports', 'discovery', 'waf'):
            self.assertEqual(rows[check_id]['state'], 'not_applicable', check_id)

    def test_a_tls_audit_that_did_not_complete_is_a_failed_run_and_no_answer_is_no_run(self):
        scan = self.run_scan({'nmap': NMAP_RESULT, 'testssl': {'items': []}})
        self.assertTrue(ServiceRun.objects.filter(service='testssl-failed', asset='10.20.0.7:443').exists())
        self.assertEqual(self.coverage(scan)[0]['tls-audit']['state'], 'due')
        ServiceRun.objects.all().delete()
        self.run_scan({'nmap': NMAP_RESULT})  # no TLS answer at all
        self.assertFalse(ServiceRun.objects.filter(service__startswith='testssl').exists())

    def test_no_sentinel_answering_records_no_run(self):
        self.run_scan({})
        self.assertFalse(ServiceRun.objects.filter(service__in=('nmap-fast', 'testssl', 'udp-scan')).exists())

    def test_a_due_check_says_when_no_internal_sentinel_is_online_and_stops_once_one_is(self):
        self.run_scan({})  # the host exists, nothing ran
        rows, _whole = self.coverage(Subdomain.objects.get(name='10.20.0.7').scan_history)
        self.assertIn('no Sentinel inside the network is online', rows['nmap']['detail'])
        self.sentinel('inside', ['nmap', sb.INTERNAL_CAPABILITY])
        rows, _whole = self.coverage(Subdomain.objects.get(name='10.20.0.7').scan_history)
        self.assertNotIn('no Sentinel', rows['nmap']['detail'])
        self.assertEqual(rows['nmap']['state'], 'due')
