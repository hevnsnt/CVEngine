"""What a Sentinel's ``-sU`` report says when the address is down, unreachable or spelled differently, and the per-day cap on asking again.

Found on cvedemo: IPv6 addresses went round forever as ``a Sentinel scanned the address but its report named no host for it``. nmap exits
``success`` with ``<hosts up="0" down="0" total="0"/>`` and no host element when it has no route to the target (the Sentinel had no IPv6), and
leaves a down on-link host out too; the old reader read both as "no host" and the address waited again at every firing."""
from unittest import mock

from cveFeed import ledger, udp_scan
from reNgine.resources import ScannerReportedNothing, ScannerUnavailable
from tests.test_udp_scan import UdpBase, run_udp

FINISHED = '<runstats><finished time="1" exit="success"/><hosts up="{up}" down="{down}" total="{total}"/></runstats>'


def report(up=0, down=0, total=0, hosts=''):
    return f'<?xml version="1.0"?><nmaprun><scaninfo type="udp" protocol="udp"/>{hosts}{FINISHED.format(up=up, down=down, total=total)}</nmaprun>'


def host_xml(address, family='ipv6'):
    return (f'<host><status state="up" reason="user-set"/><address addr="{address}" addrtype="{family}"/><ports>'
            '<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port></ports></host>')


class NormalizeTests(UdpBase):
    def test_every_spelling_of_one_ipv6_address_is_one_string(self):
        spellings = ['2600:1900:4001:370:8000:1a0::', '2600:1900:4001:0370:8000:01a0:0000:0000', '2600:1900:4001:370:8000:1a0:0:0',
                     ' [2600:1900:4001:370:8000:1A0::] ', '2600:1900:4001:370:8000:1a0::%eth0']
        self.assertEqual({udp_scan.normalize_address(s) for s in spellings}, {'2600:1900:4001:370:8000:1a0::'})

    def test_ipv4_and_junk_are_only_stripped_and_lowered(self):
        self.assertEqual(udp_scan.normalize_address(' 192.0.2.10 '), '192.0.2.10')
        self.assertEqual(udp_scan.normalize_address('Not-An-IP'), 'not-an-ip')
        self.assertEqual(udp_scan.normalize_address(None), '')


class HostFromReportTests(UdpBase):
    def test_a_differently_spelled_address_still_matches(self):
        xml = report(up=1, total=1, hosts=host_xml('2600:1900:4001:370:8000:1a0:0:0'))
        self.assertEqual(udp_scan.host_from_report(xml, '2600:1900:4001:0370:8000:01a0::')['ip'], '2600:1900:4001:370:8000:1a0:0:0')  # the record keeps nmap's own spelling

    def test_a_host_nmap_counted_down_is_a_clean_empty_record(self):
        host = udp_scan.host_from_report(report(down=1, total=1), '2600:1900:4001:370:8000:1a0::')
        self.assertEqual((host['status'], host['ports']), ('down', []))

    def test_nmap_scanning_nothing_is_an_error_not_a_wait(self):  # no route: the exact report of a Sentinel with no IPv6
        with self.assertRaises(udp_scan.UdpScanError) as caught:
            udp_scan.host_from_report(report(), '2600:1900:4001:370:8000:1a0::')
        self.assertNotIsInstance(caught.exception, ScannerUnavailable)
        self.assertIn('no route', str(caught.exception))

    def test_an_empty_cut_short_or_other_address_report_is_counted_nothing(self):
        for xml in ('', '<nmaprun><scaninfo/></nmaprun>', report(up=1, total=1, hosts=host_xml('2001:db8::9'))):
            with self.assertRaises(ScannerReportedNothing):
                udp_scan.host_from_report(xml, '2001:db8::1')


class EmptyReportSweepTests(UdpBase):
    def sweep(self, xml):
        return run_udp(runner=lambda t, f, h: xml)['scanned'][0]

    def test_a_down_host_completes_once_and_is_not_asked_again(self):
        ip = self.ip('2600:1900:4001:370:8000:1a0::')
        result = self.sweep(report(down=1, total=1))
        self.assertTrue(result['ok'])
        self.assertEqual(result['open'], [])
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(ip)]))
        self.assertEqual(run_udp(runner=lambda t, f, h: self.fail('asked again'))['scanned'], [])
        self.assertEqual(ip.ports.count(), 0)

    def test_a_target_nmap_could_not_reach_is_failed_for_a_day_not_waiting(self):
        ip = self.ip('2600:1900:4001:370:8000:1a0::')
        result = self.sweep(report())
        self.assertFalse(result['ok'])
        self.assertNotIn('waiting', result)
        self.assertTrue(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
        self.assertEqual(run_udp(runner=lambda t, f, h: self.fail('asked again'))['scanned'], [])

    def test_an_address_is_asked_at_most_the_cap_a_day_when_the_scanner_returns_nothing(self):
        ip = self.ip('192.0.2.10')
        udp_scan._empty_local.clear()
        client = udp_scan._store()
        if client is not None:
            client.delete(udp_scan.EMPTY_KEY + udp_scan.asset_of(ip))
        results = []
        with mock.patch('agentapi.sentinel_dispatch.try_nmap_udp', side_effect=ScannerReportedNothing('nmap_udp', 'empty')):
            for _ in range(udp_scan.MAX_EMPTY_PER_DAY):
                results.append(udp_scan.scan_ip(ip))
        self.assertTrue(all(r.get('waiting') for r in results[:-1]))
        self.assertTrue(results[-1].get('parked'))
        self.assertNotIn('waiting', results[-1])
        self.assertTrue(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
        self.assertEqual(udp_scan.pick(), None)  # no longer due today

    def test_the_counter_expires_after_a_day_and_a_good_scan_clears_it(self):
        udp_scan._empty_local.clear()
        with mock.patch('cveFeed.udp_scan._store', return_value=None):
            self.assertEqual([udp_scan._empty_count('a', now=t) for t in (0, 10)], [1, 2])
            self.assertEqual(udp_scan._empty_count('a', now=udp_scan.EMPTY_TTL + 11), 1)
            udp_scan._empty_reset('a')
            self.assertEqual(udp_scan._empty_count('a', now=5), 1)


# Reports captured from the real nmap 7.99 in the Sentinel image (``nmap -6 -sU -Pn -n ... -oX -``), trimmed to what is read.
REAL_NO_ROUTE = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -6 -sU -Pn -n -p U:53 -oX - 2600:1900:4001:370:8000:1a0::">'
                 '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/><verbose level="0"/><debugging level="0"/>'
                 '<runstats><finished time="1794110654" exit="success" elapsed="0.05"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>')
REAL_DOWN_ON_LINK = REAL_NO_ROUTE.replace('up="0" down="0" total="0"', 'up="0" down="1" total="1"')


class RealReportTests(UdpBase):
    def test_the_report_of_a_scanner_with_no_ipv6_route_is_not_a_result(self):
        with self.assertRaises(udp_scan.UdpScanError):
            udp_scan.host_from_report(REAL_NO_ROUTE, '2600:1900:4001:370:8000:1a0::')

    def test_the_report_of_a_down_on_link_host_is_a_clean_empty_result(self):
        self.assertEqual(udp_scan.host_from_report(REAL_DOWN_ON_LINK, 'fd00:dead:beef:77::99')['status'], 'down')
