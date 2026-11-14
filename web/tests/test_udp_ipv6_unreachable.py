"""A Sentinel with no IPv6 route cannot scan an IPv6 address. That is a fact about the Sentinel, not a failed scan of each address.

Seen on a production server: about fifty "Background UDP scan of <IPv6 address> failed (UdpScanError)" lines in six hours, one per IPv6 address,
none for an IPv4 address. The Sentinel ran ``nmap -6 -sU ...`` correctly, nmap had no route, so it exited ``success`` with ``total="0"`` hosts
and the server raised ``UdpScanError`` for every address, recorded each as failed (asked again tomorrow) and logged each as a failure.
Now the first one is noticed once ("this Sentinel cannot reach IPv6 addresses"), the address is recorded as not scanned for that reason, and
no further IPv6 address is sent to a Sentinel until the next probe a day later."""
from unittest import mock

from cveFeed import ledger, udp_scan
from cveFeed.models import AgentActivity
from reNgine import resources
from tests.test_udp_empty_report import REAL_NO_ROUTE, REAL_DOWN_ON_LINK, host_xml, report
from tests.test_udp_scan import UdpBase, run_udp

V6 = ['2001:db8:1::10', '2001:db8:1::11', '2001:db8:2::20']
NOTICE = 'cannot reach IPv6 addresses'
AGENT = 101


class Ipv6UdpBase(UdpBase):
    def setUp(self):
        super().setUp()
        udp_scan.forget_ipv6_state()
        self.addCleanup(udp_scan.forget_ipv6_state)
        patcher = mock.patch('cveFeed.udp_scan.live_sentinel_ids', return_value={AGENT})  # the one Sentinel of this tenant
        patcher.start()
        self.addCleanup(patcher.stop)

    def messages(self):
        return list(AgentActivity.objects.order_by('id').values_list('message', flat=True))

    def sweep(self, runner):
        return run_udp(runner=runner, agent=AGENT)


class ReadingTheReportTests(Ipv6UdpBase):
    def test_nothing_scanned_for_an_ipv6_address_is_no_route_not_a_scan_error(self):
        with self.assertRaises(udp_scan.NoIpv6Route):
            udp_scan.host_from_report(REAL_NO_ROUTE, '2600:1900:4001:370:8000:1a0::')

    def test_it_is_still_a_udp_scan_error_for_code_that_catches_that(self):
        self.assertTrue(issubclass(udp_scan.NoIpv6Route, udp_scan.UdpScanError))

    def test_nothing_scanned_for_an_ipv4_address_is_still_a_plain_scan_error(self):
        with self.assertRaises(udp_scan.UdpScanError) as caught:
            udp_scan.host_from_report(report(), '192.0.2.10')
        self.assertNotIsInstance(caught.exception, udp_scan.NoIpv6Route)

    def test_a_down_on_link_ipv6_host_is_still_a_clean_down_record(self):
        self.assertEqual(udp_scan.host_from_report(REAL_DOWN_ON_LINK, 'fd00:dead:beef:77::99')['status'], 'down')

    def test_an_ipv6_host_that_was_scanned_is_still_its_record(self):
        xml = report(up=1, total=1, hosts=host_xml('2001:db8:1::10'))
        self.assertEqual(udp_scan.host_from_report(xml, '2001:db8:1::10')['ip'], '2001:db8:1::10')


class SweepTests(Ipv6UdpBase):
    def test_the_first_ipv6_address_is_one_note_not_a_failed_scan(self):
        ip = self.ip(V6[0])
        result = self.sweep(lambda t, f, h: REAL_NO_ROUTE)['scanned'][0]
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'NoIpv6Route')
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [udp_scan.asset_of(ip)]))
        entry = AgentActivity.objects.get(message__contains=V6[0])
        self.assertNotEqual(entry.status, 'failed')
        self.assertIn('no Sentinel has an IPv6 route to this address', entry.message)  # one address: not yet a statement about the Sentinel
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(AGENT))
        self.assertNotIn('UdpScanError', entry.message)
        self.assertNotIn('diagnostic', entry.message)

    def test_two_global_addresses_in_a_row_make_one_notice_and_the_rest_are_not_sent_to_that_sentinel(self):
        for address in V6:
            self.ip(address)
        sent = []

        def runner(targets, flags, timeout):
            sent.extend(targets)
            return REAL_NO_ROUTE
        self.sweep(runner)
        self.assertEqual(len(sent), 2)  # two probes, not three tasks: the second made it a Sentinel with no IPv6
        notices = [m for m in self.messages() if NOTICE in m]
        self.assertEqual(len(notices), 1)
        self.assertEqual([m for m in self.messages() if 'failed' in m], [])
        self.sweep(lambda t, f, h: self.fail('an IPv6 address was sent to a Sentinel that cannot reach IPv6'))
        self.assertEqual(len([m for m in self.messages() if NOTICE in m]), 1)

    def test_an_ipv4_address_is_still_scanned_while_ipv6_is_blocked(self):
        self.ip(V6[0])
        self.sweep(lambda t, f, h: REAL_NO_ROUTE)
        v4 = self.ip('192.0.2.10')
        seen = []

        def runner(targets, flags, timeout):
            seen.extend(targets)
            return report(up=1, total=1, hosts=host_xml('192.0.2.10', 'ipv4'))
        out = self.sweep(runner)['scanned']
        self.assertEqual(seen, ['192.0.2.10'])
        self.assertTrue(out[0]['ok'])
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(v4)]))

    def test_an_ipv4_address_nmap_could_not_reach_is_still_a_failed_scan(self):
        ip = self.ip('192.0.2.10')
        result = self.sweep(lambda t, f, h: report())['scanned'][0]
        self.assertFalse(result['ok'])
        self.assertTrue(ledger.fresh(udp_scan.FAILED_SERVICE, [udp_scan.asset_of(ip)]))
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(AGENT))

    def test_a_blocked_sentinel_is_probed_again_when_its_day_ends_and_a_working_route_lifts_it(self):
        self.ip(V6[0])
        self.ip(V6[1])
        self.sweep(lambda t, f, h: REAL_NO_ROUTE)
        self.assertTrue(udp_scan.sentinel_cannot_ipv6(AGENT))
        udp_scan.forget_ipv6_state()  # what the passing of the block's day does
        other = self.ip(V6[2])
        xml = report(up=1, total=1, hosts=host_xml(V6[2]))
        out = self.sweep(lambda t, f, h: xml)['scanned']
        self.assertEqual([r['ip'] for r in out], [V6[2]])
        self.assertTrue(out[0]['ok'])
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(AGENT))
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [udp_scan.asset_of(other)]))

    def test_the_flags_do_not_need_redis(self):
        with mock.patch('cveFeed.udp_scan._store', return_value=None):
            self.assertFalse(udp_scan.sentinel_cannot_ipv6(AGENT))
            udp_scan._flag_set(udp_scan._flag_key('agent', AGENT))
            self.assertTrue(udp_scan.sentinel_cannot_ipv6(AGENT))
            udp_scan.forget_ipv6_state()
            self.assertFalse(udp_scan.sentinel_cannot_ipv6(AGENT))

    def test_the_not_scanned_record_ages_out_by_its_own_ttl(self):
        self.assertEqual(ledger.ttl(udp_scan.NO_IPV6_SERVICE), 24 * 3600)
