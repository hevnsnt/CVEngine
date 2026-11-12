"""No IPv6 route is a fact about one Sentinel, never about the install.

PR 625 kept one Redis flag for the whole install, so a second Sentinel that has IPv6 never got IPv6 UDP work, and one unroutable address (or a
Sentinel with only a link-local network) switched IPv6 UDP off for everyone for a day. Now: the Sentinel that said so is remembered (per Sentinel, per
address), skipped for that work only, any other live Sentinel of the same tenant takes it, and only when every live Sentinel said no is the address
recorded as not scanned. The Sentinel-wide block needs two different global addresses in a row."""
from types import SimpleNamespace
from unittest import mock

from cveFeed import ledger, udp_scan
from reNgine import resources
from tests.test_udp_empty_report import REAL_NO_ROUTE, host_xml, report
from tests.test_udp_ipv6_unreachable import Ipv6UdpBase
from tests.test_udp_scan import run_udp

G1, G2, G3 = '2001:db8:1::10', '2001:db8:1::11', '2001:db8:2::20'
ULA = 'fd00:dead:beef:77::99'
A, B = 101, 102
REAL_LIVE = getattr(udp_scan, 'live_sentinel_ids', None)


def reached(address):
    return report(up=1, total=1, hosts=host_xml(address))


class PerSentinelBase(Ipv6UdpBase):
    live = {A, B}

    def setUp(self):
        super().setUp()
        udp_scan.forget_ipv6_state()
        self.addCleanup(udp_scan.forget_ipv6_state)
        patcher = mock.patch('cveFeed.udp_scan.live_sentinel_ids', side_effect=lambda project: set(self.live))
        patcher.start()
        self.addCleanup(patcher.stop)

    def asset(self, ip):
        return udp_scan.asset_of(ip)

    def run_as(self, agent, runner):
        """One Sentinel working the queue as the broker does: it is never handed an address it said no to (nothing claims it, so it waits)."""
        def try_nmap_udp(project, address, scan=None, timeout=None):
            if udp_scan.sentinel_no_route_to(agent, address):
                raise resources.ScannerUnavailable('nmap_udp', 'only a Sentinel that said no is left')
            return run_udp_reader(runner, agent, address)
        with mock.patch('agentapi.sentinel_dispatch.try_nmap_udp', try_nmap_udp):
            return udp_scan.run()['scanned']

    def say_no(self, agent):
        return self.run_as(agent, lambda t, f, h: REAL_NO_ROUTE)

    def scan_as(self, agent, address):
        return self.run_as(agent, lambda t, f, h: reached(address))


def run_udp_reader(runner, agent, address):
    try:
        host = udp_scan.host_from_report(runner([address], [], '20m') or '', address)
    except udp_scan.NoIpv6Route as exc:
        exc.agent_id = agent
        raise
    host['sentinel'] = agent
    return host


class OneSentinelSaysNoTests(PerSentinelBase):
    def test_the_address_is_not_recorded_while_another_live_sentinel_can_take_it(self):
        ip = self.ip(G1)
        out = self.say_no(A)[0]
        self.assertTrue(out.get('retry_elsewhere'))
        self.assertFalse(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [self.asset(ip)]))
        self.assertTrue(udp_scan.sentinel_no_route_to(A, G1))
        self.assertFalse(udp_scan.sentinel_no_route_to(B, G1))

    def test_the_other_sentinel_scans_it_and_that_is_a_normal_scan(self):
        ip = self.ip(G1)
        self.say_no(A)
        out = self.scan_as(B, G1)
        self.assertTrue(out[0]['ok'])
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [self.asset(ip)]))

    def test_the_task_is_not_handed_to_the_sentinel_that_said_no(self):
        self.ip(G1)
        self.say_no(A)
        task = SimpleNamespace(target={'address': G1})
        self.assertTrue(udp_scan.claim_skips(A, task))
        self.assertFalse(udp_scan.claim_skips(B, task))
        self.assertFalse(udp_scan.claim_skips(A, SimpleNamespace(target={'address': '192.0.2.10'})))
        self.assertFalse(udp_scan.claim_skips(A, SimpleNamespace(target={'address': G2})))  # one address, not the Sentinel

    def test_a_sentinel_with_ipv6_keeps_getting_ipv6_work_after_another_was_blocked(self):
        self.ip(G1)
        self.ip(G2)
        self.say_no(A)  # G1 (retried elsewhere), then G1 again is skipped for A: the loop moves on to G2
        udp_scan._flag_set(udp_scan._flag_key('agent', A))
        self.assertTrue(udp_scan.sentinel_cannot_ipv6(A))
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(B))
        task = SimpleNamespace(target={'address': G3})
        self.assertTrue(udp_scan.claim_skips(A, task))
        self.assertFalse(udp_scan.claim_skips(B, task))

    def test_every_live_sentinel_saying_no_records_the_address_as_not_scanned(self):
        ip = self.ip(G1)
        self.say_no(A)
        out = self.say_no(B)[0]
        self.assertEqual(out['unreachable'], 'ipv6')
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))
        self.assertFalse(ledger.fresh(udp_scan.FAILED_SERVICE, [self.asset(ip)]))

    def test_a_lone_sentinel_that_says_no_records_the_address(self):
        self.live = {A}
        ip = self.ip(G1)
        out = self.say_no(A)[0]
        self.assertEqual(out['unreachable'], 'ipv6')
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))

    def test_an_address_every_live_sentinel_has_said_no_to_is_not_sent_again(self):
        ip = self.ip(G1)
        self.say_no(A)
        self.say_no(B)
        out = run_udp(runner=lambda t, f, h: self.fail('sent to a Sentinel that already said no'), agent=A)
        self.assertEqual(out['scanned'], [])  # not due: waits out its day


class BlockedEverywhereTests(PerSentinelBase):
    def test_when_every_live_sentinel_is_blocked_a_new_ipv6_address_is_recorded_without_a_task(self):
        for agent in (A, B):
            udp_scan._flag_set(udp_scan._flag_key('agent', agent))
        ip = self.ip(G3)
        out = run_udp(runner=lambda t, f, h: self.fail('a task was sent'), agent=A)['scanned']
        self.assertEqual(out[0]['unreachable'], 'ipv6')
        self.assertTrue(out[0]['quiet'])
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))

    def test_when_one_live_sentinel_is_not_blocked_the_address_is_sent(self):
        udp_scan._flag_set(udp_scan._flag_key('agent', A))
        ip = self.ip(G3)
        out = self.scan_as(B, G3)
        self.assertTrue(out[0]['ok'])
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [self.asset(ip)]))


class NoLoopTests(PerSentinelBase):
    def attempts(self, runner_agent):
        calls = []

        def runner(targets, flags, timeout):
            calls.append(targets[0])
            return REAL_NO_ROUTE
        out = run_udp(runner=runner, agent=runner_agent)['scanned']
        return calls, out

    def test_one_sentinel_with_no_route_is_one_attempt_and_then_recorded(self):
        self.live = {A}
        ip = self.ip(G1)
        calls, _out = self.attempts(A)
        self.assertEqual(calls, [G1])
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))

    def test_the_same_sentinel_handed_the_address_again_ends_the_retry(self):
        # the skip at claim time failed (or the Sentinel answered twice): the address is recorded, not offered again and again
        self.live = {A, B}
        ip = self.ip(G1)
        calls, _out = self.attempts(A)
        self.assertEqual(calls, [G1, G1])
        self.assertTrue(ledger.fresh(udp_scan.NO_IPV6_SERVICE, [self.asset(ip)]))

    def test_the_attempts_never_exceed_the_live_sentinels(self):
        self.live = {A, B}
        self.ip(G1)
        asked = []

        def try_nmap_udp(project, address, scan=None, timeout=None):
            agent = next(a for a in sorted(self.live) if not udp_scan.sentinel_no_route_to(a, address))  # the claim skip, as the broker applies it
            asked.append(agent)
            exc = udp_scan.NoIpv6Route('no route')
            exc.agent_id = agent
            raise exc
        with mock.patch('agentapi.sentinel_dispatch.try_nmap_udp', try_nmap_udp):
            udp_scan.run()
        self.assertEqual(asked, [A, B])


class SentinelWideBlockTests(PerSentinelBase):
    def test_one_unreachable_global_address_does_not_block_the_sentinel(self):
        self.ip(G1)
        self.say_no(A)
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(A))

    def test_two_different_global_addresses_in_a_row_block_that_sentinel_only(self):
        self.live = {A}
        self.ip(G1)
        self.say_no(A)
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(A))
        self.ip(G2)
        self.say_no(A)
        self.assertTrue(udp_scan.sentinel_cannot_ipv6(A))
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(B))

    def test_a_scan_that_works_in_between_resets_the_run(self):
        self.live = {A}
        self.ip(G1)
        self.say_no(A)
        self.ip(G2)
        run_udp(runner=lambda t, f, h: reached(G2), agent=A)
        self.ip(G3)
        self.say_no(A)
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(A))

    def test_addresses_that_are_not_global_unicast_never_block_a_sentinel(self):
        self.live = {A}
        for address in (ULA, 'fe80::1', '::', 'ff02::1', '::ffff:192.0.2.9', 'fd00:dead:beef:78::99'):
            self.ip(address)
        for _ in range(8):
            self.say_no(A)
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(A))

    def test_a_blocked_sentinel_is_skipped_for_every_ipv6_address_and_not_ipv4(self):
        udp_scan._flag_set(udp_scan._flag_key('agent', A))
        self.assertTrue(udp_scan.claim_skips(A, SimpleNamespace(target={'address': G3})))
        self.assertFalse(udp_scan.claim_skips(A, SimpleNamespace(target={'address': '192.0.2.44'})))

    def test_a_working_scan_lifts_that_sentinels_block(self):
        udp_scan._flag_set(udp_scan._flag_key('agent', A))
        self.ip(G1)
        run_udp(runner=lambda t, f, h: reached(G1), agent=A)  # a task it held from before the block, or its day's probe, that worked
        self.assertFalse(udp_scan.sentinel_cannot_ipv6(A))

    def test_the_flags_do_not_need_redis(self):
        with mock.patch('cveFeed.udp_scan._store', return_value=None):
            udp_scan._flag_set(udp_scan._flag_key('agent', A))
            self.assertTrue(udp_scan.sentinel_cannot_ipv6(A))
            self.assertFalse(udp_scan.sentinel_cannot_ipv6(B))

    def test_a_flag_is_gone_after_its_day(self):
        udp_scan._flag_set(udp_scan._flag_key('agent', A))
        with mock.patch('cveFeed.udp_scan._store', return_value=None):
            self.assertTrue(udp_scan.sentinel_cannot_ipv6(A))
            self.assertFalse(udp_scan._flag_get(udp_scan._flag_key('agent', A), now=__import__('time').time() + udp_scan.NO_IPV6_TTL + 1))


class TenancyTests(PerSentinelBase):
    def test_the_live_sentinels_are_the_tenants_own(self):
        mine = SimpleNamespace(agent=SimpleNamespace(pk=A))
        with mock.patch('agentapi.sentinel_broker.eligible_sentinels', return_value=[mine]) as eligible:
            self.assertEqual(REAL_LIVE(self.project), {A})
        eligible.assert_called_once_with(self.project, 'nmap_udp', live_only=True)

    def test_another_tenants_blocked_sentinel_does_not_count_against_this_project(self):
        self.live = {A}
        other_tenant = 999
        udp_scan._flag_set(udp_scan._flag_key('agent', other_tenant))
        ip = self.ip(G1)
        out = self.scan_as(A, G1)
        self.assertTrue(out[0]['ok'])
        self.assertTrue(ledger.fresh(udp_scan.SERVICE, [self.asset(ip)]))

    def test_every_key_is_per_sentinel_and_holds_no_project_name(self):
        self.ip(G1)
        self.say_no(A)
        keys = [k for k in udp_scan._ipv6_local if k.startswith(udp_scan.NO_IPV6_KEY)]
        self.assertTrue(keys)
        for key in keys:
            self.assertIn(f':{A}', key)
            self.assertNotIn(self.project.slug, key)
            self.assertNotIn(G1, key)
