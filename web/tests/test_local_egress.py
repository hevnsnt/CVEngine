"""The server-side egress safeguard (cveFeed.local_egress): the ledger of this server's own outbound connections, the governor that paces
budgeted ports (25 by default) without dropping work, the cap on local fallback runs, and the opt-in skip list. Sentinels are never affected.

Every test starts and ends with the module's Redis state cleared: the governor's buckets are shared state, and a test that drains one must not
change the command lines of the next."""
import json
import os
import time
from unittest import mock

from cveFeed import local_egress, naabu_scan, nmap_scan, testssl_scan
from cveFeed.models import AgentActivity, ServiceRun
from dashboard.models import Org, Project
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

T0 = 1_900_800_000.0  # a fixed clock on the hour, well clear of the real one (the bucket keys are cleared around every test)
NO_SKIP = {'CVENGINE_LOCAL_SKIP_PORTS': ''}


def _clear():
    client = local_egress._client()
    if client is None:
        return
    keys = list(client.scan_iter(f'{local_egress.PREFIX}:*', count=1000))
    if keys:
        client.delete(*keys)


class Clean:
    """Clears this module's Redis state around every test, and gives back the real defaults the test runner turns off for every other module
    (reNgine.test_runner.EGRESS_TEST_ENV)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        from reNgine.test_runner import EGRESS_TEST_ENV
        for name in EGRESS_TEST_ENV:
            os.environ.pop(name, None)
        _clear()
        self.addCleanup(_clear)


def _messages():
    return list(AgentActivity.objects.order_by('id').values_list('message', flat=True))


def report(*hosts):
    body = ''.join(f'<host><address addr="{ip}" addrtype="ipv4"/><ports>'
                   + ''.join(f'<port protocol="tcp" portid="{n}"><state state="open"/><service name="smtp"/></port>' for n in ports)
                   + '</ports></host>' for ip, ports in hosts)
    return f'<?xml version="1.0"?><nmaprun>{body}<runstats><finished exit="success"/></runstats></nmaprun>'


# --- settings -------------------------------------------------------------------------------------------------------------

class SettingParsingTests(Clean, SimpleTestCase):
    def test_ports_ranges_junk_and_whitespace(self):
        self.assertEqual(local_egress.parse_ports('25'), {25})
        self.assertEqual(local_egress.parse_ports(' 25 , 465-467 ,587'), {25, 465, 466, 467, 587})
        self.assertEqual(local_egress.parse_ports('470-468'), {468, 469, 470})  # a range either way round
        self.assertEqual(local_egress.parse_ports('smtp, 25x, -, 0, 70000, 1-70000, 22;23'), {22, 23})  # junk is skipped, never an error
        self.assertEqual(local_egress.parse_ports(''), frozenset())
        self.assertEqual(local_egress.parse_ports(None), frozenset())
        self.assertEqual(local_egress.parse_ports('   '), frozenset())

    def test_empty_skip_list_is_the_default_and_skips_nothing(self):
        env = dict(os.environ)
        env.pop('CVENGINE_LOCAL_SKIP_PORTS', None)
        self.assertEqual(local_egress.skipped_ports(env), frozenset())
        self.assertEqual(local_egress.skipped_ports({'CVENGINE_LOCAL_SKIP_PORTS': ''}), frozenset())
        self.assertEqual(local_egress.skipped_ports({'CVENGINE_LOCAL_SKIP_PORTS': '25, 587'}), {25, 587})

    def test_budgets(self):
        self.assertEqual(local_egress.parse_budgets('25:400/hour'), {25: 400})
        self.assertEqual(local_egress.parse_budgets('25:400/hour, 587 : 100/h,465:50, 23:0, x:1, 3389:9/hours'), {25: 400, 587: 100, 465: 50, 3389: 9})
        self.assertEqual(local_egress.parse_budgets(''), {})
        self.assertEqual(local_egress.parse_budgets('0'), {})
        self.assertEqual(local_egress.budgets({}), {25: 400})  # the default
        self.assertEqual(local_egress.budgets({'CVENGINE_LOCAL_PORT_BUDGETS': ''}), {})  # empty turns pacing off
        self.assertEqual(local_egress.budgets({'CVENGINE_LOCAL_PORT_BUDGETS': '0'}), {})
        self.assertEqual(local_egress.budgets({'CVENGINE_LOCAL_PORT_BUDGETS': '25:10,587:5', 'CVENGINE_LOCAL_SKIP_PORTS': '587'}), {25: 10})

    def test_the_port_25_tunable_overrides_and_zero_turns_it_off(self):
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT25_PER_HOUR': '120'}):
            self.assertEqual(local_egress.budgets(), {25: 120})
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT25_PER_HOUR': '0'}):
            self.assertEqual(local_egress.budgets(), {})
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:50/hour,465:20'}):
            os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
            self.assertEqual(local_egress.budgets(), {25: 50, 465: 20})

    def test_default_watch_list(self):
        self.assertEqual(local_egress.watched_ports({}), (23, 25, 465, 587, 3389))


# --- command lines ----------------------------------------------------------------------------------------------------------

class CommandLineTests(SimpleTestCase):
    def test_nmap_exclude(self):
        flags = ['-sV', '-p', '22,25,80,443', '-Pn']
        self.assertEqual(local_egress.nmap_exclude(flags, {25}), ['-sV', '-p', '22,80,443', '-Pn', '--exclude-ports', '25'])
        self.assertEqual(local_egress.nmap_exclude(['-sV', '-p', '20-30'], {25}), ['-sV', '-p', '20-24,26-30', '--exclude-ports', '25'])
        self.assertEqual(local_egress.nmap_exclude(nmap_scan.FAST_FLAGS, {25}), [*nmap_scan.FAST_FLAGS, '--exclude-ports', '25'])
        self.assertEqual(local_egress.nmap_exclude(nmap_scan.FULL_PORT_FLAGS, {25, 587}), [*nmap_scan.FULL_PORT_FLAGS, '--exclude-ports', '25,587'])
        self.assertIsNone(local_egress.nmap_exclude(['-sV', '-p', '25'], {25}))  # nothing else to scan
        self.assertEqual(local_egress.nmap_exclude(flags, set()), flags)
        udp = ['-sU', '-sV', '-p', 'U:25,161']
        self.assertEqual(local_egress.nmap_exclude(udp, {25}), udp)  # a UDP-only run is not a TCP connection to port 25

    def test_naabu_exclude_and_the_default_naabu_command_is_unchanged(self):
        legacy = ['/bin/naabu', '-list', '/tmp/l', '-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
        self.assertEqual(naabu_scan.build_command('/bin/naabu', '/tmp/l', 1000), legacy)
        self.assertEqual(naabu_scan.build_command('/bin/naabu', '/tmp/l', 1000, {25}), [*legacy, '-exclude-ports', '25'])

    def test_the_plan_estimate(self):
        self.assertEqual(local_egress.nmap_plan_ports(['-p', '22,25,80'])[0], 3)
        self.assertIn(25, local_egress.nmap_plan_ports(['-p', '22,25,80'])[1])
        self.assertEqual(local_egress.nmap_plan_ports(nmap_scan.FULL_PORT_FLAGS)[0], 65535)
        self.assertEqual(local_egress.nmap_plan_ports([*nmap_scan.FULL_PORT_FLAGS, '--exclude-ports', '25'])[0], 65534)
        self.assertNotIn(25, local_egress.nmap_plan_ports([*nmap_scan.FAST_FLAGS, '--exclude-ports', '25'])[1])
        self.assertEqual(local_egress.nmap_plan_ports(['-sU', '-p', 'U:161']), (0, set()))


# --- the opt-in skip list ---------------------------------------------------------------------------------------------------

class _Popen:
    calls = []

    def __init__(self, cmd, **kwargs):
        _Popen.calls.append(cmd)
        self.returncode = 0
        self.cmd = cmd

    def communicate(self, timeout=None):
        if self.cmd[0].endswith('naabu'):
            return '{"ip":"198.51.100.1","port":22}\n', ''
        return report(), ''


class _Job:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def attach(self, proc):
        pass

    def raise_if_killed(self):
        pass


class SkipListTests(Clean, TestCase):
    def setUp(self):
        super().setUp()
        _Popen.calls = []
        for target, kwargs in (('reNgine.resources.heavy_job', {'side_effect': lambda *a, **k: _Job()}),
                               ('targetApp.target_types.refuse_local', {})):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_nmap_carries_exclude_ports_and_no_port_list_holds_25(self):
        with mock.patch.object(nmap_scan.subprocess, 'Popen', _Popen):
            nmap_scan.run_nmap_xml(['198.51.100.1'], ['-sV', '-p', '22,25,80', '-Pn'], '8m')
            nmap_scan.run_nmap_xml(['198.51.100.1'], nmap_scan.FAST_FLAGS, '8m')
        first, second = _Popen.calls
        self.assertEqual(first[first.index('-p') + 1], '22,80')
        self.assertEqual(first[first.index('--exclude-ports') + 1], '25')
        self.assertEqual(second[second.index('--exclude-ports') + 1], '25')
        self.assertIn('nmap: port 25 not scanned from this server: CVENGINE_LOCAL_SKIP_PORTS; a Sentinel does this', _messages())

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_a_run_asking_only_for_a_skipped_port_sends_nothing(self):
        with mock.patch.object(nmap_scan.subprocess, 'Popen', _Popen):
            out = nmap_scan.run_nmap_xml(['198.51.100.1'], ['-sV', '-p', '25'], '8m')
        self.assertEqual(_Popen.calls, [])
        self.assertEqual(nmap_scan.parse_xml(out, strict=True), [])

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_naabu_has_exclude_ports(self):
        with mock.patch.object(naabu_scan.subprocess, 'Popen', _Popen):
            naabu_scan.run_naabu(['198.51.100.1'], binary='/bin/naabu')
        (cmd,) = _Popen.calls
        self.assertEqual(cmd[cmd.index('-exclude-ports') + 1], '25')
        self.assertIn('naabu: port 25 not scanned from this server: CVENGINE_LOCAL_SKIP_PORTS; a Sentinel does this', _messages())

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_the_naabu_to_nmap_handoff_never_reintroduces_a_skipped_port(self):
        build = naabu_scan.flags_for({'a': [22, 25], 'b': [25]}, nmap_scan.FAST_FLAGS)
        flags = build(['a', 'b'])
        self.assertNotIn('25', flags[flags.index('-p') + 1].split(','))
        self.assertIsNone(naabu_scan.flags_for({'b': [25]}, nmap_scan.FAST_FLAGS, os_probe=False)(['b']))  # only port 25 open: nothing to do here

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_a_single_port_probe_or_validation_check_is_not_run(self):
        with mock.patch.object(nmap_scan.subprocess, 'Popen', _Popen):
            with self.assertRaises(local_egress.PortHeld) as held:
                nmap_scan.run_nmap_args(['-sV', '-Pn', '-p', '25', '-oX', '-', '198.51.100.1'], '198.51.100.1:25', 10)
        self.assertEqual((held.exception.port, held.exception.reason), (25, 'skipped'))
        self.assertEqual(_Popen.calls, [])
        from cveFeed import validation
        with mock.patch.object(nmap_scan.subprocess, 'Popen', _Popen):
            out = validation.run_nmap_sv({'argv': ['nmap', '-sV', '-Pn', '-p', '25', '198.51.100.1'], 'target': '198.51.100.1:25', 'timeout': 10,
                                          'params': {'port': 25}})
        self.assertEqual(out['status'], 'failed')
        self.assertIn('skipped on the server: port 25', out['summary'])

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_an_in_process_connection_is_refused_before_anything_is_sent(self):
        from cveFeed import pinned_transport
        with mock.patch.object(pinned_transport.socket, 'socket') as sock:
            with self.assertRaises(local_egress.PortHeld):
                pinned_transport.open_socket(((2, ('198.51.100.1', 25)),), 3, proxy=None)
        sock.assert_not_called()

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_the_coverage_reason(self):
        from cveFeed import check_coverage
        self.assertEqual(check_coverage._skip_note('nmap', None), 'skipped on the server: port 25')
        self.assertEqual(check_coverage._skip_note('wpscan', None), '')
        self.assertEqual(local_egress.coverage_note(), 'skipped on the server: port 25')

    def test_with_the_setting_empty_every_command_line_is_byte_for_byte_the_old_one(self):
        for env in ({}, NO_SKIP, {'CVENGINE_LOCAL_SKIP_PORTS': ' , junk'}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env):
                if not env:
                    os.environ.pop('CVENGINE_LOCAL_SKIP_PORTS', None)
                _Popen.calls = []
                with mock.patch.object(nmap_scan.subprocess, 'Popen', _Popen), mock.patch.object(naabu_scan.subprocess, 'Popen', _Popen):
                    nmap_scan.run_nmap_xml(['198.51.100.1'], nmap_scan.FAST_FLAGS, '8m')
                    naabu_scan.run_naabu(['198.51.100.1'], binary='/bin/naabu')
                    nmap_scan.run_nmap_args(['-sV', '-Pn', '-p', '25', '-oX', '-', '198.51.100.1'], 'x', 10)
                nmap_cmd, naabu_cmd, probe_cmd = _Popen.calls
                self.assertEqual(nmap_cmd[:-6], [nmap_scan.NMAP_BIN, *nmap_scan.FAST_FLAGS])
                self.assertEqual(nmap_cmd[-6:-2], ['--host-timeout', '8m', '-oX', '-'])
                self.assertEqual(naabu_cmd[:2] + naabu_cmd[3:], ['/bin/naabu', '-list', '-p', '-', '-rate', str(naabu_scan.rate()), '-retries', '2', '-c', '25',
                                                                 '-warm-up-time', '2', '-json', '-silent', '-nc'])
                self.assertEqual(probe_cmd, [nmap_scan.NMAP_BIN, '-sV', '-Pn', '-p', '25', '-oX', '-', '198.51.100.1'])
                self.assertEqual(naabu_scan.flags_for({'a': [22, 25]}, nmap_scan.FAST_FLAGS)(['a'])[nmap_scan.FAST_FLAGS.index('--top-ports') + 1], '1,3,22,25')


class TestsslSkipTests(Clean, TestCase):
    """testssl.sh STARTTLS on port 25: skipped here when the operator asks, but a Sentinel's dispatch payload still names the port."""

    def setUp(self):
        super().setUp()
        from tests.test_route_auth import RouteFixture
        fixture = RouteFixture()
        fixture.addCleanup = self.addCleanup
        fixture.setUp()
        self.project = fixture.project
        fixture.scan(names=('mx.rt.test',), ports=((25, 'smtp'), (443, 'https')))
        self.calls = []
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()

    def runner(self, args, env, timeout):
        self.calls.append(args)
        from tests.test_testssl_scan import CLEAN
        with open(args[args.index('--jsonfile') + 1], 'w') as out:
            json.dump(CLEAN, out)

    def sweep(self):
        return testssl_scan.sweep(self.project.id, runner=self.runner, resolve=lambda host, port, project: '203.0.113.5')

    def test_default_tests_port_25_starttls_locally_as_before(self):
        with mock.patch.dict(os.environ, NO_SKIP):
            self.sweep()
        self.assertEqual(sorted(c[-1] for c in self.calls), ['mx.rt.test:25', 'mx.rt.test:443'])

    def test_a_local_run_on_25_is_charged_its_measured_weight(self):
        with mock.patch.dict(os.environ, NO_SKIP):
            self.sweep()
        self.assertEqual(local_egress.used_this_hour(25), local_egress.TESTSSL_CONNECTIONS)

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_skipped_locally_and_the_pair_stays_due(self):
        self.sweep()
        self.assertEqual([c[-1] for c in self.calls], ['mx.rt.test:443'])
        self.assertFalse(ServiceRun.objects.filter(asset='mx.rt.test:25').exists())  # neither done nor failed: still due
        self.assertTrue(any('not run from this server: skipped on the server: port 25' in m for m in _messages()))

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '25'})
    def test_a_sentinel_dispatch_payload_keeps_port_25(self):
        from agentapi import sentinel_dispatch
        seen = []

        def dispatch(project, kind, target, **kwargs):
            seen.append(target)
            return {'items': []}
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_or_none', side_effect=dispatch):
            self.sweep()
        self.assertIn({'host': 'mx.rt.test', 'ip': '203.0.113.5', 'port': 25, 'starttls': 'smtp'}, seen)
        self.assertEqual(self.calls, [])


# --- the ledger -------------------------------------------------------------------------------------------------------------

class LedgerTests(Clean, TestCase):
    def test_counts_by_watched_port_and_in_total(self):
        with local_egress.context(kind='nmap', project=7):
            local_egress.record_nmap(['-p', '22,25,80'], ['a', 'b'], kind='nmap')
        local_egress.record_naabu(['a'])
        local_egress.record_one(443, 'route-probe')
        snap = local_egress.snapshot()
        self.assertEqual(snap['hour']['all'], 6 + 65535 + 1)
        self.assertEqual(snap['hour']['p25'], 2 + 1)
        self.assertNotIn('p443', snap['hour'])  # not a watched port: in the total only
        self.assertEqual(snap['sources']['nmap|7|25'], 2)

    def test_status_shows_the_numbers_and_that_they_are_estimates(self):
        local_egress.record('nmap', 10, {25: 4})
        out = local_egress.status([])
        port25 = next(p for p in out['watched'] if p['port'] == 25)
        self.assertEqual((port25['last_hour'], port25['last_24h'], port25['budget_per_hour']), (4, 4, 400))
        self.assertIn('estimate', out['estimate_note'])
        self.assertEqual([p['port'] for p in out['watched']], [23, 25, 465, 587, 3389])

    def test_old_hours_age_out_of_the_hour_view_but_stay_in_the_day(self):
        local_egress.record('nmap', 5, {25: 5}, now=T0 - 3 * 3600)
        snap = local_egress.snapshot(now=T0)
        self.assertEqual(snap['hour'].get('p25', 0), 0)
        self.assertEqual(snap['day']['p25'], 5)


# --- the governor ----------------------------------------------------------------------------------------------------------

@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:8/hour', 'CVENGINE_LOCAL_SKIP_PORTS': ''})
class GovernorTests(Clean, TestCase):
    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)

    def test_sliding_window_with_a_fake_clock(self):
        # 8 per hour, at most a quarter of it (2) in any 15 minutes
        self.assertEqual(local_egress.take(25, 5, now=T0), 2)
        self.assertEqual(local_egress.take(25, 1, now=T0), 0)
        self.assertEqual(local_egress.take(25, 5, now=T0 + 450), 0)  # still inside the same 15 minutes
        self.assertEqual(local_egress.take(25, 5, now=T0 + 960), 2)  # 16 minutes on: the first two left the 15-minute window
        self.assertEqual(local_egress.take(25, 3, now=T0 + 960, whole=True), 0)  # all or nothing
        self.assertEqual(local_egress.take(25, 5, now=T0 + 3600 * 2), 2)
        self.assertEqual(local_egress.take(443, 1000, now=T0), 1000)  # a port with no budget is never paced

    def test_over_budget_defers_and_does_not_drop_and_resumes_next_hour(self):
        addresses = [f'198.51.100.{i}' for i in range(1, 6)]
        org = Org.objects.create(name='G', slug='gov-org')
        project = Project.objects.create(name='G', slug='gov-p', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='gov.test', project=project, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='e-gov', yaml_configuration='x'),
                                          start_scan_date=timezone.now(), scan_status=1, results_dir='/tmp')
        sub = Subdomain.objects.create(scan_history=scan, name='www.gov.test')
        for address in addresses:
            sub.ip_addresses.add(IpAddress.objects.create(address=address))
        with local_egress.context(kind='nmap', org_id=org.id, project=project.id):
            held = local_egress.plan(addresses, {25, 80}, 'nmap', now=T0)
        self.assertEqual(sorted(held), addresses[2:])  # two granted, three held back
        self.assertTrue(all(ports == {25} for ports in held.values()))
        self.assertEqual(sorted(a for _o, a, _p in local_egress.owed(25)), addresses[2:])
        self.assertIn('port 25 paced: 2 of 5 hosts this hour (nmap); the other 3 are scanned now without port 25, which is probed later '
                      'from this server', _messages())
        probed = []

        def runner(targets, flags, host_timeout):
            probed.append((list(targets), flags))
            return report(*[(t, [25]) for t in targets])
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **k: list(hosts)):
            self.assertEqual(local_egress.catch_up(runner=runner, now=T0)[25], {'probed': 0, 'left': 3})  # the bucket is empty this hour
            out = local_egress.catch_up(runner=runner, now=T0 + 3600)  # the next hour: the bucket has refilled
        self.assertEqual(out[25], {'probed': 2, 'left': 1})
        self.assertEqual(probed[0][1][probed[0][1].index('-p') + 1], '25')  # the paced pass is port 25 alone
        self.assertEqual(Port.objects.filter(number=25, ports__address__in=probed[0][0]).count(), 2)
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **k: list(hosts)):
            out = local_egress.catch_up(runner=runner, now=T0 + 7200)
        self.assertEqual(out[25], {'probed': 1, 'left': 0})  # every host gets its port 25 probe in the end

    def test_alerts_at_50_80_and_100_percent_once_each(self):
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:40/hour'}):
            for minute in (0, 16, 32, 48):  # 10 every 16 minutes: the whole hour's 40, never more than 10 in 15 minutes
                self.assertEqual(local_egress.take(25, 10, now=T0 + minute * 60), 10)
            self.assertEqual(local_egress.take(25, 1, now=T0 + 59 * 60), 0)
        lines = [m for m in _messages() if m.startswith('port 25:')]
        self.assertEqual([m.split('(')[1].split('%')[0] for m in lines], ['50', '80', '100'])


class _ScanFixture:
    def make_scan(self, addresses):
        patcher = mock.patch('targetApp.target_types.blocked_names', return_value=set())
        patcher.start()
        self.addCleanup(patcher.stop)
        org = Org.objects.create(name='E', slug='egress')
        self.project = Project.objects.create(name='E', slug='egress-p', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-egress', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, results_dir='/tmp')
        sub = Subdomain.objects.create(scan_history=self.scan, name='www.example.test')
        for address in addresses:
            sub.ip_addresses.add(IpAddress.objects.create(address=address))


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': ''})
class NmapStageTests(Clean, _ScanFixture, TestCase):
    ADDRESSES = [f'192.0.2.{i}' for i in range(10, 15)]

    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
        self.make_scan(self.ADDRESSES)
        self.calls = []

    def runner(self, targets, flags, host_timeout):
        self.calls.append((list(targets), list(flags)))
        return report(*[(t, [22]) for t in targets])

    def test_under_budget_the_pass_and_its_coverage_are_unchanged(self):
        os.environ.pop('CVENGINE_LOCAL_PORT_BUDGETS', None)
        result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=mock.Mock(side_effect=RuntimeError('off')), dispatch=False)
        self.assertEqual(self.calls, [(self.ADDRESSES, nmap_scan.FAST_FLAGS)])
        self.assertNotIn('deferred', result)
        self.assertEqual(set(ServiceRun.objects.filter(service='nmap-fast', status='done').values_list('asset', flat=True)), set(self.ADDRESSES))
        self.assertEqual(local_egress.owed(25), [])

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:8/hour'})
    def test_over_budget_the_rest_are_scanned_without_port_25_and_port_25_is_owed(self):
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=mock.Mock(side_effect=RuntimeError('off')), dispatch=False)
        self.assertEqual(self.calls[0], (self.ADDRESSES[:2], nmap_scan.FAST_FLAGS))  # the granted ones exactly as before
        held_targets, held_flags = self.calls[1]
        self.assertEqual(held_targets, self.ADDRESSES[2:])
        self.assertEqual(held_flags, [*nmap_scan.FAST_FLAGS, '--exclude-ports', '25'])
        # every address had the rest of its ports fingerprinted: the stage is done for all of them; only port 25 waits for the paced pass
        self.assertEqual(set(ServiceRun.objects.filter(service='nmap-fast', status='done').values_list('asset', flat=True)), set(self.ADDRESSES))
        self.assertEqual(sorted(a for _o, a, _p in local_egress.owed(25)), self.ADDRESSES[2:])
        self.assertEqual({p for _o, _a, p in local_egress.owed(25)}, {self.project.id})

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:8/hour'})
    def test_naabu_handoff_over_budget_strips_port_25_from_the_held_addresses(self):
        ports = {a: [22, 25] for a in self.ADDRESSES}
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=lambda ips: dict(ports), dispatch=False)
        for targets, flags in self.calls:
            if set(targets) & set(self.ADDRESSES[2:]):
                self.assertNotIn('25', flags[flags.index('-p') + 1].split(','))
                self.assertFalse(set(targets) & set(self.ADDRESSES[:2]))


# --- naabu --------------------------------------------------------------------------------------------------------------------

@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:8/hour', 'CVENGINE_LOCAL_SKIP_PORTS': ''})
class NaabuGovernorTests(Clean, TestCase):
    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
        _Popen.calls = []
        patcher = mock.patch('reNgine.resources.heavy_job', side_effect=lambda *a, **k: _Job())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_sweep_is_split_and_the_held_addresses_exclude_port_25(self):
        lists = []

        class Proc(_Popen):
            def __init__(self, cmd, **kwargs):
                super().__init__(cmd, **kwargs)
                lists.append(open(cmd[cmd.index('-list') + 1]).read().split())
        ips = [f'198.51.100.{i}' for i in range(1, 6)]
        with mock.patch.object(naabu_scan.subprocess, 'Popen', Proc), mock.patch('targetApp.target_types.refuse_local'):
            naabu_scan.run_naabu(ips, binary='/bin/naabu')
        first, second = _Popen.calls
        self.assertNotIn('-exclude-ports', first)
        self.assertEqual(second[second.index('-exclude-ports') + 1], '25')
        self.assertEqual(lists, [ips[:2], ips[2:]])
        self.assertEqual(sorted(a for _o, a, _p in local_egress.owed(25)), ips[2:])


# --- the fallback cap and its warning --------------------------------------------------------------------------------------

class FallbackTests(Clean, _ScanFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.make_scan(['192.0.2.10', '192.0.2.11'])

    def make_sentinel(self, name, live=True, capabilities=('nmap', 'naabu')):
        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user(f'owner-{name}', password='x')
        token, _raw = create_token(user, f'token-{name}')
        return Agent.objects.create(token=token, name=name, kind='scanner', status='active',
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, capabilities=list(capabilities),
                                    last_seen=timezone.now() if live else timezone.now() - timezone.timedelta(days=1))

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR': '2'})
    def test_admit_fallback_caps_per_hour_and_zero_is_unlimited(self):
        self.assertEqual([local_egress.admit_fallback('nmap', now=T0) for _ in range(3)], [True, True, False])
        self.assertTrue(local_egress.admit_fallback('nmap', now=T0 + 3600))  # the next hour
        self.assertTrue(any('did not fall back to local execution: 2 local fallback runs of nmap this hour is the cap' in m for m in _messages()))
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR': '0'}):
            self.assertTrue(all(local_egress.admit_fallback('nmap', now=T0) for _ in range(50)))
        self.assertTrue(all(local_egress.admit_fallback('nuclei_light', now=T0) for _ in range(50)))  # only nmap and naabu are capped

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR': '1'})
    def test_an_nmap_stage_over_the_cap_defers_and_the_addresses_stay_due(self):
        from agentapi import sentinel_dispatch
        local_egress.admit_fallback('nmap')  # the hour's one fallback run is used
        runner = mock.Mock(return_value=report())
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'wrap_naabu_runner', return_value=None), \
                mock.patch.object(sentinel_dispatch, 'try_nmap', side_effect=lambda project, scan, targets, **k: (list(targets), {'ports': 0, 'hosts_with_os': 0}, None)):
            result = nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner, naabu_runner=mock.Mock(side_effect=RuntimeError('off')))
        runner.assert_not_called()
        self.assertEqual(result['deferred'], 2)
        self.assertFalse(ServiceRun.objects.filter(service='nmap-fast').exists())  # not recorded: still due

    @mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK_NAABU_PER_HOUR': '1'})
    def test_naabu_over_the_cap_is_deferred_and_not_recorded(self):
        from agentapi import sentinel_dispatch
        self.make_sentinel('quiet')
        local_egress.admit_fallback('naabu')
        local = mock.Mock(return_value={})
        with mock.patch('cveFeed.naabu_scan.run_naabu', local), \
                mock.patch.object(sentinel_dispatch, 'dispatch_many', side_effect=lambda project, kind, chunks, **k: (x for x in [(0, None)])):
            runner = sentinel_dispatch.wrap_naabu_runner(self.project, self.scan, timeout=0.2)
            found = naabu_scan.discover(['192.0.2.10', '192.0.2.11'], self.scan, runner)
        local.assert_not_called()
        self.assertEqual(found, {})
        self.assertFalse(ServiceRun.objects.filter(service='naabu').exists())

    def test_the_warning_names_offline_and_full_sentinels_and_a_system_problem_follows(self):
        self.make_sentinel('edge-1', live=False)
        for _ in range(local_egress.FALLBACK_WARN_AT):
            local_egress.note_fallback('nmap', self.project.id)
        warnings = [m for m in _messages() if 'fell back to local execution in the last hour' in m]
        self.assertEqual(len(warnings), 1)
        self.assertIn('5 stages fell back to local execution in the last hour: check your Sentinels (offline: edge-1)', warnings[0])
        problems = []
        local_egress.status(problems)
        self.assertTrue(any(p.startswith('egress: 5 stages fell back') for p in problems))
        local_egress.note_fallback('nmap', self.project.id)
        self.assertEqual(len([m for m in _messages() if 'fell back to local execution in the last hour' in m]), 1)  # once per hour


# --- Sentinels are never paced ----------------------------------------------------------------------------------------------

@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:4/hour', 'CVENGINE_LOCAL_SKIP_PORTS': '25'})
class SentinelNotPacedTests(Clean, _ScanFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.make_scan(['192.0.2.10'])

    def test_a_sentinel_naabu_chunk_asks_neither_the_governor_nor_the_skip_list(self):
        from agentapi import sentinel_dispatch
        targets = []

        def many(project, kind, chunks, **kwargs):
            targets.extend(chunks)
            return (x for x in [(0, {'ports': {'192.0.2.10': [22, 25]}})])
        with mock.patch.object(sentinel_dispatch, 'any_scanner_for', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_many', side_effect=many), \
                mock.patch.object(local_egress, 'take') as take, mock.patch('cveFeed.naabu_scan.run_naabu') as local:
            found = sentinel_dispatch.wrap_naabu_runner(self.project, self.scan)(['192.0.2.10'])
        self.assertEqual(found, {'192.0.2.10': [22, 25]})  # port 25 from a Sentinel is kept
        self.assertEqual(targets, [['192.0.2.10']])
        take.assert_not_called()
        local.assert_not_called()


# --- the configMaxxing card ----------------------------------------------------------------------------------------------------

class TunableTests(Clean, SimpleTestCase):
    def test_the_defaults_equal_the_module_constants(self):
        from cveFeed import tunables
        self.assertEqual(tunables.BY_KEY['egress_port25_per_hour'].default, local_egress.DEFAULT_PORT25_PER_HOUR)
        self.assertEqual(local_egress.parse_budgets(local_egress.DEFAULT_BUDGETS)[25], local_egress.DEFAULT_PORT25_PER_HOUR)
        self.assertEqual(tunables.BY_KEY['fallback_nmap_per_hour'].default, local_egress.DEFAULT_FALLBACK_NMAP_PER_HOUR)
        self.assertEqual(tunables.BY_KEY['fallback_naabu_per_hour'].default, local_egress.DEFAULT_FALLBACK_NAABU_PER_HOUR)
        self.assertFalse(any(tunables.BY_KEY[k].auto_tunable for k in ('egress_port25_per_hour', 'fallback_nmap_per_hour', 'fallback_naabu_per_hour')))


# --- the connection log --------------------------------------------------------------------------------------------------------

@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:8/hour'})
class ConnectionLogTests(Clean, TestCase):
    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
        for name in ('CVENGINE_EGRESS_LOG_DAYS', 'CVENGINE_EGRESS_LOG_MAX', 'CVENGINE_EGRESS_LOG_PORTS'):
            os.environ.pop(name, None)

    def test_one_record_per_address_and_logged_port_saying_exact_or_estimated_sent_or_paced(self):
        org = Org.objects.create(name='R', slug='rec-org')
        project = Project.objects.create(name='R', slug='rec-p', insert_date=timezone.now(), org=org)
        with local_egress.context(kind='nmap', project=project.id, scan_id=9):
            local_egress.record_nmap(nmap_scan.FAST_FLAGS, ['198.51.100.1', '198.51.100.2'])  # an external tool: estimated
            local_egress.plan(['198.51.100.1', '198.51.100.2', '198.51.100.3'], {25}, 'nmap')  # 2 granted, 1 paced
        local_egress.record_one(465, 'route-probe', address='198.51.100.4')  # in-process: exact
        local_egress.record_one(443, 'route-probe', address='198.51.100.4')  # not a logged port
        records = local_egress.connection_log()['records']
        rows = sorted((r['address'], r['port'], r['mode'], r['outcome'], r['kind'], r['project'], r['scan_id']) for r in records)
        self.assertEqual(rows, [
            ('198.51.100.1', 25, 'estimated', 'sent', 'nmap', project.id, 9), ('198.51.100.1', 465, 'estimated', 'sent', 'nmap', project.id, 9),
            ('198.51.100.1', 587, 'estimated', 'sent', 'nmap', project.id, 9),
            ('198.51.100.2', 25, 'estimated', 'sent', 'nmap', project.id, 9), ('198.51.100.2', 465, 'estimated', 'sent', 'nmap', project.id, 9),
            ('198.51.100.2', 587, 'estimated', 'sent', 'nmap', project.id, 9),
            ('198.51.100.3', 25, 'exact', 'paced', 'nmap', project.id, 9),
            ('198.51.100.4', 465, 'exact', 'sent', 'route-probe', None, None)])

    def test_an_in_process_connection_is_logged_exactly_with_its_address(self):
        from cveFeed import pinned_transport
        sock = mock.Mock()
        with mock.patch.object(pinned_transport.socket, 'socket', return_value=sock), \
                mock.patch.object(pinned_transport, 'is_scannable_ip', return_value=True):
            pinned_transport.open_socket(((2, ('198.51.100.7', 587)),), 3, proxy=None)
        (record,) = local_egress.connection_log()['records']
        self.assertEqual((record['address'], record['port'], record['mode'], record['outcome']), ('198.51.100.7', 587, 'exact', 'sent'))

    def test_filters_and_pages(self):
        for i in range(5):
            local_egress.log_connections([f'198.51.100.{i}'], [25 if i % 2 else 587], 'nmap', project=1 if i < 3 else 2, now=T0 + i)
        self.assertEqual([r['address'] for r in local_egress.connection_log(port=25)['records']], ['198.51.100.3', '198.51.100.1'])
        self.assertEqual([r['address'] for r in local_egress.connection_log(project=2)['records']], ['198.51.100.4', '198.51.100.3'])
        self.assertEqual([r['address'] for r in local_egress.connection_log(since=T0 + 1, until=T0 + 2)['records']], ['198.51.100.2', '198.51.100.1'])
        first = local_egress.connection_log(limit=2)
        second = local_egress.connection_log(limit=2, cursor=first['next'])
        third = local_egress.connection_log(limit=2, cursor=second['next'])
        self.assertEqual([r['address'] for page in (first, second, third) for r in page['records']], [f'198.51.100.{i}' for i in (4, 3, 2, 1, 0)])

    def test_rotation_by_age_and_by_size(self):
        with mock.patch.dict(os.environ, {'CVENGINE_EGRESS_LOG_DAYS': '14'}):
            local_egress.log_connections(['198.51.100.1'], [25], 'nmap', now=T0)
            local_egress.log_connections(['198.51.100.2'], [25], 'nmap', now=T0 + 13 * 86400)
            self.assertEqual(len(local_egress.connection_log()['records']), 2)
            local_egress.log_connections(['198.51.100.3'], [25], 'nmap', now=T0 + 15 * 86400)  # the first one is now older than 14 days
        self.assertEqual([r['address'] for r in local_egress.connection_log()['records']], ['198.51.100.3', '198.51.100.2'])
        with mock.patch.dict(os.environ, {'CVENGINE_EGRESS_LOG_MAX': '100'}):
            local_egress.log_connections([f'203.0.113.{i}' for i in range(1, 151)], [25], 'naabu', now=T0 + 16 * 86400)
            records = local_egress.connection_log(limit=1000)['records']
        self.assertEqual(len(records), 100)  # the cap: the oldest are dropped first
        self.assertEqual(records[-1]['address'], '203.0.113.51')

    def test_only_logged_ports_are_logged_and_the_list_is_configurable(self):
        local_egress.log_connections(['198.51.100.1'], [23, 3389, 443], 'nmap')
        self.assertEqual(local_egress.connection_log()['records'], [])
        with mock.patch.dict(os.environ, {'CVENGINE_EGRESS_LOG_PORTS': '3389'}):
            local_egress.log_connections(['198.51.100.1'], [25, 3389], 'nmap')
            self.assertEqual([r['port'] for r in local_egress.connection_log()['records']], [3389])

    def test_admin_only_over_rest_and_mcp_and_the_csv_export(self):
        from agentapi.auth import create_token
        from django.test import Client

        from tests.test_agentapi import call, tool_call
        from tests.test_tenancy import client_for
        org = Org.objects.create(name='L', slug='log-org')
        project = Project.objects.create(name='L', slug='log-p', insert_date=timezone.now(), org=org)
        local_egress.log_connections(['198.51.100.9'], [25], 'naabu', mode=local_egress.ESTIMATED, project=project.id, scan_id=4)
        root = User.objects.create_superuser('egress-root', 'r@example.test', 'x')
        member = User.objects.create_user('egress-member', password='x')
        _, root_token = create_token(root, 'r')
        _, member_token = create_token(member, 'm')
        status, data = call(root_token, 'GET', '/api/v1/egress/connections?port=25&project=log-p')
        self.assertEqual(status, 200)
        self.assertEqual([(r['address'], r['project'], r['mode']) for r in data['records']], [('198.51.100.9', 'log-p', 'estimated')])
        self.assertIn('estimated', data['note'])
        self.assertEqual(call(member_token, 'GET', '/api/v1/egress/connections')[0], 403)
        error, data = tool_call(root_token, 'list_egress_connections', {'port': 25})
        self.assertFalse(error)
        self.assertEqual(data['records'][0]['address'], '198.51.100.9')
        self.assertTrue(tool_call(member_token, 'list_egress_connections')[0])
        response = Client().get('/api/v1/egress/connections?format=csv', HTTP_AUTHORIZATION=f'Bearer {root_token}')
        self.assertEqual((response.status_code, response['Content-Type']), (200, 'text/csv; charset=utf-8'))
        lines = response.content.decode().splitlines()
        self.assertEqual(lines[0], 'time_utc,destination_address,destination_port,outcome,exact_or_estimated,tool,project,scan_id')
        self.assertTrue(lines[1].endswith(',198.51.100.9,25,sent,estimated,naabu,log-p,4'))
        self.assertEqual(Client().get('/api/v1/egress/connections?format=csv', HTTP_AUTHORIZATION=f'Bearer {member_token}').status_code, 403)
        page = client_for(root).get('/cve/api/settings/egress/connections.csv')
        self.assertEqual(page.status_code, 200)
        self.assertIn('198.51.100.9', page.content.decode())
        self.assertEqual(client_for(member).get('/cve/api/settings/egress/connections.csv').status_code, 403)


# --- review of PR #389: regressions --------------------------------------------------------------------------------------------

def _probes_on(port, calls):
    """How many addresses the recorded nmap command lines would probe on ``port``."""
    n = 0
    for targets, flags in calls:
        _count, watched = local_egress.nmap_plan_ports(flags)
        listed = local_egress._expand(flags[flags.index('-p') + 1]) if '-p' in flags else None
        excluded = local_egress._expand(flags[flags.index('--exclude-ports') + 1]) if '--exclude-ports' in flags else set()
        if port in (excluded or set()):
            continue
        if (listed is not None and port in listed) or (listed is None and port in watched):
            n += len(targets)
    return n


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:4/hour'})
class ChunkUnionTests(Clean, _ScanFixture, TestCase):
    """naabu's handoff builds one -p list per chunk from the union of its addresses' open ports (and falls back to the full list when an address
    has no naabu answer): every address nmap will probe on port 25 must have been charged for it, and no other address may be probed on it."""
    ADDRESSES = [f'192.0.2.{i}' for i in range(10, 15)]

    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
        self.make_scan(self.ADDRESSES)
        self.calls = []

    def runner(self, targets, flags, host_timeout):
        self.calls.append((list(targets), list(flags)))
        return report(*[(t, [80]) for t in targets])

    def test_a_chunk_neighbour_without_port_25_is_not_probed_on_it(self):
        ports = {a: [80] for a in self.ADDRESSES}
        ports[self.ADDRESSES[0]] = [25, 80]
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=lambda ips: dict(ports), dispatch=False)
        self.assertEqual(local_egress.used_this_hour(25), 1)
        self.assertEqual(_probes_on(25, self.calls), 1)
        self.assertEqual(local_egress.owed(25), [])

    def test_the_fallback_to_the_full_list_is_charged_for_every_address_it_reaches(self):
        ports = {a: [80] for a in self.ADDRESSES[1:]}
        ports[self.ADDRESSES[0]] = list(range(1, naabu_scan.MAX_OPEN_PER_IP + 10))  # a tarpit: no usable naabu answer, so its chunk gets the full list
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=lambda ips: dict(ports), dispatch=False)
        self.assertIn(([self.ADDRESSES[0]], nmap_scan.FAST_FLAGS), self.calls)  # the full list, port 25 included, for that address alone
        self.assertEqual(_probes_on(25, self.calls), local_egress.used_this_hour(25))
        self.assertEqual(_probes_on(25, self.calls), 1)

    def test_over_budget_every_probe_on_25_was_charged(self):
        ports = {a: [25, 80] for a in self.ADDRESSES}  # budget 4/hour: one at once
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=self.runner, naabu_runner=lambda ips: dict(ports), dispatch=False)
        self.assertEqual(_probes_on(25, self.calls), local_egress.used_this_hour(25))
        self.assertEqual(len(local_egress.owed(25)), len(self.ADDRESSES) - local_egress.used_this_hour(25))


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:400/hour'})
class HourlyBudgetTests(Clean, TestCase):
    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)

    def test_never_more_than_the_budget_in_any_hour_nor_a_quarter_of_it_in_any_15_minutes(self):
        grants = []
        for second in range(0, 3 * 3600, 9):  # a steady demand far above the budget for three hours
            grants.append((second, local_egress.take(25, 10, now=T0 + second)))
        for start in range(0, 2 * 3600 + 1, 300):
            self.assertLessEqual(sum(g for s, g in grants if start <= s < start + 3600), 400, start)
            self.assertLessEqual(sum(g for s, g in grants if start <= s < start + 900), 100, start)
        self.assertGreaterEqual(sum(g for s, g in grants if 3600 <= s < 7200), 380)  # and the budget is really usable
        self.assertLessEqual(local_egress.used_this_hour(25, now=T0), 400)

    def test_testssl_is_charged_for_the_connections_it_opens(self):
        self.assertGreater(local_egress.TESTSSL_CONNECTIONS, 1)
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': f'25:{local_egress.TESTSSL_CONNECTIONS * 4}/hour'}):
            self.assertIsNone(local_egress.admit_one(25, 'testssl', '198.51.100.1', weight=local_egress.TESTSSL_CONNECTIONS))
            self.assertEqual(local_egress.used_this_hour(25), local_egress.TESTSSL_CONNECTIONS)
            self.assertEqual(local_egress.admit_one(25, 'testssl', '198.51.100.2', weight=local_egress.TESTSSL_CONNECTIONS), 'paced')
            self.assertEqual(local_egress.used_this_hour(25), local_egress.TESTSSL_CONNECTIONS)  # all or nothing: a paced run takes no token


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:400/hour'})
class CatchUpScopeTests(Clean, _ScanFixture, TestCase):
    def setUp(self):
        super().setUp()
        os.environ.pop('CVENGINE_LOCAL_PORT25_PER_HOUR', None)
        self.make_scan(['198.51.100.7'])
        self.probed = []

    def runner(self, targets, flags, host_timeout):
        self.probed.append(list(targets))
        return report(*[(t, [25]) for t in targets])

    def test_an_address_excluded_since_is_not_probed_and_leaves_the_owed_list(self):
        from cveFeed.models import HostExclusion
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)
        HostExclusion.objects.create(org=self.project.org, host='198.51.100.7', created_at=timezone.now())
        local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [])
        self.assertEqual(local_egress.owed(25), [])
        self.assertTrue(any('198.51.100.7' in m and 'out of scope' in m for m in _messages()))

    def test_an_address_not_scannable_right_now_stays_owed(self):
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]):
            local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [])
        self.assertEqual([a for _o, a, _p in local_egress.owed(25)], ['198.51.100.7'])

    def test_scope_is_judged_per_project_so_a_tailnet_device_of_the_project_is_probed(self):
        Subdomain.objects.get(scan_history=self.scan).ip_addresses.add(IpAddress.objects.create(address='100.64.0.9'))
        local_egress.owe(25, ['100.64.0.9'], org_id=self.project.org_id, project=self.project.id)
        seen = []

        def scannable(hosts, project=None, **kwargs):
            seen.append(project)
            return list(hosts) if project == self.project.id else []
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=scannable):
            local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [['100.64.0.9']])
        self.assertIn(self.project.id, seen)

    def test_the_launch_rechecks_scope_after_the_wait(self):
        from cveFeed.models import HostExclusion
        check = local_egress._scope_recheck(['198.51.100.7'], self.project.id)
        check()  # in scope: no error
        HostExclusion.objects.create(org=self.project.org, host='198.51.100.7', created_at=timezone.now())
        with self.assertRaises(ValueError):
            check()

    def test_overlapping_passes_never_probe_the_same_address_twice(self):
        Subdomain.objects.get(scan_history=self.scan).ip_addresses.add(IpAddress.objects.create(address='198.51.100.8'))
        local_egress.owe(25, ['198.51.100.8'], org_id=self.project.org_id, project=self.project.id)

        def runner(targets, flags, host_timeout):
            self.probed.append(list(targets))
            if len(self.probed) == 1:  # a second pass starts while the first runs (another cve_feed_queue slot)
                self.assertEqual(local_egress.catch_up(runner=runner), {'skipped': 'another catch-up pass is running'})
            return report(*[(t, [25]) for t in targets])
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, **k: list(hosts)):
            local_egress.catch_up(runner=runner)
        self.assertEqual(self.probed, [['198.51.100.8']])


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR': '1'})
class OfflineSentinelFallbackTests(Clean, _ScanFixture, TestCase):
    """A project whose Sentinels are all offline runs its stages here: that is a fallback too (capped, counted, warned about). A project that
    never had a Sentinel runs here as its normal mode: never capped, never counted."""

    def setUp(self):
        super().setUp()
        self.make_scan(['192.0.2.10', '192.0.2.11'])

    def offline_sentinel(self):
        from agentapi.auth import create_token
        from agentapi.models import Agent
        user = User.objects.create_user('owner-off', password='x')
        token, _raw = create_token(user, 'token-off')
        Agent.objects.create(token=token, name='edge-off', kind='scanner', status='active',
                             scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, capabilities=['nmap', 'naabu'],
                             last_seen=timezone.now() - timezone.timedelta(days=1))

    def run_stage(self, runner, times=3):
        for _ in range(times):
            ServiceRun.objects.all().delete()
            nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner, naabu_runner=mock.Mock(side_effect=RuntimeError('off')), force=True)

    def test_offline_sentinels_count_as_fallback_and_the_cap_applies(self):
        self.offline_sentinel()
        runner = mock.Mock(return_value=report())
        self.run_stage(runner)
        self.assertEqual(runner.call_count, 1)  # the cap of one local nmap fallback run this hour; the rest stay due
        self.assertGreaterEqual(local_egress.fallbacks_last_hour(), 3)

    def test_the_warning_fires_when_every_sentinel_is_offline(self):
        self.offline_sentinel()
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR': '0'}):
            self.run_stage(mock.Mock(return_value=report()), times=local_egress.FALLBACK_WARN_AT)
        self.assertTrue(any('fell back to local execution in the last hour: check your Sentinels (offline: edge-off)' in m for m in _messages()))

    def test_a_project_that_never_had_a_sentinel_is_neither_capped_nor_counted(self):
        runner = mock.Mock(return_value=report())
        self.run_stage(runner)
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(local_egress.fallbacks_last_hour(), 0)


class ApiInputTests(Clean, TestCase):
    def test_bad_times_ports_and_cursors_are_400_not_500(self):
        from agentapi.auth import create_token

        from tests.test_agentapi import call, tool_call
        root = User.objects.create_superuser('egress-root3', 'r3@example.test', 'x')
        _, token = create_token(root, 'r3')
        local_egress.log_connections(['198.51.100.9'], [25], 'naabu')
        for query in ('since=nan', 'until=inf', 'since=1e400', 'until=-1', 'cursor=garbage', 'port=99999999999999999999', 'port=0', 'limit=x'):
            self.assertEqual(call(token, 'GET', f'/api/v1/egress/connections?{query}')[0], 400, query)
        self.assertEqual(call(token, 'GET', '/api/v1/egress/connections?since=2026-01-01T00:00:00Z&limit=5')[0], 200)
        error, _ = tool_call(token, 'list_egress_connections', {'since': 'nan'})
        self.assertTrue(error)


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:400/hour'})
class InProcessAccountingTests(Clean, TestCase):
    def test_a_refused_destination_is_neither_logged_nor_charged(self):
        from cveFeed import pinned_transport
        with mock.patch.object(pinned_transport.socket, 'socket') as sock:
            with self.assertRaises(ValueError):
                pinned_transport.open_socket(((2, ('10.1.2.3', 25)),), 3, proxy=None)
        sock.assert_not_called()
        self.assertEqual(local_egress.connection_log()['records'], [])
        self.assertFalse(local_egress.used_this_hour(25))

    def test_each_address_actually_tried_is_logged(self):
        from cveFeed import pinned_transport
        first, second = mock.Mock(), mock.Mock()
        first.connect.side_effect = ConnectionRefusedError('refused')
        with mock.patch.object(pinned_transport.socket, 'socket', side_effect=[first, second]), \
                mock.patch.object(pinned_transport, 'is_scannable_ip', return_value=True):
            sock = pinned_transport.open_socket(((2, ('198.51.100.1', 25)), (2, ('198.51.100.2', 25))), 3, proxy=None)
        self.assertIs(sock, second)
        self.assertEqual(sorted(r['address'] for r in local_egress.connection_log()['records']), ['198.51.100.1', '198.51.100.2'])
        self.assertEqual(local_egress.used_this_hour(25), 2)


class HermeticTests(SimpleTestCase):
    def test_the_test_runner_turns_pacing_and_fallback_caps_off_outside_these_tests(self):
        self.assertEqual(os.environ.get('CVENGINE_LOCAL_PORT_BUDGETS'), '')
        self.assertEqual(local_egress.budgets(), {})
        self.assertEqual(os.environ.get('CVENGINE_LOCAL_FALLBACK_NMAP_PER_HOUR'), '0')
        self.assertEqual(os.environ.get('CVENGINE_LOCAL_FALLBACK_NAABU_PER_HOUR'), '0')


# --- second review of PR #389: regressions ---------------------------------------------------------------------------------------

def port25_targets(calls):
    """(address, port 25) probes the recorded nmap command lines would send: an address counts when 25 is in its -p list (or the full / top
    list) and not in --exclude-ports."""
    n = 0
    for targets, flags in calls:
        excluded = set()
        if '--exclude-ports' in flags:
            excluded = local_egress._expand(flags[flags.index('--exclude-ports') + 1]) or set()
        if 25 in excluded:
            continue
        if '-p-' in flags:
            n += len(targets)
        elif '-p' in flags:
            if 25 in (local_egress._expand(flags[flags.index('-p') + 1]) or set()):
                n += len(targets)
        else:
            n += len(targets)  # --top-ports 1000 holds 25
    return n


R2 = {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:400/hour'}


@mock.patch.dict(os.environ, R2)
class NucleiGovernedTests(Clean, TestCase):
    """nuclei gets host:25 for every host with port 25 open: each such target is asked of the governor (NUCLEI_TARGET_CONNECTIONS, all or
    nothing); one not granted is left out of this run, logged paced, and the rest of the run goes ahead."""

    def run_nuclei(self, targets):
        import tempfile

        from cveFeed import nuclei_scan
        handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False)
        handle.write('\n'.join(targets) + '\n')
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        seen = []

        def fake(path, *a, **k):
            seen.extend(open(path).read().split())
            return iter(())
        with mock.patch.object(nuclei_scan, '_stream_nuclei', side_effect=fake):
            list(nuclei_scan.stream_nuclei(handle.name))
        return seen

    def test_a_drained_budget_holds_host_25_targets_back_and_the_rest_runs(self):
        self.assertEqual(local_egress.take(25, 400), 100)  # this 15 minutes' share is used up
        targets = [f'198.51.100.{i}:25' for i in range(1, 51)] + ['www.example.test', '198.51.100.1:8443']
        seen = self.run_nuclei(targets)
        self.assertEqual(seen, ['www.example.test', '198.51.100.1:8443'])
        self.assertEqual(local_egress.used_this_hour(25), 100)
        records = local_egress.connection_log(port=25, limit=1000)['records']
        self.assertEqual({r['outcome'] for r in records}, {'paced'})
        self.assertEqual(len(records), 50)

    def test_each_granted_target_is_charged_its_weight_whole(self):
        self.assertGreater(local_egress.NUCLEI_TARGET_CONNECTIONS, 1)
        n = 100 // local_egress.NUCLEI_TARGET_CONNECTIONS
        seen = self.run_nuclei([f'198.51.100.{i}:25' for i in range(1, n + 3)])
        self.assertEqual(len(seen), n)  # the 15-minute share holds this many whole targets
        self.assertEqual(local_egress.used_this_hour(25), n * local_egress.NUCLEI_TARGET_CONNECTIONS)
        self.assertEqual(sorted({r['outcome'] for r in local_egress.connection_log(port=25)['records']}), ['paced', 'sent'])


@mock.patch.dict(os.environ, R2)
class MemoryKillRetryTests(Clean, _ScanFixture, TestCase):
    """scan_in_chunks halves and re-runs a chunk nmap was stopped on for memory: the re-run must not probe port 25 again uncharged."""
    ADDRESSES = [f'192.0.2.{i}' for i in range(10, 20)]

    def setUp(self):
        super().setUp()
        self.make_scan(self.ADDRESSES)
        self.calls = []

    def test_the_retried_halves_leave_port_25_to_the_paced_pass(self):
        from reNgine.resources import MemoryKill

        def runner(targets, flags, host_timeout):
            self.calls.append((list(targets), list(flags)))
            if len(self.calls) == 1:
                raise MemoryKill('nmap', 'test')
            return report(*[(t, [25, 80]) for t in targets])
        ports = {a: [25, 80] for a in self.ADDRESSES}
        nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner, naabu_runner=lambda ips: dict(ports), dispatch=False)
        self.assertEqual(len(self.calls), 3)
        self.assertLessEqual(port25_targets(self.calls), local_egress.used_this_hour(25))
        for _targets, flags in self.calls[1:]:
            self.assertIn('25', flags[flags.index('--exclude-ports') + 1].split(','))
        self.assertEqual(sorted(a for _o, a, _p in local_egress.owed(25)), self.ADDRESSES)


@mock.patch.dict(os.environ, R2)
class OwedListTests(Clean, _ScanFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.make_scan(['198.51.100.7'])
        self.probed = []

    def runner(self, targets, flags, host_timeout):
        self.probed.append(list(targets))
        return report(*[(t, [25]) for t in targets])

    def test_entries_not_scannable_now_never_starve_newer_ones(self):
        stuck = [f'10.9.0.{i}' for i in range(1, local_egress.CATCH_UP_BATCH + 5)]
        sub = Subdomain.objects.get(scan_history=self.scan)
        for a in stuck:
            sub.ip_addresses.add(IpAddress.objects.create(address=a))
            local_egress.owe(25, [a], org_id=self.project.org_id, project=self.project.id)
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)
        local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [['198.51.100.7']])
        self.assertEqual(len(local_egress.owed(25)), len(stuck))  # still owed, behind nobody

    def test_each_entry_ages_out_on_its_own_after_30_days_with_a_log_line(self):
        with mock.patch.object(local_egress.time, 'time', return_value=time.time() - 31 * 86400):
            local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)  # owing again keeps its age
        with mock.patch('targetApp.target_types.scannable_hosts', return_value=[]):
            local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(local_egress.owed(25), [])
        self.assertTrue(any('198.51.100.7' in m and '30 days' in m for m in _messages()))

    def test_an_entry_of_a_deleted_project_or_no_project_is_dropped_not_probed(self):
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)
        local_egress.owe(25, ['198.51.100.9'], org_id=None, project=None)
        self.project.delete()
        out = local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [])
        self.assertEqual(local_egress.owed(25), [])
        self.assertEqual(out[25]['probed'], 0)

    def test_an_address_that_left_the_project_is_dropped(self):
        local_egress.owe(25, ['203.0.113.77'], org_id=self.project.org_id, project=self.project.id)  # on no host of the project
        local_egress.catch_up(runner=self.runner, now=T0)
        self.assertEqual(self.probed, [])
        self.assertEqual(local_egress.owed(25), [])

    def test_the_default_runner_checks_scope_before_launch_and_logs_nothing_sent_when_refused(self):
        from cveFeed.models import HostExclusion
        local_egress.owe(25, ['198.51.100.7'], org_id=self.project.org_id, project=self.project.id)

        def heavy(kind, **kwargs):
            HostExclusion.objects.create(org=self.project.org, host='198.51.100.7', created_at=timezone.now())  # excluded during the wait
            return _Job()
        with mock.patch('reNgine.resources.heavy_job', side_effect=heavy), mock.patch('targetApp.target_types.refuse_local'), \
                mock.patch.object(nmap_scan.subprocess, 'Popen') as popen:
            local_egress.catch_up(now=T0)
        popen.assert_not_called()
        self.assertFalse([r for r in local_egress.connection_log()['records'] if r['outcome'] == 'sent'])


@mock.patch.dict(os.environ, R2)
class WindowTests(Clean, TestCase):
    def test_61_minute_buckets_are_needed(self):
        got = [(s, local_egress.take(25, 100, now=T0 + s, burst=False)) for s in (59, 960, 1860, 2760, 3600)]  # the hour alone
        self.assertEqual([g for _s, g in got[:4]], [100] * 4)
        self.assertLessEqual(sum(g for s, g in got if 59 <= s < 59 + 3600), 400)

    def test_16_minute_buckets_are_needed(self):
        got = [local_egress.take(25, 100, now=T0 + s) for s in (59, 900)]
        self.assertLessEqual(sum(got), 100)

    def test_the_window_uses_the_redis_clock_not_each_workers(self):
        with mock.patch.object(local_egress.time, 'time', return_value=time.time() + 120):  # a worker whose clock runs two minutes fast
            ahead = local_egress.take(25, 100)
        behind = local_egress.take(25, 100)
        self.assertEqual(ahead + behind, 100)

    def test_all_or_nothing_against_the_hour(self):
        for minute in (0, 16, 32):
            self.assertEqual(local_egress.take(25, 100, now=T0 + minute * 60), 100)
        self.assertEqual(local_egress.take(25, 150, now=T0 + 48 * 60, whole=True, burst=False), 0)  # 100 left in the hour: not 150
        self.assertEqual(local_egress.used_this_hour(25, now=T0), 300)
        self.assertEqual(local_egress.take(25, 100, now=T0 + 48 * 60, whole=True, burst=False), 100)


@mock.patch.dict(os.environ, R2)
class TestsslWeightTests(Clean, TestCase):
    def test_a_testssl_run_counts_its_measured_connections_and_may_exceed_the_burst_alone(self):
        self.assertEqual(local_egress.TESTSSL_CONNECTIONS, 240)
        self.assertEqual(local_egress.take(25, 50, now=T0), 50)
        self.assertIsNone(local_egress.admit_one(25, 'testssl', '198.51.100.1', weight=local_egress.TESTSSL_CONNECTIONS, now=T0, burst=False))
        self.assertEqual(local_egress.used_this_hour(25, now=T0), 290)
        self.assertEqual(local_egress.admit_one(25, 'testssl', '198.51.100.2', weight=local_egress.TESTSSL_CONNECTIONS, now=T0 + 1800,
                                                 burst=False), 'paced')  # 530 would break the hour
        self.assertEqual(local_egress.take(25, 1, now=T0 + 60), 0)  # the run filled this 15 minutes: no nmap probe on 25 beside it
        self.assertEqual(local_egress.take(25, 200, now=T0 + 1800), 100)  # later: the burst limit again, inside what is left of the hour


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:4/hour'})
class FullSweepGovernorTests(Clean, _ScanFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.make_scan(['192.0.2.30'])
        self.ip = IpAddress.objects.get(address='192.0.2.30')
        self.calls = []

    def runner(self, open_ports):
        def run(targets, flags, host_timeout):
            self.calls.append(list(flags))
            return report(*[(t, open_ports) for t in targets])
        return run

    def test_a_drained_budget_sweeps_without_25_and_owes_it(self):
        from cveFeed import fullscan
        local_egress.take(25, 10)
        fullscan.sweep_ip(self.ip, runner=self.runner([80]), fingerprint_runner=self.runner([80]), pipeline=lambda *a: None)
        self.assertIn('25', self.calls[0][self.calls[0].index('--exclude-ports') + 1].split(','))
        self.assertEqual([a for _o, a, _p in local_egress.owed(25)], ['192.0.2.30'])

    def test_a_new_port_25_is_not_fingerprinted_over_budget(self):
        from cveFeed import fullscan
        local_egress.take(25, 10)
        fullscan.investigate(self.ip, [25, 8080], self.project.id, runner=self.runner([25, 8080]), pipeline=lambda *a: None)
        self.assertEqual(self.calls[0][self.calls[0].index('-p') + 1], '8080')
        self.assertEqual([a for _o, a, _p in local_egress.owed(25)], ['192.0.2.30'])


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '6379'})
class OtherInProcessGateTests(Clean, _ScanFixture, TestCase):
    def test_a_database_check_on_a_held_port_is_not_run(self):
        from cveFeed import db_exposure
        self.make_scan(['192.0.2.40'])
        ip = IpAddress.objects.get(address='192.0.2.40')
        ip.ports.add(Port.objects.create(number=6379, service_name='redis', state='open'))
        probe = mock.Mock(return_value=True)
        with mock.patch('targetApp.target_types.is_scannable_ip', return_value=True):
            db_exposure.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
        probe.assert_not_called()

    def test_a_zombie_liveness_probe_on_a_held_port_is_not_sent(self):
        from cveFeed import zombie
        with mock.patch('socket.create_connection') as connect:
            self.assertFalse(zombie.tcp_alive('192.0.2.41', 6379))
        connect.assert_not_called()


class FallbackWindowTests(Clean, TestCase):
    def test_the_fallback_count_is_a_true_60_minute_window(self):
        local_egress.note_fallback('nmap', now=T0 - 1900)  # 61 minutes before the look below: out of the window
        for _ in range(2):
            local_egress.note_fallback('nmap', now=T0 - 1700)
        self.assertEqual(local_egress.fallbacks_last_hour(now=T0 + 1800), 2)


class FloodInvariantTests(Clean, _ScanFixture, TestCase):
    """Randomised: in the local fingerprinting pass the (address, port 25) probes nmap is handed never exceed what the governor charged, across
    naabu answers with and without 25, missing answers, tarpits, chunking, a drained or partial budget, the fallback --top-ports flags and a
    sustained flood (the reviewer's fuzz probe, kept)."""

    def setUp(self):
        super().setUp()
        os.environ['CVENGINE_LOCAL_SKIP_PORTS'] = ''
        import random
        self.rng = random.Random(389)
        self.all = [f'198.51.100.{i + 1}' for i in range(180)]
        self.make_scan(self.all)

    def one_pass(self, flags_fallback):
        calls = []

        def runner(targets, flags, host_timeout):
            calls.append((list(targets), list(flags)))
            return report(*[(t, [80]) for t in targets])
        answer = {}
        for ip in self.all:
            r = self.rng.random()
            if r < 0.15:
                continue
            if r < 0.20:
                answer[ip] = list(range(1, naabu_scan.MAX_OPEN_PER_IP + 5))
            elif r < 0.55:
                answer[ip] = sorted({25, 80, self.rng.randint(1, 9000)})
            else:
                answer[ip] = sorted({80, 443, self.rng.randint(1, 9000)} - {25})
        ServiceRun.objects.all().delete()
        before = local_egress.used_this_hour(25) or 0
        patches = [mock.patch.object(nmap_scan, 'fast_flags', return_value=list(nmap_scan.FAST_FLAGS))] if flags_fallback else []
        for p in patches:
            p.start()
        try:
            nmap_scan.run_nmap_for_scan(self.scan.id, runner=runner, naabu_runner=lambda ips: {i: answer[i] for i in ips if i in answer},
                                        dispatch=False, force=True)
        finally:
            for p in patches:
                p.stop()
        return port25_targets(calls), (local_egress.used_this_hour(25) or 0) - before, calls

    def test_flood(self):
        for budget in (4, 37, 120, 400, 2000):
            with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': f'25:{budget}/hour'}):
                _clear()
                for i in range(4):
                    probed, charged, calls = self.one_pass(flags_fallback=bool(i % 2))
                    self.assertLessEqual(probed, charged, (budget, i))
