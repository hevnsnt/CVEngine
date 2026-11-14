"""The server-side egress safeguard (cveFeed.local_egress): the ledger of this server's own outbound connections, the governor that paces
budgeted ports (25 by default) without dropping work, the cap on local fallback runs, and the opt-in skip list. Sentinels are never affected.

Every test starts and ends with the module's Redis state cleared: the governor's buckets are shared state, and a test that drains one must not
change the command lines of the next."""
import os
import time
from unittest import mock


from cveFeed import local_egress
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

WHOLE_RUN = 240  # connections one whole run is charged: more than the 15-minute quarter (100) of a 400 budget
T0 = 1_900_800_000.0  # a fixed clock on the hour, well clear of the real one (the bucket keys are cleared around every test)
NO_SKIP = {'CVENGINE_LOCAL_SKIP_PORTS': ''}


def _clear():
    getattr(local_egress, '_RESERVED', {}).clear()  # grants made when a pass was planned and not yet started (kept in this process)
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




# --- the ledger -------------------------------------------------------------------------------------------------------------

class LedgerTests(Clean, TestCase):
    def test_counts_by_watched_port_and_in_total(self):
        with local_egress.context(kind='testssl', project=7):
            local_egress.record('testssl', 6, {25: 2})
        local_egress.record_one(25, 'route-probe')
        local_egress.record_one(443, 'route-probe')
        snap = local_egress.snapshot()
        self.assertEqual(snap['hour']['all'], 6 + 1 + 1)
        self.assertEqual(snap['hour']['p25'], 2 + 1)
        self.assertNotIn('p443', snap['hour'])  # not a watched port: in the total only

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


# --- naabu --------------------------------------------------------------------------------------------------------------------

# --- the fallback cap and its warning: gone, with the local fallback they limited ------------------------------------------

class NoFallbackCapTests(SimpleTestCase):
    def test_no_kind_falls_back_to_a_local_run_so_the_cap_the_counter_and_the_warning_are_gone(self):
        for name in ('admit_fallback', 'note_fallback', 'fallback_runs_this_hour', 'fallbacks_last_hour', 'fallback_warning', 'fallback_cap', 'sentinel_trouble',
                     'FALLBACK_WARN_AT', 'FALLBACK_KEY', 'DEFAULT_FALLBACK_NMAP_PER_HOUR', 'DEFAULT_FALLBACK_NAABU_PER_HOUR'):
            self.assertFalse(hasattr(local_egress, name), name)

    def test_the_status_has_no_fallback_figures_and_adds_no_fallback_problem(self):
        problems = []
        out = local_egress.status(problems)
        self.assertNotIn('fallbacks_last_hour', out)
        self.assertNotIn('fallback_caps_per_hour', out)
        self.assertEqual([p for p in problems if 'fell back' in p], [])


# --- Sentinels are never paced ----------------------------------------------------------------------------------------------

# --- the configMaxxing card ----------------------------------------------------------------------------------------------------

class TunableTests(Clean, SimpleTestCase):
    def test_the_defaults_equal_the_module_constants(self):
        from cveFeed import tunables
        self.assertEqual(tunables.BY_KEY['egress_port25_per_hour'].default, local_egress.DEFAULT_PORT25_PER_HOUR)
        self.assertEqual(local_egress.parse_budgets(local_egress.DEFAULT_BUDGETS)[25], local_egress.DEFAULT_PORT25_PER_HOUR)
        self.assertNotIn('fallback_nmap_per_hour', tunables.BY_KEY)  # the local fallback caps went with the local fallback
        self.assertNotIn('fallback_naabu_per_hour', tunables.BY_KEY)
        self.assertFalse(tunables.BY_KEY['egress_port25_per_hour'].auto_tunable)


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
        with local_egress.context(kind='nmap', project=project.id, scan_id=9):  # the source of every record below
            local_egress.log_connections(['198.51.100.1', '198.51.100.2'], [25, 465, 587], mode=local_egress.ESTIMATED)  # an external tool: estimated
            local_egress.log_connections(['198.51.100.3'], [25], outcome=local_egress.PACED)  # one the budget held back
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

    def test_a_whole_run_is_charged_for_the_connections_it_opens(self):
        self.assertGreater(WHOLE_RUN, 1)
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': f'25:{WHOLE_RUN * 4}/hour'}):
            self.assertIsNone(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=WHOLE_RUN))
            self.assertEqual(local_egress.used_this_hour(25), WHOLE_RUN)
            self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.2', weight=WHOLE_RUN), 'paced')
            self.assertEqual(local_egress.used_this_hour(25), WHOLE_RUN)  # all or nothing: a paced run takes no token


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


class HermeticTests(SimpleTestCase):
    def test_the_test_runner_turns_pacing_off_outside_these_tests(self):
        self.assertEqual(os.environ.get('CVENGINE_LOCAL_PORT_BUDGETS'), '')
        self.assertEqual(local_egress.budgets(), {})


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
class WindowTests(Clean, TestCase):
    def test_61_minute_buckets_are_needed(self):
        with mock.patch.object(local_egress, 'BURST_SHARE', 1):  # the hour alone: the 15-minute share set to the whole budget
            got = [(s, local_egress.take(25, 100, now=T0 + s)) for s in (59, 960, 1860, 2760, 3600)]
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
class WholeRunWeightTests(Clean, TestCase):
    def test_a_whole_run_counts_its_connections_and_may_exceed_the_burst_alone(self):
        self.assertEqual(local_egress.take(25, 50, now=T0), 50)
        # 240 is more than the 15-minute share (100): the run needs its 15 minutes to itself, so not beside the 50 just granted
        self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=WHOLE_RUN, now=T0, burst=False),
                         'paced')
        self.assertIsNone(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=WHOLE_RUN, now=T0 + 16 * 60,
                                                 burst=False))
        self.assertEqual(local_egress.used_this_hour(25, now=T0), 290)
        self.assertEqual(local_egress.take(25, 1, now=T0 + 17 * 60), 0)  # the run fills its 15 minutes: no nmap probe on 25 beside it
        self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.2', weight=WHOLE_RUN, now=T0 + 40 * 60,
                                                 burst=False), 'paced')  # 530 would break the 60 minutes
        self.assertEqual(local_egress.take(25, 200, now=T0 + 40 * 60), 100)  # later: the 15-minute share again, inside what is left of the hour


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

# --- round 2 of the #389 review, completed: the stated limits, exactly ------------------------------------------------------------

def _grant_log(port=25):
    """``[(minute, granted, alone)]`` of every grant the governor made through ``take`` while the patch is active."""
    out = []
    real = local_egress.take

    def counting(p, want, now=None, whole=False, burst=True):
        got = real(p, want, now=now, whole=whole, burst=burst)
        if int(p) == port and got:
            out.append((int(now // 60), got, not burst and want > local_egress.bucket_size(local_egress.budgets()[port])))
        return got
    return out, mock.patch.object(local_egress, 'take', side_effect=counting)


@mock.patch.dict(os.environ, {'CVENGINE_LOCAL_SKIP_PORTS': '', 'CVENGINE_LOCAL_PORT_BUDGETS': '25:800/hour'})
class StatedLimitsInvariantTests(Clean, TestCase):
    """Randomised over eight hours of asks from many callers (nmap chunks, single probes, whole runs) at random times:
    every 61 consecutive minute buckets (any 60 minutes) hold at most the hourly budget, and every 16 (any 15 minutes) hold at most a quarter
    of it, or one whole run and nothing else."""

    def test_any_60_minutes_and_any_15_minutes(self):
        import random
        rng = random.Random(3893)
        grants, patcher = _grant_log()
        with patcher:
            dense = [T0 + rng.uniform(0, 2 * 3600) for _ in range(900)]  # a busy stretch, then a quiet one with gaps a whole run fits in
            quiet = [T0 + 2 * 3600 + rng.uniform(0, 6 * 3600) for _ in range(60)]
            for at in sorted(dense + quiet):  # the Redis clock only moves forward
                r = rng.random()
                if r < (0.05 if at < T0 + 2 * 3600 else 0.4):
                    local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=WHOLE_RUN, now=at, burst=False)
                elif r < 0.25:
                    local_egress.admit_one(25, 'nmap', '198.51.100.2', weight=25, now=at)
                elif r < 0.6:
                    local_egress.take(25, rng.randint(1, 64), now=at)
                else:
                    local_egress.admit_one(25, 'nmap', '198.51.100.3', now=at)
        by_minute = {}
        for minute, got, alone in grants:
            by_minute.setdefault(minute, []).append((got, alone))
        self.assertTrue(any(alone for _m, _g, alone in grants))  # the case under test happened
        first, last = min(by_minute), max(by_minute)
        for start in range(first - 60, last + 1):
            hour = [g for m in range(start, start + 61) for g in by_minute.get(m, ())]
            self.assertLessEqual(sum(got for got, _a in hour), 800, start)
            quarter = [g for m in range(start, start + 16) for g in by_minute.get(m, ())]
            if any(alone for _g, alone in quarter):
                self.assertEqual(len(quarter), 1, (start, quarter))  # one whole run, alone in its 15 minutes
                self.assertEqual(quarter[0][0], WHOLE_RUN)
            else:
                self.assertLessEqual(sum(got for got, _a in quarter), 200, start)

    def test_a_burst_spaced_841_seconds_is_still_one_15_minutes(self):
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:400/hour'}):
            self.assertEqual(local_egress.take(25, 100, now=T0 + 59), 100)
            self.assertEqual(local_egress.take(25, 100, now=T0 + 900), 0)  # 841 s later: inside the same 15 minutes
            self.assertEqual(local_egress.take(25, 100, now=T0 + 960), 100)  # 901 s later: a new 15 minutes

    def test_a_partial_grant_is_never_made_for_a_whole_run(self):
        self.assertEqual(local_egress.take(25, 150, now=T0), 150)
        self.assertEqual(local_egress.take(25, 60, now=T0, whole=True), 0)  # 50 left of the share: a whole ask of 60 gets nothing
        self.assertEqual(local_egress.take(25, 60, now=T0), 50)  # a divisible ask takes what is left
        self.assertEqual(local_egress.used_this_hour(25, now=T0), 200)

    def test_a_large_budget_holds_a_whole_run_to_the_ordinary_share(self):
        with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_PORT_BUDGETS': '25:2000/hour'}):  # share 500: 240 fits in it, no run alone
            self.assertEqual(local_egress.take(25, 200, now=T0), 200)
            self.assertIsNone(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=240, now=T0, burst=False))  # beside it: 440
            self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.2', weight=240, now=T0, burst=False), 'paced')  # 680 > 500


@mock.patch.dict(os.environ, R2)
class SentOnlyOnceStartedTests(Clean, TestCase):
    """A run refused at its memory wait sent nothing: no 'sent' record and no ledger count (its grant stays spent: over-charging is the
    safe side of the cap)."""

    def test_heavy_process_calls_on_start_only_once_admitted(self):
        from cveFeed import heavy_process
        from reNgine.resources import MemoryBusy
        started = mock.Mock()
        with mock.patch('reNgine.resources.heavy_job', side_effect=MemoryBusy('no memory')):
            with self.assertRaises(MemoryBusy):
                heavy_process.run('whole-run', ['/bin/true'], 5, on_start=started)
        started.assert_not_called()
        order = []
        with mock.patch('reNgine.resources.heavy_job', return_value=_Job()), \
                mock.patch.object(heavy_process.subprocess, 'Popen', side_effect=lambda *a, **k: order.append('popen') or mock.Mock(
                    communicate=mock.Mock(return_value=('', '')), returncode=0)):
            heavy_process.run('whole-run', ['/bin/true'], 5, on_start=lambda: order.append('on_start'))
        self.assertEqual(order, ['on_start', 'popen'])


# --- charged when a process starts, after its memory wait (coordinator follow-up to #393) -------------------------------------------

def _window(port=25):
    return {int(k): int(v) for k, v in (local_egress._client().hgetall(f'{local_egress.PREFIX}:window:{port}') or {}).items()}


# --- round 3 of the review (#393): no in-scope port 25 is dropped for good ------------------------------------------------------------

@mock.patch.dict(os.environ, R2)
class WholeRunPriorityTests(Clean, TestCase):
    """A whole run on port 25 larger than the 15-minute quarter needs a quiet 15 minutes. One that has waited ALONE_PRIORITY_AFTER (60 minutes)
    gets priority: ordinary port-25 grants are held (paced) until it starts."""

    def test_priority_lapses_when_the_run_stops_waiting(self):
        local_egress.take(25, 1, now=T0)
        self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=240, burst=False, now=T0), 'paced')
        self.assertEqual(local_egress.take(25, 1, now=T0 + 2400), 1)  # ordinary grants still go while the run has waited under an hour
        self.assertEqual(local_egress.admit_one(25, 'whole-run', '198.51.100.1', weight=240, burst=False, now=T0 + 3600 - 60 * 15), 'paced')
        self.assertEqual(local_egress.take(25, 1, now=T0 + 3600), 0)  # waited 60 minutes: ordinary grants are held
        local_egress._client().delete(f'{local_egress.PREFIX}:alone-waiting:25')  # the run gave up (its marker expired)
        self.assertEqual(local_egress.take(25, 1, now=T0 + 3660), 1)


class PathProbeScopeTests(TestCase):
    """Security review 1.3.4 (ssrf-1): the daily raw-packet path probe picks addresses from fingerprints of every organization; it must only
    send to one some project may still have probed."""

    def setUp(self):
        self.org = Org.objects.create(name='P', slug='pp-org')
        self.project = Project.objects.create(name='P', slug='pp-p', insert_date=timezone.now(), org=self.org)

    def held(self, name, address, mode='standard'):
        domain = Domain.objects.create(name=name, project=self.project, insert_date=timezone.now(), discovery_mode=mode)
        sub = Subdomain.objects.create(target_domain=domain, name=f'www.{name}')
        sub.ip_addresses.add(IpAddress.objects.create(address=address))
        return sub

    def test_only_an_address_a_project_may_still_probe(self):
        from cveFeed import path_probe
        from cveFeed.models import HostExclusion
        self.held('ok.test', '198.51.100.20')
        self.held('manual.test', '198.51.100.21', mode='manual')
        self.held('passive.test', '198.51.100.22', mode='passive')
        self.held('gone.test', '198.51.100.23')
        HostExclusion.objects.create(org=self.org, host='198.51.100.23', created_at=timezone.now())
        IpAddress.objects.create(address='198.51.100.24')  # fingerprinted once, now on no host of any project
        self.assertTrue(path_probe.in_scope('198.51.100.20'))
        for address in ('198.51.100.21', '198.51.100.22', '198.51.100.23', '198.51.100.24'):
            self.assertFalse(path_probe.in_scope(address), address)
