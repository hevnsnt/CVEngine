"""The work planner at the owner's shape: 15 projects, about 3,000 hosts, two Sentinels (3 and 5 slots), a cold estate (no SSH or secrets check ever ran).

A tick is the once-a-minute part: it must cost under a second and a number of queries that does not grow with the hosts (it reads the cached census; the
census, a pass over every host, is its own task every five minutes and has its own, looser budget)."""
import cProfile
import io
import pstats
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import sentinel_contract
from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import work_planner
from cveFeed.models import PlannerBatch, RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

SHAPE = (600, 520, 420, 300, 250, 200, 150, 120, 100, 80, 60, 60, 50, 30, 10)  # hosts per project: 15 projects, 2,950 hosts
TICK_SECONDS = 1.0
TICK_QUERIES = 150
CENSUS_SECONDS = 60.0  # the census runs in a worker every five minutes: about 1.4 s on a quiet laptop, 12 s on a loaded one; the query count below is the stable bound
# Both budgets are CPU seconds of this process (time.process_time), not wall seconds. CI runs the suite with parallel workers against one Postgres on a runner
# that ran out of memory once ('10 MB free'): the same census then took 445.8 s of wall time, of which 439 s was spent waiting inside psycopg2 and the Python side
# cost about 6 s. A starved box stretches the wait, not the work; a real regression (a query per host, a pass that grows with the hosts) is caught by the query
# count bounds and by the CPU seconds. The wall time is printed so a slow run is still visible in the log.
CENSUS_QUERIES = 600


def build(hosts_per_project, now, tag='p', offset=0):
    org, _ = Org.objects.get_or_create(slug='load', defaults={'name': 'Load'})
    engine, _ = EngineType.objects.get_or_create(engine_name='e', defaults={'yaml_configuration': 'x', 'default_engine': True})
    n = 0
    through_ip = Subdomain.ip_addresses.through
    through_port = IpAddress.ports.through
    for index, count in enumerate(hosts_per_project):
        project = Project.objects.create(name=f'{tag}{index}', slug=f'{tag}{index}', org=org, insert_date=now)
        domain = Domain.objects.create(name=f'{tag}{index}.example', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, start_scan_date=now, scan_status=2, tasks=[], results_dir='x', scan_type=engine)
        subs = [Subdomain(name=f'h{i}.{tag}{index}.example', target_domain=domain, scan_history=scan) for i in range(count)]
        Subdomain.objects.bulk_create(subs)
        ips = [IpAddress(address=f'2001:db8:{offset + index:x}::{i + 1:x}') for i in range(count)]
        IpAddress.objects.bulk_create(ips)
        subs = list(Subdomain.objects.filter(scan_history=scan).order_by('id'))
        ips = list(IpAddress.objects.filter(address__startswith=f'2001:db8:{offset + index:x}::').order_by('id'))
        ports = []
        for i, ip in enumerate(ips):
            if i % 3 == 0:
                ports.append((ip, Port(number=22, service_name='ssh', state='open')))
            ports.append((ip, Port(number=443, service_name='https', state='open')))
        Port.objects.bulk_create([p for _ip, p in ports])
        through_ip.objects.bulk_create([through_ip(subdomain_id=s.pk, ipaddress_id=ip.pk) for s, ip in zip(subs, ips)])
        through_port.objects.bulk_create([through_port(ipaddress_id=ip.pk, port_id=p.pk) for ip, p in ports])
        RouteAuth.objects.bulk_create([RouteAuth(project=project, domain=domain, host=s.name, url=f'https://{s.name}/', path='/', auth_state='open', http_status=200,
                                                 content_type='text/html') for s in subs[: count * 8 // 10]])
        n += count
    # Rows added with bulk_create inside the test transaction have no planner statistics: Postgres plans the census joins as if the tables were empty
    # (nested loops over thousands of rows: 937 s locally, 445 s once in CI). ANALYZE is allowed in a transaction and gives it real numbers (6 s).
    with connection.cursor() as cursor:
        cursor.execute('ANALYZE')
    return n


class LoadTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        for key in (work_planner.CENSUS_KEY, work_planner.LAST_KEY, work_planner.LOCK_KEY, work_planner.CURSOR_KEY):
            cache.delete(key)
        mock.patch('cveFeed.scan_control.pause_requested', return_value=False).start()
        self.sent = mock.patch('cveFeed.tasks.work_planner_batch.apply_async').start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: [cache.delete(k) for k in (work_planner.CENSUS_KEY, work_planner.LAST_KEY, work_planner.LOCK_KEY, work_planner.CURSOR_KEY)])
        user = User.objects.create_user('load-owner', password='x')
        for slots in (3, 5):
            token, _raw = create_token(user, f'load-{slots}')
            Agent.objects.create(token=token, name=f'load-{slots}', kind='scanner', status='active', max_concurrent=slots, capabilities=['ssh_probe', 'secrets_scan'],
                                 last_seen=timezone.now(), info={'contract_version': sentinel_contract.version()}, scope={'instance': True})

    def measure(self):
        profile = cProfile.Profile()
        with CaptureQueriesContext(connection) as census_queries:
            started, wall = time.process_time(), time.monotonic()
            profile.enable()
            data = work_planner.census(self.now)
            profile.disable()
            census_seconds, census_wall = time.process_time() - started, time.monotonic() - wall
        out = io.StringIO()
        pstats.Stats(profile, stream=out).sort_stats('cumulative').print_stats(25)
        self.census_profile = out.getvalue()
        cache.delete(work_planner.LOCK_KEY)
        with CaptureQueriesContext(connection) as tick_queries:
            started, wall = time.process_time(), time.monotonic()
            out = work_planner.run(self.now)
            tick_seconds, tick_wall = time.process_time() - started, time.monotonic() - wall
        return data, out, (census_seconds, len(census_queries), census_wall), (tick_seconds, len(tick_queries), tick_wall)

    def test_a_tick_at_the_owners_shape_costs_under_a_second_and_a_bounded_number_of_queries(self):
        hosts = build(SHAPE, self.now)
        self.assertEqual(hosts, 2950)
        data, out, census, tick = self.measure()
        due_ssh = sum(e['kinds']['ssh_probe']['due'] for e in data['projects'].values())
        due_web = sum(e['kinds']['secrets_scan']['due'] for e in data['projects'].values())
        self.assertEqual(due_ssh, sum(-(-c // 3) for c in SHAPE))  # a third of the hosts have SSH open, none was ever inspected
        self.assertEqual(due_web, hosts)
        self.assertEqual(out['state'], 'queued')
        self.assertEqual(out['batches'], 12)  # the per-run ceiling: a backlog of thousands fills the queue over several runs
        self.assertLess(tick[0], TICK_SECONDS, f'a tick took {tick[0]:.2f} CPU s ({tick[2]:.2f} s wall)')
        self.assertLessEqual(tick[1], TICK_QUERIES, f'a tick ran {tick[1]} queries')
        self.assertLess(census[0], CENSUS_SECONDS, f'the census took {census[0]:.2f} CPU s ({census[2]:.2f} s wall)\n{self.census_profile}')
        self.assertLessEqual(census[1], CENSUS_QUERIES, f'the census ran {census[1]} queries')
        # one batch is one task of at most 25 units, and the projects take turns inside each kind: 6 batches of a kind reach 6 projects, not one
        for kind in ('ssh_probe', 'secrets_scan'):
            self.assertEqual(len({b.project_id for b in PlannerBatch.objects.filter(kind=kind)}), PlannerBatch.objects.filter(kind=kind).count(), kind)
        self.assertLessEqual(max(len(b.units) for b in PlannerBatch.objects.all()), 25)
        print(f'\nplanner load: census {census[0]:.2f} CPU s ({census[2]:.2f} s wall) {census[1]} queries; tick {tick[0]:.3f} CPU s ({tick[2]:.3f} s wall) {tick[1]} queries; due ssh {due_ssh}, web reads {due_web}')

    def test_the_queries_of_a_tick_do_not_grow_with_the_hosts(self):
        build((60,) * 15, self.now)
        _data, _out, _c, small = self.measure()
        PlannerBatch.objects.all().delete()
        build((200,) * 15, self.now, tag='q', offset=64)  # three times the hosts
        _data, _out, _c, big = self.measure()
        self.assertLessEqual(big[1], small[1] + 12, f'{small[1]} queries at 900 hosts, {big[1]} at 3,900')
