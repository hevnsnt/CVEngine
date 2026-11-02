"""The internal flag on hosts, findings and the stats, and the filter that goes with it."""
import os
from datetime import timedelta
from unittest import mock

from django.test import Client
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed import internal_view
from cveFeed.models import InternalRange
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_internal_ranges import World
from tests.test_sentinels import reset_rates


class ViewBase(World):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        internal_view.invalidate()
        self.addCleanup(internal_view.invalidate)
        InternalRange.objects.create(project=self.pa, cidr='10.20.0.0/24', description='Head office')
        now = timezone.now()
        engine = EngineType.objects.create(engine_name='e-iv', yaml_configuration='x', default_engine=True)
        self.inside = Domain.objects.create(name='10.20.0.7', project=self.pa, insert_date=now)
        self.outside = Domain.objects.create(name='203.0.113.7', project=self.pa, insert_date=now)
        self.scan_in = ScanHistory.objects.create(domain=self.inside, scan_type=engine, start_scan_date=now - timedelta(days=1), scan_status=2,
                                                  results_dir='/tmp', tasks=['internal_pipeline'])
        self.scan_out = ScanHistory.objects.create(domain=self.outside, scan_type=engine, start_scan_date=now, scan_status=2, results_dir='/tmp', tasks=[])
        self.sub_in = Subdomain.objects.create(scan_history=self.scan_in, target_domain=self.inside, name='10.20.0.7')
        self.sub_out = Subdomain.objects.create(scan_history=self.scan_out, target_domain=self.outside, name='203.0.113.7')
        for sub, addr in ((self.sub_in, '10.20.0.7'), (self.sub_out, '203.0.113.7')):
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=addr)[0])
        for scan, sub, domain in ((self.scan_in, self.sub_in, self.inside), (self.scan_out, self.sub_out, self.outside)):
            Vulnerability.objects.create(scan_history=scan, target_domain=domain, subdomain=sub, name=f'Finding on {sub.name}', severity=3,
                                         http_url=f'https://{sub.name}/', open_status=True)

    def get(self, path, token='admin'):
        status, out = call(self.t[token], 'GET', path)
        self.assertEqual(status, 200, out)
        return out


class FlagTests(ViewBase):
    def test_a_host_inside_a_declared_range_is_flagged_with_its_network(self):
        rows = {r['host']: r for r in self.get('/api/v1/projects/ir-a/hosts')['results']}
        self.assertEqual((rows['10.20.0.7']['internal'], rows['10.20.0.7']['network']), (True, '10.20.0.0/24'))
        self.assertEqual((rows['203.0.113.7']['internal'], rows['203.0.113.7']['network']), (False, None))

    def test_the_internal_filter_keeps_or_drops_them(self):
        only = self.get('/api/v1/projects/ir-a/hosts?internal=1')
        self.assertEqual([r['host'] for r in only['results']], ['10.20.0.7'])
        rest = self.get('/api/v1/projects/ir-a/hosts?internal=0')
        self.assertEqual([r['host'] for r in rest['results']], ['203.0.113.7'])
        self.assertEqual(len(self.get('/api/v1/projects/ir-a/hosts')['results']), 2)

    def test_scanner_findings_carry_the_flag_and_the_filter(self):
        rows = {r['host']: r for r in self.get('/api/v1/projects/ir-a/vulnerabilities')['results']}
        self.assertTrue(rows['10.20.0.7']['internal'])
        self.assertFalse(rows['203.0.113.7']['internal'])
        self.assertEqual([r['host'] for r in self.get('/api/v1/projects/ir-a/vulnerabilities?internal=1')['results']], ['10.20.0.7'])
        self.assertEqual([r['host'] for r in self.get('/api/v1/projects/ir-a/vulnerabilities?internal=0')['results']], ['203.0.113.7'])

    def test_the_unified_findings_list_flags_and_filters_too(self):
        out = self.get('/api/v1/projects/ir-a/findings?type=scanner')
        self.assertEqual({r['host']: r['internal'] for r in out['results']}, {'10.20.0.7': True, '203.0.113.7': False})
        only = self.get('/api/v1/projects/ir-a/findings?type=scanner&internal=1')
        self.assertEqual([r['host'] for r in only['results']], ['10.20.0.7'])
        rest = self.get('/api/v1/projects/ir-a/findings?internal=0')
        self.assertNotIn('10.20.0.7', [r['host'] for r in rest['results']])

    def test_without_a_declared_range_nothing_is_internal_and_the_filter_matches_nothing(self):
        InternalRange.objects.all().delete()
        internal_view.invalidate()
        rows = self.get('/api/v1/projects/ir-a/hosts')['results']
        self.assertFalse(any(r['internal'] for r in rows))
        self.assertEqual(self.get('/api/v1/projects/ir-a/hosts?internal=1')['results'], [])

    def test_another_projects_range_does_not_flag_this_projects_host(self):
        InternalRange.objects.all().delete()
        InternalRange.objects.create(project=self.pb, cidr='10.20.0.0/24')
        internal_view.invalidate()
        self.assertFalse(any(r['internal'] for r in self.get('/api/v1/projects/ir-a/hosts', 'root')['results']))

    def test_with_the_operator_allowing_private_targets_nothing_is_sentinel_only(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
            internal_view.invalidate()
            self.assertFalse(internal_view.is_internal(self.pa.id, '10.20.0.7'))


class StatsTests(ViewBase):
    def setUp(self):
        super().setUp()
        from cveFeed import views
        views.clear_stats_cache()  # the payload is cached for a short while per user
        self.addCleanup(views.clear_stats_cache)

    def stats(self, project=''):
        from cveFeed import views
        views.clear_stats_cache()
        client = Client()
        client.force_login(self.admin)
        return client.get('/cve/api/stats', {'project': project} if project else {}).json()

    def sentinel(self, capabilities, last_seen=True):
        token = create_token(self.root, f'iv-{"-".join(capabilities)}')[1]
        reset_rates({'t': token})
        status, out = call(token, 'PUT', '/api/v1/sentinel', {'name': 'iv-sentinel', 'scope': {'projects': ['ir-a']}, 'capabilities': capabilities})
        self.assertIn(status, (200, 201), out)
        Agent.objects.filter(pk=out['id']).update(status='active', last_seen=timezone.now() if last_seen else None,
                                                  network='internal' if 'network:internal' in capabilities else 'external')

    def test_the_internal_object_lists_the_networks_and_the_internal_share(self):
        internal = self.stats()['internal']
        self.assertTrue(internal['has'])
        self.assertEqual((internal['hosts'], internal['hosts_live'], internal['findings']), (1, 1, 1))
        net = internal['networks'][0]
        self.assertEqual((net['project'], net['cidr'], net['description'], net['hosts']), ('ir-a', '10.20.0.0/24', 'Head office', 1))
        self.assertIsNotNone(net['last_scan_at'])
        self.assertEqual(self.stats()['hosts'], 2)  # the headline totals still include internal hosts

    def test_the_sentinel_state_of_a_network_is_none_offline_or_online(self):
        self.assertEqual(self.stats()['internal']['networks'][0]['sentinel']['state'], 'none')
        self.sentinel(['nmap'])  # an outside Sentinel does not count
        self.assertEqual(self.stats()['internal']['networks'][0]['sentinel']['state'], 'none')
        Agent.objects.all().delete()
        self.sentinel(['nmap', 'network:internal'], last_seen=False)
        self.assertEqual(self.stats()['internal']['networks'][0]['sentinel']['state'], 'offline')
        Agent.objects.all().delete()
        self.sentinel(['nmap', 'network:internal'])
        state = self.stats()['internal']
        self.assertEqual((state['networks'][0]['sentinel']['state'], state['sentinels_online']), ('online', 1))

    def test_no_declared_network_means_the_group_is_absent(self):
        InternalRange.objects.all().delete()
        internal_view.invalidate()
        out = self.stats()['internal']
        self.assertEqual((out['has'], out['networks'], out['hosts']), (False, [], 0))

    def test_a_user_of_another_organization_sees_none_of_it(self):
        client = Client()
        client.force_login(self.other)
        out = client.get('/cve/api/stats').json()['internal']
        self.assertFalse(out['has'])


class GraphTests(ViewBase):
    def test_graph_nodes_say_which_hosts_are_internal(self):
        client = Client()
        client.force_login(self.admin)
        nodes = {n['label']: n for n in client.get('/cve/api/graph').json()['nodes'] if n['kind'] == 'subdomain'}
        self.assertEqual((nodes['10.20.0.7']['internal'], nodes['10.20.0.7']['network']), (True, '10.20.0.0/24'))
        self.assertFalse(nodes['203.0.113.7']['internal'])


class SearchTests(ViewBase):
    def test_the_host_search_takes_the_scope_filter_and_says_whether_to_offer_it(self):
        out = self.get('/api/v1/projects/ir-a/search?internal=1')
        self.assertEqual([h['host'] for h in out['results']], ['10.20.0.7'])
        self.assertTrue(out['has_internal'])
        self.assertEqual([h['host'] for h in self.get('/api/v1/projects/ir-a/search?internal=0')['results']], ['203.0.113.7'])
        InternalRange.objects.all().delete()
        internal_view.invalidate()
        self.assertFalse(self.get('/api/v1/projects/ir-a/search')['has_internal'])

    def test_a_user_of_another_organization_is_not_offered_the_filter(self):
        self.assertFalse(self.get('/api/v1/projects/ir-b/search', 'other')['has_internal'])


class CacheInvalidationTests(World):
    """The table that says which hosts are internal is dropped when what it is built from changes, so a page never waits on a timer for it."""

    def setUp(self):
        internal_view.invalidate()
        self.addCleanup(internal_view.invalidate)

    def test_declaring_or_removing_a_range_drops_it(self):
        internal_view.table()
        self.assertIsNotNone(internal_view._cache['at'])
        row = self.declare()
        self.assertIsNone(internal_view._cache['at'])
        internal_view.table()
        row.delete()
        self.assertIsNone(internal_view._cache['at'])

    def test_adding_a_host_named_by_an_address_drops_it_and_a_named_host_does_not(self):
        self.declare()
        Domain.objects.create(name='10.20.0.5', project=self.pa, insert_date=timezone.now())
        self.assertIsNone(internal_view._cache['at'])
        self.assertTrue(internal_view.is_internal(self.pa.id, '10.20.0.5'))
        Domain.objects.create(name='www.example.test', project=self.pa, insert_date=timezone.now())
        self.assertIsNotNone(internal_view._cache['at'])  # a name that is not an address changes nothing about it

    def test_a_machine_up_for_less_than_the_cache_time_still_builds_the_table(self):
        """The monotonic clock starts at boot: a fresh table must build whatever it reads, not wait for 300 seconds of uptime."""
        self.declare()
        internal_view.invalidate()
        Domain.objects.create(name='10.20.0.5', project=self.pa, insert_date=timezone.now())
        with mock.patch('time.monotonic', return_value=12.0):
            self.assertTrue(internal_view.is_internal(self.pa.id, '10.20.0.5'))

    def test_the_table_is_not_rebuilt_by_the_clock_inside_a_few_minutes(self):
        internal_view.table()
        built = internal_view._cache['at']
        with mock.patch('time.monotonic', return_value=built + 120):
            internal_view.table()
        self.assertEqual(internal_view._cache['at'], built)
