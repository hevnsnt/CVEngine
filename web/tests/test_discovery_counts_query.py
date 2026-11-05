"""The live ticker's three counts (hosts, addresses, open ports) after the query rewrite, and the snapshot cache's stale keep.

``views.discovery_counts`` used to be three nested queries that each repeated the whole host walk; it reads the live hosts once and looks the
addresses and ports up through the link tables. The old expression stays here as the oracle: both must give the same three numbers on data with
a shared address, a shared port, a closed port, an address no live host holds and a host that is not live."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import snapshot_cache, views
from cveFeed.counts import LIVE_HOST_Q, host_reps
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import OPEN_PORT_STATES, IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain


def old_discovery_counts():
    live_subs = host_reps().filter(LIVE_HOST_Q).distinct()
    ips = IpAddress.objects.filter(ip_addresses__in=live_subs).distinct()
    return {'hosts': live_subs.count(), 'ips': ips.count(), 'ports': Port.objects.filter(ports__in=ips, state__in=OPEN_PORT_STATES).distinct().count()}


class DiscoveryCountsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Org DC', slug='org-dc')
        project = Project.objects.create(name='DC', slug='dc-project', insert_date=now, org=org)
        engine = EngineType.objects.create(engine_name='dc-engine', yaml_configuration='x', default_engine=True)
        domain = Domain.objects.create(name='dc.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now - timedelta(hours=2),
                                          stop_scan_date=now - timedelta(hours=1))

        def host(name, http=0):
            return Subdomain.objects.create(name=f'{name}.dc.example.test', target_domain=domain, scan_history=scan, http_status=http)

        ip = {k: IpAddress.objects.create(address=f'192.0.2.{n}') for k, n in zip('ABCDE', (1, 2, 3, 4, 5))}
        p22, p80, p443 = (Port.objects.create(number=n, state='open') for n in (22, 80, 443))
        closed = Port.objects.create(number=8080, state='closed')
        p3306 = Port.objects.create(number=3306, state='open')
        ip['A'].ports.add(p22, p80, closed)
        ip['B'].ports.add(p22)  # the same port row on a second address: one port
        ip['C'].ports.add(p443)
        ip['E'].ports.add(p3306)  # an address no live host holds: its port is not counted
        h1 = host('one', http=200)
        h1.ip_addresses.add(ip['A'], ip['B'])
        host('two').ip_addresses.add(ip['C'])  # live by its address alone
        host('three')  # no address and no HTTP answer: not live
        host('four').ip_addresses.add(ip['D'])  # live, an address with no ports

    def test_the_counts_are_what_the_data_says(self):
        self.assertEqual(views.discovery_counts(), {'hosts': 3, 'ips': 4, 'ports': 3})

    def test_the_new_query_gives_the_old_numbers(self):
        self.assertEqual(views.discovery_counts(), old_discovery_counts())

    def test_a_long_list_is_looked_up_in_chunks_with_the_same_answer(self):
        with mock.patch.object(views, '_COUNT_CHUNK', 1):
            self.assertEqual(views.discovery_counts(), {'hosts': 3, 'ips': 4, 'ports': 3})

    def test_no_live_hosts_is_three_zeros(self):
        Subdomain.objects.all().delete()
        self.assertEqual(views.discovery_counts(), {'hosts': 0, 'ips': 0, 'ports': 0})


class StaleKeepTests(SimpleTestCase):
    """A count that takes longer than three freshness windows to compute must not leave its key empty: an empty key sends every request that
    finds it to compute the count itself, all at once."""

    def setUp(self):
        self.scope = 'stale-keep-scope'
        self.key = f'cve:snap:stats:{self.scope}'
        self.addCleanup(cache.delete_many, [self.key, f'{self.key}:lock'])

    def test_a_stored_snapshot_is_kept_for_minutes_not_three_windows(self):
        stored = []
        real_set = cache.set
        with mock.patch.object(snapshot_cache.cache, 'set', side_effect=lambda key, value, timeout=None: (stored.append((key, timeout)), real_set(key, value, timeout))[1]):
            snapshot_cache.snapshot('stats', self.scope, lambda: {'n': 1}, 10)
        self.assertIn((self.key, snapshot_cache.STALE_KEEP_SECONDS), stored)
        self.assertGreaterEqual(snapshot_cache.STALE_KEEP_SECONDS, 300)

    def test_an_old_snapshot_is_served_while_one_request_recomputes(self):
        cache.set(self.key, {'payload': {'n': 1}, 'etag': 'e', 'at': snapshot_cache._now() - 120, 'rev': snapshot_cache.revision()}, 600)
        cache.add(f'{self.key}:lock', 1, 30)  # another request is already computing
        compute = mock.Mock(return_value={'n': 2})
        entry = snapshot_cache.snapshot('stats', self.scope, compute, 10)
        self.assertEqual(entry['payload'], {'n': 1}, 'the old copy answers; this request does not start a second computation')
        compute.assert_not_called()
