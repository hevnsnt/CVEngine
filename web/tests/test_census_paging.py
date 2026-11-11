"""The work planner's census reads a project's hosts a page at a time (review finding A15, the port-rows class of incident).

It used to load every host of a project with all its addresses and ports into one list before its page loop (``list(Subdomain...prefetch_related(
'ip_addresses__ports', 'technologies'))``): memory grew with hosts x ports, not with the page. At 1,000 hosts with 20 ports each that is 20,000 port
objects at once; a project of 50,000 hosts would bring back the 1.3 GB census of the port-flood incident. Now a page of hosts and its ports are read,
checked and let go before the next.
"""
import gc
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import check_coverage, work_planner
from cveFeed.models import RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

HOSTS, PORTS = 1000, 20


class CensusPagingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Pg', slug='pg-org')
        engine = EngineType.objects.create(engine_name='pg-engine', yaml_configuration='x', default_engine=True)
        cls.project = Project.objects.create(name='Pg', slug='pg-proj', org=org, insert_date=now)
        cls.domain = Domain.objects.create(name='pg.example.com', project=cls.project, insert_date=now)
        scan = ScanHistory.objects.create(domain=cls.domain, start_scan_date=now, scan_status=2, tasks=[], results_dir='x', scan_type=engine)
        Subdomain.objects.bulk_create([Subdomain(name=f'h{i}.pg.example.com', target_domain=cls.domain, scan_history=scan) for i in range(HOSTS)])
        subs = list(Subdomain.objects.filter(scan_history=scan).order_by('id'))
        IpAddress.objects.bulk_create([IpAddress(address=f'2001:db8:9::{i + 1:x}') for i in range(HOSTS)])
        ips = list(IpAddress.objects.filter(address__startswith='2001:db8:9::').order_by('id'))
        ports = [(ip, Port(number=1000 + n, service_name='http' if n == 0 else 'x', state='open')) for ip in ips for n in range(PORTS)]
        Port.objects.bulk_create([p for _ip, p in ports])
        through_ip, through_port = Subdomain.ip_addresses.through, IpAddress.ports.through
        through_ip.objects.bulk_create([through_ip(subdomain_id=s.pk, ipaddress_id=ip.pk) for s, ip in zip(subs, ips)])
        through_port.objects.bulk_create([through_port(ipaddress_id=ip.pk, port_id=p.pk) for ip, p in ports])
        RouteAuth.objects.bulk_create([RouteAuth(project=cls.project, domain=cls.domain, host=s.name, url=f'https://{s.name}/', path='/', auth_state='open',
                                                 http_status=200, content_type='text/html') for s in subs])

    def setUp(self):
        cache.delete(work_planner.CENSUS_KEY)
        mock.patch('cveFeed.scan_control.pause_requested', return_value=False).start()
        self.addCleanup(mock.patch.stopall)

    def census_with_a_gauge(self):
        """The census, and the most Port objects alive at any call of ``check_coverage.load`` (once per page of hosts)."""
        seen, real = [], check_coverage.load

        def gauge(items, *args, **kwargs):
            gc.collect()
            seen.append(sum(1 for o in gc.get_objects() if type(o) is Port))
            return real(items, *args, **kwargs)
        with mock.patch.object(check_coverage, 'load', gauge):
            data = work_planner.build_census(timezone.now())
        return data, seen

    def test_the_ports_alive_at_once_are_those_of_one_page_not_of_the_project(self):
        data, seen = self.census_with_a_gauge()
        self.assertGreater(len(seen), 1)  # it did page
        print(f'\ncensus paging: {len(seen)} pages, at most {max(seen)} Port objects alive at once of {HOSTS * PORTS}')
        self.assertLessEqual(max(seen), work_planner.PAGE * PORTS, f'{max(seen)} Port objects alive at once; the whole project has {HOSTS * PORTS}')
        self.assertEqual(sum(e['kinds']['secrets_scan']['applicable'] for e in data['projects'].values()), HOSTS)

    def test_every_host_is_still_checked_once_in_id_order(self):
        names = []
        real = check_coverage.load

        def spy(items, *args, **kwargs):
            names.extend(s.name for s, _x, _p in items)
            return real(items, *args, **kwargs)
        with mock.patch.object(check_coverage, 'load', spy):
            work_planner.build_census(timezone.now())
        self.assertEqual(names, [f'h{i}.pg.example.com' for i in range(HOSTS)])
