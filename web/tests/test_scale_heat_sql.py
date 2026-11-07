"""Heat counts of a host search computed in the database (agentapi.services._heat_facets): the same answer as walking every host through the
models (``_heat_facets_walk``), at a fixed number of queries however many hosts match (round 2 of the scale work: 64,500 model instances for
3000 hosts, 1.5 s)."""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from cveFeed.models import CVEEntry, CVEMatch, Triage
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import CveId, IpAddress, ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class HeatSqlTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='H', slug='hs', insert_date=now, org=Org.objects.create(name='H', slug='hs-org'))
        cls.domain = Domain.objects.create(name='hs.example.test', project=cls.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='hs')
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=2)
        cls.nuclei_scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, start_scan_date=now, scan_status=2)
        ScanActivity.objects.create(scan_of=cls.nuclei_scan, title='n', name='nuclei_scan', time=now, status=2)
        cls.kev = CVEEntry.objects.create(cve_id='CVE-2099-1', cvss=9.8, kev=True, published_at=now)
        cls.cold = CVEEntry.objects.create(cve_id='CVE-2099-2', cvss=4.0, kev=False, published_at=now)
        cls.counter = 0

    def host(self, name=None, scan=None, ip=None):
        type(self).counter += 1
        n = type(self).counter
        sub = Subdomain.objects.create(name=name or f'h{n}.hs.example.test', target_domain=self.domain, scan_history=scan or self.scan, http_status=200)
        sub.ip_addresses.add(IpAddress.objects.get_or_create(address=ip or f'192.0.2.{n}')[0])
        return sub

    def match(self, sub, cve, **kw):
        return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9, source=kw.pop('source', 'version'), **kw)

    def finding(self, sub, severity, **kw):
        return Vulnerability.objects.create(name=f'f{severity}', severity=severity, source='nuclei', subdomain=sub, target_domain=self.domain,
                                            scan_history=self.scan, open_status=kw.pop('open_status', True), **kw)

    def build(self):
        self.match(self.host(), self.kev, source='host')                                  # fire: hot, proven by the host's own report
        self.match(self.host(), self.kev)                                                 # smoke: hot, version only
        self.match(self.host(), self.cold)                                                # ice: not hot
        self.match(self.host(), self.kev, distro_status='patched')                        # ice: patched
        self.match(self.host(), self.kev, source='host', remediation_status='fixed')       # closed: no reason
        self.match(self.host(), self.kev, source='host', ai_verdict='not_affected')        # ruled out: no reason
        self.finding(self.host(), 4)                                                      # critical, no CVE
        self.finding(self.host(), 2)                                                      # medium: smoke
        self.finding(self.host(), 1)                                                      # low: ice
        self.finding(self.host(), 0)                                                      # informational: clean (has a finding)
        self.finding(self.host(), 4, open_status=False)                                   # closed finding: clean
        v = self.finding(self.host(), 3)                                                  # a CVE finding on a cold CVE: ice
        v.cve_ids.add(CveId.objects.create(name='CVE-2099-2'))
        w = self.finding(self.host(), 3)                               # a CVE finding on a hot CVE
        w.cve_ids.add(CveId.objects.create(name=' cve-2099-1 '))
        m = self.match(self.host(), self.kev, source='host')                              # a person set it to ice
        Triage.objects.create(project=self.project, domain=self.domain, host=m.subdomain.name, kind='cve', match=m, status='triaged', heat_override='ice')
        a = self.host(name='a.hs.example.test', ip='198.51.100.1')                        # two names on one address: the heat is the group's
        self.host(name='b.hs.example.test', ip='198.51.100.1')
        self.match(a, self.kev, source='host')
        self.host()                                                                       # no scan result: unscanned
        self.host(scan=self.nuclei_scan)                                                  # nuclei ran, nothing found: clean
        shared = self.host(name='c.hs.example.test', ip='198.51.100.2')
        self.host(name='d.hs.example.test', ip='198.51.100.2', scan=self.nuclei_scan)     # one name was through nuclei: the group is clean
        self.finding(shared, 4, open_status=False)

    def both(self):
        qs = Subdomain.objects.filter(target_domain=self.domain)
        return services._heat_facets(self.project, qs), services._heat_facets_walk(self.project, qs)

    def test_the_database_answer_is_the_walk_answer_for_every_kind_of_host(self):
        self.build()
        sql, walk = self.both()
        self.assertEqual(sql, walk)
        counts = sql[0]
        self.assertTrue(all(counts[k] > 0 for k in ('fire', 'smoke', 'ice', 'clean', 'unscanned')), counts)

    def test_the_cap_reports_truncation(self):
        self.build()
        qs = Subdomain.objects.filter(target_domain=self.domain)
        old = services.HEAT_FACET_CAP
        services.HEAT_FACET_CAP = 5
        try:
            sql, walk = services._heat_facets(self.project, qs), services._heat_facets_walk(self.project, qs)
        finally:
            services.HEAT_FACET_CAP = old
        self.assertEqual(sql, walk)
        self.assertTrue(sql[2])

    def cost(self):
        qs = Subdomain.objects.filter(target_domain=self.domain)
        services._heat_facets(self.project, qs)  # warm process-wide caches (settings, content types)
        with CaptureQueriesContext(connection) as q:
            services._heat_facets(self.project, qs)
        return len(q)

    def test_the_cost_is_a_fixed_number_of_queries_however_many_hosts(self):
        self.build()
        few = self.cost()
        for _ in range(40):
            self.match(self.host(), self.kev)
            self.finding(self.host(), 3)
        self.assertEqual(self.cost(), few)
        self.assertLessEqual(few, 14)
