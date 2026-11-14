"""The system status's cold project rows read what every project shares once, not once per project.

Before: each of 15 rows ran the host collapse (a window over the instance's hosts), the exposed-host read, the web-host count and the severity and heat
group-bys of the findings for its own project: 25 statements each, 5.4 s for 15 rows on a seed shaped like the reported install (31.9 s with the
previous current-scans filter). Now the host counts, the exposed hosts, the web hosts and the finding counts of every project are read once and each
row takes its own numbers from them: 0.9 s. The rows are the same (compared below with the rows each project counts for itself).
"""
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import system_status
from agentapi.services import Ctx
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class World(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='SC', slug='sc-org')
        engine = EngineType.objects.create(engine_name='sc')
        cve = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=9.8, kev=True, published_at=now, affected=[])
        mild = CVEEntry.objects.create(cve_id='CVE-2099-7002', cvss=5.0, published_at=now, affected=[])
        cls.projects = []
        for n in range(3):
            project = Project.objects.create(name=f'SC{n}', slug=f'sc-{n}', insert_date=now, org=org)
            cls.projects.append(project)
            domain = Domain.objects.create(name=f'sc{n}.example.test', project=project, insert_date=now)
            full = ScanHistory.objects.create(start_scan_date=now - timedelta(days=2), scan_status=2, domain=domain, scan_type=engine, tasks=[])
            ScanHistory.objects.create(start_scan_date=now - timedelta(days=3), scan_status=2, domain=domain, scan_type=engine, tasks=['host_pipeline'])
            after = ScanHistory.objects.create(start_scan_date=now - timedelta(days=1), scan_status=2, domain=domain, scan_type=engine, tasks=['host_pipeline'])
            ip = IpAddress.objects.create(address=f'198.51.{n}.1')
            port = Port.objects.create(number=443, service_name='https', protocol='tcp', state='open')
            ip.ports.add(port)
            apex = Subdomain.objects.create(name=f'sc{n}.example.test', target_domain=domain, scan_history=full, http_url='https://x.invalid/')
            www = Subdomain.objects.create(name=f'www.sc{n}.example.test', target_domain=domain, scan_history=full)  # an alias of the apex: one host
            api = Subdomain.objects.create(name=f'api.sc{n}.example.test', target_domain=domain, scan_history=after)
            old = Subdomain.objects.create(name=f'old.sc{n}.example.test', target_domain=domain, scan_history=ScanHistory.objects.filter(domain=domain).first())
            for sub in (apex, www):
                sub.ip_addresses.add(ip)
            api.ip_addresses.add(IpAddress.objects.create(address=f'198.51.{n}.2'))
            CVEMatch.objects.create(cve_entry=cve, subdomain=www, matched_product='nginx', template_result='vulnerable')
            CVEMatch.objects.create(cve_entry=mild, subdomain=api, matched_product='php')
            CVEMatch.objects.create(cve_entry=mild, subdomain=old, matched_product='old')
            Vulnerability.objects.create(name='Exposed admin', severity=3 - n, subdomain=api, target_domain=domain, open_status=True,
                                         discovered_date=now, http_url=f'https://api.sc{n}.example.test/')
            if n == 1:
                HygieneFinding.objects.create(domain=domain, host=f'sc{n}.example.test', check_name='spf_missing', severity=2, status='open', title='no spf')
        cls.root = User.objects.create_superuser('sc-root', 'root@sc.example.test', 'x')

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)


class SameRowsTests(World):
    def test_a_row_from_the_shared_counts_is_the_row_the_project_counts_for_itself(self):
        shared = system_status._shared_inputs([p.id for p in self.projects])
        self.assertIsNotNone(shared)
        for project in self.projects:
            self.assertEqual(system_status._project_row(project, shared), system_status._project_row(project), project.slug)
        row = system_status._project_row(self.projects[1], shared)
        self.assertEqual(row['hosts'], 3)  # the apex and its alias are one host (with api and old: three), the same as the project counts alone
        self.assertGreater(sum(row['open_findings'].values()), 1)

    def test_a_project_with_no_domain_has_zero_counts(self):
        empty = Project.objects.create(name='SCE', slug='sc-empty', insert_date=timezone.now(), org=self.projects[0].org)
        shared = system_status._shared_inputs([p.id for p in self.projects] + [empty.id])
        self.assertEqual(system_status._project_row(empty, shared), system_status._project_row(empty))


class StatementCountTests(World):
    def statements(self, fn):
        with CaptureQueriesContext(connection) as captured:
            fn()
        return [q['sql'] for q in captured.captured_queries]

    def test_cold_rows_collapse_the_hosts_and_group_the_findings_once_for_all_projects(self):
        from unittest import mock

        from cveFeed import inventory_counts
        python_runs = []
        original = inventory_counts._collapse
        ctx = Ctx(user=self.root)
        with mock.patch.object(inventory_counts, '_collapse', lambda *a, **k: python_runs.append(1) or original(*a, **k)):
            shared_run = self.statements(lambda: system_status._projects_partial(ctx))
        self.assertEqual(len(python_runs), 1)  # the hosts of every project are collapsed exactly once, however many projects there are
        cache.clear()
        own_run = self.statements(lambda: [system_status._project_row(p) for p in self.projects])
        collapses = lambda run: [q for q in run if 'ROW_NUMBER() OVER' in q]
        self.assertEqual(len(collapses(own_run)), 3)       # one SQL collapse per project
        self.assertEqual(len(collapses(shared_run)), 0)    # none: the hosts of every project are collapsed once, in Python, from set-based reads
        cve_groups = lambda run: [q for q in run if '"cveFeed_cveentry"."cvss" >=' in q and 'GROUP BY' in q]
        self.assertEqual((len(cve_groups(own_run)), len(cve_groups(shared_run))), (3, 1))
        self.assertLess(len(shared_run), len(own_run))
