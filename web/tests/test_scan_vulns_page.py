"""A scan's findings list joins what each row reads and cuts the page on ids first (review finding A9).

``_vuln`` reads every row's target (for ``internal``) and the author of a manual heat; ``list_scan_vulnerabilities`` joined neither, so a page of
200 findings ran up to 400 extra queries. The page is now cut on ids first (``paginate_narrow``), like ``list_vulnerabilities``: the same count,
order and rows.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import triage
from cveFeed.models import Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call


class ScanVulnerabilitiesPageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Sv', slug='sv-org')
        project = Project.objects.create(name='sv', slug='sv-proj', insert_date=now, org=org)
        domain = Domain.objects.create(name='sv.example', project=project, insert_date=now)
        engine = EngineType.objects.create(engine_name='sv-e', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now)
        other_scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now)
        cls.user = User.objects.create_user('sv-user', password='x')
        ProjectMembership.objects.create(user=cls.user, project=project, role='user')
        cls.token = create_token(cls.user, 'agent')[1]
        cls.vulns = []
        for i in range(12):
            sub = Subdomain.objects.create(target_domain=domain, name=f'h{i}.sv.example', scan_history=cls.scan)
            cls.vulns.append(Vulnerability.objects.create(name=f'flaw {i}', severity=i % 5, subdomain=sub, target_domain=domain, scan_history=cls.scan,
                                                          open_status=True, http_url=f'https://h{i}.sv.example/', source='nuclei'))
        Vulnerability.objects.create(name='other scan', severity=4, target_domain=domain, scan_history=other_scan, open_status=True, source='nuclei')
        triage.track(cls.vulns)
        Triage.objects.filter(vulnerability__in=cls.vulns[:6]).update(  # a heat a person set: the row names who set it
            heat_override='fire', heat_override_reason='seen it', heat_override_by=cls.user, heat_override_at=now)

    def setUp(self):
        cache.clear()

    def get(self, query=''):
        with CaptureQueriesContext(connection) as ctx:
            status, body = call(self.token, 'GET', f'/api/v1/projects/sv-proj/scans/{self.scan.pk}/vulnerabilities?{query}')
        self.assertEqual(status, 200, body)
        return body, len(ctx.captured_queries)

    def test_the_page_is_the_same_order_and_rows(self):
        body, _ = self.get('page_size=5&page=2')
        expected = sorted(self.vulns, key=lambda v: (-v.severity, -v.id))[5:10]
        self.assertEqual((body['count'], [r['id'] for r in body['results']]), (12, [v.id for v in expected]))
        self.assertEqual(self.get('page_size=50&severity=critical')[0]['count'], len([v for v in self.vulns if v.severity == 4]))
        self.assertEqual(self.get('page_size=0')[0], {'count': 12, 'page': 1, 'page_size': 0, 'results': []})

    def test_a_row_reads_no_target_or_heat_author_of_its_own(self):
        self.get('page_size=1')  # the first request of a test reads the access rules it then keeps: not a row's query
        small, few = self.get('page_size=2')
        big, many = self.get('page_size=12')
        self.assertEqual(len(big['results']), 12)
        self.assertEqual(many, few)  # the queries do not grow with the rows
        manual = [r for r in big['results'] if r['heat_override']]
        self.assertEqual(len(manual), 6)
        self.assertTrue(all(r['heat_override']['by'] for r in manual))
        self.assertTrue(all(r['internal'] is False for r in big['results']))
