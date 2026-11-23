"""The agent's work list builds full rows for its page only (review finding A2).

``work_items`` read its window of up to 2,000 matches with every list annotation (a comment count and three agent task subqueries per row), prefetched
every port and technology of their hosts, and built each of them in full (``_match``) before it filtered assets and cut one page in Python. The window
is now read light (the match, its CVE, host and Triage row: what the asset test, the heat, the order and the grouping read) and only the page's matches
are loaded and built in full. The answer is the same: these tests compare it with the former implementation, kept below as the reference.
"""
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services as svc
from cveFeed.models import CVEEntry, CVEMatch, Triage
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain


def reference_work_items(ctx, slug, params):
    """``work_items`` as it was before: every match of the window built as a full row, then filtered, sorted, grouped and paged."""
    from cveFeed.counts import CLOSED
    project, _ = svc.get_one_project(ctx, slug)
    asked = [a.strip() for a in (params.get('assets') or '').split(',') if a.strip()]
    patterns = asked or (ctx.token.assets if ctx.token else [])
    wanted = svc.AssetFilter(patterns)
    placed = {}
    qs = svc._matches_qs(project).exclude(ai_verdict='not_affected').exclude(version_in_range=False).exclude(remediation_status__in=CLOSED) \
        .prefetch_related('subdomain__ip_addresses__ports', 'subdomain__technologies')
    if params.get('include_fp') == '0':
        qs = qs.exclude(triage__classification__in=svc.FALSE_POSITIVES)
    tier = params.get('tier')
    if tier:
        from cveFeed.threat import HEAT_RANK, match_heat_rank_expr
        qs = qs.annotate(_heat_rank=match_heat_rank_expr()).filter(_heat_rank=HEAT_RANK[tier]) if tier in HEAT_RANK else qs.none()
    rows = list(qs[:svc.WORK_ITEMS_WINDOW + 1])
    truncated = len(rows) > svc.WORK_ITEMS_WINDOW
    items = []
    for m in rows[:svc.WORK_ITEMS_WINDOW]:
        sub = m.subdomain
        ips = [ip.address for ip in sub.ip_addresses.all()] if sub else []
        if wanted:
            key = sub.pk if sub else None
            if key not in placed:
                placed[key] = wanted.matches([sub.name.lower()] if sub else [], ips)
            if not placed[key]:
                continue
        item = svc._match(m)
        item['ips'] = ips
        item['host_score'] = sub.score if sub else 0
        item['fixed_in'] = svc._fixed_versions(m.cve_entry, m.matched_product)
        items.append(item)
    order = {'fire': 0, 'smoke': 1, 'ice': 2}
    items.sort(key=lambda i: (i['triage']['classification'] in svc.FALSE_POSITIVES, order.get(i['cve']['tier'], 3), -(i['cve']['cvss'] or 0),
                              -i['host_score']))
    matches = len(items)
    items = svc._one_item_per_upgrade(items)
    page, size = svc.page_args(params)
    return {'count': len(items), 'matches': matches, 'truncated': truncated, 'registered_assets': patterns, 'page': page, 'page_size': size,
            'results': items[(page - 1) * size:page * size]}


class WorkItemsLightWindowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='WL', slug='wl-org')
        cls.project = Project.objects.create(name='WL', slug='wl-proj', insert_date=now, org=org)
        other = Project.objects.create(name='WL2', slug='wl-other', insert_date=now, org=org)
        cls.domain = Domain.objects.create(name='wl.example.com', project=cls.project, insert_date=now)
        foreign = Domain.objects.create(name='wl-other.example.com', project=other, insert_date=now)
        engine = EngineType.objects.create(engine_name='wl-engine', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])
        foreign_scan = ScanHistory.objects.create(domain=foreign, scan_type=engine, scan_status=2, start_scan_date=now, tasks=[])
        cls.user = User.objects.create_superuser('wl-root', 'root@wl.example.test', 'x')
        affected = [{'product': 'nginx', 'ranges': [{'fixed': '1.20.0'}, {'fixed': '1.21.1'}]}]
        cls.cves = [CVEEntry.objects.create(cve_id='CVE-2099-5001', cvss=9.8, kev=True, published_at=now, affected=affected),
                    CVEEntry.objects.create(cve_id='CVE-2099-5002', cvss=7.5, published_at=now, affected=affected),
                    CVEEntry.objects.create(cve_id='CVE-2099-5003', cvss=5.0, published_at=now, affected=[])]
        for i in range(12):
            cls.add_host(i)
        # a host of another project with a match: never in this project's list
        stranger = Subdomain.objects.create(name='h0.wl-other.example.com', target_domain=foreign, scan_history=foreign_scan)
        CVEMatch.objects.create(cve_entry=cls.cves[0], subdomain=stranger, matched_product='nginx', matched_version='1.18.0', confidence=.99)

    @classmethod
    def add_host(cls, i):
        sub = Subdomain.objects.create(name=f'h{i}.wl.example.com', target_domain=cls.domain, scan_history=cls.scan, score=i % 4)
        ip = IpAddress.objects.create(address=f'198.51.{100 + i % 2}.{i + 1}')
        sub.ip_addresses.add(ip)
        made = [CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', confidence=(i + n) / 40,
                                        template_result='vulnerable' if (i + n) % 5 == 0 else '')
                for n, cve in enumerate(cls.cves)]
        if i % 3 == 0:  # a likely false positive: listed last, or left out with include_fp=0
            Triage.objects.create(project=cls.project, domain=cls.domain, host=sub.name, kind='match', match=made[1], status='triaged',
                                  classification='likely_false_positive')
        return sub

    def ctx(self):
        return svc.Ctx(user=self.user)

    def test_the_same_answer_as_building_every_row(self):
        cases = [{}, {'page_size': '3'}, {'page_size': '3', 'page': '2'}, {'page_size': '4', 'page': '5'}, {'tier': 'fire'}, {'tier': 'smoke'},
                 {'tier': 'ice', 'page_size': '2'}, {'include_fp': '0'}, {'assets': 'h1.wl.example.com,h4.wl.example.com'},
                 {'assets': '198.51.101.0/24', 'page_size': '5'}, {'assets': 'wl.example.com', 'include_fp': '0'}, {'assets': 'nothing.example'}]
        for params in cases:
            with self.subTest(params=params):
                got = svc.work_items(self.ctx(), 'wl-proj', dict(params))
                self.assertEqual(got, reference_work_items(self.ctx(), 'wl-proj', dict(params)))
                self.assertNotIn('h0.wl-other.example.com', {i['host'] for i in got['results']})
        self.assertTrue(any(len(i['cves']) > 1 for i in svc.work_items(self.ctx(), 'wl-proj', {})['results']))  # the fixture groups upgrades

    def test_only_the_page_is_built_in_full(self):
        with mock.patch.object(svc, '_match', wraps=svc._match) as built:
            out = svc.work_items(self.ctx(), 'wl-proj', {'page_size': '3'})
        self.assertEqual(len(out['results']), 3)
        self.assertEqual(built.call_count, 3)  # it was every match of the window (36 here, up to 2,000)
        self.assertGreater(out['matches'], 3)

    def test_queries_do_not_grow_with_the_window(self):
        def queries():
            with CaptureQueriesContext(connection) as ctx:
                svc.work_items(self.ctx(), 'wl-proj', {'page_size': '3', 'assets': '198.51.100.0/23'})
            return len(ctx.captured_queries)
        queries()  # the first call of a process reads what it then keeps (the internal network table): not a cost of the window
        before = queries()
        for i in range(12, 30):
            self.add_host(i)
        self.assertEqual(queries(), before)
