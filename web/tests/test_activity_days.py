"""The dashboard's Activity card counts the database, it does not sample it (cveFeed.activity_days, GET /api/v1/projects/<slug>/activity-days).

It used to read at most 1,000 rows of each list and print that as the total: every big project showed "1,000".
"""
from datetime import datetime, timedelta, timezone as dt_timezone
import re
import time
from pathlib import Path

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import activity_days, views
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call

import itertools

SERIAL = itertools.count()
NOW = timezone.now()
TODAY_NOON = NOW.replace(hour=12, minute=0, second=0, microsecond=0)


def days_ago(n, hour=12):
    return TODAY_NOON.replace(hour=hour) - timedelta(days=n)


class ActivityDaysTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='Widgets', slug='ad-widgets')
        cls.pa = Project.objects.create(name='Acme', slug='ad-a', insert_date=NOW, org=org)
        cls.pb = Project.objects.create(name='Other', slug='ad-b', insert_date=NOW, org=org)
        cls.da = Domain.objects.create(name='acme.example', project=cls.pa, insert_date=NOW)
        cls.db = Domain.objects.create(name='other.example', project=cls.pb, insert_date=NOW)
        cls.www = Subdomain.objects.create(name='www.acme.example', target_domain=cls.da)
        cls.other = Subdomain.objects.create(name='www.other.example', target_domain=cls.db)
        cls.alice = User.objects.create_user('ad-alice', password='x')
        cls.stranger = User.objects.create_user('ad-stranger', password='x')
        ProjectMembership.objects.create(user=cls.alice, project=cls.pa, role='user')
        _, cls.token = create_token(cls.alice, 'ad')
        _, cls.stranger_token = create_token(cls.stranger, 'ad-s')

    def setUp(self):
        views.clear_stats_cache()  # a snapshot of an earlier test must not answer this one

    def vulns(self, n, when, severity=1, domain=None, sub=None, **extra):
        domain, sub = domain or self.da, sub or self.www
        Vulnerability.objects.bulk_create([Vulnerability(name=f'finding {next(SERIAL)} {i}', severity=severity, subdomain=sub, target_domain=domain, open_status=True,
                                                        discovered_date=when, http_url=f'https://{sub.name}/{i}', **extra) for i in range(n)])

    def get(self, path, token=None, project='ad-a'):
        status, body = call(token or self.token, 'GET', f'/api/v1/projects/{project}/{path}')
        self.assertEqual(status, 200, body)
        return body

    def card(self, **params):
        query = '&'.join(f'{k}={v}' for k, v in {'days': 90, **params}.items())
        return self.get(f'activity-days?{query}')

    def test_the_total_is_the_real_count_past_a_thousand_rows(self):
        self.vulns(1205, days_ago(3))
        body = self.card()
        self.assertEqual(body['findings']['total'], 1205)  # the sampled card said 1,000
        self.assertEqual(body['findings']['by_tier'], {'fire': 0, 'smoke': 0, 'ice': 1205})
        self.assertEqual(body['findings']['busiest']['n'], 1205)
        changes = [AssetChange(project=self.pa, domain=self.da, host='h', kind='port_opened', detected_at=days_ago(i % 80)) for i in range(1271)]
        AssetChange.objects.bulk_create(changes)
        views.bump_stats_revision()
        self.assertEqual(self.card()['changes']['total'], 1271)

    def test_the_card_total_equals_the_findings_page_total_for_the_same_filters(self):
        kev = CVEEntry.objects.create(cve_id='CVE-2099-8001', kev=True, cvss=9.8, title='t', published_at=NOW)
        mild = CVEEntry.objects.create(cve_id='CVE-2099-8002', cvss=5.0, title='t', published_at=NOW)
        CVEMatch.objects.create(cve_entry=kev, subdomain=self.www, matched_product='nginx', matched_version='1.18.0', template_result='vulnerable')
        CVEMatch.objects.create(cve_entry=mild, subdomain=self.www, ai_verdict='not_affected')  # ruled out: in "all", not in "actionable"
        self.vulns(4, days_ago(2), severity=3)
        self.vulns(2, days_ago(9), severity=0)
        Vulnerability.objects.create(name='closed', severity=4, subdomain=self.www, target_domain=self.da, open_status=False, discovered_date=days_ago(5))
        HygieneFinding.objects.create(domain=self.da, host='acme.example', check_name='dmarc_none', severity=2, title='DMARC', status='open')
        # another project's rows are in neither number
        self.vulns(3, days_ago(2), severity=4, domain=self.db, sub=self.other)
        page = self.get('findings?status=all&page_size=0')
        card = self.card()
        # everything above was first seen inside the window, so the page and the card must agree to the row, by type as well
        self.assertEqual(card['findings']['total'], page['total'])
        self.assertEqual(card['findings']['by_type'], page['counts'])
        self.assertEqual(sum(card['findings']['by_tier'].values()), page['total'])

    def test_rows_outside_the_window_and_without_a_date_are_not_counted(self):
        self.vulns(2, days_ago(1))
        self.vulns(5, days_ago(91))
        self.vulns(1, None)
        body = self.card()
        self.assertEqual(body['findings']['total'], 2)
        self.assertEqual(self.card(days=120)['findings']['total'], 7)
        self.assertEqual(self.card(days=1)['findings']['total'], 0)

    def test_days_tiers_and_the_busiest_day_are_exact(self):
        self.vulns(3, days_ago(4), severity=1)   # ice by severity: no heat
        self.vulns(2, days_ago(4), severity=2)   # medium: smoke
        self.vulns(1, days_ago(10), severity=4)
        body = self.card()
        by_date = {d['date']: d for d in body['findings']['days']}
        busy = (NOW - timedelta(days=4)).date().isoformat()
        self.assertEqual(by_date[busy]['n'], 5)
        self.assertEqual(sum(by_date[busy][t] for t in activity_days.TIERS), 5)
        self.assertEqual(body['findings']['busiest']['date'], busy)
        self.assertEqual(body['findings']['busiest']['n'], 5)
        self.assertEqual(body['findings']['total'], sum(d['n'] for d in body['findings']['days']))
        self.assertEqual(body['findings']['total'], 6)

    def test_a_day_is_a_calendar_day_in_the_asked_zone(self):
        stamp = datetime(2026, 6, 10, 23, 30, tzinfo=dt_timezone.utc)
        at = lambda tz: {d['date'] for d in activity_days.build(
            {'scanner': __import__('agentapi.services', fromlist=['x'])._finding_sources(self.pa, {'status': 'all'})['scanner']},
            AssetChange.objects.none(), 90, tz, now=datetime(2026, 6, 12, 12, 0, tzinfo=dt_timezone.utc))['findings']['days']}
        self.vulns(1, stamp)
        self.assertEqual(at('UTC'), {'2026-06-10'})
        self.assertEqual(at('Asia/Tokyo'), {'2026-06-11'})
        self.assertEqual(at('America/Los_Angeles'), {'2026-06-10'})
        self.assertEqual(activity_days.zone_of('not/a-zone').key, 'UTC')
        self.assertEqual(activity_days.zone_of('../../etc/passwd').key, 'UTC')

    def test_one_grouped_query_per_series_whatever_the_size(self):
        self.vulns(300, days_ago(3))
        self.vulns(300, days_ago(6), severity=3)
        AssetChange.objects.bulk_create([AssetChange(project=self.pa, domain=self.da, host='h', kind='port_opened', detected_at=days_ago(7)) for _ in range(300)])
        self.card()  # warm what the first request of a process reads once (the token, the project)
        views.clear_stats_cache()
        with CaptureQueriesContext(connection) as small:
            self.card()
        views.clear_stats_cache()
        self.vulns(900, days_ago(8))
        with CaptureQueriesContext(connection) as large:
            self.card()
        self.assertEqual(len(small), len(large))  # no query per row, per day or per page
        grouped = [q['sql'] for q in large.captured_queries if 'GROUP BY' in q['sql']]
        self.assertEqual(len(grouped), 4, grouped)  # CVE matches, scanner findings, configuration checks and inventory changes
        self.assertFalse([q for q in grouped if re.search(r'LIMIT \d+\s*$', q)])  # no outer LIMIT: nothing is sampled (the "latest scan" rule has its own inner one)

    def test_the_second_ask_is_served_from_the_snapshot(self):
        from unittest import mock

        from cveFeed import snapshot_cache
        self.vulns(10, days_ago(1))
        with mock.patch.object(snapshot_cache, '_now', return_value=time.time()):  # the snapshot's age is the entries' clock: frozen, a slow runner cannot age it out between the two asks
            self.card()
            with CaptureQueriesContext(connection) as again:
                body = self.card()
        self.assertEqual(body['findings']['total'], 10)
        self.assertFalse([q for q in again.captured_queries if 'GROUP BY' in q['sql']], 'the grouped queries ran again')

    def test_a_closed_finding_drops_the_snapshot_like_the_other_cards(self):
        self.vulns(2, days_ago(1))
        self.assertEqual(self.card()['findings']['total'], 2)
        self.vulns(1, days_ago(1))
        self.assertEqual(self.card()['findings']['total'], 2)  # still the snapshot
        views.bump_stats_revision()
        self.assertEqual(self.card()['findings']['total'], 3)

    def test_it_is_scoped_to_the_projects_the_caller_may_see(self):
        self.vulns(2, days_ago(1))
        self.vulns(7, days_ago(1), domain=self.db, sub=self.other)
        AssetChange.objects.create(project=self.pb, domain=self.db, host='x', kind='host_new', detected_at=days_ago(1))
        body = self.card()
        self.assertEqual((body['findings']['total'], body['changes']['total']), (2, 0))
        status, _ = call(self.token, 'GET', '/api/v1/projects/ad-b/activity-days')
        self.assertEqual(status, 404)
        status, _ = call(self.stranger_token, 'GET', '/api/v1/projects/ad-a/activity-days')
        self.assertEqual(status, 404)
        everywhere = self.get('activity-days?days=90', project='_all')  # alice sees one project: the same two rows
        self.assertEqual(everywhere['findings']['total'], 2)

    def test_the_window_is_the_changes_page_window(self):
        for n in (0, 30, 89, 91):
            AssetChange.objects.create(project=self.pa, domain=self.da, host='h', kind='port_opened', detected_at=days_ago(n))
        body = self.card()
        listed = self.get(f'changes?since={body["since"]}&page_size=0')
        self.assertEqual(body['changes']['total'], listed['count'])

    def test_a_bad_days_value_is_a_400_and_the_range_is_clamped(self):
        status, _ = call(self.token, 'GET', '/api/v1/projects/ad-a/activity-days?days=lots')
        self.assertEqual(status, 400)
        self.assertEqual(self.card(days=100000)['days'], activity_days.MAX_DAYS)
        self.assertEqual(self.card(days=0)['days'], 1)

    def test_nothing_is_capped_so_the_page_carries_no_cap_note(self):
        static = Path(__file__).resolve().parents[1] / 'static' / 'cve'
        script = (static / 'dashboard.js').read_text()
        for phrase in ('hottest of', 'New findings counts', 'Inventory changes counts'):
            self.assertNotIn(phrase, script)
        self.assertIn('activity-days', script)

    def test_scans_and_changes_series_are_exact_for_the_scans_and_changes_pages(self):
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        engine = EngineType.objects.create(engine_name='ad-fast', yaml_configuration='x')
        ScanHistory.objects.bulk_create([ScanHistory(scan_type=engine, domain=self.da, start_scan_date=days_ago(i % 100), scan_status=2) for i in range(260)])
        ScanHistory.objects.bulk_create([ScanHistory(scan_type=engine, domain=self.db, start_scan_date=days_ago(1), scan_status=2) for _ in range(5)])
        AssetChange.objects.bulk_create([AssetChange(project=self.pa, domain=self.da, host='h', kind='port_opened', detected_at=days_ago(i % 50)) for i in range(420)])
        body = self.get('activity-days?days=126&series=scans,changes')
        self.assertNotIn('findings', body)
        self.assertEqual(body['scans']['total'], 260)  # the Scans page chart drew the newest 200
        listed = self.get('scans?page_size=0')
        self.assertEqual(listed.get('total', listed.get('count')), 260)
        self.assertEqual(body['changes']['total'], 420)  # the Changes page chart drew the newest 200
        self.assertEqual(sum(d['n'] for d in body['scans']['days']), 260)

    def test_an_unknown_series_is_a_400_and_unasked_series_cost_no_query(self):
        status, _ = call(self.token, 'GET', '/api/v1/projects/ad-a/activity-days?series=findings,bogus')
        self.assertEqual(status, 400)
        self.card()  # warm
        views.clear_stats_cache()
        with CaptureQueriesContext(connection) as only_scans:
            self.get('activity-days?series=scans')
        self.assertEqual(len([q for q in only_scans.captured_queries if 'GROUP BY' in q['sql']]), 1)


class HygieneTopChecksTests(TestCase):
    """The dashboard's Hygiene tile listed its top checks from the first 100 rows of each severity: a check with 400 findings said 100."""

    def test_the_top_checks_count_every_actionable_finding(self):
        from cveFeed import counts
        org = Org.objects.create(name='H', slug='ht-org')
        project = Project.objects.create(name='H', slug='ht-p', insert_date=NOW, org=org)
        domain = Domain.objects.create(name='ht.example', project=project, insert_date=NOW)
        make = lambda check, n, severity, **kw: HygieneFinding.objects.bulk_create(
            [HygieneFinding(domain=domain, host=f'{check}-{i}.ht.example', check_name=check, severity=severity, title='t', status='open', **kw) for i in range(n)])
        make('tls_expired', 400, 3)
        make('dmarc_none', 250, 2)
        make('spf_soft', 7, 2)
        make('mta_sts_missing', 90, 1)             # low: not in the top, only in the open number
        make('tls_legacy', 30, 3, remediation_status='accepted_risk')  # closed: in neither number
        top = counts.hygiene_top_checks()
        self.assertEqual([(t['check'], t['worst'], t['n']) for t in top], [('tls_expired', 'high', 400), ('dmarc_none', 'medium', 250), ('spf_soft', 'medium', 7)])
        views.clear_stats_cache()
        stats = views.stats_payload()
        self.assertEqual(stats['hygiene_top'], top)
        self.assertEqual(stats['hygiene_open'], 400 + 250 + 7 + 90)
