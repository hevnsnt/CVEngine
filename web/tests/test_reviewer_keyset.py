"""The finding reviewer's due list read without OFFSET paging (reviewer.due and reviewer._due_in): the same findings, in the same order and within
the same budget as the paging it replaced, with the heat sort run at most twice a call however many pages are walked. Also the projects ``due``
visits, read by EXISTS, and the typical Sentinel queue wait of the operations check, read in one query: each the same as the read it replaced."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import reviewer, triage
from cveFeed.models import CVEEntry, CVEMatch, FindingReview, HygieneFinding, Triage
from dashboard.models import Project
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_reviewer import Fixture


def _due_in_by_offset(project_id, limit, now):
    """The OFFSET paging ``reviewer._due_in`` used before, kept here as the reference the cursor must agree with."""
    from django.db.models import Case, IntegerField, Value, When
    rank = Case(*[When(kind=k, then=Value(v)) for k, v in reviewer.KIND_ORDER.items()], default=Value(9), output_field=IntegerField())
    qs = (Triage.objects.filter(reviewer.open_q(), project_id=project_id).exclude(kind='route_auth')
          .annotate(heat_rank=reviewer.heat_rank_expr(), kind_rank=rank)
          .order_by('-heat_rank', 'kind_rank', '-last_seen', '-id')
          .only('id', 'kind', 'project_id', 'host', 'evidence_key', 'signature'))
    picked = []
    offset = 0
    while len(picked) < limit:
        rows = list(qs[offset:offset + reviewer.WINDOW])
        if not rows:
            break
        offset += reviewer.WINDOW
        fingerprints = reviewer._fingerprints({(t.project_id, t.host) for t in rows})
        seen_all = reviewer._reviewed(rows, fingerprints)
        for row in rows:
            key = reviewer.review_key(row, fingerprints.get((row.project_id, row.host), ''))
            seen = seen_all.get((row.project_id, row.host, key), [])
            if seen and not (all(outcome == reviewer.REFUSED for outcome, _ in seen) and now - seen[0][1] >= reviewer.REFUSED_WAIT):
                continue
            if not cache.add(f'cvengine:reviewer:lease:{row.pk}', key, reviewer.LEASE_SECONDS):
                continue
            picked.append((row.pk, key))
            if len(picked) >= limit:
                break
    return picked


def _heat_sorts(queries):
    return sum(1 for q in queries if 'CASE WHEN' in q['sql'] and 'ORDER BY' in q['sql'] and 'cveFeed_triage' in q['sql'])


class KeysetFixture(Fixture):
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.now = now
        self.rows = [Triage.objects.get(match=self.match)]
        for i in range(8):  # cold CVE matches, two pairs sharing a last_seen so the id tiebreak decides
            cve = CVEEntry.objects.create(cve_id=f'CVE-2099-66{i:02d}', cvss=9.8, published_at=now, affected=[])
            m = CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source='tech', matched_product='lib-k', matched_version='1.0',
                                        version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=self.scan, evidence={'source': 'tech'})
            triage.track([m])
            row = Triage.objects.get(match=m)
            Triage.objects.filter(pk=row.pk).update(last_seen=now - timedelta(hours=i // 2))
            self.rows.append(row)
        kev = CVEEntry.objects.create(cve_id='CVE-2099-6699', cvss=9.8, kev=True, published_at=now, affected=[])
        hot_sub = Subdomain.objects.create(name='kev.example.com', target_domain=self.domain, scan_history=self.scan)
        hot = CVEMatch.objects.create(cve_entry=kev, subdomain=hot_sub, source='tech', matched_product='lib-h', matched_version='2.0',
                                      version_in_range=True, confidence=0.8, scan_history=self.scan, evidence={'source': 'tech'}, distro_status='vulnerable')
        triage.track(triage.with_cves([hot]))
        self.rows.append(Triage.objects.get(match=hot))
        for severity, name in ((4, 'Exposed admin'), (1, 'Banner')):
            vuln = Vulnerability.objects.create(source='nuclei', name=name, severity=severity, discovered_date=now, target_domain=self.domain,
                                                subdomain=self.sub, scan_history=self.scan, open_status=True, template_id=f'k-{severity}')
            triage.track([vuln])
            self.rows.append(Triage.objects.get(vulnerability=vuln))
        for check, severity in (('spf_missing', 2), ('tls_expired', 4)):
            hygiene = HygieneFinding.objects.create(domain=self.domain, host='www.example.com', check_name=check, severity=severity, title=check)
            triage.track([hygiene])
            self.rows.append(Triage.objects.get(hygiene=hygiene))
        Triage.objects.filter(pk=self.rows[3].pk).update(heat_override='smoke')
        closed = CVEMatch.objects.create(cve_entry=self.cve, subdomain=hot_sub, source='tech', matched_product='lib-c', matched_version='1.0',
                                         version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=self.scan, evidence={'source': 'tech'})
        triage.track([closed])
        CVEMatch.objects.filter(pk=closed.pk).update(remediation_status='fixed')  # not open: never due
        fingerprint = self.state.fingerprint

        def review(row, outcome='recorded', age=None):
            r = FindingReview.objects.create(triage=row, project=self.proj, review_key=reviewer.review_key(row, fingerprint if row.host == 'www.example.com' else ''),
                                             verdict='' if outcome == reviewer.REFUSED else 'true_open', confidence='high', outcome=outcome)
            if age is not None:
                FindingReview.objects.filter(pk=r.pk).update(created_at=now - age)
        for row in self.rows[1:9:2]:
            review(row)  # reviewed in its current state
        review(self.rows[2], reviewer.REFUSED, timedelta(days=2))  # refused long ago: asked again
        review(self.rows[4], reviewer.REFUSED, timedelta(hours=1))  # refused lately: waits its day
        review(self.rows[-1])
        cache.clear()

    def both(self, limit, leased=()):
        """``(by offset, by cursor)`` for one project, each from the same cache state (``leased`` are handed out already)."""
        out = []
        for fn in (_due_in_by_offset, reviewer._due_in):
            cache.clear()
            for pk in leased:
                cache.add(f'cvengine:reviewer:lease:{pk}', 'x', reviewer.LEASE_SECONDS)
            out.append(fn(self.proj.pk, limit, self.now))
        cache.clear()
        return out


class SelectionTests(KeysetFixture):
    def test_the_cursor_hands_out_what_offset_paging_did_in_the_same_order(self):
        open_count = Triage.objects.filter(reviewer.open_q(), project=self.proj).count()
        self.assertGreater(open_count, 12)
        for window in (1, 2, 3, 5, 400):
            with mock.patch.object(reviewer, 'WINDOW', window):
                for limit in range(1, open_count + 3):
                    old, new = self.both(limit)
                    self.assertEqual(new, old, f'window {window}, limit {limit}')
                    self.assertLessEqual(len(new), limit)
        with mock.patch.object(reviewer, 'WINDOW', 3):
            old, new = self.both(25)
        self.assertTrue(old)
        self.assertNotIn(self.rows[4].pk, dict(new))  # refused lately
        self.assertIn(self.rows[2].pk, dict(new))  # refused two days ago

    def test_a_finding_handed_out_lately_is_skipped_the_same_way(self):
        with mock.patch.object(reviewer, 'WINDOW', 2):
            first = self.both(25)[0]
            leased = [pk for pk, _ in first[:3]]
            for limit in (1, 3, 25):
                old, new = self.both(limit, leased)
                self.assertEqual(new, old)
                self.assertFalse(set(leased) & set(dict(new)))

    def test_the_batch_across_projects_is_unchanged(self):
        now = self.now
        other = Project.objects.create(name='Rev3', slug='rev-proj-3', insert_date=now, org=self.org)
        dom = Domain.objects.create(name='example.net', project=other, insert_date=now)
        sub = Subdomain.objects.create(name='www.example.net', target_domain=dom, scan_history=ScanHistory.objects.create(
            domain=dom, scan_type=self.scan.scan_type, scan_status=2, start_scan_date=now))
        m = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='lib-a', matched_version='1.2',
                                    version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=sub.scan_history, evidence={'source': 'tech'})
        triage.track([m])
        for limit in (1, 2, 5, 25):
            cache.clear()
            with mock.patch.object(reviewer, 'WINDOW', 2):
                with mock.patch.object(reviewer, '_due_in', _due_in_by_offset):
                    old = reviewer.due(limit, now=now)
                cache.clear()
                new = reviewer.due(limit, now=now)
            self.assertEqual(new, old, f'limit {limit}')
        cache.clear()


class QueryCountTests(KeysetFixture):
    def test_the_heat_sort_runs_at_most_twice_however_many_pages_are_walked(self):
        FindingReview.objects.filter(project=self.proj).delete()
        fingerprint = self.state.fingerprint
        for row in Triage.objects.filter(reviewer.open_q(), project=self.proj):
            FindingReview.objects.create(triage=row, project=self.proj, review_key=reviewer.review_key(row, fingerprint if row.host == 'www.example.com' else ''),
                                         verdict='true_open', confidence='high', outcome='recorded')
        new_rows = []
        for i in range(2):  # two findings nobody reviewed, the coldest and oldest, so every page is walked to reach them
            hygiene = HygieneFinding.objects.create(domain=self.domain, host='www.example.com', check_name=f'old_{i}', severity=0, title='old')
            triage.track([hygiene])
            new_rows.append(Triage.objects.get(hygiene=hygiene).pk)
        Triage.objects.filter(pk__in=new_rows).update(last_seen=self.now - timedelta(days=30))
        cache.clear()
        with mock.patch.object(reviewer, 'WINDOW', 3):
            with CaptureQueriesContext(connection) as before:
                old = _due_in_by_offset(self.proj.pk, 25, self.now)
            cache.clear()
            with CaptureQueriesContext(connection) as after:
                new = reviewer._due_in(self.proj.pk, 25, self.now)
        self.assertEqual(new, old)
        self.assertEqual(sorted(pk for pk, _ in new), sorted(new_rows))
        self.assertGreaterEqual(_heat_sorts(before.captured_queries), 5)  # one sort of the whole open set per page of three
        self.assertEqual(_heat_sorts(after.captured_queries), 2)  # the first page and the ids, once
        self.assertLessEqual(len(after.captured_queries), len(before.captured_queries))

    def test_a_first_page_that_holds_the_batch_is_one_sorted_read(self):
        cache.clear()
        with CaptureQueriesContext(connection) as queries:
            picked = reviewer._due_in(self.proj.pk, 1, self.now)
        self.assertEqual(len(picked), 1)
        self.assertEqual(_heat_sorts(queries.captured_queries), 1)
        ours = [q for q in queries.captured_queries if 'cveFeed_tunablesettings' not in q['sql']]  # the heat thresholds, read once a process
        self.assertEqual(len(ours), 3)  # the page, its host fingerprints, its reviews


class ProjectListTests(KeysetFixture):
    def test_due_visits_the_projects_the_distinct_read_named(self):
        now = self.now
        quiet = Project.objects.create(name='Rev4', slug='rev-proj-4', insert_date=now, org=self.org)  # only a closed finding and a route check
        dom = Domain.objects.create(name='example.org', project=quiet, insert_date=now)
        sub = Subdomain.objects.create(name='www.example.org', target_domain=dom, scan_history=ScanHistory.objects.create(
            domain=dom, scan_type=self.scan.scan_type, scan_status=2, start_scan_date=now))
        m = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='lib-q', matched_version='1.0',
                                    version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=sub.scan_history, evidence={'source': 'tech'})
        triage.track([m])
        CVEMatch.objects.filter(pk=m.pk).update(remediation_status='fixed')
        Project.objects.create(name='Rev5', slug='rev-proj-5', insert_date=now, org=self.org)  # nothing at all
        old = sorted(Triage.objects.filter(reviewer.open_q()).exclude(kind='route_auth').order_by().values_list('project_id', flat=True).distinct())
        seen = []
        with mock.patch.object(reviewer, '_due_in', side_effect=lambda pid, limit, now: seen.append(pid) or []):
            reviewer.due(25, now=now)
        self.assertEqual(seen, old)
        self.assertIn(self.proj.pk, seen)
        self.assertNotIn(quiet.pk, seen)


class QueueWaitTests(KeysetFixture):
    def _old(self, kind, now):
        from agentapi.models import SentinelTask
        return sorted((c - k).total_seconds() for k, c in SentinelTask.objects.filter(kind=kind, claimed_at__isnull=False, created_at__gte=now - timedelta(days=1))
                      .order_by('-id').values_list('created_at', 'claimed_at')[:reviewer.WAIT_SAMPLE])

    def test_one_read_gives_each_kind_the_waits_its_own_read_gave(self):
        from agentapi.models import SentinelTask
        now = self.now
        rows = []
        for kind, n in (('nmap', 9), ('nuclei', 2), ('hygiene_check', 0)):
            for i in range(n):
                rows.append((kind, now - timedelta(hours=i * 2 + 1), timedelta(minutes=i + 1)))
        rows += [('nmap', now - timedelta(days=2), timedelta(hours=30)),  # created before the day, claimed in it: left out by both
                 ('nuclei', now - timedelta(days=3), timedelta(minutes=5))]
        for kind, created, wait in rows:
            task = SentinelTask.objects.create(project=self.proj, kind=kind, target={}, status='done')
            SentinelTask.objects.filter(pk=task.pk).update(created_at=created, claimed_at=created + wait)
        unclaimed = SentinelTask.objects.create(project=self.proj, kind='nmap', target={}, status='queued')
        self.assertIsNone(unclaimed.claimed_at)
        for sample in (1, 3, 200):
            with mock.patch.object(reviewer, 'WAIT_SAMPLE', sample):
                got = reviewer._recent_waits(['nmap', 'nuclei', 'hygiene_check'], now)
                for kind in ('nmap', 'nuclei', 'hygiene_check'):
                    new = sorted((c - k).total_seconds() for k, c in got.get(kind, ()))
                    self.assertEqual(new, self._old(kind, now), f'{kind}, sample {sample}')
        self.assertEqual(reviewer._recent_waits([], now), {})
        with CaptureQueriesContext(connection) as queries:
            reviewer._recent_waits(['nmap', 'nuclei'], now)
        self.assertEqual(len(queries.captured_queries), 1)
