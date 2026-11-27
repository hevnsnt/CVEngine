"""The Overview, the alert strip and the page shell read the same numbers in fewer queries: one read of the current scans per snapshot
(``current_scans.shared_sets``), the week's change log and the certificates counted in grouped reads, the setup questions counted from their states
alone, the alerts' answering decisions read in one statement. Every test here compares the new answer with the one the old reads gave for the same
rows, or puts a ceiling on the queries of one request."""
import contextlib
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import current_scans, overview, reviewer, setup_questions, snapshot_cache
from cveFeed.models import AdminAlert, AssetChange, HygieneFinding, SetupAnswer, StatsSnapshot, TlsCertificate, TuningDecision
from startScan.models import ScanHistory
from tests.steady import steady_caches
from tests.test_setup_questions import Base as QuestionsBase
from tests.test_situations import Fixture


def _volatile_out(payload):
    """The payload without what moves with the clock between two builds (when it was built)."""
    return json.loads(json.dumps({k: v for k, v in payload.items() if k != 'updated_at'}, default=str))


def legacy_certs(ids, now):
    """``overview._certs`` as it read before (three counts), kept here as the reference the grouped read must agree with."""
    from cveFeed import counts
    from cveFeed.report_data import clean
    base = TlsCertificate._base_manager.filter(domain__project_id__in=list(ids))
    due = counts.expiring_certificates(base)
    total = due.count()
    nxt = base.filter(not_after__gte=now).order_by('not_after').values_list('host', 'not_after').first() if total else None
    expired = due.filter(not_after__lt=now).count() if total else 0
    if nxt:
        days = max(0, (nxt[1] - now).days)
        detail = f"next: {clean(nxt[0], 100)} " + ('expires today' if days == 0 else f"in {overview.plural(days, 'day', 'days')}")
    elif total:
        detail = f'{expired:,} already expired'
    else:
        detail = 'none expired or due in 30 days'
    return total, detail


def legacy_log_counts(ids, now):
    """The three counts of the week's change log as ``what_changed`` read them before (one query each)."""
    log = AssetChange._base_manager.filter(project_id__in=list(ids), detected_at__gte=now - timedelta(days=overview.WINDOW_DAYS))
    return {'sens': log.filter(kind='sensitive_found').count(),
            'new': log.filter(kind='host_new').values('project_id', 'host').distinct().count(),
            'gone': log.filter(kind='host_retired').values('project_id', 'host').distinct().count(),
            'new_host': log.filter(kind='host_new').order_by('-detected_at', '-id').values_list('host', flat=True).first()}


class Seeded(Fixture):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        now = cls.now
        for i in range(3):
            h = cls.host(f'web{i}.sa.test', http=200)
            cls.match(h, cls.exploit, validation='hit' if i == 0 else 'none', steps=cls.hit() if i == 0 else None)
            cls.finding(h, 3, name=f'finding {i}')
        cls.match(cls.host('b1.sb.test', domain=cls.db, http=200), cls.kev)
        HygieneFinding.objects.create(domain=cls.da, host='web1.sa.test', check_name='tls_expired', severity=4, title='Certificate for web1.sa.test:443 expired 2 days ago')
        for d in range(10):
            for p in (cls.pa, cls.pb):
                StatsSnapshot.objects.create(project=p, date=timezone.localdate() - timedelta(days=9 - d), hosts=10, exposed_hosts=d, open_findings={'critical': 1, 'high': 2},
                                             cve_matches={'fire': 1, 'smoke': 1}, fixed=1, mean_days_to_fix=3.0, needs_hosts=2)
        TlsCertificate.objects.create(domain=cls.da, host='soon.sa.test', port=443, not_after=now + timedelta(days=3))
        TlsCertificate.objects.create(domain=cls.da, host='gone.sa.test', port=443, not_after=now - timedelta(days=5))
        TlsCertificate.objects.create(domain=cls.db, host='late.sb.test', port=443, not_after=now - timedelta(days=1))
        TlsCertificate.objects.create(domain=cls.da, host='fine.sa.test', port=443, not_after=now + timedelta(days=300))
        changes = [(cls.pa, cls.da, 'new.sa.test', 'host_new', 1), (cls.pa, cls.da, 'new.sa.test', 'host_new', 2), (cls.pb, cls.db, 'new.sa.test', 'host_new', 1),
                   (cls.pb, cls.db, 'b2.sb.test', 'host_new', 3), (cls.pa, cls.da, 'old.sa.test', 'host_retired', 3), (cls.pa, cls.da, 'old.sa.test', 'host_retired', 4),
                   (cls.pb, cls.db, 'old.sa.test', 'host_retired', 2), (cls.pa, cls.da, 'ancient.sa.test', 'host_new', 30),
                   (cls.pa, cls.da, 'pii.sa.test', 'sensitive_found', 1), (cls.pb, cls.db, 'pii.sb.test', 'sensitive_found', 2)]
        for project, domain, host, kind, days in changes:
            AssetChange.objects.create(project=project, domain=domain, host=host, kind=kind, detected_at=now - timedelta(days=days),
                                       after={'types': ['email']} if kind == 'sensitive_found' else {})

    def setUp(self):
        cache.clear()


class WhatChangedSameAsBeforeTests(Seeded):
    def test_the_grouped_reads_say_what_the_separate_counts_said(self):
        for ids in ([self.pa.pk], [self.pb.pk], [self.pa.pk, self.pb.pk], [self.empty.pk]):
            with self.subTest(ids=ids):
                self.assertEqual(overview._certs(ids, self.now), legacy_certs(ids, self.now))
                old = legacy_log_counts(ids, self.now)
                tiles = overview.kpis(ids, {'hosts': 5, 'exposed_hosts': 3}, self.now)
                lines = {line['key']: line for line in overview.what_changed(ids, tiles, self.now)['lines']}
                self.assertEqual(lines['sensitive']['value'], f"{old['sens']:,}")
                self.assertEqual(lines['hosts']['value'], f"{old['new']:,} / {old['gone']:,}")
                self.assertEqual(lines['hosts']['detail'], f"new: {old['new_host']}" if old['new_host'] else 'none found this week')

    def test_a_host_found_in_two_projects_is_two_hosts_and_found_twice_in_one_is_one(self):
        lines = {line['key']: line for line in overview.what_changed([self.pa.pk, self.pb.pk], overview.kpis([self.pa.pk, self.pb.pk], None, self.now), self.now)['lines']}
        self.assertEqual(lines['hosts']['value'], '3 / 2')  # new.sa.test in A (twice) and in B, b2 in B; old.sa.test retired in A (twice) and in B

    def test_the_week_is_read_in_fewer_queries(self):
        tiles = overview.kpis([self.pa.pk], None, self.now)
        with CaptureQueriesContext(connection) as ctx:
            overview.what_changed([self.pa.pk], tiles, self.now)
        self.assertLessEqual(len(ctx), 5, [q['sql'][:120] for q in ctx])  # was 8: three log counts, three certificate reads, the example, the newest host


class SharedScanSetsTests(Seeded):
    def build(self, ids):
        return overview.build(ids, live={'hosts': 9, 'exposed_hosts': 4}, now=self.now)

    def payload(self, compute, shared):
        cache.clear()
        with contextlib.ExitStack() as stack:
            if not shared:  # the reads as they were: the current scans read again for every statement
                stack.enter_context(mock.patch.object(current_scans, 'shared_sets', contextlib.nullcontext))
            with CaptureQueriesContext(connection) as ctx:
                payload = snapshot_cache._build(compute, None, '')['payload']
        return payload, len(ctx)

    def test_the_overview_says_the_same_with_one_read_of_the_current_scans(self):
        for ids in ([self.pa.pk], [self.pa.pk, self.pb.pk]):
            with self.subTest(ids=ids), steady_caches():
                old, old_n = self.payload(lambda: self.build(ids), shared=False)
                new, new_n = self.payload(lambda: self.build(ids), shared=True)
                self.assertEqual(_volatile_out(new), _volatile_out(old))
                self.assertLess(new_n, old_n)

    def test_the_headline_counts_say_the_same(self):
        from cveFeed import views
        with steady_caches():
            old, _ = self.payload(views.stats_payload, shared=False)
            new, _ = self.payload(views.stats_payload, shared=True)
        self.assertEqual(new, old)

    def test_the_shared_read_ends_with_the_snapshot(self):
        """A scan that finishes after one snapshot was built is in the next one: the sets are never kept across computations."""
        from startScan.models import Subdomain
        seen = []
        compute = lambda: seen.append(set(Subdomain.objects.filter(scan_history_id__in_current_scans='current').values_list('scan_history_id', flat=True)))  # noqa: E731
        snapshot_cache._build(compute, None, '')
        newer = ScanHistory.objects.create(domain=self.da, scan_type=self.engine, scan_status=2, start_scan_date=self.now, tasks=[])
        Subdomain.objects.create(target_domain=self.da, name='later.sa.test', scan_history=newer)
        snapshot_cache._build(compute, None, '')
        self.assertNotIn(newer.pk, seen[0])
        self.assertIn(newer.pk, seen[1])

    def test_inside_a_snapshot_every_statement_shares_one_read_and_outside_each_reads_its_own(self):
        from startScan.models import Subdomain
        reads = mock.Mock(wraps=current_scans.current_scan_sets)
        with mock.patch.object(current_scans, 'current_scan_sets', reads):
            for _ in range(3):
                list(Subdomain.objects.filter(scan_history_id__in_current_scans='current'))
            self.assertEqual(reads.call_count, 3)
            snapshot_cache._build(lambda: [list(Subdomain.objects.filter(scan_history_id__in_current_scans='current')) for _ in range(3)], None, '')
            self.assertEqual(reads.call_count, 4)

    def test_the_shared_read_is_per_scope(self):
        """Two scopes inside one computation never share the sets: a caller who sees one project gets that project's scans only."""
        from tenancy import scope
        got = {}

        def compute():
            for allowed in ({self.pa.pk}, {self.pb.pk}):
                tokens = scope.set_scope(allowed, None)
                try:
                    got[frozenset(allowed)] = current_scans.sets_for_statement(connection).current
                finally:
                    scope.reset_scope(tokens)
        snapshot_cache._build(compute, None, '')
        self.assertEqual(got[frozenset({self.pa.pk})], {self.scans[self.da].pk})
        self.assertEqual(got[frozenset({self.pb.pk})], {self.scans[self.db].pk})


class OverviewQueryCeilingTests(Seeded):
    """How many queries one Overview costs, cold (every snapshot it reads is built in the request) and warm (served from the cache)."""

    def client_for(self, user):
        from django.test import Client
        c = Client()
        c.force_login(user)
        return c

    def count(self, client, **params):
        with CaptureQueriesContext(connection) as ctx:
            r = client.get('/cve/api/overview', params)
        self.assertEqual(r.status_code, 200, r.content)
        return len(ctx)

    def test_a_cold_build_of_one_project(self):
        with steady_caches():
            self.build_once()
            cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                overview.build([self.pa.pk], live={'hosts': 9, 'exposed_hosts': 4}, now=self.now)
        self.assertLessEqual(len(ctx), 30, '\n'.join(q['sql'][:140] for q in ctx))  # 35 before: the current scans were read again for every statement

    def build_once(self):
        overview.build([self.pa.pk], live={'hosts': 9, 'exposed_hosts': 4}, now=self.now)  # the settings rows read once per process

    def test_the_endpoint_cold_and_warm(self):
        admin = User.objects.create_superuser('ovf-admin', 'a@example.com', 'x')
        c = self.client_for(admin)
        with steady_caches():
            self.count(c, project='sa')
            cache.clear()
            cold = self.count(c, project='sa')
            warm = self.count(c, project='sa')
        self.assertLessEqual(cold, 70, cold)  # every snapshot it reads built in this request: the headline counts, the ranking, the threats, the Sentinel line (79 before)
        self.assertLessEqual(warm, 13, warm)  # 10 before every request saved its session again (one UPDATE, plus a savepoint and its release in a test case)


class SetupQuestionCountsTests(QuestionsBase):
    def states(self):
        return [q['state'] for q in setup_questions.snapshot()['questions']]

    def assert_same(self):
        full = setup_questions.snapshot()
        self.assertEqual(setup_questions.counts(), {k: full[k] for k in ('pending', 'later', 'open')}, self.states())

    def test_the_counts_are_the_snapshot_counts_in_every_state(self):
        self.assert_same()  # nothing answered
        self.connect_ai()
        self.assert_same()
        SetupAnswer.objects.create(key='scan_from', answer='later', answered_by=self.admin, answered_at=timezone.now(), version=1)
        self.assert_same()
        SetupAnswer.objects.create(key='ai_validation', answer='recommend', answered_by=self.admin, answered_at=timezone.now(), version=1)  # older version: asked again
        self.assert_same()
        SetupAnswer.objects.filter(key='ai_validation').update(version=setup_questions.BY_KEY['ai_validation'].version)
        self.assert_same()
        SetupAnswer.objects.create(key='credential_checks', answer='off', answered_by=self.admin, answered_at=timezone.now(), version=1)
        SetupAnswer.objects.create(key='agent_policy', answer='later', answered_by=None, answered_at=timezone.now(), version=1)
        self.assert_same()

    def test_the_reminder_reads_the_states_only(self):
        self.connect_ai()
        setup_questions.reminder()
        with CaptureQueriesContext(connection) as ctx:
            line = setup_questions.reminder()
        self.assertEqual(line['open'], setup_questions.snapshot()['open'])
        self.assertLessEqual(len(ctx), 7, '\n'.join(q['sql'][:140] for q in ctx))  # 11 before

    def test_who_answered_is_read_with_the_answers(self):
        for key in ('scan_from', 'credential_checks', 'agent_policy'):
            SetupAnswer.objects.create(key=key, answer='later', answered_by=self.admin, answered_at=timezone.now(), version=1)
        answers = setup_questions._answers()
        with self.assertNumQueries(0):
            self.assertEqual({a.answered_by.username for a in answers.values()}, {'qadmin'})


class AlertStripTests(QuestionsBase):
    def alerts(self, n):
        now = timezone.now()
        out = []
        for i, code in enumerate(reviewer.OPS_CODES[:n]):
            a = AdminAlert.objects.create(code=code, title=f'alert {i}', first_seen=now - timedelta(hours=i + 1), last_seen=now)
            out.append(a)
            for j in range(2):  # one decision before the alert opened (never its answer) and newer ones after it
                TuningDecision.objects.create(created_at=now - timedelta(hours=i + 2) + timedelta(minutes=j * 90), setting='s', mode='auto', source='ai', action='raise',
                                              signals={'alerts': [code]})
        AdminAlert.objects.create(code='not_a_check', title='other', last_seen=now)
        return out

    def test_the_decisions_are_the_ones_each_alert_read_by_itself(self):
        rows = self.alerts(5)
        self.assertEqual(reviewer.answering_decisions(rows), {a.pk: reviewer.answering_decision(a) for a in rows})
        self.assertTrue(any(reviewer.answering_decisions(rows).values()))
        with self.assertNumQueries(1):
            reviewer.answering_decisions(rows)
        self.assertEqual([a['decision_id'] for a in reviewer.open_alerts()], [reviewer.answering_decision(a) for a in AdminAlert.objects.filter(resolved_at__isnull=True).order_by('-last_seen', '-id')])

    def test_the_alert_strip_poll_has_a_ceiling(self):
        self.alerts(6)
        self.connect_ai()
        self.c.get('/cve/api/settings/alerts')
        with CaptureQueriesContext(connection) as ctx:
            r = self.c.get('/cve/api/settings/alerts')
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(len(r.json()['alerts']), 7)
        self.assertLessEqual(len(ctx), 18, '\n'.join(q['sql'][:140] for q in ctx))  # 24 before: a query per alert, and the questions' choices and facts; 15 before every request saved its session again (one UPDATE, plus a savepoint and its release in a test case)


class SentinelLineTests(Fixture):
    def test_leaving_the_queue_out_changes_nothing_else(self):
        from agentapi import sentinel_broker
        full = sentinel_broker.planner_capacity(())
        short = sentinel_broker.planner_capacity((), queued=False)
        self.assertEqual({k: v for k, v in short.items() if not k.startswith('queued')}, {k: v for k, v in full.items() if not k.startswith('queued')})
        self.assertEqual((short['queued_total'], short['queued_planner'], short['queued']), (0, 0, {}))
        with CaptureQueriesContext(connection) as full_ctx:
            sentinel_broker.planner_capacity(())
        with CaptureQueriesContext(connection) as short_ctx:
            sentinel_broker.planner_capacity((), queued=False)
        self.assertEqual(len(full_ctx) - len(short_ctx), 2)
