"""The record a person reads (AI maintainer WP7): the decisions with their outcomes over REST and MCP (filters by outcome and source, the alert codes a
decision answered), ``get_maintainer_report`` (the last 24 hours in one bounded answer, App Admin only), and the link from an open alert to the
decision that answered it."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import autotune, maintainer_report, reviewer, autotune_signals as signals
from cveFeed.models import AdminAlert, TuningDecision
from dashboard.models import Org, OrgMembership
from tests.test_agentapi import call, tool_call
from tests.test_autotune import Isolated, history

REPORT_KEYS = {'at', 'window_hours', 'tuning', 'signals', 'sentinels', 'alerts', 'decisions', 'decisions_total', 'decisions_shown', 'counts'}


def decision(ago_minutes=5, **over):
    fields = dict(setting='discovery_concurrency', old_value=12, new_value=14, mode='auto', source='controller', action='raise', layer='auto', applied=True,
                  phase='probe', reason='two healthy hours: probed 12 to 14', signals={'summary': {'measurements': 3}})
    fields.update(over)
    row = TuningDecision.objects.create(**fields)
    TuningDecision.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(minutes=ago_minutes))
    return row


class Base(Isolated, TestCase):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('rec_root', 'r@x.io', 'x')
        self.member = User.objects.create_user('rec_member', password='x')
        org = Org.objects.create(name='T', slug='rec-org')
        OrgMembership.objects.create(user=self.member, org=org, role='admin')
        _, self.rw = create_token(self.root, 'rw')
        _, self.ro = create_token(self.root, 'ro', read_only=True)
        _, self.other = create_token(self.member, 'm')


class DecisionsTests(Base):
    def setUp(self):
        super().setUp()
        self.helped = decision(60, outcome='helped', outcome_detail='scans waiting in the discovery queue: 12 before, 3 after',
                               expected='discovery_queue', baseline={'metric': 'discovery_queue', 'value': 12.0, 'after': {'metric': 'discovery_queue', 'value': 3.0}},
                               verified_at=timezone.now())
        self.agent = decision(50, source='agent', outcome='no_effect', outcome_detail='x')
        self.pending = decision(40, verify_at=timezone.now() + timedelta(minutes=20))
        self.suggested = decision(30, applied=False, mode='suggest', layer='')

    def ids(self, data):
        return [d['id'] for d in data['results']]

    def test_every_decision_carries_its_outcome_fields_over_rest_and_mcp(self):
        status, rest = call(self.rw, 'GET', '/api/v1/tuning/decisions')
        self.assertEqual(status, 200)
        error, mcp = tool_call(self.rw, 'list_tuning_decisions')
        self.assertFalse(error)
        self.assertEqual(rest, mcp)
        for key in ('expected', 'baseline', 'verify_at', 'verified_at', 'outcome', 'outcome_detail', 'alerts', 'undoes'):
            self.assertIn(key, rest['results'][0], key)
        by = {d['id']: d for d in rest['results']}
        self.assertEqual((by[self.helped.pk]['outcome'], by[self.helped.pk]['baseline']['after']['value']), ('helped', 3.0))
        self.assertIsNone(by[self.pending.pk]['outcome'])
        self.assertIsNotNone(by[self.pending.pk]['verify_at'])

    def test_filter_by_outcome_and_by_source_keeps_paging_and_the_setting_filter(self):
        for tool, run in (('rest', lambda q: call(self.rw, 'GET', f'/api/v1/tuning/decisions?{q}')[1]),
                          ('mcp', lambda q: tool_call(self.rw, 'list_tuning_decisions', dict(p.split('=') for p in q.split('&')))[1])):
            self.assertEqual(self.ids(run('outcome=helped')), [self.helped.pk], tool)
            self.assertEqual(self.ids(run('outcome=pending')), [self.pending.pk], tool)  # not judged yet
            self.assertEqual(self.ids(run('source=agent')), [self.agent.pk], tool)
            self.assertEqual(self.ids(run('source=controller&outcome=helped')), [self.helped.pk], tool)
            page = run('limit=2&offset=1')
            self.assertEqual((len(page['results']), page['has_more']), (2, True), tool)
            self.assertEqual(self.ids(run('setting=heavy.nmap')), [], tool)

    def test_a_filter_value_that_means_nothing_is_a_400_not_an_empty_list(self):
        self.assertEqual(call(self.rw, 'GET', '/api/v1/tuning/decisions?outcome=great')[0], 400)
        error, _ = tool_call(self.rw, 'list_tuning_decisions', {'outcome': 'great'})
        self.assertTrue(error)

    def test_only_an_app_admin_reads_them(self):
        self.assertEqual(call(self.other, 'GET', '/api/v1/tuning/decisions')[0], 403)
        self.assertEqual(call(self.ro, 'GET', '/api/v1/tuning/decisions')[0], 200)
        self.assertTrue(tool_call(self.other, 'list_tuning_decisions')[0])

    def test_a_revert_row_says_which_decision_it_undid_and_the_alerts_a_change_answered_are_listed(self):
        revert = decision(10, action='revert', phase='verify', pressure=True, outcome='reverted', signals={'verified_decision': self.helped.pk})
        answered = decision(9, signals={'summary': {}, 'alerts': ['memory', 'queue_starvation']})
        data = call(self.rw, 'GET', '/api/v1/tuning/decisions')[1]
        by = {d['id']: d for d in data['results']}
        self.assertEqual(by[revert.pk]['undoes'], self.helped.pk)
        self.assertEqual(by[answered.pk]['alerts'], ['memory', 'queue_starvation'])
        self.assertEqual(by[self.helped.pk]['alerts'], [])


class ReportTests(Base):
    def setUp(self):
        super().setUp()
        self.recent = decision(30, outcome='helped', outcome_detail='ok', signals={'alerts': ['memory']})
        self.old = decision(60 * 30)  # 30 hours ago: outside the window
        self.suggested = decision(20, applied=False, mode='suggest', layer='')

    def report(self, token=None):
        status, data = call(token or self.rw, 'GET', '/api/v1/tuning/report')
        self.assertEqual(status, 200, data)
        return data

    def test_the_last_24_hours_in_one_answer_and_the_same_from_rest_and_mcp(self):
        data = self.report()
        self.assertEqual(set(data), REPORT_KEYS)
        self.assertEqual(data['window_hours'], 24)
        self.assertEqual({d['id'] for d in data['decisions']}, {self.recent.pk, self.suggested.pk})  # the old one is outside the window
        self.assertEqual(data['decisions_total'], 2)
        self.assertEqual(data['counts']['helped'], 1)
        self.assertEqual(data['counts']['recommended'], 1)
        self.assertEqual(set(data['tuning']), {'mode', 'effective_mode', 'killed', 'agent_policy', 'pinned'})
        self.assertEqual(data['tuning']['mode'], 'auto')
        error, mcp = tool_call(self.rw, 'get_maintainer_report')
        self.assertFalse(error)
        self.assertEqual(set(mcp), REPORT_KEYS)
        self.assertEqual([d['id'] for d in mcp['decisions']], [d['id'] for d in data['decisions']])

    def test_it_is_for_an_app_admin_and_read_only_tokens_may_read_it(self):
        self.assertEqual(call(self.other, 'GET', '/api/v1/tuning/report')[0], 403)
        self.assertTrue(tool_call(self.other, 'get_maintainer_report')[0])
        self.assertEqual(call(self.ro, 'GET', '/api/v1/tuning/report')[0], 200)
        self.assertFalse(tool_call(self.ro, 'get_maintainer_report')[0])

    def test_open_alerts_with_stale_marked_and_the_decision_that_answered_each(self):
        now = timezone.now()
        AdminAlert.objects.create(code='memory', severity='warning', title='A lane is near its limit', detail='d', first_seen=now - timedelta(hours=3), last_seen=now - timedelta(minutes=2))
        AdminAlert.objects.create(code='queue_starvation', severity='warning', title='Scans wait', detail='d', first_seen=now - timedelta(hours=5), last_seen=now - timedelta(hours=3))
        AdminAlert.objects.create(code='sentinels_idle', severity='info', title='Sentinels idle', detail='d', first_seen=now - timedelta(hours=1), last_seen=now - timedelta(minutes=1),
                                  dismissed_at=now, dismissed_digest='x', digest='x')
        data = self.report()
        by = {a['code']: a for a in data['alerts']}
        self.assertEqual(set(by), {'memory', 'queue_starvation'})  # the dismissed one is not shown
        self.assertEqual((by['memory']['stale'], by['memory']['decision_id']), (False, self.recent.pk))
        self.assertEqual((by['queue_starvation']['stale'], by['queue_starvation']['decision_id']), (True, None))
        self.assertEqual(set(by['memory']), {'id', 'code', 'severity', 'title', 'stale', 'age_minutes', 'decision_id'})

    def test_it_is_bounded_and_says_so(self):
        for i in range(maintainer_report.MAX_DECISIONS + 25):
            decision(1 + i % 50, reason='r' * 300, outcome_detail='d' * 300, signals={'summary': {'x': 'y' * 500}})
        data = self.report()
        self.assertEqual(len(data['decisions']), maintainer_report.MAX_DECISIONS)
        self.assertEqual(data['decisions_shown'], maintainer_report.MAX_DECISIONS)
        self.assertEqual(data['decisions_total'], maintainer_report.MAX_DECISIONS + 25 + 2)
        self.assertLess(len(str(data)), 120_000)
        self.assertNotIn('signals', data['decisions'][0])  # the raw measurements stay out of the report
        self.assertNotIn('baseline', data['decisions'][0])
        newest = [d['at'] for d in data['decisions']]
        self.assertEqual(newest, sorted(newest, reverse=True))

    def test_pinned_settings_say_by_whom_and_signals_say_what_they_know(self):
        with mock.patch.object(autotune, 'status', return_value={**autotune.status(), 'pinned': [{'setting': 'heavy.nmap', 'label': 'nmap', 'value': 2, 'by': 'bill', 'from': 'saved'}]}):
            data = self.report()
        self.assertEqual(data['tuning']['pinned'], [{'setting': 'heavy.nmap', 'label': 'nmap', 'value': 2, 'by': 'bill', 'from': 'saved'}])
        self.assertIn('unknown', data['signals'])
        self.assertEqual(set(data['sentinels']), {'live', 'live_remote', 'slots'})
        self.assertNotIn('host', str(data['sentinels']))

    def test_no_host_name_or_tenant_data_is_in_it(self):
        text = str(self.report())
        for word in ('hostname', 'project', 'tenant', 'finding'):
            self.assertNotIn(word, text)


class AlertLinkTests(Base):
    def test_open_alerts_carry_the_decision_that_answered_them_and_only_a_later_one(self):
        now = timezone.now()
        alert = AdminAlert.objects.create(code='memory', severity='warning', title='t', detail='d', first_seen=now - timedelta(hours=2), last_seen=now)
        before = decision(60 * 5, signals={'alerts': ['memory']})  # before the alert opened: not an answer to it
        self.assertIsNone(reviewer.open_alerts()[0]['decision_id'])
        later = decision(30, signals={'alerts': ['memory']})
        decision(10, signals={'alerts': ['queue_starvation']})  # another code
        self.assertEqual(reviewer.open_alerts()[0]['decision_id'], later.pk)
        newer = decision(5, signals={'alerts': ['memory', 'queue_starvation']})
        self.assertEqual(reviewer.open_alerts()[0]['decision_id'], newer.pk)
        self.assertNotEqual(before.pk, newer.pk)
        AdminAlert.objects.create(code='nuclei_templates', severity='info', title='t2', detail='d', first_seen=now - timedelta(hours=2), last_seen=now)
        self.assertTrue(all('decision_id' in a for a in reviewer.open_alerts()))
        self.assertTrue(alert.pk)

    def test_a_round_that_changes_something_records_the_alert_codes_that_were_open(self):
        AdminAlert.objects.create(code='memory', severity='warning', title='t', detail='d')
        AdminAlert.objects.create(code='ai_errors', severity='warning', title='t', detail='d')  # not a throughput problem
        AdminAlert.objects.create(code='queue_starvation', severity='warning', title='t', detail='d', resolved_at=timezone.now())  # resolved
        self.assertEqual(autotune.open_alert_codes(), ['memory'])
        now = timezone.now()
        samples = history(1, end=now.timestamp())
        with mock.patch.object(signals, 'collect', return_value=samples[-1]):
            autotune.run(now)
        row = TuningDecision.objects.filter(applied=True).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.signals['alerts'], ['memory'])
