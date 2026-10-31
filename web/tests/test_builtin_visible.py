"""The built-in scanner is visible: a ``scanning.builtin_scanner`` block and problem lines in the system status (the lines for an App Admin only), and a
``builtin`` flag on every Sentinel the Sentinels page and the agents list carry. With the switch off nothing is added but ``{'enabled': False}`` and ``False``."""
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import system_status
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelEnrollment
from tests.test_builtin_scanner import BuiltinBase
from tests.test_system_status import call, patched

LINE = 'built-in scanner:'


class BuiltinVisibleBase(BuiltinBase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': '0'})
        env.start()
        self.addCleanup(env.stop)
        self.member = User.objects.create_user('plain-member', password='x')
        _, self.t_root = create_token(self.admin, 'root')
        _, self.t_member = create_token(self.member, 'member')

    def status(self, token):
        a, b, c = patched()
        with a, b, c:
            status, data = call(token, 'GET', '/api/v1/system/status')
        self.assertEqual(status, 200, data)
        return data

    def lines(self, data):
        return [p for p in data['problems'] if p.startswith(LINE)]

    def enroll(self, seen=None):
        from agentapi import builtin_scanner
        builtin_scanner.ensure()
        self.redeem()
        agent = builtin_scanner.builtin_agent()
        Agent.objects.filter(pk=agent.pk).update(last_seen=seen or timezone.now())
        agent.refresh_from_db()
        return agent


class StatusBlockTests(BuiltinVisibleBase):
    def test_with_the_switch_off_the_block_is_just_disabled_and_costs_no_query(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': ''}):
            for token in (self.t_root, self.t_member):
                data = self.status(token)
                self.assertEqual(data['scanning']['builtin_scanner'], {'enabled': False})
                self.assertEqual(self.lines(data), [])
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(system_status._builtin_scanner(True, []), {'enabled': False})
            self.assertEqual(len(queries), 0)

    def test_enrolled_and_live_shows_the_agent_and_is_not_a_problem(self):
        agent = self.enroll()
        data = self.status(self.t_root)
        block = data['scanning']['builtin_scanner']
        self.assertEqual((block['enabled'], block['enrolled'], block['live'], block['agent_id']), (True, True, True, agent.pk))
        self.assertEqual(block['name'], 'CVEngine Scanner')
        self.assertTrue(block['last_seen'])
        self.assertEqual(self.lines(data), [])

    def test_a_member_sees_whether_it_is_up_but_not_which_agent_or_when_it_was_seen(self):
        self.enroll()
        block = self.status(self.t_member)['scanning']['builtin_scanner']
        self.assertEqual(block, {'enabled': True, 'enrolled': True, 'live': True})

    def test_not_enrolled_for_over_ten_minutes_is_an_admin_problem_and_a_members_silence(self):
        from agentapi import builtin_scanner
        builtin_scanner.ensure()  # a blob is written and waits for the scanner
        self.assertEqual(self.lines(self.status(self.t_root)), [])  # just written: the scanner is still starting
        SentinelEnrollment.objects.update(created_at=timezone.now() - timedelta(minutes=9))
        self.assertEqual(self.lines(self.status(self.t_root)), [])
        SentinelEnrollment.objects.update(created_at=timezone.now() - timedelta(minutes=11))
        admin = self.status(self.t_root)
        self.assertEqual(admin['scanning']['builtin_scanner'], {'enabled': True, 'enrolled': False})
        self.assertEqual(len(self.lines(admin)), 1)
        self.assertIn('not enrolled after 11 minutes', self.lines(admin)[0])
        self.assertEqual(admin['overall'], 'degraded')
        member = self.status(self.t_member)
        self.assertEqual(self.lines(member), [])
        self.assertFalse(any('builtin-scanner' in p or 'docker compose' in p for p in member['problems']))
        self.assertEqual(member['scanning']['builtin_scanner'], {'enabled': True, 'enrolled': False})

    def test_nothing_written_yet_claims_no_age(self):
        self.assertFalse(SentinelEnrollment.objects.exists())
        data = self.status(self.t_root)
        self.assertEqual(data['scanning']['builtin_scanner'], {'enabled': True, 'enrolled': False})
        self.assertEqual(self.lines(data), [])

    def test_enrolled_but_silent_is_an_admin_problem_with_how_long(self):
        self.enroll(seen=timezone.now() - timedelta(minutes=10))
        admin = self.status(self.t_root)
        self.assertFalse(admin['scanning']['builtin_scanner']['live'])
        self.assertEqual(len(self.lines(admin)), 1)
        self.assertIn('enrolled but not checking in (last heard from 10 minutes ago)', self.lines(admin)[0])
        member = self.status(self.t_member)
        self.assertEqual(self.lines(member), [])
        self.assertEqual(member['scanning']['builtin_scanner'], {'enabled': True, 'enrolled': True, 'live': False})

    def test_an_agent_that_never_checked_in_is_said_so(self):
        agent = self.enroll()
        Agent.objects.filter(pk=agent.pk).update(last_seen=None)
        self.assertIn('never heard from', self.lines(self.status(self.t_root))[0])


class BuiltinFlagTests(BuiltinVisibleBase):
    """``builtin`` is true for the scanner the server enrolled and for no other Sentinel, whatever it calls itself, in the live page and the agent list."""

    def external(self, name):
        owner = User.objects.create_user(f'owner-{name}', password='x')
        token, _raw = create_token(owner, f'{name}-token')
        return Agent.objects.create(token=token, name=name, kind='scanner', status='active', last_seen=timezone.now(),
                                    scope={'orgs': [], 'projects': [], 'hosts': [], 'instance': True}, capabilities=['nmap'])

    def flags(self, path):
        status, data = call(self.t_root, 'GET', path)
        self.assertEqual(status, 200, data)
        return {row['name']: row['builtin'] for row in data['results']}

    def test_the_sentinels_page_flags_only_the_built_in_scanner(self):
        self.external('CVEngine Scanner look-alike')
        self.enroll()
        self.assertEqual(self.flags('/api/v1/sentinels/live'), {'CVEngine Scanner': True, 'CVEngine Scanner look-alike': False})

    def test_the_agent_list_and_detail_flag_it_too(self):
        other = self.external('outside')
        built = self.enroll()
        self.assertEqual(self.flags('/api/v1/agents?kind=scanner'), {'CVEngine Scanner': True, 'outside': False})
        self.assertIs(call(self.t_root, 'GET', f'/api/v1/agents/{built.pk}')[1]['builtin'], True)
        self.assertIs(call(self.t_root, 'GET', f'/api/v1/agents/{other.pk}')[1]['builtin'], False)

    def test_without_the_scanner_nothing_is_flagged(self):
        self.external('outside')
        self.assertEqual(self.flags('/api/v1/sentinels/live'), {'outside': False})

    def test_a_revoked_built_in_scanner_is_not_flagged(self):
        built = self.enroll()
        Agent.objects.filter(pk=built.pk).update(status='revoked')
        self.assertEqual(self.flags('/api/v1/agents?kind=scanner'), {'CVEngine Scanner': False})

    def test_the_flag_costs_the_agent_list_one_read_not_one_per_row(self):
        self.enroll()
        for n in range(3):
            self.external(f'extra-{n}')

        def count(path):
            with CaptureQueriesContext(connection) as queries:
                call(self.t_root, 'GET', path)
            return len([q for q in queries.captured_queries if 'agentapi_sentinelenrollment' in q['sql']])
        self.assertEqual(count('/api/v1/agents?kind=scanner'), 1)
        self.assertEqual(count('/api/v1/sentinels/live'), 1)
