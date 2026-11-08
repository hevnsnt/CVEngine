"""Whether a Sentinel runs the current Sentinel client: the cached check of GitHub, the states, and that nothing asks GitHub while a page is built."""
import os
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase

from agentapi import sentinel_version as sv
from agentapi.models import Agent
from agentapi.auth import create_token
from django.contrib.auth.models import User
from django.utils import timezone

HEAD = 'a' * 40
OLD = 'b' * 12


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


def github(head=HEAD, behind=3, status=200, compare_status='ahead'):
    """A stand-in for ``requests.get`` answering the two calls the check makes."""
    calls = []

    def get(url, **kw):
        calls.append(url)
        if '/compare/' in url:
            return Resp(200, {'status': compare_status, 'ahead_by': behind, 'commits': [{'sha': 'c' * 40, 'commit': {'message': 'x'}}]})
        return Resp(status, {'sha': head, 'html_url': 'https://github.com/o/r/commit/' + head, 'commit': {'message': 'Latest change\n\nbody', 'committer': {'date': '2026-10-28T00:00:00Z'}}})
    get.calls = calls
    return get


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        user = User.objects.create_user('ver-owner', password='x')
        self.n = 0
        self.user = user
        patcher = mock.patch('agentapi.sentinel_version._ask_for_refresh')
        self.asked = patcher.start()
        self.addCleanup(patcher.stop)

    def agent(self, version=None, **kw):
        self.n += 1
        token, _raw = create_token(self.user, f'ver-{self.n}')
        info = {'version': version} if version else {}
        return Agent.objects.create(token=token, name=f'v{self.n}', kind='scanner', status='active', capabilities=['nmap'], info=info,
                                    last_seen=timezone.now(), **kw)


class StateTests(Base):
    def test_a_sentinel_at_the_head_is_current_and_one_behind_says_how_far(self):
        self.agent(HEAD[:12])
        self.agent(OLD)
        sv.refresh(get=github(behind=3))
        current, behind = (sv.state(a) for a in Agent.objects.order_by('id'))
        self.assertEqual((current['status'], current['behind_by'], current['latest']), ('current', 0, HEAD[:12]))
        self.assertEqual((behind['status'], behind['behind_by']), ('behind', 3))
        self.assertIn('3 commits behind the latest', behind['detail'])
        self.assertEqual(behind['latest_message'], 'Latest change')

    def test_one_commit_behind_is_singular_and_the_self_update_setting_is_named(self):
        self.agent(OLD)
        sv.refresh(get=github(behind=1))
        out = sv.state(Agent.objects.get(), 'manual')
        self.assertIn('1 commit behind', out['detail'])
        self.assertIn('self-update is manual', out['detail'])

    def test_a_build_ahead_of_the_head_is_current(self):
        self.agent(OLD)
        sv.refresh(get=github(compare_status='behind', behind=0))
        self.assertEqual(sv.state(Agent.objects.get())['status'], 'current')

    def test_no_reported_version_is_unknown_with_the_words_the_page_shows(self):
        self.agent(None)
        sv.refresh(get=github())
        out = sv.state(Agent.objects.get())
        self.assertEqual(out['status'], 'unknown')
        self.assertIn('unknown (built without the updater)', out['detail'])

    def test_a_version_that_is_not_a_commit_cannot_be_compared(self):
        self.agent('1.4.0')
        sv.refresh(get=github())
        self.assertIn('not a commit', sv.state(Agent.objects.get())['detail'])

    def test_before_the_first_check_it_is_unknown_and_a_refresh_is_asked_for_not_run(self):
        self.agent(OLD)
        with mock.patch('agentapi.sentinel_version.updater.fetch_latest', side_effect=AssertionError('no request while a page is built')):
            out = sv.state(Agent.objects.get())
        self.assertEqual(out['status'], 'unknown')
        self.assertIn('not been checked yet', out['detail'])
        self.asked.assert_called()

    def test_a_failed_check_keeps_the_last_known_head_and_says_why(self):
        self.agent(OLD)
        sv.refresh(get=github(behind=2))
        sv.refresh(get=github(status=403))
        out = sv.state(Agent.objects.get())
        self.assertEqual((out['status'], out['behind_by']), ('behind', 2))
        self.assertIn('the last check failed', out['detail'])

    def test_a_failed_first_check_is_unknown_with_the_reason(self):
        self.agent(OLD)
        sv.refresh(get=github(status=404))
        out = sv.state(Agent.objects.get())
        self.assertEqual(out['status'], 'unknown')
        self.assertIn('not found', out['detail'])

    def test_the_check_can_be_switched_off_and_then_asks_nothing(self):
        self.agent(OLD)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_VERSION_CHECK': 'off'}):
            get = github()
            sv.refresh(get=get)
            out = sv.state(Agent.objects.get())
        self.assertEqual(get.calls, [])
        self.assertEqual(out['status'], 'unknown')
        self.assertIn('switched off', out['detail'])

    def test_the_repository_and_branch_are_validated_settings(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_REPO': 'owner/other', 'CVENGINE_SENTINEL_BRANCH': 'release'}):
            self.assertEqual((sv.repo(), sv.branch()), ('owner/other', 'release'))
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_REPO': 'not a repo; rm -rf', 'CVENGINE_SENTINEL_BRANCH': '../x'}):
            self.assertEqual((sv.repo(), sv.branch()), (sv.DEFAULT_REPO, sv.DEFAULT_BRANCH))

    def test_only_commit_looking_versions_are_compared_and_a_revoked_sentinel_is_skipped(self):
        self.agent(OLD)
        self.agent('1.4.0')
        revoked = self.agent('d' * 12)
        Agent.objects.filter(pk=revoked.pk).update(status='revoked')
        self.assertEqual(sv.reported_versions(), [OLD])

    def test_one_comparison_per_distinct_version(self):
        self.agent(OLD)
        self.agent(OLD)
        get = github()
        sv.refresh(get=get)
        self.assertEqual(sum('/compare/' in u for u in get.calls), 1)


class SurfaceTests(Base):
    def test_the_agent_row_carries_the_state_and_the_task_is_scheduled(self):
        from agentapi import agent_broker as broker
        from django_celery_beat.models import PeriodicTask
        agent = self.agent(OLD)
        sv.refresh(get=github(behind=2))
        row = broker.agent_dict(Agent.objects.select_related('token__user').get(pk=agent.pk), counts={})
        self.assertEqual((row['version_state']['status'], row['version_state']['behind_by']), ('behind', 2))
        task = PeriodicTask.objects.get(name='cvengine-sentinel-version-check')
        self.assertEqual((task.task, task.enabled), ('refresh_sentinel_version', True))

    def test_the_celery_task_refreshes_and_is_exempt_from_a_scanning_pause(self):
        from cveFeed import scan_control, tasks
        self.assertIn('refresh_sentinel_version', scan_control.PAUSE_EXEMPT_TASKS)
        with mock.patch('agentapi.sentinel_version.updater.fetch_latest', return_value={'sha': HEAD, 'message': 'm', 'url': '', 'date': '', 'behind_by': None, 'commits': []}):
            out = tasks.refresh_sentinel_version()
        self.assertEqual(out['latest'], HEAD[:12])


class StaleVerdictTests(Base):
    """The live defect: a scanner that updated to the newest build was shown as behind the (older) head cached before it updated."""

    def set_since(self, agent, when):
        agent.info = {**agent.info, 'version_since': when.isoformat()}
        agent.save(update_fields=['info'])

    def test_after_an_update_the_verdict_for_the_old_commit_is_not_shown_for_the_new_one(self):
        agent = self.agent(OLD)
        sv.refresh(get=github(behind=3))
        self.assertEqual(sv.state(agent)['status'], 'behind')
        from agentapi import sentinel_settings
        sentinel_settings.record_info(agent, {'version': 'c' * 12})
        agent.refresh_from_db()
        out = sv.state(agent)
        self.assertEqual((out['status'], out['behind_by']), ('unknown', None))
        self.assertIsNone(cache.get(sv.verdict_key(OLD)), 'the verdict of the commit it left is dropped at once')
        self.asked.assert_called()

    def test_a_build_newer_than_the_cached_head_is_not_behind_whatever_was_cached(self):
        agent = self.agent(OLD)
        sv.refresh(get=github(head=HEAD, behind=3))  # cached head HEAD; OLD behind by 3
        newer = 'e' * 12
        Agent.objects.filter(pk=agent.pk).update(info={'version': newer, 'version_since': (timezone.now() + timedelta(minutes=5)).isoformat()})
        out = sv.state(Agent.objects.get(pk=agent.pk))
        self.assertNotEqual(out['status'], 'behind')
        self.assertIsNone(out['behind_by'])
        # the background refresh then compares exactly this commit: the cached head is a parent of it, so it is current
        sv.refresh(get=github(head=HEAD, compare_status='behind', behind=0), now=timezone.now() + timedelta(minutes=10))
        self.assertEqual(sv.state(Agent.objects.get(pk=agent.pk))['status'], 'current')

    def test_a_head_checked_before_the_version_changed_asks_for_a_new_check(self):
        agent = self.agent(OLD)
        sv.refresh(get=github(behind=3), now=timezone.now() - timedelta(hours=2))
        self.set_since(agent, timezone.now())
        self.asked.reset_mock()
        out = sv.state(Agent.objects.get(pk=agent.pk))
        self.assertEqual(out['status'], 'unknown')
        self.asked.assert_called()

    def test_installed_equal_to_the_head_is_current(self):
        self.agent(HEAD[:12])
        sv.refresh(get=github())
        self.assertEqual(sv.state(Agent.objects.get())['status'], 'current')

    def test_the_verdict_is_per_installed_commit_and_per_branch(self):
        self.assertNotEqual(sv.verdict_key(OLD), sv.verdict_key('d' * 12))
        self.assertNotEqual(sv.verdict_key(OLD), sv.verdict_key(OLD, branch_name='other'))
        self.assertNotEqual(sv.latest_key(), sv.latest_key(branch_name='other'))

    def test_an_unknown_remote_stays_unknown(self):
        self.agent(OLD)
        sv.refresh(get=github(status=500))
        self.assertEqual(sv.state(Agent.objects.get())['status'], 'unknown')

    def test_a_compare_error_is_not_behind(self):
        self.agent(OLD)

        def get(url, **kw):
            if '/compare/' in url:
                return Resp(500)
            return github()(url, **kw)
        sv.refresh(get=get)
        out = sv.state(Agent.objects.get())
        self.assertEqual((out['status'], out['behind_by']), ('unknown', None))

    def test_a_commit_github_never_saw_or_a_diverged_one_is_not_behind(self):
        self.agent(OLD)
        self.agent('d' * 12)

        def get(url, **kw):
            if '/compare/' in url:
                return Resp(404) if 'd' * 12 in url else Resp(200, {'status': 'diverged', 'ahead_by': 2, 'commits': []})
            return github()(url, **kw)
        sv.refresh(get=get)
        for agent in Agent.objects.all():
            self.assertEqual(sv.state(agent)['status'], 'unknown')

    def test_the_time_the_head_was_checked_is_reported(self):
        self.agent(OLD)
        sv.refresh(get=github())
        self.assertTrue(sv.state(Agent.objects.get())['checked_at'])
