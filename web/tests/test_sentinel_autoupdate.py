"""cvENGINE keeps Sentinels on the newest version: the decision matrix, its safety rails, the heartbeat field, the audit trail and who may change what."""
import json
import os
import tempfile
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_autoupdate as au
from agentapi import sentinel_contract
from agentapi import sentinel_settings as ss
from agentapi import sentinel_version as sv
from agentapi.models import Agent, SentinelDefaults, SentinelTask
from dashboard.models import AuditLog
from tests.test_agentapi import call
from tests.test_sentinels import build_world, register_sentinel, reset_rates

HEAD = 'a' * 40
OLD = 'b' * 12
NEXT_HEAD = 'c' * 40


class Resp:
    def __init__(self, status=200, body=None, raw=None):
        self.status_code, self._body = status, body or {}
        self.content = raw if raw is not None else json.dumps(self._body).encode()

    def json(self):
        return self._body


def github(head=HEAD, behind=3, contract_version=None, min_supported=None, contract_status=200, compare_status='ahead'):
    """A stand-in for ``requests.get`` answering the calls the check makes: the head, a compare, and the contract file at the head."""
    contract_version = sentinel_contract.version() if contract_version is None else contract_version
    min_supported = sentinel_contract.min_supported() if min_supported is None else min_supported

    def get(url, **kw):
        if '/contents/' in url:
            return Resp(contract_status, raw=json.dumps({'contract_version': contract_version, 'min_supported_contract_version': min_supported}).encode())
        if '/compare/' in url:
            return Resp(200, {'status': compare_status, 'ahead_by': behind, 'commits': []})
        return Resp(200, {'sha': head, 'html_url': 'https://github.com/o/r/commit/' + head, 'commit': {'message': 'Newest', 'committer': {'date': '2026-11-08T00:00:00Z'}}})
    return get


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        reset_rates(self.tokens)
        patcher = mock.patch('agentapi.sentinel_version._ask_for_refresh')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.now = timezone.now()
        self.n = 0

    def sentinel(self, version=OLD):
        self.n += 1
        status, out = register_sentinel(self.tokens['alice'], name=f'au-{self.n}')
        self.assertIn(status, (200, 201), out)
        info = {'contract_version': sentinel_contract.version()}
        if version:
            info['version'] = version
        Agent.objects.filter(pk=out['id']).update(info=info)
        return Agent.objects.get(pk=out['id'])

    def refresh(self, **kw):
        sv.refresh(get=github(**kw))

    def audits(self, action):
        return list(AuditLog.objects.filter(action=action).order_by('id'))

    def task(self, agent, kind, status='running'):
        return SentinelTask.objects.create(agent=agent, project=self.pa, kind=kind, status=status, target={}, claimed_at=timezone.now())


class MatrixTests(Base):
    def test_a_sentinel_behind_the_newest_build_is_asked_with_the_commit(self):
        agent = self.sentinel()
        self.refresh()
        found = au.decide(agent, self.now)
        self.assertEqual((found['action'], found['code'], found['target']), ('request', 'request', HEAD))

    def test_the_default_is_on_and_a_sentinel_following_the_instance_is_automatic(self):
        self.assertTrue(ss.keep_newest())
        self.assertEqual(ss.instance_self_update(), 'automatic')
        SentinelDefaults.objects.update_or_create(pk=1, defaults={'keep_newest': False})
        self.assertEqual(ss.instance_self_update(), 'manual')
        SentinelDefaults.objects.update(self_update='off')
        self.assertEqual(ss.instance_self_update(), 'off')  # an administrator's explicit choice still wins

    def test_nothing_is_asked_when_the_instance_switch_is_off(self):
        agent = self.sentinel()
        self.refresh()
        SentinelDefaults.objects.update_or_create(pk=1, defaults={'keep_newest': False})
        found = au.decide(agent, self.now)
        self.assertEqual((found['action'], found['code']), ('none', 'switched_off'))
        au.consider(agent, self.now)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)
        self.assertEqual(self.audits('sentinel.update_requested'), [])

    def test_a_sentinel_that_opted_out_is_not_asked(self):
        agent = self.sentinel()
        self.refresh()
        self.assertEqual(call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'settings': {'self_update': 'off'}})[0], 200)
        agent.refresh_from_db()
        self.assertEqual(au.decide(agent, self.now)['code'], 'opted_out')
        au.consider(agent, self.now)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)

    def test_a_current_sentinel_is_left_alone_and_a_build_ahead_is_never_downgraded(self):
        current, ahead = self.sentinel(HEAD[:12]), self.sentinel(OLD)
        self.refresh(compare_status='behind', behind=0)  # the head is behind or equal to what ahead runs
        self.assertEqual(au.decide(current, self.now)['code'], 'current')
        self.assertEqual(au.decide(ahead, self.now)['code'], 'current')
        au.consider(ahead, self.now)
        ahead.refresh_from_db()
        self.assertIsNone(ahead.update_requested_at)

    def test_a_build_that_cannot_be_compared_or_has_no_version_is_not_asked(self):
        diverged, unversioned = self.sentinel(OLD), self.sentinel(version='')
        self.refresh(compare_status='diverged', behind=2)
        self.assertEqual(au.decide(diverged, self.now)['action'], 'none')
        self.assertEqual(au.decide(unversioned, self.now)['action'], 'none')

    def test_a_build_whose_contract_the_server_cannot_run_is_skipped_and_says_so(self):
        agent = self.sentinel()
        self.refresh(contract_version=sentinel_contract.version() + 1)
        found = au.decide(agent, self.now)
        self.assertEqual((found['action'], found['code']), ('none', 'waiting_for_server'))
        self.assertEqual(found['text'], 'The newest Sentinel build is newer than this server, waiting for the server update')
        au.consider(agent, self.now)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)

    def test_a_contract_that_could_not_be_read_is_never_taken_as_fine(self):
        agent = self.sentinel()
        self.refresh(contract_status=404)
        self.assertEqual(au.decide(agent, self.now)['code'], 'contract_unknown')
        self.assertIsNone(sv.fetch_contract(HEAD, get=lambda *a, **k: Resp(200, raw=b'not json')))
        bad = json.dumps({'contract_version': True, 'min_supported_contract_version': 1}).encode()
        self.assertIsNone(sv.fetch_contract(HEAD, get=lambda *a, **k: Resp(200, raw=bad)))

    def test_a_heavy_task_holds_the_request_back_and_a_light_one_does_not(self):
        agent = self.sentinel()
        self.refresh()
        light = self.task(agent, 'nmap')
        self.assertEqual(au.decide(agent, self.now)['action'], 'request')
        heavy = self.task(agent, 'openvas')
        found = au.decide(agent, self.now)
        self.assertEqual((found['action'], found['code']), ('wait', 'busy'))
        au.consider(agent, self.now)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)
        heavy.status = 'done'
        heavy.save()
        self.assertEqual(au.decide(agent, self.now)['action'], 'request')
        light.delete()

    def test_one_request_per_sentinel_every_six_hours(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)
        self.assertEqual(len(self.audits('sentinel.update_requested')), 1)
        au.consider(agent, self.now + timedelta(minutes=30))  # still waiting for the answer: not asked again
        self.assertEqual(len(self.audits('sentinel.update_requested')), 1)
        # it comes back on that build, and the next commit lands within the window: not asked before six hours have passed
        Agent.objects.filter(pk=agent.pk).update(info={**agent.info, 'version': HEAD[:12]})
        agent.refresh_from_db()
        au.consider(agent, self.now + timedelta(minutes=40))
        self.assertEqual(au.stored(agent)['status'], 'done')
        self.refresh(head=NEXT_HEAD)
        self.assertEqual(au.decide(agent, self.now + timedelta(hours=1))['code'], 'rate_limited')
        self.assertEqual(au.decide(agent, self.now + timedelta(hours=6, minutes=1))['action'], 'request')

    def test_a_sentinel_that_does_not_come_back_is_flagged_with_the_reason_and_not_asked_again(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)
        agent.refresh_from_db()
        self.assertIsNotNone(agent.update_requested_at)
        late = self.now + timedelta(minutes=au.grace_minutes() + 1)
        au.consider(agent, late)
        agent.refresh_from_db()
        held = au.stored(agent)
        self.assertEqual(held['status'], 'failed')
        self.assertIn('Did not report a newer version within 90 minutes', held['flag'])
        self.assertIsNone(agent.update_requested_at)  # it is no longer told to update
        self.assertEqual(len(self.audits('sentinel.update_flagged')), 1)
        found = au.decide(agent, late + timedelta(days=3))  # days later: the server has stopped asking
        self.assertEqual((found['action'], found['code']), ('none', 'flagged'))
        au.consider(agent, late + timedelta(days=3))
        self.assertEqual(len(self.audits('sentinel.update_requested')), 1)
        shown = au.view(agent, late)
        self.assertTrue(shown['flagged'])
        self.assertIn('Press Update now', shown['text'])

    def test_a_sentinel_that_never_came_back_is_flagged_by_the_sweep_and_shown_flagged_before_it(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)  # it is asked, then goes away and sends no heartbeat at all
        agent.refresh_from_db()
        late = self.now + timedelta(minutes=au.grace_minutes() + 1)
        shown = au.view(agent, late)  # the page says so at once, even before anything wrote it down
        self.assertEqual((shown['code'], shown['flagged']), ('flagged', True))
        self.assertIn('Press Update now', shown['text'])
        self.assertEqual(au.sweep(self.now + timedelta(minutes=10)), 0)  # still inside the grace period: nothing
        self.assertEqual(au.sweep(late), 1)
        agent.refresh_from_db()
        self.assertEqual(au.stored(agent)['status'], 'failed')
        self.assertEqual(len(self.audits('sentinel.update_flagged')), 1)
        self.assertEqual(au.sweep(late + timedelta(hours=1)), 0)  # flagged once, not again

    def test_update_now_clears_the_flag_and_asks_again(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)
        agent.refresh_from_db()
        au.consider(agent, self.now + timedelta(minutes=120))
        agent.refresh_from_db()
        self.assertEqual(au.stored(agent)['status'], 'failed')
        status, out = call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})
        self.assertEqual(status, 200, out)
        agent.refresh_from_db()
        held = au.stored(agent)
        self.assertEqual((held['status'], held['target'], held['flag']), ('requested', HEAD, ''))
        self.assertIsNotNone(agent.update_requested_at)
        self.assertEqual(self.audits('agent.update_requested')[-1].detail['update_to'], HEAD)

    def test_a_sentinel_that_updates_itself_after_a_flag_is_settled(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)
        agent.refresh_from_db()
        au.consider(agent, self.now + timedelta(minutes=120))
        agent.refresh_from_db()
        Agent.objects.filter(pk=agent.pk).update(info={**agent.info, 'version': HEAD[:12]})
        agent.refresh_from_db()
        au.consider(agent, self.now + timedelta(hours=5))
        agent.refresh_from_db()
        self.assertEqual(au.stored(agent)['status'], 'done')

    def test_the_grace_period_is_set_with_an_environment_variable_within_bounds(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_UPDATE_GRACE_MINUTES': '30'}):
            self.assertEqual(au.grace_minutes(), 30)
        for bad in ('0', '99999', 'x', ''):
            with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_UPDATE_GRACE_MINUTES': bad}):
                self.assertEqual(au.grace_minutes(), au.DEFAULT_GRACE_MINUTES)


class HeartbeatTests(Base):
    def beat(self, body=None):
        status, out = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', body)
        self.assertEqual(status, 200, out)
        return out

    def test_the_heartbeat_answer_carries_the_request_with_the_target_and_the_contract_is_unchanged(self):
        agent = self.sentinel()
        self.refresh()
        out = self.beat({'info': {'version': OLD}})
        self.assertTrue(out['update']['requested'])
        self.assertEqual((out['update']['target'], out['update']['reason']), (HEAD, 'newest'))
        self.assertEqual(out['update']['setting'], 'automatic')
        self.assertEqual(out['contract'], sentinel_contract.reply())  # no contract bump: the field is an optional key of an object clients already read
        self.assertEqual(len(self.audits('sentinel.update_requested')), 1)
        entry = self.audits('sentinel.update_requested')[0]
        self.assertEqual((entry.detail['update_to'], entry.detail['version'], entry.detail['automatic']), (HEAD, OLD, True))
        self.assertEqual(entry.target, agent.name)
        self.assertEqual(entry.actor_name, '')  # the server itself, not a person
        again = self.beat({'info': {'version': OLD}})
        self.assertEqual(again['update']['target'], HEAD)
        self.assertEqual(len(self.audits('sentinel.update_requested')), 1)

    def test_a_current_sentinel_gets_no_request_and_no_target(self):
        self.sentinel(HEAD[:12])
        self.refresh()
        out = self.beat({'info': {'version': HEAD[:12]}})
        self.assertFalse(out['update']['requested'])
        self.assertNotIn('target', out['update'])

    def test_a_sentinel_that_comes_back_on_the_new_build_closes_the_request(self):
        agent = self.sentinel()
        self.refresh()
        self.beat({'info': {'version': OLD}})
        out = self.beat({'info': {'version': HEAD[:12], 'update': {'status': 'done'}}})
        self.assertFalse(out['update']['requested'])
        agent.refresh_from_db()
        self.assertEqual(au.stored(agent)['status'], 'done')

    def test_the_detail_shows_running_newest_and_the_request(self):
        agent = self.sentinel()
        self.refresh()
        self.beat({'info': {'version': OLD}})
        status, detail = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual(status, 200)
        shown = detail['auto_update']
        self.assertEqual((shown['code'], shown['running'], shown['newest']), ('requested', OLD, HEAD[:12]))
        self.assertTrue(shown['requested_at'])

    def test_the_built_in_scanner_is_asked_through_the_host_watcher_not_the_heartbeat(self):
        agent = self.sentinel()
        self.refresh()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(au, '_is_builtin', return_value=True), mock.patch.object(au, '_host_watcher_alive', return_value=True), \
                mock.patch('cveFeed.updater._file', side_effect=lambda name: os.path.join(tmp, name)):
            au.consider(agent, self.now)
            with open(os.path.join(tmp, au.HOST_REQUEST_FILE)) as handle:
                wrote = json.loads(handle.read())
        self.assertEqual(wrote['target'], HEAD)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)  # the built-in scanner's daemon is never told to update itself
        self.assertEqual(au.stored(agent)['host'], True)
        self.assertEqual(self.audits('sentinel.update_requested')[0].detail['how'], 'host watcher')

    def test_without_a_listening_host_watcher_the_built_in_scanner_is_not_asked(self):
        agent = self.sentinel()
        self.refresh()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(au, '_is_builtin', return_value=True), mock.patch.object(au, '_host_watcher_alive', return_value=False), \
                mock.patch('cveFeed.updater._file', side_effect=lambda name: os.path.join(tmp, name)):
            found = au.consider(agent, self.now)
            self.assertFalse(os.path.exists(os.path.join(tmp, au.HOST_REQUEST_FILE)))
        self.assertEqual(found['code'], 'host_watcher')
        self.assertEqual(self.audits('sentinel.update_requested'), [])


class PermissionTests(Base):
    def test_only_an_app_admin_changes_the_instance_switch_and_it_is_audited(self):
        for who, expected in (('alice', 403), ('dana', 403), ('root', 200)):
            status, out = call(self.tokens[who], 'PUT', '/api/v1/sentinels/defaults', {'keep_newest': False})
            self.assertEqual(status, expected, (who, out))
        self.assertFalse(SentinelDefaults.current().keep_newest)
        entry = AuditLog.objects.filter(action='sentinel.defaults').latest('id')
        self.assertEqual(entry.detail['keep_newest'], {'before': True, 'after': False})
        self.assertEqual(call(self.tokens['alice'], 'GET', '/api/v1/sentinels/defaults')[1]['keep_newest'], False)

    def test_the_switch_must_be_a_boolean(self):
        for bad in ('yes', 1, None, [], {}):
            self.assertEqual(call(self.tokens['root'], 'PUT', '/api/v1/sentinels/defaults', {'keep_newest': bad})[0], 400, bad)
        self.assertTrue(SentinelDefaults.current().keep_newest)

    def test_update_now_needs_the_right_to_manage_the_sentinel(self):
        agent = self.sentinel()
        self.assertIn(call(self.tokens['alice'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})[0], (403, 404))
        self.assertEqual(call(self.tokens['dana'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})[0], 200)
        self.assertEqual(call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})[0], 200)

    def test_a_sentinel_cannot_write_the_servers_record_about_it(self):
        agent = self.sentinel()
        self.refresh()
        au.consider(agent, self.now)
        agent.refresh_from_db()
        before = au.stored(agent)
        call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'version': OLD, 'auto_update': {'status': 'done', 'target': 'f' * 40}}})
        agent.refresh_from_db()
        self.assertEqual(au.stored(agent), before)
