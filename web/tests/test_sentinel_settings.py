"""A Sentinel's settings: set where it runs or from cvENGINE, the most recent change wins."""
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from agentapi import sentinel_settings as ss
from agentapi.models import Agent
from tests.test_agentapi import call
from tests.test_sentinels import build_world, register_sentinel, reset_rates


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_world(cls)

    def setUp(self):
        reset_rates(self.tokens)

    def sentinel(self, settings=None, **extra):
        status, out = register_sentinel(self.tokens['alice'], **({'settings': settings} if settings is not None else {}), **extra)
        self.assertIn(status, (200, 201), out)
        return Agent.objects.get(pk=out['id']), out

    def manage(self, agent, settings):
        return call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'settings': settings})


class ReportedTests(Base):
    def test_a_sentinel_reports_its_own_settings_and_is_told_the_effective_ones(self):
        agent, out = self.sentinel({'network': 'internal', 'profile': 'light', 'disabled_kinds': ['wpscan'], 'max_concurrent': 4})
        self.assertEqual(out['settings']['values'], {'network': 'external', 'profile': 'light', 'disabled_kinds': ['wpscan'], 'max_concurrent': 4, 'self_update': 'manual'})  # it says internal, but only the server decides that
        self.assertEqual(out['settings']['detail']['network']['value'], 'external')
        self.assertEqual(out['settings']['detail']['network']['server_grant'], 'external')
        self.assertEqual(out['settings']['detail']['network']['machine_value'], 'internal')
        self.assertTrue(out['settings']['detail']['network']['limited_by_server'])
        self.assertEqual({k: v['source'] for k, v in out['settings']['detail'].items() if k != 'network'},
                         {k: 'sentinel' for k in out['settings']['detail'] if k != 'network'})
        agent.refresh_from_db()
        self.assertEqual(agent.reported_settings['network']['value'], 'internal')

    def test_bad_settings_are_refused_and_nothing_is_stored(self):
        for bad in ({'network': 'dmz'}, {'profile': 'huge'}, {'disabled_kinds': ['rm -rf']}, {'max_concurrent': 99}, {'max_concurrent': True},
                    {'colour': 'red'}, {}, 'x'):
            status, out = call(self.tokens['alice'], 'PUT', '/api/v1/sentinel', {'name': 's', 'scope': {'projects': ['sen-a']}, 'settings': bad})
            self.assertEqual(status, 400, bad)
        self.assertFalse(Agent.objects.filter(kind='scanner').exists())

    def test_only_a_changed_value_moves_its_time_forward(self):
        agent, _ = self.sentinel({'network': 'external'})
        agent.refresh_from_db()
        first = agent.reported_settings['network']['at']
        self.sentinel({'network': 'external'})  # restart with the same configuration
        agent.refresh_from_db()
        self.assertEqual(agent.reported_settings['network']['at'], first)
        self.sentinel({'network': 'internal'})
        agent.refresh_from_db()
        self.assertNotEqual(agent.reported_settings['network']['at'], first)

    def test_a_registration_without_settings_changes_nothing(self):
        agent, _ = self.sentinel({'network': 'internal'})
        status, out = call(self.tokens['alice'], 'PUT', '/api/v1/sentinel', {'name': 'sentinel-1'})
        self.assertEqual(status, 200)
        self.assertEqual(out['settings']['values'], {'network': 'external', 'self_update': 'manual'})  # its own claim of internal is not honoured


class MostRecentWinsTests(Base):
    def test_an_admin_internal_grant_is_capped_by_the_machine_until_it_changes(self):
        agent, _ = self.sentinel({'network': 'external', 'max_concurrent': 2})
        status, out = self.manage(agent, {'network': 'internal'})
        self.assertEqual(status, 200, out)
        self.assertEqual(out['settings']['network']['source'], 'sentinel')
        self.assertEqual(out['settings']['network']['server_grant'], 'internal')
        self.assertEqual(out['settings']['network']['value'], 'external')
        self.assertEqual(out['settings']['network']['grant_by'], 's_root')
        self.assertTrue(out['settings']['network']['managed'])
        self.assertEqual(out['settings']['max_concurrent']['source'], 'sentinel')  # untouched settings stay the Sentinel's
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')
        self.assertEqual(status, 200, beat)
        self.assertEqual(beat['settings']['values'], {'network': 'external', 'max_concurrent': 2, 'self_update': 'manual'})
        self.assertEqual(beat['settings']['rev'], ss.revision({'network': 'external', 'max_concurrent': 2, 'self_update': 'manual'}))
        ss.record_reported(agent, {'network': 'internal'})
        agent.refresh_from_db()
        self.assertEqual(ss.effective(agent)['network'], 'internal')

    def test_a_restart_with_an_unchanged_configuration_does_not_override_the_dashboard(self):
        agent, _ = self.sentinel({'network': 'external'})
        self.manage(agent, {'network': 'internal'})
        _, out = self.sentinel({'network': 'external'})  # the machine still says external, as it always did
        self.assertEqual(out['settings']['values']['network'], 'external')
        self.assertEqual(out['settings']['detail']['network']['server_grant'], 'internal')

    def test_a_change_made_on_the_machine_after_the_dashboard_edit_wins(self):
        agent, _ = self.sentinel({'network': 'external', 'max_concurrent': 2})
        self.manage(agent, {'network': 'internal', 'max_concurrent': 8})
        later = timezone.now() + timedelta(minutes=5)
        agent.refresh_from_db()
        ss.record_reported(agent, {'network': 'external', 'max_concurrent': 3}, now=later)  # the operator changed the machine's concurrency after
        agent.refresh_from_db()
        self.assertEqual({k: v['source'] for k, v in ss.detail(agent).items()}, {'network': 'sentinel', 'max_concurrent': 'sentinel'})
        self.assertEqual(ss.effective(agent), {'network': 'external', 'max_concurrent': 3, 'self_update': 'manual'})

    def test_clearing_a_server_value_hands_the_setting_back_to_the_sentinel(self):
        agent, _ = self.sentinel({'max_concurrent': 3})
        self.manage(agent, {'max_concurrent': 8})
        status, out = self.manage(agent, {'max_concurrent': None})
        self.assertEqual(status, 200)
        self.assertEqual(out['settings']['max_concurrent'], {**out['settings']['max_concurrent'], 'value': 3, 'source': 'sentinel'})

    def test_a_setting_only_the_server_has_applies(self):
        agent, _ = self.sentinel()
        self.manage(agent, {'disabled_kinds': ['openvas', 'wpscan', 'openvas']})
        agent.refresh_from_db()
        self.assertEqual(ss.effective(agent), {'disabled_kinds': ['openvas', 'wpscan'], 'self_update': 'manual', 'network': 'external'})


class AdminTests(Base):
    def test_only_an_administrator_of_the_owner_may_edit_and_each_edit_is_audited(self):
        from dashboard.models import AuditLog
        agent, _ = self.sentinel({'network': 'external'})
        status, _ = call(self.tokens['alice'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'settings': {'network': 'internal'}})
        self.assertIn(status, (403, 404))  # the Sentinel's own token cannot edit itself through the administrator call
        self.assertEqual(self.manage(agent, {'network': 'internal'})[0], 200)
        entry = AuditLog.objects.filter(action='agent.settings').latest('id')
        self.assertEqual((entry.detail['before'], entry.detail['after']), ({'network': 'external'}, {'network': 'external'}))
        self.assertEqual((entry.detail['network_grant_before'], entry.detail['network_grant_after']), ('external', 'internal'))

    def test_bad_values_and_non_sentinel_agents_are_refused(self):
        agent, _ = self.sentinel({'network': 'external'})
        self.assertEqual(self.manage(agent, {'network': 'dmz'})[0], 400)
        status, out = call(self.tokens['dana'], 'PUT', '/api/v1/agent', {'name': 'fixer', 'kind': 'remediation', 'scope': {'projects': ['sen-a']}})
        other = Agent.objects.get(pk=out['id'])
        self.assertEqual(self.manage(other, {'network': 'internal'})[0], 400)

    def test_the_agent_detail_shows_where_each_setting_comes_from(self):
        agent, _ = self.sentinel({'network': 'external'})
        self.manage(agent, {'profile': 'light'})
        status, out = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual(status, 200)
        self.assertEqual(out['settings']['profile']['source'], 'server')
        self.assertEqual(out['settings']['network']['source'], 'server')
        self.assertEqual(out['settings']['network']['machine_value'], 'external')


class UpdateTests(Base):
    def test_a_sentinel_reports_its_version_and_updater_state_and_is_told_the_mode(self):
        agent, out = self.sentinel(info={'version': 'abc1234'})
        status, beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat',
                            {'info': {'version': 'abc1234', 'update': {'status': 'waiting', 'phase': 'drain', 'detail': '2 tasks running'}}})
        self.assertEqual(status, 200, beat)
        self.assertEqual(beat['update'], {'mode': 'manual', 'setting': 'manual', 'requested': False})
        status, detail = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual(detail['version'], 'abc1234')
        self.assertEqual(detail['update']['status'], 'waiting')
        self.assertEqual(detail['update']['detail'], '2 tasks running')

    def test_the_instance_update_mode_reaches_the_sentinel(self):
        from unittest import mock
        self.sentinel()
        with mock.patch('cveFeed.updater.read_mode', return_value='auto'):
            beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')[1]
        self.assertEqual(beat['update']['mode'], 'auto')

    def test_update_now_is_an_administrators_request_and_a_new_version_answers_it(self):
        from dashboard.models import AuditLog
        agent, _ = self.sentinel(info={'version': 'old1'})
        status, out = call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})
        self.assertEqual(status, 200, out)
        self.assertTrue(out['update']['requested_at'])
        self.assertTrue(AuditLog.objects.filter(action='agent.update_requested').exists())
        self.assertTrue(call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')[1]['update']['requested'])
        call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'version': 'old1'}})  # same version: still waiting
        self.assertTrue(call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')[1]['update']['requested'])
        beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'version': 'new2', 'update': {'status': 'done'}}})[1]
        self.assertFalse(beat['update']['requested'])

    def test_a_failed_attempt_also_clears_the_request(self):
        agent, _ = self.sentinel(info={'version': 'v1'})
        call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})
        beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat',
                    {'info': {'version': 'v1', 'update': {'status': 'failed', 'detail': 'docker compose pull failed'}}})[1]
        self.assertFalse(beat['update']['requested'])
        self.assertEqual(Agent.objects.get(pk=agent.pk).info['update']['status'], 'failed')

    def test_bad_reports_and_requests_are_refused(self):
        agent, _ = self.sentinel()
        for bad in ({'version': 'x y'}, {'version': 'a' * 80}, {'update': {'status': 'exploding'}}, {'update': 'x'}, 'x'):
            self.assertEqual(call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': bad})[0], 400, bad)
        self.assertEqual(call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'later'})[0], 400)
        status, out = call(self.tokens['dana'], 'PUT', '/api/v1/agent', {'name': 'fixer', 'kind': 'remediation', 'scope': {'projects': ['sen-a']}})
        self.assertEqual(call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{out["id"]}', {'update': 'now'})[0], 400)


class SelfUpdateSettingTests(Base):
    """Self-update is Off, Manual or Automatic: per Sentinel, with an instance default, the most recent change winning like any other setting."""

    def effective(self, agent):
        agent.refresh_from_db()
        return ss.effective(agent)['self_update']

    def test_it_follows_the_instances_update_choice_until_someone_sets_it(self):
        from unittest import mock
        agent, _ = self.sentinel()
        self.assertEqual(self.effective(agent), 'manual')
        with mock.patch('cveFeed.updater.read_mode', return_value='auto'):
            self.assertEqual(self.effective(agent), 'automatic')
            status, out = call(self.tokens['root'], 'GET', '/api/v1/sentinels/defaults')
        self.assertEqual((status, out['self_update'], out['follows_instance'], out['effective_self_update']), (200, None, True, 'automatic'))

    def test_the_instance_default_applies_to_a_sentinel_with_no_value_of_its_own_and_its_own_value_beats_it(self):
        agent, _ = self.sentinel()
        status, out = call(self.tokens['root'], 'PUT', '/api/v1/sentinels/defaults', {'self_update': 'off'})
        self.assertEqual((status, out['self_update'], out['follows_instance']), (200, 'off', False))
        self.assertEqual(self.effective(agent), 'off')
        self.assertEqual(self.manage(agent, {'self_update': 'automatic'})[0], 200)
        self.assertEqual(self.effective(agent), 'automatic')  # an administrator's value for this Sentinel beats the default
        self.assertEqual(self.manage(agent, {'self_update': None})[0], 200)  # handed back: the default applies again
        self.assertEqual(self.effective(agent), 'off')
        call(self.tokens['root'], 'PUT', '/api/v1/sentinels/defaults', {'self_update': None})
        self.assertEqual(self.effective(agent), 'manual')

    def test_the_sentinels_own_configuration_and_the_dashboard_follow_the_most_recent_change(self):
        agent, _ = self.sentinel({'self_update': 'automatic'})
        self.assertEqual(self.effective(agent), 'automatic')
        self.manage(agent, {'self_update': 'off'})
        self.assertEqual(self.effective(agent), 'off')  # a later edit in cvENGINE beats the machine's configuration
        later = timezone.now() + timedelta(minutes=5)
        agent.refresh_from_db()
        ss.record_reported(agent, {'self_update': 'manual'}, now=later)  # the machine's configuration changed after
        self.assertEqual(self.effective(agent), 'manual')

    def test_only_an_app_admin_changes_the_default_and_bad_values_are_refused(self):
        self.assertEqual(call(self.tokens['dana'], 'PUT', '/api/v1/sentinels/defaults', {'self_update': 'off'})[0], 403)
        for body in ({'self_update': 'sometimes'}, {}, {'self_update': 'off', 'other': 1}, {'self_update': 3}):
            self.assertEqual(call(self.tokens['root'], 'PUT', '/api/v1/sentinels/defaults', body)[0], 400, body)
        agent, _ = self.sentinel()
        self.assertEqual(self.manage(agent, {'self_update': 'sometimes'})[0], 400)

    def test_a_change_of_the_default_is_audited(self):
        from dashboard.models import AuditLog
        call(self.tokens['root'], 'PUT', '/api/v1/sentinels/defaults', {'self_update': 'automatic'})
        entry = AuditLog.objects.filter(action='sentinel.defaults').latest('id')
        self.assertEqual((entry.detail['before'], entry.detail['after']), (None, 'automatic'))

    def test_the_reply_says_the_setting_and_off_never_asks_for_an_update(self):
        agent, _ = self.sentinel()
        self.manage(agent, {'self_update': 'automatic'})
        beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')[1]
        self.assertEqual(beat['update'], {'setting': 'automatic', 'mode': 'auto', 'requested': False})
        self.assertEqual(beat['settings']['values']['self_update'], 'automatic')
        self.assertEqual(call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})[0], 200)
        self.manage(agent, {'self_update': 'off'})
        beat = call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat')[1]
        self.assertEqual(beat['update'], {'setting': 'off', 'mode': 'manual', 'requested': False})  # a pending request is not honoured while Off

    def test_update_now_is_refused_while_self_update_is_off(self):
        agent, _ = self.sentinel({'self_update': 'off'})
        status, out = call(self.tokens['root'], 'PATCH', f'/api/v1/agents/{agent.pk}', {'update': 'now'})
        self.assertEqual(status, 409, out)
        agent.refresh_from_db()
        self.assertIsNone(agent.update_requested_at)

    def test_the_mcp_tools_read_and_set_the_default(self):
        from tests.test_agentapi import tool_call
        err, out = tool_call(self.tokens['root'], 'set_sentinel_defaults', {'self_update': 'manual'})
        self.assertFalse(err, out)
        err, out = tool_call(self.tokens['alice'], 'get_sentinel_defaults')
        self.assertEqual((err, out['self_update']), (False, 'manual'))
        err, out = tool_call(self.tokens['dana'], 'set_sentinel_defaults', {'self_update': 'off'})
        self.assertTrue(err)


class UpdaterStateTests(Base):
    """A Sentinel that cannot update itself is visible, with the command that fixes it; the command is the server's, never the Sentinel's."""

    def beat(self, updater):
        return call(self.tokens['alice'], 'POST', '/api/v1/sentinel/heartbeat', {'info': {'version': 'abc1234', 'updater': updater}})

    def detail(self, agent):
        status, out = call(self.tokens['root'], 'GET', f'/api/v1/agents/{agent.pk}')
        self.assertEqual(status, 200, out)
        return out

    def test_an_older_client_that_says_nothing_is_unknown_with_no_warning(self):
        agent, _ = self.sentinel()
        out = self.detail(agent)
        self.assertEqual((out['updater']['state'], out['updater']['warning'], out['updater']['install_command']), ('unknown', None, None))

    def test_no_updater_installed_warns_and_names_the_install_command(self):
        agent, _ = self.sentinel({'self_update': 'automatic'})
        self.assertEqual(self.beat({'installed': False, 'running': False})[0], 200)
        out = self.detail(agent)['updater']
        self.assertEqual(out['state'], 'not_installed')
        self.assertEqual(out['install_command'], ss.INSTALL_COMMAND)
        self.assertIn('not installed', out['warning'])
        self.assertIn('Automatic', out['warning'])

    def test_installed_but_not_running_warns_differently_and_running_has_no_warning(self):
        agent, _ = self.sentinel()
        self.beat({'installed': True, 'running': False, 'last_run': '2026-10-28T10:00:00+00:00', 'last_result': 'failed', 'detail': 'git fetch failed'})
        out = self.detail(agent)['updater']
        self.assertEqual((out['state'], out['last_result'], out['detail']), ('stopped', 'failed', 'git fetch failed'))
        self.assertIn('not running', out['warning'])
        self.beat({'installed': True, 'running': True, 'last_run': '2026-10-28T11:00:00+00:00', 'last_result': 'ok'})
        out = self.detail(agent)['updater']
        self.assertEqual((out['state'], out['warning'], out['install_command']), ('running', None, None))

    def test_off_never_warns_because_nothing_is_meant_to_update(self):
        agent, _ = self.sentinel({'self_update': 'off'})
        self.beat({'installed': False, 'running': False})
        out = self.detail(agent)['updater']
        self.assertEqual((out['state'], out['warning']), ('not_installed', None))

    def test_the_list_rows_carry_version_setting_and_updater_so_a_stuck_sentinel_shows_without_opening_it(self):
        agent, _ = self.sentinel()
        self.beat({'installed': False, 'running': False})
        status, out = call(self.tokens['root'], 'GET', '/api/v1/agents?kind=scanner')
        row = next(r for r in out['results'] if r['id'] == agent.pk)
        self.assertEqual((row['version'], row['self_update'], row['updater']['state']), ('abc1234', 'manual', 'not_installed'))

    def test_a_bad_report_is_refused_and_text_is_cleaned_and_clipped(self):
        self.sentinel()
        for bad in ({'installed': 'yes'}, {'running': True}, 'nope', {'installed': True, 'detail': 5}):
            self.assertEqual(self.beat(bad)[0], 400, bad)
        agent = Agent.objects.get(name='sentinel-1')
        self.beat({'installed': True, 'running': True, 'detail': 'ok\x07' + 'x' * 500})
        agent.refresh_from_db()
        self.assertEqual(len(agent.info['updater']['detail']), 300)
        self.assertTrue(agent.info['updater']['detail'].startswith('okxxx'))  # the control character is dropped
        self.assertNotIn('install_command', agent.info['updater'])  # whatever else a Sentinel sends is dropped; the command is the server\'s
