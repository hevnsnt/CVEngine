"""The per-Sentinel capability policy (``agentapi.sentinel_policy``): an administrator chooses, per Sentinel and per kind, what it may take (allow), never
takes (deny) or takes first (prefer), with an optional cap on how many of a kind it runs at once, for the built-in scanner and for an external one alike; the
instance defaults of each class; what only the Sentinel can declare; the claim order (deny, per-kind cap, prefer); and the honest reasons when a kind has
nowhere to go (disabled, offline, never)."""
import logging
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import scanner_fallback, scanner_state
from agentapi import sentinel_broker as sb
from agentapi import sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi import sentinel_policy as policy
from agentapi import sentinel_settings as ss
from agentapi.auth import create_token
from agentapi.models import Agent, ScannerFallback, SentinelDefaults, SentinelTask
from agentapi.services import ApiError, Ctx
from dashboard.models import AuditLog, ProjectMembership
from reNgine import resources
from tests.fake_scanner import FakeScanner, LocalFallback
from tests.test_agentapi import call, tool_call
from tests.test_openvas import Fixture as OpenvasFixture
from tests.test_sentinel_dispatch import DispatchBase
from tests.test_sentinels import SentinelBase, register_sentinel


def ctx_of(agent):
    return Ctx(user=agent.token.user, token=agent.token)


class PolicyBase(DispatchBase):
    """A project, an App Admin to make the changes, and helpers for external Sentinels and for queued work."""

    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('policy-root', 'policy-root@example.test', 'x')
        self.root_token = create_token(self.root, 'policy-root')[1]
        self.counter = 0

    def external(self, name, caps=('nmap', 'naabu', 'openvas'), **fields):
        """A live, active external Sentinel that covers the project and declares ``caps`` at the current contract version."""
        self.counter += 1
        user = User.objects.create_user(f'policy-owner-{self.counter}', password='x')
        token, _ = create_token(user, f'policy-token-{self.counter}')
        ProjectMembership.objects.create(user=user, project=self.project, role='user')  # what lets its scope reach the project
        return Agent.objects.create(token=token, name=name, kind='scanner', status='active', capabilities=list(caps), last_seen=timezone.now(),
                                    scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []},
                                    info={'contract_version': sentinel_contract.version()}, **fields)

    def manage(self, agent, settings):
        agent.refresh_from_db()
        return ss.set_managed(agent, settings, self.root)

    def queue(self, kind, created=None, **fields):
        task = SentinelTask.objects.create(project=self.project, kind=kind, target={'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], **fields)
        if created is not None:
            SentinelTask.objects.filter(pk=task.pk).update(created_at=created)
        return task

    def claim(self, agent, kinds, now=None):
        agent.refresh_from_db()
        return sb._try_claim(agent, set(kinds), now or timezone.now())

    def deny_everywhere(self, fake, *externals, kind='openvas'):
        for agent in (fake.agent, *externals):
            self.manage(agent, {'kinds': {kind: {'mode': 'deny', 'max_concurrent': None}}})


class DenyTests(PolicyBase):
    def test_the_external_sentinel_takes_openvas_when_the_built_in_one_is_denied_it(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        task = self.queue('openvas')
        taken, why = self.claim(fake.agent, ['openvas'])
        self.assertIsNone(taken)
        self.assertEqual(why, 'no eligible work is queued')  # a denied kind is not even looked at
        taken, why = self.claim(outside, ['openvas'])
        self.assertEqual((taken.pk, why), (task.pk, ''))
        self.assertEqual(taken.agent_id, outside.pk)

    def test_denying_a_kind_on_the_external_one_leaves_it_to_the_built_in_one(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        task = self.queue('openvas')
        self.assertIsNone(self.claim(outside, ['openvas'])[0])
        self.assertEqual(self.claim(fake.agent, ['openvas'])[0].pk, task.pk)

    def test_a_denied_kind_is_not_offered_and_a_task_of_it_is_refused(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        outside.refresh_from_db()
        eff = sb.effective(outside)
        self.assertNotIn('openvas', eff.caps)
        self.assertIn('nmap', eff.caps)
        self.assertEqual(eff.refusal(self.queue('openvas')), ('capability', 'openvas'))

    def test_both_denied_the_state_says_disabled_and_every_message_names_it(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.deny_everywhere(fake, outside)
        state = sb.capacity_state(self.project, 'openvas', why=True)
        self.assertEqual((state['state'], state['reason']), ('none', 'disabled'))
        self.assertIn('OpenVAS is not enabled on any live Sentinel', state['message'])
        self.assertIn('off on CVEngine Scanner', state['message'])
        self.assertIn('off on Remote-1', state['message'])
        self.assertNotIn('reason', sb.capacity_state(self.project, 'openvas'))  # the gate every stage asks stays the cheap answer
        self.assertFalse(dispatch.any_scanner_for(self.project, 'openvas'))
        self.assertTrue(dispatch.any_scanner_for(self.project, 'nmap'))  # only the kind is off

    def test_the_stage_waits_with_a_message_naming_the_cause_when_the_kind_may_not_run_here(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.deny_everywhere(fake, outside)
        with LocalFallback('none'):
            with self.assertRaises(resources.ScannerUnavailable) as raised:
                dispatch.dispatch_or_none(self.project, 'openvas', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])
        self.assertIn('OpenVAS is not enabled on any live Sentinel (', raised.exception.why)
        self.assertIn('off on CVEngine Scanner', raised.exception.why)
        self.assertFalse(SentinelTask.objects.exists())  # nothing was queued for a Sentinel that was told not to take it

    def test_the_telemetry_row_says_disabled_everywhere_when_the_kind_runs_here_instead(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.deny_everywhere(fake, outside)
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'openvas', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10']))
        self.assertEqual(list(ScannerFallback.objects.values_list('kind', 'reason')), [('openvas', 'disabled_everywhere')])
        self.assertIn('disabled_everywhere', scanner_fallback.REASONS)

    def test_a_plain_offline_scanner_is_still_no_scanner(self):
        outside = self.external('Remote-1')
        Agent.objects.filter(pk=outside.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        state = sb.capacity_state(self.project, 'openvas', why=True)
        self.assertEqual((state['reason'], state['message']), ('offline', 'OpenVAS is not enabled on any live Sentinel (Remote-1 has it but is offline)'))
        dispatch.dispatch_or_none(self.project, 'openvas', {'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])
        self.assertEqual(list(ScannerFallback.objects.values_list('reason', flat=True)), ['no_scanner'])

    def test_the_reasons_for_none(self):
        self.assertEqual(sb.capacity_state(self.project, 'openvas', why=True)['reason'], 'never')
        self.assertEqual(sb.capacity_state(self.project, 'openvas', why=True)['message'], 'no Sentinel is live for this project')
        nmap_only = self.external('Remote-1', caps=('nmap',))
        state = sb.capacity_state(self.project, 'openvas', why=True)
        self.assertEqual(state['reason'], 'never')
        self.assertIn('no Sentinel that covers this has OpenVAS', state['message'])
        Agent.objects.filter(pk=nmap_only.pk).update(capabilities=['nmap', 'openvas'], status='suspended')
        self.assertEqual(sb.capacity_state(self.project, 'openvas', why=True)['reason'], 'inactive')
        Agent.objects.filter(pk=nmap_only.pk).update(status='active', last_seen=timezone.now() - timedelta(hours=1))
        self.assertEqual(sb.capacity_state(self.project, 'openvas', why=True)['reason'], 'offline')

    def test_a_kind_it_keeps_failing_says_withheld(self):
        outside = self.external('Remote-1')
        for _ in range(3):
            SentinelTask.objects.create(project=self.project, kind='openvas', target={}, agent=outside, status='failed', finished_at=timezone.now())
        state = sb.capacity_state(self.project, 'openvas', why=True)
        self.assertEqual(state['reason'], 'withheld')
        self.assertIn('cooling off after repeated failures', state['message'])

    def test_the_banner_says_disabled_not_offline_for_a_kind_turned_off_everywhere(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.deny_everywhere(fake, outside)
        with LocalFallback('none'):
            now = timezone.now()
            snapshot = scanner_state.state(now=now)
            self.assertEqual(snapshot['disabled'], ['openvas'])
            self.assertIn('openvas', scanner_state.waiting_kinds(now))  # still waiting: the sweeps stay off it
            self.assertEqual(scanner_state.disabled_kinds(now), ['openvas'])
            self.assertNotIn('openvas', scanner_state.offline_kinds(now))
            text = scanner_state.messages(snapshot)
            self.assertIn('OpenVAS is turned off on every Sentinel that has it', text['disabled'])
            self.assertNotIn('openvas', text['offline'] or '')  # the offline sentence is for kinds that are really waiting for a scanner
            status = scanner_state.status(admin=True, snapshot=snapshot)
            self.assertEqual(status['disabled_message'], text['disabled'])
            self.assertIn(text['disabled'], status['messages'])
            self.assertEqual(scanner_state.status(admin=False, snapshot=snapshot)['disabled'], ['openvas'])

    def test_a_kind_off_on_one_sentinel_and_offline_on_another_is_offline_on_the_banner(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        Agent.objects.filter(pk=outside.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        with LocalFallback('none'):
            snapshot = scanner_state.state(now=timezone.now())
            self.assertNotIn('disabled', snapshot)
            self.assertIn('openvas', scanner_state.offline_kinds(timezone.now()))
            self.assertIn('Scanner offline', scanner_state.messages(snapshot)['offline'])
            self.assertEqual(scanner_state.skip_note('openvas', timezone.now()), 'no scanner is online for openvas; the targets stay due')
        state = sb.capacity_state(self.project, 'openvas', why=True)
        self.assertEqual(state['reason'], 'disabled')  # the live one has it and is told not to
        self.assertIn('Remote-1 has it but is offline', state['message'])

    def test_a_sweep_of_a_kind_turned_off_says_so(self):
        fake = FakeScanner(kinds=['wpscan']).start_for(self)
        self.manage(fake.agent, {'kinds': {'wpscan': {'mode': 'deny', 'max_concurrent': None}}})
        with LocalFallback('none'):
            self.assertEqual(scanner_state.skip_note('wpscan', timezone.now()), 'wpscan is turned off on every Sentinel that has it; the targets stay due')

    def test_the_overview_of_the_system_status_names_each_kind(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        by_kind = sb.kinds_overview()
        self.assertEqual(by_kind['openvas'], {'live_sentinels': 0, 'free_slots': 0, 'state': 'none', 'reason': 'disabled'})
        self.assertEqual((by_kind['nmap']['live_sentinels'], by_kind['nmap']['state']), (2, 'free'))
        self.assertEqual(by_kind['nmap']['free_slots'], fake.max_concurrent + outside.max_concurrent)
        self.assertEqual((by_kind['wpscan']['state'], by_kind['wpscan']['reason']), ('none', 'never'))
        from agentapi.system_status import _sentinels
        self.assertEqual(_sentinels([])['by_kind'], by_kind)


class DefaultsTests(PolicyBase):
    def test_the_built_in_scanner_ships_with_openvas_denied_and_an_own_allow_overrides_it(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        self.assertNotIn('openvas', sb.effective(fake.agent).caps)
        self.assertIn('nmap', sb.effective(fake.agent).caps)
        kind = sb.kind_report(fake.agent)['openvas']
        self.assertEqual((kind['mode'], kind['source'], kind['effective'], kind['declared'], kind['state']), ('deny', 'instance default', False, True, 'denied'))
        self.assertTrue(ss.get_defaults()['builtin_kinds_is_shipped'])
        self.manage(fake.agent, {'kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})
        fake.agent.refresh_from_db()
        self.assertIn('openvas', sb.effective(fake.agent).caps)
        kind = sb.kind_report(fake.agent)['openvas']
        self.assertEqual((kind['mode'], kind['source'], kind['effective']), ('allow', 'agent', True))
        self.manage(fake.agent, {'kinds': {'openvas': None}})  # its own policy removed: the default applies again
        fake.agent.refresh_from_db()
        self.assertNotIn('openvas', sb.effective(fake.agent).caps)

    def test_the_shipped_default_is_for_the_built_in_scanner_only(self):
        FakeScanner(kinds=['openvas']).start_for(self)
        outside = self.external('Remote-1')
        self.assertIn('openvas', sb.effective(outside).caps)
        self.assertEqual(sb.kind_report(outside)['openvas']['source'], 'default')

    def test_an_administrator_changes_each_class_default_and_a_null_restores_the_shipped_one(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        out = ss.set_defaults(self.root, {'builtin_kinds': {}, 'external_kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None},
                                                                                   'openvas': {'mode': 'prefer', 'max_concurrent': 1}}})
        self.assertEqual((out['builtin_kinds'], out['builtin_kinds_is_shipped']), ({}, False))
        fake.agent.refresh_from_db()
        outside.refresh_from_db()
        self.assertIn('openvas', sb.effective(fake.agent).caps)  # no built-in defaults: nothing is denied
        self.assertNotIn('nmap', sb.effective(outside).caps)
        self.assertIn('nmap', sb.effective(fake.agent).caps)
        kind = sb.kind_report(outside)['openvas']
        self.assertEqual((kind['mode'], kind['cap'], kind['source']), ('prefer', 1, 'instance default'))
        out = ss.set_defaults(self.root, {'builtin_kinds': None, 'external_kinds': None})
        self.assertEqual((out['builtin_kinds'], out['builtin_kinds_is_shipped'], out['external_kinds']),
                         ({'openvas': {'mode': 'deny', 'max_concurrent': None}}, True, {}))
        self.assertNotIn('openvas', sb.effective(fake.agent).caps)
        self.assertIn('nmap', sb.effective(outside).caps)

    def test_a_sentinels_own_policy_beats_its_class_default_as_a_whole(self):
        outside = self.external('Remote-1')
        ss.set_defaults(self.root, {'external_kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 2}}})
        self.manage(outside, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        kind = sb.kind_report(outside)['nmap']
        self.assertEqual((kind['mode'], kind['cap'], kind['source']), ('prefer', None, 'agent'))  # not the default's cap of 2

    def test_a_default_is_changed_by_an_app_admin_with_valid_values_and_is_audited(self):
        dana = User.objects.create_user('policy-dana', password='x')
        with self.assertRaises(ApiError) as raised:
            ss.set_defaults(dana, {'builtin_kinds': {}})
        self.assertEqual(raised.exception.status, 403)
        for body in ({}, {'other': 1}, {'builtin_kinds': {'rm -rf': {'mode': 'deny'}}}, {'external_kinds': {'nmap': {'mode': 'maybe'}}},
                     {'external_kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 11}}}, {'external_kinds': {'nmap': None}}, {'external_kinds': []},
                     {'builtin_kinds': {'nmap': {'mode': 'allow', 'extra': 1}}}):
            with self.assertRaises(ApiError, msg=body) as raised:
                ss.set_defaults(self.root, body)
            self.assertEqual(raised.exception.status, 400, body)
        ss.set_defaults(self.root, {'external_kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        entry = AuditLog.objects.filter(action='sentinel.defaults').latest('id')
        self.assertEqual(entry.actor, self.root)
        self.assertEqual(entry.detail['external_kinds'], {'before': {}, 'after': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        self.assertNotIn('builtin_kinds', entry.detail)

    def test_the_defaults_are_read_through_the_rest_and_mcp_calls(self):
        status, out = call(self.root_token, 'GET', '/api/v1/sentinels/defaults')
        self.assertEqual((status, out['builtin_kinds'], out['builtin_kinds_is_shipped'], out['external_kinds']),
                         (200, {'openvas': {'mode': 'deny', 'max_concurrent': None}}, True, {}))
        status, out = call(self.root_token, 'PUT', '/api/v1/sentinels/defaults', {'external_kinds': {'wpscan': {'mode': 'deny', 'max_concurrent': 1}}})
        self.assertEqual((status, out['external_kinds']), (200, {'wpscan': {'mode': 'deny', 'max_concurrent': 1}}))
        is_error, text = tool_call(self.root_token, 'set_sentinel_defaults', {'builtin_kinds': {}})
        self.assertFalse(is_error, text)
        self.assertEqual(SentinelDefaults.current().builtin_kinds, {})
        is_error, text = tool_call(self.root_token, 'get_sentinel_defaults', {})
        self.assertFalse(is_error)
        self.assertIn('external_kinds', text)


class MachineAndDeclaredTests(PolicyBase):
    def test_only_a_declared_kind_can_be_allowed_or_preferred(self):
        outside = self.external('Remote-1', caps=('nmap',))
        for mode in ('allow', 'prefer'):
            with self.assertRaises(ApiError, msg=mode) as raised:
                self.manage(outside, {'kinds': {'openvas': {'mode': mode, 'max_concurrent': None}}})
            self.assertEqual(raised.exception.status, 409)
            self.assertIn('not available on this Sentinel', raised.exception.message)
        outside.refresh_from_db()
        self.assertEqual(policy.managed_kinds(outside), {})  # refused before anything was stored
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})  # turning something off is always allowed
        kind = sb.kind_report(outside)['openvas']
        self.assertEqual((kind['declared'], kind['effective'], kind['state']), (False, False, 'denied'))
        kind = sb.kind_report(self.external('Remote-2', caps=('nmap',)))['openvas']
        self.assertEqual((kind['declared'], kind['state'], kind['mode']), (False, 'unavailable', 'allow'))
        self.assertIn('tool missing or off on the machine', kind['note'])

    def test_a_kind_turned_off_on_the_machine_cannot_be_lifted_by_the_server(self):
        outside = self.external('Remote-1')
        outside.reported_settings = {'disabled_kinds': {'value': ['openvas'], 'at': timezone.now().isoformat()}}
        outside.save()
        kind = sb.kind_report(outside)['openvas']
        self.assertEqual((kind['mode'], kind['source'], kind['state'], kind['effective']), ('deny', 'machine', 'machine_off', False))
        self.assertIn('turned off on the machine', kind['note'])
        with self.assertRaises(ApiError) as raised:
            self.manage(outside, {'kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})
        self.assertEqual(raised.exception.status, 409)
        outside.refresh_from_db()
        self.assertNotIn('openvas', sb.effective(outside).caps)
        # an own policy of the Sentinel's does not lift it either, nor does the instance default
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        ss.set_defaults(self.root, {'external_kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})
        outside.refresh_from_db()
        self.assertNotIn('openvas', sb.effective(outside).caps)
        self.assertEqual(sb.kind_report(outside)['openvas']['source'], 'machine')

    def test_a_kind_its_contract_predates_and_one_it_keeps_failing_say_why(self):
        outside = self.external('Remote-1')
        outside.info = {'contract_version': 1}
        outside.save()
        late = [k for k in SentinelTask.KINDS if not sentinel_contract.can_run(1, k)]
        if late:
            kind = sb.kind_report(self.external_with(late[0]))[late[0]]
            self.assertEqual((kind['state'], kind['source']), ('outdated', 'contract'))
        for _ in range(3):
            SentinelTask.objects.create(project=self.project, kind='naabu', target={}, agent=outside, status='failed', finished_at=timezone.now())
        kind = sb.kind_report(outside)['naabu']
        self.assertEqual((kind['state'], kind['source'], kind['effective']), ('cool_off', 'cool-off', False))
        self.assertTrue(kind['retry_at'])

    def external_with(self, kind):
        agent = self.external('Old', caps=(kind,))
        agent.info = {'contract_version': 1}
        agent.save()
        return agent


class LegacyTests(PolicyBase):
    def test_a_stored_disabled_kinds_still_reads_as_deny(self):
        outside = self.external('Remote-1')
        outside.managed_settings = {'disabled_kinds': {'value': ['openvas'], 'at': timezone.now().isoformat(), 'by': 'alice'}}
        outside.save()
        kind = sb.kind_report(outside)['openvas']
        self.assertEqual((kind['mode'], kind['source'], kind['by'], kind['effective']), ('deny', 'agent', 'alice', False))
        self.assertNotIn('openvas', sb.effective_capabilities(outside))
        self.assertEqual(ss.effective(outside)['disabled_kinds'], ['openvas'])
        self.assertEqual(ss.detail(outside)['disabled_kinds']['value'], ['openvas'])

    def test_the_older_list_still_sets_and_clears_denials_and_folds_into_the_policy(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'disabled_kinds': ['openvas', 'wpscan', 'openvas']})
        outside.refresh_from_db()
        self.assertEqual(ss.effective(outside)['disabled_kinds'], ['openvas', 'wpscan'])
        self.assertEqual({k: e['mode'] for k, e in policy.managed_kinds(outside).items()}, {'openvas': 'deny', 'wpscan': 'deny'})
        self.assertNotIn('disabled_kinds', outside.managed_settings)  # one home now: the policy
        self.manage(outside, {'disabled_kinds': ['wpscan']})
        outside.refresh_from_db()
        self.assertEqual(ss.effective(outside)['disabled_kinds'], ['wpscan'])
        self.manage(outside, {'disabled_kinds': None})
        outside.refresh_from_db()
        self.assertNotIn('disabled_kinds', ss.effective(outside))
        self.assertEqual(policy.managed_kinds(outside), {})

    def test_the_older_list_keeps_the_cap_of_a_kind_it_allows_again(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': 2}}})
        self.manage(outside, {'disabled_kinds': []})
        outside.refresh_from_db()
        self.assertEqual(policy.managed_kinds(outside), {'openvas': {'mode': 'allow', 'max_concurrent': 2}})

    def test_a_newer_entry_wins_over_a_stored_older_denial_and_the_two_cannot_be_sent_together(self):
        outside = self.external('Remote-1')
        outside.managed_settings = {'disabled_kinds': {'value': ['openvas'], 'at': timezone.now().isoformat(), 'by': 'alice'}}
        outside.save()
        self.manage(outside, {'kinds': {'openvas': {'mode': 'allow', 'max_concurrent': None}}})
        outside.refresh_from_db()
        self.assertIn('openvas', sb.effective(outside).caps)
        self.assertNotIn('disabled_kinds', outside.managed_settings)
        with self.assertRaises(ApiError) as raised:
            self.manage(outside, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}, 'disabled_kinds': ['nmap']})
        self.assertEqual(raised.exception.status, 400)

    def test_the_wire_reply_to_the_sentinel_still_carries_disabled_kinds_derived_from_the_policy(self):
        fake = FakeScanner(kinds=['openvas', 'nmap']).start_for(self)
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': 1}, 'naabu': {'mode': 'prefer', 'max_concurrent': None}}})
        outside.refresh_from_db()
        values = ss.reply(outside)['values']
        self.assertEqual(values['disabled_kinds'], ['nmap'])  # the policy as the one list an older client honours
        self.assertNotIn('kinds', values)  # and nothing a client has not seen
        beat = sb.heartbeat(ctx_of(fake.agent), {})
        self.assertEqual(beat['settings']['values']['disabled_kinds'], ['openvas'])  # the shipped default of the built-in scanner reaches it the same way
        before = ss.reply(outside)['rev']
        self.manage(outside, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 1}}})
        outside.refresh_from_db()
        self.assertNotEqual(ss.reply(outside)['rev'], before)  # a changed policy changes the fingerprint, so the client fetches it


class ClaimOrderTests(PolicyBase):
    def test_prefer_holds_a_task_back_from_the_others_until_the_defer_has_passed(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            first, second = self.external('X'), self.external('Y')
            self.manage(first, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            task = self.queue('nmap', created=created)
            taken, why = self.claim(second, ['nmap'], created + timedelta(seconds=1))
            self.assertIsNone(taken)  # both idle: the preferring one gets the work first
            self.assertIn('held for a Sentinel that prefers it', why)
            self.assertEqual(self.claim(first, ['nmap'], created + timedelta(seconds=2))[0].pk, task.pk)
            # the preferring Sentinel never answered: the hold ends before the stage's claim window (8 s) does, at 8 - 2 = 6 s
            late = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(second, ['nmap'], created + timedelta(seconds=5))[0])
            self.assertEqual(self.claim(second, ['nmap'], created + timedelta(seconds=7))[0].pk, late.pk)

    def test_an_openvas_task_keeps_the_whole_defer_because_no_stage_waits_for_it(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            first, second = self.external('X'), self.external('Y')
            self.manage(first, {'kinds': {'openvas': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            task = self.queue('openvas', created=created)
            self.assertIsNone(self.claim(second, ['openvas'], created + timedelta(seconds=59))[0])
            self.assertEqual(self.claim(second, ['openvas'], created + timedelta(seconds=61))[0].pk, task.pk)
            self.assertEqual((sb.prefer_defer_for('openvas'), sb.prefer_defer_for('nmap')), (60, 6))

    def test_the_defer_is_a_ceiling_the_environments_and_never_longer_than_the_claim_window(self):
        first, second = self.external('X'), self.external('Y')
        self.manage(first, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        created = timezone.now()
        self.queue('nmap', created=created)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_PREFER_DEFER_SECONDS': '4', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            self.assertEqual((sb.prefer_defer_seconds(), sb.prefer_defer_for('nmap'), sb.prefer_defer_for('openvas')), (4, 4, 4))
            self.assertIsNone(self.claim(second, ['nmap'], created + timedelta(seconds=3))[0])
            self.assertIsNotNone(self.claim(second, ['nmap'], created + timedelta(seconds=5))[0])
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_PREFER_DEFER_SECONDS': '600', 'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '30'}):
            self.assertEqual((sb.prefer_defer_for('nmap'), sb.prefer_defer_for('openvas')), (28, 600))
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '1'}):  # a claim window under two seconds leaves no room to hold anything
            self.assertEqual(sb.prefer_defer_for('nmap'), 0)
        self.queue('nmap', created=created)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_PREFER_DEFER_SECONDS': '0'}):
            self.assertEqual((sb.prefer_defer_for('nmap'), sb.prefer_defer_for('openvas')), (0, 0))
            self.assertIsNotNone(self.claim(second, ['nmap'], created + timedelta(seconds=1))[0])
        self.assertEqual(sb.prefer_defer_seconds(), 60)

    def test_a_preferring_sentinel_that_cannot_take_it_does_not_hold_the_work_back(self):
        preferred, other = self.external('X'), self.external('Y')
        self.manage(preferred, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': 1}}})
        created = timezone.now()
        task = self.queue('nmap', created=created)
        busy = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=preferred, status='running',
                                           lease_expires_at=created + timedelta(minutes=5))  # at its per-kind cap: no room
        self.assertEqual(self.claim(other, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)
        task2 = self.queue('nmap', created=created)
        SentinelTask.objects.filter(pk=busy.pk).update(status='done')
        Agent.objects.filter(pk=preferred.pk).update(last_seen=created - timedelta(hours=1))  # offline: not a candidate
        self.assertEqual(self.claim(other, ['nmap'], created + timedelta(seconds=1))[0].pk, task2.pk)

    def test_a_pass_over_many_queued_tasks_of_several_projects_does_not_query_per_task(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        from dashboard.models import Project
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            projects = [self.project] + [Project.objects.create(name=f'P{n}', slug=f'policy-p{n}', insert_date=timezone.now(), org=self.org) for n in range(2)]
            first, second = self.external('X'), self.external('Y')
            for agent in (first, second):
                Agent.objects.filter(pk=agent.pk).update(scope={'orgs': [self.org.slug], 'projects': [], 'hosts': []}, max_concurrent=10)
                ProjectMembership.objects.get_or_create(user=agent.token.user, project=projects[1], defaults={'role': 'user'})
                ProjectMembership.objects.get_or_create(user=agent.token.user, project=projects[2], defaults={'role': 'user'})
            self.manage(first, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}, 'naabu': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()

            def queue_many(n):
                for project in projects:
                    for kind in ('nmap', 'naabu'):
                        for _ in range(n):
                            task = SentinelTask.objects.create(project=project, kind=kind, target={}, ips=['192.0.2.10'])
                            SentinelTask.objects.filter(pk=task.pk).update(created_at=created)

            def queries(now):
                with CaptureQueriesContext(connection) as captured:
                    taken, why = self.claim(second, ['nmap', 'naabu'], now)
                return len(captured), taken, why
            queue_many(1)
            few, taken, why = queries(created + timedelta(seconds=1))
            self.assertIsNone(taken)  # every task is held for the preferring Sentinel
            self.assertIn('held for a Sentinel that prefers it', why)
            queue_many(9)  # ten times the tasks, the same projects and kinds
            many, taken, _ = queries(created + timedelta(seconds=1))
            self.assertIsNone(taken)
            self.assertEqual(many, few, f'{many} queries for 60 tasks against {few} for 6: the prefer check must not query per task')

    def test_a_task_that_only_one_preferring_sentinel_with_hosts_may_take_is_judged_task_by_task(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            first, second = self.external('X'), self.external('Y')
            Agent.objects.filter(pk=first.pk).update(scope={'orgs': [], 'projects': [self.project.slug], 'hosts': ['only.test']})
            self.manage(first, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
            created = timezone.now()
            inside = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, host='a.only.test', ips=[])
            outside = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, host='b.elsewhere.test', ips=[])
            SentinelTask.objects.filter(pk__in=(inside.pk, outside.pk)).update(created_at=created)
            taken, _ = self.claim(second, ['nmap'], created + timedelta(seconds=1))
            self.assertEqual(taken.pk, outside.pk)  # the preferring Sentinel's scope does not reach it: nothing to wait for
            inside.refresh_from_db()
            self.assertEqual(inside.status, 'queued')  # but the one it could take is held for it

    def test_a_policy_for_a_kind_the_sentinel_stopped_declaring_stays_stored_and_holds_nothing_back(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': '8'}):
            first, second = self.external('X'), self.external('Y')
            self.manage(first, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': 2}}})
            created = timezone.now()
            task = self.queue('nmap', created=created)
            self.assertIsNone(self.claim(second, ['nmap'], created + timedelta(seconds=1))[0])  # held while X declares it
            Agent.objects.filter(pk=first.pk).update(capabilities=['naabu', 'openvas'])  # it registered again without nmap
            first.refresh_from_db()
            self.assertEqual(policy.managed_kinds(first), {'nmap': {'mode': 'prefer', 'max_concurrent': 2}})  # the prefer entry is still there
            self.assertEqual(self.claim(second, ['nmap'], created + timedelta(seconds=1))[0].pk, task.pk)  # and holds nothing back
            kind = sb.kind_report(first)['nmap']
            self.assertEqual((kind['state'], kind['mode'], kind['declared'], kind['effective'], kind['cap']), ('unavailable', 'prefer', False, False, 2))
            Agent.objects.filter(pk=first.pk).update(capabilities=['nmap', 'naabu'])  # it declares it again: the policy is back in force
            first.refresh_from_db()
            kind = sb.kind_report(first)['nmap']
            self.assertEqual((kind['state'], kind['mode'], kind['effective']), ('on', 'prefer', True))

    def test_two_preferring_sentinels_do_not_hold_each_other_back(self):
        first, second = self.external('X'), self.external('Y')
        for agent in (first, second):
            self.manage(agent, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        task = self.queue('nmap')
        self.assertEqual(self.claim(second, ['nmap'])[0].pk, task.pk)

    def test_a_per_kind_cap_makes_a_second_task_of_the_kind_wait_while_another_kind_is_taken(self):
        outside = self.external('X', max_concurrent=4)
        self.manage(outside, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 1}}})
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=outside, status='running',
                                    lease_expires_at=timezone.now() + timedelta(minutes=5))
        second_nmap = self.queue('nmap', created=timezone.now() - timedelta(minutes=2))  # older and so first in line
        naabu = self.queue('naabu')
        taken, _ = self.claim(outside, ['nmap', 'naabu'])
        self.assertEqual(taken.pk, naabu.pk)
        second_nmap.refresh_from_db()
        self.assertEqual(second_nmap.status, 'queued')
        taken, why = self.claim(outside, ['nmap', 'naabu'])
        self.assertIsNone(taken)
        self.assertIn('nmap is at its limit of 1 at once here', why)

    def test_a_cap_is_for_its_kind_and_inside_the_sentinels_own_limit(self):
        outside = self.external('X', max_concurrent=2)
        self.manage(outside, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 1}}})
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['slots'], state['free']), ('free', 1, 1))
        state = sb.capacity_state(self.project, 'naabu')
        self.assertEqual((state['slots'], state['free']), (2, 2))
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=outside, status='running',
                                    lease_expires_at=timezone.now() + timedelta(minutes=5))
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['state'], state['free']), ('busy', 0))  # at the cap of its kind though a slot of the Sentinel is free
        self.assertEqual(sb.capacity_state(self.project, 'naabu')['free'], 1)
        self.assertEqual(sb.kind_report(outside)['nmap']['held'], 1)

    def test_the_slots_of_a_kind_add_up_over_the_sentinels_by_their_headroom(self):
        capped = self.external('X', max_concurrent=4)
        plain = self.external('Y', max_concurrent=3)
        self.manage(capped, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 2}}})
        state = sb.capacity_state(self.project, 'nmap')
        self.assertEqual((state['slots'], state['free'], state['live']), (2 + plain.max_concurrent, 2 + plain.max_concurrent, 2))

    def test_the_order_is_deny_then_cap_then_prefer(self):
        outside = self.external('X')
        other = self.external('Y')
        self.manage(other, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': None}}})
        self.manage(outside, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': 1}, 'naabu': {'mode': 'allow', 'max_concurrent': 1}}})
        self.queue('nmap')
        self.assertEqual(self.claim(outside, ['nmap'])[1], 'no eligible work is queued')  # denied: not looked at, so not "held back" either
        SentinelTask.objects.create(project=self.project, kind='naabu', target={}, agent=outside, status='running',
                                    lease_expires_at=timezone.now() + timedelta(minutes=5))
        self.queue('naabu')
        self.assertIn('at its limit', self.claim(outside, ['naabu'])[1])  # at the cap: skipped, and the reason is the cap


class ValidationAndAuditTests(PolicyBase):
    def test_bad_policies_are_refused_by_name(self):
        outside = self.external('Remote-1')
        bad = [{}, [], 'deny', {'rm -rf': {'mode': 'deny'}}, {'nmap': 'deny'}, {'nmap': {}}, {'nmap': {'mode': 'maybe'}},
               {'nmap': {'mode': 'deny', 'extra': 1}}, {'nmap': {'mode': 'deny', 'max_concurrent': 0}}, {'nmap': {'mode': 'deny', 'max_concurrent': 11}},
               {'nmap': {'mode': 'deny', 'max_concurrent': True}}, {'nmap': {'mode': 'deny', 'max_concurrent': '2'}},
               {'nmap': {'mode': 'deny', 'max_concurrent': 1.5}}, {1: {'mode': 'deny'}}]
        for value in bad:
            with self.assertRaises(ApiError, msg=value) as raised:
                self.manage(outside, {'kinds': value})
            self.assertEqual(raised.exception.status, 400, value)
        outside.refresh_from_db()
        self.assertEqual(outside.managed_settings or {}, {})
        self.assertEqual(AuditLog.objects.filter(action='agent.settings').count(), 0)

    def test_a_sentinel_cannot_report_a_policy_for_itself(self):
        with self.assertRaises(ApiError) as raised:
            ss.clean_settings({'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': 1}}}, managed=False)
        self.assertEqual(raised.exception.status, 400)
        self.assertIn('kinds', ss.clean_settings({'kinds': None}))  # an administrator may clear it

    def test_every_change_is_audited_with_who_and_the_map_before_and_after(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}, 'nmap': {'mode': 'prefer', 'max_concurrent': 3}}})
        entry = AuditLog.objects.filter(action='agent.settings').latest('id')
        self.assertEqual((entry.actor, entry.actor_name, entry.target), (self.root, 'policy-root', 'Remote-1'))
        self.assertEqual(entry.detail['kinds_before'], {})
        self.assertEqual(entry.detail['kinds_after'], {'openvas': {'mode': 'deny', 'max_concurrent': None}, 'nmap': {'mode': 'prefer', 'max_concurrent': 3}})
        self.assertEqual(entry.detail['agent_id'], outside.pk)
        self.manage(outside, {'kinds': {'openvas': None}})
        entry = AuditLog.objects.filter(action='agent.settings').latest('id')
        self.assertEqual(set(entry.detail['kinds_before']) - set(entry.detail['kinds_after']), {'openvas'})
        outside.refresh_from_db()
        self.assertEqual(outside.managed_settings['kinds']['by'], 'policy-root')  # the last write wins, and says whose it was
        self.manage(outside, {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': 3}}})  # the same again changes nothing
        outside.refresh_from_db()
        self.assertEqual(outside.managed_settings['kinds']['value']['nmap'], {'mode': 'prefer', 'max_concurrent': 3})

    def test_last_write_wins(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        self.manage(outside, {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': None}}})
        outside.refresh_from_db()
        self.assertIn('nmap', sb.effective(outside).caps)
        self.assertEqual(sb.kind_report(outside)['nmap']['mode'], 'allow')

    def test_clearing_the_policy_hands_every_kind_back(self):
        outside = self.external('Remote-1')
        self.manage(outside, {'kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}, 'naabu': {'mode': 'deny', 'max_concurrent': None}}})
        self.manage(outside, {'kinds': None})
        outside.refresh_from_db()
        self.assertEqual(policy.managed_kinds(outside), {})
        self.assertEqual({'nmap', 'naabu'} - sb.effective(outside).caps, set())


class RestAndMcpTests(SentinelBase):
    def setUp(self):
        super().setUp()
        _, out = register_sentinel(self.t['dana'], name='policy-sentinel', capabilities=['nmap', 'naabu', 'openvas'])
        self.agent_id = out['id']
        Agent.objects.filter(pk=self.agent_id).update(last_seen=timezone.now(), info={'contract_version': sentinel_contract.version()})

    def patch(self, who, settings):
        return call(self.t[who], 'PATCH', f'/api/v1/agents/{self.agent_id}', {'settings': settings})

    def test_an_administrator_sets_the_policy_and_get_agent_shows_it_per_kind(self):
        status, out = self.patch('root', {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}, 'nmap': {'mode': 'prefer', 'max_concurrent': 2}}})
        self.assertEqual(status, 200, out)
        status, out = call(self.t['root'], 'GET', f'/api/v1/agents/{self.agent_id}')
        kinds = out['kinds']
        self.assertEqual(set(kinds), set(SentinelTask.KINDS))
        self.assertEqual({k: kinds['openvas'][k] for k in ('declared', 'effective', 'mode', 'source', 'cap', 'held')},
                         {'declared': True, 'effective': False, 'mode': 'deny', 'source': 'agent', 'cap': None, 'held': 0})
        self.assertEqual({k: kinds['nmap'][k] for k in ('declared', 'effective', 'mode', 'source', 'cap')}, {'declared': True, 'effective': True, 'mode': 'prefer', 'source': 'agent', 'cap': 2})
        self.assertEqual((kinds['wpscan']['declared'], kinds['wpscan']['state']), (False, 'unavailable'))
        self.assertEqual(kinds['openvas']['by'], 's_root')
        self.assertNotIn('openvas', out['effective']['capabilities'])
        self.assertIn('nmap', out['effective']['capabilities'])
        self.assertEqual(out['settings']['kinds']['value']['openvas'], {'mode': 'deny', 'max_concurrent': None})
        self.assertEqual(out['settings']['disabled_kinds']['value'], ['openvas'])  # the older reading of the same thing
        _, listed = call(self.t['root'], 'GET', '/api/v1/agents?kind=scanner')
        self.assertNotIn('kinds', listed['results'][0])  # the list stays cheap: the detail carries it

    def test_a_refused_policy_says_why_and_stores_nothing(self):
        status, out = self.patch('root', {'kinds': {'wpscan': {'mode': 'allow', 'max_concurrent': None}}})
        self.assertEqual(status, 409)
        self.assertIn('not available on this Sentinel', out['error'])
        self.assertEqual(self.patch('root', {'kinds': {'nmap': {'mode': 'sometimes'}}})[0], 400)
        self.assertEqual(self.patch('root', {'kinds': {'nmap': {'mode': 'allow', 'max_concurrent': 99}}})[0], 400)
        self.assertEqual(Agent.objects.get(pk=self.agent_id).managed_settings or {}, {})

    def test_a_user_who_is_not_an_administrator_cannot_change_it(self):
        status, _ = self.patch('alice', {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        self.assertIn(status, (403, 404))
        self.assertEqual(Agent.objects.get(pk=self.agent_id).managed_settings or {}, {})
        status, _ = call(self.t['alice'], 'PUT', '/api/v1/sentinels/defaults', {'external_kinds': {'nmap': {'mode': 'deny', 'max_concurrent': None}}})
        self.assertEqual(status, 403)
        self.assertEqual(self.patch('dana', {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})[0], 403)  # an administrator cannot change their own Sentinel
        self.assertEqual(self.patch('root', {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})[0], 200)

    def test_the_sentinels_own_registration_cannot_carry_a_policy(self):
        status, out = call(self.t['dana'], 'PUT', '/api/v1/sentinel', {'name': 'policy-sentinel', 'scope': {'projects': ['sen-a']},
                                                                       'settings': {'kinds': {'nmap': {'mode': 'prefer', 'max_concurrent': 1}}}})
        self.assertEqual(status, 400)
        self.assertIn('unknown setting', out['error'])

    def test_the_heartbeat_reply_carries_the_derived_disabled_kinds(self):
        self.patch('root', {'kinds': {'openvas': {'mode': 'deny', 'max_concurrent': None}}})
        status, out = call(self.t['dana'], 'POST', '/api/v1/sentinel/heartbeat', {})
        self.assertEqual(status, 200, out)
        self.assertEqual(out['settings']['values']['disabled_kinds'], ['openvas'])
        self.assertNotIn('kinds', out['settings']['values'])

    def test_mcp_update_agent_and_get_sentinel_carry_the_policy(self):
        is_error, text = tool_call(self.t['root'], 'update_agent', {'agent_id': self.agent_id, 'settings': {'kinds': {'naabu': {'mode': 'deny', 'max_concurrent': None}}}})
        self.assertFalse(is_error, text)
        is_error, text = tool_call(self.t['root'], 'get_sentinel', {'agent_id': self.agent_id})
        self.assertFalse(is_error)
        self.assertEqual((text['kinds']['naabu']['mode'], text['kinds']['naabu']['effective']), ('deny', False))
        self.assertIn('machine', policy.SOURCES)

    def test_the_system_status_carries_by_kind(self):
        status, out = call(self.t['root'], 'GET', '/api/v1/system/status')
        self.assertEqual(status, 200)
        by_kind = out['system']['sentinels']['by_kind']
        self.assertEqual(by_kind['nmap']['live_sentinels'], 1)
        self.assertEqual(by_kind['wpscan']['state'], 'none')


class OpenvasTickTests(OpenvasFixture, TestCase):
    """The OpenVAS tick used to ``continue`` past a project with no eligible Sentinel without a word: it names the state now, once per tick."""

    def test_one_line_per_tick_names_why_nothing_was_dispatched(self):
        FakeScanner(kinds=['openvas']).start_for(self)  # the built-in scanner has OpenVAS denied by default
        self.settings.sentinel_only = True
        self.settings.save()
        with self.assertLogs('cveFeed.openvas_scan', level=logging.INFO) as logs:
            out = self.tick()
        lines = [m for m in logs.output if 'OpenVAS tick' in m]
        self.assertEqual(len(lines), 1, logs.output)
        self.assertIn('(disabled)', lines[0])
        self.assertIn('off on CVEngine Scanner', lines[0])
        self.assertIn('their hosts stay due', lines[0])
        self.assertIn('Sentinel-only mode is on', out['skipped'])
        self.assertIn('OpenVAS is not enabled on any live Sentinel (off on CVEngine Scanner)', out['skipped'])

    def test_with_no_sentinel_at_all_the_returned_text_is_the_one_it_always_was(self):
        self.settings.sentinel_only = True
        self.settings.save()
        with self.assertLogs('cveFeed.openvas_scan', level=logging.DEBUG) as logs:  # debug: no Sentinel at all is the ordinary way to this server's own OpenVAS
            out = self.tick()
        self.assertEqual(out, {'skipped': 'Sentinel-only mode is on and no opted-in host with an eligible Sentinel is due'})
        self.assertIn('(never)', [m for m in logs.output if 'OpenVAS tick' in m][0])
