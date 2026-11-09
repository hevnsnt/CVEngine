"""Discovery API keys to the owner's own Sentinels (owner approval 2026-11-08, option 2): the one gate (``sentinel_stream.key_delivery_decision``), the
claim, the single-use read and its audit, the capacity answer and its plain reasons, and a canary showing that no key value is in any row, activity line, log
or result of the server. Key values here are fakes (FAKE-KEY-...)."""
import json
import logging
from unittest import mock

from agentapi import sentinel_broker as broker
from agentapi import sentinel_settings
from agentapi import sentinel_stream as stream
from agentapi.models import Agent, SentinelPartial, SentinelTask
from agentapi.services import ApiError
from cveFeed import tunables
from cveFeed.models import AgentActivity
from dashboard.models import AuditLog
from tests.test_agentapi import call
from tests.test_sentinel_secret_read import SecretBase
from tests.test_sentinels import reset_rates

CANARY = 'FAKE-KEY-CANARY-7d41c0ffee'
CANARY2 = 'FAKE-ID-CANARY-90ab:FAKE-SECRET-CANARY-55cd'
ARGS = ['-c', f'modules.shodan_dns.api_key={CANARY}', '-c', f'modules.censys_dns.api_key={CANARY2}']
KEYS = {'modules': {'shodan_dns': {'api_key': CANARY}, 'censys_dns': {'api_key': CANARY2}}}


def instance_setting(value):
    """The instance setting ``sentinel_bbot_keys`` read as ``value`` (1 or 0) and every other tunable as it is."""
    real = tunables.value
    return mock.patch('cveFeed.tunables.value', side_effect=lambda key, default=None: value if key == 'sentinel_bbot_keys' else real(key, default))


class KeysBase(SecretBase):
    def setUp(self):
        super().setUp()
        for agent in (self.builtin, self.external, self.instance):
            Agent.objects.filter(pk=agent.pk).update(capabilities=sorted({*agent.capabilities, 'bbot_discovery', 'nmap'}),
                                                     info={**agent.info, 'contract_version': 3})
        self.say(self.external, True)
        self.say(self.instance, True)
        for agent in (self.builtin, self.external, self.instance):
            agent.refresh_from_db()
            self.touch(agent)
        self.ref = stream.keys_ref(self.pa.pk)

    def say(self, agent, flagged):
        features = ['bbot_keys'] if flagged else []
        Agent.objects.filter(pk=agent.pk).update(info={**(Agent.objects.get(pk=agent.pk).info or {}), 'features': features})
        agent.refresh_from_db()

    def eff(self, agent):
        agent.refresh_from_db()
        return broker.effective(agent)

    def keyed(self, agent=None, status='claimed', kind='bbot_discovery', project=None, ref='default'):
        task = self.task(agent=agent, status=status, kind=kind, project=project, ref=self.ref if ref == 'default' else ref)
        return SentinelTask.objects.select_related('project').get(pk=task.pk)

    def everything(self):
        return ' '.join([str(list(AuditLog.objects.values())), str(list(SentinelTask._base_manager.values())), str(list(SentinelPartial._base_manager.values())),
                         str(list(AgentActivity.objects.values())), ' '.join(self.logs.lines)])

    def assertNoKeyAnywhere(self):
        everything = self.everything()
        for needle in (CANARY, CANARY2, *CANARY2.split(':')):
            self.assertNotIn(needle, everything)


class GateTests(KeysBase):
    def decide(self, who, kind='bbot_discovery', ref='default', project=None):
        ref = self.ref if ref == 'default' else ref
        return stream.key_delivery_decision(self.eff(who), kind, ref, (project or self.pa).pk)

    def test_an_own_sentinel_that_says_bbot_keys_is_allowed_for_its_discovery(self):
        self.assertEqual(self.decide(self.external), (True, ''))
        self.assertEqual(self.decide(self.instance), (True, ''))
        self.assertEqual(self.decide(self.builtin), (True, ''))  # unchanged: the built-in scanner reads secrets

    def test_a_sentinel_that_does_not_say_it_never_gets_keys(self):
        self.say(self.external, False)  # every older client
        self.assertEqual(self.decide(self.external), (False, 'keys_client_outdated'))
        Agent.objects.filter(pk=self.external.pk).update(info={'contract_version': 3})  # no features field at all
        self.assertEqual(self.decide(self.external), (False, 'keys_client_outdated'))
        task = self.keyed(status='queued')
        self.assertEqual(self.eff(self.external).refusal(task), ('capability', 'keys_client_outdated'))
        self.assertEqual(broker.queued_for(self.external), {})

    def test_the_instance_setting_off_stops_every_external_sentinel_but_not_the_builtin_one(self):
        with instance_setting(0):
            self.assertEqual(self.decide(self.external), (False, 'keys_setting_off'))
            self.assertEqual(self.decide(self.instance), (False, 'keys_setting_off'))
            self.assertEqual(self.decide(self.builtin), (True, ''))

    def test_a_sentinels_own_opt_out_stops_it_alone(self):
        sentinel_settings.set_managed(self.external, {'discovery_keys': False}, self.root)
        self.assertEqual(self.decide(self.external), (False, 'keys_sentinel_opt_out'))
        self.assertEqual(self.decide(self.instance), (True, ''))
        self.assertTrue(AuditLog.objects.filter(action='agent.settings', detail__discovery_keys_after='never send').exists())
        sentinel_settings.set_managed(self.external, {'discovery_keys': None}, self.root)  # back to following the instance
        self.assertEqual(self.decide(self.external), (True, ''))
        self.assertNotIn('discovery_keys', sentinel_settings.effective(self.external))  # never sent to a Sentinel
        with self.assertRaises(ApiError):
            sentinel_settings.clean_settings({'discovery_keys': 'no'})
        self.assertEqual(sentinel_settings.clean_settings({'discovery_keys': True}), {'discovery_keys': True})
        with self.assertRaises(ApiError):
            sentinel_settings.clean_settings({'discovery_keys': False}, managed=False)  # a Sentinel cannot set it itself

    def test_only_bbot_discovery_carries_keys_every_other_kind_is_refused(self):
        for kind in SentinelTask.KINDS:
            if kind == 'bbot_discovery':
                continue
            for who in (self.external, self.instance, self.builtin):
                self.assertEqual(self.decide(who, kind=kind), (False, 'keys_wrong_kind'), (kind, who.name))

    def test_another_projects_keys_a_stored_sign_in_or_a_malformed_reference_are_refused(self):
        for who in (self.external, self.builtin):
            self.assertEqual(self.decide(who, ref=stream.keys_ref(self.pb.pk)), (False, 'keys_wrong_project'))
            self.assertEqual(self.decide(who, ref='bbotkeys:abc'), (False, 'keys_wrong_project'))
            self.assertEqual(self.decide(who, ref=broker.secret_ref_for(self.cred.pk)), (False, 'keys_wrong_project'))
            self.assertEqual(self.decide(who, ref=None), (False, 'keys_wrong_project'))
        task = self.keyed(status='queued', ref=broker.secret_ref_for(self.cred.pk), kind='bbot_discovery')
        self.assertEqual(self.eff(self.external).refusal(task), ('capability', broker.SIGNED_IN))  # a sign-in stays the built-in scanner's alone

    def test_a_suspended_sentinel_is_refused(self):
        Agent.objects.filter(pk=self.external.pk).update(status='suspended')
        self.assertEqual(self.decide(self.external)[0], False)


class ClaimTests(KeysBase):
    def claim(self, who, **body):
        status, out = call(self.t[who], 'POST', '/api/v1/sentinel/tasks/next', body)
        self.assertEqual(status, 200, out)
        return out['task']

    def test_a_keyed_discovery_is_claimed_by_a_flagged_sentinel_and_the_offer_carries_no_key(self):
        task = self.keyed(status='queued')
        offered = self.claim('external')
        self.assertEqual(offered['id'], task.pk)
        self.assertNotIn(CANARY, json.dumps(offered))

    def test_it_is_not_offered_to_a_sentinel_without_the_flag_or_with_the_setting_off_or_opted_out(self):
        task = self.keyed(status='queued')
        self.say(self.external, False)
        self.assertIsNone(self.claim('external'))
        self.say(self.external, True)
        with instance_setting(0):
            self.assertIsNone(self.claim('external'))
        sentinel_settings.set_managed(self.external, {'discovery_keys': False}, self.root)
        self.assertIsNone(self.claim('external'))
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')

    def test_no_other_kind_with_a_reference_is_ever_offered_to_an_external_sentinel(self):
        for kind in ('nmap', 'nuclei_targeted', 'secrets_scan', 'ssh_probe'):
            self.keyed(status='queued', kind=kind)
        for who in ('external', 'instance'):
            self.assertIsNone(self.claim(who), who)
        self.assertEqual(broker.queued_for(self.external), {})

    def test_keys_of_another_project_are_never_offered(self):
        self.keyed(status='queued', ref=stream.keys_ref(self.pb.pk))
        self.assertIsNone(self.claim('external'))

    def test_a_task_without_keys_is_unchanged(self):
        plain = self.keyed(status='queued', ref=None)
        self.assertEqual(self.claim('external')['id'], plain.pk)


class ReadTests(KeysBase):
    def test_a_flagged_sentinel_reads_the_keys_once_and_the_audit_names_providers_only(self):
        task = self.keyed(self.external)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            status, out = self.read('external', task)
            self.assertEqual(status, 200, out)
            self.assertEqual(out['bbot_config'], KEYS)
            self.assertEqual(self.read('external', task)[0], 409)
        task.refresh_from_db()
        self.assertIsNotNone(task.secret_read_at)
        rows = AuditLog.objects.filter(action='sentinel.discovery_keys.delivered')
        self.assertEqual(rows.count(), 1)
        row = rows.get()
        self.assertEqual(row.detail['providers'], ['censys_dns', 'shodan_dns'])
        self.assertIn('providers: censys_dns, shodan_dns', row.target)
        self.assertIn(self.external.name, row.target)
        self.assertEqual([a.detail['outcome'] for a in self.audits()], ['granted', 'refused: already read, or no longer held by this Sentinel'])
        self.assertNoKeyAnywhere()

    def test_a_response_is_not_cached(self):
        from django.test import Client
        task = self.keyed(self.external)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            response = Client().post(f'/api/v1/sentinel/tasks/{task.pk}/secret', HTTP_AUTHORIZATION=f'Bearer {self.t["external"]}')
        self.assertEqual((response.status_code, response['Cache-Control']), (200, 'no-store'))

    def test_an_old_sentinel_the_setting_off_and_an_opt_out_get_a_403_and_decrypt_nothing(self):
        def old():
            self.say(self.external, False)

        def opted_out():
            self.say(self.external, True)
            sentinel_settings.set_managed(self.external, {'discovery_keys': False}, self.root)
        for label, arrange in (('no flag', old), ('opt-out', opted_out)):
            with self.subTest(label):
                arrange()
                task = self.keyed(self.external)
                with mock.patch('cveFeed.api_credentials.bbot_config_args', side_effect=AssertionError('decrypted')) as decrypt:
                    status, out = self.read('external', task)
                self.assertEqual(status, 403, out)
                decrypt.assert_not_called()
                task.refresh_from_db()
                self.assertIsNone(task.secret_read_at)
                sentinel_settings.set_managed(self.external, {'discovery_keys': None}, self.root)
        self.say(self.external, True)
        task = self.keyed(self.external)
        with instance_setting(0), mock.patch('cveFeed.api_credentials.bbot_config_args', side_effect=AssertionError('decrypted')):
            self.assertEqual(self.read('external', task)[0], 403)
        self.assertFalse(AuditLog.objects.filter(action='sentinel.discovery_keys.delivered').exists())

    def test_every_other_kind_and_another_projects_keys_and_signed_in_tasks_are_refused_to_an_external_sentinel(self):
        refused = [self.keyed(self.external, kind=kind) for kind in ('nmap', 'nuclei_targeted', 'secrets_scan', 'ssh_probe', 'route_probe_signed')]
        refused.append(self.keyed(self.external, ref=stream.keys_ref(self.pb.pk)))
        refused.append(self.keyed(self.external, ref=broker.secret_ref_for(self.cred.pk)))
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            for task in refused:
                reset_rates(self.t)  # the secure read is limited to 6 calls a minute per token
                status, out = self.read('external', task)
                self.assertEqual(status, 403, (task.kind, task.secret_ref, out))
                self.assertNotIn(CANARY, json.dumps(out))
        self.assertFalse(AuditLog.objects.filter(action='sentinel.discovery_keys.delivered').exists())

    def test_it_is_only_for_the_sentinel_holding_the_task(self):
        task = self.keyed(self.external)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            self.assertEqual(self.read('instance', task)[0], 403)  # another Sentinel, even a flagged one
            task.status = 'done'
            task.save(update_fields=['status'])
            self.assertEqual(self.read('external', task)[0], 409)  # no longer in progress: refused, nothing read

    def test_the_builtin_scanner_reads_as_before_and_is_audited_the_same_way(self):
        task = self.keyed(self.builtin)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            self.assertEqual(self.read('builtin', task)[0], 200)
        self.assertEqual(AuditLog.objects.filter(action='sentinel.discovery_keys.delivered').count(), 1)

    def test_keys_that_no_longer_exist_are_a_410(self):
        task = self.keyed(self.external)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=[]):
            self.assertEqual(self.read('external', task)[0], 410)
        self.assertFalse(AuditLog.objects.filter(action='sentinel.discovery_keys.delivered').exists())


class CapacityTests(KeysBase):
    def state(self, **kw):
        return broker.capacity_state(self.pa, 'bbot_discovery', why=True, bbot_keys=True, **kw)

    def clear_builtin(self):
        Agent.objects.filter(pk=self.builtin.pk).update(last_seen=None)

    def test_an_own_sentinel_counts_as_capacity_for_a_keyed_discovery(self):
        self.clear_builtin()
        self.assertEqual(self.state()['state'], 'free')

    def test_with_nothing_allowed_the_answer_is_the_plain_reason(self):
        self.clear_builtin()
        with instance_setting(0):
            out = self.state()
        self.assertEqual((out['state'], out['reason']), ('none', 'keys_setting_off'))
        self.assertIn('your Sentinels are set not to receive them', out['message'])
        sentinel_settings.set_managed(self.external, {'discovery_keys': False}, self.root)
        sentinel_settings.set_managed(self.instance, {'discovery_keys': False}, self.root)
        self.assertEqual(self.state()['reason'], 'keys_sentinel_opt_out')
        sentinel_settings.set_managed(self.external, {'discovery_keys': None}, self.root)
        sentinel_settings.set_managed(self.instance, {'discovery_keys': None}, self.root)
        self.say(self.external, False)
        self.say(self.instance, False)
        out = self.state()
        self.assertEqual((out['state'], out['reason']), ('none', 'keys_client_outdated'))
        self.assertIn('too old', out['message'])
        self.assertIn('bbot_keys', out['message'])

    def test_a_blocked_external_sentinel_leaves_the_builtin_scanner_the_work(self):
        with instance_setting(0):
            out = self.state()
        self.assertEqual(out['state'], 'free')
        self.assertEqual(out['live'], 1)  # only the built-in scanner counts

    def test_without_any_live_sentinel_it_is_the_usual_answer(self):
        self.clear_builtin()
        Agent.objects.filter(pk__in=[self.external.pk, self.instance.pk]).update(last_seen=None)
        out = self.state()
        self.assertEqual(out['state'], 'none')
        self.assertNotIn('keys_', out['reason'])

    def test_the_dispatch_flags_follow_the_reference(self):
        from agentapi import sentinel_dispatch as dispatch
        self.assertEqual(dispatch.capacity_flags(self.ref), {'bbot_keys': True})
        self.assertEqual(dispatch.capacity_flags(broker.secret_ref_for(1)), {'builtin_only': True, 'secret': True})
        self.assertEqual(dispatch.capacity_flags(None), {'builtin_only': False, 'secret': False})


class CanaryTests(KeysBase):
    """One whole run through the server with a canary for a key: it is decrypted once, in the response only, and is in no row, activity line, log or result."""

    def test_no_key_value_is_kept_anywhere_after_a_run(self):
        logging.getLogger().setLevel(logging.DEBUG)
        task = self.keyed(status='queued')
        status, out = call(self.t['external'], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertEqual(out['task']['id'], task.pk)
        SentinelTask.objects.filter(pk=task.pk).update(target=stream.bbot_target(self.da, 'standard', 3600, api_keys=True))
        self.assertEqual(call(self.t['external'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept', {})[0], 200)
        with mock.patch('cveFeed.api_credentials.bbot_config_args', return_value=ARGS):
            status, out = self.read('external', task)
        self.assertEqual((status, out['bbot_config']), (200, KEYS))
        batch = {'seq': 1, 'subdomains': ['www.a.example'], 'ips': [], 'ports': [], 'urls': [], 'technologies': [], 'resolutions': [], 'edges': [],
                 'findings': [], 'http': [], 'events': [], 'screenshots': []}
        self.assertEqual(call(self.t['external'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/partial', batch)[0], 200)
        result = {'outcome': 'done', 'partials': 1, 'mode': 'standard', 'incomplete': '', 'scan_name': 'demo_scan', 'web_events': {'URL': 0, 'HTTP_RESPONSE': 0},
                  'problems': [{'module': 'shodan_dns', 'reason': 'Error with API (401) key ***'}], 'hard_failures': []}
        status, out = call(self.t['external'], 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', result)
        self.assertEqual(status, 200, out)
        task = SentinelTask._base_manager.get(pk=task.pk)
        self.assertEqual(task.status, 'done')
        # the task row keeps the reference and the time of the read, never a value
        self.assertEqual(task.secret_ref, self.ref)
        self.assertIsNotNone(task.secret_read_at)
        self.assertNoKeyAnywhere()
        self.assertNotIn(CANARY, json.dumps(task.result, default=str) + json.dumps(task.target, default=str))


class FeatureAndSettingTests(KeysBase):
    def test_the_heartbeat_features_keep_bbot_keys_and_drop_what_the_server_does_not_know(self):
        info = sentinel_settings.clean_info({'features': ['bbot_keys', 'made_up', 'secret_read']})
        self.assertEqual(info['features'], ['bbot_keys', 'secret_read'])
        self.assertIsNone(sentinel_settings.clean_info({'version': 'abc'}).get('features'))  # an old client sends none: tolerated

    def test_the_instance_setting_is_a_tunable_on_by_default(self):
        tunable = tunables.BY_KEY['sentinel_bbot_keys']
        self.assertEqual((tunable.default, tunable.low, tunable.high, tunable.group, tunable.env), (1, 0, 1, 'discovery_keys', 'CVENGINE_SENTINEL_BBOT_KEYS'))
        self.assertFalse(tunable.auto_tunable)
        self.assertTrue(stream.keys_enabled())
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_BBOT_KEYS': 'off'}):
            self.assertEqual(tunables.env_value(tunable), 0)

    def test_the_setting_appears_in_the_sentinels_detail_for_an_administrator(self):
        sentinel_settings.set_managed(self.external, {'discovery_keys': False}, self.root)
        self.external.refresh_from_db()
        self.assertIs(sentinel_settings.detail(self.external)['discovery_keys']['value'], False)
        self.assertTrue(sentinel_settings.discovery_keys_opt_out(self.external))
