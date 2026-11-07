"""The built-in scanner as a default part of every install (docs/BUILTIN-SCANNER.md): on unless CVENGINE_BUILTIN_SCANNER=0 (which revokes it), the
kinds it runs never run here by default once it has enrolled (CVENGINE_LOCAL_FALLBACK unset; ``all`` is the escape hatch), what its image reports
(info.builtin, info.features), the vantage settings it alone is sent, signed-in nuclei dispatched through the secure read, and work that waited for a
scanner queued again for when one is back."""
import os
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from agentapi import builtin_scanner as builtin
from agentapi import scanner_state, sentinel_dispatch, sentinel_settings
from agentapi import sentinel_broker as sentinels
from agentapi.models import Agent, SentinelEnrollment, SentinelTask
from agentapi.services import ApiError
from cveFeed import auth_checks, egress_proxy, scanner_wait
from cveFeed.models import DeferredRetest
from reNgine.resources import ScannerUnavailable
from scanEngine.models import Proxy
from tests.test_sentinel_secret_read import SECRETS, SecretBase

BUILTIN_KINDS = set(sentinel_dispatch.BUILTIN_SCANNER_KINDS)
EVERY_LOCAL = set(SentinelTask.KINDS) - set(sentinel_dispatch.NEVER_LOCAL)  # every kind that has a local path at all


class Env:
    def env(self, **values):
        patcher = mock.patch.dict(os.environ, {k: v for k, v in values.items() if v is not None})
        patcher.start()
        self.addCleanup(patcher.stop)
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)


class SwitchTests(Env, TestCase):
    def test_it_is_on_unless_switched_off(self):
        self.env(CVENGINE_BUILTIN_SCANNER=None)
        self.assertTrue(builtin.enabled())
        for value in ('0', 'false', 'no', 'off', 'OFF'):
            self.env(CVENGINE_BUILTIN_SCANNER=value)
            self.assertFalse(builtin.enabled(), value)

    def test_unset_every_kind_runs_here_until_the_builtin_scanner_has_enrolled(self):
        self.env(CVENGINE_BUILTIN_SCANNER=None, CVENGINE_LOCAL_FALLBACK=None)
        self.assertEqual(sentinel_dispatch.local_fallback_kinds(), EVERY_LOCAL)
        self.assertEqual(scanner_state.state(), {'offline': False, 'kinds': [], 'never_seen': []})


class DefaultFallbackTests(Env, SecretBase):
    """SecretBase enrols a real built-in scanner (``CVENGINE_BUILTIN_SCANNER=1`` there)."""

    def test_unset_the_builtin_scanners_kinds_never_run_here_once_it_has_enrolled(self):
        self.env(CVENGINE_LOCAL_FALLBACK=None)
        allowed = sentinel_dispatch.local_fallback_kinds()
        self.assertFalse(allowed & BUILTIN_KINDS)
        self.assertEqual(allowed, EVERY_LOCAL - BUILTIN_KINDS)
        self.assertIn('openvas', allowed)  # the built-in scanner has no OpenVAS: the server's own sidecar still runs it

    def test_all_is_the_escape_hatch_and_the_off_switch_restores_every_kind(self):
        self.env(CVENGINE_LOCAL_FALLBACK='all')
        self.assertEqual(sentinel_dispatch.local_fallback_kinds(), EVERY_LOCAL)
        self.env(CVENGINE_LOCAL_FALLBACK=None, CVENGINE_BUILTIN_SCANNER='0')
        self.assertEqual(sentinel_dispatch.local_fallback_kinds(), EVERY_LOCAL)

    def test_turning_it_off_revokes_its_token_and_removes_the_blob(self):
        task = self.task(status='claimed', ref=None)
        self.env(CVENGINE_BUILTIN_SCANNER='0')
        out = builtin.ensure()
        self.assertEqual(out, {'state': 'disabled', 'revoked': 1})
        self.builtin.refresh_from_db()
        self.assertTrue(self.builtin.token.revoked)
        self.assertEqual(self.builtin.status, 'revoked')
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')  # handed back, not left with a revoked scanner
        self.assertFalse(os.path.exists(builtin.blob_path()))
        self.assertFalse(SentinelEnrollment.objects.filter(builtin=True, used_at__isnull=True).exists())
        self.assertEqual(builtin.ensure(), {'state': 'disabled', 'revoked': 0})  # again: nothing more to do

    def test_info_records_builtin_and_known_features_only(self):
        out = sentinel_settings.clean_info({'builtin': True, 'features': ['secret_read', 'vantage', 'root-shell']})
        self.assertEqual(out, {'builtin': True, 'features': ['secret_read', 'vantage']})
        for bad in ({'builtin': 'yes'}, {'features': 'secret_read'}, {'features': [1]}):
            with self.assertRaises(ApiError):
                sentinel_settings.clean_info(bad)


class VantageTests(Env, SecretBase):
    def setUp(self):
        super().setUp()
        egress_proxy.reset_cache()
        self.addCleanup(egress_proxy.reset_cache)
        self.env(CVENGINE_ALLOW_PRIVATE_TARGETS=None, COMPOSE_PROFILES=None, CVENGINE_TAILSCALE_STATUS_FILE='/nonexistent/status.json',
                 CVENGINE_PROXY_BYPASS='.corp.example.org', NO_PROXY=None, no_proxy=None, CVENGINE_PROXY_PRIVATE=None, CVENGINE_LOCAL_FALLBACK=None)

    def proxy_on(self):
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies='http://user:pw@198.51.100.7:3128')
        egress_proxy.reset_cache()

    def test_nothing_set_nothing_sent(self):
        self.assertNotIn('vantage', sentinel_settings.reply(self.builtin)['values'])

    def test_the_builtin_scanner_alone_is_sent_the_proxy_and_the_private_ranges(self):
        self.proxy_on()
        self.env(CVENGINE_ALLOW_PRIVATE_TARGETS='1')
        values = sentinel_settings.reply(self.builtin)['values']
        self.assertEqual(values['vantage']['proxies'], ['http://user:pw@198.51.100.7:3128'])
        self.assertEqual(values['vantage']['bypass'], ['.corp.example.org'])
        self.assertIs(values['vantage']['proxy_private'], False)
        self.assertIn('10.0.0.0/8', values['vantage']['private_ranges'])
        for agent in (self.external, self.instance):
            self.assertNotIn('vantage', sentinel_settings.reply(agent)['values'])

    def test_tailscale_opens_only_the_tailnet(self):
        self.env(COMPOSE_PROFILES='tailscale')
        self.assertEqual(sentinel_settings.reply(self.builtin)['values']['vantage'], {'private_ranges': list(sentinel_settings.TAILNET_RANGES)})

    def test_a_changed_proxy_changes_the_revision(self):
        before = sentinel_settings.reply(self.builtin)['rev']
        self.proxy_on()
        self.assertNotEqual(sentinel_settings.reply(self.builtin)['rev'], before)

    def test_no_warning_once_the_builtin_scanner_applies_them_and_one_for_an_older_image(self):
        self.proxy_on()
        self.env(CVENGINE_ALLOW_PRIVATE_TARGETS='1', COMPOSE_PROFILES='tailscale', CVENGINE_LOCAL_FALLBACK='none')  # every kind of the built-in scanner has no local path now, so only a list that takes the others off moves anything
        self.assertEqual(scanner_state.vantage_warnings(), [])
        Agent.objects.filter(pk=self.builtin.pk).update(info={'builtin': True})
        warnings = scanner_state.vantage_warnings()
        self.assertEqual(len(warnings), 3)
        self.assertTrue(all('whose image does not use' in w for w in warnings))


class SignedInDispatchTests(Env, SecretBase):
    def setUp(self):
        super().setUp()
        self.env(CVENGINE_LOCAL_FALLBACK=None, CVENGINE_SENTINEL_CLAIM_TIMEOUT='1', CVENGINE_SENTINEL_DISPATCH_TIMEOUT='2')
        self.cred.allow_untrusted_certificate = True
        self.cred.save()
        self.items = [auth_checks.PlanItem('https://www.a.example', self.cred, 'www.a.example')]
        # a lone signed-in task must be the only queued one the built-in scanner could take
        SentinelTask.objects.all().delete()

    def test_the_pass_is_sent_with_a_reference_never_the_value_and_waits_when_nobody_takes_it(self):
        run = sentinel_dispatch.signed_in_stream(self.scan, 'nuclei_targeted')
        kinds = set()
        token = scanner_wait._waited.set(kinds)
        try:
            with self.assertRaises(ScannerUnavailable):
                list(run(self.items, tags=['cve'], secret_file='/should/not/travel'))
        finally:
            scanner_wait._waited.reset(token)
        task = SentinelTask.objects.get()
        self.assertEqual(task.secret_ref, sentinels.secret_ref_for(self.cred.pk))
        self.assertEqual(task.target['targets'], ['https://www.a.example'])
        for secret in (*SECRETS, '/should/not/travel'):
            self.assertNotIn(secret, str(task.target))
        self.assertEqual(kinds, {'nuclei_targeted'})  # the scan's hosts are queued again for when a scanner is back

    def test_the_builtin_scanners_findings_come_back_as_nuclei_lines(self):
        finding = {'template_id': 't-1', 'name': 'Admin panel', 'severity': 'high', 'host': 'https://www.a.example',
                   'matched_at': 'https://www.a.example/admin'}
        with mock.patch.object(sentinel_dispatch, 'dispatch_or_none', return_value={'findings': [finding]}) as dispatch:
            lines = list(sentinel_dispatch.signed_in_stream(self.scan, 'nuclei_targeted')(self.items, tags=['cve']))
        self.assertEqual(lines[0]['template-id'], 't-1')
        self.assertEqual(dispatch.call_args.kwargs['secret_ref'], sentinels.secret_ref_for(self.cred.pk))

    def test_without_a_builtin_scanner_that_reads_sign_ins_it_waits_even_with_every_kind_allowed_here(self):
        self.env(CVENGINE_LOCAL_FALLBACK='all')  # the nuclei kinds have no local path whatever this says (NEVER_LOCAL)
        Agent.objects.filter(pk=self.builtin.pk).update(info={'builtin': True})  # an image that cannot read sign-ins
        with self.assertRaises(ScannerUnavailable):
            list(sentinel_dispatch.signed_in_stream(self.scan, 'nuclei_targeted')(self.items, tags=['cve']))
        self.assertFalse(SentinelTask.objects.exists())

    def test_the_wrapped_stream_carries_the_signed_in_runner(self):
        stream = sentinel_dispatch.wrap_nuclei_stream(self.scan, 'nuclei_targeted')
        self.assertTrue(callable(getattr(stream, 'signed_in', None)))


class RequeueTests(Env, SecretBase):
    def setUp(self):
        super().setUp()
        self.env(CVENGINE_LOCAL_FALLBACK=None, CVENGINE_SCANNER_REQUEUE_MINUTES='10')

    def test_a_run_that_waited_queues_its_hosts_again_after_the_delay(self):
        @scanner_wait.requeues(lambda result, args, kwargs: ['www.a.example', 'api.a.example'])
        def pipeline():
            scanner_wait.noted('nmap')
            return {'scan_id': self.scan.id, 'status': 'done'}
        out = pipeline()
        self.assertEqual(out['scanner_waited'], ['nmap'])
        rows = DeferredRetest.objects.filter(signature=scanner_wait.SIGNATURE)
        self.assertEqual(sorted(r.host for r in rows), ['api.a.example', 'www.a.example'])
        self.assertTrue(all(r.next_attempt_at > timezone.now() + timedelta(minutes=9) for r in rows))
        pipeline()  # again while they wait: one row per host
        self.assertEqual(rows.count(), 2)

    def test_a_run_that_did_not_wait_queues_nothing(self):
        @scanner_wait.requeues(lambda result, args, kwargs: None)
        def pipeline():
            return {'scan_id': self.scan.id}
        self.assertNotIn('scanner_waited', pipeline())
        self.assertFalse(DeferredRetest.objects.exists())

    def test_the_dispatcher_holds_them_back_while_a_scanner_is_missing(self):
        from cveFeed import retest
        DeferredRetest.objects.create(project_id=self.scan.domain.project_id, domain=self.scan.domain, scan=self.scan, host='www.a.example',
                                      signature=scanner_wait.SIGNATURE, next_attempt_at=timezone.now() - timedelta(minutes=1))
        with mock.patch.object(scanner_wait, 'held_back', return_value=True), mock.patch('cveFeed.tasks.retest_hosts.delay') as delay:
            self.assertEqual(retest.dispatch_deferred_retests(), {'queued': 0})
        delay.assert_not_called()
        row = DeferredRetest.objects.get()
        self.assertEqual(row.status, 'pending')
        self.assertGreater(row.next_attempt_at, timezone.now())
        DeferredRetest.objects.filter(pk=row.pk).update(next_attempt_at=timezone.now() - timedelta(minutes=1))
        with mock.patch.object(scanner_wait, 'held_back', return_value=False), mock.patch('cveFeed.tasks.retest_hosts.delay') as delay:
            self.assertEqual(retest.dispatch_deferred_retests()['queued'], 1)
        delay.assert_called_once()

    def test_a_re_test_that_waited_again_stays_pending(self):
        from cveFeed import tasks
        row = DeferredRetest.objects.create(project_id=self.scan.domain.project_id, domain=self.scan.domain, scan=self.scan, host='www.a.example',
                                            signature=scanner_wait.SIGNATURE, status='queued', attempts=1)
        from cveFeed.discovery import SUCCESS
        outcome = {'status': SUCCESS, 'scan_id': self.scan.id, 'scanner_waited': ['nmap']}
        with mock.patch('cveFeed.discovery.run_host_pipeline', return_value=outcome), mock.patch('cveFeed.bounty_gate.Gate.project_blocked', return_value=False):
            tasks.retest_hosts.run(self.scan.domain_id, ['www.a.example'], self.scan.id, [row.pk])
        row.refresh_from_db()
        self.assertEqual((row.status, row.attempts), ('pending', 0))
        self.assertGreater(row.next_attempt_at, timezone.now())


class ResultTests(SecretBase):
    def test_a_result_knows_whether_the_builtin_scanner_ran_it(self):
        self.assertTrue(sentinel_dispatch.Result({'hosts': []}, agent_id=self.builtin.pk).ran_here)
        self.assertFalse(sentinel_dispatch.Result({'hosts': []}, agent_id=self.external.pk).ran_here)
        self.assertEqual(sentinel_dispatch.Result({'a': 1}, agent_id=1), {'a': 1})
