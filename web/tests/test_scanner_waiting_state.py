"""The derived, read-only "scanner offline" state (``agentapi.scanner_state``): which kinds have no live scanner (no kind runs on this server), which of
those no scanner ever registered for, how it is shown (system status, the page strip) and how the sweeps that run on their own schedules stop dispatching,
raising, catching and logging every tick while they wait. It is a reading of the Sentinels' heartbeats, never a pause: ``ScanControl`` is untouched, nothing
running is stopped, and until the built-in scanner has enrolled nothing is reported. ``CVENGINE_LOCAL_FALLBACK`` is ignored since 1.4 (``policy`` sets it to prove it)."""
import json
import os
import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import scanner_state, sentinel_broker, sentinel_contract, sentinel_dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import conductor, tls_audit, wpscan_scan
from cveFeed.models import AgentActivity, ProbeObservation, ScanControl, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from targetApp.models import Domain
from tests import probe_scanner
from tests.test_route_auth import RouteFixture
from tests.test_system_status import call, patched
from tests.test_tls_audit import CLEAN
from tests.test_udp_scan import UdpBase, run_udp, udp_xml
from tests.test_wpscan_quick import WP
from tests.test_wordpress import WordPressFixture

ENV = 'CVENGINE_LOCAL_FALLBACK'  # ignored since 1.4
ALL_KINDS = [k for k in SentinelTask.KINDS if k not in scanner_state.NO_STAGE and k not in scanner_state.INTERNAL_ONLY]  # every kind but the internal one waits: none runs here


class FallbackEnv:
    """The built-in scanner has enrolled (the signal reads nothing before that), ``CVENGINE_LOCAL_FALLBACK`` is unset (it is ignored since 1.4: ``policy`` sets
    it to prove that), and each test gets a cache key of its own so the answers of other tests are never read."""

    def setUp(self):
        super().setUp()
        enrolled = mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=True)
        enrolled.start()
        self.addCleanup(enrolled.stop)
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(ENV, None)
        key = mock.patch.object(scanner_state, 'CACHE_KEY', f'test:{uuid.uuid4().hex}:')
        key.start()
        self.addCleanup(key.stop)

    def policy(self, value):
        if value is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = value


class SentinelWorld(FallbackEnv):
    def setUp(self):
        super().setUp()
        self.org = Org.objects.create(name='W', slug='waiting-org')
        self.project = Project.objects.create(name='W', slug='waiting-p', insert_date=timezone.now(), org=self.org)
        self.count = 0

    def sentinel(self, capabilities, status='active', seen='now', token_revoked=False, builtin=False):
        """A Sentinel of this project that speaks the current contract. ``builtin``: it is the install's own scanner, the only one offered the kinds
        ``sentinel_broker.BUILTIN_KINDS`` names."""
        self.count += 1
        user = User.objects.create_user(f'waiting-owner-{self.count}', password='x')
        token, _raw = create_token(user, f'waiting-token-{self.count}')
        if token_revoked:
            token.revoked = True
            token.save(update_fields=['revoked'])
        last_seen = {'now': timezone.now(), 'old': timezone.now() - timedelta(hours=2), None: None}[seen]
        agent = Agent.objects.create(token=token, name=f'sentinel-{self.count}', kind='scanner', status=status, capabilities=capabilities,
                                     scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []}, last_seen=last_seen,
                                     info={'contract_version': sentinel_contract.version()})
        if builtin:
            patcher = mock.patch('agentapi.sentinel_broker.builtin_pk', return_value=agent.pk)
            patcher.start()
            self.addCleanup(patcher.stop)
        return agent


class HelperTests(SentinelWorld, TestCase):
    def test_the_ignored_all_changes_nothing_every_kind_still_waits(self):
        for value in ('all', '*'):
            self.policy(value)
            self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)
            self.assertEqual(scanner_state.state()['kinds'], ALL_KINDS)

    def test_nothing_is_reported_until_the_builtin_scanner_has_enrolled(self):
        for value in (None, '', 'none'):
            self.policy(value)
            with mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False), self.assertNumQueries(0):
                self.assertEqual(scanner_state.waiting_kinds(), [])
                self.assertEqual(scanner_state.state(), {'offline': False, 'kinds': [], 'never_seen': []})

    def test_the_variable_is_read_nowhere_so_nothing_is_warned_about(self):
        for value in ('nmpa, Openvas,wpscn,nmpa', 'openvas,tesssl', 'none'):
            self.policy(value)
            with self.assertNoLogs('agentapi.sentinel_dispatch', 'WARNING'):
                self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)

    def test_naming_every_kind_in_the_ignored_variable_does_not_stop_it_waiting(self):
        self.policy(','.join(ALL_KINDS))
        self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)

    def test_with_no_sentinel_at_all_every_kind_waits_and_none_was_ever_seen(self):
        out = scanner_state.state()
        self.assertTrue(out['offline'])
        self.assertEqual(out['kinds'], ALL_KINDS)
        self.assertEqual(out['never_seen'], ALL_KINDS)
        self.assertNotIn('since', out)
        self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)

    def test_a_live_sentinel_takes_its_kinds_out_of_waiting_and_out_of_never_seen(self):
        self.sentinel(['nmap', 'naabu', 'nuclei_light'])
        out = scanner_state.state()
        self.assertEqual(out['kinds'], [k for k in ALL_KINDS if k not in ('nmap', 'naabu', 'nuclei_light')])
        self.assertEqual(out['never_seen'], out['kinds'])
        self.assertFalse(scanner_state.is_waiting('nmap'))
        self.assertTrue(scanner_state.is_waiting('testssl'))

    def test_a_kind_only_the_built_in_scanner_takes_waits_while_only_an_external_sentinel_declares_it(self):
        self.sentinel(ALL_KINDS)
        self.assertEqual(scanner_state.state()['kinds'], [k for k in ALL_KINDS if k in sentinel_broker.BUILTIN_KINDS])
        self.assertTrue(scanner_state.is_waiting('path_probe'))
        self.assertFalse(scanner_state.is_waiting('waf'))

    def test_a_live_sentinel_for_every_kind_is_not_offline(self):
        self.sentinel(ALL_KINDS)
        self.sentinel(list(sentinel_broker.BUILTIN_KINDS), builtin=True)  # the kinds only the install's own scanner takes
        self.assertEqual(scanner_state.state(), {'offline': False, 'kinds': [], 'never_seen': []})

    def test_a_registered_sentinel_that_is_not_live_waits_but_was_seen(self):
        agent = self.sentinel(['nmap', 'testssl'], seen='old')
        out = scanner_state.state()
        self.assertEqual(out['kinds'], ALL_KINDS)
        self.assertEqual(out['never_seen'], [k for k in ALL_KINDS if k not in ('nmap', 'testssl')])
        self.assertEqual(out['since'], agent.last_seen.isoformat())

    def test_a_pending_sentinel_that_never_heartbeated_counts_as_registered(self):
        self.sentinel(['wpscan'], status='pending', seen=None)
        out = scanner_state.state()
        self.assertIn('wpscan', out['kinds'])
        self.assertNotIn('wpscan', out['never_seen'])
        self.assertNotIn('since', out)

    def test_a_suspended_sentinel_is_not_live_even_when_it_heartbeats(self):
        self.sentinel(['nmap'], status='suspended')
        self.assertIn('nmap', scanner_state.waiting_kinds())
        self.assertNotIn('nmap', scanner_state.state()['never_seen'])

    def test_a_revoked_sentinel_waits_and_was_seen(self):
        self.sentinel(['nmap'], status='revoked')
        self.sentinel(['naabu'], token_revoked=True)  # a live-looking one whose token was revoked
        out = scanner_state.state()
        self.assertIn('nmap', out['kinds'])
        self.assertIn('naabu', out['kinds'])
        self.assertNotIn('nmap', out['never_seen'])
        self.assertNotIn('naabu', out['never_seen'])

    def test_a_sentinel_that_is_not_a_scanner_does_not_count(self):
        agent = self.sentinel(['nmap'])
        Agent.objects.filter(pk=agent.pk).update(kind='validation')
        self.assertEqual(scanner_state.state()['never_seen'], ALL_KINDS)

    def test_a_list_in_the_ignored_variable_takes_no_kind_off_the_waiting_list(self):
        self.policy('openvas,hygiene_check')
        self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)
        self.sentinel(['openvas'])  # a Sentinel for one of them takes only its own kind out
        scanner_state.CACHE_KEY = f'test:{uuid.uuid4().hex}:'
        self.assertEqual(scanner_state.waiting_kinds(), [k for k in ALL_KINDS if k != 'openvas'])

    def test_a_kind_the_sentinel_cannot_run_yet_is_still_waiting(self):
        self.sentinel(['nmap'])
        with mock.patch('agentapi.sentinel_contract.can_run', side_effect=lambda reported, kind: kind != 'nmap'):
            self.assertIn('nmap', scanner_state.waiting_kinds())

    def test_the_answer_is_cached_so_a_second_call_makes_no_query(self):
        self.sentinel(['nmap'])
        first = scanner_state.state()
        with self.assertNumQueries(0):
            self.assertEqual(scanner_state.state(), first)
            self.assertEqual(scanner_state.waiting_kinds(), first['kinds'])
            self.assertEqual(scanner_state.skip_note('testssl'), 'no scanner is online for testssl; the targets stay due')
            self.assertIsNone(scanner_state.skip_note('nmap'))

    def test_the_first_call_costs_the_live_sentinels_rights_and_nothing_else(self):
        for _ in range(6):
            self.sentinel(['nmap'])
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as small:
            scanner_state.state()
        self.sentinel(['naabu'])
        self.sentinel(['testssl'])
        scanner_state.CACHE_KEY = f'test:{uuid.uuid4().hex}:'  # a fresh key: ask again
        with CaptureQueriesContext(connection) as large:
            scanner_state.state()
        self.assertLess(len(small), 6 * 8 + 6)  # the rights of each live Sentinel (a few queries each) and two for the rest, never a scan of anything else
        self.assertLess(len(large) - len(small), 2 * 8 + 2)  # two more Sentinels cost two more rights, not another sweep

    def test_the_cache_lasts_about_fifteen_seconds_and_a_scanner_returning_clears_it_then(self):
        self.assertIn('nmap', scanner_state.waiting_kinds())
        self.sentinel(['nmap'])
        self.assertIn('nmap', scanner_state.waiting_kinds())  # still the old answer inside the window
        self.assertEqual(scanner_state.CACHE_SECONDS, 15)
        scanner_state.CACHE_KEY = f'test:{uuid.uuid4().hex}:'  # the window passed
        self.assertNotIn('nmap', scanner_state.waiting_kinds())

    def test_a_changed_ignored_setting_changes_nothing(self):
        self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)
        self.policy(None)
        self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)

    def test_a_cache_that_is_down_only_means_asking_again(self):
        with mock.patch('django.core.cache.cache.get', side_effect=OSError('down')), mock.patch('django.core.cache.cache.set', side_effect=OSError('down')):
            self.assertEqual(scanner_state.waiting_kinds(), ALL_KINDS)

    def test_a_sweep_goes_on_when_the_state_cannot_be_read(self):
        with mock.patch.object(scanner_state, '_compute', side_effect=RuntimeError('database gone')):
            self.assertIsNone(scanner_state.skip_note('testssl'))

    def test_a_named_time_is_not_cached(self):
        scanner_state.state()
        self.sentinel(['nmap'])
        self.assertNotIn('nmap', scanner_state.waiting_kinds(now=timezone.now()))

    def test_reading_it_writes_nothing(self):
        self.sentinel(['nmap'], seen='old')
        before = (ScanControl.objects.count(), SentinelTask.objects.count(), Agent.objects.count(), AgentActivity.objects.count())
        scanner_state.state()
        scanner_state.status()
        scanner_state.status(admin=False)
        self.assertEqual(before, (ScanControl.objects.count(), SentinelTask.objects.count(), Agent.objects.count(), AgentActivity.objects.count()))
        self.assertFalse(ScanControl.objects.exists())


class WordingTests(SimpleTestCase):
    def test_the_two_sentences(self):
        text = scanner_state.messages({'offline': True, 'kinds': ['nmap', 'testssl', 'wpscan'], 'never_seen': ['wpscan']})
        self.assertEqual(text['offline'], 'Scanner offline: nmap, testssl work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.')
        self.assertEqual(text['never_seen'], 'No scanner has ever registered for wpscan, and this server runs none of them: '
                                             'nothing of that kind will run until one does.')

    def test_nothing_waiting_says_nothing(self):
        self.assertEqual(scanner_state.messages({'offline': False, 'kinds': [], 'never_seen': []}), {'offline': None, 'never_seen': None})

    def test_neither_sentence_is_the_pause_text(self):
        text = scanner_state.messages({'offline': True, 'kinds': ['nmap', 'testssl'], 'never_seen': ['testssl']})
        for sentence in text.values():
            self.assertNotIn('paused', sentence.lower())

    def test_a_member_does_not_get_the_sentence_that_names_a_server_setting(self):
        snapshot = {'offline': True, 'kinds': ['nmap', 'wpscan'], 'never_seen': ['wpscan']}
        admin, member = scanner_state.status(admin=True, snapshot=snapshot), scanner_state.status(admin=False, snapshot=snapshot)
        self.assertEqual(admin['never_seen'], ['wpscan'])
        self.assertEqual(len(admin['messages']), 2)
        self.assertEqual((member['kinds'], member['never_seen'], member['never_seen_message']), (['nmap'], [], None))
        self.assertNotIn('CVENGINE_LOCAL_FALLBACK', json.dumps(member))

    def test_the_status_has_no_unknown_kinds_whatever_the_ignored_variable_says(self):
        with mock.patch.dict(os.environ, {ENV: 'nmap,nmpa,wpscn'}):
            for admin in (True, False):
                out = scanner_state.status(admin=admin, snapshot={'offline': False, 'kinds': [], 'never_seen': []})
                self.assertNotIn('unknown_kinds', out)
                self.assertNotIn('unknown_kinds_message', out)
                self.assertNotIn('CVENGINE_LOCAL_FALLBACK', json.dumps(out))

    def test_a_member_with_only_never_seen_kinds_sees_nothing(self):
        member = scanner_state.status(admin=False, snapshot={'offline': True, 'kinds': ['wpscan'], 'never_seen': ['wpscan']})
        self.assertFalse(member['offline'])
        self.assertEqual(member['messages'], [])


class SystemStatusTests(SentinelWorld, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('waiting-root', 'r@x.io', 'x')
        cls.member = User.objects.create_user('waiting-member', password='x')
        _, cls.t_root = create_token(cls.root, 'root')
        _, cls.t_member = create_token(cls.member, 'member')

    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': '0'})
        patch.start()
        self.addCleanup(patch.stop)
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')

    def status(self, token):
        a, b, c = patched()
        with a, b, c:
            return call(token, 'GET', '/api/v1/system/status')[1]

    @mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False)  # nothing is reported until the built-in scanner has enrolled
    def test_before_the_builtin_scanner_enrolls_the_block_is_there_and_empty_and_nothing_else_changes(self, _enrolled):
        data = self.status(self.t_root)
        scanner = data['scanning']['scanner']
        self.assertEqual((scanner['offline'], scanner['kinds'], scanner['never_seen'], scanner['messages']), (False, [], [], []))
        self.assertFalse([p for p in data['problems'] if 'CVENGINE_LOCAL_FALLBACK' in p])
        self.assertFalse([n for n in data['notes'] if 'Scanner offline' in n])
        self.assertFalse(data['scanning']['paused'])

    def test_a_scanner_that_was_set_up_and_is_gone_is_a_note_not_a_problem_and_not_a_pause(self):
        self.sentinel(ALL_KINDS, seen='old')
        data = self.status(self.t_root)
        scanner = data['scanning']['scanner']
        self.assertTrue(scanner['offline'])
        self.assertEqual(scanner['kinds'], ALL_KINDS)
        self.assertEqual(scanner['never_seen'], [])
        self.assertIn('Scanner offline: nmap, ', scanner['message'])
        self.assertIn('Nothing has failed; it resumes automatically when a scanner reconnects.', scanner['message'])
        self.assertIn(scanner['message'], data['notes'])
        self.assertFalse([p for p in data['problems'] if 'Scanner offline' in p or 'CVENGINE_LOCAL_FALLBACK' in p])
        self.assertFalse(data['scanning']['paused'])
        self.assertFalse(ScanControl.current().paused)

    def test_a_kind_no_scanner_ever_registered_for_is_a_problem(self):
        self.sentinel(['nmap'], seen='old')
        data = self.status(self.t_root)
        scanner = data['scanning']['scanner']
        never = [k for k in ALL_KINDS if k not in ('nmap', 'openvas')]  # OpenVAS is an opt-in add-on: nothing waits for it here, so it is not named
        self.assertEqual(scanner['never_seen'], never)
        self.assertNotIn('openvas', scanner['never_seen_message'])
        self.assertEqual(scanner['never_seen_message'], scanner_state.messages(scanner)['never_seen'])
        self.assertIn(f"No scanner has ever registered for {', '.join(never)}, and this server runs none of them", scanner['never_seen_message'])
        self.assertIn(scanner['never_seen_message'], data['problems'])
        self.assertEqual(data['overall'], 'degraded')
        self.assertEqual(scanner['message'], 'Scanner offline: nmap work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.')

    def openvas_problems(self, **setup):
        data = self.status(self.t_root)
        return data, [p for p in data['problems'] + data['notes'] if 'openvas' in p.lower()]

    def test_openvas_absent_and_nothing_waiting_says_nothing_anywhere(self):
        self.sentinel([k for k in ALL_KINDS if k != 'openvas'])
        self.sentinel(list(sentinel_broker.BUILTIN_KINDS), builtin=True)
        data, found = self.openvas_problems()
        self.assertEqual(found, [])
        scanner = data['scanning']['scanner']
        self.assertNotIn('openvas', scanner['kinds'] + scanner['never_seen'])
        self.assertFalse([m for m in scanner['messages'] if 'openvas' in m.lower()])
        self.assertIsNone(scanner['never_seen_message'])

    def test_a_queued_openvas_task_makes_the_missing_scanner_a_problem(self):
        self.sentinel([k for k in ALL_KINDS if k != 'openvas'])
        self.sentinel(list(sentinel_broker.BUILTIN_KINDS), builtin=True)
        SentinelTask.objects.create(project=self.project, kind='openvas', status='queued', host='198.51.100.7', target={'addresses': ['198.51.100.7']})
        data, found = self.openvas_problems()
        self.assertEqual(len(found), 1)
        self.assertIn('No scanner has ever registered for openvas', found[0])
        self.assertIn(found[0], data['problems'])

    def test_a_project_with_openvas_turned_on_makes_the_missing_scanner_a_problem(self):
        from cveFeed.models import OpenvasProject, OpenvasSettings
        self.sentinel([k for k in ALL_KINDS if k != 'openvas'])
        self.sentinel(list(sentinel_broker.BUILTIN_KINDS), builtin=True)
        OpenvasProject.objects.create(project=self.project, enabled=True)
        self.assertEqual(self.openvas_problems()[1], [])  # the add-on's global switch is still off
        row = OpenvasSettings.current()
        row.enabled = True
        row.save()
        self.assertEqual(len(self.openvas_problems()[1]), 1)

    def test_an_openvas_scanner_that_registered_and_went_offline_is_still_said(self):
        self.sentinel(['openvas'], seen='old')
        data, found = self.openvas_problems()
        self.assertEqual(len(found), 1)
        self.assertIn('openvas work is waiting', found[0])

    def test_a_misspelt_ignored_variable_is_no_problem_for_anyone(self):
        self.policy('nmap,nmpa')
        self.sentinel(ALL_KINDS)
        for token in (self.t_root, self.t_member):
            data = self.status(token)
            self.assertNotIn('unknown_kinds', data['scanning']['scanner'])
            self.assertFalse([p for p in data['problems'] if 'CVENGINE_LOCAL_FALLBACK' in p or 'do not exist' in p])

    def test_a_live_scanner_for_everything_is_quiet(self):
        self.sentinel(ALL_KINDS)
        self.sentinel(list(sentinel_broker.BUILTIN_KINDS), builtin=True)  # the kinds only the install's own scanner takes
        scanner = self.status(self.t_root)['scanning']['scanner']
        self.assertFalse(scanner['offline'])

    def test_a_member_sees_the_waiting_kinds_but_not_the_server_setting_and_no_problem(self):
        self.sentinel(['nmap'], seen='old')
        data = self.status(self.t_member)
        scanner = data['scanning']['scanner']
        self.assertEqual(scanner['kinds'], ['nmap'])
        self.assertEqual(scanner['never_seen'], [])
        self.assertNotIn('CVENGINE_LOCAL_FALLBACK', json.dumps(data))
        self.assertFalse([p for p in data['problems'] if 'scanner' in p.lower()])


class StripEndpointTests(SentinelWorld, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('strip-root', 'r@x.io', 'x')
        cls.member = User.objects.create_user('strip-member', password='x')

    def setUp(self):
        super().setUp()
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')

    def get(self, user):
        self.client.force_login(user)
        return self.client.get('/cve/api/scanner')

    @mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False)  # nothing is reported until the built-in scanner has enrolled
    def test_before_the_builtin_scanner_enrolls_it_is_empty(self, _enrolled):
        response = self.get(self.root)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['messages'], [])
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_an_admin_gets_both_sentences_a_member_the_first(self):
        self.sentinel(['nmap'], seen='old')
        admin, member = self.get(self.root).json(), self.get(self.member).json()
        self.assertEqual(len(admin['messages']), 2)
        self.assertEqual(admin['message'], 'Scanner offline: nmap work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.')
        self.assertEqual(member['messages'], [member['message']])
        self.assertIsNone(member['never_seen_message'])

    def test_it_asks_for_a_login(self):
        self.client.logout()
        self.assertNotEqual(self.client.get('/cve/api/scanner').status_code, 200)

    def test_the_page_loads_the_strip_and_the_strip_has_its_own_look_and_words(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        base = (root / 'cveFeed' / 'templates' / 'cveFeed' / 'base.html').read_text()
        js = (root / 'static' / 'cve' / 'scannerbar.js').read_text()
        css = (root / 'static' / 'cve' / 'cve.css').read_text()
        self.assertIn("{% asset 'cve/scannerbar.js' %}", base)
        self.assertIn('/cve/api/scanner', js)
        self.assertIn('.scannerbar{', css)
        self.assertNotIn('.scannerbar.update', css)
        self.assertNotIn('paused', js.lower())  # a different message and colour from the pause and the update's drain


class NoActivity:
    """Asserts on the feed itself, not on a mock: the sweep wrote no activity row."""

    def assertQuiet(self):
        self.assertEqual(AgentActivity.objects.count(), 0)
        self.assertFalse(ScanControl.objects.exists())
        self.assertFalse(SentinelTask.objects.exists())


class TestsslSweepTests(NoActivity, FallbackEnv, RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',), ports=((443, 'https'),))
        mock.patch('reNgine.resources.global_pause_requested', return_value=False).start()

    def sweep(self):
        return tls_audit.sweep(self.project.id, resolve=lambda host, port, project: '203.0.113.5')

    def test_waiting_for_a_scanner_it_does_not_run_log_or_raise(self):
        with mock.patch('agentapi.sentinel_dispatch.try_testssl') as dispatched:
            out = self.sweep()
        self.assertEqual(out['skipped'], 'no scanner is online for testssl; the targets stay due')
        self.assertEqual((out['tested'], out['failed']), (0, 0))
        dispatched.assert_not_called()
        self.assertQuiet()
        self.assertFalse(ServiceRun.objects.exists())  # the target is still due: nothing was recorded, so nothing is fresh

    def test_it_never_runs_here_whatever_the_policy_says(self):
        for value in (None, 'all', 'testssl'):
            with self.subTest(policy=value):
                self.policy(value)
                out = self.sweep()  # with other kinds still local the stage itself finds no scanner and waits (NEVER_LOCAL)
                self.assertRegex(out['skipped'], r'no scanner (is online for|could take this work \() ?testssl')
                self.assertEqual((out['tested'], out['failed']), (0, 0))
                self.assertFalse(ServiceRun.objects.exists())

    def test_the_daily_sweep_over_all_projects_returns_before_taking_its_claim(self):
        with mock.patch('cveFeed.ledger.sweep_claim') as claim:
            out = tls_audit.sweep_all()
        self.assertEqual(out, {'skipped': 'no scanner is online for testssl; the targets stay due'})
        claim.assert_not_called()
        self.assertQuiet()

    def test_a_live_scanner_for_it_lets_it_through(self):
        user = User.objects.create_user('tls-owner', password='x')
        token, _raw = create_token(user, 'tls-token')
        Agent.objects.create(token=token, name='tls', kind='scanner', status='active', capabilities=['testssl'], last_seen=timezone.now(),
                             scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
        self.assertIsNone(scanner_state.skip_note('testssl'))
        with mock.patch('agentapi.sentinel_dispatch.try_testssl', return_value=CLEAN):
            self.assertEqual(self.sweep()['tested'], 1)  # the sweep goes on with the Sentinel's report


class UdpSweepTests(NoActivity, FallbackEnv, UdpBase):
    def runner(self):
        calls = []

        def run(targets, flags, host_timeout):
            calls.append(targets)
            return udp_xml(targets[0], {53: 'closed'})
        run.calls = calls
        return run

    def test_waiting_for_a_scanner_it_runs_nothing_and_logs_nothing(self):
        self.ip('192.0.2.10')
        runner = self.runner()
        with mock.patch('cveFeed.coverage_topup.log_deferral') as deferral:
            out = run_udp(runner=runner)
        self.assertEqual(out, {'skipped': 'no scanner is online for nmap_udp; the targets stay due'})
        self.assertEqual(runner.calls, [])
        deferral.assert_not_called()
        self.assertQuiet()
        self.assertFalse(ServiceRun.objects.exists())

    def test_it_answers_before_the_coverage_check_and_before_any_claim(self):
        with mock.patch('cveFeed.coverage_topup.backlog_exists') as backlog, mock.patch('reNgine.resources.redis_claim') as claim:
            run_udp(runner=self.runner())
        backlog.assert_not_called()
        claim.assert_not_called()

    @mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False)  # nothing is reported until the built-in scanner has enrolled
    def test_before_the_builtin_scanner_enrolls_it_runs_exactly_as_before(self, _enrolled):
        self.ip('192.0.2.10')
        runner = self.runner()
        out = run_udp(runner=runner, pipeline=lambda d, n: None)
        self.assertEqual(len(out['scanned']), 1)
        self.assertEqual(len(runner.calls), 1)

    def test_the_off_switch_is_still_answered_first(self):
        with mock.patch.dict(os.environ, {'CVENGINE_UDPSCAN': '0'}):
            self.assertEqual(run_udp(runner=self.runner()), {'skipped': 'CVENGINE_UDPSCAN is off'})

    def test_a_scanner_for_another_kind_does_not_let_it_through(self):
        user = User.objects.create_user('udp-owner', password='x')
        token, _raw = create_token(user, 'udp-token')
        Agent.objects.create(token=token, name='nmap-only', kind='scanner', status='active', capabilities=['nmap'], last_seen=timezone.now(),
                             scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
        self.assertIn('nmap_udp', scanner_state.waiting_kinds())


class WpscanQuickTests(NoActivity, FallbackEnv, WordPressFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.table = dict(WP)

    def start_scanner(self):
        """A scanner that answers the WordPress probe but has no ``wpscan``: the quick pass has nothing to wait for it on, and must say so."""
        return probe_scanner.start(self, get=self.probe_get)

    def run_quick(self, **kw):
        return wpscan_scan.run_quick(self.scan_obj.id, ['rt.test'], attempt=2, runner=kw.pop('runner', self.runner))

    @mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False)  # nothing is reported until the built-in scanner has enrolled
    def test_before_the_builtin_scanner_enrolls_it_runs_exactly_as_before(self, _enrolled):
        out = self.run_quick()
        self.assertNotIn('skipped', out)
        self.assertEqual({u for u, _t in self.calls}, {'https://rt.test'})

    def test_waiting_for_a_scanner_it_does_not_scan_log_or_record_a_state(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async') as again:
            out = self.run_quick()
        self.assertEqual(out, {'skipped': 'no scanner is online for wpscan; the targets stay due'})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.asked, [])
        self.assertQuiet()
        self.assertFalse(ProbeObservation.objects.exists())
        _args, kwargs = again.call_args
        # asked again at the same attempt after the same delay, so a scanner coming back finds it without the tries having been spent
        self.assertEqual(kwargs['args'], [self.scan_obj.id, ['rt.test'], 2])
        self.assertEqual((kwargs['countdown'], kwargs['queue']), (wpscan_scan.QUICK_DELAY * 2, wpscan_scan.QUEUE))

    def test_a_broker_that_is_down_does_not_fail_it(self):
        with mock.patch('cveFeed.tasks.wpscan_quick.apply_async', side_effect=OSError('broker down')):
            out = self.run_quick()
        self.assertIn('no scanner is online', out['skipped'])

    def test_a_pause_is_answered_before_it(self):
        from reNgine import resources
        with mock.patch.object(resources, 'global_pause_requested', return_value=True), mock.patch.object(wpscan_scan, 'queue_quick') as again:
            out = self.run_quick()
        self.assertIn('paused', out['skipped'])
        again.assert_called_once()


class ConductorWaitingTests(FallbackEnv, TestCase):
    """The conductor starts discovery (bbot runs on this server), which is local work: it goes on while kinds wait for a scanner, and says so."""

    def setUp(self):
        super().setUp()
        engine = EngineType.objects.create(engine_name='e-cw', yaml_configuration='x', default_engine=True)  # noqa: F841 - the engine discovery picks
        org = Org.objects.create(name='C', slug='cw-org')
        project = Project.objects.create(name='C', slug='cw-p', insert_date=timezone.now(), org=org)
        Domain.objects.create(name='due.cw.test', project=project, insert_date=timezone.now())
        for patcher in (mock.patch('cveFeed.tasks.run_bbot_discovery.delay'), mock.patch('cveFeed.ledger.sweep_claim', return_value=True),
                        mock.patch.dict('os.environ', {'CVENGINE_WORK_DEPTH': '3', 'CVENGINE_WORK_MIN_GAP_HOURS': '2'})):
            patcher.start()
            self.addCleanup(patcher.stop)

    @property
    def delay(self):
        from cveFeed.tasks import run_bbot_discovery
        return run_bbot_discovery.delay

    def test_it_still_starts_discovery_and_records_what_waits(self):
        result = conductor.keep_work_queued()
        self.assertEqual(result['started'], 1)
        self.assertEqual(result['scanner_waiting'], ALL_KINDS)
        self.assertEqual(self.delay.call_count, 1)
        self.assertFalse(ScanControl.objects.exists())
        self.assertNotIn('skipped', result)

    @mock.patch.object(sentinel_dispatch, 'builtin_scanner_enrolled', return_value=False)  # nothing is reported until the built-in scanner has enrolled
    def test_before_the_builtin_scanner_enrolls_nothing_is_added(self, _enrolled):
        result = conductor.keep_work_queued()
        self.assertEqual(result['started'], 1)
        self.assertNotIn('scanner_waiting', result)

    def test_a_scanner_state_that_cannot_be_read_never_stops_it(self):
        with mock.patch.object(scanner_state, 'waiting_kinds', side_effect=RuntimeError('boom')):
            result = conductor.keep_work_queued()
        self.assertEqual(result['started'], 1)
        self.assertNotIn('scanner_waiting', result)

    def test_the_pause_still_holds_it(self):
        ScanControl.objects.create(pk=1, paused=True)
        self.assertEqual(conductor.keep_work_queued()['skipped'], 'paused')
        self.delay.assert_not_called()
