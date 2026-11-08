"""The first-run setup wizard (cveFeed.setup_flow, /cve/api/welcome/): who may use it, what each step stores, and that nothing is lost or doubled."""
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase
from django.utils import timezone

from agentapi import sentinel_settings
from agentapi.models import SentinelDefaults, SentinelEnrollment, SentinelTask
from cveFeed import discovery, setup_flow
from cveFeed.models import OpenvasOrg, OpenvasSettings
from dashboard.models import Org, Project, SetupWizard, UserProfile
from scanEngine.models import EngineType, Notification
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner
from tests.test_tenancy import client_for


def post(client, path, body=None):
    return client.post(f'/cve/api/welcome/{path}', json.dumps(body or {}), content_type='application/json')


SEED = {'org': 'Acme', 'project': 'Prod', 'domain': 'seed.test', 'authorized': True}


class WizardBase(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser('wiz', password='x')
        self.c = client_for(self.admin)
        EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        patcher = mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False)  # no real DNS in tests
        self.resolves = patcher.start()
        self.addCleanup(patcher.stop)
        self.live = True  # a scanner is live unless a test says otherwise (the first discovery is held until one is: setup_flow.start_discovery)
        live = mock.patch.object(setup_flow, 'live_sentinels', side_effect=lambda now=None: {'live': int(self.live), 'builtin': int(self.live), 'external': 0})
        live.start()
        self.live_patch = live
        self.addCleanup(live.stop)

    def seed(self, **changes):
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
            response = post(self.c, 'seed', {**SEED, **changes})
        self.queued = queued
        return response


class AccessTests(WizardBase):
    def test_a_non_admin_is_blocked_everywhere(self):
        user = User.objects.create_user('analyst', password='x')
        c = client_for(user)
        for method, path in (('get', 'state'), ('get', 'progress'), ('post', 'seed'), ('post', 'plan'), ('post', 'scanners'), ('post', 'provision'),
                             ('post', 'skip'), ('post', 'finish'), ('post', 'notify'), ('post', 'password'), ('post', 'extra')):
            response = getattr(c, method)(f'/cve/api/welcome/{path}', **({'data': '{}', 'content_type': 'application/json'} if method == 'post' else {}))
            self.assertEqual(response.status_code, 403, path)
        self.assertEqual(Org.objects.exclude(slug='default').count(), 0)
        page = c.get('/cve/welcome/')
        self.assertIn(page.status_code, (302, 403), 'the page itself is not shown to them')
        self.assertNotIn(b'setup-wizard', page.content.lower())
        self.assertNotEqual(c.get('/cve/').headers.get('Location'), '/cve/welcome/')  # and the dashboard never sends them there

    def test_signed_out_gets_nothing(self):
        response = Client().get('/cve/api/welcome/state')
        self.assertIn(response.status_code, (302, 403))  # sent to sign in (or refused): never the state
        self.assertNotIn(b'steps', response.content)
        self.assertIn(Client().post('/cve/api/welcome/seed', '{}', content_type='application/json').status_code, (302, 403))
        self.assertFalse(Domain.objects.exists())

    def test_a_post_without_the_csrf_token_is_refused(self):
        c = Client(enforce_csrf_checks=True)
        c.cookies.update(client_for(self.admin).cookies)
        response = c.post('/cve/api/welcome/seed', json.dumps(SEED), content_type='application/json')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Domain.objects.exists())

    def test_the_first_admin_is_sent_to_the_wizard_and_a_finished_one_is_not(self):
        self.assertEqual(self.c.get('/cve/')['Location'], '/cve/welcome/')
        self.assertEqual(self.c.get('/cve/?skip=1').status_code, 200)  # a person may still leave it
        self.assertEqual(post(self.c, 'finish').status_code, 200)
        self.assertEqual(self.c.get('/cve/').status_code, 200)

    def test_an_install_that_already_has_targets_is_not_redirected(self):
        org = Org.objects.get(slug='default')
        project = Project.objects.create(name='Old', slug='old', org=org, insert_date=timezone.now())
        Domain.objects.create(name='old.test', project=project, insert_date=timezone.now())
        self.assertEqual(self.c.get('/cve/').status_code, 200)

    def test_a_started_wizard_resumes_even_with_targets(self):
        self.seed()
        self.assertEqual(self.c.get('/cve/')['Location'], '/cve/welcome/')

    def test_the_requests_are_rate_limited(self):
        self.seed()
        for _ in range(setup_flow.LIMITS['write'][0]):
            post(self.c, 'plan', {'plan': 'internal'})
        self.assertEqual(post(self.c, 'plan', {'plan': 'internal'}).status_code, 429)


class SeedTests(WizardBase):
    def test_the_seed_step_creates_everything_and_queues_one_discovery(self):
        response = self.seed()
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertTrue(body['discovery_started'])
        self.assertEqual(body['seed'], {'org': 'Acme', 'project': 'Prod', 'domain': 'seed.test'})
        org = Org.objects.get(name='Acme')
        project = Project.objects.get(name='Prod')
        self.assertEqual(project.org, org)
        domain = Domain.objects.get(name='seed.test')
        self.assertEqual(domain.project, project)
        scan = ScanHistory.objects.get(domain=domain)
        self.assertEqual(scan.scan_status, discovery.QUEUED)
        self.queued.assert_called_once_with(scan.id, 'standard')
        data = SetupWizard.objects.get().data
        self.assertEqual((data['domain'], data['discovery']['scan_id'], data['steps']['seed']), ('seed.test', scan.id, 'done'))
        self.assertIsNotNone(SetupWizard.objects.get().started_at)

    def test_sending_it_again_changes_nothing_and_starts_nothing(self):
        self.seed()
        counts = (Org.objects.count(), Project.objects.count(), Domain.objects.count(), ScanHistory.objects.count())
        second = self.seed()
        self.assertEqual(second.status_code, 200)
        self.assertFalse(second.json()['discovery_started'])
        self.queued.assert_not_called()
        self.assertEqual((Org.objects.count(), Project.objects.count(), Domain.objects.count(), ScanHistory.objects.count()), counts)

    def test_a_new_name_renames_the_organization_and_project(self):
        self.seed()
        self.seed(org='Acme Security', project='Production')
        self.assertEqual(list(Org.objects.values_list('name', flat=True)), ['Acme Security'])  # the untouched Default is the one renamed
        self.assertEqual(Project.objects.filter(name='Production').count(), 1)
        self.assertEqual(ScanHistory.objects.count(), 1)

    def test_the_worker_is_asked_to_enrol_the_built_in_scanner_not_left_to_the_beat(self):
        with mock.patch('cveFeed.tasks.ensure_builtin_scanner.delay') as asked, mock.patch('agentapi.builtin_scanner.enabled', return_value=True):
            self.seed()
            self.c.get('/cve/api/welcome/progress')  # inside the throttle window: not asked twice
        asked.assert_called_once_with()
        cache.clear()
        with mock.patch('cveFeed.tasks.ensure_builtin_scanner.delay') as asked, mock.patch('agentapi.builtin_scanner.enabled', return_value=False):
            self.c.get('/cve/api/welcome/progress')
        asked.assert_not_called()  # switched off by the installer: nothing to enrol

    def test_a_bad_domain_is_rejected_and_nothing_is_created(self):
        for bad in ('', 'localhost', '10.0.0.0/24', '192.0.2.5', 'not a domain', 'a..b.test', '-x.test', 'http://'):
            response = self.seed(domain=bad)
            self.assertEqual(response.status_code, 400, bad)
        self.assertFalse(Domain.objects.exists())
        self.assertFalse(Org.objects.exclude(slug='default').exists())
        self.assertFalse(SetupWizard.objects.exists() and SetupWizard.objects.get().data.get('steps'))

    def test_a_domain_that_resolves_to_an_internal_address_is_refused(self):
        self.resolves.return_value = True
        response = self.seed()
        self.assertEqual(response.status_code, 400)
        self.assertIn('internal address', response.json()['error'])
        self.assertFalse(Domain.objects.exists())

    def test_url_and_wildcard_forms_are_cleaned_to_the_domain(self):
        self.assertEqual(setup_flow.clean_domain('https://WWW.Seed.test/path'), 'www.seed.test')
        self.assertEqual(setup_flow.clean_domain('*.seed.test'), 'seed.test')

    def test_the_authorization_checkbox_is_required(self):
        self.assertEqual(self.seed(authorized=False).status_code, 400)
        self.assertFalse(Domain.objects.exists())

    def test_names_must_be_real_and_not_the_reserved_one(self):
        self.assertEqual(self.seed(org='x').status_code, 400)
        self.assertEqual(self.seed(project='_all').status_code, 400)

    def test_the_stored_values_come_back_in_the_state(self):
        self.seed()
        state = self.c.get('/cve/api/welcome/state').json()
        self.assertEqual(state['seed'], {'org': 'Acme', 'project': 'Prod', 'domain': 'seed.test'})
        self.assertEqual(state['next'], 'plan')
        self.assertEqual(state['steps'], {'seed': 'done'})

    def test_the_bbot_discovery_runs_on_the_fake_built_in_scanner(self):
        self.seed()
        scan = ScanHistory.objects.get()
        # the fake scanner (tests.fake_scanner) does not stream bbot batches, so the run itself is not replayed here: what is proven is that the
        # discovery is queued for this scan and that a live (fake) built-in scanner is what the wizard reports as ready
        self.live_patch.stop()  # the real reading of the heartbeats from here on
        self.assertEqual(setup_flow.live_sentinels()['builtin'], 0)
        with FakeScanner(kinds=['bbot_discovery']) as fake:
            self.assertEqual(setup_flow.live_sentinels()['builtin'], 1)
            self.assertIn('bbot_discovery', fake.kinds)
        self.queued.assert_called_once_with(scan.id, 'standard')

    def test_a_discovery_the_server_refused_shows_the_reason_not_only_that_it_ended_early(self):
        self.seed()
        scan = ScanHistory.objects.get()
        reason = 'seed.test resolves to a loopback, link-local or internal address; discovery refused (CVENGINE_ALLOW_PRIVATE_TARGETS=1 allows internal ranges)'
        ScanHistory.objects.filter(pk=scan.pk).update(scan_status=discovery.FAILED, error_message=reason)
        found = self.c.get('/cve/api/welcome/progress').json()['discovery']
        self.assertEqual(found['state'], 'ended')
        self.assertIn('resolves to a loopback, link-local or internal address', found['text'])
        self.assertIn('0 hosts found:', found['text'])
        self.assertEqual(found['error'], reason)
        ScanHistory.objects.filter(pk=scan.pk).update(error_message=None)  # no reason on record: the plain sentence, as before
        plain = self.c.get('/cve/api/welcome/progress').json()['discovery']
        self.assertEqual(plain['text'], 'Discovery of seed.test ended early with 0 hosts found. You can start it again from Targets.')

    def test_sending_step_one_again_restarts_a_discovery_that_found_no_host(self):
        self.seed()
        first = ScanHistory.objects.get()
        self.assertFalse(self.seed().json()['discovery_started'])  # still queued: nothing is started a second time
        ScanHistory.objects.filter(pk=first.pk).update(scan_status=discovery.FAILED, error_message='bbot exited with status 1')
        again = self.seed().json()
        self.assertTrue(again['discovery_started'])
        self.assertEqual(ScanHistory.objects.filter(domain__name='seed.test').count(), 2)
        self.assertEqual(SetupWizard.objects.get().data['discovery']['scan_id'], ScanHistory.objects.exclude(pk=first.pk).get().pk)
        self.queued.assert_called_once()  # the second seed()'s own mock: one run queued for the new scan

    def test_sending_step_one_again_leaves_a_discovery_that_found_hosts_alone(self):
        self.seed()
        scan = ScanHistory.objects.get()
        Subdomain.objects.create(name='www.seed.test', scan_history=scan, target_domain=scan.domain)
        ScanHistory.objects.filter(pk=scan.pk).update(scan_status=discovery.FAILED, error_message='bbot reached its time limit')
        self.assertFalse(self.seed().json()['discovery_started'])
        self.assertEqual(ScanHistory.objects.filter(domain__name='seed.test').count(), 1)

    def test_with_no_sentinel_the_discovery_is_queued_then_requeued_when_one_is_live(self):
        self.seed()
        scan = ScanHistory.objects.get()
        ScanHistory.objects.filter(pk=scan.pk).update(scan_status=discovery.FAILED, error_message='waiting for a scanner: bbot_discovery')
        row = SetupWizard.objects.get()
        self.live = False
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
            self.assertFalse(setup_flow.resume_discovery(row))  # nobody is live: it stays as it is
            queued.assert_not_called()
            progress = self.c.get('/cve/api/welcome/progress').json()
            self.assertEqual(progress['discovery']['state'], 'waiting')
            self.assertIn('as soon as one is connected', progress['discovery']['text'])
            with FakeScanner(kinds=['bbot_discovery']):
                self.live = True
                SetupWizard.objects.update(data={**row.data, 'discovery': {**row.data['discovery'], 'last_try': None}})
                self.assertTrue(setup_flow.resume_discovery(SetupWizard.objects.get()))
                self.assertFalse(setup_flow.resume_discovery(SetupWizard.objects.get()))  # not again inside the window
        self.assertEqual(ScanHistory.objects.filter(domain__name='seed.test').count(), 2)
        queued.assert_called_once()

    def test_the_first_discovery_is_held_until_a_scanner_is_live_and_no_failed_scan_is_made(self):
        self.live = False
        response = self.seed()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['discovery_started'])
        self.assertFalse(ScanHistory.objects.exists())  # no scan to show as failed on a clean install
        self.queued.assert_not_called()
        progress = self.c.get('/cve/api/welcome/progress').json()
        self.assertEqual(progress['discovery']['state'], 'queued')
        self.assertIn('starts as soon as one is', progress['discovery']['text'])
        self.assertFalse(ScanHistory.objects.exists())  # polling while nothing is live starts nothing
        self.live = True  # the built-in scanner enrols
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as queued:
            progress = self.c.get('/cve/api/welcome/progress').json()
        queued.assert_called_once()
        self.assertEqual(ScanHistory.objects.filter(domain__name='seed.test').count(), 1)
        self.assertEqual(progress['discovery']['state'], 'queued')
        self.assertIsNotNone(progress['discovery']['scan_id'])
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay') as again:
            self.c.get('/cve/api/welcome/progress')
        again.assert_not_called()  # once, not on every poll
        self.assertEqual(ScanHistory.objects.filter(domain__name='seed.test').count(), 1)

    def test_the_progress_poll_carries_the_built_in_scanners_current_state_for_the_plan_step(self):
        self.seed()
        with mock.patch.object(setup_flow, 'builtin_state', return_value={'enabled': True, 'enrolled': True, 'live': True, 'text': 'The built-in scanner is ready.'}):
            out = self.c.get('/cve/api/welcome/progress').json()
        self.assertEqual(out['sentinel']['builtin_state']['text'], 'The built-in scanner is ready.')
        js = (setup_flow.__file__.rsplit('/cveFeed/', 1)[0] + '/static/cve/welcome.js')
        text = open(js, encoding='utf-8').read()
        self.assertIn('builtinNote.textContent = live.text', text)  # the plan step's line is rewritten by the poll, so "starting" never outlives the enrolment


class PlanAndKindsTests(WizardBase):
    def setUp(self):
        super().setUp()
        self.seed()
        patcher = mock.patch('agentapi.builtin_scanner.enabled', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def defaults(self):
        return sentinel_settings.get_defaults()

    def test_plan_is_validated_and_stored(self):
        self.assertEqual(post(self.c, 'plan', {'plan': 'sideways'}).status_code, 400)
        self.assertEqual(post(self.c, 'plan', {'plan': 'both'}).json()['plan'], 'both')
        self.assertEqual(SetupWizard.objects.get().data['plan'], 'both')

    def test_openvas_is_off_by_default_for_both_classes(self):
        post(self.c, 'plan', {'plan': 'both'})
        post(self.c, 'scanners', {})
        d = self.defaults()
        self.assertEqual(d['builtin_kinds']['openvas']['mode'], 'deny')
        self.assertEqual(d['external_kinds']['openvas']['mode'], 'deny')
        self.assertFalse(OpenvasSettings.current().enabled)

    def test_skipping_the_kinds_step_takes_the_suggested_ones_with_openvas_off(self):
        self.assertEqual(post(self.c, 'skip', {'step': 'scanners'}).status_code, 200)
        d = self.defaults()
        self.assertEqual(d['external_kinds']['openvas']['mode'], 'deny')
        self.assertEqual(SetupWizard.objects.get().data['steps']['scanners'], 'skipped')

    def test_per_location_openvas_internal_external_both(self):
        for plan, where, builtin_on, external_on in (('both', 'internal', True, False), ('both', 'external', False, True), ('both', 'both', True, True)):
            post(self.c, 'plan', {'plan': plan})
            response = post(self.c, 'scanners', {'openvas': {'enabled': True, 'where': where}})
            self.assertEqual(response.status_code, 200, response.content)
            d = self.defaults()
            self.assertEqual('openvas' not in d['builtin_kinds'], builtin_on, where)
            self.assertEqual('openvas' not in d['external_kinds'], external_on, where)
            self.assertTrue(OpenvasSettings.current().enabled)
            self.assertTrue(OpenvasOrg.objects.get(org__name='Acme').enabled)
        post(self.c, 'scanners', {'openvas': {'enabled': False, 'where': 'both'}})  # turned back off
        self.assertFalse(OpenvasSettings.current().enabled)
        self.assertEqual(self.defaults()['builtin_kinds']['openvas']['mode'], 'deny')

    def test_openvas_cannot_be_put_where_the_plan_has_no_scanner(self):
        post(self.c, 'plan', {'plan': 'internal'})
        self.assertEqual(post(self.c, 'scanners', {'openvas': {'enabled': True, 'where': 'external'}}).status_code, 400)
        post(self.c, 'plan', {'plan': 'external'})
        self.assertEqual(post(self.c, 'scanners', {'openvas': {'enabled': True, 'where': 'internal'}}).status_code, 400)

    def test_a_switch_an_administrator_set_is_never_turned_off_by_the_wizard(self):
        row = OpenvasSettings.current()
        row.enabled = True
        row.save()
        post(self.c, 'scanners', {})
        self.assertTrue(OpenvasSettings.current().enabled)

    def test_switched_off_kinds_are_denied_for_both_classes_and_the_locked_ones_cannot_be(self):
        post(self.c, 'plan', {'plan': 'both'})
        response = post(self.c, 'scanners', {'kinds': {'web_screenshot': False, 'nuclei_deep': False, 'bbot_discovery': False, 'testssl': True}})
        self.assertEqual(response.status_code, 200)
        d = self.defaults()
        for cls in ('builtin_kinds', 'external_kinds'):
            self.assertEqual(d[cls]['web_screenshot']['mode'], 'deny')
            self.assertEqual(d[cls]['nuclei_deep']['mode'], 'deny')
            self.assertNotIn('bbot_discovery', d[cls])
            self.assertNotIn('testssl', d[cls])

    def test_the_ssh_family_is_offered_on_by_default_and_can_be_switched_off(self):
        state = self.c.get('/cve/api/welcome/state').json()
        self.assertIn('ssh', [f['id'] for f in state['families']])
        post(self.c, 'plan', {'plan': 'both'})
        self.assertEqual(post(self.c, 'scanners', {}).status_code, 200)
        for cls in ('builtin_kinds', 'external_kinds'):
            self.assertNotIn('ssh_probe', self.defaults()[cls])  # on by default, also on a small machine
        post(self.c, 'scanners', {'kinds': {'ssh_probe': False}})
        for cls in ('builtin_kinds', 'external_kinds'):
            self.assertEqual(self.defaults()[cls]['ssh_probe']['mode'], 'deny')

    def test_unknown_kinds_and_bad_values_are_refused(self):
        self.assertEqual(post(self.c, 'scanners', {'kinds': {'rm_rf': False}}).status_code, 400)
        self.assertEqual(post(self.c, 'scanners', {'kinds': {'nmap': 'yes'}}).status_code, 400)
        self.assertEqual(post(self.c, 'scanners', {'openvas': {'enabled': True, 'where': 'moon'}}).status_code, 400)

    def test_external_only_turns_the_built_in_off_but_keeps_the_first_discovery_until_finish(self):
        post(self.c, 'plan', {'plan': 'external'})
        builtin = self.defaults()['builtin_kinds']
        self.assertEqual(builtin['nmap']['mode'], 'deny')
        self.assertNotIn('bbot_discovery', builtin)  # the seed discovery is not stranded
        post(self.c, 'finish')
        self.assertEqual(self.defaults()['builtin_kinds']['bbot_discovery']['mode'], 'deny')
        self.assertEqual({k for k, e in self.defaults()['builtin_kinds'].items() if e['mode'] == 'deny'}, set(SentinelTask.KINDS))

    def test_both_keeps_the_built_in_as_a_scanner(self):
        post(self.c, 'plan', {'plan': 'both'})
        post(self.c, 'finish')
        self.assertNotIn('nmap', self.defaults()['builtin_kinds'])

    def test_when_the_installer_switched_the_built_in_off_internal_is_not_offered(self):
        with mock.patch('agentapi.builtin_scanner.enabled', return_value=False):
            self.assertEqual(post(self.c, 'plan', {'plan': 'internal'}).status_code, 409)
            self.assertEqual(post(self.c, 'plan', {'plan': 'external'}).status_code, 200)
            state = self.c.get('/cve/api/welcome/state').json()
        self.assertFalse(state['builtin']['enabled'])

    def test_small_machines_start_with_the_heavy_checks_off(self):
        self.assertEqual(setup_flow.suggested_off(2.0), sorted(setup_flow.HEAVY))
        self.assertEqual(setup_flow.suggested_off(16.0), [])
        state = self.c.get('/cve/api/welcome/state').json()
        names = {f['id'] for f in state['families']}
        self.assertEqual(names, {'discovery', 'web', 'network', 'tls_mail', 'ssh', 'secrets', 'screenshots', 'wordpress', 'nuclei'})

    def test_every_family_kind_is_a_real_kind_and_none_is_listed_twice(self):
        kinds = setup_flow.family_kinds()
        self.assertEqual(len(kinds), len(set(kinds)))
        self.assertFalse(set(kinds) - set(SentinelTask.KINDS))
        self.assertNotIn('openvas', kinds)  # it has its own group

    def test_running_the_steps_again_writes_the_same_defaults(self):
        post(self.c, 'plan', {'plan': 'both'})
        post(self.c, 'scanners', {'kinds': {'wpscan': False}})
        first = SentinelDefaults.current()
        a = (first.builtin_kinds, first.external_kinds)
        post(self.c, 'scanners', {'kinds': {'wpscan': False}})
        second = SentinelDefaults.current()
        self.assertEqual(a, (second.builtin_kinds, second.external_kinds))

    def test_the_policy_is_audited(self):
        from dashboard.models import AuditLog
        post(self.c, 'plan', {'plan': 'both'})
        self.assertTrue(AuditLog.objects.filter(action='sentinel.defaults').exists())


class EnrollmentTests(WizardBase):
    def test_provision_needs_the_organization_first(self):
        self.assertEqual(post(self.c, 'provision', {}).status_code, 409)

    def test_provision_returns_the_command_once_and_the_status_follows_the_sentinel(self):
        self.seed()
        response = post(self.c, 'provision', {'profile': 'light'})
        self.assertEqual(response.status_code, 200, response.content)
        out = response.json()
        self.assertIn('setup.sh', out['command'])
        self.assertIn('--blob', out['command'])
        state = self.c.get('/cve/api/welcome/state').json()
        self.assertEqual(len(state['enrollments']), 1)
        self.assertFalse(state['enrollments'][0]['used'])
        self.assertNotIn('command', json.dumps(state))  # the secret is never part of the state
        self.assertNotIn(out['command'][-40:], json.dumps(state))
        enrollment = SentinelEnrollment.objects.get(pk=out['enrollment_id'])
        self.assertEqual(enrollment.org.name, 'Acme')
        enrollment.expires_at = timezone.now() - timedelta(minutes=1)
        enrollment.save()
        self.assertTrue(self.c.get('/cve/api/welcome/state').json()['enrollments'][0]['expired'])

    def test_provision_is_rate_limited(self):
        self.seed()
        for _ in range(setup_flow.LIMITS['provision'][0]):
            post(self.c, 'provision', {})
        self.assertEqual(post(self.c, 'provision', {}).status_code, 429)

    def test_a_redeemed_enrollment_shows_the_connected_sentinel(self):
        self.seed()
        with FakeScanner(kinds=['bbot_discovery']) as fake:
            enrollment = SentinelEnrollment.objects.filter(used_by_agent=fake.agent).first()
            self.assertIsNotNone(enrollment)
            row = SetupWizard.objects.get()
            row.data = {**row.data, 'enrollments': [enrollment.pk]}
            row.save()
            item = self.c.get('/cve/api/welcome/state').json()['enrollments'][0]
        self.assertTrue(item['used'])
        self.assertEqual(item['agent']['name'], fake.agent.name)
        self.assertTrue(item['agent']['live'])


class ExtrasTests(WizardBase):
    def test_a_slack_webhook_is_stored_and_never_returned(self):
        url = 'https://hooks.slack.com/services/T000/B000/XXXXXXXX'
        response = post(self.c, 'notify', {'service': 'slack', 'url': url})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Notification.objects.get().send_to_slack)
        self.assertEqual(Notification.objects.get().slack_hook_url, url)
        self.assertNotIn('XXXXXXXX', response.content.decode())
        self.assertTrue(response.json()['notify']['slack'])

    def test_other_webhook_addresses_are_refused(self):
        for bad in ('http://hooks.slack.com/x/y', 'https://evil.test/hooks/x', 'https://hooks.slack.com/', 'javascript:alert(1)'):
            self.assertEqual(post(self.c, 'notify', {'service': 'slack', 'url': bad}).status_code, 400, bad)
        self.assertFalse(Notification.objects.exists())

    def test_the_password_changes_with_the_current_one_and_keeps_the_scanner_token_alive(self):
        from dashboard.models import ApiToken
        sentinel = ApiToken.objects.create(user=self.admin, name='sentinel', key_hash='a' * 64, prefix='cvs_abc', scope='sentinel')
        person = ApiToken.objects.create(user=self.admin, name='mine', key_hash='b' * 64, prefix='cvp_abc', scope='full')
        self.assertEqual(post(self.c, 'password', {'current': 'wrong', 'new': 'Correct-Horse-Battery-9'}).status_code, 400)
        response = post(self.c, 'password', {'current': 'x', 'new': 'Correct-Horse-Battery-9'})
        self.assertEqual(response.status_code, 200, response.content)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password('Correct-Horse-Battery-9'))
        sentinel.refresh_from_db(); person.refresh_from_db()
        self.assertFalse(sentinel.revoked)
        self.assertTrue(person.revoked)
        self.assertEqual(SetupWizard.objects.get().data['extras']['password'], 'done')

    def test_every_extra_can_be_skipped_and_the_step_completes(self):
        for name in setup_flow.EXTRAS:
            self.assertEqual(post(self.c, 'extra', {'name': name, 'how': 'skipped'}).status_code, 200)
        self.assertEqual(SetupWizard.objects.get().data['steps']['extras'], 'done')
        self.assertEqual(post(self.c, 'extra', {'name': 'bogus', 'how': 'done'}).status_code, 400)

    def test_only_the_middle_steps_can_be_skipped(self):
        self.assertEqual(post(self.c, 'skip', {'step': 'seed'}).status_code, 400)
        self.assertEqual(post(self.c, 'skip', {'step': 'build'}).status_code, 400)
        self.assertEqual(post(self.c, 'skip', {'step': 'extras'}).status_code, 200)


class ProgressTests(WizardBase):
    def test_the_counts_come_from_the_discovery_and_cost_a_bounded_number_of_queries(self):
        self.seed()
        scan = ScanHistory.objects.get()
        for i in range(30):
            Subdomain.objects.create(name=f'h{i}.seed.test', scan_history=scan, target_domain=Domain.objects.get(), discovered_date=timezone.now())
        ScanHistory.objects.filter(pk=scan.pk).update(scan_status=discovery.RUNNING)
        self.c.get('/cve/api/welcome/progress')  # warm caches
        with self.assertNumQueries(self.queries_of_progress()):
            out = self.c.get('/cve/api/welcome/progress').json()
        self.assertEqual(out['discovery']['hosts'], 30)
        self.assertEqual(out['discovery']['state'], 'running')
        self.assertIn('30 hosts found so far', out['discovery']['text'])
        self.assertTrue(out['dwell']['ready'])  # plenty found: no reason to wait

    def queries_of_progress(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as ctx:
            self.c.get('/cve/api/welcome/progress')
        self.assertLessEqual(len(ctx), 14)  # a constant, however many hosts were found
        return len(ctx)

    def test_nothing_found_yet_holds_the_wait_until_the_dwell_is_over(self):
        self.live = False
        self.seed()
        out = self.c.get('/cve/api/welcome/progress').json()
        self.assertFalse(out['dwell']['ready'])
        self.assertTrue(out['dwell']['hold'])
        self.assertEqual(out['dwell']['min_seconds'], 90)
        self.assertEqual(out['discovery']['state'], 'queued')
        self.assertIn('No Sentinel is connected yet', out['discovery']['text'])
        row = SetupWizard.objects.get()
        row.data = {**row.data, 'discovery': {**row.data['discovery'], 'started_at': (timezone.now() - timedelta(seconds=100)).isoformat()}}
        row.save()
        self.assertTrue(self.c.get('/cve/api/welcome/progress').json()['dwell']['ready'])  # a person who took their time is never made to wait

    def test_the_dwell_is_configurable(self):
        self.seed()
        with mock.patch.dict('os.environ', {'CVENGINE_SETUP_DWELL_SECONDS': '0'}):
            self.assertTrue(self.c.get('/cve/api/welcome/progress').json()['dwell']['ready'])
        with mock.patch.dict('os.environ', {'CVENGINE_SETUP_DWELL_SECONDS': '300'}):
            self.assertEqual(self.c.get('/cve/api/welcome/progress').json()['dwell']['min_seconds'], 300)

    def test_a_finished_discovery_ends_the_wait(self):
        self.seed()
        ScanHistory.objects.update(scan_status=discovery.SUCCESS)
        out = self.c.get('/cve/api/welcome/progress').json()
        self.assertTrue(out['dwell']['ready'])
        self.assertEqual(out['discovery']['state'], 'done')

    def test_a_live_sentinel_is_reported(self):
        self.seed()
        with FakeScanner(kinds=['bbot_discovery']):
            out = self.c.get('/cve/api/welcome/progress').json()
        self.assertEqual((out['sentinel']['live'], out['sentinel']['builtin'], out['sentinel']['external']), (1, 1, 0))

    def test_no_seed_means_no_discovery_and_nothing_to_wait_for(self):
        out = self.c.get('/cve/api/welcome/progress').json()
        self.assertIsNone(out['discovery'])
        self.assertTrue(out['dwell']['ready'])


class FinishTests(WizardBase):
    def test_finish_completes_marks_the_admin_onboarded_and_is_repeatable(self):
        self.seed()
        out = post(self.c, 'finish').json()
        self.assertEqual(out['follow'], ScanHistory.objects.get().id)
        self.assertEqual(out['project'], 'prod')
        row = SetupWizard.objects.get()
        self.assertIsNotNone(row.completed_at)
        self.assertEqual(row.completed_by, 'wiz')
        self.assertTrue(UserProfile.objects.get(user=self.admin).onboarded)
        first = row.completed_at
        post(self.c, 'finish')
        self.assertEqual(SetupWizard.objects.get().completed_at, first)
        self.assertEqual(self.c.get('/cve/api/welcome/state').json()['completed'], True)

    def test_a_finished_wizard_can_be_opened_again_without_losing_values(self):
        self.seed()
        post(self.c, 'finish')
        self.assertEqual(self.c.get('/cve/welcome/').status_code, 200)
        self.assertEqual(self.c.get('/cve/api/welcome/state').json()['seed']['domain'], 'seed.test')

    def test_no_secret_is_ever_in_the_stored_state(self):
        self.seed()
        post(self.c, 'notify', {'service': 'discord', 'url': 'https://discord.com/api/webhooks/1/SECRETTOKEN'})
        post(self.c, 'provision', {})
        self.assertNotIn('SECRETTOKEN', json.dumps(SetupWizard.objects.get().data))
        self.assertNotIn('cvenroll', json.dumps(SetupWizard.objects.get().data).lower())
