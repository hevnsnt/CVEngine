"""The AI host review's fixed list of next steps (cveFeed.host_actions): what is offered, what runs, what is refused, and the gates each action
passes on its own (scope, exclusions, the pause, the project's caps). The model only ever names an action and a ref; nothing else reaches a function."""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import host_actions, host_review, hot_validation, notify, reviewer, triage
from cveFeed.models import (AIJob, AutomaticValidation, CVEEntry, CVEMatch, HostAssessment, HostExclusion, HostState, HygieneFinding,
                            OnDemandValidation, Triage)
from cveFeed.validation_authority import require_authority
from dashboard.models import AIProviderSettings, Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class Fixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='HA', slug='ha-org')
        cls.proj = Project.objects.create(name='HA', slug='ha-proj', insert_date=now, org=cls.org)
        cls.other = Project.objects.create(name='HA2', slug='ha-proj2', insert_date=now, org=cls.org)
        cls.domain = Domain.objects.create(name='example.com', project=cls.proj, insert_date=now)
        cls.other_domain = Domain.objects.create(name='example.org', project=cls.other, insert_date=now)
        engine = EngineType.objects.create(engine_name='ha-e', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=engine, scan_status=2, start_scan_date=now)
        cls.other_scan = ScanHistory.objects.create(domain=cls.other_domain, scan_type=engine, scan_status=2, start_scan_date=now)
        cls.sub = Subdomain.objects.create(name='www.example.com', target_domain=cls.domain, scan_history=cls.scan, http_url='https://www.example.com/')
        cls.other_sub = Subdomain.objects.create(name='www.example.org', target_domain=cls.other_domain, scan_history=cls.other_scan)
        ip = IpAddress.objects.create(address='192.0.2.10')
        port = Port.objects.create(number=443, service_name='https', product='nginx', version='1.18')
        ip.ports.add(port)
        cls.sub.ip_addresses.add(ip)
        cls.state = HostState.objects.create(project=cls.proj, domain=cls.domain, host='www.example.com', fingerprint='f' * 40)
        cls.user = User.objects.create_user('ha-user', password='x')
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-9101', cvss=9.8, published_at=now, affected=[])

    def setUp(self):
        self.match = self.make_match(self.cve, self.sub, self.scan)
        self.vuln = Vulnerability.objects.create(name='Debug page', severity=3, subdomain=self.sub, target_domain=self.domain, open_status=True,
                                                 http_url='https://www.example.com/debug', source='nuclei')
        self.hyg = HygieneFinding.objects.create(domain=self.domain, host='www.example.com', check_name='spf_missing', severity=2, title='No SPF')
        triage.track([self.vuln, self.hyg])
        self.pairs = host_review.pairs(self.proj, 'www.example.com')
        self.refs = {t.kind: ref for ref, t in self.pairs}

    def make_match(self, cve, sub, scan):
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech', matched_product='lib-a', matched_version='1.2',
                                        version_in_range=False, confidence=0.8, ai_verdict='uncertain', scan_history=scan, evidence={'source': 'tech'})
        triage.track([match])
        return match

    def offered(self, **kw):
        return host_actions.offered(self.proj, self.sub, self.pairs, **kw)

    def act(self, action, target='', by=None, **kw):
        return host_actions.run(action, target, self.proj, self.sub, by=by, rows=self.pairs, **kw)


class RegistryTests(Fixture):
    def test_the_registry_is_the_design_list_with_its_classes(self):
        self.assertEqual(set(host_actions.ACTIONS), {'none', 'validate_match', 'revalidate_finding', 'screenshot', 'draft_check', 'ask_person',
                                                      'rescan_host', 'assess_host', 'run_hygiene'})
        self.assertEqual(set(host_actions.AUTO_ACTIONS), {'none', 'validate_match', 'revalidate_finding', 'screenshot', 'draft_check', 'ask_person'})
        self.assertEqual(set(host_actions.RECOMMEND_ACTIONS), {'rescan_host', 'assess_host', 'run_hygiene'})
        self.assertEqual(set(host_actions.TARGETED), {'validate_match', 'revalidate_finding', 'draft_check'})
        for forbidden in ('validate_secret', 'mark_fixed', 'accept_risk', 'set_heat', 'retest', 'close_false_positive', 'delete_host', 'exclude_host'):
            self.assertNotIn(forbidden, host_actions.ACTIONS)

    def test_a_name_that_is_not_in_the_registry_is_refused_and_starts_nothing(self):
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline, mock.patch('cveFeed.tasks.run_hygiene_task.delay') as hygiene:
            for name in ('delete_host', 'exclude_host', 'validate_secret', '', None, 'rescan_host; rm -rf /', 'RESCAN_HOST', '__import__', 'run'):
                with self.subTest(name=name):
                    result = self.act(name)
                    self.assertEqual(result['state'], 'refused')
                    self.assertEqual(result['detail'], 'not an action the review may take')
            pipeline.assert_not_called()
            hygiene.assert_not_called()
        self.assertFalse(HostAssessment.objects.exists())

    def test_none_and_ask_person_are_always_offered_and_the_rest_follow_the_host(self):
        offered = self.offered()
        self.assertEqual({a for a, o in offered.items() if o['class'] == 'auto'},
                         {'none', 'ask_person', 'validate_match', 'revalidate_finding', 'screenshot'})
        self.assertEqual({a for a, o in offered.items() if o['class'] == 'recommend'}, {'rescan_host', 'assess_host', 'run_hygiene'})
        self.assertEqual(offered['validate_match']['targets'], [self.refs['cve_match']])
        self.assertEqual(sorted(offered['revalidate_finding']['targets']), sorted([self.refs['nuclei'], self.refs['hygiene']]))
        self.assertEqual(offered['none'], {'class': 'auto', 'targets': [], 'touches_host': False, 'summary': mock.ANY})
        self.assertFalse(offered['ask_person']['touches_host'])
        self.assertTrue(offered['rescan_host']['touches_host'])

    def test_nothing_that_touches_the_host_is_offered_while_scanning_is_paused_or_the_host_is_unknown(self):
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            self.assertEqual(set(self.offered()), {'none', 'ask_person'})
            for action in ('validate_match', 'rescan_host', 'screenshot', 'assess_host', 'run_hygiene', 'revalidate_finding'):
                with self.subTest(action=action), mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline:
                    result = self.act(action, self.refs.get('cve_match', '') if action == 'validate_match' else '')
                    self.assertEqual((result['state'], result['detail']), ('refused', 'not offered for this host now'))
                    pipeline.assert_not_called()
        self.assertEqual(set(host_actions.offered(self.proj, None, self.pairs)), {'none', 'ask_person'})

    def test_only_this_projects_findings_on_this_host_can_be_named(self):
        foreign = self.make_match(CVEEntry.objects.create(cve_id='CVE-2099-9102', cvss=9.8, published_at=timezone.now(), affected=[]),
                                  self.other_sub, self.other_scan)
        row = Triage.objects.get(match=foreign)
        pairs = self.pairs + [('f9', row)]
        offered = host_actions.offered(self.proj, self.sub, pairs)
        self.assertNotIn('f9', offered['validate_match']['targets'])
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as task:
            result = host_actions.run('validate_match', 'f9', self.proj, self.sub, rows=pairs)
        self.assertEqual(result['state'], 'refused')
        task.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match=foreign).exists())


class ValidationTests(Fixture):
    def test_a_validation_is_queued_with_source_host_review_and_is_never_a_persons_work(self):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as task:
            result = self.act('validate_match', self.refs['cve_match'])
        self.assertEqual(result['state'], 'started', result)
        job = OnDemandValidation.objects.get(match=self.match)
        self.assertEqual((job.source, job.status, job.requested_by_id, job.project_id), ('host_review', 'queued', None, self.proj.pk))
        task.assert_called_once()
        self.assertFalse(reviewer.worked_by_person('cve_match', CVEMatch.objects.get(pk=self.match.pk)))  # an automatic step never blocks a closure
        # a second ask while it is queued is not offered
        self.assertNotIn('validate_match', {a for a, o in self.offered().items() if o['targets']})

    def test_a_person_pressing_start_still_makes_a_host_review_row_not_a_manual_one(self):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            result = self.act('validate_match', self.refs['cve_match'], by=self.user)
        self.assertEqual(result['state'], 'started', result)
        self.assertEqual(OnDemandValidation.objects.get(match=self.match).source, 'host_review')
        self.assertFalse(reviewer.worked_by_person('cve_match', CVEMatch.objects.get(pk=self.match.pk)))

    def test_the_workers_accept_the_source_and_refuse_an_unknown_one(self):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            self.act('validate_match', self.refs['cve_match'])
        job = OnDemandValidation.objects.get(match=self.match)
        require_authority(job)  # no person to check, like an automatic request
        job.source = 'legacy'
        with self.assertRaises(Exception):
            require_authority(job)

    def test_a_target_that_is_not_a_cve_match_or_not_offered_for_the_action_is_refused(self):
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as task:
            for target in (self.refs['hygiene'], self.refs['nuclei'], 'f99', '', 'f1; drop table'):
                with self.subTest(target=target):
                    self.assertEqual(self.act('validate_match', target)['state'], 'refused')
            self.assertEqual(self.act('ask_person', 'f1')['detail'], 'this action takes no target')
        task.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.exists())

    def test_the_projects_cap_on_validations_in_progress_holds(self):
        for n in range(hot_validation.PROJECT_ACTIVE_CAP):
            m = self.make_match(CVEEntry.objects.create(cve_id=f'CVE-2099-92{n:02d}', cvss=5, published_at=timezone.now(), affected=[]), self.sub, self.scan)
            OnDemandValidation.objects.create(match=m, project=self.proj, source='automatic', status='running')
        self.assertNotIn(self.refs['cve_match'], self.offered().get('validate_match', {}).get('targets', []))
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as task:
            result = self.act('validate_match', self.refs['cve_match'])
        self.assertEqual(result['state'], 'refused')
        task.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.filter(match=self.match).exists())

    def test_an_excluded_host_is_not_validated(self):
        HostExclusion.objects.create(org=self.org, host='www.example.com')
        self.assertEqual(set(self.offered()) - {'none', 'ask_person'}, set())
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async') as task:
            self.assertEqual(self.act('validate_match', self.refs['cve_match'])['state'], 'refused')
        task.assert_not_called()

    def test_a_scanner_finding_is_revalidated_with_a_host_review_row_the_worker_accepts(self):
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async') as task:
            result = self.act('revalidate_finding', self.refs['nuclei'])
        self.assertEqual(result['state'], 'started', result)
        job = AutomaticValidation.objects.get(triage__vulnerability=self.vuln)
        self.assertEqual((job.source, job.status, job.requested_by_id), ('host_review', 'queued', None))
        task.assert_called_once()
        require_authority(job)
        # while it is queued it is not offered again, and a second try is refused
        self.assertNotIn(self.refs['nuclei'], self.offered().get('revalidate_finding', {}).get('targets', []))
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async') as again:
            self.assertEqual(self.act('revalidate_finding', self.refs['nuclei'])['state'], 'refused')
        again.assert_not_called()

    def test_the_worker_takes_a_host_review_row_for_a_finding_the_sweep_would_not_validate(self):
        from cveFeed import tasks
        low = Vulnerability.objects.create(name='Banner', severity=1, subdomain=self.sub, target_domain=self.domain, open_status=True,
                                           http_url='https://www.example.com/banner', source='nuclei')
        triage.track([low])
        self.assertIsNone(hot_validation.tier_for(Triage.objects.get(vulnerability=low)))  # not a Fire or Smoke finding: the sweep leaves it
        self.pairs = host_review.pairs(self.proj, 'www.example.com')
        ref = next(r for r, t in self.pairs if t.vulnerability_id == low.pk)
        with mock.patch('cveFeed.tasks.automatic_validate_finding.apply_async'):
            self.assertEqual(self.act('revalidate_finding', ref)['state'], 'started')
        job = AutomaticValidation.objects.get(triage__vulnerability=low)
        with mock.patch('cveFeed.triage.run_triage', return_value={'asked': 0}), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)):
            outcome = tasks.automatic_validate_finding(job.pk)
        job.refresh_from_db()
        self.assertNotEqual(job.status, 'skipped', outcome)
        self.assertNotIn('diagnostic', outcome)


class HostActionTests(Fixture):
    def test_a_rescan_is_queued_for_the_host_with_no_person_behind_it_unless_one_started_it(self):
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline:
            self.assertEqual(self.act('rescan_host')['state'], 'started')
            pipeline.assert_called_once_with(self.domain.id, ['www.example.com'], by_person=False)
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline:
            self.assertEqual(self.act('rescan_host', by=self.user)['state'], 'started')
            pipeline.assert_called_once_with(self.domain.id, ['www.example.com'], by_person=True)

    def test_a_target_set_to_manual_only_is_not_rescanned_unless_a_person_asks(self):
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=Domain.DISCOVERY_MANUAL)
        self.sub = Subdomain.objects.select_related('target_domain').get(pk=self.sub.pk)  # the target is read from the database, as a worker does
        self.assertNotIn('rescan_host', self.offered())
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline:
            self.assertEqual(self.act('rescan_host')['state'], 'refused')
            pipeline.assert_not_called()
            self.assertEqual(self.act('rescan_host', by=self.user)['state'], 'started')

    def test_an_excluded_or_archived_host_is_refused_by_every_action_that_touches_it(self):
        HostExclusion.objects.create(org=self.org, host='www.example.com')
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline, mock.patch('cveFeed.tasks.run_hygiene_task.delay') as hygiene, \
                mock.patch('cveFeed.tasks.assess_host.apply_async') as assess, mock.patch('cveFeed.web_shot.kick') as kick:
            for action in ('rescan_host', 'assess_host', 'run_hygiene', 'screenshot'):
                with self.subTest(action=action):
                    self.assertEqual(self.act(action, by=self.user)['state'], 'refused')
            pipeline.assert_not_called()
            hygiene.assert_not_called()
            assess.assert_not_called()
            kick.assert_not_called()
        self.assertFalse(HostAssessment.objects.exists())

    def test_an_archived_host_is_not_assessed(self):
        HostState.objects.filter(pk=self.state.pk).update(archived_at=timezone.now())
        with mock.patch('cveFeed.tasks.assess_host.apply_async') as assess:
            self.assertEqual(self.act('assess_host', by=self.user)['state'], 'refused')
            assess.assert_not_called()

    def test_an_assessment_is_queued_with_source_host_review_and_only_one_at_a_time(self):
        with mock.patch('cveFeed.tasks.assess_host.apply_async', return_value=mock.Mock(id='celery-1')) as assess:
            result = self.act('assess_host', by=self.user)
            self.assertEqual(result['state'], 'started', result)
            assess.assert_called_once()
            job = HostAssessment.objects.get()
            self.assertEqual((job.source, job.requested_by_id, job.host), ('host_review', self.user.pk, 'www.example.com'))
            self.assertNotIn('assess_host', self.offered())
            self.assertEqual(self.act('assess_host', by=self.user)['state'], 'refused')
        self.assertEqual(HostAssessment.objects.count(), 1)

    def test_the_assessment_queues_own_capacity_limit_holds(self):
        with mock.patch('cveFeed.host_assessment._require_capacity', side_effect=RuntimeError('host assessment queue is at capacity')), \
                mock.patch('cveFeed.tasks.assess_host.apply_async') as assess:
            self.assertNotIn('assess_host', self.offered())
            result = self.act('assess_host', by=self.user)
            self.assertEqual(result['state'], 'refused')
            assess.assert_not_called()

    def test_hygiene_runs_for_the_hosts_target(self):
        with mock.patch('cveFeed.tasks.run_hygiene_task.delay') as hygiene:
            self.assertEqual(self.act('run_hygiene', by=self.user)['state'], 'started')
            hygiene.assert_called_once_with(self.domain.id)

    def test_a_screenshot_is_queued_for_a_host_with_a_web_page_and_refused_when_the_switch_is_off(self):
        with mock.patch('cveFeed.web_shot.kick') as kick:
            result = self.act('screenshot')
            self.assertEqual(result['state'], 'started', result)
            kick.assert_called()
        with mock.patch.dict('os.environ', {'CVENGINE_SCREENSHOTS': '0'}):
            self.assertNotIn('screenshot', self.offered())

    def test_ask_person_only_sends_a_line_that_names_the_host_and_nothing_the_model_wrote(self):
        with mock.patch('cveFeed.notify._send') as send:
            result = self.act('ask_person')
        self.assertEqual(result['state'], 'done')
        text = send.call_args[0][0]
        self.assertIn('`www.example.com`', text)
        self.assertEqual(send.call_args[0][1], 'send_vuln_notif')
        self.assertTrue(notify.host_needs_person)

    def test_none_does_nothing(self):
        with mock.patch('cveFeed.tasks.host_pipeline.delay') as pipeline:
            self.assertEqual(self.act('none')['state'], 'done')
            pipeline.assert_not_called()
        self.assertFalse(OnDemandValidation.objects.exists() or AutomaticValidation.objects.exists() or HostAssessment.objects.exists())

    def test_an_action_that_breaks_is_refused_not_raised(self):
        with mock.patch('cveFeed.tasks.host_pipeline.delay', side_effect=RuntimeError('broker down')):
            result = self.act('rescan_host')
        self.assertEqual(result['state'], 'refused')
        self.assertIn('RuntimeError', result['detail'])


class DraftTests(Fixture):
    def offer_ready(self):
        AIProviderSettings.objects.create(provider='anthropic', api_key='sk-test-key', enabled=True)
        return mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', return_value=None)

    def test_a_draft_check_is_offered_for_a_cve_with_no_template_and_asks_the_gated_generator(self):
        with self.offer_ready(), mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')):
            self.assertEqual(self.offered()['draft_check']['targets'], [self.refs['cve_match']])
            job = mock.Mock(pk=77)
            with mock.patch('cveFeed.templategen.generate_template', return_value=job) as generate:
                result = self.act('draft_check', self.refs['cve_match'])
        self.assertEqual(result['state'], 'started', result)
        generate.assert_called_once_with(self.cve, project=self.proj.pk, candidate_only=True)

    def test_a_cve_that_a_template_covers_or_with_no_provider_or_no_scanner_is_not_offered(self):
        with self.offer_ready(), mock.patch('cveFeed.validation.resolve_template', return_value=('/x.yaml', '')):
            self.assertNotIn('draft_check', self.offered())
        AIProviderSettings.objects.all().delete()
        with mock.patch('cveFeed.validation.resolve_template', return_value=('', '')):
            self.assertNotIn('draft_check', self.offered())

    def test_the_generators_own_budget_refuses_and_nothing_is_queued(self):
        from cveFeed import templategen
        with self.offer_ready(), mock.patch('cveFeed.validation.resolve_template', return_value=('', 'none')), \
                mock.patch('cveFeed.templategen.generate_template', side_effect=templategen.TemplateBudgetExceeded('the daily AI template budget is spent')):
            result = self.act('draft_check', self.refs['cve_match'])
        self.assertEqual((result['state'], result['detail']), ('refused', 'the daily AI template budget is spent'))
        self.assertFalse(AIJob.objects.exists())
