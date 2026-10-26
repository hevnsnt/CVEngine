"""AI may select only checks already admitted by the deterministic planner."""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed.validation_plan import parse_plan, plan
from cveFeed.validation import local_component_only, plan_checks


class PlanParsingTests(SimpleTestCase):
    def test_unknown_check_and_generation_without_a_gap_are_rejected(self):
        checks = [{'kind': 'nmap_sv'}]
        self.assertIsNone(parse_plan('{"check_kinds":["shell"],"generate_template":false,"reason":"run it"}', checks, True))
        self.assertIsNone(parse_plan('{"check_kinds":[],"generate_template":true,"reason":"write it"}', checks, False))
        self.assertIsNone(parse_plan('{"check_kinds":["nmap_sv"],"generate_template":false,"reason":"ok","host":"elsewhere"}', checks, True))

    def test_valid_choice_cannot_invent_a_target(self):
        selected = parse_plan('{"check_kinds":["nmap_sv"],"generate_template":false,"reason":"Check observed service"}',
                              [{'kind': 'nmap_sv'}], True)
        self.assertEqual(selected['check_kinds'], ['nmap_sv'])
        self.assertEqual(set(selected), {'check_kinds', 'generate_template', 'reason', 'source'})

    def test_empty_ai_plan_is_valid_and_does_not_authorize_generic_checks(self):
        checks = [{'kind': 'nmap_sv'}, {'kind': 'http_head'}]
        selected = parse_plan('{"check_kinds":[],"generate_template":false,"reason":"Local driver evidence is required; external banners cannot establish it."}', checks, True)
        self.assertEqual(selected['check_kinds'], [])
        self.assertIn('Local driver', selected['reason'])

    def test_provider_unavailable_only_allows_a_specific_vetted_template(self):
        row = mock.Mock(signature='sig')
        cve = mock.Mock()
        with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
            generic, _ = plan(1, row, cve, {}, [{'kind': 'nmap_sv'}, {'kind': 'http_head'}], ('', 'no template'))
            specific, _ = plan(1, row, cve, {}, [{'kind': 'nuclei_template'}, {'kind': 'http_head'}], ('/approved/cve.yaml', ''))
        self.assertEqual(generic['check_kinds'], [])
        self.assertEqual(specific['check_kinds'], ['nuclei_template'])

    def test_explicit_local_driver_advisory_does_not_plan_external_banners(self):
        cve = mock.Mock(title='Local mlx5e driver flaw', original_description='A local kernel driver issue requires a specific NIC.')
        self.assertTrue(local_component_only(cve))
        subject = {'kind': 'cve_match', 'host': 'vpn.example.test', 'cve_id': 'CVE-2099-1',
                   'source': 'tech', 'url': 'https://vpn.example.test/', 'local_component_only': True,
                   'candidate_services': [{'ip': '203.0.113.5', 'port': 443}]}
        checks, notes = plan_checks(subject, 'signature', ('', 'no template covers this CVE'))
        self.assertEqual(checks, [])
        self.assertIn('local kernel', notes[0])


class PlanBudgetTests(TestCase):
    def setUp(self):
        from dashboard.models import Project
        from django.utils import timezone
        self.project = Project.objects.create(name='B', slug='budget', insert_date=timezone.now())

    def reserve(self, signature):
        from cveFeed.validation_plan import _reserve
        claim, why = _reserve(self.project.id, signature)
        if claim:
            claim.status = 'succeeded'
            claim.save(update_fields=['status'])
        return why

    def test_the_budget_comes_from_the_ai_settings(self):
        from dashboard.models import AIProviderSettings
        from cveFeed.validation_plan import daily_limits
        self.assertEqual(daily_limits(), (200, 20))  # nothing configured yet: the defaults
        AIProviderSettings.objects.create(plan_daily_total=3, plan_daily_per_project=2)
        self.assertEqual(daily_limits(), (3, 2))

    def test_the_project_limit_stops_planning_and_raising_it_resumes(self):
        from dashboard.models import AIProviderSettings
        cfg = AIProviderSettings.objects.create(plan_daily_total=100, plan_daily_per_project=2)
        self.assertEqual([self.reserve(f's{i}') for i in range(2)], ['', ''])
        self.assertIn('daily budget reached', self.reserve('s2'))
        self.assertIn('Settings', self.reserve('s2'))  # the message says where to raise it
        cfg.plan_daily_per_project = 3
        cfg.save()
        self.assertEqual(self.reserve('s3'), '')

    def test_zero_turns_ai_planning_off(self):
        from dashboard.models import AIProviderSettings
        AIProviderSettings.objects.create(plan_daily_total=0)
        self.assertIn('daily budget reached', self.reserve('s0'))
