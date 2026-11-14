"""The secrets inventory over REST and MCP (docs/SECRETS-PLAN.md section 11): masked values only, the roles, tenancy, search, the custom rules and
the Sentinel's rule bundle."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import mcp, secrets_api
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx, search_hosts
from cveFeed import secrets_inventory as inv
from cveFeed import secrets_validation
from cveFeed.models import SecretFinding
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

GITHUB = 'ghp_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2'


class Base(TestCase):
    def setUp(self):
        inv.reset_key_cache()
        self.addCleanup(inv.reset_key_cache)
        self.org = Org.objects.create(name='A', slug='api-org')
        self.project = Project.objects.create(name='A', slug='api-p', insert_date=timezone.now(), org=self.org)
        self.other = Project.objects.create(name='B', slug='api-b', insert_date=timezone.now(), org=Org.objects.create(name='B', slug='b-org'))
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-api', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
        Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='www.example.com')
        self.member = User.objects.create_user('m-api', password='x')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        self.auditor = User.objects.create_user('a-api', password='x')
        ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
        self.row = inv.record(self.project.pk, host='www.example.com', url='https://www.example.com/app.js', source='kingfisher',
                              rule_id='betterleaks.github-pat', value=GITHUB, domain_id=self.domain.pk)

    def ctx(self, user):
        return Ctx(user=user, token=None)


class ApiTests(Base):
    def test_lists_and_details_carry_the_mask_and_never_the_value(self):
        page = secrets_api.list_secrets(self.ctx(self.member), self.project.slug, {})
        self.assertEqual(page['count'], 1)
        detail = secrets_api.get_secret(self.ctx(self.member), self.project.slug, self.row.pk)
        self.assertEqual((detail['masked'], detail['class'], detail['severity']), ('ghp_…J3i2', 'S', 'high'))
        self.assertEqual(detail['occurrence_list'][0]['url'], 'https://www.example.com/app.js')
        for answer in (page, detail):
            self.assertNotIn(GITHUB[4:], json.dumps(answer, default=str))

    def test_filters(self):
        get = lambda **p: secrets_api.list_secrets(self.ctx(self.member), self.project.slug, p)['count']  # noqa: E731
        self.assertEqual((get(**{'class': 'S'}), get(**{'class': 'P'}), get(provider='github'), get(q='app.js'), get(status='quiet')), (1, 0, 1, 1, 0))
        with self.assertRaises(ApiError):
            get(status='nonsense')

    def test_another_projects_secret_is_not_found(self):
        with self.assertRaises(ApiError) as caught:
            secrets_api.get_secret(self.ctx(self.member), self.other.slug, self.row.pk)
        self.assertEqual(caught.exception.status, 404)

    def test_a_status_needs_a_write_role_and_is_audited(self):
        with self.assertRaises(ApiError) as caught:
            secrets_api.set_secret_status(self.ctx(self.auditor), self.project.slug, self.row.pk, {'status': 'accepted'})
        self.assertEqual(caught.exception.status, 403)
        with mock.patch('cveFeed.scoring.rescore_quietly'):
            out = secrets_api.set_secret_status(self.ctx(self.member), self.project.slug, self.row.pk, {'status': 'revoked', 'note': 'rotated'})
        self.assertEqual(out['status'], 'revoked')
        log = AuditLog.objects.get(action='secrets.status')
        self.assertEqual((log.detail['before'], log.detail['after']), ('unverified', 'revoked'))
        with self.assertRaises(ApiError):
            secrets_api.set_secret_status(self.ctx(self.member), self.project.slug, self.row.pk, {'status': 'live'})

    def test_validation_settings_and_requests_are_for_admins_of_opted_in_projects(self):
        with self.assertRaises(ApiError) as caught:
            secrets_api.set_secrets_settings(self.ctx(self.member), self.project.slug, {'validation': {'enabled': True}})
        self.assertEqual(caught.exception.status, 403)
        admin = User.objects.create_user('o-api', password='x')
        OrgMembership.objects.create(user=admin, org=self.org, role='admin')
        with self.assertRaises(ApiError) as caught:
            secrets_api.request_validation(self.ctx(admin), self.project.slug, self.row.pk)
        self.assertEqual(caught.exception.status, 409)  # off for this project
        state = secrets_api.set_secrets_settings(self.ctx(admin), self.project.slug,
                                                 {'validation': {'enabled': True, 'attestation': secrets_validation.ATTESTATION}})
        self.assertTrue(state['validation']['enabled'])
        with mock.patch('agentapi.sentinel_broker.any_scanner_for', return_value=True), \
                mock.patch('cveFeed.tasks.secrets_validate_hosts.apply_async') as queued:
            out = secrets_api.request_validation(self.ctx(admin), self.project.slug, self.row.pk)
        self.assertEqual(out['hosts'], ['www.example.com'])
        queued.assert_called_once_with(args=[self.project.pk, ['www.example.com'], admin.pk])

    def test_search_finds_the_hosts_that_serve_a_counting_secret(self):
        admin = User.objects.create_superuser('root-api', password='x')
        hits = lambda q: [h['host'] for h in search_hosts(self.ctx(admin), self.project.slug, {'q': q, 'facets': 'none'})['results']]  # noqa: E731
        self.assertEqual(hits('secret:s'), ['www.example.com'])
        self.assertEqual(hits('secret:github'), ['www.example.com'])
        self.assertEqual(hits('secret:p'), [])
        with mock.patch('cveFeed.scoring.rescore_quietly'):
            inv.set_status(SecretFinding.objects.get(), 'false_positive', admin)
        self.assertEqual(hits('secret:any'), [])

    def test_the_mcp_tools_are_listed_and_say_no_value_is_returned(self):
        tools = {name: (desc, write) for name, desc, _schema, _fn, write in mcp.TOOLS}
        for name in ('list_secrets', 'get_secret', 'set_secret_status', 'request_secret_validation'):
            self.assertIn(name, tools)
            self.assertRegex(tools[name][0], r'[Nn]ever returns? (a|the) value')
        self.assertFalse(tools['list_secrets'][1])
        self.assertTrue(tools['set_secret_status'][1])


class RulesApiTests(Base):
    def test_app_admins_only_and_the_sentinel_bundle(self):
        with self.assertRaises(ApiError):
            secrets_api.set_secret_rules(self.ctx(self.member), {'rules_yaml': ''})
        admin = User.objects.create_superuser('root-rules', password='x')
        good = 'rules:\n- name: Example\n  id: custom.example\n  pattern: exm_[a-z0-9]{20}\n'
        out = secrets_api.set_secret_rules(self.ctx(admin), {'rules_yaml': good, 'skip_words': ['EXAMPLE']})
        self.assertEqual((out['rule_ids'], out['skip_words']), (['custom.example'], ['EXAMPLE']))
        with self.assertRaises(ApiError):
            secrets_api.set_secret_rules(self.ctx(admin), {'rules_yaml': good + '  validation:\n    type: Http\n'})
        self.assertTrue(AuditLog.objects.filter(action='secrets.rules.updated').exists())
        with self.assertRaises(ApiError) as caught:
            secrets_api.rules_bundle_response(self.ctx(admin))
        self.assertEqual(caught.exception.status, 403)  # a person's token is not a Sentinel's
        token, _raw = create_token(admin, 'sentinel', scope='sentinel')
        with mock.patch('agentapi.sentinel_broker._sentinel_agent'):
            answer = secrets_api.rules_bundle_response(Ctx(user=admin, token=token))
        self.assertEqual(answer.content.decode(), good)
        self.assertEqual(answer['ETag'], f'"{out["bundle_sha256"]}"')
