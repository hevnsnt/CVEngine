"""Edge paths of the security and gate code that the suite did not run (node N6 coverage, release 1.5.0): the do-not-scan lists, the bug
bounty gate, the client address, the field encryption key, the input guard, API token and stored sign-in checks, and tenancy. Each test
names the promise the line keeps, mostly that a bad input or a failing dependency refuses, or is skipped, rather than letting work through."""
import ipaddress
import json
import logging
import os
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import authcheck
from agentapi import auth as agent_auth
from agentapi.services import ApiError, Ctx
from cveFeed import bounty_gate, exclusions
from cveFeed.models import AuthCredential, BountyEngagement, BountyProgram
from cvengine import client_ip, crypto_fields, input_guard
from dashboard.models import Org, OrgMembership, Project
from targetApp.models import Domain
from tenancy import audit as tenancy_audit
from tenancy import membership_cache, mfa_nag, roles


class ExclusionListEdgeTests(TestCase):
    def setUp(self):
        exclusions._bump()
        self.org = Org.objects.create(name='Edge', slug='edge-org')
        self.project = Project.objects.create(name='Edge', slug='edge-p', insert_date=timezone.now(), org=self.org)

    def test_only_a_string_can_be_an_address(self):
        for value in (None, 7, b'192.0.2.1', ['192.0.2.1']):
            self.assertIsNone(exclusions.as_address(value))
        self.assertIsNone(exclusions.as_address('not an address'))

    def test_one_unreadable_stored_network_never_hides_the_others(self):
        nets = exclusions._networks_of(['198.51.100.0/24', 'garbage', '2001:db8::/32'])
        self.assertEqual(nets, (ipaddress.ip_network('198.51.100.0/24'), ipaddress.ip_network('2001:db8::/32')))

    def test_a_value_that_is_not_text_is_never_a_member_of_a_list_that_could_be_read(self):
        listed = exclusions.ExclusionSet(['a.edge.test'], networks=[ipaddress.ip_network('198.51.100.0/24')])
        self.assertNotIn(7, listed)
        self.assertNotIn(None, listed)
        self.assertIn(7, exclusions.ExclusionSet(unreadable=True))  # an unreadable list holds everything: fail closed

    def test_no_project_has_no_networks_and_no_names_have_no_addresses(self):
        self.assertEqual(exclusions.address_networks(None), ())
        self.assertEqual(exclusions.stored_addresses(self.project.pk, ['', '  ']), {})

    def test_a_pattern_covers_its_subtree_only_when_made_with_subdomains(self):
        self.assertTrue(exclusions.covers('edge.test', 'EDGE.test.', False))
        self.assertTrue(exclusions.covers('edge.test', 'https://www.edge.test/x', True))
        self.assertFalse(exclusions.covers('edge.test', 'www.edge.test', False))
        self.assertFalse(exclusions.covers('edge.test', 'notedge.test', True))  # a suffix is not a subdomain

    def test_a_change_inside_a_batch_is_seen_by_the_next_lookup(self):
        # the lists are never cached across calls (PR 892): only the batch memo exists, and a list change drops it
        from cveFeed.models import HostExclusion
        with exclusions.memo():
            self.assertNotIn('late.edge.test', exclusions.excluded_names(self.project.pk, names_only=True))
            HostExclusion.objects.create(org=self.org, host='late.edge.test')
            self.assertIn('late.edge.test', exclusions.excluded_names(self.project.pk, names_only=True))

    def test_forget_without_a_transaction_to_wait_for_keeps_the_reset(self):
        with mock.patch('django.db.transaction.on_commit', side_effect=RuntimeError('no connection')), \
                mock.patch.object(exclusions, '_bump', wraps=exclusions._bump) as bump:
            exclusions.forget()
        bump.assert_called_once()

    def test_a_nested_batch_shares_the_outer_one(self):
        from cveFeed.models import HostExclusion
        HostExclusion.objects.create(org=self.org, host='one.edge.test')
        with exclusions.memo():
            exclusions.excluded_names(self.project.pk, names_only=True)
            with exclusions.memo(), self.assertNumQueries(0):
                self.assertIn('one.edge.test', exclusions.excluded_names(self.project.pk, names_only=True))

    def test_a_read_that_fails_is_never_kept(self):
        calls = []
        def read():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('database down')
            return ('x.edge.test',)
        with exclusions.memo():
            with self.assertRaises(RuntimeError):
                exclusions._cached('names', self.project.pk, read)
            self.assertEqual(exclusions._cached('names', self.project.pk, read), ('x.edge.test',))
        self.assertEqual(len(calls), 2)


class BountyGateEdgeTests(TestCase):
    def test_a_bounty_project_whose_program_has_no_scope_index_is_refused(self):
        scope = bounty_gate._ProjectScope.__new__(bounty_gate._ProjectScope)
        scope.bounty, scope.indexes, scope.targets = True, [], set()
        self.assertEqual(scope.refusal('www.acme.test'), 'the program lists no scope')

    def test_work_with_no_project_is_not_a_bounty_question(self):
        gate = bounty_gate.Gate(blocked=set())
        self.assertEqual(gate.refusal(None, 'www.acme.test'), '')
        self.assertEqual(gate.refusal(0), '')
        self.assertEqual(gate.refusal(12345), '')  # a project, no host, not blocked: the host question is not asked

    def test_a_project_with_an_engagement_reads_its_scope_and_refuses_an_unlisted_host(self):
        org = Org.objects.create(name='B', slug='b-edge')
        project = Project.objects.create(name='B', slug='b-edge-p', insert_date=timezone.now(), org=org)
        program = BountyProgram.objects.create(platform='hackerone', handle='edge', name='Edge')
        BountyEngagement.objects.create(project=project, program=program, status='active', automated_ok=True, policy_ack_at=timezone.now(),
                                        ack_content_hash=program.content_hash)
        self.assertTrue(bounty_gate.Gate(blocked=set()).refusal(project.pk, 'www.acme.test'))  # the program names nothing: never scanned


class ClientAddressEdgeTests(SimpleTestCase):
    def test_an_unparseable_trusted_proxy_entry_is_skipped_and_the_others_still_apply(self):
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': 'not-a-network, 172.30.0.0/24,,  '}):
            self.assertEqual(client_ip.trusted_proxies(), [ipaddress.ip_network('172.30.0.0/24')])
            request = RequestFactory().get('/', REMOTE_ADDR='172.30.0.5', HTTP_X_FORWARDED_FOR='8.8.4.4')
            self.assertEqual(client_ip.client_ip(request), '8.8.4.4')
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': 'nonsense'}):
            request = RequestFactory().get('/', REMOTE_ADDR='172.30.0.5', HTTP_X_FORWARDED_FOR='8.8.4.4')
            self.assertEqual(client_ip.client_ip(request), '172.30.0.5')  # nothing trusted: the forwarded header is ignored


class FieldKeyEdgeTests(SimpleTestCase):
    def test_an_unreadable_key_file_is_logged_and_gives_no_key(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith('CVENGINE_FIELD_KEY')}
        env['CVENGINE_FIELD_KEY_FILE'] = '/nonexistent/n6/field.key'
        with mock.patch.dict(os.environ, env, clear=True), self.assertLogs('cvengine.crypto_fields', logging.WARNING) as logs:
            self.assertEqual(crypto_fields.dedicated_keys(), ())
        self.assertIn('/nonexistent/n6/field.key', logs.output[0])

    def test_an_encrypted_json_value_that_does_not_decode_reads_as_empty(self):
        field = crypto_fields.EncryptedJSONField()
        token = crypto_fields.encrypt_text('{not json')
        self.assertEqual(field.from_db_value(json.dumps({crypto_fields.JSON_MARKER: token}), None, connection), {})


class InputGuardEdgeTests(TestCase):
    def test_a_bad_strike_threshold_is_the_default(self):
        for value in ('lots', ''):
            with mock.patch.dict(os.environ, {'CVENGINE_GUARD_STRIKES': value}):
                self.assertEqual(input_guard._threshold(), 3)
        with mock.patch.dict(os.environ, {'CVENGINE_GUARD_STRIKES': '0'}):
            self.assertEqual(input_guard._threshold(), 1)

    def test_inspection_stops_at_the_string_cap(self):
        pairs = [('note', 'plain words')] * input_guard.MAX_STRINGS + [('note', '<script>alert(1)</script>')]
        self.assertEqual(input_guard.inspect(pairs), [])
        self.assertTrue(input_guard.inspect(pairs[-1:]))

    def test_a_commented_line_of_a_pasted_list_is_not_input(self):
        field = sorted(input_guard.BULK_FIELDS)[0]
        self.assertEqual(input_guard.inspect([(field, '# a<b>c comment line\nwww.example.test')]), [])

    def test_a_bad_content_length_reads_as_no_body(self):
        request = RequestFactory().post('/cve/api/x', data='{}', content_type='application/json')
        request.META['CONTENT_LENGTH'] = 'many'
        self.assertEqual(input_guard._request_pairs(request), [])
        api = RequestFactory().post('/api/v1/projects/x/notes', data='{}', content_type='application/json')
        api.META['CONTENT_LENGTH'] = 'many'
        self.assertFalse(input_guard._oversize_api_json(api))

    def test_a_ban_lookup_that_fails_is_logged_and_bans_nobody(self):
        input_guard.invalidate_cache()
        with mock.patch.object(input_guard, 'banned_ips', side_effect=RuntimeError('db down')), self.assertLogs('cvengine.input_guard', logging.ERROR):
            self.assertFalse(input_guard.is_banned('8.8.4.4'))

    def test_a_bearer_token_request_has_no_session_to_end(self):
        user = User.objects.create_user('guard-edge', password='x')
        request = RequestFactory().get('/')
        request.api_token, request.session, request.user = object(), mock.Mock(), user
        self.assertFalse(input_guard._end_session(request, user))
        browser = RequestFactory().get('/')
        browser.session, browser.user = mock.Mock(), mock.Mock(pk=user.pk + 1)
        self.assertFalse(input_guard._end_session(browser, user))  # a session of someone else is never ended for this user

    def test_a_strike_that_cannot_be_recorded_still_rejects_the_request(self):
        middleware = input_guard.InputGuardMiddleware(lambda request: self.fail('the request reached the app'))
        request = RequestFactory().get('/cve/api/stats', {'q': '<script>alert(1)</script>'})
        request.user = mock.Mock(is_authenticated=False)
        with mock.patch.object(input_guard, 'record_and_maybe_ban', side_effect=RuntimeError('db down')), \
                self.assertLogs('cvengine.input_guard', logging.ERROR):
            response = middleware(request)
        self.assertEqual(response.status_code, 400)


class StoredSignInEdgeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org, cls.other_org = Org.objects.create(name='SI', slug='si-org'), Org.objects.create(name='SI2', slug='si-org2')
        cls.project = Project.objects.create(name='SI', slug='si-p', insert_date=now, org=cls.org)
        cls.other = Project.objects.create(name='SI2', slug='si-p2', insert_date=now, org=cls.other_org)
        cls.domain = Domain.objects.create(name='app.si.test', project=cls.project, insert_date=now)
        cls.foreign = Domain.objects.create(name='app.si2.test', project=cls.other, insert_date=now)
        cls.root = User.objects.create_superuser('si-root', 'r@si.test', 'x')
        cls.foreign_cred = AuthCredential.objects.create(project=cls.other, domain=cls.foreign, host='app.si2.test', label='theirs',
                                                         origins=['https:443'], secret={'headers': [['Authorization', 'Bearer aaaaaaaa']], 'cookie': ''})

    def test_a_target_id_must_be_a_number_of_this_project(self):
        ctx = Ctx(user=self.root)
        with self.assertRaises(ApiError) as bad:
            authcheck.list_credentials(ctx, 'si-p', {'target_id': 'abc'})
        self.assertEqual(bad.exception.status, 400)
        with self.assertRaises(ApiError) as foreign:
            authcheck.list_credentials(ctx, 'si-p', {'target_id': self.foreign.pk})
        self.assertEqual(foreign.exception.status, 404)  # another project's target is not found, not listed
        self.assertEqual(authcheck.list_credentials(ctx, 'si-p', {'target_id': self.domain.pk})['results'], [])

    def test_a_credential_of_another_project_cannot_be_deleted_through_this_one(self):
        ctx = Ctx(user=self.root)
        with self.assertRaises(ApiError) as bad:
            authcheck.delete_credential(ctx, 'si-p', 'abc')
        self.assertEqual(bad.exception.status, 400)
        with self.assertRaises(ApiError) as foreign:
            authcheck.delete_credential(ctx, 'si-p', self.foreign_cred.pk)
        self.assertEqual(foreign.exception.status, 404)
        self.assertTrue(AuthCredential.objects.filter(pk=self.foreign_cred.pk).exists())

    def test_a_target_holds_at_most_the_cap(self):
        ctx = Ctx(user=self.root)
        for i in range(authcheck.MAX_PER_TARGET):
            AuthCredential.objects.create(project=self.project, domain=self.domain, host=f'h{i}.app.si.test', label=f'a{i}', origins=['https:443'],
                                          secret={'headers': [['Authorization', 'Bearer aaaaaaaa']], 'cookie': ''})
        body = {'label': 'one more', 'scope': 'host', 'host': 'app.si.test', 'headers': [{'name': 'Authorization', 'secret': 'Bearer bbbbbbbbbbbb'}],
                'expires': 30}
        with self.assertRaises(ApiError) as full:
            authcheck.set_credential(ctx, 'si-p', self.domain.pk, body)
        self.assertEqual(full.exception.status, 400)
        self.assertIn(str(authcheck.MAX_PER_TARGET), str(full.exception))


class TokenEdgeTests(TestCase):
    def test_a_value_without_the_token_prefix_is_never_looked_up(self):
        with self.assertNumQueries(0):
            self.assertIsNone(agent_auth.authenticate('Bearer something-else'))


class TenancyEdgeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org_a, cls.org_b = Org.objects.create(name='TA', slug='te-a'), Org.objects.create(name='TB', slug='te-b')
        cls.pa = Project.objects.create(name='TA', slug='te-pa', insert_date=now, org=cls.org_a)
        cls.root = User.objects.create_superuser('te-root', 'r@te.test', 'x')
        cls.admin_a = User.objects.create_user('te-admin-a', password='x')
        cls.admin_b = User.objects.create_user('te-admin-b', password='x')
        cls.member_b = User.objects.create_user('te-member-b', password='x')
        cls.plain = User.objects.create_user('te-plain', password='x')
        OrgMembership.objects.create(user=cls.admin_a, org=cls.org_a, role='admin')
        OrgMembership.objects.create(user=cls.admin_b, org=cls.org_b, role='admin')
        OrgMembership.objects.create(user=cls.member_b, org=cls.org_b, role='user')

    def test_an_org_admin_cannot_reset_the_sign_in_of_a_user_outside_their_orgs(self):
        self.assertFalse(roles.can_manage_credentials(self.admin_a, self.member_b))
        self.assertTrue(roles.can_manage_credentials(self.admin_b, self.member_b))

    def test_an_org_admin_can_never_grant_a_membership_to_an_app_admin(self):
        self.assertFalse(roles.can_grant_membership_to(self.admin_a, self.root))

    def test_an_org_admin_of_no_organization_has_no_admins_to_list(self):
        self.assertEqual(mfa_nag.admins_without_mfa(self.plain), [])

    def test_a_cache_that_is_down_never_breaks_a_membership_change(self):
        with mock.patch.object(membership_cache.cache, 'set', side_effect=RuntimeError('redis down')):
            membership_cache.bump_epoch()

    def test_a_cache_that_cannot_store_the_live_screen_answer_still_answers(self):
        request = RequestFactory().get('/cve/api/stats')
        with mock.patch.object(membership_cache, 'CACHE_IN_TRANSACTION', True), \
                mock.patch.object(membership_cache.livecache_config, 'auth_cache_seconds', return_value=30), \
                mock.patch.object(membership_cache.cache, 'set', side_effect=RuntimeError('redis down')):
            self.assertEqual(membership_cache.allowed_for_request(request, self.admin_a), roles.allowed_project_ids(self.admin_a))

    def test_scoping_the_managers_twice_wraps_each_once(self):
        from django.apps import apps

        from tenancy import scope
        before = {label: type(apps.get_model(label)._default_manager) for label in scope.SCOPES}
        scope.install(apps)
        self.assertEqual({label: type(apps.get_model(label)._default_manager) for label in scope.SCOPES}, before)

    def test_a_token_whose_agent_cannot_be_read_still_describes_the_token(self):
        token = mock.Mock(pk=5)
        token.name = 'ci key'
        with mock.patch('agentapi.models.Agent.objects.filter', side_effect=RuntimeError('db')):
            self.assertEqual(tenancy_audit.describe_token(token), {'name': 'ci key'})

    def test_sign_out_and_the_admin_login_redirect(self):
        # the views themselves: the tenancy middleware answers /admin/ for anyone but an App Admin before the view runs
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.sessions.backends.db import SessionStore

        from tenancy.views import SignOutView, admin_login_redirect

        def get(path, user):
            request = RequestFactory().get(path)
            request.user, request.session = user, SessionStore()
            return request
        response = SignOutView.as_view()(get('/logout/', AnonymousUser()))
        self.assertEqual((response.status_code, response['Location']), (302, '/login/'))
        response = admin_login_redirect(get('/admin/login/', self.plain))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('/admin/', response['Location'])  # a user who is not staff goes to the app, never the admin
        self.assertEqual(admin_login_redirect(get('/admin/login/', self.root))['Location'], '/admin/')
        self.assertEqual(admin_login_redirect(get('/admin/login/?next=https://evil.example/', self.root))['Location'], '/admin/')  # never off site


class TenancyDeadRuleTests(SimpleTestCase):
    def test_the_admin_only_rule_matches_no_path(self):
        # ADMIN_ONLY is '^/(?!)', which matches nothing: settings are guarded by SUPERUSER_ONLY. Pinned so a change to it is deliberate.
        for path in ('/', '/cve/api/settings/x', '/cve/settings/', '/scanEngine/x/tool_settings'):
            self.assertIsNone(roles.ADMIN_ONLY.match(path), path)
        self.assertEqual(roles.check_access(roles.ADMIN, 'GET', '/cve/api/stats'), None)
