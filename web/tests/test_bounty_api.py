import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed import bounty_data, bounty_report, bounty_submit
from cveFeed.models import (BountyCredential, BountyEngagement, BountyEngagementTarget, BountyProgram, BountyReport, BountySource)
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership, UserProfile
from startScan.models import Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_tenancy import client_for

B = '/cve/api/bounty/'
A = '/cve/api/admin/'

CAT = [{'handle': 'acme', 'name': 'Acme', 'url': 'https://hackerone.com/acme', 'offers_bounties': True, 'submission_state': 'open',
        'targets': {'in_scope': [{'asset_type': 'URL', 'asset_identifier': '*.acme.test', 'eligible_for_bounty': True},
                                 {'asset_type': 'URL', 'asset_identifier': 'www.acme.test', 'eligible_for_bounty': True},
                                 {'asset_type': 'CIDR', 'asset_identifier': '203.0.113.0/30'}],
                    'out_of_scope': [{'asset_type': 'URL', 'asset_identifier': 'status.acme.test'}]}},
       {'handle': 'free', 'name': 'Free VDP', 'offers_bounties': False,
        'targets': {'in_scope': [{'asset_type': 'URL', 'asset_identifier': 'free.test'}], 'out_of_scope': []}}]
CAT_BC = [{'name': 'Beta', 'url': 'https://bugcrowd.com/engagements/beta', 'max_payout': 100, 'safe_harbor': 'full',
           'targets': {'in_scope': [{'type': 'website', 'name': 'x', 'uri': 'https://beta.test'}], 'out_of_scope': []}}]


def call(client, method, path, body=None):
    fn = getattr(client, method.lower())
    r = fn(path, json.dumps(body) if body is not None else None, content_type='application/json') if method != 'GET' else fn(path)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None


class BountyBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org_a, cls.org_b = Org.objects.create(name='Alpha', slug='alpha'), Org.objects.create(name='Beta', slug='beta')
        cls.pa = Project.objects.create(name='A1', slug='a1', insert_date=now, org=cls.org_a)
        cls.pa2 = Project.objects.create(name='A2', slug='a2', insert_date=now, org=cls.org_a)
        cls.pb = Project.objects.create(name='B1', slug='b1', insert_date=now, org=cls.org_b)
        mk = lambda n, **kw: User.objects.create_user(n, password='pw-Secret-1', **kw)
        cls.root = User.objects.create_superuser('root', 'r@x.io', 'pw-Secret-1')
        cls.admin_a, cls.member, cls.granted, cls.granted_b, cls.audit = mk('adminA'), mk('member'), mk('granted'), mk('grantedB'), mk('auditor')
        OrgMembership.objects.create(user=cls.admin_a, org=cls.org_a, role='admin')
        OrgMembership.objects.create(user=cls.member, org=cls.org_a, role='user')
        OrgMembership.objects.create(user=cls.granted, org=cls.org_a, role='user')
        OrgMembership.objects.create(user=cls.granted_b, org=cls.org_b, role='user')
        OrgMembership.objects.create(user=cls.audit, org=cls.org_a, role='audit')
        for u in (cls.granted, cls.granted_b, cls.audit):
            UserProfile.objects.update_or_create(user=u, defaults={'bugbounty_enabled': True})
        bounty_data.sync_platform('hackerone', fetcher=lambda url, old: (CAT, '"e"'))
        bounty_data.sync_platform('bugcrowd', fetcher=lambda url, old: (CAT_BC, '"e"'))
        cls.acme = BountyProgram.objects.get(handle='acme')

    def setUp(self):
        self.c = client_for(self.granted)


class GrantTests(BountyBase):
    def put(self, client, user, enabled):
        return call(client, 'PUT', f'{A}users/{user.pk}/bug-bounty', {'enabled': enabled})

    def test_the_app_admin_authorizes_and_it_is_audited(self):
        status, data = self.put(client_for(self.root), self.member, True)
        self.assertEqual(status, 200)
        self.assertTrue(data['bugbounty_enabled'])
        self.assertTrue(UserProfile.objects.get(user=self.member).bugbounty_enabled)
        row = AuditLog.objects.get(action='user.bugbounty_grant')
        self.assertEqual((row.actor_name, row.target, row.detail), ('root', 'member', {'before': False, 'after': True}))

    def test_revoking_is_audited_and_takes_effect_at_once(self):
        self.put(client_for(self.root), self.member, True)
        mc = client_for(self.member)
        self.assertEqual(call(mc, 'GET', B + 'status')[0], 200)
        self.assertEqual(self.put(client_for(self.root), self.member, False)[0], 200)
        self.assertEqual(call(mc, 'GET', B + 'status')[0], 403)
        self.assertTrue(AuditLog.objects.filter(action='user.bugbounty_revoke', target='member').exists())

    def test_nobody_else_can_authorize(self):
        for who in (self.admin_a, self.member, self.granted, self.audit):
            status, data = self.put(client_for(who), self.member, True)
            self.assertEqual(status, 403, who.username)
        self.assertFalse(UserProfile.objects.filter(user=self.member, bugbounty_enabled=True).exists())
        self.assertFalse(AuditLog.objects.filter(action__startswith='user.bugbounty').exists())

    def test_an_org_admin_cannot_authorize_herself(self):
        self.assertEqual(self.put(client_for(self.admin_a), self.admin_a, True)[0], 403)
        self.assertEqual(call(client_for(self.admin_a), 'GET', B + 'status')[0], 403)

    def test_the_ordinary_user_update_cannot_set_it(self):
        status, _ = call(client_for(self.admin_a), 'PATCH', f'{A}users/{self.member.pk}', {'bugbounty_enabled': True, 'first_name': 'Mo'})
        self.assertEqual(status, 200)
        self.assertFalse(UserProfile.objects.filter(user=self.member, bugbounty_enabled=True).exists())

    def test_input_checks(self):
        root = client_for(self.root)
        self.assertEqual(call(root, 'PUT', f'{A}users/{self.member.pk}/bug-bounty', {'enabled': 'yes'})[0], 400)
        self.assertEqual(call(root, 'PUT', f'{A}users/{self.member.pk}/bug-bounty', {})[0], 400)
        self.assertEqual(call(root, 'PUT', f'{A}users/999999/bug-bounty', {'enabled': True})[0], 404)
        self.assertEqual(self.put(root, self.root, False)[0], 409)  # an App Admin always has it

    def test_the_users_list_shows_the_flag_and_an_app_admin_always(self):
        _, data = call(client_for(self.root), 'GET', A + 'users')
        by = {u['username']: u for u in data['results']}
        self.assertTrue(by['root']['bugbounty_enabled'])
        self.assertTrue(by['granted']['bugbounty_enabled'])
        self.assertFalse(by['member']['bugbounty_enabled'])


class AccessTests(BountyBase):
    def test_unauthorized_users_are_refused_everywhere(self):
        mc, ac = client_for(self.member), client_for(self.admin_a)
        for c in (mc, ac):
            self.assertEqual(call(c, 'GET', B + 'status')[0], 403)
            self.assertEqual(call(c, 'GET', B + 'programs')[0], 403)
            self.assertEqual(call(c, 'POST', B + 'reports', {'project': 'a1'})[0], 403)
            self.assertEqual(c.get('/cve/bounty/').status_code, 403)

    def test_authorized_and_app_admin_get_in(self):
        for who in (self.granted, self.root):
            c = client_for(who)
            self.assertEqual(call(c, 'GET', B + 'status')[0], 200, who.username)
            self.assertEqual(c.get('/cve/bounty/?project=a1').status_code, 200)

    def test_the_page_and_nav_only_show_for_the_authorized(self):
        self.assertIn(b'Bug bounty', client_for(self.granted).get('/cve/bounty/?project=a1').content)
        self.assertNotIn(b'href="/cve/bounty/', client_for(self.member).get('/cve/?skip=1').content)
        self.assertIn(b'href="/cve/bounty/', client_for(self.granted).get('/cve/?skip=1').content)

    def test_audit_can_read_but_not_write(self):
        ac = client_for(self.audit)
        self.assertEqual(call(ac, 'GET', B + 'programs')[0], 200)
        self.assertEqual(call(ac, 'POST', B + 'engagements', {'project': 'a1', 'program_id': self.acme.pk})[0], 403)

    def test_handler_checks_again_when_the_middleware_is_skipped(self):
        from django.test import RequestFactory
        from cveFeed import bounty_api
        req = RequestFactory().get(B + 'status')
        req.user = self.member
        self.assertEqual(bounty_api.dispatch(req, 'status').status_code, 403)
        req.user = self.granted
        self.assertEqual(bounty_api.dispatch(req, 'status').status_code, 200)

    def test_unknown_route_and_wrong_method(self):
        self.assertEqual(call(self.c, 'GET', B + 'nope')[0], 404)
        self.assertEqual(call(self.c, 'DELETE', B + 'status')[0], 405)


class CatalogueTests(BountyBase):
    def test_status_lists_every_platform(self):
        _, d = call(self.c, 'GET', B + 'status')
        by = {c['platform']: c for c in d['catalogue']}
        self.assertTrue(by['hackerone']['loaded'] and by['bugcrowd']['loaded'])
        self.assertFalse(by['intigriti']['loaded'])
        self.assertEqual(d['credentials'], {})

    def test_program_filters(self):
        _, d = call(self.c, 'GET', B + 'programs?bounty=1')
        self.assertEqual({p['handle'] for p in d['results']}, {'acme', 'beta'})
        _, d = call(self.c, 'GET', B + 'programs?q=free')
        self.assertEqual([p['handle'] for p in d['results']], ['free'])
        _, d = call(self.c, 'GET', B + 'programs?q=beta.test')  # a domain search finds the program that lists it
        self.assertEqual([p['handle'] for p in d['results']], ['beta'])
        _, d = call(self.c, 'GET', B + 'programs?harbor=full')
        self.assertEqual([p['handle'] for p in d['results']], ['beta'])
        _, d = call(self.c, 'GET', B + 'programs?platform=bugcrowd')
        self.assertEqual(d['count'], 1)
        self.assertEqual(call(self.c, 'GET', B + 'programs?page=x')[0], 400)

    def test_search_text_is_not_interpreted(self):
        status, d = call(self.c, 'GET', B + "programs?q=%25_%5C%5C")  # LIKE wildcards and a backslash are matched literally
        self.assertEqual((status, d['count']), (200, 0))
        _, d = call(self.c, 'GET', B + "programs?q=%25")
        self.assertEqual(d['count'], 0)

    def test_detail_and_scope_check(self):
        status, d = call(self.c, 'GET', f'{B}programs/{self.acme.pk}')
        self.assertEqual(status, 200)
        self.assertEqual(sum(1 for a in d['assets'] if a['in_scope']), 3)
        _, chk = call(self.c, 'POST', B + 'scope-check', {'program_id': self.acme.pk, 'hosts': ['x.acme.test', 'acme.test', 'status.acme.test', 'other.org', '203.0.113.2']})
        self.assertEqual([r['state'] for r in chk['results']], ['in_scope', 'ambiguous', 'out_of_scope', 'not_listed', 'in_scope'])
        self.assertEqual(call(self.c, 'GET', B + 'programs/999999')[0], 404)

    def test_matches_list_only_this_projects_targets(self):
        now = timezone.now()
        Domain.objects.create(name='www.acme.test', project=self.pa, insert_date=now)
        Domain.objects.create(name='app.beta.test', project=self.pb, insert_date=now)
        _, d = call(self.c, 'GET', B + 'matches?project=a1')
        self.assertEqual([r['program']['handle'] for r in d['results']], ['acme'])
        self.assertEqual(d['results'][0]['targets'][0]['state'], 'in_scope')
        self.assertEqual(call(self.c, 'GET', B + 'matches?project=b1')[0], 404)  # not this user's project
        self.assertEqual(call(self.c, 'GET', B + 'matches')[0], 400)  # a project is needed

    def test_refresh_is_rate_limited_and_queued(self):
        from django.core.cache import cache
        cache.delete('bounty-catalogue-refresh')
        with mock.patch('cveFeed.tasks.sync_bounty_catalogue.delay') as q:
            self.assertEqual(call(self.c, 'POST', B + 'catalogue/refresh', {})[0], 202)
            self.assertEqual(call(self.c, 'POST', B + 'catalogue/refresh', {})[0], 429)
        self.assertEqual(q.call_count, 1)
        cache.delete('bounty-catalogue-refresh')

    def test_the_status_follows_a_queued_load_until_the_task_finishes_it(self):
        from django.core.cache import cache
        from cveFeed.tasks import sync_bounty_catalogue
        cache.delete('bounty-catalogue-refresh')
        with mock.patch('cveFeed.tasks.sync_bounty_catalogue.delay'):
            call(self.c, 'POST', B + 'catalogue/refresh', {})
        loading = call(self.c, 'GET', B + 'status')[1]['loading']
        self.assertTrue(loading['requested'])
        self.assertIsNone(loading['running'])
        with mock.patch('cveFeed.bounty_data.sync_all', return_value=[{'platform': 'hackerone', 'status': 'updated', 'programs': 3},
                                                                    {'platform': 'bugcrowd', 'status': 'error', 'error': 'the data host answered 503'}]):
            sync_bounty_catalogue.run(force=True)
        self.assertEqual(call(self.c, 'GET', B + 'status')[1]['loading'], {'requested': None, 'running': None})
        from cveFeed.models import AgentActivity
        line = AgentActivity.objects.filter(message__startswith='Bug bounty catalogue').latest('id')
        self.assertEqual(line.status, 'failed')
        self.assertIn('hackerone 3', line.message)
        self.assertIn('bugcrowd: the data host answered 503', line.message)
        cache.delete('bounty-catalogue-refresh')

    def test_refresh_can_be_turned_off(self):
        with mock.patch.dict('os.environ', {'CVENGINE_BOUNTY_CATALOGUE': '0'}):
            self.assertEqual(call(self.c, 'POST', B + 'catalogue/refresh', {})[0], 409)

    def test_the_task_does_nothing_until_loaded_once_and_honours_the_switch(self):
        from cveFeed.tasks import sync_bounty_catalogue
        BountySource.objects.all().delete()
        self.assertEqual(sync_bounty_catalogue.run()['status'], 'not loaded yet')
        with mock.patch.dict('os.environ', {'CVENGINE_BOUNTY_CATALOGUE': '0'}):
            self.assertEqual(sync_bounty_catalogue.run(force=True)['status'], 'disabled')


def legacy_engagement(project, program, user):
    """An engagement in a client's own project, as every engagement was before the Bug Bounty org: still supported."""
    from cveFeed.bounty_api import engagement_dict
    eng, _ = BountyEngagement.objects.get_or_create(project=project, program=program, defaults={'created_by': user, 'policy_url': program.url})
    return engagement_dict(eng)


class EngagementTests(BountyBase):
    def make(self, client=None):
        return legacy_engagement(self.pa, self.acme, self.granted)

    def test_an_existing_engagement_is_project_scoped(self):
        self.make()
        self.assertEqual(self.make()['id'], self.make()['id'])
        self.assertEqual(BountyEngagement.objects.filter(project=self.pa).count(), 1)
        self.assertEqual(call(client_for(self.granted_b), 'GET', B + 'engagements?project=a1')[0], 404)

    def test_gates_need_the_policy_acknowledgement(self):
        e = self.make()
        url = f'{B}engagements/{e["id"]}'
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'active'})[0], 409)
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'automated_ok': True})[0], 409)
        self.assertEqual(call(self.c, 'POST', url + '/import', {'project': 'a1', 'dry_run': False})[0], 409)
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'bogus'})[0], 400)
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'policy_url': 'http://x'})[0], 400)

    def test_acknowledging_is_recorded_and_flags_a_later_scope_change(self):
        e = self.make()
        url = f'{B}engagements/{e["id"]}'
        status, d = call(self.c, 'PATCH', url, {'project': 'a1', 'acknowledge': True})
        self.assertEqual((status, d['policy_ack_by'], d['scope_changed_since_ack']), (200, 'granted', False))
        self.assertTrue(AuditLog.objects.filter(action='bounty.policy_ack', actor_name='granted').exists())
        changed = json.loads(json.dumps(CAT))
        changed[0]['targets']['in_scope'].append({'asset_type': 'URL', 'asset_identifier': 'new.acme.test'})
        bounty_data.sync_platform('hackerone', fetcher=lambda u, o: (changed, '"e2"'))
        _, d = call(self.c, 'GET', f'{B}engagements?project=a1')
        self.assertTrue(d['results'][0]['scope_changed_since_ack'])
        _, st = call(self.c, 'GET', B + 'stats?project=a1')
        self.assertEqual(len(st['scope_changed']), 1)

    def test_import_previews_then_adds_without_discovery_by_default(self):
        e = self.make()
        url = f'{B}engagements/{e["id"]}'
        _, plan = call(self.c, 'POST', url + '/import', {'project': 'a1'})
        values = [t['value'] for t in plan['targets']]
        self.assertIn('acme.test', values)
        self.assertIn('www.acme.test', values)
        self.assertNotIn('status.acme.test', values)
        self.assertFalse(plan['discovery'])
        call(self.c, 'PATCH', url, {'project': 'a1', 'acknowledge': True})
        with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async'), mock.patch('agentapi.services._start_discoveries') as disc:
            status, out = call(self.c, 'POST', url + '/import', {'project': 'a1', 'dry_run': False, 'values': ['www.acme.test', 'not-in-plan.example']})
        self.assertEqual(status, 200)
        self.assertEqual((out['requested'], out['created'], out['discovery_started']), (1, 1, False))
        disc.assert_not_called()
        self.assertTrue(Domain.objects.filter(project=self.pa, name='www.acme.test').exists())
        self.assertFalse(Domain.objects.filter(name='not-in-plan.example').exists())
        self.assertEqual(BountyEngagementTarget.objects.filter(engagement_id=e['id']).count(), 1)
        self.assertTrue(AuditLog.objects.filter(action='bounty.import_targets').exists())

    def test_discovery_starts_only_when_scanning_was_confirmed(self):
        e = self.make()
        url = f'{B}engagements/{e["id"]}'
        call(self.c, 'PATCH', url, {'project': 'a1', 'acknowledge': True})
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'automated_ok': True})[0], 200)
        with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async'), mock.patch('agentapi.services._start_discoveries', return_value=[mock.Mock(id=1)]) as disc:
            _, out = call(self.c, 'POST', url + '/import', {'project': 'a1', 'dry_run': False, 'values': ['www.acme.test']})
        disc.assert_called_once()
        self.assertTrue(out['discovery_started'])

    def test_import_size_is_capped(self):
        e = self.make()
        call(self.c, 'PATCH', f'{B}engagements/{e["id"]}', {'project': 'a1', 'acknowledge': True})
        eng = BountyEngagement.objects.get(pk=e['id'])
        with mock.patch('cveFeed.bounty_api.bounty_scope.import_plan', return_value={'targets': [{'value': f'h{i}.acme.test', 'asset': 'x', 'note': ''} for i in range(300)], 'skipped': []}):
            status, out = call(self.c, 'POST', f'{B}engagements/{eng.pk}/import', {'project': 'a1', 'dry_run': False})
        self.assertEqual(status, 400)

    def test_removing_needs_closed_reports(self):
        e = self.make()
        r = BountyReport.objects.create(project=self.pa, engagement_id=e['id'], title='t', status='submitted')
        self.assertEqual(call(self.c, 'DELETE', f'{B}engagements/{e["id"]}?project=a1')[0], 409)
        r.status = 'closed'; r.save()
        self.assertEqual(call(self.c, 'DELETE', f'{B}engagements/{e["id"]}?project=a1')[0], 200)


class BugBountyOrgTests(BountyBase):
    """Working a program puts it in that program's own project in the Bug Bounty org, never in a client's project."""

    def create(self, client=None, program=None, **body):
        return call(client or self.c, 'POST', B + 'engagements', {'program_id': (program or self.acme).pk, **body})

    def test_a_program_gets_its_own_project_in_a_bug_bounty_org_created_on_first_use(self):
        self.assertFalse(Org.objects.filter(slug='bug-bounty').exists())
        status, e = self.create()
        self.assertEqual((status, e['project'], e['org'], e['project_name']), (201, 'bb-hackerone-acme', 'bug-bounty', self.acme.name))
        org = Org.objects.get(slug='bug-bounty')
        self.assertEqual(org.name, 'Bug Bounty')
        project = Project.objects.get(slug='bb-hackerone-acme')
        self.assertEqual(project.org, org)
        self.assertEqual(BountyEngagement.objects.get(pk=e['id']).project, project)

    def test_each_program_gets_a_separate_project_in_the_same_org(self):
        bc = BountyProgram.objects.get(platform='bugcrowd')
        _, one = self.create()
        _, two = self.create(program=bc)
        self.assertNotEqual(one['project'], two['project'])
        self.assertEqual(Org.objects.filter(slug='bug-bounty').count(), 1)
        self.assertEqual(Project.objects.filter(org__slug='bug-bounty').count(), 2)

    def test_the_project_passed_in_is_not_where_it_goes(self):
        _, e = self.create(project='a1')
        self.assertNotEqual(e['project'], 'a1')
        self.assertFalse(BountyEngagement.objects.filter(project=self.pa).exists())
        self.assertEqual(self.create(project='b1')[0], 200)  # not even a project this user may see: it is not looked at

    def test_creating_again_returns_the_same_engagement(self):
        _, first = self.create()
        status, again = self.create()
        self.assertEqual((status, again['id']), (200, first['id']))
        self.assertEqual(BountyEngagement.objects.filter(program=self.acme).count(), 1)

    def test_the_creator_can_open_what_they_made_and_it_is_audited(self):
        _, e = self.create()
        self.assertEqual(ProjectMembership.objects.get(user=self.granted, project__slug=e['project']).role, 'admin')
        self.assertEqual(call(self.c, 'GET', f'{B}engagements?project={e["project"]}')[0], 200)
        self.assertEqual(call(client_for(self.granted_b), 'GET', f'{B}engagements?project={e["project"]}')[0], 404)
        self.assertTrue(AuditLog.objects.filter(action='bounty.project_create', actor_name='granted', detail__project=e['project']).exists())
        self.assertTrue(AuditLog.objects.filter(action='bounty.engagement_create', actor_name='granted').exists())

    def test_another_user_cannot_silently_join_an_engagement_they_were_not_added_to(self):
        _, e = self.create()
        status, body = self.create(client=client_for(self.granted_b))
        self.assertEqual(status, 409)
        self.assertIn(e['project'], body['error'])
        self.assertFalse(ProjectMembership.objects.filter(user=self.granted_b, project__slug=e['project']).exists())
        self.assertEqual(self.create(client=client_for(self.root))[0], 200)  # an App Admin sees every project

    def test_the_audit_role_and_a_user_with_no_role_cannot_create(self):
        self.assertEqual(self.create(client=client_for(self.audit))[0], 403)
        nobody = User.objects.create_user('nobody', password='pw-Secret-1')
        UserProfile.objects.update_or_create(user=nobody, defaults={'bugbounty_enabled': True})
        self.assertEqual(self.create(client=client_for(nobody))[0], 403)
        self.assertFalse(Org.objects.filter(slug='bug-bounty').exists())

    def test_the_list_without_a_project_shows_only_the_bug_bounty_projects_the_caller_can_see(self):
        bc = BountyProgram.objects.get(platform='bugcrowd')
        self.create()
        self.create(client=client_for(self.granted_b), program=bc)
        legacy_engagement(self.pa, bc, self.granted)  # a client project's own engagement is not in the Bug Bounty org
        mine = call(self.c, 'GET', B + 'engagements')[1]['results']
        self.assertEqual([r['project'] for r in mine], ['bb-hackerone-acme'])
        self.assertEqual({r['project'] for r in call(client_for(self.root), 'GET', B + 'engagements')[1]['results']},
                         {'bb-hackerone-acme', 'bb-bugcrowd-beta'})
        legacy = call(self.c, 'GET', B + 'engagements?project=a1')[1]['results']
        self.assertEqual([r['project'] for r in legacy], ['a1'])

    def test_importing_scope_adds_the_targets_to_the_engagements_own_project(self):
        _, e = self.create()
        call(self.c, 'PATCH', f'{B}engagements/{e["id"]}', {'project': e['project'], 'acknowledge': True})
        with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async'), mock.patch('agentapi.services._start_discoveries'):
            status, out = call(self.c, 'POST', f'{B}engagements/{e["id"]}/import', {'project': e['project'], 'dry_run': False, 'values': ['www.acme.test']})
        self.assertEqual((status, out['created']), (200, 1))
        self.assertTrue(Domain.objects.filter(project__slug=e['project'], name='www.acme.test').exists())
        self.assertFalse(Domain.objects.filter(project=self.pa, name='www.acme.test').exists())

    def test_a_long_handle_still_makes_a_valid_unique_slug(self):
        long_one = BountyProgram.objects.create(platform='hackerone', handle='a' * 150 + '-one', name='Long One')
        long_two = BountyProgram.objects.create(platform='hackerone', handle='a' * 150 + '-two', name='Long Two')
        _, one = self.create(program=long_one)
        _, two = self.create(program=long_two)
        self.assertLessEqual(len(one['project']), 50)
        self.assertNotEqual(one['project'], two['project'])

    def test_a_clashing_slug_held_by_a_non_bounty_project_is_stepped_around(self):
        Project.objects.create(name='Squatter', slug='bb-hackerone-acme', insert_date=timezone.now(), org=self.org_a)
        _, e = self.create()
        self.assertEqual(e['project'], 'bb-hackerone-acme-2')
        self.assertEqual(Project.objects.get(slug='bb-hackerone-acme-2').org.slug, 'bug-bounty')


class ReportBase(BountyBase):
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.dom = Domain.objects.create(name='acme.test', project=self.pa, insert_date=now)
        self.sub = Subdomain.objects.create(name='www.acme.test', target_domain=self.dom)
        self.vuln = Vulnerability.objects.create(
            name='Exposed admin panel', severity=3, http_url='https://www.acme.test/admin', target_domain=self.dom, subdomain=self.sub, description='Reachable.',
            curl_command="curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwx' https://www.acme.test/admin", template_id='admin-panel')
        self.eng = legacy_engagement(self.pa, self.acme, self.granted)
        call(self.c, 'PATCH', f'{B}engagements/{self.eng["id"]}', {'project': 'a1', 'acknowledge': True})

    def draft(self, client=None, **extra):
        status, r = call(client or self.c, 'POST', B + 'reports', {'project': 'a1', 'engagement_id': self.eng['id'], 'vulnerability_id': self.vuln.pk, **extra})
        return status, r

    def complete(self, rid):
        body = {'project': 'a1', 'title': 'Exposed admin panel on www.acme.test lets anyone reach the staff console',
                'steps': '1. Open https://www.acme.test/admin\n2. Observe the sign-in page without any VPN.',
                'impact': 'Anyone on the internet can reach the staff console and attempt the default credentials against every staff account.',
                'severity': 'high', 'cvss_score': 7.5, 'asset': 'www.acme.test', 'checklist': {k: True for k, _ in bounty_report.CHECKLIST}}
        return call(self.c, 'PATCH', f'{B}reports/{rid}', body)


class ReportTests(ReportBase):
    def test_draft_from_a_finding_masks_secrets_and_blocks_until_finished(self):
        status, r = self.draft()
        self.assertEqual(status, 201)
        self.assertNotIn('abcdefghijklmnopqrstuvwx', json.dumps(r))
        self.assertEqual((r['severity'], r['asset'], r['status'], r['impact']), ('high', 'www.acme.test', 'draft', ''))
        self.assertFalse(r['can_submit'])
        blocks = {c['code'] for c in r['checks'] if c['level'] == 'block'}
        self.assertTrue({'impact_missing', 'steps_todo', 'checklist'} <= blocks)
        self.assertEqual(r['scope']['state'], 'in_scope')
        self.assertEqual(r['events'][0]['kind'], 'created')

    def test_a_second_draft_for_the_same_finding_and_program_is_refused(self):
        self.draft()
        self.assertEqual(self.draft()[0], 409)

    def test_findings_of_another_project_are_not_reachable(self):
        other = Domain.objects.create(name='b.test', project=self.pb, insert_date=timezone.now())
        v = Vulnerability.objects.create(name='x', severity=3, http_url='https://b.test', target_domain=other)
        self.assertEqual(call(self.c, 'POST', B + 'reports', {'project': 'a1', 'vulnerability_id': v.pk})[0], 404)
        self.assertEqual(call(self.c, 'POST', B + 'reports', {'project': 'b1', 'vulnerability_id': v.pk})[0], 404)
        _, f = call(self.c, 'GET', B + 'findings?project=a1')
        self.assertEqual([x['name'] for x in f['results']], ['Exposed admin panel'])

    def test_reports_are_isolated_between_projects_and_users(self):
        _, r = self.draft()
        rid = r['id']
        self.assertEqual(call(client_for(self.granted_b), 'GET', f'{B}reports/{rid}?project=a1')[0], 404)
        self.assertEqual(call(client_for(self.granted_b), 'GET', f'{B}reports/{rid}?project=b1')[0], 404)
        self.assertEqual(call(self.c, 'GET', f'{B}reports/{rid}?project=a2')[0], 404)  # right user, wrong project
        self.assertEqual(call(client_for(self.granted_b), 'PATCH', f'{B}reports/{rid}', {'project': 'b1', 'title': 'x'})[0], 404)
        self.assertEqual(call(self.c, 'GET', f'{B}reports/{rid}')[0], 400)

    def test_edit_validates_and_records_history(self):
        _, r = self.draft()
        url = f'{B}reports/{r["id"]}'
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'severity': 'urgent'})[0], 400)
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'vrt': 'nope'})[0], 400)
        status, d = call(self.c, 'PATCH', url, {'project': 'a1', 'title': 'New title for the report here'})
        self.assertEqual((status, d['title']), (200, 'New title for the report here'))
        self.assertEqual(d['events'][-1]['kind'], 'edited')

    def test_ready_needs_no_blockers_and_submit_needs_the_whole_chain(self):
        _, r = self.draft()
        url = f'{B}reports/{r["id"]}'
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'ready'})[0], 409)
        status, d = self.complete(r['id'])
        self.assertEqual(status, 200)
        self.assertEqual({c['code'] for c in d['checks'] if c['level'] == 'block'}, set())
        self.assertTrue(d['can_submit'])
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'ready'})[1]['status'], 'ready')

    def test_the_text_of_a_submitted_report_is_final(self):
        _, r = self.draft()
        self.complete(r['id'])
        call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1', 'platform_url': 'https://hackerone.com/reports/1'})
        status, d = call(self.c, 'PATCH', f'{B}reports/{r["id"]}', {'project': 'a1', 'title': 'changed after the fact'})
        self.assertEqual(status, 409)
        self.assertEqual(call(self.c, 'POST', f'{B}reports/{r["id"]}/redact', {'project': 'a1'})[0], 409)
        self.assertEqual(call(self.c, 'DELETE', f'{B}reports/{r["id"]}?project=a1')[0], 409)

    def test_status_moves_follow_the_table_and_bounty_is_recorded(self):
        _, r = self.draft()
        self.complete(r['id'])
        call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1'})
        url = f'{B}reports/{r["id"]}'
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'draft'})[0], 409)
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'triaged', 'note': 'confirmed by analyst'})[0], 200)
        status, d = call(self.c, 'PATCH', url, {'project': 'a1', 'status': 'resolved', 'bounty_amount': '500', 'bounty_currency': 'usd'})
        self.assertEqual((status, d['status'], d['bounty_amount'], d['bounty_currency']), (200, 'resolved', '500.00', 'USD'))
        self.assertEqual(call(self.c, 'PATCH', url, {'project': 'a1', 'bounty_amount': 'lots'})[0], 400)
        _, st = call(self.c, 'GET', B + 'stats?project=a1')
        self.assertEqual((st['reports']['resolved'], st['paid'][0]['total']), (1, '500.00'))

    def test_redact_masks_what_the_person_pasted(self):
        _, r = self.draft()
        url = f'{B}reports/{r["id"]}'
        call(self.c, 'PATCH', url, {'project': 'a1', 'steps': '1. use AKIAABCDEFGHIJKLMNOP and password=hunter2hunter2'})
        status, out = call(self.c, 'POST', url + '/redact', {'project': 'a1'})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(out['masked'], 2)
        self.assertNotIn('hunter2hunter2', out['report']['steps'])

    def test_export_formats(self):
        _, r = self.draft()
        self.complete(r['id'])
        _, md = call(self.c, 'GET', f'{B}reports/{r["id"]}/export?project=a1&format=md')
        self.assertIn('## Steps to reproduce', md['content'])
        _, h1 = call(self.c, 'GET', f'{B}reports/{r["id"]}/export?project=a1&format=hackerone')
        self.assertEqual(h1['fields'][0]['name'], 'Title')
        self.assertEqual(call(self.c, 'GET', f'{B}reports/{r["id"]}/export?project=a1&format=pdf')[0], 400)

    def test_blank_draft_and_delete(self):
        status, r = call(self.c, 'POST', B + 'reports', {'project': 'a1', 'title': 'by hand'})
        self.assertEqual((status, r['program']), (201, ''))
        self.assertEqual(call(self.c, 'DELETE', f'{B}reports/{r["id"]}?project=a1')[0], 200)

    def test_taxonomy_search(self):
        _, t = call(self.c, 'GET', B + 'taxonomy?q=sql')
        self.assertTrue(any('SQL' in x['label'] for x in t['results']))
        self.assertLessEqual(len(t['results']), 40)

    def test_playbook_is_served(self):
        _, pb = call(self.c, 'GET', B + 'playbook')
        self.assertTrue(pb['sections'] and pb['sources'])


class SubmitTests(ReportBase):
    TOKEN = 'tok-0123456789-secret'

    def ready(self, rid=None):
        if rid is None:
            _, r = self.draft()
            rid = r['id']
        self.complete(rid)
        return rid

    def creds(self):
        return call(self.c, 'PUT', B + 'credentials/hackerone', {'username': 'granted-h1', 'token': self.TOKEN})

    def submit(self, rid, **body):
        return call(self.c, 'POST', f'{B}reports/{rid}/submit', {'project': 'a1', 'confirm': 'acme', **body})

    def test_credentials_are_per_user_encrypted_and_never_returned(self):
        with mock.patch('cveFeed.bounty_submit.verify_hackerone', return_value={'verified': True, 'reason': ''}):
            status, out = self.creds()
        self.assertEqual((status, out['verified']), (200, True))
        self.assertNotIn(self.TOKEN, json.dumps(out))
        _, st = call(self.c, 'GET', B + 'status')
        self.assertEqual(st['credentials'], {'hackerone': 'granted-h1'})
        self.assertNotIn(self.TOKEN, json.dumps(st))
        self.assertEqual(call(client_for(self.granted_b), 'GET', B + 'status')[1]['credentials'], {})
        self.assertEqual(BountyCredential.objects.get(user=self.granted).token, self.TOKEN)
        self.assertEqual(call(self.c, 'PUT', B + 'credentials/bugcrowd', {'username': 'x', 'token': 'y'})[0], 404)
        self.assertEqual(call(self.c, 'PUT', B + 'credentials/hackerone', {'username': '', 'token': ''})[0], 400)
        self.assertEqual(call(self.c, 'DELETE', B + 'credentials/hackerone')[0], 200)
        self.assertFalse(BountyCredential.objects.exists())

    def test_the_username_is_cleaned_an_email_is_refused_and_a_refusal_says_why(self):
        with mock.patch('cveFeed.bounty_submit.verify_hackerone', return_value={'verified': True, 'reason': ''}) as verify:
            status, out = call(self.c, 'PUT', B + 'credentials/hackerone', {'username': ' https://hackerone.com/@granted-h1/ ', 'token': self.TOKEN})
        self.assertEqual((status, out['username']), (200, 'granted-h1'))
        self.assertEqual(verify.call_args.args, ('granted-h1', self.TOKEN))
        status, out = call(self.c, 'PUT', B + 'credentials/hackerone', {'username': 'me@acme.example', 'token': self.TOKEN})
        self.assertEqual(status, 400)
        self.assertIn('email address', out['error'])
        with mock.patch('cveFeed.bounty_submit.verify_hackerone', return_value={'verified': False, 'reason': 'HackerOne refused this username'}):
            status, out = call(self.c, 'POST', B + 'credentials/hackerone/test', {})
        self.assertEqual((status, out['verified'], out['reason']), (200, False, 'HackerOne refused this username'))

    def test_submit_sends_under_the_callers_account_and_records_it(self):
        rid = self.ready()
        with mock.patch('cveFeed.bounty_submit.verify_hackerone', return_value={'verified': True, 'reason': ''}):
            self.creds()
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone', return_value={'id': '777', 'url': 'https://hackerone.com/reports/777'}) as send:
            status, d = self.submit(rid)
        self.assertEqual(status, 200)
        self.assertEqual((d['status'], d['platform_report_id'], d['platform_url']), ('submitted', '777', 'https://hackerone.com/reports/777'))
        payload, username, token = send.call_args.args
        self.assertEqual((username, token, payload['data']['attributes']['team_handle']), ('granted-h1', self.TOKEN, 'acme'))
        self.assertNotIn(self.TOKEN, json.dumps(d))
        self.assertTrue(AuditLog.objects.filter(action='bounty.submit', actor_name='granted').exists())
        self.assertEqual(BountyReport.objects.get(pk=rid).submitted_by, self.granted)

    def test_one_users_credentials_are_never_used_for_another(self):
        rid = self.ready()
        BountyCredential.objects.create(user=self.granted_b, platform='hackerone', username='b-user', token='b-token')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone') as send:
            status, d = self.submit(rid)
        self.assertEqual(status, 409)
        send.assert_not_called()

    def test_the_handle_must_be_typed_back(self):
        rid = self.ready()
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone') as send:
            self.assertEqual(self.submit(rid, confirm='')[0], 400)
            self.assertEqual(self.submit(rid, confirm='ACME')[0], 400)
        send.assert_not_called()

    def test_blockers_stop_it_and_nothing_is_sent(self):
        _, r = self.draft()  # impact missing, TODO in steps, checklist empty
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone') as send:
            status, d = self.submit(r['id'])
        self.assertEqual(status, 409)
        self.assertIn('blocking', d['error'])
        send.assert_not_called()

    def test_an_out_of_scope_asset_stops_it(self):
        rid = self.ready()
        call(self.c, 'PATCH', f'{B}reports/{rid}', {'project': 'a1', 'asset': 'status.acme.test'})
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone') as send:
            self.assertEqual(self.submit(rid)[0], 409)
        send.assert_not_called()

    def test_a_second_submit_is_refused(self):
        rid = self.ready()
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone', return_value={'id': '1', 'url': 'https://hackerone.com/reports/1'}) as send:
            self.assertEqual(self.submit(rid)[0], 200)
            self.assertEqual(self.submit(rid)[0], 409)
        self.assertEqual(send.call_count, 1)

    def test_a_timeout_is_recorded_and_the_retry_needs_a_confirmation(self):
        rid = self.ready()
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        boom = bounty_submit.SubmitError('did not answer', uncertain=True)
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone', side_effect=boom):
            self.assertEqual(self.submit(rid)[0], 502)
        self.assertTrue(BountyReport.objects.get(pk=rid).events.filter(kind='uncertain').exists())
        self.assertEqual(BountyReport.objects.get(pk=rid).status, 'draft')
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone') as send:
            self.assertEqual(self.submit(rid)[0], 409)
            send.assert_not_called()
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone', return_value={'id': '9', 'url': 'https://hackerone.com/reports/9'}):
            self.assertEqual(self.submit(rid, checked_platform=True)[0], 200)

    def test_a_refusal_surfaces_the_hint_and_leaves_the_draft(self):
        rid = self.ready()
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='secret-token-xyz')
        err = bounty_submit.SubmitError('HackerOne refused the API credentials; check them in My accounts. [HTTP 401]', status=401)
        with mock.patch('cveFeed.bounty_api.bounty_submit.submit_hackerone', side_effect=err):
            status, d = self.submit(rid)
        self.assertEqual(status, 400)
        self.assertNotIn('secret-token-xyz', json.dumps(d))
        self.assertEqual(BountyReport.objects.get(pk=rid).status, 'draft')

    def test_other_platforms_use_mark_submitted(self):
        bc = BountyProgram.objects.get(platform='bugcrowd')
        e = legacy_engagement(self.pa, bc, self.granted)
        status, r = call(self.c, 'POST', B + 'reports', {'project': 'a1', 'engagement_id': e['id'], 'vulnerability_id': self.vuln.pk})
        self.assertEqual(status, 201)
        BountyCredential.objects.create(user=self.granted, platform='hackerone', username='u', token='t')
        self.assertEqual(call(self.c, 'POST', f'{B}reports/{r["id"]}/submit', {'project': 'a1', 'confirm': 'beta'})[0], 409)
        self.assertEqual(call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1', 'platform_url': 'javascript:alert(1)'})[0], 400)
        self.assertEqual(call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1', 'platform_report_id': 'a b!'})[0], 400)
        status, d = call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1', 'platform_url': 'https://bugcrowd.com/submissions/abc', 'platform_report_id': 'abc-1'})
        self.assertEqual((status, d['status']), (200, 'submitted'))
        self.assertEqual(call(self.c, 'POST', f'{B}reports/{r["id"]}/mark-submitted', {'project': 'a1'})[0], 409)


class GuardTests(ReportBase):
    """Reports are about attack strings. The input guard must let that text through on the report endpoints, and only there."""
    PAYLOAD = "1. open <script>alert(1)</script>\n2. GET /a?id=1' OR 1=1--\n3. GET /../../etc/passwd; cat /etc/passwd | sh `id` $(id)"

    def strikes(self):
        from dashboard.models import AbuseStrike
        return AbuseStrike.objects.filter(user=self.granted).count()

    def test_report_text_with_attack_strings_saves_and_costs_nothing(self):
        _, r = self.draft()
        body = {'project': 'a1', 'title': self.PAYLOAD, 'summary': self.PAYLOAD, 'steps': self.PAYLOAD, 'impact': self.PAYLOAD, 'remediation': self.PAYLOAD,
                'references': self.PAYLOAD, 'location_url': "https://www.acme.test/a?id=1' OR 1=1--", 'cwe': 'CWE-22'}
        status, d = call(self.c, 'PATCH', f'{B}reports/{r["id"]}', body)
        self.assertEqual(status, 200)
        self.assertIn('<script>', d['steps'])
        self.assertEqual(self.strikes(), 0)
        self.assertTrue(User.objects.get(pk=self.granted.pk).is_active)

    def test_a_blank_report_and_notes_take_it_too(self):
        status, r = call(self.c, 'POST', B + 'reports', {'project': 'a1', 'title': self.PAYLOAD, 'steps': self.PAYLOAD})
        self.assertEqual(status, 201)
        status, _ = call(self.c, 'PATCH', f'{B}engagements/{self.eng["id"]}', {'project': 'a1', 'notes': self.PAYLOAD})
        self.assertEqual(status, 200)
        self.assertEqual(self.strikes(), 0)

    def test_the_same_text_in_a_strict_field_is_still_refused_and_counted(self):
        status, _ = call(self.c, 'POST', B + 'scope-check', {'program_id': self.acme.pk, 'host': 'x.acme.test; cat /etc/passwd'})
        self.assertIn(status, (400, 403))  # one command-injection hit reaches the threshold: the guard disables the account
        self.assertGreaterEqual(self.strikes(), 1)

    def test_other_endpoints_keep_the_full_rules(self):
        from reNgine import input_guard
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.patch(f'{B}reports/1', json.dumps({'steps': self.PAYLOAD, 'project': 'a1'}), content_type='application/json')
        self.assertEqual([k for k, _ in input_guard._request_pairs(req)], ['project'])
        req = rf.patch('/cve/api/admin/users/1', json.dumps({'steps': self.PAYLOAD}), content_type='application/json')
        self.assertEqual([k for k, _ in input_guard._request_pairs(req)], ['steps'])
        req = rf.post(f'{B}programs', json.dumps({'title': self.PAYLOAD}), content_type='application/json')
        self.assertEqual([k for k, _ in input_guard._request_pairs(req)], ['title'])
        self.assertTrue(input_guard.inspect([('steps', self.PAYLOAD)]))  # the signatures themselves are unchanged
