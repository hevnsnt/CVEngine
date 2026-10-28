"""Internal ranges: a project declares a private network, its addresses may become targets, and this server still never scans them."""
import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError
from cveFeed.models import InternalRange
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from startScan.models import ScanHistory
from targetApp import target_types as tt
from targetApp.models import Domain
from tests.test_agentapi import call


class CleanCidrTests(SimpleTestCase):
    def test_accepts_private_networks(self):
        for value, expected in (('10.20.0.0/24', '10.20.0.0/24'), (' 192.168.0.0/16 ', '192.168.0.0/16'), ('172.16.4.0/22', '172.16.4.0/22'),
                                ('fd12:3456::/112', 'fd12:3456::/112'), ('100.64.8.0/24', '100.64.8.0/24')):
            self.assertEqual(tt.clean_internal_cidr(value), expected)

    def test_refuses_public_oversized_host_bit_and_blocked_ranges(self):
        for value in ('8.8.8.0/24', '10.0.0.0/8', '10.20.0.5/24', 'example.com', '', '127.0.0.0/8', '169.254.0.0/16',
                      '100.64.0.0/10', '100.100.100.0/24', '172.16.0.0/11', 'fe80::/64', '2001:db8::/64'):
            with self.assertRaises(ValueError, msg=value):
                tt.clean_internal_cidr(value)

    def test_the_metadata_address_inside_cgnat_cannot_be_declared(self):
        with self.assertRaises(ValueError):
            tt.clean_internal_cidr('100.100.100.200/32')


class InRangeTests(SimpleTestCase):
    nets = [tt.ipaddress.ip_network('10.20.0.0/24')]

    def test_inside_and_outside(self):
        self.assertTrue(tt.in_internal_range('10.20.0.5', self.nets))
        self.assertFalse(tt.in_internal_range('10.21.0.5', self.nets))
        self.assertFalse(tt.in_internal_range('not an ip', self.nets))
        self.assertFalse(tt.in_internal_range('10.20.0.5', []))

    def test_wrapped_forms_are_not_the_address(self):
        for wrapped in ('::ffff:10.20.0.5', '64:ff9b::a14:5', '2002:0a14:0005::'):
            self.assertFalse(tt.in_internal_range(wrapped, self.nets), wrapped)


class World(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org1, cls.org2 = Org.objects.create(name='One', slug='ir-one'), Org.objects.create(name='Two', slug='ir-two')
        cls.pa = Project.objects.create(name='A', slug='ir-a', insert_date=now, org=cls.org1)
        cls.pb = Project.objects.create(name='B', slug='ir-b', insert_date=now, org=cls.org2)
        mk = lambda n: User.objects.create_user(n, password='x')
        cls.admin, cls.member, cls.other, cls.root = mk('ir_admin'), mk('ir_member'), mk('ir_other'), mk('ir_root')
        cls.root.is_superuser = True
        cls.root.save()
        OrgMembership.objects.create(user=cls.admin, org=cls.org1, role='admin')
        ProjectMembership.objects.create(user=cls.member, project=cls.pa, role='user')
        OrgMembership.objects.create(user=cls.other, org=cls.org2, role='admin')
        cls.t = {n: create_token(u, n)[1] for n, u in (('admin', cls.admin), ('member', cls.member), ('other', cls.other), ('root', cls.root))}

    def declare(self, cidr='10.20.0.0/24', project=None):
        return InternalRange.objects.create(project=project or self.pa, cidr=cidr)


class RestTests(World):
    url = '/api/v1/projects/ir-a/internal-ranges'

    def test_admin_declares_lists_and_removes_a_range(self):
        status, row = call(self.t['admin'], 'POST', self.url, {'cidr': '10.20.0.0/24', 'description': 'office'})
        self.assertEqual(status, 201)
        self.assertEqual((row['cidr'], row['description'], row['created_by']), ('10.20.0.0/24', 'office', 'ir_admin'))
        self.assertEqual([r['cidr'] for r in call(self.t['admin'], 'GET', self.url)[1]['results']], ['10.20.0.0/24'])
        self.assertTrue(AuditLog.objects.filter(action='internal_range.add', actor=self.admin).exists())
        status, out = call(self.t['admin'], 'DELETE', f'{self.url}/{row["id"]}')
        self.assertEqual(status, 200)
        self.assertFalse(InternalRange.objects.exists())
        self.assertTrue(AuditLog.objects.filter(action='internal_range.delete').exists())

    def test_only_administrators_may_read_or_change_them(self):
        self.declare()
        self.assertEqual(call(self.t['member'], 'GET', self.url)[0], 403)
        self.assertEqual(call(self.t['member'], 'POST', self.url, {'cidr': '10.30.0.0/24'})[0], 403)
        self.assertEqual(call(self.t['other'], 'GET', self.url)[0], 404)  # another tenant cannot tell the project exists
        self.assertEqual(call(self.t['root'], 'GET', self.url)[0], 200)

    def test_bad_and_duplicate_input(self):
        self.assertEqual(call(self.t['admin'], 'POST', self.url, {'cidr': '8.8.8.0/24'})[0], 400)
        self.assertEqual(call(self.t['admin'], 'POST', self.url, {'cidr': '10.20.0.0/24', 'extra': 1})[0], 400)
        self.assertEqual(call(self.t['admin'], 'POST', self.url, {'cidr': '10.20.0.0/24', 'description': 'x' * 201})[0], 400)
        self.assertEqual(call(self.t['admin'], 'POST', self.url, {'cidr': '10.20.0.0/24'})[0], 201)
        self.assertEqual(call(self.t['admin'], 'POST', self.url, {'cidr': '10.20.0.0/24'})[0], 409)

    def test_a_range_of_another_project_cannot_be_deleted_through_this_one(self):
        row = self.declare('10.50.0.0/24', project=self.pb)
        self.assertEqual(call(self.t['admin'], 'DELETE', f'{self.url}/{row.pk}')[0], 404)
        self.assertTrue(InternalRange.objects.filter(pk=row.pk).exists())

    def test_all_projects_view_is_refused(self):
        self.assertEqual(call(self.t['root'], 'POST', '/api/v1/projects/_all/internal-ranges', {'cidr': '10.20.0.0/24'})[0], 400)


class TargetTests(World):
    def test_expand_target_admits_only_declared_addresses(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}):
            with self.assertRaises(ApiError):
                svc._expand_target('10.20.0.5')  # not declared
            with self.assertRaises(ApiError):
                svc._expand_target('10.20.0.5', self.pa.id)
            self.declare()
            self.assertEqual(svc._expand_target('10.20.0.5', self.pa.id), ('ip', ['10.20.0.5']))
            self.assertEqual(svc._expand_target('10.20.0.0/30', self.pa.id)[1], ['10.20.0.1', '10.20.0.2'])
            with self.assertRaises(ApiError):
                svc._expand_target('10.20.1.5', self.pa.id)  # outside the declared range
            with self.assertRaises(ApiError):
                svc._expand_target('10.20.0.5', self.pb.id)  # declared by another project
            with self.assertRaises(ApiError):
                svc._expand_target('10.20.0.0/23', self.pa.id)  # a CIDR reaching outside it
            with self.assertRaises(ApiError):
                svc._expand_target('127.0.0.1', self.pa.id)
            self.assertEqual(svc._expand_target('203.0.113.9', self.pa.id), ('ip', ['203.0.113.9']))  # public: as before

    def test_declaring_a_range_does_not_make_it_scannable_from_this_server(self):
        self.declare()
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}):
            self.assertFalse(tt.is_scannable_ip('10.20.0.5'))
            self.assertFalse(tt.is_scannable_ip('10.20.0.5', project=self.pa.id))
            self.assertEqual(tt.scannable_hosts(['10.20.0.5', '10.20.0.6:8443'], project=self.pa.id), [])

    def test_adding_internal_targets_never_starts_local_discovery(self):
        self.declare()
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}), \
                mock.patch('cveFeed.discovery.start_discoveries') as start, mock.patch('agentapi.services._start_discoveries') as start_bulk:
            status, out = call(self.t['admin'], 'POST', '/api/v1/projects/ir-a/targets', {'value': '10.20.0.0/30', 'discover': True})
            self.assertEqual(status, 201, out)
            self.assertEqual(sorted(c['name'] if isinstance(c, dict) else c for c in out['created']).__len__(), 2)
            status, out = call(self.t['admin'], 'POST', '/api/v1/projects/ir-a/targets/bulk', {'targets': '10.20.0.9', 'discover': True})
            self.assertEqual(status, 201, out)
            self.assertEqual(out['created'], 1)
            start.assert_not_called()
            start_bulk.assert_not_called()
        self.assertEqual(set(Domain.objects.filter(project=self.pa).values_list('name', flat=True)), {'10.20.0.1', '10.20.0.2', '10.20.0.9'})
        self.assertFalse(ScanHistory.objects.exists())

    def test_public_targets_in_the_same_request_are_still_discovered(self):
        self.declare()
        with mock.patch('agentapi.services._start_discoveries', return_value=[]) as start_bulk:
            call(self.t['admin'], 'POST', '/api/v1/projects/ir-a/targets/bulk', {'targets': '10.20.0.9\n203.0.113.7', 'discover': True})
        (created, *_), _ = start_bulk.call_args
        self.assertEqual([d.name for d in created], ['203.0.113.7'])


class NeverLocalTests(World):
    """A target inside a declared internal range is never queued for local discovery, by anyone."""

    def setUp(self):
        self.declare()
        self.inside = Domain.objects.create(name='10.20.0.7', project=self.pa, insert_date=timezone.now())
        self.public = Domain.objects.create(name='203.0.113.7', project=self.pa, insert_date=timezone.now())

    def test_sentinel_only_target_predicate(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}):
            self.assertTrue(tt.sentinel_only_target('10.20.0.7', self.pa.id))
            self.assertFalse(tt.sentinel_only_target('10.20.0.7', self.pb.id))
            self.assertFalse(tt.sentinel_only_target('203.0.113.7', self.pa.id))
            self.assertFalse(tt.sentinel_only_target('example.com', self.pa.id))
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': '1'}):
            self.assertFalse(tt.sentinel_only_target('10.20.0.7', self.pa.id))  # the operator allowed private targets: not Sentinel-only

    def test_the_conductor_never_picks_one(self):
        from cveFeed import conductor
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}):
            self.assertEqual(conductor.next_targets(5), [self.public.id])
            Domain.objects.filter(pk=self.public.pk).delete()
            self.assertEqual(conductor.next_targets(5), [])

    def test_starting_a_scan_by_hand_is_refused(self):
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}), mock.patch('cveFeed.discovery.start_discovery') as start:
            status, out = call(self.t['admin'], 'POST', f'/api/v1/projects/ir-a/targets/{self.inside.pk}/discover', {})
            self.assertEqual(status, 409, out)
            status, out = call(self.t['admin'], 'POST', '/api/v1/projects/ir-a/scans', {'target_id': self.inside.pk})
            self.assertEqual(status, 409, out)
            start.assert_not_called()

    def test_a_queued_discovery_that_slips_through_fails_with_a_clear_reason(self):
        from cveFeed import discovery
        from scanEngine.models import EngineType
        engine = EngineType.objects.create(engine_name='e-ir', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=self.inside, scan_type=engine, start_scan_date=timezone.now(), scan_status=discovery.QUEUED,
                                          results_dir='/tmp')
        with mock.patch.dict(os.environ, {'CVENGINE_ALLOW_PRIVATE_TARGETS': ''}), mock.patch('cveFeed.discovery.bbot_lib') as bbot:
            discovery.run_pipeline(scan.id, 'standard')
            bbot.assert_not_called()
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, discovery.FAILED)
        self.assertIn('only a Sentinel', scan.error_message)


class InternalClaimTests(World):
    """Work on an address of a declared internal range is claimable only by a Sentinel that says it is inside a private network."""

    def setUp(self):
        from agentapi.models import Agent, SentinelTask
        from tests.test_sentinels import reset_rates
        self.declare()
        self.Agent, self.SentinelTask = Agent, SentinelTask

        def sentinel(name, capabilities):
            token = create_token(self.root, f'ir-{name}')[1]
            reset_rates({'t': token})
            status, out = call(token, 'PUT', '/api/v1/sentinel', {'name': name, 'scope': {'projects': ['ir-a']}, 'capabilities': capabilities})
            self.assertIn(status, (200, 201), out)
            Agent.objects.filter(pk=out['id']).update(status='active')
            return token, out['id']
        self.outside = sentinel('outside', ['nmap'])
        self.inside = sentinel('inside', ['nmap', 'network:internal'])

    def queue(self, ips):
        return self.SentinelTask.objects.create(project=self.pa, kind='nmap', host='h', target={'addresses': ips}, ips=ips, status='queued')

    def claim(self, who):
        status, out = call(who[0], 'POST', '/api/v1/sentinel/tasks/next', {})
        self.assertEqual(status, 200, out)
        return out['task']

    def test_an_outside_sentinel_never_gets_internal_work(self):
        task = self.queue(['10.20.0.5'])
        self.assertIsNone(self.claim(self.outside))
        self.assertEqual(self.SentinelTask.objects.get(pk=task.pk).status, 'queued')
        self.assertEqual(self.claim(self.inside)['id'], task.pk)

    def test_an_outside_sentinel_still_gets_ordinary_work_and_skips_past_internal(self):
        internal, public = self.queue(['10.20.0.5']), self.queue(['203.0.113.5'])
        self.assertEqual(self.claim(self.outside)['id'], public.pk)
        self.assertEqual(self.SentinelTask.objects.get(pk=internal.pk).status, 'queued')

    def test_a_task_held_by_an_outside_sentinel_is_taken_back(self):
        from agentapi import sentinel_broker as sb
        task = self.queue(['10.20.0.5'])
        agent = self.Agent.objects.get(pk=self.outside[1])
        self.SentinelTask.objects.filter(pk=task.pk).update(status='claimed', agent=agent)
        task.refresh_from_db()
        self.assertEqual(sb.effective(agent).refusal(task), ('capability', sb.INTERNAL_CAPABILITY))
        self.assertIsNone(sb.effective(self.Agent.objects.get(pk=self.inside[1])).refusal(task))


class PageTests(World):
    def test_the_project_sentinels_page_carries_the_internal_networks_card(self):
        from django.test import Client
        client = Client()
        client.force_login(self.admin)
        page = client.get('/cve/ir-a/sentinels/')
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'Internal networks')
        self.assertContains(page, '/internal-ranges')
