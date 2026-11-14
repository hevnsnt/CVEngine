"""The do-not-scan address list (addresses we must never scan): the rule, every enforcement point, the editor, and the guard that holds each contract kind.

Addresses here are documentation ranges (198.51.100.0/24, 192.0.2.0/24, 203.0.113.0/24, 2001:db8::/32) and example.com names only."""
import json
from pathlib import Path

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from unittest import mock

from agentapi import address_guard, excluded_addresses
from agentapi import sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelTask
from cveFeed import exclusions
from cveFeed.exclusions import address_excluded, excluded_names, parse_entry
from cveFeed.models import AgentActivity, ExcludedAddress
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from reNgine.resources import AddressExcluded, ScannerUnavailable
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call

FIXTURES = Path(__file__).with_name('fixtures') / 'sentinel_targets'
IN, OUT = '198.51.100.7', '192.0.2.9'


@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})  # the once-per-host note must not outlive a test run
class World(TestCase):
    def setUp(self):
        now = timezone.now()
        self.org = Org.objects.create(name='Guard', slug='guard')
        self.other_org = Org.objects.create(name='Other', slug='other-g')
        self.project = Project.objects.create(name='G', slug='guard-p', insert_date=now, org=self.org)
        self.other = Project.objects.create(name='O', slug='other-p', insert_date=now, org=self.other_org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e-guard', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=now, scan_status=1, results_dir='/tmp')
        self.admin = User.objects.create_user('g_admin', password='x')
        self.member = User.objects.create_user('g_member', password='x')
        self.stranger = User.objects.create_user('g_stranger', password='x')
        self.root = User.objects.create_user('g_root', password='x', is_superuser=True)
        OrgMembership.objects.create(user=self.admin, org=self.org, role='admin')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        OrgMembership.objects.create(user=self.stranger, org=self.other_org, role='admin')

    def host(self, name, *addresses, project=None):
        project = project or self.project
        domain = Domain.objects.filter(project=project).first()
        sub = Subdomain.objects.create(scan_history=self.scan, target_domain=domain, name=name)
        for address in addresses:
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=address)[0])
        return sub

    def exclude(self, *entries, org=None):
        for entry in entries:
            net, why = parse_entry(entry, confirm_broad=True)
            self.assertIsNone(why, entry)
            ExcludedAddress.objects.create(org=org or self.org, cidr=str(net))

    def sentinel(self, kinds=('nmap',)):
        _, raw = create_token(self.admin, f'tok-{Agent.objects.count()}')
        status, out = call(raw, 'PUT', '/api/v1/sentinel', {'name': f'live-{Agent.objects.count()}', 'scope': {'projects': [self.project.slug]}, 'capabilities': list(kinds)})
        self.assertIn(status, (200, 201), out)
        Agent.objects.filter(pk=out['id']).update(status='active', info={'features': ['credential_filter']})  # a current client: an old one is offered no nuclei work while credential checks are off
        return Agent.objects.get(pk=out['id']), raw

class TheRule(World):
    def test_cidr_edges_and_families(self):
        self.exclude('198.51.100.0/24', '192.0.2.77', '2001:db8:abcd::/48')
        for inside in ('198.51.100.0', '198.51.100.255', '198.51.100.128', '192.0.2.77', '[2001:db8:abcd::1]:443', '198.51.100.9:8443', 'https://198.51.100.9/x'):
            self.assertTrue(address_excluded(self.project.pk, inside), inside)
        for outside in ('198.51.99.255', '198.51.101.0', '192.0.2.76', '192.0.2.78', '2001:db8:abce::1', '2001:db8:abc::1', '203.0.113.5'):
            self.assertIsNone(address_excluded(self.project.pk, outside), outside)

    def test_ipv6_compressed_and_expanded_forms_are_equal_and_stored_once(self):
        a, _ = parse_entry('2001:0db8:0000:0000:0000:0000:0000:0005')
        b, _ = parse_entry('2001:db8::5')
        self.assertEqual(str(a), str(b))
        self.assertEqual(str(a), '2001:db8::5/128')
        self.exclude('2001:0DB8:0:0:0:0:0:5')
        for form in ('2001:db8::5', '2001:0db8:0000:0000:0000:0000:0000:0005', '[2001:db8::5]:22'):
            self.assertTrue(address_excluded(self.project.pk, form), form)
        self.assertIsNone(address_excluded(self.project.pk, '2001:db8::6'))

    def test_an_ipv4_mapped_ipv6_address_is_its_ipv4_address(self):
        self.exclude('198.51.100.0/24')
        self.assertTrue(address_excluded(self.project.pk, '::ffff:198.51.100.5'))
        self.exclude('::ffff:192.0.2.9')  # stored as the IPv4 address
        self.assertTrue(address_excluded(self.project.pk, '192.0.2.9'))
        self.assertEqual(sorted(ExcludedAddress.objects.values_list('cidr', flat=True)), ['192.0.2.9/32', '198.51.100.0/24'])

    def test_entries_are_validated(self):
        self.assertIn('whole internet', parse_entry('0.0.0.0/0', confirm_broad=True)[1])
        self.assertIn('whole internet', parse_entry('::/0', confirm_broad=True)[1])
        self.assertIn('confirm', parse_entry('10.0.0.0/7')[1])
        self.assertIsNone(parse_entry('10.0.0.0/7', confirm_broad=True)[1])
        self.assertIn('confirm', parse_entry('2001::/31')[1])
        self.assertIsNone(parse_entry('2001:db8::/32')[1])
        self.assertIsNone(parse_entry('10.0.0.0/8')[1])
        self.assertEqual(str(parse_entry('10.1.2.3/24')[0]), '10.1.2.0/24')  # host bits cleared; private ranges are valid
        self.assertEqual(str(parse_entry('192.168.0.0/16')[0]), '192.168.0.0/16')
        for bad in ('', '   ', 'example.com', '999.1.1.1', '198.51.100.0/33', '1.2.3.4/abc', 'x' * 100, None, 7):
            self.assertIsNotNone(parse_entry(bad)[1], bad)

    def test_a_name_whose_stored_addresses_fall_inside_is_refused(self):
        self.host('survey.example.com', IN)
        self.host('fine.example.com', OUT)
        self.host('both.example.com', OUT, '198.51.100.200')
        self.exclude('198.51.100.0/24')
        refusal = address_excluded(self.project.pk, 'Survey.Example.com.')
        self.assertIn('resolves to 198.51.100.7', refusal)
        self.assertIn('198.51.100.0/24', refusal)
        self.assertIsNone(address_excluded(self.project.pk, 'fine.example.com'))
        self.assertTrue(address_excluded(self.project.pk, 'https://both.example.com:8443/x'))
        self.assertIsNone(address_excluded(self.project.pk, 'unknown.example.com'))  # nothing known: the lookup a task makes is judged on its answer

    def test_what_a_task_resolved_itself_counts(self):
        self.exclude('198.51.100.0/24')
        self.assertIsNone(address_excluded(self.project.pk, 'new.example.com'))
        self.assertTrue(address_excluded(self.project.pk, 'new.example.com', resolved=['198.51.100.44']))
        self.assertIsNone(address_excluded(self.project.pk, 'new.example.com', resolved=['192.0.2.44', 'not an address']))

    def test_one_organization_never_sees_anothers_list(self):
        self.exclude('198.51.100.0/24', org=self.other_org)
        self.assertIsNone(address_excluded(self.project.pk, IN))
        self.assertTrue(address_excluded(self.other.pk, IN))

    def test_the_excluded_names_set_is_address_aware_and_names_only_is_not(self):
        self.host('survey.example.com', IN)
        self.exclude('198.51.100.0/24')
        banned = excluded_names(self.project.pk)
        self.assertIn('survey.example.com', banned)  # a name test, and an SQL NOT IN through iteration
        self.assertIn(IN, banned)
        self.assertNotIn('192.0.2.9', banned)
        self.assertIn('survey.example.com', list(banned))
        self.assertNotIn('survey.example.com', excluded_names(self.project.pk, names_only=True))
        self.assertTrue(banned)
        self.assertIn('198.51.100.9', banned | frozenset({'x.example.com'}))

    def test_a_list_that_cannot_be_read_fails_closed_with_the_reason(self):
        self.exclude('198.51.100.0/24')
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db down')):
            for value in (OUT, 'www.example.com', '2001:db8::1'):
                refusal = address_excluded(self.project.pk, value)
                self.assertTrue(refusal and refusal.unreadable, value)
                self.assertIn('could not be read', refusal)
            banned = excluded_names(self.project.pk)
            self.assertTrue(banned.unreadable)
            self.assertIn('anything.example.com', banned)
            self.assertIn(OUT, banned)
            self.assertEqual(excluded_names(self.project.pk, names_only=True), frozenset())  # inventory-level questions do not read it
            with self.assertRaises(AddressExcluded) as caught:
                dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': [OUT]}, ips=[OUT])
            self.assertTrue(caught.exception.refusal.unreadable)
            self.assertIn('could not be read', str(caught.exception))
        self.assertFalse(SentinelTask.objects.exists())

    def test_a_stored_address_lookup_that_fails_also_fails_closed(self):
        self.exclude('198.51.100.0/24')
        with mock.patch('cveFeed.exclusions.stored_addresses', side_effect=RuntimeError('db')):
            self.assertTrue(address_excluded(self.project.pk, 'www.example.com').unreadable)
            self.assertIsNone(address_excluded(self.project.pk, OUT))  # a literal needs no lookup


class Dispatch(World):
    def setUp(self):
        super().setUp()
        self.host('survey.example.com', IN)
        self.exclude('198.51.100.0/24')

    def assertNoTask(self):
        self.assertFalse(SentinelTask.objects.exists())

    def test_an_address_is_refused_before_a_task_exists(self):
        for kind, target in (('nmap', {'addresses': [IN]}), ('naabu', {'addresses': [IN]}), ('nmap_udp', {'address': IN}), ('nmap_full', {'addresses': [IN]}),
                             ('ssh_probe', {'targets': [{'address': IN, 'port': 22}]}), ('path_probe', {'targets': [{'ip': IN, 'port': 80}]}),
                             ('db_probe', {'address': IN, 'port': 6379, 'db': 'redis'})):
            with self.assertRaises(AddressExcluded, msg=kind):
                dispatch.dispatch_or_none(self.project, kind, target, ips=[IN], scan=self.scan)
        self.assertNoTask()

    def test_a_name_that_resolves_into_the_range_is_refused_for_name_targets(self):
        for kind, target in (('nuclei_light', {'targets': ['https://survey.example.com']}), ('http_probe', {'probes': [{'host': 'survey.example.com', 'port': 443}]}),
                             ('web_screenshot', {'host': 'survey.example.com', 'port': 443}), ('page_read', {'reads': [{'host': 'survey.example.com', 'url': 'https://survey.example.com/'}]})):
            with self.assertRaises(AddressExcluded, msg=kind):
                dispatch.dispatch_or_none(self.project, kind, target, host='survey.example.com', scan=self.scan)
        self.assertNoTask()

    def test_internal_work_is_refused_quietly(self):
        self.assertIsNone(dispatch.dispatch_or_none(self.project, 'discover', {'cidr': '198.51.100.0/25'}, internal=True))
        self.assertNoTask()

    def test_a_sweep_of_a_range_that_overlaps_the_list_is_refused(self):
        with self.assertRaises(AddressExcluded):
            dispatch.dispatch_or_none(self.project, 'discover', {'cidr': '198.51.0.0/16'}, internal=True) or (_ for _ in ()).throw(AddressExcluded('discover', 'x'))
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'discover', {'cidr': '203.0.113.0/24'}))

    def test_a_name_with_no_known_address_waits_for_a_lookup_unless_the_work_only_asks_dns_or_finds_names(self):
        for kind, target in (('nuclei_light', {'targets': ['https://new.example.com']}), ('hygiene_check', {'tls': [{'host': 'new.example.com', 'port': 443}], 'mail': []})):
            with self.assertRaises(AddressExcluded, msg=kind) as caught:
                dispatch.dispatch_or_none(self.project, kind, target, host='new.example.com')
            self.assertIn('no known address yet', str(caught.exception))
        self.assertFalse(SentinelTask.objects.exists())
        # work that only asks DNS, and the runs that find where names point, are not held back by it
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'hygiene_check', {'mail': [{'name': 'new.example.com'}]}))
        with self.assertRaises(AddressExcluded):  # the same name as a TLS endpoint is a connection, whatever else the task asks about it
            dispatch.dispatch_or_none(self.project, 'hygiene_check', {'tls': [{'host': 'new.example.com', 'port': 443}], 'mail': [{'name': 'new.example.com'}]}, host='new.example.com')
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'dns_resolve', {'names': ['new.example.com']}))
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'bbot_discovery', {'domain': 'new.example.com', 'scope': {'in_scope_domains': ['new.example.com']}}))
        self.host('known.example.com', OUT)  # a name that resolved somewhere else is fine
        self.assertIsNone(address_guard.dispatch_refusal(self.project, 'nuclei_light', {'targets': ['https://known.example.com']}))

    def test_a_queued_task_for_a_name_with_no_known_address_is_left_queued_not_cancelled(self):
        _, raw = self.sentinel(['nuclei_light'])
        ExcludedAddress.objects.all().delete()
        queued = SentinelTask.objects.create(project=self.project, kind='nuclei_light', target={'targets': ['https://later.example.com']})
        self.exclude('198.51.100.0/24')
        status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNone(out['task'])
        queued.refresh_from_db()
        self.assertEqual(queued.status, 'queued')
        self.host('later.example.com', OUT)  # a lookup has told where it points
        status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], queued.pk)

    def test_the_model_is_the_backstop_for_any_other_way_of_making_a_task(self):
        with self.assertRaises(AddressExcluded):
            SentinelTask.objects.create(project=self.project, kind='openvas', ips=[IN], host='survey.example.com', target={'hosts': {IN: 'survey.example.com'}})
        with self.assertRaises(AddressExcluded):
            SentinelTask(project=self.project, kind='some_new_kind', target={'anything': {'deep': [IN]}}).save()  # an address anywhere in a target is seen
        self.assertNoTask()
        SentinelTask.objects.create(project=self.project, kind='nmap', ips=[OUT], target={'addresses': [OUT]})  # not on the list: made as before
        self.assertEqual(SentinelTask.objects.count(), 1)

    def test_a_lookup_only_kind_is_allowed_and_keeps_its_answers(self):
        task = SentinelTask.objects.create(project=self.project, kind='dns_resolve', target={'names': ['survey.example.com', 'new.example.com']})
        self.assertEqual(task.kind, 'dns_resolve')

    def test_a_chunk_loses_only_the_excluded_addresses_and_a_skip_line_names_them_once(self):
        prepare = dispatch._guarded_prepare(self.project, 'nmap', lambda chunk: ({'addresses': chunk}, chunk), self.scan)
        self.assertEqual(prepare([OUT, IN, '192.0.2.10']), ({'addresses': [OUT, '192.0.2.10']}, [OUT, '192.0.2.10']))
        self.assertIsNone(prepare([IN, '198.51.100.8']))
        self.assertIsNone(prepare([IN]))
        lines = AgentActivity.objects.filter(detail__address_excluded=True)
        self.assertEqual(lines.count(), 2)  # one line per distinct set of fresh hosts, never one per repeat
        self.assertIn("Skipped 1 address on the organization's do-not-scan list", lines.first().message)

    def test_dispatch_many_creates_nothing_for_a_refused_chunk(self):
        with self.assertRaises(ScannerUnavailable):  # never offered to a Sentinel: the stage stays due, nothing ran
            list(dispatch.dispatch_many(self.project, 'nmap', [[IN], ['198.51.100.9']], scan=self.scan))
        self.assertNoTask()

    def test_the_skip_line_says_it_once_per_host_in_plain_words(self):
        self.host('a.example.com', IN)
        self.host('b.example.com', '198.51.100.9')
        for _ in range(3):
            for name in ('survey.example.com', 'a.example.com', 'b.example.com'):
                with self.assertRaises(AddressExcluded):
                    dispatch.dispatch_or_none(self.project, 'nuclei_light', {'targets': [name]}, host=name, scan=self.scan)
        messages = list(AgentActivity.objects.filter(detail__address_excluded=True).values_list('message', flat=True))
        self.assertEqual(len(messages), 3)
        self.assertTrue(all("resolve to an address on the organization's do-not-scan list" in m or 'resolves to' in m or 'that resolve' in m for m in messages), messages)

    def test_a_stage_stays_due_not_failed(self):
        with self.assertRaises(ScannerUnavailable):  # the stages already treat this as "nothing ran, still due"
            dispatch.dispatch_or_none(self.project, 'nmap', {'addresses': [IN]}, ips=[IN])


class DiscoveryFirstLookup(World):
    def test_a_single_host_target_is_looked_up_first_and_never_handed_to_the_scanner_when_it_points_into_the_list(self):
        self.exclude('198.51.100.0/24')
        domain = Domain.objects.create(name='lab.example.com', project=self.project, insert_date=timezone.now(), scope_mode='host')
        self.assertTrue(domain.is_host_scoped())
        with mock.patch('agentapi.probe_dispatch.try_dns_resolve', return_value=({('lab.example.com', IN)}, {})) as lookup:
            with self.assertRaises(AddressExcluded) as caught:
                address_guard.resolve_before_discovery(self.scan, domain)
        lookup.assert_called_once()
        self.assertIn('resolves to 198.51.100.7', str(caught.exception))
        self.assertEqual(sorted(IpAddress.objects.filter(ip_addresses__name='lab.example.com').values_list('address', flat=True)), [IN])  # the inventory learned it
        with mock.patch('agentapi.probe_dispatch.try_dns_resolve') as lookup:  # known now: no second lookup
            with self.assertRaises(AddressExcluded):
                address_guard.resolve_before_discovery(self.scan, domain)
        lookup.assert_not_called()

    def test_a_target_that_resolves_elsewhere_or_a_whole_domain_goes_ahead(self):
        self.exclude('198.51.100.0/24')
        host = Domain.objects.create(name='ok.example.com', project=self.project, insert_date=timezone.now(), scope_mode='host')
        with mock.patch('agentapi.probe_dispatch.try_dns_resolve', return_value=({('ok.example.com', OUT)}, {})):
            address_guard.resolve_before_discovery(self.scan, host)
        with mock.patch('agentapi.probe_dispatch.try_dns_resolve') as lookup:
            address_guard.resolve_before_discovery(self.scan, self.domain)  # a whole domain: discovered as before
        lookup.assert_not_called()

    def test_an_unreadable_list_refuses_the_run(self):
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db')):
            with self.assertRaises(AddressExcluded):
                address_guard.resolve_before_discovery(self.scan, self.domain)


class Claim(World):
    def test_a_task_queued_before_its_address_was_listed_is_cancelled_when_it_is(self):
        queued = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [IN]}, ips=[IN])
        fine = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [OUT]}, ips=[OUT])
        row, cancelled = excluded_addresses.add(self.admin, self.org, '198.51.100.0/24', 'lab range')
        self.assertEqual(cancelled, 1)
        queued.refresh_from_db()
        fine.refresh_from_db()
        self.assertEqual(queued.status, 'expired')
        self.assertIn('on the organization\'s do-not-scan list', queued.error)
        self.assertTrue(queued.error.startswith('cancelled:'))
        self.assertEqual(fine.status, 'queued')

    def test_a_task_is_not_leased_when_its_address_is_listed_and_the_list_is_read_at_claim(self):
        _, raw = self.sentinel(['nmap'])
        queued = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [IN]}, ips=[IN])
        ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')  # listed without the cancel pass: the claim still refuses
        status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200)
        self.assertIsNone(out['task'])
        queued.refresh_from_db()
        self.assertEqual(queued.status, 'expired')

    def test_an_unreadable_list_leaves_the_task_queued_and_hands_out_nothing(self):
        _, raw = self.sentinel(['nmap'])
        queued = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [OUT]}, ips=[OUT])
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db')):
            status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNone(out['task'])
        self.assertIn('could not be read', out['reason'])
        queued.refresh_from_db()
        self.assertEqual(queued.status, 'queued')  # nothing lost: it runs when the list can be read
        status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], queued.pk)


class Ingestion(World):
    def leased(self, kind, target, ips, agent):
        return self._lease(kind, target, ips, agent, timezone.now())

    def _lease(self, kind, target, ips, agent, now):
        from datetime import timedelta
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind=kind, target=target, ips=ips)
        SentinelTask.objects.filter(pk=task.pk).update(status='running', agent=agent, claimed_at=now, accepted_at=now, lease_expires_at=now + timedelta(minutes=5))
        return task

    def test_a_result_for_an_address_listed_after_dispatch_is_dropped_and_logged(self):
        agent, raw = self.sentinel(['nmap'])
        task = self.leased('nmap', {'addresses': [IN]}, [IN], agent)
        self.exclude('198.51.100.0/24')
        status, out = call(raw, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result',
                           {'outcome': 'done', 'hosts': [{'ip': IN, 'os_guess': '', 'ports': [{'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh'}]}]})
        self.assertEqual(status, 200, out)
        self.assertTrue(out['dropped'])
        task.refresh_from_db()
        self.assertEqual((task.status, task.result), ('failed', {}))
        self.assertIn('result dropped', task.error)
        self.assertTrue(AgentActivity.objects.filter(message__startswith='Dropped a nmap result', detail__address_excluded=True).exists())
        self.assertTrue(AuditLog.objects.filter(action='sentinel.task.complete', detail__outcome='dropped').exists())

    def test_a_result_that_names_an_excluded_address_the_task_did_not_ask_about_is_dropped(self):
        agent, _ = self.sentinel(['naabu'])
        task = self.leased('naabu', {'addresses': [OUT]}, [OUT], agent)
        self.exclude('198.51.100.0/24')
        for result in ({'outcome': 'done', 'ports': {IN: [22]}}, {'outcome': 'done', 'findings': [{'host': 'x', 'ip': IN}]},
                       {'outcome': 'done', 'hosts': [{'ip': '[2001:db8::1]:22'}], 'x': {'matched-at': f'https://{IN}/'}}):
            if '2001' in str(result):
                self.exclude('2001:db8::/32')
            self.assertTrue(address_guard.result_refusal(task, result), result)
        self.assertIsNone(address_guard.result_refusal(task, {'outcome': 'done', 'ports': {OUT: [22]}}))

    def test_a_result_for_an_address_that_is_not_listed_is_kept(self):
        agent, raw = self.sentinel(['naabu'])
        task = self.leased('naabu', {'addresses': [OUT]}, [OUT], agent)
        self.exclude('198.51.100.0/24')
        status, out = call(raw, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'ports': {OUT: [22]}})
        self.assertEqual(status, 200, out)
        self.assertNotIn('dropped', out)
        task.refresh_from_db()
        self.assertEqual(task.status, 'done')

    def test_a_name_whose_address_moved_into_the_range_after_dispatch_is_dropped(self):
        agent, raw = self.sentinel(['http_probe'])
        sub = self.host('moved.example.com', OUT)
        task = self.leased('nuclei_light', {'targets': ['https://moved.example.com']}, [], agent)
        self.exclude('198.51.100.0/24')
        IpAddress.objects.filter(address=OUT).update(address=IN)  # the name now resolves into the range
        self.assertTrue(address_guard.result_refusal(task, {'outcome': 'done'}))
        self.assertEqual(sub.ip_addresses.get().address, IN)

    def test_an_unreadable_list_drops_the_result_instead_of_storing_it(self):
        agent, raw = self.sentinel(['naabu'])
        task = self.leased('naabu', {'addresses': [OUT]}, [OUT], agent)
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db')):
            status, out = call(raw, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', {'outcome': 'done', 'ports': {OUT: [22]}})
        self.assertTrue(out['dropped'])
        task.refresh_from_db()
        self.assertEqual((task.status, task.result), ('failed', {}))
        self.assertIn('could not be read', task.error)

    def test_dns_resolve_keeps_its_answers_so_the_inventory_learns_where_a_name_went(self):
        agent, _ = self.sentinel(['dns_resolve'])
        task = self.leased('dns_resolve', {'names': ['survey.example.com'], 'scope': {'hosts': ['survey.example.com']}}, [], agent)
        self.exclude('198.51.100.0/24')
        result = {'outcome': 'done', 'resolved': {'survey.example.com': [IN]}, 'errors': {}, 'refused': []}
        self.assertIsNone(address_guard.result_refusal(task, result))  # nothing is dropped: the answers reach the inventory
        line = AgentActivity.objects.get(detail__address_excluded=True)
        self.assertIn("Skipped 1 host that resolves to an address on the organization's do-not-scan list: survey.example.com", line.message)

    def test_a_streamed_batch_loses_only_the_entries_about_listed_addresses(self):
        task = SentinelTask(project=self.project, scan=self.scan, kind='bbot_discovery', target={})
        self.exclude('198.51.100.0/24')
        batch, dropped = address_guard.filter_batch(task, {'seq': 1, 'http': [{'host': 'a.example.com', 'ip': IN}, {'host': 'b.example.com', 'ip': OUT}], 'events': ['x']})
        self.assertEqual(dropped, 1)
        self.assertEqual([h['host'] for h in batch['http']], ['b.example.com'])
        self.assertEqual(batch['events'], ['x'])
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db')):
            _, dropped = address_guard.filter_batch(task, {'http': [{'host': 'b.example.com', 'ip': OUT}]})
        self.assertEqual(dropped, 1)


class Editor(World):
    def url(self, suffix=''):
        return f'/cve/api/admin/orgs/{self.org.pk}/excluded-addresses{suffix}'

    def login(self, user):
        c = Client()
        c.force_login(user)
        return c

    def post(self, user, body, org=None):
        return self.login(user).post(f'/cve/api/admin/orgs/{(org or self.org).pk}/excluded-addresses', json.dumps(body), content_type='application/json')

    def test_an_org_admin_adds_lists_and_removes_with_audit_and_normalisation(self):
        r = self.post(self.admin, {'cidr': '198.51.100.9/24', 'note': 'prod VPS lab range'})
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()['cidr'], '198.51.100.0/24')
        self.assertTrue(AuditLog.objects.filter(action='org.excluded_address.add', org_id=self.org.pk, actor=self.admin).exists())
        listed = self.login(self.admin).get(self.url()).json()
        self.assertEqual([x['cidr'] for x in listed['results']], ['198.51.100.0/24'])
        self.assertEqual(listed['results'][0]['by'], 'g_admin')
        gone = self.login(self.admin).delete(self.url(f"/{listed['results'][0]['id']}"))
        self.assertEqual(gone.status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action='org.excluded_address.remove', org_id=self.org.pk).exists())
        self.assertFalse(ExcludedAddress.objects.exists())

    def test_an_app_admin_may_too_and_everyone_else_may_not(self):
        self.assertEqual(self.post(self.root, {'cidr': '192.0.2.1'}).status_code, 201)
        for user in (self.member, self.stranger):
            self.assertIn(self.post(user, {'cidr': '192.0.2.2'}).status_code, (403, 404), user.username)
            self.assertIn(self.login(user).get(self.url()).status_code, (403, 404))
        self.assertEqual(self.login(self.member).delete(self.url('/1')).status_code, 403)
        self.assertIn(Client().get(self.url()).status_code, (302, 401, 403))  # signed out
        self.assertEqual(ExcludedAddress.objects.count(), 1)
        row = ExcludedAddress.objects.get()
        self.assertEqual(self.login(self.stranger).delete(self.url(f'/{row.pk}')).status_code, 404)  # another org's admin cannot remove it either
        self.assertTrue(ExcludedAddress.objects.filter(pk=row.pk).exists())

    def test_a_post_without_the_csrf_token_is_refused(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        r = c.post(self.url(), json.dumps({'cidr': '192.0.2.1'}), content_type='application/json')
        self.assertEqual(r.status_code, 403)
        self.assertFalse(ExcludedAddress.objects.exists())

    def test_validation_and_the_broad_network_confirmation(self):
        for body in ({'cidr': '0.0.0.0/0', 'confirm_broad': True}, {'cidr': '::/0', 'confirm_broad': True}, {'cidr': 'example.com'}, {'cidr': ''}, {}, {'cidr': '1.2.3.4', 'note': 'x' * 301}, {'cidr': '1.2.3.4', 'note': 5}):
            self.assertEqual(self.post(self.admin, body).status_code, 400, body)
        r = self.post(self.admin, {'cidr': '10.0.0.0/7'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('confirm it to add it', r.json()['error'])
        self.assertEqual(self.post(self.admin, {'cidr': '10.0.0.0/7', 'confirm_broad': 'yes'}).status_code, 400)  # only a real true confirms
        self.assertEqual(self.post(self.admin, {'cidr': '10.0.0.0/7', 'confirm_broad': True}).status_code, 201)
        self.assertEqual(self.post(self.admin, {'cidr': '10.0.0.0/8'}).status_code, 201)  # /8 is the floor for IPv4: no confirmation
        self.assertEqual(self.post(self.admin, {'cidr': '2001::/31'}).status_code, 400)
        self.assertEqual(self.post(self.admin, {'cidr': '2001:db8::/32'}).status_code, 201)

    def test_the_same_network_in_another_form_is_a_duplicate(self):
        self.assertEqual(self.post(self.admin, {'cidr': '2001:db8::5'}).status_code, 201)
        self.assertEqual(self.post(self.admin, {'cidr': '2001:0DB8:0:0:0:0:0:5/128'}).status_code, 409)
        self.assertEqual(self.post(self.admin, {'cidr': '192.0.2.9'}).status_code, 201)
        self.assertEqual(self.post(self.admin, {'cidr': '::ffff:192.0.2.9'}).status_code, 409)
        self.assertEqual(self.post(self.stranger, {'cidr': '192.0.2.9'}, org=self.other_org).status_code, 201)  # another org may list the same one

    def test_the_list_has_a_size_cap(self):
        with mock.patch.object(exclusions, 'MAX_ENTRIES', 3):
            for n in range(3):
                self.assertEqual(self.post(self.admin, {'cidr': f'192.0.2.{n}'}).status_code, 201)
            r = self.post(self.admin, {'cidr': '192.0.2.99'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('at most 3', r.json()['error'])

    def test_adding_cancels_waiting_work_and_says_so(self):
        SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': [IN]}, ips=[IN])
        r = self.post(self.admin, {'cidr': '198.51.100.0/24'})
        self.assertEqual(r.json()['cancelled_tasks'], 1)
        self.assertEqual(AuditLog.objects.get(action='org.excluded_address.add').detail['cancelled_tasks'], 1)


class ReadApi(World):
    def setUp(self):
        super().setUp()
        _, self.raw = create_token(self.member, 'read')
        self.exclude('198.51.100.0/24')
        self.host('survey.example.com', IN)

    def test_rest_lists_and_answers_for_a_host(self):
        status, out = call(self.raw, 'GET', '/api/v1/projects/guard-p/excluded-addresses')
        self.assertEqual(status, 200, out)
        self.assertEqual([r['cidr'] for r in out['results']], ['198.51.100.0/24'])
        status, out = call(self.raw, 'GET', '/api/v1/projects/guard-p/excluded-addresses?host=survey.example.com')
        self.assertTrue(out['excluded'])
        self.assertIn('198.51.100.7', out['reason'])
        status, out = call(self.raw, 'GET', '/api/v1/projects/guard-p/excluded-addresses?host=www.example.com')
        self.assertFalse(out['excluded'])

    def test_the_other_orgs_project_is_not_readable_and_the_mcp_tool_exists(self):
        status, _ = call(self.raw, 'GET', '/api/v1/projects/other-p/excluded-addresses')
        self.assertIn(status, (403, 404))
        from agentapi import mcp
        self.assertIn('list_excluded_addresses', [t[0] for t in mcp.TOOLS])

    def test_the_host_row_and_the_scan_summary_say_why_it_is_not_scanned(self):
        from agentapi import services
        sub = Subdomain.objects.get(name='survey.example.com')
        row = services._scan_blocked(sub, self.project.pk, [IN], None)
        self.assertIn('survey.example.com is not scanned', row)
        self.assertIn('198.51.100.0/24', row)
        self.assertEqual(services._scan_blocked(sub, self.project.pk, [OUT], None), '')
        with mock.patch('cveFeed.exclusions.address_networks', side_effect=RuntimeError('db')):
            self.assertIn('could not be read', services._scan_blocked(sub, self.project.pk, [OUT], None))
        address_guard.note_skipped(self.project, {'survey.example.com': exclusions.Refusal('x')}, scan=self.scan, kind='nmap')
        out = services._scan(self.scan, detail=True)
        self.assertEqual(out['not_scanned'][0]['hosts'], ['survey.example.com'])


class EveryKindIsGuarded(World):
    """A kind added to the contract without being routed through the guard fails here: the next kind cannot forget."""

    EXEMPT_NO_ADDRESS = {'nuclei_validate': 'carries a template only; the hosts it runs against are other tasks',
                         'bucket_check': 'asks public cloud storage endpoints by bucket name; it carries no host of the organization'}

    def fixture(self, kind):
        name = 'nuclei_light' if kind in ('nuclei_targeted', 'nuclei_deep') else kind
        return json.loads((FIXTURES / f'{name}.json').read_text())

    def test_the_coverage_table_names_every_contract_kind(self):
        table = address_guard.coverage()
        self.assertEqual(set(table), set(sentinel_contract.KINDS))
        self.assertEqual(set(table.values()), {'guarded', 'lookup_only'})
        self.assertEqual([k for k, v in table.items() if v == 'lookup_only'], ['dns_resolve'])

    def test_every_guarded_kind_is_refused_at_dispatch_and_at_the_model_and_ingestion(self):
        self.exclude('198.51.100.0/24')
        silent = []
        for kind in sentinel_contract.KINDS:
            target = self.fixture(kind)
            values = address_guard.task_values(kind, target)
            if not values:
                silent.append(kind)
                continue
            if kind == 'dns_resolve' or kind in self.EXEMPT_NO_ADDRESS:
                continue
            names = [v for v in values if not exclusions.as_address(v) and '/' not in v]
            sub_names = [n for n in names if '.' in n]
            for n in sub_names:
                if not Subdomain.objects.filter(name=n.lower()).exists():
                    self.host(n.lower().split('/')[0], '198.51.100.99')
            ExcludedAddress.objects.all().delete()
            self.exclude('198.51.100.0/24')
            for v in values:
                if exclusions.as_address(v):
                    self.exclude(v) if not ExcludedAddress.objects.filter(cidr=str(parse_entry(v)[0])).exists() else None
            refusals = address_guard.task_refusals(self.project, kind, target)
            self.assertTrue(refusals, f'{kind}: the guard sees nothing to refuse in its own target fixture')
            with self.assertRaises(AddressExcluded, msg=kind):
                SentinelTask.objects.create(project=self.project, kind=kind, target=target)
            with self.assertRaises(AddressExcluded, msg=kind):
                dispatch.dispatch_or_none(self.project, kind, target, scan=self.scan)
            stored = mock.Mock(kind=kind, project_id=self.project.pk, target=target, host='', ips=[])
            self.assertTrue(address_guard.task_refusal(stored), kind)
        self.assertEqual([k for k in silent if k not in self.EXEMPT_NO_ADDRESS], [], 'a kind whose target the guard reads no address from: add it to address_guard.task_values')
        self.assertFalse(SentinelTask.objects.exists())

    def test_the_lookup_only_kind_is_made_and_every_other_kind_is_in_the_never_local_set(self):
        self.exclude('198.51.100.0/24')
        SentinelTask.objects.create(project=self.project, kind='dns_resolve', target=self.fixture('dns_resolve'))
        self.assertEqual(set(sentinel_contract.KINDS) - set(dispatch.NEVER_LOCAL), {'discover'})
