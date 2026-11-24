"""A Sentinel's DNS answers are checked against a second source before they change a host (``agentapi.dns_crosscheck``): what is taken, what is held
and why, the confirming lookup on another Sentinel, the one-Sentinel rule, discovery batches, the do-not-scan list, and where the flag is shown.

Addresses are documentation ranges and example.com names only."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import address_guard, dns_crosscheck, probe_dispatch, services, sentinel_stream
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import Agent, DnsReading, SentinelTask
from cveFeed.models import AgentActivity
from cvengine.resources import AddressExcluded
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain
from tests.test_address_guard import IN, OUT, World
from tests.test_agentapi import call

OLD, NEW = '192.0.2.10', '203.0.113.20'


class Base(World):
    def setUp(self):
        super().setUp()
        self.a, self.raw_a = self.sentinel(['dns_resolve', 'bbot_discovery'])
        self.b, self.raw_b = self.sentinel(['dns_resolve'])
        Agent.objects.filter(pk__in=[self.a.pk, self.b.pk]).update(last_seen=timezone.now())

    def answer(self, agent, task_id, pairs, now=None, via='dns_resolve'):
        dns_crosscheck.record(self.project.pk, agent.pk, task_id, pairs, via, now=now)
        out = {}
        for name, address in pairs:
            out.setdefault(name, []).append(address)
        return dns_crosscheck.judge(self.project.pk, out, now=now)

    def reading(self, name, address):
        return DnsReading.objects.get(project=self.project, name=name, address=address)

    def lease(self, agent, names, avoid=None):
        now = timezone.now()
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='dns_resolve', avoid_agent=avoid,
                                           target={'names': names, 'scope': {'hosts': names}})
        SentinelTask.objects.filter(pk=task.pk).update(status='running', agent=agent, claimed_at=now, accepted_at=now, lease_expires_at=now + timedelta(minutes=5))
        return task


class Judge(Base):
    def test_a_new_host_takes_its_answer_and_nothing_is_held(self):
        verdict = self.answer(self.a, 1, {('new.example.com', NEW)})
        self.assertEqual((verdict.accepted, verdict.held, verdict.carried), ({('new.example.com', NEW)}, {}, set()))
        self.assertEqual(self.reading('new.example.com', NEW).status, 'seen')

    def test_an_address_the_host_already_has_is_taken(self):
        self.host('www.example.com', OLD)
        verdict = self.answer(self.a, 1, {('www.example.com', OLD)})
        self.assertEqual((verdict.accepted, verdict.held), ({('www.example.com', OLD)}, {}))

    def test_a_single_source_answer_that_replaces_the_addresses_is_held_and_the_host_keeps_its_own(self):
        self.host('www.example.com', OLD)
        verdict = self.answer(self.a, 1, {('www.example.com', NEW)})
        self.assertEqual(verdict.accepted, set())
        self.assertEqual(verdict.held, {'www.example.com': {NEW: 'replaces'}})
        self.assertEqual(verdict.carried, {('www.example.com', OLD)})
        row = self.reading('www.example.com', NEW)
        self.assertEqual((row.status, row.reason, row.runs, list(row.sources)), ('held', 'replaces', 1, [str(self.a.pk)]))

    def test_an_added_address_is_held_and_the_known_one_taken(self):
        self.host('www.example.com', OLD)
        verdict = self.answer(self.a, 1, {('www.example.com', OLD), ('www.example.com', NEW)})
        self.assertEqual(verdict.accepted, {('www.example.com', OLD)})
        self.assertEqual(verdict.held, {'www.example.com': {NEW: 'adds'}})

    def test_a_move_into_or_out_of_the_do_not_scan_list_is_held(self):
        self.exclude('198.51.100.0/24')
        self.host('www.example.com', OLD)
        self.host('listed.example.com', IN)
        verdict = self.answer(self.a, 1, {('www.example.com', IN), ('listed.example.com', OUT), ('fresh.example.com', IN)})
        self.assertEqual(verdict.held, {'www.example.com': {IN: 'into_list'}, 'listed.example.com': {OUT: 'out_of_list'}, 'fresh.example.com': {IN: 'into_list'}})
        self.assertEqual(verdict.carried, {('www.example.com', OLD), ('listed.example.com', IN)})  # a new host has nothing to keep: it stays without an address
        self.assertEqual(verdict.accepted, set())

    def test_one_sentinel_confirms_by_the_same_answer_over_three_runs_and_twelve_hours(self):
        self.host('www.example.com', OLD)
        start = timezone.now() - timedelta(hours=13)
        self.assertTrue(self.answer(self.a, 1, {('www.example.com', NEW)}, now=start).held)
        self.assertTrue(self.answer(self.a, 1, {('www.example.com', NEW)}, now=start + timedelta(hours=1)).held)  # the same task again: still one run
        self.assertTrue(self.answer(self.a, 2, {('www.example.com', NEW)}, now=start + timedelta(hours=2)).held)
        self.assertTrue(self.answer(self.a, 3, {('www.example.com', NEW)}, now=start + timedelta(hours=3)).held)  # three runs, but within three hours
        verdict = self.answer(self.a, 4, {('www.example.com', NEW)}, now=start + timedelta(hours=13))
        self.assertEqual((verdict.accepted, verdict.held), ({('www.example.com', NEW)}, {}))
        row = self.reading('www.example.com', NEW)
        self.assertEqual((row.status, row.confirmed_how, row.runs), ('confirmed', 'repeated', 4))

    def test_a_second_sentinel_with_the_same_answer_confirms_it(self):
        self.host('www.example.com', OLD)
        self.assertTrue(self.answer(self.a, 1, {('www.example.com', NEW)}).held)
        verdict = self.answer(self.b, 2, {('www.example.com', NEW)})
        self.assertEqual(verdict.accepted, {('www.example.com', NEW)})
        self.assertEqual(self.reading('www.example.com', NEW).confirmed_how, 'second_sentinel')


class ConfirmingLookup(Base):
    def test_a_held_answer_is_handed_to_another_sentinel_which_alone_may_take_it(self):
        self.host('www.example.com', OLD)
        result = dispatch.Result({'outcome': 'done', 'resolved': {'www.example.com': [NEW]}, 'errors': {}, 'refused': []}, agent_id=self.a.pk)
        dns_crosscheck.record(self.project.pk, self.a.pk, 99, {('www.example.com', NEW)}, 'dns_resolve')  # what the ingestion did
        held = {}
        with mock.patch.object(dispatch, 'dispatch_or_none', return_value=result), mock.patch.object(probe_dispatch, '_offered', return_value=True):
            pairs, errors = probe_dispatch.try_dns_resolve(self.domain, ['www.example.com'], scan=self.scan, held=held)
        self.assertEqual((pairs, errors, held), ({('www.example.com', OLD)}, {}, {'www.example.com': {NEW: 'replaces'}}))
        confirm = SentinelTask.objects.get(kind='dns_resolve', avoid_agent=self.a.pk)
        self.assertEqual((confirm.status, confirm.target['names']), ('queued', ['www.example.com']))
        self.assertTrue(AgentActivity.objects.filter(message__startswith='Held 1 unconfirmed DNS answer for www.example.com', detail__dns_unconfirmed=True).exists())
        self.assertTrue(AgentActivity.objects.filter(message__startswith='Asked a second Sentinel to confirm').exists())
        status, out = call(self.raw_a, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertIsNone(out['task'])  # never the Sentinel whose answer it checks
        status, out = call(self.raw_b, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], confirm.pk)
        # asked once: a second held answer for the same name soon after asks no one again
        self.assertIsNone(dns_crosscheck.request_confirmation(self.project, self.domain, ['www.example.com'], self.a.pk))

    def test_with_no_other_sentinel_nothing_is_asked_and_the_answer_waits_for_the_repeat_rule(self):
        Agent.objects.filter(pk=self.b.pk).update(status='suspended')
        self.assertIsNone(dns_crosscheck.request_confirmation(self.project, self.domain, ['www.example.com'], self.a.pk))
        self.assertFalse(SentinelTask.objects.filter(avoid_agent__isnull=False).exists())

    def test_the_second_sentinels_report_confirms_the_answer_and_adds_it_to_the_host(self):
        sub = self.host('www.example.com', OLD)
        self.answer(self.a, 1, {('www.example.com', NEW)})
        task = self.lease(self.b, ['www.example.com'], avoid=self.a.pk)
        status, out = call(self.raw_b, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result',
                           {'outcome': 'done', 'resolved': {'www.example.com': [NEW]}, 'errors': {}, 'refused': []})
        self.assertEqual(status, 200, out)
        row = self.reading('www.example.com', NEW)
        self.assertEqual((row.status, row.confirmed_how, sorted(row.sources)), ('confirmed', 'second_sentinel', sorted([str(self.a.pk), str(self.b.pk)])))
        self.assertEqual(sorted(sub.ip_addresses.values_list('address', flat=True)), sorted([OLD, NEW]))
        self.assertTrue(AgentActivity.objects.filter(message__startswith='Confirmed 1 DNS answer for www.example.com').exists())
        self.assertEqual(dns_crosscheck.held_for([self.project.pk], ['www.example.com']), {})

    def test_a_second_sentinel_that_disagrees_leaves_the_answer_unconfirmed(self):
        sub = self.host('www.example.com', OLD)
        self.answer(self.a, 1, {('www.example.com', NEW)})
        task = self.lease(self.b, ['www.example.com'], avoid=self.a.pk)
        status, out = call(self.raw_b, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result',
                           {'outcome': 'done', 'resolved': {'www.example.com': [OLD]}, 'errors': {}, 'refused': []})
        self.assertEqual(status, 200, out)
        self.assertEqual(self.reading('www.example.com', NEW).status, 'held')
        self.assertEqual(list(sub.ip_addresses.values_list('address', flat=True)), [OLD])
        self.assertTrue(AgentActivity.objects.filter(message__startswith='A second Sentinel did not confirm the held DNS answers for www.example.com').exists())


class DiscoveryBatches(Base):
    def test_a_held_resolution_is_taken_out_of_the_batch_and_the_host_keeps_its_address(self):
        self.host('www.example.com', OLD)
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='bbot_discovery', target={})
        SentinelTask.objects.filter(pk=task.pk).update(agent=self.a, status='running')
        task.refresh_from_db()
        batch = {'seq': 1, 'subdomains': ['www.example.com', 'api.example.com'],
                 'resolutions': [{'name': 'www.example.com', 'ip': NEW}, {'name': 'api.example.com', 'ip': '203.0.113.30'}]}
        out = dns_crosscheck.screen_batch(task, batch)
        self.assertEqual(out['resolutions'], [{'name': 'api.example.com', 'ip': '203.0.113.30'}, {'name': 'www.example.com', 'ip': OLD}])
        self.assertEqual(self.reading('www.example.com', NEW).via, ['discovery'])
        self.assertTrue(SentinelTask.objects.filter(kind='dns_resolve', avoid_agent=self.a.pk, target__names=['www.example.com']).exists())

    def test_the_partial_route_stores_the_screened_batch(self):
        from agentapi.models import SentinelPartial
        self.host('www.example.com', OLD)
        now = timezone.now()
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='bbot_discovery', host='example.com', target={}, status='running',
                                           agent=self.a, accepted_at=now, lease_expires_at=now + timedelta(minutes=5))
        batch = {'seq': 1, 'subdomains': ['www.example.com'], 'resolutions': [{'name': 'www.example.com', 'ip': NEW}]}
        with mock.patch.object(sentinel_stream, 'clean_partial', return_value=batch):
            status, out = call(self.raw_a, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/partial', batch)
        self.assertEqual(status, 200, out)
        self.assertEqual(SentinelPartial.objects.get(task=task).body['resolutions'], [{'name': 'www.example.com', 'ip': OLD}])
        self.assertEqual(self.reading('www.example.com', NEW).status, 'held')


class DoNotScanList(Base):
    def test_a_held_answer_that_points_a_single_host_target_into_the_list_still_refuses_the_run_and_is_not_stored(self):
        self.exclude('198.51.100.0/24')
        domain = Domain.objects.create(name='lab.example.com', project=self.project, insert_date=timezone.now(), scope_mode='host')

        def lookup(domain, names, scan=None, held=None):
            held['lab.example.com'] = {IN: 'into_list'}
            return set(), {}
        with mock.patch('agentapi.probe_dispatch.try_dns_resolve', side_effect=lookup):
            with self.assertRaises(AddressExcluded):
                address_guard.resolve_before_discovery(self.scan, domain)
        self.assertFalse(IpAddress.objects.filter(ip_addresses__name='lab.example.com').exists())


class Shown(Base):
    def test_the_host_row_names_its_unconfirmed_addresses(self):
        sub = self.host('www.example.com', OLD)
        self.answer(self.a, 1, {('www.example.com', NEW)})
        row = services.host_group(self.project, sub)
        self.assertEqual([ip['address'] for ip in row['ips']], [OLD])
        [flag] = row['unconfirmed_addresses']
        self.assertEqual((flag['address'], flag['state'], flag['single_source'], flag['reason'], flag['runs']), (NEW, 'unconfirmed', True, 'replaces', 1))
        self.assertIn('unconfirmed_addresses', open(services.__file__.replace('services.py', 'mcp.py')).read())
        self.assertEqual(Subdomain.objects.filter(name='www.example.com').count(), 1)
