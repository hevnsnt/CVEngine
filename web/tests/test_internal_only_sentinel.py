"""A Sentinel inside a private network (``network:internal``) is handed internal work only (``sentinel_broker.internal_work_refusal``): a task whose
every host lies inside a range its project declared internal, a ``discover`` sweep of part of one, or a name whose addresses on record are all inside
one. Anything else (a public address, a name that resolves outside the ranges, a domain discovery, a public web check) is never offered to it, never
claimed or accepted by it, a result it sends for one is refused, and one it held from before the rule is handed back to the queue for an external
Sentinel. An external Sentinel is unaffected. Public addresses here are truly public (8.8.4.4, 9.9.9.9, 4.151.32.174, 35.190.45.195): Python counts the
documentation ranges as private.
"""
from unittest import mock

from django.utils import timezone

from agentapi import sentinel_broker as sentinels
from agentapi import sentinel_contract
from agentapi.models import Agent, SentinelTask
from cveFeed.models import InternalRange
from dashboard.models import AuditLog
from startScan.models import IpAddress, Subdomain
from tests.test_agentapi import call
from tests.test_sentinels import SentinelBase, create_token, register_sentinel

CAPS = ['nmap', 'naabu', 'nuclei_light', 'wpscan', 'discover', 'http_probe', 'bbot_discovery', 'dns_resolve']
INFO = {'features': ['credential_filter'], 'contract_version': 11}

# Each kind of the 19 external tasks an internal Sentinel was handed, with the shape of its target: none of them is internal work.
EXTERNAL = [
    ('naabu', {'addresses': ['4.151.32.174']}, '4.151.32.174', ['4.151.32.174']),
    ('nmap_verify', {'addresses': ['35.190.45.195']}, '35.190.45.195', ['35.190.45.195']),
    ('wpscan', {'url': 'https://www.knuckleheadskc.com', 'token': 't'}, '', []),
    ('bbot_discovery', {'domain': 'fieldcraftcyber.com'}, 'fieldcraftcyber.com', []),
    ('dns_resolve', {'names': ['knuckleheadskc.com', 'norecognition.org']}, '', []),
    ('identity_check', {'dns': [{'name': 'norecognition.org'}]}, '', []),
    ('http_probe', {'probes': [{'host': 'www.knuckleheadskc.com', 'port': 443}]}, '', []),
    ('page_read', {'reads': [{'host': 'norecognition.org', 'path': '/'}]}, '', []),
    ('route_probe', {'url': 'https://www.knuckleheadskc.com/login'}, 'www.knuckleheadskc.com', []),
    ('secrets_scan', {'hosts': [{'host': 'www.knuckleheadskc.com', 'urls': ['https://www.knuckleheadskc.com/app.js']}]}, '', []),
    ('nuclei_light', {'targets': ['https://www.knuckleheadskc.com']}, '', []),
    ('nuclei_validate', {'targets': ['9.9.9.9:443'], 'mode': 'test'}, '9.9.9.9', ['9.9.9.9']),
]


class Base(SentinelBase):
    def setUp(self):
        super().setUp()
        InternalRange.objects.create(project=self.pa, cidr='10.0.0.0/24')
        self.outside_token = self.t['dana']
        self.outside = Agent.objects.get(pk=register_sentinel(self.outside_token, name='outside', capabilities=CAPS)[1]['id'])
        self.inside_token = create_token(self.dana, 'haxxxk')[1]
        self.inside = Agent.objects.get(pk=register_sentinel(self.inside_token, name='haxxxk', capabilities=CAPS + ['network:internal'])[1]['id'])
        Agent.objects.filter(pk=self.inside.pk).update(network='internal', info=INFO, last_seen=timezone.now())  # the server's grant
        Agent.objects.filter(pk=self.outside.pk).update(info=INFO, last_seen=timezone.now())
        self.inside.refresh_from_db()
        self.outside.refresh_from_db()

    def task(self, kind='nmap', target=None, host='', ips=None, **extra):
        return SentinelTask.objects.create(project=self.pa, kind=kind, target=target if target is not None else {'addresses': list(ips or [])},
                                           host=host, ips=list(ips or []), **extra)

    def next(self, token):
        status, out = call(token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200, out)
        return out['task']

    def refusal(self, task, agent=None):
        return sentinels.effective(agent or self.inside).refusal(task)


class TheRule(Base):
    def test_every_external_task_kind_is_refused_and_its_internal_twin_is_not(self):
        eff = sentinels.effective(self.inside)
        self.assertTrue(eff.internal_only)
        for kind, target, host, ips in EXTERNAL:
            with self.subTest(kind=kind):
                self.assertIsNotNone(eff.external_refusal(self.task(kind, target, host, ips)))
        for kind in sentinel_contract.KINDS:  # whatever the kind, a task that names only an internal address is internal work
            with self.subTest(kind=kind):
                self.assertIsNone(eff.external_refusal(self.task(kind, {}, '10.0.0.5', ['10.0.0.5'])))
                self.assertIsNotNone(eff.external_refusal(self.task(kind, {}, '8.8.4.4', ['8.8.4.4'])))

    def test_a_target_list_with_one_public_address_is_refused(self):
        task = self.task('nmap', {'addresses': ['10.0.0.5', '10.0.0.6', '8.8.4.4']}, '10.0.0.5', ['10.0.0.5', '10.0.0.6', '8.8.4.4'])
        self.assertIn('8.8.4.4', sentinels.internal_work_refusal(task))
        self.assertEqual(self.refusal(task)[0], sentinels.INTERNAL_ONLY)

    def test_a_private_address_outside_the_declared_ranges_is_refused(self):
        self.assertIn('outside the declared internal ranges', sentinels.internal_work_refusal(self.task(ips=['192.168.1.5'], host='192.168.1.5')))

    def test_a_name_is_judged_by_its_addresses_on_record(self):
        sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.da, name='printer.a.example')
        sub.ip_addresses.add(IpAddress.objects.create(address='10.0.0.9'))
        public = Subdomain.objects.create(scan_history=self.scan, target_domain=self.da, name='www.public.a.example')
        public.ip_addresses.add(IpAddress.objects.create(address='8.8.4.4'))
        split = Subdomain.objects.create(scan_history=self.scan, target_domain=self.da, name='split.a.example')
        split.ip_addresses.add(IpAddress.objects.create(address='10.0.0.10'), IpAddress.objects.create(address='9.9.9.9'))
        self.assertIsNone(sentinels.internal_work_refusal(self.task('nuclei_light', {'targets': ['http://printer.a.example']})))
        self.assertIn('8.8.4.4', sentinels.internal_work_refusal(self.task('nuclei_light', {'targets': ['https://www.public.a.example']})))
        self.assertIn('9.9.9.9', sentinels.internal_work_refusal(self.task('nuclei_light', {'targets': ['split.a.example']})))
        self.assertIn('no address on record', sentinels.internal_work_refusal(self.task('nuclei_light', {'targets': ['unknown.a.example']})))

    def test_a_sweep_of_part_of_a_declared_range_is_internal_and_one_past_it_is_not(self):
        inside = self.task('discover', {'cidr': '10.0.0.0/25'}, '10.0.0.0/25', ['10.0.0.0'])
        wider = self.task('discover', {'cidr': '10.0.0.0/23'}, '10.0.0.0/23', ['10.0.0.0'])
        self.assertIsNone(sentinels.internal_work_refusal(inside))
        self.assertIn('10.0.0.0/23', sentinels.internal_work_refusal(wider))

    def test_a_task_that_names_no_host_or_a_project_without_ranges_is_refused(self):
        self.assertIsNotNone(sentinels.internal_work_refusal(self.task('nmap', {}, '', [])))
        other = SentinelTask.objects.create(project=self.pb, kind='nmap', target={'addresses': ['10.0.0.5']}, host='10.0.0.5', ips=['10.0.0.5'])
        self.assertIn('declares no internal range', sentinels.internal_work_refusal(other))

    def test_an_external_sentinel_is_unaffected(self):
        eff = sentinels.effective(self.outside)
        self.assertFalse(eff.internal_only)
        for kind, target, host, ips in EXTERNAL:
            with self.subTest(kind=kind):
                self.assertIsNone(eff.external_refusal(self.task(kind, target, host, ips)))
        self.assertEqual(eff.refusal(self.task(ips=['10.0.0.5'], host='10.0.0.5')), ('capability', sentinels.INTERNAL_CAPABILITY))  # private: still refused


class Claiming(Base):
    def test_the_internal_sentinel_takes_only_the_internal_task_and_the_external_one_the_rest(self):
        public = self.task(ips=['8.8.4.4'], host='8.8.4.4')
        bbot = self.task('bbot_discovery', {'domain': 'fieldcraftcyber.com'}, 'fieldcraftcyber.com', [])
        wp = self.task('wpscan', {'url': 'https://www.knuckleheadskc.com', 'token': 't'})
        mixed = self.task(ips=['10.0.0.5', '9.9.9.9'], host='10.0.0.5')
        internal = self.task(ips=['10.0.0.5'], host='10.0.0.5')
        sweep = self.task('discover', {'cidr': '10.0.0.0/24'}, '10.0.0.0/24', ['10.0.0.0'])
        got = [self.next(self.inside_token), self.next(self.inside_token), self.next(self.inside_token)]
        self.assertEqual(sorted(t['id'] for t in got if t), sorted([internal.pk, sweep.pk]))
        for task in (public, bbot, wp, mixed):
            task.refresh_from_db()
            self.assertEqual((task.status, task.agent_id), ('queued', None))
        for _ in range(3):
            self.next(self.outside_token)
        outside = set(SentinelTask.objects.filter(agent=self.outside).values_list('pk', flat=True))
        self.assertIn(public.pk, outside)  # (the external Sentinel's own rules, such as a discovery's keys, decide the rest, as before)
        self.assertLessEqual(outside, {public.pk, bbot.pk, wp.pk})
        mixed.refresh_from_db()
        self.assertEqual(mixed.status, 'queued')  # an external Sentinel never takes an internal address, an internal one never a public one

    def test_a_hostname_that_resolves_to_a_public_address_is_never_claimed(self):
        public = Subdomain.objects.create(scan_history=self.scan, target_domain=self.da, name='shop.a.example')
        public.ip_addresses.add(IpAddress.objects.create(address='8.8.4.4'))
        task = self.task('nuclei_light', {'targets': ['https://shop.a.example']})
        self.assertIsNone(self.next(self.inside_token))
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')
        self.assertEqual(self.next(self.outside_token)['id'], task.pk)

    def test_the_internal_sentinel_is_no_capacity_for_external_work(self):
        Agent.objects.filter(pk=self.outside.pk).update(status='suspended')
        self.assertEqual(sentinels.capacity_state(self.pa, 'nmap')['state'], 'none')
        self.assertNotEqual(sentinels.capacity_state(self.pa, 'nmap', internal=True)['state'], 'none')

    def test_a_queued_external_task_wakes_only_external_sentinels(self):
        from agentapi import sentinel_notify
        with mock.patch.object(sentinel_notify, '_push') as push, mock.patch.object(sentinel_notify, '_after_commit', lambda f: f()):
            sentinel_notify.task_queued(self.task(ips=['8.8.4.4'], host='8.8.4.4'))
        self.assertEqual(push.call_args[0][0], [sentinel_notify.agent_key(self.outside.pk)])


class HeldBeforeTheRule(Base):
    def held(self, status='claimed', **kw):
        now = timezone.now()
        task = self.task(ips=['8.8.4.4'], host='8.8.4.4', **kw)
        SentinelTask.objects.filter(pk=task.pk).update(status=status, agent=self.inside, last_holder=self.inside.pk, claimed_at=now,
                                                       accepted_at=now if status == 'running' else None, lease_expires_at=now + sentinels.RUN_LEASE)
        task.refresh_from_db()
        return task

    def test_an_external_task_it_held_goes_back_to_the_queue_and_an_external_sentinel_takes_it(self):
        task = self.held()
        self.assertIsNone(self.next(self.inside_token))
        task.refresh_from_db()
        self.assertEqual((task.status, task.agent_id), ('queued', None))
        self.assertIn('scans only hosts inside the declared internal ranges', task.error)
        self.assertTrue(AuditLog.objects.filter(action='sentinel.task.requeue', detail__task_id=task.pk).exists())
        self.assertEqual(self.next(self.outside_token)['id'], task.pk)

    def test_a_heartbeat_hands_it_back_too(self):
        task = self.held('running')
        self.assertEqual(sentinels.release_ineligible(self.inside), 1)
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')

    def test_accepting_it_is_refused(self):
        task = self.held()
        status, out = call(self.inside_token, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')
        self.assertEqual(status, 409, out)
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')

    def test_its_result_is_refused_and_nothing_is_filed(self):
        task = self.held('running')
        body = {'outcome': 'done', 'hosts': [{'ip': '8.8.4.4', 'ports': [{'number': 443}]}]}
        status, out = call(self.inside_token, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', body)
        self.assertEqual(status, 409, out)
        task.refresh_from_db()
        self.assertEqual((task.status, task.result), ('queued', {}))
        self.assertFalse(IpAddress.objects.filter(address='8.8.4.4', ports__number=443).exists())
        status, out = call(self.inside_token, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/result', body)  # sent again after the hand-back: still refused
        self.assertEqual(status, 409, out)

    def test_an_internal_task_it_holds_is_left_alone(self):
        now = timezone.now()
        task = self.task(ips=['10.0.0.5'], host='10.0.0.5')
        SentinelTask.objects.filter(pk=task.pk).update(status='claimed', agent=self.inside, claimed_at=now, lease_expires_at=now + sentinels.OFFER_LEASE)
        self.assertEqual(sentinels.release_ineligible(self.inside), 0)
        task.refresh_from_db()
        self.assertEqual(task.status, 'claimed')
