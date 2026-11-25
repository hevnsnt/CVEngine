"""The do-not-scan gate fails closed on every path, for every task kind, when the database or the cache answers errors.

Each subtest takes one kind of the Sentinel contract and injects a failure: the do-not-scan networks cannot be read, the stored addresses of the hosts
cannot be read, or the cache raises on every call. The task must not be created (``SentinelTask.save`` and ``dispatch_or_none``), a queued one must not
be leased (left queued: nothing lost, nothing run), and a result must not be stored. A failed read of the excluded HOSTS must refuse a scan decision the
same way, while the inventory still keeps every host.

Addresses are documentation and benchmark ranges only (192.0.2.0/24, 198.18.0.0/24) and example names."""
from unittest import mock

from django.test import override_settings

from agentapi import address_guard
from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from cveFeed import bounty_gate, exclusions
from cveFeed.models import HostExclusion
from cvengine.resources import AddressExcluded
from startScan.models import IpAddress, Subdomain
from tests.test_address_guard import FIXTURES, World

NAME_ADDRESS = '192.0.2.99'
LISTED_NET, LISTED = '198.18.0.0/24', '198.18.0.7'  # the benchmark range: on the do-not-scan list here
NO_ADDRESS = {'nuclei_validate', 'bucket_check'}  # carry no host of the organization (tests.test_address_guard.EveryKindIsGuarded.EXEMPT_NO_ADDRESS)


def target_of(kind):
    import json
    name = 'nuclei_light' if kind in ('nuclei_targeted', 'nuclei_deep') else kind
    return json.loads((FIXTURES / f'{name}.json').read_text())


def networks_fail():
    return mock.patch('cveFeed.models.ExcludedAddress.objects.filter', side_effect=RuntimeError('database gone'))


def addresses_fail():
    return mock.patch('cveFeed.exclusions.stored_addresses', side_effect=RuntimeError('database gone'))


class BrokenCache:
    """A cache whose every call raises, the way a Redis that is down answers."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise ConnectionError('redis down')
        return fail


@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
class EveryKindFailsClosed(World):
    def setUp(self):
        super().setUp()
        self.exclude(LISTED_NET)  # a range no target fixture uses, so a refusal below comes from the failure

    def known(self, kind, target):
        for value in address_guard.task_values(kind, target):
            name = exclusions.normalize(value)
            if exclusions.as_address(value) or '/' in value or not name or Subdomain.objects.filter(name=name).exists():
                continue
            sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=name)
            sub.ip_addresses.add(IpAddress.objects.get_or_create(address=NAME_ADDRESS, org=self.org)[0])

    def guarded_kinds(self):
        kinds = [k for k in sentinel_contract.KINDS if k not in address_guard.LOOKUP_ONLY and k not in NO_ADDRESS]
        self.assertGreater(len(kinds), 30)
        return kinds

    def test_with_no_failure_every_kind_may_run(self):
        """The baseline: the same targets pass when nothing fails, so the refusals below come from the failure and not from the targets."""
        for kind in self.guarded_kinds():
            with self.subTest(kind=kind):
                target = target_of(kind)
                self.known(kind, target)
                self.assertEqual(address_guard.task_refusals(self.project, kind, target), {})

    def test_an_unreadable_network_list_refuses_every_kind_at_creation_dispatch_claim_and_ingestion(self):
        for kind in self.guarded_kinds():
            with self.subTest(kind=kind):
                target = target_of(kind)
                self.known(kind, target)
                queued = SentinelTask.objects.create(project=self.project, kind=kind, target=target)
                with networks_fail():
                    with self.assertRaises(AddressExcluded):
                        SentinelTask.objects.create(project=self.project, kind=kind, target=target)
                    with self.assertRaises(AddressExcluded):
                        dispatch.dispatch_or_none(self.project, kind, target, scan=self.scan)
                    refusal = address_guard.task_refusal(queued)
                    self.assertTrue(refusal and refusal.unreadable, kind)
                    self.assertTrue(address_guard.result_refusal(queued, {'outcome': 'done'}), kind)
                self.assertEqual(SentinelTask.objects.filter(kind=kind).count(), 1)
                queued.delete()

    def test_an_unreadable_address_lookup_refuses_every_kind_that_names_a_host(self):
        named = []
        for kind in self.guarded_kinds():
            target = target_of(kind)
            values = address_guard.task_values(kind, target)
            if not any(not exclusions.as_address(v) and '/' not in v for v in values):
                continue
            named.append(kind)
            with self.subTest(kind=kind):
                self.known(kind, target)
                with addresses_fail():
                    with self.assertRaises(AddressExcluded):
                        SentinelTask.objects.create(project=self.project, kind=kind, target=target)
                    with self.assertRaises(AddressExcluded):
                        dispatch.dispatch_or_none(self.project, kind, target, scan=self.scan)
        self.assertTrue(named)

    def test_a_cache_that_raises_on_every_call_changes_no_decision(self):
        for kind in self.guarded_kinds():
            with self.subTest(kind=kind):
                target = target_of(kind)
                self.known(kind, target)
                with mock.patch('django.core.cache.cache', BrokenCache()):
                    self.assertEqual(address_guard.task_refusals(self.project, kind, target), {})  # nothing listed is named: it may run
                    self.assertTrue(address_guard.task_refusals(self.project, kind, target, ips=[LISTED]), kind)

    def test_a_queued_task_is_not_leased_while_the_list_cannot_be_read(self):
        _, raw = self.sentinel(['nmap'])
        from tests.test_agentapi import call
        task = SentinelTask.objects.create(project=self.project, kind='nmap', target={'addresses': ['192.0.2.10']}, ips=['192.0.2.10'])
        with networks_fail():
            status, out = call(raw, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(status, 200, out)
        self.assertIsNone(out.get('task'))
        task.refresh_from_db()
        self.assertEqual(task.status, 'queued')  # nothing lost, nothing run


@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
class ExcludedHostsFailClosed(World):
    def setUp(self):
        super().setUp()
        HostExclusion.objects.create(org=self.org, host='gone.example.com')

    def hosts_fail(self):
        return mock.patch('cveFeed.models.HostExclusion.objects.filter', side_effect=RuntimeError('database gone'))

    def test_a_failed_read_refuses_a_scan_decision(self):
        with self.hosts_fail():
            banned = exclusions.excluded_names(self.project.pk)
            self.assertTrue(banned.unreadable)
            self.assertIn('gone.example.com', banned)
            self.assertIn('any.example.com', banned)
            self.assertTrue(exclusions.is_excluded(self.project.pk, 'gone.example.com'))
            self.assertEqual(exclusions.drop_excluded(self.project.pk, ['gone.example.com', 'www.example.com']), [])

    def test_a_failed_read_keeps_every_host_in_the_inventory(self):
        with self.hosts_fail():
            kept = exclusions.excluded_names(self.project.pk, names_only=True)
            self.assertFalse(kept.unreadable)
            self.assertNotIn('www.example.com', kept)

    def test_strict_still_raises(self):
        with self.hosts_fail(), self.assertRaises(RuntimeError):
            exclusions.excluded_names(self.project.pk, strict=True)

    def test_the_read_works_again_on_the_next_call(self):
        with self.hosts_fail():
            self.assertTrue(exclusions.excluded_names(self.project.pk).unreadable)
        after = exclusions.excluded_names(self.project.pk)
        self.assertFalse(after.unreadable)
        self.assertIn('gone.example.com', after)
        self.assertNotIn('www.example.com', after)


class BountyGateFailsClosed(World):
    def test_a_gate_that_cannot_read_the_engagements_raises_instead_of_allowing(self):
        with mock.patch('cveFeed.models.BountyEngagement.objects.exclude', side_effect=RuntimeError('database gone')), self.assertRaises(RuntimeError):
            bounty_gate.Gate()
        gate = bounty_gate.Gate(blocked=())
        with mock.patch('cveFeed.models.BountyEngagement._base_manager.filter', side_effect=RuntimeError('database gone')), self.assertRaises(RuntimeError):
            gate.refusal(self.project.pk, 'www.example.com')

    def test_a_gate_reads_the_engagements_again_for_every_sweep(self):
        first = bounty_gate.Gate()
        from cveFeed.models import BountyEngagement
        self.assertFalse(first.project_blocked(self.project.pk))
        with mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={self.project.pk}):
            self.assertTrue(bounty_gate.Gate().project_blocked(self.project.pk))  # a new sweep reads it again: nothing is kept between sweeps
        self.assertFalse(BountyEngagement.objects.exists())
