"""A probe task carries the organization's do-not-scan list to its scanner (``probe_scope.blocked_networks``).

The server checks a probe task's names against the addresses the inventory knows when it makes the task. The Sentinel resolves the names again when
it connects and follows redirects; it refuses every address in the policy's ``blocked`` at every hop. Before, ``blocked`` held only the server's own
``CVENGINE_BLOCKED_CIDRS``, so a listed host whose name now resolved into the do-not-scan list (or a redirect to one) was reached. Every policy builder
now carries the list; a list that cannot be read, or one too long for the contract's bound, makes no task.

Addresses are documentation ranges only and the names are example names."""
import ipaddress
from unittest import mock

from django.test import TestCase
from django.utils import timezone
from jsonschema import Draft202012Validator

from agentapi import sentinel_contract
from cveFeed import exclusions, probe_scope
from cveFeed.models import ExcludedAddress
from cvengine.resources import AddressExcluded
from dashboard.models import Org, Project


def scope_schema():
    doc = sentinel_contract.load()
    return {'$schema': doc['$schema'], '$ref': '#/$defs/probe_scope', '$defs': doc['$defs']}


class Base(TestCase):
    def setUp(self):
        self.org = Org.objects.create(name='Blocked', slug='blocked-org')
        self.project = Project.objects.create(name='B', slug='blocked-p', insert_date=timezone.now(), org=self.org)
        self.pid = self.project.pk

    def listed(self, *cidrs):
        for cidr in cidrs:
            ExcludedAddress.objects.create(org=self.org, cidr=cidr)

    def builders(self):
        """Every policy builder that takes plain names or addresses, called the way its stage calls it: ``{name: policy}``."""
        pid, names, addresses = self.pid, ['www.example.com'], ['192.0.2.10']
        out = {
            'for_hosts': probe_scope.for_hosts(pid, names),
            'for_signed_routes': probe_scope.for_signed_routes(pid, names),
            'for_addresses': probe_scope.for_addresses(pid, addresses),
            'for_ssh': probe_scope.for_ssh(pid, addresses),
            'for_buckets': probe_scope.for_buckets(pid, []),
            'for_dangling': probe_scope.for_dangling(pid, names),
            'for_suppliers': probe_scope.for_suppliers(pid, ['example.com']),
            'for_vhosts': probe_scope.for_vhosts(pid, addresses, names),
            'for_subdirs': probe_scope.for_subdirs(pid, names),
            'for_hygiene': probe_scope.for_hygiene(pid, [], names),
        }
        shots = probe_scope.for_screenshots(pid, names)
        out['for_screenshots'] = shots[0] if isinstance(shots, tuple) else shots
        return out


class BlockedCarriesTheList(Base):
    def test_every_builder_carries_the_list_and_stays_in_contract(self):
        self.listed('198.51.100.0/24', '2001:db8:dead::/48')
        validator = Draft202012Validator(scope_schema())
        for name, policy in self.builders().items():
            with self.subTest(builder=name):
                self.assertIn('198.51.100.0/24', policy['blocked'])
                self.assertIn('2001:db8:dead::/48', policy['blocked'])
                self.assertEqual([e.message for e in validator.iter_errors(policy)], [])

    def test_with_no_list_only_the_servers_own_ranges_travel(self):
        with mock.patch.dict('os.environ', {'CVENGINE_BLOCKED_CIDRS': '203.0.113.0/24'}):
            self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], ['203.0.113.0/24'])
        self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], [])

    def test_neighbouring_and_nested_networks_are_merged(self):
        self.listed('198.51.100.0/25', '198.51.100.128/25', '198.51.100.7/32')
        with mock.patch.dict('os.environ', {'CVENGINE_BLOCKED_CIDRS': '198.51.100.0/24'}):
            self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], ['198.51.100.0/24'])

    def test_another_organizations_list_never_travels(self):
        other = Org.objects.create(name='Other', slug='blocked-other')
        ExcludedAddress.objects.create(org=other, cidr='198.51.100.0/24')
        self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], [])

    def test_a_list_added_after_a_policy_was_built_is_in_the_next_one(self):
        self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], [])
        self.listed('198.51.100.0/24')
        self.assertEqual(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked'], ['198.51.100.0/24'])


class FailsClosed(Base):
    def test_a_list_that_cannot_be_read_makes_no_policy(self):
        with mock.patch('cveFeed.models.ExcludedAddress.objects.filter', side_effect=RuntimeError('database gone')):
            for name in ('for_hosts', 'for_ssh', 'for_vhosts'):
                with self.subTest(builder=name), self.assertRaises(AddressExcluded) as raised:
                    self.builders()
                self.assertTrue(raised.exception.refusal.unreadable)

    def test_more_networks_than_a_policy_can_carry_makes_no_policy(self):
        spread = [str(ipaddress.ip_network(f'10.{i}.0.0/24')) for i in range(probe_scope.MAX_BLOCKED + 1)]  # not neighbours: nothing merges
        for cidr in spread:
            ExcludedAddress.objects.create(org=self.org, cidr=cidr)
        with self.assertRaises(AddressExcluded) as raised:
            probe_scope.for_hosts(self.pid, ['www.example.com'])
        self.assertIn('more than the', str(raised.exception))

    def test_exactly_the_bound_is_carried(self):
        for i in range(probe_scope.MAX_BLOCKED):
            ExcludedAddress.objects.create(org=self.org, cidr=f'10.{i}.0.0/24')
        self.assertEqual(len(probe_scope.for_hosts(self.pid, ['www.example.com'])['blocked']), probe_scope.MAX_BLOCKED)

    def test_the_bound_is_the_contracts(self):
        self.assertEqual(scope_schema()['$defs']['probe_scope']['properties']['blocked']['maxItems'], probe_scope.MAX_BLOCKED)
        self.assertLessEqual(exclusions.MAX_ENTRIES, 500)
