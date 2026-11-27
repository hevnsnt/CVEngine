"""The exclusion lists (an organization's excluded hosts, the hosts moved out of a project, the do-not-scan networks) are never cached across calls or
processes: they are read once per batch (``exclusions.memo``) and from the database on every other call, and every way of changing them takes effect on
the very next lookup: a create, an update, a delete (one row, a queryset, a cascade), a bulk insert, a project moving to another organization. A failed
read is never kept, and a lookup made while a change is still uncommitted is dropped when it commits."""
import ipaddress

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import exclusions
from cveFeed.models import ExcludedAddress, HostExclusion, HostMove
from dashboard.models import Org, Project
from cvengine import discovery_events as bbot_lib
from cvengine.tasks import persist_bbot_result
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class Base(TestCase):
	def setUp(self):
		exclusions._bump()
		self.org = Org.objects.create(name='Cache', slug='cache-org')
		self.other = Org.objects.create(name='Other', slug='cache-other')
		self.project = Project.objects.create(name='P', slug='p-cache', insert_date=timezone.now(), org=self.org)
		self.pid = self.project.pk

	def names(self):
		return exclusions.excluded_names(self.pid, names_only=True)


class CacheTests(Base):
	def test_every_call_outside_a_batch_reads_the_database(self):
		HostExclusion.objects.create(org=self.org, host='x.cache.test')
		self.assertIn('x.cache.test', self.names())
		with CaptureQueriesContext(connection) as queries:
			self.assertIn('x.cache.test', self.names())
			exclusions.address_networks(self.pid)
			exclusions.address_networks(self.pid)
		self.assertEqual(len([q for q in queries.captured_queries if 'cvefeed_excludedaddress' in q['sql'].lower()]), 2)
		self.assertEqual(len([q for q in queries.captured_queries if 'cvefeed_hostexclusion' in q['sql'].lower()]), 1)

	def test_the_shared_cache_is_never_read_or_written(self):
		from unittest import mock
		ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		HostExclusion.objects.create(org=self.org, host='c.cache.test')
		with mock.patch('django.core.cache.cache') as shared, mock.patch('django.core.cache.caches') as named:
			self.assertIn('c.cache.test', exclusions.excluded_names(self.pid))
			self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))
		self.assertEqual(shared.mock_calls, [])
		self.assertEqual(named.mock_calls, [])

	def test_inside_a_batch_each_list_is_read_once(self):
		with exclusions.memo(), CaptureQueriesContext(connection) as queries:
			for _ in range(3):
				self.names()
				exclusions.address_networks(self.pid)
		self.assertEqual(len(queries.captured_queries), 3)  # host exclusions, moved hosts, networks

	def test_nothing_of_a_batch_outlives_it(self):
		with exclusions.memo():
			self.assertEqual(exclusions.address_refusals(self.pid, ['198.51.100.7']), {})
		ExcludedAddress.objects.bulk_create([ExcludedAddress(org=self.org, cidr='198.51.100.0/24')])
		with exclusions.memo():
			self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))

	def test_a_change_whose_reset_could_not_be_written_is_still_seen_by_the_next_lookup(self):
		"""With a shared cache, a list change whose reset could not be written (the cache refusing writes) left every process scanning the address for
		up to 30 seconds. Nothing is shared now, so a failed write anywhere changes nothing."""
		from unittest import mock
		from django.core.cache import cache
		self.assertEqual(exclusions.address_refusals(self.pid, ['198.51.100.7']), {})
		with mock.patch.object(cache, 'set', side_effect=RuntimeError('redis refuses writes')):
			ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))

	def test_a_change_made_inside_a_batch_is_seen_by_its_next_lookup(self):
		with exclusions.memo():
			self.assertNotIn('in.cache.test', self.names())
			HostExclusion.objects.create(org=self.org, host='in.cache.test')
			self.assertIn('in.cache.test', self.names())

	def test_a_cache_that_is_down_changes_nothing(self):
		from unittest import mock
		HostExclusion.objects.create(org=self.org, host='down.cache.test')
		with mock.patch('django.core.cache.cache.get', side_effect=RuntimeError('redis down')), \
				mock.patch('django.core.cache.cache.set', side_effect=RuntimeError('redis down')):
			self.assertIn('down.cache.test', self.names())

	def test_a_failed_read_is_never_kept(self):
		from unittest import mock
		ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		with exclusions.memo():
			with mock.patch('cveFeed.models.ExcludedAddress.objects.filter', side_effect=RuntimeError('db')):
				refusal = exclusions.address_refusals(self.pid, ['203.0.113.7'])['203.0.113.7']
			self.assertTrue(refusal.unreadable)  # fail closed, as before
			self.assertEqual(exclusions.address_refusals(self.pid, ['203.0.113.7']), {})  # the next lookup reads the real list
			self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))

	def test_the_inventory_side_is_never_cached(self):
		ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		domain = Domain.objects.create(name='inv.cache.test', project=self.project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.inv.cache.test', target_domain=domain)
		self.assertNotIn('www.inv.cache.test', exclusions.excluded_names(self.pid))
		from startScan.models import IpAddress
		sub.ip_addresses.add(IpAddress.objects.create(address='198.51.100.20', org=self.org))  # a batch resolved it into the list
		self.assertIn('www.inv.cache.test', exclusions.excluded_names(self.pid))
		self.assertIn('www.inv.cache.test', exclusions.address_refusals(self.pid, ['www.inv.cache.test']))


class EveryWriteTakesEffectTests(Base):
	def warm(self):
		self.names()
		exclusions.address_networks(self.pid)

	def test_create_update_and_delete_of_a_host_exclusion(self):
		self.warm()
		row = HostExclusion.objects.create(org=self.org, host='a.cache.test')
		self.assertIn('a.cache.test', self.names())
		row.include_subdomains = True
		row.save(update_fields=['include_subdomains'])
		self.assertIn('deep.a.cache.test', self.names())
		HostExclusion.objects.filter(pk=row.pk).update(host='b.cache.test', include_subdomains=False)
		self.assertNotIn('a.cache.test', self.names())
		self.assertIn('b.cache.test', self.names())
		row.refresh_from_db()
		row.delete()
		self.assertNotIn('b.cache.test', self.names())

	def test_bulk_and_queryset_writes(self):
		self.warm()
		HostExclusion.objects.bulk_create([HostExclusion(org=self.org, host=f'bulk{i}.cache.test') for i in range(3)])
		self.assertIn('bulk2.cache.test', self.names())
		HostExclusion.objects.filter(org=self.org).delete()
		self.assertNotIn('bulk2.cache.test', self.names())
		HostMove.objects.bulk_create([HostMove(project=self.project, host='moved.cache.test')])
		self.assertIn('moved.cache.test', self.names())
		HostMove.objects.filter(project=self.project).update(host='moved2.cache.test')
		self.assertIn('moved2.cache.test', self.names())
		rows = list(HostMove.objects.filter(project=self.project))
		rows[0].host = 'moved3.cache.test'
		HostMove.objects.bulk_update(rows, ['host'])
		self.assertIn('moved3.cache.test', self.names())

	def test_the_host_manage_paths(self):
		self.warm()
		HostExclusion.objects.get_or_create(org=self.org, host='gc.cache.test')
		self.assertIn('gc.cache.test', self.names())
		HostMove.objects.update_or_create(project=self.project, host='uc.cache.test', defaults={'moved_to': None})
		self.assertIn('uc.cache.test', self.names())

	def test_the_address_list(self):
		self.warm()
		self.assertEqual(exclusions.address_refusals(self.pid, ['198.51.100.7']), {})
		row = ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))
		self.assertEqual(exclusions.address_networks(self.pid), (ipaddress.ip_network('198.51.100.0/24'),))
		ExcludedAddress.objects.filter(pk=row.pk).update(cidr='203.0.113.0/24')
		self.assertEqual(exclusions.address_refusals(self.pid, ['198.51.100.7']), {})
		self.assertIn('203.0.113.7', exclusions.address_refusals(self.pid, ['203.0.113.7']))
		ExcludedAddress.objects.filter(pk=row.pk).delete()
		self.assertEqual(exclusions.address_networks(self.pid), ())

	def test_the_admin_api_add_and_remove(self):
		from django.contrib.auth.models import User
		from agentapi import excluded_addresses
		admin = User.objects.create_user('cache-admin', password='x')
		self.warm()
		row, _ = excluded_addresses.add(admin, self.org, '198.51.100.0/24', '', False)
		self.assertIn('198.51.100.7', exclusions.address_refusals(self.pid, ['198.51.100.7']))
		excluded_addresses.remove(admin, self.org, row.pk)
		self.assertEqual(exclusions.address_refusals(self.pid, ['198.51.100.7']), {})

	def test_a_cascade_from_the_organization(self):
		HostExclusion.objects.create(org=self.other, host='org.cache.test')
		ExcludedAddress.objects.create(org=self.other, cidr='198.51.100.0/24')
		project = Project.objects.create(name='Q', slug='q-cache', insert_date=timezone.now(), org=self.other)
		self.assertIn('org.cache.test', exclusions.excluded_names(project.pk, names_only=True))
		self.assertTrue(exclusions.address_networks(project.pk))
		self.other.delete()  # its lists go with it (a cascade); the project is left without an organization
		self.assertNotIn('org.cache.test', exclusions.excluded_names(project.pk, names_only=True))
		self.assertEqual(exclusions.address_networks(project.pk), ())

	def test_a_project_that_moves_to_another_organization(self):
		HostExclusion.objects.create(org=self.other, host='theirs.cache.test')
		self.warm()
		self.assertNotIn('theirs.cache.test', self.names())
		self.project.org = self.other
		self.project.save()
		self.assertIn('theirs.cache.test', self.names())

	def test_a_change_committed_after_a_lookup_in_a_batch_read_the_old_list(self):
		with exclusions.memo():
			with self.captureOnCommitCallbacks(execute=False) as callbacks:
				HostExclusion.objects.create(org=self.org, host='late.cache.test')
			# the batch read the list before the commit (as another connection would see it) and kept that copy
			exclusions._memo.get()[('names', self.pid)] = ()
			self.assertNotIn('late.cache.test', self.names())
			for callback in callbacks:  # the commit
				callback()
			self.assertIn('late.cache.test', self.names())


class IngestAndScanTests(Base):
	def setUp(self):
		super().setUp()
		self.domain = Domain.objects.create(name='ing.cache.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
		self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

	def test_an_exclusion_added_between_two_batches_keeps_the_host_out(self):
		persist_bbot_result(bbot_lib.BbotResult(subdomains={'a.ing.cache.test'}), ctx=dict(self.ctx))
		HostExclusion.objects.create(org=self.org, host='b.ing.cache.test')
		persist_bbot_result(bbot_lib.BbotResult(subdomains={'b.ing.cache.test'}, ports={('b.ing.cache.test', 443)}), ctx=dict(self.ctx))
		self.assertEqual(sorted(Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True)), ['a.ing.cache.test'])

	def test_an_address_added_between_two_streamed_batches_drops_the_next_one(self):
		from types import SimpleNamespace
		from agentapi import address_guard
		task = SimpleNamespace(project_id=self.pid, project=self.project, pk=None, scan_id=self.scan.id, kind='bbot_discovery',
							   target={'domain': 'ing.cache.test'}, host='', ips=[])
		batch = {'http': [{'host': '198.51.100.7', 'url': 'https://198.51.100.7/'}]}
		with exclusions.memo():
			self.assertEqual(address_guard.filter_batch(task, batch)[1], 0)
		ExcludedAddress.objects.create(org=self.org, cidr='198.51.100.0/24')
		with exclusions.memo():
			self.assertEqual(address_guard.filter_batch(task, batch)[1], 1)
		self.assertIsNone(address_guard.task_refusal(task, wait_for_unknown=False))
		self.assertIsNotNone(address_guard.dispatch_refusal(self.project, 'nmap_ports', {'targets': [{'ip': '198.51.100.7'}]}, note=False))
