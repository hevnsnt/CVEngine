from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import nuclei_scan, tasks
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


class FeedSyncBatchingTests(TestCase):
	def test_matched_existing_advisory_refreshes_and_only_material_change_recorrelates(self):
		import datetime
		from targetApp.models import Domain
		project = Project.objects.create(name='R', slug='ref', insert_date=timezone.now(), org=Org.objects.create(name='R', slug='ref'))
		domain = Domain.objects.create(name='ref.test', project=project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.ref.test', target_domain=domain)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-9000', affected=[{'product': 'nginx'}], original_description='old')
		CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='tech')
		CVEEntry.objects.filter(pk=cve.pk).update(synced_at=timezone.now() - datetime.timedelta(days=2))
		client = mock.Mock()
		client.iter_entries.return_value = iter([])
		client.get_entry.return_value = {'id': cve.cve_id, 'affected': [{'product': 'nginx'}], 'originalDescription': 'old'}
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.correlate_refreshed_cves.delay') as queued:
			out = tasks.sync_cve_now_feed()
		self.assertEqual((out['refreshed'], out['changed']), (1, 0))
		queued.assert_not_called()
		CVEEntry.objects.filter(pk=cve.pk).update(synced_at=timezone.now() - datetime.timedelta(days=2))
		client.iter_entries.return_value = iter([])
		client.get_entry.return_value = {'id': cve.cve_id, 'affected': [{'product': 'nginx', 'ranges': [{'fixed': '1.20'}]}],
			'originalDescription': 'old'}
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.correlate_refreshed_cves.delay') as queued:
			out = tasks.sync_cve_now_feed()
		self.assertEqual((out['refreshed'], out['changed']), (1, 1))
		self.assertTrue(CVEEntry.objects.get(pk=cve.pk).needs_recorrelation)
		queued.assert_called_once()
	def test_known_ids_are_checked_in_batches(self):
		for n in range(250):
			CVEEntry.objects.create(cve_id=f'CVE-2099-{n}', affected=[])
		client = mock.Mock()
		client.iter_entries.return_value = iter([{'id': f'CVE-2099-{n}'} for n in range(250)])
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), CaptureQueriesContext(connection) as ctx:
			out = tasks.sync_cve_now_feed(catch_up_after=1000, max_scan=250)
		self.assertEqual((out['seen'], out['skipped'], out['created']), (250, 250, 0))
		lookups = [q for q in ctx if '"cve_id" IN' in q['sql']]
		self.assertEqual(len(lookups), 3)  # 100 + 100 + 50, not 250
		client.get_entry.assert_not_called()

	def test_new_entries_are_still_fetched_and_the_catch_up_stop_still_applies(self):
		for n in range(5):
			CVEEntry.objects.create(cve_id=f'CVE-2099-{n}', affected=[])
		summaries = [{'id': 'CVE-2099-900'}] + [{'id': f'CVE-2099-{n}'} for n in range(5)] + [{'id': 'CVE-2099-901'}]
		client = mock.Mock()
		client.iter_entries.return_value = iter(summaries)
		client.get_entry.side_effect = lambda cid: {'id': cid, 'title': 't'}
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.auto_fire_new_cves.delay'):
			out = tasks.sync_cve_now_feed(catch_up_after=3)
		self.assertEqual(out['created'], 1)  # stopped after three known in a row, before the last id
		self.assertEqual([c.args[0] for c in client.get_entry.call_args_list], ['CVE-2099-900'])


class LightPassBatchingTests(TestCase):
	def test_technology_rows_are_cached_and_links_bulk_created(self):
		now = timezone.now()
		project = Project.objects.create(name='B', slug='pb', insert_date=now, org=Org.objects.create(name='B', slug='b'))
		domain = Domain.objects.create(name='batch.test', project=project, insert_date=now)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=1, start_scan_date=now)
		hosts = []
		for i in range(30):
			sub = Subdomain.objects.create(name=f'h{i}.batch.test', target_domain=domain, scan_history=scan)
			sub.ip_addresses.add(IpAddress.objects.create(address=f'198.51.100.{i + 1}'))
			hosts.append(sub.name)
		lines = [{'host': f'https://{h}', 'template-id': 'tech-detect', 'matcher-name': tech}
			for h in hosts for tech in ('nginx', 'php', 'wordpress')]
		with CaptureQueriesContext(connection) as ctx:
			out = nuclei_scan.run_light_nuclei(scan.id, stream=lambda path, **k: iter(lines))
		self.assertEqual(out['hosts'], 30)
		self.assertEqual(sorted(Technology.objects.values_list('name', flat=True)), ['nginx', 'php', 'wordpress'])
		self.assertEqual(Subdomain.technologies.through.objects.count(), 90)
		inserts = [q for q in ctx if q['sql'].startswith('INSERT INTO "startScan_subdomain_technologies"')]
		self.assertEqual(len(inserts), 1)
		self.assertLess(len([q for q in ctx if 'startScan_technology' in q['sql']]), 10)  # 90 get_or_creates before
		self.assertEqual(sorted(out['techs']['h0.batch.test']), ['nginx', 'php', 'wordpress'])
