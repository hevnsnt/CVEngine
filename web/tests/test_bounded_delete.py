"""Bounded deletes (cveFeed.bounded_delete): a project, organization, target, scan or host is removed in batches of their own transactions,
and that removes exactly the rows (and screenshot files) one Django delete removed, keeps every other row as it was, never puts more than
a batch in one statement, and leaves a state that the same delete run again finishes when it fails part way."""
import json
from datetime import timedelta
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, OperationalError, connection, transaction
from django.db.models import QuerySet
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import host_manage as hm
from agentapi import services as svc
from agentapi.models import SentinelTask
from cveFeed import admin_api, bounded_delete, scan_retention
from cveFeed.models import (AgentActivity, CVEEntry, CVEMatch, DiscoveryEvent, FindingAuditEvent, FindingComment, HostScreenshot, HostState,
                            ServiceRun, Triage)
from dashboard.models import AuditLog, Org, Project
from startScan.models import EndPoint, ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_host_manage import Base

IGNORED = {'dashboard.AuditLog', 'cveFeed.HostExclusion'}  # written by the operation itself, compared on their own


def snapshot():
	"""Every row of every table as comparable text, so a test can compare the whole database after two ways of deleting."""
	rows = {}
	for model in apps.get_models(include_auto_created=True):
		if model._meta.proxy or not model._meta.managed or model._meta.label in IGNORED:
			continue
		fields = [f.attname for f in model._meta.concrete_fields]
		rows[model._meta.label] = sorted(repr(r) for r in model._base_manager.order_by().values_list(*fields))
	return rows


class Fixture(Base):
	def setUp(self):
		super().setUp()
		self.removed = []  # screenshot rows whose files the post_delete hook removed
		patcher = mock.patch('cveFeed.web_shot.remove_row_files', side_effect=lambda row: self.removed.append(row.pk))
		patcher.start()
		self.addCleanup(patcher.stop)
		self.cve, _ = CVEEntry.objects.get_or_create(cve_id='CVE-2099-0042')

	def fill(self, project, target, scans=2, hosts=('www', 'api', 'mail'), age=timedelta(0), notes=True):
		"""A target with ``scans`` scans, each with its own copy of every host and the rows hanging off it, plus the project's per-host
		rows and activity. Returns the target and its scans."""
		now = timezone.now()
		d = Domain.objects.create(name=target, project=project, insert_date=now)
		made = []
		for i in range(scans):
			scan = ScanHistory.objects.create(domain=d, scan_type=self.engine, start_scan_date=now - age - timedelta(days=scans - i),
				scan_status=2, results_dir='/tmp')
			made.append(scan)
			for n in range(3):
				ScanActivity.objects.create(scan_of=scan, title=f't{n}', name='nuclei_scan', time=now, status=2)
			SentinelTask.objects.create(project=project, scan=scan, kind='nmap', host=target)
			ServiceRun.objects.create(project=project, scan=scan, service='nmap-fast', asset=f'{target}#{i}')  # SET_NULL: stays, its scan cleared
			for h in hosts:
				name = f'{h}.{target}'
				s = Subdomain.objects.create(target_domain=d, scan_history=scan, name=name)
				e = EndPoint.objects.create(subdomain=s, target_domain=d, scan_history=scan, http_url=f'https://{name}/')
				v = Vulnerability.objects.create(name='F', severity=3, subdomain=s, endpoint=e, target_domain=d, scan_history=scan,
					http_url=f'https://{name}/x')
				m = CVEMatch.objects.create(cve_entry=self.cve, subdomain=s, scan_history=scan)
				Triage.objects.create(project=project, domain=d, host=name, kind='nuclei', vulnerability=v, status='triaged')
				Triage.objects.create(project=project, domain=d, host=name, kind='cve_match', match=m, status='triaged')
				for kind, fid in (('vulnerability', v.pk), ('match', m.pk)) if notes else ():
					FindingComment.objects.create(project=project, finding_kind=kind, finding_id=fid, text='note')
					FindingAuditEvent.objects.create(project=project, finding_kind=kind, finding_id=fid, event='status')
				DiscoveryEvent.objects.create(scan=scan, domain=d, type='DNS_NAME', host=name)
		for h in hosts:
			name = f'{h}.{target}'
			HostState.objects.create(project=project, domain=d, host=name)
			HostScreenshot.objects.create(project=project, domain=d, host=name, image_path=f'screenshots/{project.pk}/{name}/a.png')
		for n in range(5):
			AgentActivity.objects.create(kind='scan', message=f'm{n}', project=project)
		return d, made

	def expected(self, fn):
		"""The database (and the screenshot files removed) after ``fn``, which is then rolled back."""
		start = len(self.removed)
		with transaction.atomic():
			result = fn()
			rows = snapshot()
			transaction.set_rollback(True)
		removed = sorted(self.removed[start:])
		del self.removed[start:]
		return rows, removed, result

	def assertSameDatabase(self, rows, removed):
		connection.check_constraints()  # no row was left pointing at a deleted one
		now = snapshot()
		for label in sorted(set(rows) | set(now)):
			self.assertEqual(now.get(label), rows.get(label), label)
		self.assertEqual(sorted(self.removed), removed)

	def request(self, confirm, **extra):
		return RequestFactory().post('/x', data=json.dumps({'confirm': confirm, **extra}), content_type='application/json')


class PlanTests(Fixture):
	def test_the_plan_follows_only_cascade_keys_and_lists_children_before_parents(self):
		plan = bounded_delete.plan(ScanHistory)
		paths = dict(plan)
		order = [m for m, _ in plan]
		self.assertEqual(paths[CVEMatch], 'subdomain__scan_history')  # never through the SET_NULL key a scan holds on a match
		self.assertNotIn(ServiceRun, paths)  # SET_NULL: the run stays, its scan is cleared by the final delete
		self.assertNotIn(ScanHistory, paths)
		for child, parent in ((Vulnerability, Subdomain), (EndPoint, Subdomain), (Triage, Vulnerability), (Triage, CVEMatch),
				(Vulnerability, EndPoint)):
			self.assertLess(order.index(child), order.index(parent), (child, parent))
		kept = dict(bounded_delete.plan(Domain, keep=(ScanHistory,)))
		self.assertNotIn(ScanHistory, kept)
		self.assertEqual(kept[ScanActivity], 'scan_of__domain')  # what is under a kept model is still drained
		self.assertEqual(dict(bounded_delete.plan(Domain, only=(ScanActivity,))), {ScanActivity: 'scan_of__domain'})

	def test_each_batch_is_its_own_bounded_statement(self):
		_, scans = self.fill(self.a1, 'big.test', scans=1)
		qs = ScanActivity.objects.filter(scan_of=scans[0])
		ScanActivity.objects.bulk_create([ScanActivity(scan_of=scans[0], title='x', name='n', time=timezone.now(), status=2) for _ in range(2)])
		self.assertEqual(qs.count(), 5)
		with CaptureQueriesContext(connection) as ctx:
			out = bounded_delete.drain(qs, batch=2)
		deletes = [q['sql'] for q in ctx.captured_queries if q['sql'].startswith('DELETE FROM "startScan_scanactivity"')]
		self.assertEqual((out['rows'], len(deletes)), (5, 3))
		reads = [q['sql'] for q in ctx.captured_queries if q['sql'].startswith('SELECT "startScan_scanactivity"."id"')]
		self.assertTrue(reads and all(sql.endswith('LIMIT 2') for sql in reads), reads)
		self.assertFalse(qs.exists())
		# a model with post_delete receivers is loaded whole by Django's collector: one batch at a time, never every row at once
		subs = Subdomain.objects.filter(target_domain__name='big.test')
		with CaptureQueriesContext(connection) as ctx:
			bounded_delete.drain(subs, batch=2)
		deletes = [q['sql'] for q in ctx.captured_queries if q['sql'].startswith('DELETE FROM "startScan_subdomain" WHERE')]
		self.assertEqual(len(deletes), 2)
		self.assertTrue(all(sql.count(',') < 2 for sql in deletes), deletes)  # at most two ids each
		self.assertFalse(subs.exists())

	def test_a_batch_a_scan_got_in_the_way_of_is_read_and_tried_again_and_counted_once(self):
		self.fill(self.a1, 'retry.test', scans=1)
		calls = []

		def before(ids):
			calls.append(list(ids))
			if len(calls) == 1:
				raise IntegrityError('still referenced')
			return {'seen': len(ids)}
		with mock.patch.object(bounded_delete.time, 'sleep') as slept:
			out = bounded_delete.drain(Subdomain.objects.filter(target_domain__name='retry.test'), batch=2, before=before, attempts=3, pause=2)
		self.assertEqual(out, {'rows': 3, 'seen': 3})
		self.assertEqual(slept.call_count, 1)
		with self.assertRaises(IntegrityError):
			bounded_delete.drain(ScanActivity.objects.all(), before=mock.Mock(side_effect=IntegrityError('x')), attempts=2)


class EquivalenceTests(Fixture):
	def setUp(self):
		super().setUp()
		self.fill(self.a1, 'one.test')
		self.fill(self.a1, 'two.test')
		self.fill(self.a2, 'kept.test')
		self.fill(self.b1, 'other.test')

	def test_a_project_delete_removes_the_same_rows_and_files_as_one_cascade(self):
		rows, removed, _ = self.expected(lambda: Project.objects.get(pk=self.a1.pk).delete())
		with mock.patch.object(bounded_delete, 'BATCH', 2):
			out = admin_api.projects_delete(self.request('A1'), self.admin, self.a1.pk)
		self.assertEqual(out, {'deleted': True})
		self.assertSameDatabase(rows, removed)
		self.assertEqual(len(removed), 6)
		self.assertTrue(AuditLog.objects.filter(action='project.delete', target='A1').exists())

	def test_an_organization_delete_removes_the_same_rows_as_one_cascade(self):
		root = type(self.admin).objects.create_superuser('root', password='x')

		def old():
			for project in Project.objects.filter(org=self.org_a):
				project.delete()
			Org.objects.get(pk=self.org_a.pk).delete()
		rows, removed, _ = self.expected(old)
		out = admin_api.orgs_delete(self.request('A', delete_projects=True), root, self.org_a.pk)
		self.assertEqual(out, {'deleted': True, 'projects_deleted': 2})
		self.assertSameDatabase(rows, removed)
		self.assertTrue(AuditLog.objects.filter(action='org.delete', target='A').exists())
		self.assertTrue(Project.objects.filter(pk=self.b1.pk).exists())

	def test_deleting_targets_removes_the_same_rows_and_result_directories(self):
		ids = list(Domain.objects.filter(project=self.a1).values_list('id', flat=True))
		dirs = sorted(list(Domain.objects.filter(pk__in=ids).values_list('name', flat=True))
			+ [f'{n}_{sid}' for sid, n in ScanHistory.objects.filter(domain_id__in=ids).values_list('id', 'domain__name')])
		rows, removed, _ = self.expected(lambda: Domain.objects.filter(pk__in=ids).delete())
		with mock.patch('reNgine.common_func.safe_remove_path') as rm, mock.patch.object(bounded_delete, 'BATCH', 2):
			out = svc.delete_targets(self.ctx(self.admin), 'a1', ids=ids)
		self.assertEqual(out['deleted'], 3)  # one.test, two.test and the fixture's own target
		self.assertSameDatabase(rows, removed)
		self.assertEqual(sorted(c.args[0].rsplit('/', 1)[-1] for c in rm.call_args_list), dirs)

	def test_scan_retention_removes_the_same_rows_as_deleting_each_scan(self):
		now = timezone.now()
		d, scans = self.fill(self.a1, 'old.test', scans=5, age=timedelta(days=400), notes=False)  # nobody worked on them
		current = ScanHistory.objects.create(domain=d, scan_type=self.engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
		Subdomain.objects.create(target_domain=d, scan_history=current, name='www.old.test')
		gone = [s.pk for s in scans[:3]]  # the current scan and the two newest old ones stay

		def old():
			for pk in gone:
				ScanHistory.objects.filter(pk=pk).delete()
		rows, removed, _ = self.expected(old)
		with mock.patch.object(bounded_delete, 'BATCH', 2):
			out = scan_retention.run(now, days=180)
		self.assertEqual(out, {'days': 180, 'scans': 3, 'complete': True})
		self.assertSameDatabase(rows, removed)

	def test_deleting_a_host_removes_the_same_rows_and_reports_the_same_counts(self):
		name = 'www.one.test'
		first, second = Subdomain.objects.filter(name=name).order_by('id')[:2]
		# a finding on the later copy reached through an endpoint of the earlier one, and a bare-host finding the same way: a batch
		# that takes them must still count them and clear their notes, as the single delete did
		cross = Vulnerability.objects.create(name='X', severity=2, subdomain=second, endpoint=EndPoint.objects.filter(subdomain=first).first(),
			target_domain=first.target_domain, scan_history=second.scan_history, http_url=f'https://{name}/y')
		bare = Vulnerability.objects.create(name='B', severity=2, subdomain=None, endpoint=EndPoint.objects.filter(subdomain=first).first(),
			target_domain=first.target_domain, scan_history=first.scan_history, http_url=f'https://{name}/z')
		for fid in (cross.pk, bare.pk):
			FindingComment.objects.create(project=self.a1, finding_kind='vulnerability', finding_id=fid, text='note')
		rows, removed, (counts, _) = self.expected(lambda: hm._purge(self.a1, name))
		with mock.patch.object(hm, 'DRAIN_BATCH', 1):
			out = hm.delete_host(self.ctx(self.admin), 'a1', name)
		self.assertSameDatabase(rows, removed)
		for key, value in counts.items():
			self.assertEqual(out[key], value, key)
		self.assertEqual((out['hosts'], out['findings']), (2, 4))
		self.assertTrue(AuditLog.objects.filter(action='host.delete').exists())

	def test_excluding_a_whole_domain_removes_the_same_rows_and_reports_the_same_counts(self):
		def old():
			return [hm._purge(p, 'one.test', True) for p in (self.a1, self.a2)]
		rows, removed, parts = self.expected(old)
		with mock.patch.object(hm, 'DRAIN_BATCH', 2), mock.patch.object(bounded_delete, 'BATCH', 2):
			out = hm.exclude_host(self.ctx(self.admin), 'a1', 'one.test', include_subdomains=True)
		self.assertSameDatabase(rows, removed)
		before = [{'project': p.slug, **counts} for p, (counts, _) in zip((self.a1, self.a2), parts) if any(v for v in counts.values())]
		self.assertEqual(out['projects'], before)
		self.assertEqual((out['hosts_removed'], out['targets_removed']), (6, 1))


class FailureTests(Fixture):
	def setUp(self):
		super().setUp()
		self.fill(self.a1, 'one.test')
		self.fill(self.a2, 'kept.test')

	def failing_delete(self, after):
		"""``QuerySet.delete`` that fails like a statement timeout on its ``after``-th call."""
		real, calls = QuerySet.delete, []

		def delete(qs):
			calls.append(qs.model)
			if len(calls) == after:
				raise OperationalError('canceling statement due to statement timeout')
			return real(qs)
		return mock.patch.object(QuerySet, 'delete', autospec=True, side_effect=delete)

	def test_a_project_delete_that_fails_part_way_keeps_its_work_and_a_second_run_finishes(self):
		rows, removed, _ = self.expected(lambda: Project.objects.get(pk=self.a1.pk).delete())
		total = lambda: sum(len(v) for v in snapshot().values())  # noqa: E731
		before = total()
		with mock.patch.object(bounded_delete, 'BATCH', 2), self.failing_delete(after=4):
			with self.assertRaises(OperationalError):
				admin_api.projects_delete(self.request('A1'), self.admin, self.a1.pk)
		connection.check_constraints()  # consistent: nothing points at a deleted row
		self.assertTrue(Project.objects.filter(pk=self.a1.pk).exists())  # the project and its audit row come last, together
		self.assertFalse(AuditLog.objects.filter(action='project.delete').exists())
		self.assertLess(total(), before)  # the batches before the failure stay done
		admin_api.projects_delete(self.request('A1'), self.admin, self.a1.pk)
		self.assertSameDatabase(rows, removed)
		self.assertEqual(AuditLog.objects.filter(action='project.delete').count(), 1)

	def test_a_host_delete_that_fails_part_way_is_finished_by_running_it_again(self):
		name = 'www.one.test'
		rows, removed, _ = self.expected(lambda: hm._purge(self.a1, name))
		# a batch makes five deletes (the notes and audit events of its findings and matches, then the copy): the seventh is in the second
		with mock.patch.object(hm, 'DRAIN_BATCH', 1), self.failing_delete(after=7):
			with self.assertRaises(OperationalError):
				hm.delete_host(self.ctx(self.admin), 'a1', name)
		connection.check_constraints()
		self.assertEqual(Subdomain.objects.filter(name=name).count(), 1)  # one copy went, with its notes; the other is still whole
		self.assertEqual(FindingComment.objects.filter(project=self.a1).count(), 12 - 2)
		hm.delete_host(self.ctx(self.admin), 'a1', name)
		self.assertSameDatabase(rows, removed)
