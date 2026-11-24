"""The database cost of validation and triage: a finding costs a bounded number of queries, a budget reservation is two conditional
UPDATEs that never pass a cap, and a triage pass rewrites only what changed on a row."""
import datetime
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import mock

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import match_policy, triage, validation
from cveFeed.models import CVEMatch, ServiceRun, Triage, ValidationBudget
from startScan.models import Port, Technology
from tests.test_validation import ValidationBase

FINDING_QUERY_CEILING = 52  # one finding with two checks, measured at 49 (66 before); a query per host, address or step would pass it


def _updates(ctx, table):
	return [q['sql'] for q in ctx.captured_queries if q['sql'].startswith('UPDATE') and f'"{table}"' in q['sql']]


class FindingQueryCostTests(ValidationBase):
	def setUp(self):
		super().setUp()
		ValidationBudget.objects.all().delete()

	def cost(self, rows):
		runners, calls = self.runners('no_match')
		with CaptureQueriesContext(connection) as ctx:
			stats, _ = self.run_validation(rows, runners=(runners, calls))
		self.assertEqual(stats['ran'], 2 * len(rows))
		return len(ctx.captured_queries)

	def test_each_finding_costs_a_bounded_number_of_queries(self):
		for n in range(6):
			self.match(name=f'h{n}.v.test')
		rows = sorted(self.rows(), key=lambda r: r.pk)
		self.cost(rows[:1])  # the day's budget rows are made by the first check
		three, more = self.cost(rows[1:4]), self.cost(rows[4:6])
		self.assertLessEqual(three, 3 * FINDING_QUERY_CEILING)
		self.assertLessEqual(more, 2 * FINDING_QUERY_CEILING)
		self.assertLessEqual(abs(three / 3 - more / 2), 2)  # the same per finding, whatever the batch

	def test_the_host_is_read_once_per_finding(self):
		self.match()
		(row,) = self.rows()
		runners, calls = self.runners('no_match')
		with CaptureQueriesContext(connection) as ctx:
			self.run_validation([row], runners=(runners, calls))
		reads = [q['sql'] for q in ctx.captured_queries if q['sql'].startswith('SELECT')]
		self.assertEqual(sum('FROM "startScan_ipaddress"' in s for s in reads), 1)  # was one for the context, one for the subject, one for the probe plan
		self.assertEqual(sum('FROM "startScan_waf"' in s for s in reads), 1)

	def test_the_same_outcome_as_a_finding_described_on_its_own(self):
		match = self.match()
		(row,) = self.rows()
		finding, subject = validation._read_finding(row)
		self.assertIsNotNone(subject)
		alone = triage.load_findings([row])[0]
		self.assertEqual(triage.effective_signature(triage.describe(alone), row.review_nonce), row.signature)
		self.assertEqual(subject, validation.subject_for(row, alone))
		self.assertIsNone(triage._CONTEXT_MEMO.get())  # nothing read for the row outlives it
		self.assertNotIn('_worked_on', finding.__dict__)
		self.assertEqual(finding.pk, match.pk)


class BudgetReservationTests(TestCase):
	def setUp(self):
		ValidationBudget.objects.all().delete()

	def reserve(self, project_id, total, per_project):
		with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_DAY': str(total), 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': str(per_project)}):
			return validation._reserve_validation_check(project_id)

	def reserved(self, scope):
		return ValidationBudget.objects.get(day=validation._today().date(), scope=scope).reserved

	def test_the_project_cap_is_exact(self):
		self.assertEqual([self.reserve(7, 100, 2) for _ in range(4)], [True, True, False, False])
		self.assertEqual((self.reserved('project:7'), self.reserved('global')), (2, 2))

	def test_a_full_global_budget_leaves_the_project_row_unmoved(self):
		self.assertTrue(self.reserve(7, 1, 10))
		self.assertFalse(self.reserve(8, 1, 10))
		self.assertEqual((self.reserved('global'), self.reserved('project:7'), self.reserved('project:8')), (1, 1, 0))

	def test_a_reservation_is_two_updates_and_takes_no_row_lock(self):
		self.reserve(7, 100, 100)
		with CaptureQueriesContext(connection) as ctx:
			self.assertTrue(self.reserve(7, 100, 100))
		sql = [q['sql'] for q in ctx.captured_queries if not q['sql'].startswith(('SAVEPOINT', 'RELEASE'))]
		# the reservation commits durably (usage_stamps.durable_commit): one SET LOCAL first, then the two updates
		self.assertEqual(sql[0], 'SET LOCAL synchronous_commit TO ON', sql)
		sql = sql[1:]
		self.assertEqual(len(sql), 2, sql)
		self.assertTrue(all(s.startswith('UPDATE "cveFeed_validationbudget"') for s in sql))
		self.assertFalse(any('FOR UPDATE' in q['sql'] for q in ctx.captured_queries))

	def test_the_first_reservation_of_the_day_seeds_from_the_runs_already_recorded(self):
		now = timezone.now()
		ServiceRun.objects.create(service='validate:nuclei', asset='a', project_id=None, status='done', finished_at=now)
		ServiceRun.objects.create(service='validate:nuclei', asset='b', project_id=None, status='done', finished_at=now)
		self.assertTrue(self.reserve(7, 3, 10))
		self.assertEqual(self.reserved('global'), 3)
		self.assertFalse(self.reserve(7, 3, 10))  # the seed counts against the cap, as before
		self.assertEqual(self.reserved('project:7'), 1)


@unittest.skipUnless(connection.vendor == 'postgresql', 'requires PostgreSQL row locks')
class BudgetReservationConcurrencyTests(TransactionTestCase):
	def test_many_workers_never_pass_the_cap(self):
		gate = Barrier(8)

		def reserve(project_id):
			close_old_connections()
			try:
				gate.wait(timeout=10)
				return validation._reserve_validation_check(project_id)
			finally:
				close_old_connections()

		with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_DAY': '5', 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '3'}):
			with ThreadPoolExecutor(max_workers=8) as pool:
				futures = [pool.submit(reserve, 201 + n % 2) for n in range(8)]
				admitted = [future.result(timeout=30) for future in futures]
		day = validation._today().date()
		self.assertEqual(admitted.count(True), 5)
		rows = dict(ValidationBudget.objects.filter(day=day).values_list('scope', 'reserved'))
		self.assertEqual(rows['global'], 5)
		self.assertEqual(rows['project:201'] + rows['project:202'], 5)
		self.assertLessEqual(max(rows['project:201'], rows['project:202']), 3)


class TrackWritesTests(ValidationBase):
	def test_an_unchanged_row_is_only_marked_seen(self):
		match = self.match()
		(row,) = self.rows()
		Triage.objects.filter(pk=row.pk).update(last_seen=timezone.now() - datetime.timedelta(days=1))
		with CaptureQueriesContext(connection) as ctx:
			triage.track(triage.with_cves(CVEMatch.objects.filter(pk=match.pk).select_related('subdomain__target_domain')))
		writes = _updates(ctx, 'cveFeed_triage')
		self.assertEqual(len(writes), 1, writes)
		self.assertIn('SET "last_seen"', writes[0])
		self.assertNotIn('validation_steps', writes[0])
		self.assertNotIn('CASE', writes[0])
		after = Triage.objects.get(pk=row.pk)
		self.assertGreater(after.last_seen, timezone.now() - datetime.timedelta(minutes=5))
		self.assertEqual((after.signature, after.classification, after.validation_status, after.updated_at),
						 (row.signature, row.classification, row.validation_status, row.updated_at))

	def test_a_change_made_while_the_pass_runs_is_not_written_back(self):
		match = self.match()
		(row,) = self.rows()
		fetch = triage._fetch

		def fetch_then_a_person_acts(fk, ids):
			rows = fetch(fk, ids)
			Triage.objects.filter(pk__in=[r.pk for r in rows.values()]).update(
				classification='false_positive', reason='a person said so', validation_status='hit')
			return rows
		with mock.patch('cveFeed.triage._fetch', side_effect=fetch_then_a_person_acts):
			triage.track(triage.with_cves(CVEMatch.objects.filter(pk=match.pk).select_related('subdomain__target_domain')))
		after = Triage.objects.get(pk=row.pk)
		self.assertEqual((after.classification, after.reason, after.validation_status), ('false_positive', 'a person said so', 'hit'))

	def test_a_rereview_writes_only_what_a_fresh_review_sets(self):
		with mock.patch('cveFeed.triage.hard_evidence', return_value=(False, [])):
			fields = triage._rereview_fields({'signature': 's', 'evidence_key': 'e', 'kind': 'cve_match', 'facts': {}}, timezone.now())
		self.assertEqual(set(fields), set(triage._REREVIEW_FIELDS))


class SightingTests(ValidationBase):
	def sighted(self, name, source, evidence):
		m = self.match(name=name, source=source)
		m.evidence = evidence
		m.save(update_fields=['evidence'])
		return m

	def test_primed_sightings_answer_as_the_database_does_without_a_query_each(self):
		tech = Technology.objects.create(name='nginx:1.18.0')
		port = Port.objects.create(number=443, product='nginx', cpe='cpe:/a:nginx:nginx:1.18.0')
		matches = [self.sighted('a.v.test', 'tech', {'source': 'tech', 'source_id': tech.pk}),
				   self.sighted('b.v.test', 'port', {'source': 'port', 'source_id': port.pk, 'cpe': 'x'}),
				   self.sighted('c.v.test', 'tech', {'source': 'tech', 'source_id': tech.pk + 999}),
				   self.sighted('d.v.test', 'port', {})]
		alone = [match_policy.sighting_of(m) for m in matches]
		match_policy.prime_sightings(matches)
		with CaptureQueriesContext(connection) as ctx:
			primed = [match_policy.sighting_of(m) for m in matches]
		self.assertEqual(primed, alone)
		self.assertEqual(len(ctx.captured_queries), 0)
		match_policy.forget_primed(matches)
		self.assertFalse(any('_sighted' in m.__dict__ for m in matches))

	def test_a_primed_sighting_of_other_evidence_is_not_used(self):
		tech = Technology.objects.create(name='nginx:1.18.0')
		other = Technology.objects.create(name='apache:2.4.1')
		m = self.sighted('a.v.test', 'tech', {'source': 'tech', 'source_id': tech.pk})
		match_policy.prime_sightings([m])
		m.evidence = {'source': 'tech', 'source_id': other.pk}
		self.assertEqual(match_policy.sighting_of(m)[0], 'apache')
