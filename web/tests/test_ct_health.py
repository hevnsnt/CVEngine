"""Whether the certificate transparency watch works, per source: the daily rollup every real lookup writes, the line on the Timings page
and in get_system_status, and the ct_watch_stalled notice. No test reaches crt.sh or Cert Spotter: every request is mocked."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import ct_health, ctmonitor, reviewer
from cveFeed.models import AdminAlert, CtLookupDay
from tests.test_ct_fallback import FallbackTestCase, Router, issuance, reply


class RollupTests(FallbackTestCase):
	def test_each_lookup_is_counted_for_the_source_that_answered_or_failed(self):
		self.run_with(Router(crtsh=[reply(502)], certspotter=[reply(200, [issuance('www.fallback.test', 'api.fallback.test')])]))
		self.run_with(Router(crtsh=[reply(200, [{'name_value': 'www.fallback.test'}, {'name_value': 'mail.fallback.test'}])]))
		reset = Router(crtsh=[reply(502)], certspotter=[reply(503)])
		self.run_with(reset)
		rows = {r.source: r for r in CtLookupDay.objects.all()}
		self.assertEqual(set(rows), {'crt.sh', 'certspotter'})
		crt, spotter = rows['crt.sh'], rows['certspotter']
		self.assertEqual((crt.ok, crt.failed, crt.names, crt.new_hosts), (1, 2, 2, 1))
		self.assertEqual(crt.last_error, f'HTTP 502 after {ctmonitor.MAX_ATTEMPTS} attempts')
		self.assertEqual((spotter.ok, spotter.failed, spotter.names, spotter.new_hosts), (1, 1, 2, 2))
		self.assertEqual(spotter.last_error, f'HTTP 503 after {ctmonitor.CERTSPOTTER_ATTEMPTS} attempts')
		self.assertIsNotNone(spotter.last_ok_at)
		self.assertEqual(CtLookupDay.objects.count(), 2)  # one row per source and day, however many lookups

	def test_a_lookup_held_by_pacing_is_counted_as_busy(self):
		ctmonitor.reserve_slot(500)  # crt.sh's shared pacing: the next free slot is 500 seconds away
		with mock.patch.object(ctmonitor.requests, 'get') as get, self.assertRaises(ctmonitor.CtBusy):
			ctmonitor.run_ct_watch(self.domain.id)
		get.assert_not_called()
		row = CtLookupDay.objects.get(source='crt.sh')
		self.assertEqual((row.ok, row.failed, row.busy), (0, 0, 1))

	def test_an_injected_fetch_is_not_a_lookup_and_writes_nothing(self):
		ctmonitor.run_ct_watch(self.domain.id, fetch=lambda name: {'x.fallback.test'})
		self.assertFalse(CtLookupDay.objects.exists())

	def test_rows_are_kept_a_bounded_number_of_days(self):
		today = timezone.now().date()
		CtLookupDay.objects.create(day=today - timedelta(days=ct_health.KEEP_DAYS + 5), source='crt.sh', ok=3)
		CtLookupDay.objects.create(day=today - timedelta(days=2), source='crt.sh', ok=3)
		ct_health.record('crt.sh', 'ok', names=1)
		self.assertEqual(sorted(CtLookupDay.objects.values_list('day', flat=True)), [today - timedelta(days=2), today])

	def test_a_monitoring_write_never_fails_the_lookup(self):
		with mock.patch('cveFeed.models.CtLookupDay.objects') as rows:
			rows.filter.side_effect = RuntimeError('database gone')
			ct_health.record('crt.sh', 'ok')  # no exception


class SummaryLineTests(TestCase):
	def test_the_line_says_when_and_which_source_last_answered_and_todays_counts(self):
		now = timezone.now()
		CtLookupDay.objects.create(day=now.date(), source='crt.sh', ok=12, failed=3, new_hosts=0, last_ok_at=now - timedelta(minutes=4),
		                           last_attempt_at=now)
		out = ct_health.summary(now)
		self.assertEqual(out['line'], 'Certificate Transparency: last successful lookup 4 minutes ago (crt.sh), 12 lookups ok, 3 failed, 0 new hosts today')
		self.assertEqual(out['last_ok_source'], 'crt.sh')
		self.assertEqual(out['totals'], {'ok': 12, 'failed': 3, 'busy': 0, 'new_hosts': 0})

	def test_the_line_names_the_fallback_when_it_answered(self):
		now = timezone.now()
		CtLookupDay.objects.create(day=now.date(), source='crt.sh', failed=2, last_attempt_at=now)
		CtLookupDay.objects.create(day=now.date(), source='certspotter', ok=1, new_hosts=1, last_ok_at=now - timedelta(hours=2), last_attempt_at=now)
		self.assertEqual(ct_health.summary(now)['line'], 'Certificate Transparency: last successful lookup 2 hours ago (certspotter), 1 lookup ok, '
		                                                 '2 failed, 1 new host today (1 answered by certspotter)')

	def test_nothing_yet(self):
		self.assertEqual(ct_health.summary()['line'], 'Certificate Transparency: no lookup yet, 0 lookups ok, 0 failed, 0 new hosts today')


class StalledAlertTests(TestCase):
	def setUp(self):
		cache.clear()
		self.addCleanup(cache.clear)
		self.now = timezone.now()

	def row(self, source, **fields):
		return CtLookupDay.objects.create(day=self.now.date(), source=source, **fields)

	def test_nothing_attempted_is_ok(self):
		self.assertEqual(ct_health.stalled_check(self.now)['state'], 'ok')
		self.row('crt.sh', failed=5, last_attempt_at=self.now - timedelta(hours=4), last_failed_at=self.now - timedelta(hours=4), last_error='HTTP 502')
		self.assertEqual(ct_health.stalled_check(self.now)['state'], 'ok')  # the sweep idle or paused for the last three hours: nothing to judge

	def test_a_recent_success_of_any_source_is_ok(self):
		self.row('crt.sh', failed=9, last_attempt_at=self.now, last_error='HTTP 502')
		self.row('certspotter', ok=1, last_ok_at=self.now - timedelta(hours=1), last_attempt_at=self.now - timedelta(hours=1))
		check = ct_health.stalled_check(self.now)
		self.assertEqual((check['state'], check['facts']['last_ok_source']), ('ok', 'certspotter'))

	def test_attempts_with_no_success_for_three_hours_raise_a_warning_that_names_each_source(self):
		self.row('crt.sh', ok=4, failed=7, last_ok_at=self.now - timedelta(hours=5), last_attempt_at=self.now - timedelta(minutes=5),
		         last_failed_at=self.now - timedelta(minutes=5), last_error='HTTP 502 after 4 attempts')
		self.row('certspotter', failed=2, busy=3, last_attempt_at=self.now - timedelta(minutes=30), last_failed_at=self.now - timedelta(hours=1),
		         last_error='HTTP 429 (rate limited)')
		check = ct_health.stalled_check(self.now)
		self.assertEqual(check['state'], 'warning')
		self.assertIn('crt.sh: 7 failed today (last: HTTP 502 after 4 attempts)', check['detail'])
		self.assertIn('certspotter: 2 failed today (last: HTTP 429 (rate limited)), 3 held back by its rate limit today', check['detail'])
		self.assertIn('The last successful lookup was 5 hours ago', check['detail'])
		self.assertEqual(check['facts']['last_errors'], {'crt.sh': 'HTTP 502 after 4 attempts', 'certspotter': 'HTTP 429 (rate limited)'})

	def test_the_operations_check_raises_the_notice_and_clears_it(self):
		bad = self.row('crt.sh', failed=3, last_attempt_at=self.now, last_failed_at=self.now, last_error='HTTP 502 after 4 attempts')
		with mock.patch('agentapi.system_status.system_status', return_value={'problems': [], 'system': {}}):
			checks = {c['code']: c for c in reviewer.ops_checks(self.now)}
			self.assertEqual((checks['ct_watch_stalled']['state'], checks['ct_watch_stalled']['severity']), ('warning', 'warning'))
			reviewer.sync_alerts([checks['ct_watch_stalled']], self.now)
			alert = AdminAlert.objects.get(code='ct_watch_stalled', resolved_at__isnull=True)
			self.assertEqual(alert.severity, 'warning')
			self.assertIn('crt.sh', alert.detail)
			CtLookupDay.objects.filter(pk=bad.pk).update(ok=1, last_ok_at=self.now)  # a source answered again
			checks = {c['code']: c for c in reviewer.ops_checks(self.now)}
			self.assertEqual(checks['ct_watch_stalled']['state'], 'ok')
			reviewer.sync_alerts([checks['ct_watch_stalled']], self.now)
		self.assertFalse(AdminAlert.objects.filter(code='ct_watch_stalled', resolved_at__isnull=True).exists())


class StatusSurfacesTests(TestCase):
	def setUp(self):
		cache.clear()
		self.addCleanup(cache.clear)
		self.root = User.objects.create_superuser('cth-root', 'root@cth.example.test', 'x')
		now = timezone.now()
		CtLookupDay.objects.create(day=now.date(), source='crt.sh', ok=2, failed=1, new_hosts=1, last_ok_at=now - timedelta(minutes=4),
		                           last_attempt_at=now)

	def test_get_system_status_carries_the_watch_and_its_line(self):
		from agentapi import system_status
		from agentapi.services import Ctx
		with mock.patch.object(system_status, '_broker_client', lambda: mock.Mock(ping=lambda: True, llen=lambda n: 0, hlen=lambda n: 0)):
			out = system_status.system_status(Ctx(user=self.root))
		ct = out['system']['ct_watch']
		self.assertEqual(ct['line'], ct_health.summary()['line'])  # one function behind every surface
		self.assertEqual(ct['today']['crt.sh']['ok'], 2)
		self.assertEqual(ct['last_ok_source'], 'crt.sh')

	def test_the_timings_page_shows_the_same_line(self):
		from tests.test_admin import api
		from tests.test_tenancy import client_for
		status, data = api(client_for(self.root), 'GET', 'timings')
		self.assertEqual(status, 200)
		self.assertEqual(data['ct_watch_status'], ct_health.summary()['line'])
		self.assertIn('last successful lookup 4 minutes ago (crt.sh), 2 lookups ok, 1 failed, 1 new host today', data['ct_watch_status'])
