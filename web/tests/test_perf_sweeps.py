from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import ctmonitor, hygiene, ledger, tasks
from cveFeed.models import ServiceRun
from dashboard.models import Org, Project, SystemTimings
from reNgine import resources
from targetApp.models import Domain


def _clear_claims():
	client = getattr(resources.get_store(), 'r', None)
	if client is not None:
		for name in ('hygiene', 'ct-watch'):
			client.delete(f'cvengine:sweep:{name}')


class SweepTests(TestCase):
	def setUp(self):
		_clear_claims()
		self.addCleanup(_clear_claims)
		org = Org.objects.create(name='S', slug='s')
		self.project = Project.objects.create(name='P', slug='ps', insert_date=timezone.now(), org=org)

	def _domains(self, *names):
		return [Domain.objects.create(name=n, project=self.project, insert_date=timezone.now()) for n in names]

	def _age(self, service, name, hours):
		ledger.record(service, [name], self.project)
		ServiceRun.objects.filter(service=service, asset=name).update(finished_at=timezone.now() - timedelta(hours=hours))

	def test_ct_sweep_skips_fresh_domains_and_goes_oldest_first(self):
		a, b, c, d = self._domains('a.test', 'b.test', 'c.test', 'd.test')
		self._age('ct-watch', 'a.test', 1)    # fresh: skipped
		self._age('ct-watch', 'b.test', 30)
		self._age('ct-watch', 'c.test', 90)   # oldest run; d never ran so it goes first
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as dispatch:
			out = tasks.watch_certificates_all()
		self.assertEqual(out['queued'], 3)
		self.assertEqual([call.kwargs['args'][0] for call in dispatch.call_args_list], [d.id, c.id, b.id])

	def test_ct_sweep_is_capped_by_the_interval(self):
		self._domains(*[f'h{i}.test' for i in range(10)])
		SystemTimings.objects.create(ct_watch_minutes=5)  # 5 minutes of 3-second checks is 100 hosts; cap it lower
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as dispatch, \
				mock.patch.object(SystemTimings, 'current', return_value=SystemTimings(ct_watch_minutes=1)):
			out = tasks.watch_certificates_all()
		self.assertEqual(out['queued'], 10)  # 60s / 3 = 20 >= 10
		self.assertEqual(dispatch.call_count, 10)
		_clear_claims()
		dispatch.reset_mock()
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as dispatch, \
				mock.patch.object(SystemTimings, 'current', return_value=SystemTimings(ct_watch_minutes=1)), \
				mock.patch.object(ledger, 'stale_first', return_value=[(i, f'x{i}', None) for i in range(50)]):
			self.assertEqual(tasks.watch_certificates_all()['queued'], 20)

	def test_two_sweeps_never_overlap(self):
		self._domains('a.test')
		with mock.patch.object(tasks.watch_certificate_transparency, 'apply_async') as dispatch:
			first = tasks.watch_certificates_all()
			second = tasks.watch_certificates_all()
		self.assertEqual(first['queued'], 1)
		self.assertEqual(second['queued'], 0)
		self.assertEqual(dispatch.call_count, 1)

	def test_hygiene_sweep_skips_fresh_is_capped_and_overlap_safe(self):
		fresh, old, never = self._domains('fresh.test', 'old.test', 'never.test')
		self._age('hygiene', 'fresh.test', 2)
		self._age('hygiene', 'old.test', 48)
		with mock.patch.object(tasks.run_hygiene_task, 'delay') as delay:
			out = tasks.run_hygiene_all()
			again = tasks.run_hygiene_all()
		self.assertEqual([c.args[0] for c in delay.call_args_list], [never.id, old.id])
		self.assertEqual(out['queued'], 2)
		self.assertEqual(again['queued'], 0)
		_clear_claims()
		with mock.patch.object(tasks.run_hygiene_task, 'delay') as delay, mock.patch.object(tasks, 'HYGIENE_SWEEP_MAX', 1):
			self.assertEqual(tasks.run_hygiene_all()['queued'], 1)
		self.assertEqual(delay.call_args.args[0], never.id)

	def test_a_finished_check_is_recorded_so_the_next_sweep_skips_it(self):
		(domain,) = self._domains('rec.test')
		ctmonitor.run_ct_watch(domain.id, fetch=lambda name: set())
		self.assertEqual(ledger.fresh('ct-watch', ['rec.test'], self.project), {'rec.test'})
		with mock.patch.object(hygiene, 'tls_targets', return_value=[]), \
				mock.patch.object(hygiene, 'email_domains', return_value=[]):
			hygiene.run_hygiene(domain.id)
		self.assertEqual(ledger.fresh('hygiene', ['rec.test'], self.project), {'rec.test'})
