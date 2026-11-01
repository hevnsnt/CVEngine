"""Settings, configMaxxing, Scan concurrency: validation, precedence (saved > environment > default), reset, who may use it, the audit trail, what
admission and the conductor read, the AI tuner's bounds, the memory warning and the live resize of the discovery worker."""
import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase

from cveFeed import conductor, config_maxxing, scan_concurrency as sc
from cveFeed.models import ScanConcurrency
from dashboard.models import AuditLog, Org, OrgMembership
from reNgine import resources as res
from tests.test_settings import send
from tests.test_tenancy import client_for

REAL_REQUEST_APPLY = sc.request_apply
ENV_NAMES = [f.env for f in sc.FIELDS] + [n for f in sc.FIELDS for n in ('HEAVY_TUNE_MIN_' + f.key.split('.', 1)[-1].upper().replace('-', '_'),
	'HEAVY_TUNE_MAX_' + f.key.split('.', 1)[-1].upper().replace('-', '_'))]


class Isolated:
	"""No environment value of ours leaks in, and nothing saved in Redis or in this process's cache leaks out."""

	def setUp(self):
		super().setUp()
		self.env = mock.patch.dict(os.environ)
		self.env.start()
		for name in ENV_NAMES:
			os.environ.pop(name, None)
		self.addCleanup(self.env.stop)
		self.addCleanup(self.scrub)
		queue = mock.patch.object(sc, 'request_apply')  # nothing in these tests may put a message on a real broker
		self.queued = queue.start()
		self.addCleanup(queue.stop)
		self.scrub()

	def scrub(self):
		client = sc._redis()
		if client is not None:
			client.delete(sc.VALUES_KEY, sc.RUNNING_KEY, *[f'cvengine:adaptive:max:{k}' for k in res.MAX_CONCURRENT])
		sc.invalidate()
		res._saved.update(values={})  # not even the last copy of an outage may carry over to the next test


class FieldTests(Isolated, unittest.TestCase):
	def test_every_scanner_kind_has_a_field_with_its_default_and_a_sane_ceiling(self):
		for kind, default in res.MAX_CONCURRENT.items():
			field = sc.BY_KEY[f'heavy.{kind}']
			self.assertEqual((field.default, field.low), (default, 1), kind)
			self.assertTrue(default <= field.high <= 16, kind)
		self.assertEqual((sc.BY_KEY['discovery_concurrency'].default, sc.BY_KEY['work_depth'].default, sc.BY_KEY['assess_batch'].default), (8, 3, 8))

	def test_clean_accepts_whole_numbers_in_range_and_none_for_reset(self):
		self.assertEqual(sc.clean('heavy.nmap', 4), 4)
		self.assertEqual(sc.clean('heavy.nmap', '4'), 4)
		self.assertEqual(sc.clean('heavy.nmap', 4.0), 4)
		self.assertIsNone(sc.clean('heavy.nmap', None))
		self.assertEqual(sc.clean('work_depth', 0), 0)  # the conductor can be switched off

	def test_clean_refuses_everything_else_with_the_range_in_the_message(self):
		for key, bad in (('heavy.nmap', 0), ('heavy.nmap', 9), ('heavy.bbot-deep', 5), ('heavy.nmap', -1), ('heavy.nmap', True), ('heavy.nmap', 2.5),
				('heavy.nmap', 'lots'), ('heavy.nmap', ''), ('heavy.nmap', [2]), ('discovery_concurrency', 0), ('discovery_concurrency', 33),
				('work_depth', 33), ('work_depth', -1), ('heavy.route-probe', 17)):
			with self.assertRaises(ValueError, msg=(key, bad)) as caught:
				sc.clean(key, bad)
			self.assertRegex(str(caught.exception), r'from \d+ to \d+')
		with self.assertRaises(ValueError):
			sc.clean('heavy.nope', 2)


class PrecedenceTests(Isolated, TestCase):
	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')

	def test_default_then_environment_then_the_saved_value(self):
		self.assertEqual(sc.resolve('heavy.nmap', {}), {'value': 2, 'source': 'default'})
		os.environ['HEAVY_MAX_NMAP'] = '3'
		self.assertEqual(sc.resolve('heavy.nmap', {}), {'value': 3, 'source': 'environment'})
		self.assertEqual(sc.resolve('heavy.nmap', {'heavy.nmap': 5}), {'value': 5, 'source': 'admin'})

	def test_the_same_rule_for_the_discovery_pool_and_the_conductor(self):
		os.environ.update(DISCOVERY_CONCURRENCY='12', CVENGINE_WORK_DEPTH='0')
		self.assertEqual(sc.resolve('discovery_concurrency', {}), {'value': 12, 'source': 'environment'})
		self.assertEqual(sc.resolve('work_depth', {}), {'value': 0, 'source': 'environment'})
		self.assertEqual(sc.resolve('work_depth', {'work_depth': 6}), {'value': 6, 'source': 'admin'})

	def test_an_environment_value_that_is_not_a_number_is_ignored(self):
		os.environ['HEAVY_MAX_NMAP'] = 'many'
		self.assertEqual(sc.resolve('heavy.nmap', {})['source'], 'default')
		os.environ['HEAVY_MAX_NMAP'] = '0'  # 0 never meant zero runs: it meant "not set"
		self.assertEqual(sc.resolve('heavy.nmap', {})['source'], 'default')

	def test_a_saved_value_that_is_out_of_range_is_not_used(self):
		self.assertEqual(sc.resolve('heavy.nmap', {'heavy.nmap': 99})['source'], 'default')

	def test_a_saved_value_wins_over_the_environment_and_a_reset_goes_back_to_it(self):
		os.environ['HEAVY_MAX_NMAP'] = '3'
		sc.update({'heavy.nmap': 5}, self.root)
		self.assertEqual(sc.effective('heavy.nmap'), 5)
		sc.update({'heavy.nmap': None}, self.root)
		self.assertEqual((sc.effective('heavy.nmap'), sc.resolve('heavy.nmap')['source']), (3, 'environment'))
		del os.environ['HEAVY_MAX_NMAP']
		self.assertEqual(sc.effective('heavy.nmap'), 2)

	def test_the_assessment_batch_size_is_saved_then_environment_then_default(self):
		from cveFeed import host_assessment
		self.assertEqual(host_assessment.batch_size(), 8)
		os.environ['CVENGINE_ASSESS_BATCH'] = '16'
		self.assertEqual(host_assessment.batch_size(), 16)
		sc.update({'assess_batch': 24}, self.root)
		self.assertEqual((host_assessment.batch_size(), sc.resolve('assess_batch')['source']), (24, 'admin'))
		sc.update({'assess_batch': None}, self.root)
		self.assertEqual(host_assessment.batch_size(), 16)
		with self.assertRaises(ValueError):
			sc.clean('assess_batch', 65)

	def test_the_conductor_reads_the_saved_depth_then_the_environment(self):
		os.environ['CVENGINE_WORK_DEPTH'] = '4'
		self.assertEqual(conductor.wanted_depth(), 4)
		sc.update({'work_depth': 7}, self.root)
		self.assertEqual(conductor.wanted_depth(), 7)
		sc.update({'work_depth': 0}, self.root)
		self.assertEqual(conductor.wanted_depth(), 0)  # an explicit 0 is a choice: the conductor is off
		sc.update({'work_depth': None}, self.root)
		self.assertEqual(conductor.wanted_depth(), 4)


class SavingTests(Isolated, TestCase):
	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')
		self.org_admin = User.objects.create_user('conc_oadmin', password='x')
		self.member = User.objects.create_user('conc_member', password='x')
		org = Org.objects.create(name='C', slug='conc')
		OrgMembership.objects.create(user=self.org_admin, org=org, role='admin')
		OrgMembership.objects.create(user=self.member, org=org, role='user')
		self.c = client_for(self.root)

	def field(self, data, key):
		return next(f for f in data['fields'] if f['key'] == key)

	def test_get_describes_every_field_with_its_default_range_environment_and_origin(self):
		os.environ['HEAVY_MAX_NUCLEI'] = '2'
		status, data = send(self.c, 'GET', 'scan_concurrency')
		self.assertEqual(status, 200)
		keys = [f['key'] for f in data['fields']]
		self.assertEqual(keys, [f.key for f in sc.FIELDS])
		nmap = self.field(data, 'heavy.nmap')
		self.assertEqual((nmap['value'], nmap['default'], nmap['min'], nmap['max'], nmap['source'], nmap['env_value']), (2, 2, 1, 8, 'default', None))
		self.assertEqual(nmap['env_name'], 'HEAVY_MAX_NMAP')
		nuclei = self.field(data, 'heavy.nuclei')
		self.assertEqual((nuclei['value'], nuclei['source'], nuclei['env_value'], nuclei['default']), (2, 'environment', 2, 1))
		self.assertEqual(self.field(data, 'discovery_concurrency')['applies'], 'pool')
		self.assertEqual(nmap['applies'], 'live')

	def test_put_saves_a_partial_change_and_says_who_and_when(self):
		status, data = send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 4, 'work_depth': 5}})
		self.assertEqual(status, 200)
		nmap = self.field(data, 'heavy.nmap')
		self.assertEqual((nmap['value'], nmap['source'], nmap['set_by']), (4, 'admin', 'conc_root'))
		self.assertTrue(nmap['set_at'])
		self.assertEqual(self.field(data, 'work_depth')['value'], 5)
		self.assertEqual(self.field(data, 'heavy.nuclei')['source'], 'default')  # untouched
		self.assertEqual(ScanConcurrency.current().values, {'heavy.nmap': 4, 'work_depth': 5})

	def test_one_bad_value_saves_nothing(self):
		status, data = send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 4, 'heavy.nuclei': 99}})
		self.assertEqual(status, 400)
		self.assertIn('Vulnerability templates (nuclei) must be a whole number from 1 to 8', data['error'])
		self.assertEqual(ScanConcurrency.current().values, {})
		for body in ({}, {'values': {}}, {'values': 'x'}, {'values': {'heavy.nope': 1}}, {'nmap': 3}):
			self.assertEqual(send(self.c, 'PUT', 'scan_concurrency', body)[0], 400, body)

	def test_null_resets_one_field_and_leaves_the_others(self):
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 4, 'heavy.nuclei': 3}})
		status, data = send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': None}})
		self.assertEqual(status, 200)
		self.assertEqual((self.field(data, 'heavy.nmap')['source'], self.field(data, 'heavy.nmap')['set_by']), ('default', None))
		self.assertEqual(self.field(data, 'heavy.nuclei')['value'], 3)
		self.assertEqual(ScanConcurrency.current().meta.keys(), {'heavy.nuclei'})

	def test_reset_all_clears_every_tinkerer_setting_and_is_audited(self):
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 4, 'work_depth': 5, 'discovery_concurrency': 12}})
		status, data = send(self.c, 'POST', 'config_maxxing/reset', {})
		self.assertEqual((status, data['cleared']), (200, {'scan_concurrency': 3}))
		self.assertEqual(ScanConcurrency.current().values, {})
		self.assertTrue(AuditLog.objects.filter(action='config_maxxing.reset_all', actor=self.root).exists())
		self.assertTrue(AuditLog.objects.filter(action='config_maxxing.scan_concurrency_reset_all').exists())
		self.assertEqual(send(self.c, 'GET', 'config_maxxing')[1], {'cards': [{'id': 'scan_concurrency', 'title': 'Scan concurrency'}]})

	def test_every_change_is_audited_with_before_and_after_and_a_no_change_is_not(self):
		os.environ['HEAVY_MAX_NMAP'] = '3'
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 5}})
		entry = AuditLog.objects.get(action='scan_concurrency.set')
		self.assertEqual((entry.actor_name, entry.target, entry.detail['before'], entry.detail['before_source'], entry.detail['after']),
			('conc_root', 'heavy.nmap', 3, 'environment', 5))
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': 5}})  # the same again
		self.assertEqual(AuditLog.objects.filter(action='scan_concurrency.set').count(), 1)
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': None}})
		reset = AuditLog.objects.get(action='scan_concurrency.reset')
		self.assertEqual((reset.target, reset.detail['before'], reset.detail['after']), ('heavy.nmap', 5, 3))
		send(self.c, 'PUT', 'scan_concurrency', {'values': {'heavy.nmap': None}})  # nothing was set
		self.assertEqual(AuditLog.objects.filter(action='scan_concurrency.reset').count(), 1)

	def test_only_an_app_admin_may_read_or_change_it(self):
		for user in (self.org_admin, self.member):
			other = client_for(user)
			for method, path, body in (('GET', 'scan_concurrency', None), ('PUT', 'scan_concurrency', {'values': {'heavy.nmap': 3}}),
					('GET', 'config_maxxing', None), ('POST', 'config_maxxing/reset', {})):
				self.assertEqual(send(other, method, path, body)[0], 403, (user.username, path))
			self.assertEqual(other.get('/cve/settings/').status_code, 403)  # the page that holds the section
		self.assertEqual(self.client.get('/cve/api/settings/scan_concurrency').status_code, 302)  # signed out
		self.assertEqual(ScanConcurrency.objects.count(), 0)
		self.assertFalse(AuditLog.objects.filter(action__startswith='scan_concurrency').exists())

	def test_it_is_not_part_of_the_agent_rest_api_or_mcp(self):
		from agentapi import mcp
		self.assertFalse([t for t in mcp.TOOLS if 'concurrency' in str(t).lower()] if hasattr(mcp, 'TOOLS') else [])
		self.assertEqual(client_for(self.root).get('/api/v1/scan_concurrency/').status_code, 404)

	def test_saving_publishes_to_redis_and_clears_the_tuner_step_of_that_scanner(self):
		client = sc._redis()
		client.set('cvengine:adaptive:max:nmap', json.dumps({'value': 1}))
		client.set('cvengine:adaptive:max:nuclei', json.dumps({'value': 1}))
		sc.update({'heavy.nmap': 4}, self.root)
		self.assertEqual(json.loads(client.get(sc.VALUES_KEY))['values'], {'heavy.nmap': 4})
		self.assertIsNone(client.get('cvengine:adaptive:max:nmap'))
		self.assertIsNotNone(client.get('cvengine:adaptive:max:nuclei'))

	def test_a_discovery_change_queues_the_live_resize_and_others_do_not(self):
		sc.update({'heavy.nmap': 4}, self.root)
		self.queued.assert_not_called()
		sc.update({'discovery_concurrency': 12}, self.root)
		self.queued.assert_called_once_with()

	def test_a_broker_that_is_down_does_not_fail_the_save(self):
		sc.update({'discovery_concurrency': 12}, self.root)
		with mock.patch('reNgine.celery.app.send_task', side_effect=OSError('broker down')):
			REAL_REQUEST_APPLY()  # logs and returns
		self.assertEqual(ScanConcurrency.current().values, {'discovery_concurrency': 12})


class AdmissionTests(Isolated, TestCase):
	"""reNgine.resources admission reads the saved value without a restart, and falls back to today's static value when it cannot."""

	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')

	def test_admission_honours_the_saved_value(self):
		self.assertEqual(res.max_concurrent('nmap'), 2)
		sc.update({'heavy.nmap': 5}, self.root)
		self.assertEqual(res.max_concurrent('nmap'), 5)
		store = res.MemoryStore()
		for i in range(5):
			self.assertTrue(store.reserve(f't{i}', 100, 'nmap: x', 99999, 0, 'nmap', res.max_concurrent('nmap')))
		self.assertFalse(store.reserve('t5', 100, 'nmap: x', 99999, 0, 'nmap', res.max_concurrent('nmap')))

	def test_the_saved_value_beats_the_environment_and_a_reset_goes_back_to_it(self):
		os.environ['HEAVY_MAX_NMAP'] = '3'
		self.assertEqual(res.max_concurrent('nmap'), 3)
		sc.update({'heavy.nmap': 1}, self.root)
		self.assertEqual(res.max_concurrent('nmap'), 1)
		sc.update({'heavy.nmap': None}, self.root)
		self.assertEqual(res.max_concurrent('nmap'), 3)

	def test_another_process_sees_a_save_within_the_cache_time(self):
		sc.update({'heavy.nmap': 5}, self.root)
		self.assertEqual(sc.stored_values(now_fn=lambda: 1000.0), {'heavy.nmap': 5})
		sc._redis().set(sc.VALUES_KEY, json.dumps({'values': {'heavy.nmap': 6}}))  # a save in another process
		self.assertEqual(sc.stored_values(now_fn=lambda: 1000.0 + sc.CACHE_SECONDS - 1), {'heavy.nmap': 5})  # still cached
		self.assertEqual(sc.stored_values(now_fn=lambda: 1000.0 + sc.CACHE_SECONDS + 1), {'heavy.nmap': 6})

	def test_with_redis_down_admission_falls_back_to_the_static_value(self):
		os.environ['HEAVY_MAX_NMAP'] = '3'
		sc.invalidate()
		with mock.patch.object(res, 'redis_client', side_effect=ConnectionError('redis is down')), mock.patch.object(res, 'get_store', side_effect=ConnectionError('down')):
			self.assertEqual(res.max_concurrent('nmap'), 3)
			self.assertEqual(res.max_concurrent('nuclei'), 1)
			self.assertEqual(conductor.wanted_depth(), 3)

	def test_with_redis_down_the_last_value_this_process_saw_is_kept(self):
		sc.update({'heavy.nmap': 5}, self.root)
		self.assertEqual(res.max_concurrent('nmap'), 5)
		res._saved.update(at=-1000.0)  # expired: it will try Redis again
		with mock.patch.object(res, 'redis_client', side_effect=ConnectionError('redis is down')):
			self.assertEqual(res.max_concurrent('nmap'), 5)

	def test_a_reading_failure_is_not_retried_on_every_call(self):
		sc.invalidate()
		with mock.patch.object(res, 'redis_client', side_effect=ConnectionError('redis is down')) as attempts:
			for _ in range(5):
				sc.stored_values(now_fn=lambda: 50.0)
		self.assertEqual(attempts.call_count, 1)


class TunerBoundsTests(Isolated, TestCase):
	"""The AI review moves a cap one step at a time inside the bounds; what the admin saved is the baseline and, unless the environment says
	otherwise, the top of that range."""

	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')

	def test_without_a_saved_value_the_bounds_are_what_they_were(self):
		self.assertEqual(res.adaptive_bounds('nmap'), (1, 2))
		os.environ.update(HEAVY_TUNE_MAX_NMAP='4', HEAVY_TUNE_MIN_NMAP='2')
		self.assertEqual(res.adaptive_bounds('nmap'), (2, 4))

	def test_the_saved_value_is_the_baseline_and_the_top_of_the_range(self):
		sc.update({'heavy.nmap': 6}, self.root)
		self.assertEqual(res.adaptive_bounds('nmap'), (1, 6))
		self.assertEqual(res.max_concurrent('nmap'), 6)

	def test_the_environment_may_still_give_the_tuner_more_room_but_never_less_than_the_saved_value(self):
		sc.update({'heavy.nmap': 6}, self.root)
		os.environ['HEAVY_TUNE_MAX_NMAP'] = '8'
		self.assertEqual(res.adaptive_bounds('nmap'), (1, 8))
		os.environ['HEAVY_TUNE_MAX_NMAP'] = '3'
		self.assertEqual(res.adaptive_bounds('nmap'), (1, 6))
		os.environ['HEAVY_TUNE_MIN_NMAP'] = '7'
		self.assertEqual(res.adaptive_bounds('nmap'), (6, 6))  # the minimum cannot push the saved value out either

	def test_a_tuner_step_above_the_saved_value_is_held_to_it(self):
		sc._redis().set('cvengine:adaptive:max:nmap', json.dumps({'value': 5}))
		self.assertEqual(res.max_concurrent('nmap'), 2)  # the old behaviour: bounded by the static cap
		sc.update({'heavy.nmap': 3}, self.root)
		sc._redis().set('cvengine:adaptive:max:nmap', json.dumps({'value': 5}))
		self.assertEqual(res.max_concurrent('nmap'), 3)

	def test_a_tuner_step_down_stays_until_the_admin_saves_again(self):
		sc.update({'heavy.nmap': 4}, self.root)
		sc._redis().set('cvengine:adaptive:max:nmap', json.dumps({'value': 3, 'direction': 'down'}))
		self.assertEqual(res.max_concurrent('nmap'), 3)
		sc.update({'heavy.nmap': 4}, self.root)  # unchanged: nothing to apply
		self.assertEqual(res.max_concurrent('nmap'), 3)
		sc.update({'heavy.nmap': 5}, self.root)  # a new choice starts from what the admin chose
		self.assertEqual(res.max_concurrent('nmap'), 5)

	def test_the_review_candidate_never_leaves_the_bounds_the_admin_set(self):
		from cveFeed import performance_review as pr
		sc.update({'heavy.nmap': 3}, self.root)
		low, high = res.adaptive_bounds('nmap')
		self.assertEqual((low, high), (1, 3))
		kinds = {'nmap': (low, high)}
		caps = {'nmap': res.max_concurrent('nmap')}
		self.assertEqual(caps, {'nmap': 3})
		busy = {'samples': 100, 'span_minutes': 180, 'free_p10': 0.9, 'waiting': {'nmap': 50}, 'running': {'nmap': 3}}
		with mock.patch.object(pr, 'KINDS', ('nmap',)):
			candidate = pr.safe_candidate(busy, memory_kills=0, scanner_failures=0, scanner_runs=50, stage_outcomes={}, provider_throttles=0,
				caps=caps, bounds=kinds, previous={}, now=1_000_000.0)
			self.assertEqual(candidate['kind'], 'none', candidate)  # queued work and plenty of memory, yet nmap is at the top of what the admin allowed
			sc.update({'heavy.nmap': 2}, self.root)
			caps['nmap'] = res.max_concurrent('nmap')
			wider = {'nmap': (1, 4)}
			self.assertEqual(pr.safe_candidate(busy, memory_kills=0, scanner_failures=0, scanner_runs=50, stage_outcomes={}, provider_throttles=0,
				caps=caps, bounds=wider, previous={}, now=1_000_000.0)['direction'], 'up')  # control: with room above, the same telemetry does step up


class MemoryPlanTests(unittest.TestCase):
	COSTS = {'nmap': 400, 'nuclei': 1000, 'bbot-deep': 2400}

	def plan(self, caps, budget, defaults=None):
		return sc.memory_plan(caps, self.COSTS, budget, defaults or {'nmap': 2, 'nuclei': 1, 'bbot-deep': 1})

	def test_the_defaults_are_never_flagged_even_when_every_kind_at_its_limit_exceeds_the_budget(self):
		plan = self.plan({'nmap': 2, 'nuclei': 1, 'bbot-deep': 1}, 3072)
		self.assertEqual((plan['total_mb'], plan['default_total_mb'], plan['warnings']), (4200, 4200, []))

	def test_raising_a_limit_past_the_budget_warns_and_names_the_way_out(self):
		plan = self.plan({'nmap': 8, 'nuclei': 4, 'bbot-deep': 1}, 3072)
		self.assertEqual(plan['total_mb'], 3200 + 4000 + 2400)
		text = ' '.join(plan['warnings'])
		self.assertIn('9600 MB', text)
		self.assertIn('more than 2 times the 3072 MB', text)
		self.assertIn('CELERY_MEM_LIMIT', text)
		self.assertIn('second machine', text)

	def test_one_scanner_alone_above_the_budget_is_named(self):
		plan = self.plan({'nmap': 2, 'nuclei': 4, 'bbot-deep': 1}, 3000)
		self.assertTrue(any('Vulnerability templates (nuclei)' in w and 'by itself' in w for w in plan['warnings']), plan['warnings'])

	def test_a_raise_that_stays_under_twice_the_budget_is_quiet(self):
		plan = self.plan({'nmap': 4, 'nuclei': 2, 'bbot-deep': 1}, 3072)  # 6000 MB worst case, budget 3072: under 6144
		self.assertEqual((plan['total_mb'], plan['warnings']), (6000, []))

	def test_a_raise_that_fits_is_quiet_and_an_unknown_budget_is_never_a_warning(self):
		self.assertEqual(self.plan({'nmap': 3, 'nuclei': 1, 'bbot-deep': 1}, 16000)['warnings'], [])
		self.assertEqual(self.plan({'nmap': 8, 'nuclei': 8, 'bbot-deep': 4}, None)['warnings'], [])

	def test_lowering_a_limit_is_never_flagged(self):
		self.assertEqual(self.plan({'nmap': 1, 'nuclei': 1, 'bbot-deep': 1}, 100)['warnings'], [])


class MemoryContextTests(Isolated, TestCase):
	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')
		self.c = client_for(self.root)

	def test_the_page_shows_the_scanning_containers_budget_and_a_warning_for_a_big_raise(self):
		snapshot = {'store': 'redis', 'containers': [{'host': 'celery', 'memory': {'limit_mb': 4096, 'total_mb': 4096}, 'budget_mb': 3072}]}
		with mock.patch.object(res, 'cluster_snapshot', return_value=snapshot):
			memory = send(self.c, 'GET', 'scan_concurrency')[1]['memory']
			self.assertEqual((memory['budget_mb'], memory['limit_mb'], memory['warnings']), (3072, 4096, []))
			sc.update({'heavy.nmap': 8, 'heavy.nuclei': 8, 'heavy.bbot-standard': 8}, self.root)
			memory = send(self.c, 'GET', 'scan_concurrency')[1]['memory']
		self.assertTrue(memory['warnings'])
		self.assertGreater(memory['total_mb'], memory['default_total_mb'])
		self.assertIn('nmap', memory['costs_mb'])

	def test_without_redis_the_web_containers_own_memory_is_not_taken_for_the_scanners(self):
		snapshot = {'store': 'process', 'containers': [{'host': 'web', 'memory': {'limit_mb': 1024}, 'budget_mb': 768}]}
		with mock.patch.object(res, 'cluster_snapshot', return_value=snapshot):
			memory = send(self.c, 'GET', 'scan_concurrency')[1]['memory']
		self.assertEqual((memory['budget_mb'], memory['warnings']), (None, []))

	def test_without_a_worker_report_the_budget_is_unknown_and_nothing_is_claimed(self):
		with mock.patch.object(res, 'cluster_snapshot', return_value={'store': 'redis', 'containers': []}):
			memory = send(self.c, 'GET', 'scan_concurrency')[1]['memory']
		self.assertEqual((memory['budget_mb'], memory['limit_mb'], memory['warnings']), (None, None, []))


class FakeApp:
	"""Just enough of celery's app.control for the resize: inspect().stats() and broadcast()."""

	def __init__(self, ceilings, answer=True):
		self.ceilings, self.answer, self.calls = dict(ceilings), answer, []
		self.control = self

	def inspect(self, timeout=None):
		app = self

		class Inspect:
			def stats(self):
				return {name: {'autoscaler': {'max': ceiling, 'min': 1}} for name, ceiling in app.ceilings.items()} or None
		return Inspect()

	def broadcast(self, command, arguments=None, destination=None, reply=False, timeout=1):
		self.calls.append((command, arguments, destination, reply))
		if not self.answer:
			return []
		name = destination[0]
		self.ceilings[name] = arguments['max']
		return [{name: {'ok': f'autoscale now max={arguments["max"]} min=1'}}]


class LiveResizeTests(Isolated, TestCase):
	def setUp(self):
		super().setUp()
		self.root = User.objects.create_superuser('conc_root', 'c@x.io', 'x')

	def test_the_resize_is_queued_on_the_feed_queue(self):
		with mock.patch('reNgine.celery.app.send_task') as send_task:
			REAL_REQUEST_APPLY()
		send_task.assert_called_once_with('apply_scan_concurrency', queue='cve_feed_queue')

	def test_the_autoscale_control_is_called_for_the_discovery_worker_whose_ceiling_differs(self):
		sc.update({'discovery_concurrency': 12}, self.root)
		app = FakeApp({'discovery_worker@celery': 8, 'cve_feed_worker@celery': 4})
		record = sc.apply_discovery(app)
		self.assertEqual(app.calls, [('autoscale', {'max': 12}, ['discovery_worker@celery'], True)])
		self.assertEqual((record['want'], record['workers'], record['changed']), (12, {'discovery_worker@celery': 12}, ['discovery_worker@celery']))
		self.assertEqual(sc.running_discovery()['value'], 12)

	def test_nothing_is_sent_when_the_worker_already_runs_the_value(self):
		app = FakeApp({'discovery_worker@celery': 8})
		sc.apply_discovery(app)
		self.assertEqual(app.calls, [])

	def test_the_value_comes_from_the_environment_or_default_when_nothing_is_saved(self):
		os.environ['DISCOVERY_CONCURRENCY'] = '6'
		app = FakeApp({'discovery_worker@celery': 8})
		sc.apply_discovery(app)
		self.assertEqual(app.calls, [('autoscale', {'max': 6}, ['discovery_worker@celery'], True)])

	def test_a_worker_that_does_not_answer_is_not_recorded_as_resized(self):
		sc.update({'discovery_concurrency': 12}, self.root)
		app = FakeApp({'discovery_worker@celery': 8}, answer=False)
		record = sc.apply_discovery(app)
		self.assertEqual((record['workers'], record['changed']), ({'discovery_worker@celery': 8}, []))
		self.assertEqual(sc.running_discovery()['value'], 8)
		status = send(client_for(self.root), 'GET', 'scan_concurrency')[1]['discovery']
		self.assertEqual(status['state'], 'pending')
		self.assertIn('after the next restart or update', status['message'])

	def test_no_worker_reporting_is_unknown_not_applied(self):
		sc.update({'discovery_concurrency': 12}, self.root)
		sc.apply_discovery(FakeApp({}))
		data = send(client_for(self.root), 'GET', 'scan_concurrency')[1]
		self.assertEqual(data['discovery']['state'], 'unknown')
		field = next(f for f in data['fields'] if f['key'] == 'discovery_concurrency')
		self.assertEqual((field['value'], field['running']), (12, None))

	def test_the_status_says_applied_only_when_the_workers_report_the_saved_value(self):
		sc.update({'discovery_concurrency': 12}, self.root)
		sc.apply_discovery(FakeApp({'discovery_worker@celery': 8}))
		data = send(client_for(self.root), 'GET', 'scan_concurrency')[1]
		self.assertEqual(data['discovery']['state'], 'applied')
		field = next(f for f in data['fields'] if f['key'] == 'discovery_concurrency')
		self.assertEqual(field['running'], 12)

	def test_a_stale_report_is_unknown(self):
		status = sc.discovery_status(12, {'value': 12, 'workers': {'discovery_worker@celery': 12}, 'age_seconds': 900})
		self.assertEqual(status['state'], 'unknown')

	def test_two_workers_that_disagree_have_no_single_running_value(self):
		client = sc._redis()
		client.set(sc.RUNNING_KEY, json.dumps({'want': 12, 'workers': {'discovery_worker@a': 12, 'discovery_worker@b': 8}, 't': 1e12}))
		self.assertIsNone(sc.running_discovery()['value'])

	def test_the_30_second_tick_republishes_the_saved_values_and_resizes_and_never_raises(self):
		ScanConcurrency.current(); ScanConcurrency.objects.update(values={'heavy.nmap': 4, 'discovery_concurrency': 10})
		app = FakeApp({'discovery_worker@celery': 8})
		with mock.patch('reNgine.celery.app', app):
			sc.reconcile()
		self.assertEqual(json.loads(sc._redis().get(sc.VALUES_KEY))['values'], {'heavy.nmap': 4, 'discovery_concurrency': 10})
		self.assertEqual(app.calls[0][1], {'max': 10})
		with mock.patch.object(sc, 'saved_values', side_effect=RuntimeError('db')):
			self.assertIsNone(sc.reconcile())
		with mock.patch.object(sc, 'discovery_workers', side_effect=OSError('broker')):
			self.assertIsNone(sc.reconcile())

	def test_the_report_resources_task_runs_the_tick(self):
		from cveFeed import tasks
		with mock.patch.object(res, 'report_state'), mock.patch.object(sc, 'reconcile') as tick:
			tasks.report_resources()
		tick.assert_called_once_with()
		with mock.patch.object(sc, 'apply_discovery', return_value={'want': 8}) as apply:
			self.assertEqual(tasks.apply_scan_concurrency(), {'want': 8})
		apply.assert_called_once_with()

	def test_the_resize_task_keeps_running_while_scanning_is_paused(self):
		from cveFeed.scan_control import PAUSE_EXEMPT_TASKS
		self.assertTrue({'report_resources', 'apply_scan_concurrency'} <= PAUSE_EXEMPT_TASKS)


class StartupTests(Isolated, TestCase):
	"""A restart or an update lands on the saved value: celery-entrypoint.sh asks the database before it starts the discovery worker."""

	def run_command(self, key):
		from io import StringIO
		out = StringIO()
		call_command('scan_concurrency_value', key, stdout=out)
		return out.getvalue().strip()

	def test_the_command_prints_saved_then_environment_then_default(self):
		self.assertEqual(self.run_command('discovery_concurrency'), '8')
		os.environ['DISCOVERY_CONCURRENCY'] = '5'
		self.assertEqual(self.run_command('discovery_concurrency'), '5')
		sc.update({'discovery_concurrency': 12}, User.objects.create_superuser('conc_root', 'c@x.io', 'x'))
		self.assertEqual(self.run_command('discovery_concurrency'), '12')

	def test_the_command_reads_the_database_not_the_redis_copy(self):
		ScanConcurrency.objects.create(values={'discovery_concurrency': 9})
		self.assertEqual(self.run_command('discovery_concurrency'), '9')

	def test_an_unknown_key_is_an_error(self):
		from django.core.management.base import CommandError
		with self.assertRaises(CommandError):
			self.run_command('nope')

	def test_the_entrypoint_uses_it_and_falls_back_to_the_environment(self):
		script = (Path(__file__).resolve().parent.parent / 'celery-entrypoint.sh').read_text()
		self.assertIn('manage.py scan_concurrency_value discovery_concurrency', script)
		self.assertRegex(script, r'generate_worker_command "discovery_queue" "\$discovery_concurrency"')
		self.assertRegex(script, r'discovery_concurrency="\$\{DISCOVERY_CONCURRENCY:-8\}"')
		self.assertNotRegex(script, r'"discovery_queue" "\$\{DISCOVERY_CONCURRENCY')

	def test_the_celery_pool_is_one_that_can_be_resized_live(self):
		script = (Path(__file__).resolve().parent.parent / 'celery-entrypoint.sh').read_text()
		self.assertRegex(script, r'--pool=gevent --optimization=fair --autoscale=\$concurrency,1')  # autoscale max,min: what `autoscale` resizes

	def test_celery_can_resize_a_gevent_autoscaler(self):
		import inspect

		from celery.concurrency import gevent as gevent_pool
		from celery.worker import control
		self.assertTrue(hasattr(gevent_pool.TaskPool, 'grow') and hasattr(gevent_pool.TaskPool, 'shrink'))
		self.assertIn('autoscaler.update(max, min)', inspect.getsource(control.autoscale))


class ScopeTests(unittest.TestCase):
	def test_the_row_belongs_to_no_project_so_it_needs_no_scope(self):
		from tenancy.scope import SCOPES, UNSCOPED
		self.assertNotIn('cveFeed.ScanConcurrency', SCOPES)
		fields = {f.name: f for f in ScanConcurrency._meta.get_fields()}
		self.assertFalse([n for n, f in fields.items() if f.is_relation and f.related_model._meta.label in ('dashboard.Project', 'dashboard.Org', 'targetApp.Domain')])
		self.assertNotIn('cveFeed.ScanConcurrency', UNSCOPED)
		self.assertTrue(config_maxxing.CARDS)


if __name__ == '__main__':
	unittest.main()
