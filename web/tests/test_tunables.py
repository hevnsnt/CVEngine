"""Settings, configMaxxing, the generic tunable registry (AI spend, Scan pacing): the registry itself, precedence (saved > environment > default),
validation bounds, who may change a value, the audit trail, live propagation to the code that reads each knob, and that the documentation names
every tunable. No test waits on a clock: the cache is driven with an injected time."""
import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from cveFeed import config_maxxing, tunables
from cveFeed.models import TunableSettings
from dashboard.models import AuditLog, Org, OrgMembership
from reNgine import resources
from tests.test_settings import send
from tests.test_tenancy import client_for

WEB = Path(__file__).resolve().parent.parent
ROOT = WEB.parent
ENV_NAMES = [t.env for t in tunables.TUNABLES]


class Isolated:
    """No environment value of ours leaks in, and nothing saved in Redis or in this process's cache leaks out. The Redis key is a private one, so
    a test running next to this one in another process never sees a number saved here."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ENV_NAMES:
            os.environ.pop(name, None)
        key = mock.patch.object(tunables, 'VALUES_KEY', f'cvengine:tunables:values:test:{os.getpid()}:{id(self)}')
        key.start()
        self.addCleanup(key.stop)
        self.addCleanup(self.scrub)
        self.scrub()

    def scrub(self):
        client = resources.redis_client()
        if client is not None:
            client.delete(tunables.VALUES_KEY)
        tunables.invalidate()
        tunables._cache.update(values={})  # not even the last copy of an outage may carry over to the next test


class RegistryTests(Isolated, SimpleTestCase):
    def test_every_tunable_is_well_formed(self):
        self.assertTrue(len(tunables.TUNABLES) >= 6)
        self.assertEqual(len({t.key for t in tunables.TUNABLES}), len(tunables.TUNABLES))
        self.assertEqual(len({t.env for t in tunables.TUNABLES}), len(tunables.TUNABLES))
        for t in tunables.TUNABLES:
            self.assertRegex(t.key, r'^[a-z][a-z0-9_]+$')
            self.assertRegex(t.env, r'^CVENGINE_[A-Z0-9_]+$', t.key)
            self.assertTrue(t.low <= t.default <= t.high, t.key)
            self.assertIn(t.group, tunables.GROUP_BY_ID, t.key)
            self.assertIn(t.applies, (tunables.LIVE, tunables.RESTART), t.key)
            self.assertTrue(t.label and len(t.help) > 40 and t.unit, t.key)  # a help text says what it affects
        for g in tunables.GROUPS:
            self.assertTrue(g.title and g.intro)
            self.assertTrue([t for t in tunables.TUNABLES if t.group == g.id], f'group {g.id} is empty')

    def test_the_registry_defaults_are_the_defaults_the_code_has_always_had(self):
        from agentapi import sentinel_dispatch, services
        from cveFeed import conductor, coverage_topup, hot_validation, templategen, triage, validation
        by = tunables.BY_KEY
        for name, default in triage.DEFAULT_CAPS.items():
            self.assertEqual(by[name.lower()].default, default, name)
        for name, default in validation.DEFAULT_CAPS.items():
            self.assertEqual(by[name.lower()].default, default, name)
        self.assertEqual(by['validate_min_gap_hours'].default, hot_validation.MIN_GAP_HOURS)
        self.assertEqual(by['template_gen_max_per_day'].default, templategen.GENERATION_DEFAULTS['TEMPLATE_GEN_MAX_PER_DAY'])
        self.assertEqual(by['stage_parallel'].default, sentinel_dispatch.DEFAULT_STAGE_PARALLEL)
        self.assertEqual(by['work_min_gap_hours'].default, conductor.DEFAULT_MIN_GAP_HOURS)
        self.assertEqual(by['sentinel_refresh_gap_hours'].default, coverage_topup.REFRESH_GAP_DEFAULT_HOURS)
        self.assertEqual(by['bulk_discover_now'].default, services.BULK_DISCOVER_NOW)

    def test_the_cards_of_the_section_are_the_groups_of_the_registry(self):
        self.assertEqual([c.id for c in config_maxxing.CARDS], ['scan_concurrency'] + [g.id for g in tunables.GROUPS])

    def test_the_page_registers_exactly_the_groups_the_server_has(self):
        source = (WEB / 'static' / 'cve' / 'tunables-card.js').read_text()
        self.assertEqual(re.findall(r'registerTunableGroup\("([a-z_]+)", "([^"]+)"\);', source), [(g.id, g.title) for g in tunables.GROUPS])
        self.assertIn('tunables-card.js', (WEB / 'static' / 'cve' / 'settings.js').read_text())

    def test_no_code_reads_a_registered_variable_around_the_registry(self):
        """Reading the environment directly would ignore what an App Admin saved: every reader goes through tunables.value."""
        names = '|'.join(re.escape(t.env) for t in tunables.TUNABLES)
        pattern = re.compile(rf'(environ|getenv)[^\n]*({names})\b')
        offenders = []
        for path in WEB.rglob('*.py'):
            if 'tests' in path.parts or path.name == 'tunables.py' or 'migrations' in path.parts:
                continue
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if pattern.search(line) and not line.lstrip().startswith('#'):
                    offenders.append(f'{path.relative_to(WEB)}:{number}')
        self.assertEqual(offenders, [])

    def test_a_restart_tunable_says_so_and_a_live_one_does_not(self):
        self.assertEqual(tunables.APPLIES_TEXT[tunables.RESTART], 'Applies after the next restart')
        self.assertTrue(all(t.applies == tunables.LIVE for t in tunables.TUNABLES), 'a new restart-only tunable needs a test of its own')

    def test_the_row_belongs_to_no_project_so_it_needs_no_scope(self):
        from tenancy.scope import SCOPES, UNSCOPED
        self.assertNotIn('cveFeed.TunableSettings', SCOPES)
        self.assertNotIn('cveFeed.TunableSettings', UNSCOPED)
        related = [f.related_model._meta.label for f in TunableSettings._meta.get_fields() if f.is_relation]
        self.assertEqual(related, ['auth.User'])  # only who saved it; no project, organization or target


class ResolveTests(Isolated, SimpleTestCase):
    def test_default_then_environment_then_the_saved_value(self):
        self.assertEqual(tunables.resolve('triage_max_per_day', {}), {'value': 2000, 'source': 'default'})
        os.environ['CVENGINE_TRIAGE_MAX_PER_DAY'] = '900'
        self.assertEqual(tunables.resolve('triage_max_per_day', {}), {'value': 900, 'source': 'environment'})
        self.assertEqual(tunables.resolve('triage_max_per_day', {'triage_max_per_day': 5}), {'value': 5, 'source': 'admin'})

    def test_the_environment_keeps_the_meaning_it_always_had(self):
        # not a number, empty and not finite: the default; below the minimum: clamped up to it (the readers always did max(1, ...)); above the
        # page's maximum: used as is (the environment was never range checked)
        for raw, expected in (('lots', 'default'), ('', 'default'), ('  ', 'default'), ('nan', 'default'), ('inf', 'default'), ('0', 1), ('-4', 1), ('99999999', 99999999), ('7.9', 7)):
            os.environ['CVENGINE_STAGE_PARALLEL'] = raw
            got = tunables.resolve('stage_parallel', {})
            if expected == 'default':
                self.assertEqual((got['value'], got['source']), (4, 'default'), raw)
            else:
                self.assertEqual((got['value'], got['source']), (expected, 'environment'), raw)

    def test_hours_may_be_a_fraction_in_the_environment_and_zero_turns_the_gap_off(self):
        os.environ['CVENGINE_VALIDATE_MIN_GAP_HOURS'] = '0.5'
        self.assertEqual(tunables.resolve('validate_min_gap_hours', {}), {'value': 0.5, 'source': 'environment'})
        os.environ['CVENGINE_VALIDATE_MIN_GAP_HOURS'] = '-3'
        self.assertEqual(tunables.resolve('validate_min_gap_hours', {})['value'], 0)

    def test_a_saved_value_that_is_not_valid_is_not_used(self):
        for bad in (0, 99999, -1, True, 2.5, '5', None):
            self.assertEqual(tunables.resolve('triage_max_per_run', {'triage_max_per_run': bad})['source'], 'default', bad)

    def test_an_unreadable_saved_copy_means_the_environment_then_the_default(self):
        os.environ['CVENGINE_TRIAGE_MAX_PER_RUN'] = '30'
        with mock.patch.object(tunables, 'stored_values', side_effect=RuntimeError('boom')):
            self.assertEqual(tunables.value('triage_max_per_run'), 30)
            del os.environ['CVENGINE_TRIAGE_MAX_PER_RUN']
            self.assertEqual(tunables.value('triage_max_per_run'), 100)

    def test_a_module_constant_still_wins_as_the_default(self):
        self.assertEqual(tunables.value('bulk_discover_now', 7), 7)
        os.environ['CVENGINE_BULK_DISCOVER_NOW'] = '9'
        self.assertEqual(tunables.value('bulk_discover_now', 7), 9)


class ValidationTests(Isolated, SimpleTestCase):
    def test_the_bounds_of_every_tunable_are_inclusive_and_nothing_else_passes(self):
        for t in tunables.TUNABLES:
            self.assertEqual(tunables.clean(t.key, t.low), t.low, t.key)
            self.assertEqual(tunables.clean(t.key, t.high), t.high, t.key)
            self.assertEqual(tunables.clean(t.key, str(t.high)), t.high, t.key)
            self.assertEqual(tunables.clean(t.key, float(t.low)), t.low, t.key)
            self.assertIsNone(tunables.clean(t.key, None), t.key)
            for bad in (t.low - 1, t.high + 1, True, False, 1.5, 'lots', '', [t.low], {}):
                with self.assertRaises(ValueError, msg=(t.key, bad)) as caught:
                    tunables.clean(t.key, bad)
                self.assertIn(f'from {t.low} to {t.high}', str(caught.exception))
        with self.assertRaises(ValueError):
            tunables.clean('triage_max_per_run', -5)
        with self.assertRaises(ValueError):
            tunables.clean('no_such_setting', 1)

    def test_a_gap_may_be_zero_but_a_cap_may_not(self):
        self.assertEqual(tunables.clean('validate_min_gap_hours', 0), 0)
        self.assertEqual(tunables.clean('sentinel_refresh_gap_hours', 0), 0)
        self.assertEqual(tunables.clean('work_min_gap_hours', 0), 0)
        for key in ('triage_max_per_day', 'validate_max_per_day', 'stage_parallel', 'bulk_discover_now'):
            with self.assertRaises(ValueError):
                tunables.clean(key, 0)


class SavingTests(Isolated, TestCase):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('tun_root', 't@x.io', 'x')
        self.org_admin = User.objects.create_user('tun_oadmin', password='x')
        self.member = User.objects.create_user('tun_member', password='x')
        org = Org.objects.create(name='T', slug='tun')
        OrgMembership.objects.create(user=self.org_admin, org=org, role='admin')
        OrgMembership.objects.create(user=self.member, org=org, role='user')
        self.c = client_for(self.root)

    def field(self, data, key):
        return next(f for f in data['fields'] if f['key'] == key)

    def test_get_describes_every_tunable_with_its_default_range_environment_and_origin(self):
        os.environ['CVENGINE_STAGE_PARALLEL'] = '6'
        status, data = send(self.c, 'GET', 'tunables')
        self.assertEqual(status, 200)
        self.assertEqual([f['key'] for f in data['fields']], [t.key for t in tunables.TUNABLES])
        self.assertEqual([g['id'] for g in data['groups']], [g.id for g in tunables.GROUPS])
        stage = self.field(data, 'stage_parallel')
        self.assertEqual((stage['value'], stage['source'], stage['env_name'], stage['env_value'], stage['default'], stage['min'], stage['max']),
                         (6, 'environment', 'CVENGINE_STAGE_PARALLEL', 6, 4, 1, 16))
        triage = self.field(data, 'triage_max_per_day')
        self.assertEqual((triage['value'], triage['source'], triage['env_value'], triage['applies']), (2000, 'default', None, 'live'))
        self.assertTrue(triage['help'] and triage['unit'])

    def test_put_saves_a_partial_change_and_says_who_and_when(self):
        status, data = send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800, 'stage_parallel': 2}})
        self.assertEqual(status, 200)
        triage = self.field(data, 'triage_max_per_day')
        self.assertEqual((triage['value'], triage['source'], triage['set_by'], triage['saved']), (800, 'admin', 'tun_root', 800))
        self.assertTrue(triage['set_at'])
        self.assertEqual(self.field(data, 'validate_max_per_day')['source'], 'default')  # untouched
        self.assertEqual(TunableSettings.current().values, {'triage_max_per_day': 800, 'stage_parallel': 2})

    def test_a_saved_value_wins_over_the_environment_and_a_reset_goes_back_to_it(self):
        os.environ['CVENGINE_TRIAGE_MAX_PER_DAY'] = '900'
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800}})
        self.assertEqual(tunables.resolve('triage_max_per_day'), {'value': 800, 'source': 'admin'})
        status, data = send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': None}})
        self.assertEqual(status, 200)
        field = self.field(data, 'triage_max_per_day')
        self.assertEqual((field['value'], field['source'], field['set_by']), (900, 'environment', None))
        self.assertEqual(TunableSettings.current().meta, {})

    def test_one_bad_value_saves_nothing(self):
        status, data = send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800, 'stage_parallel': 17}})
        self.assertEqual(status, 400)
        self.assertIn('Chunks of one scan stage at once must be a whole number from 1 to 16', data['error'])
        self.assertEqual(TunableSettings.current().values, {})
        for body in ({}, {'values': {}}, {'values': 'x'}, {'values': {'no_such': 1}}, {'stage_parallel': 3}):
            self.assertEqual(send(self.c, 'PUT', 'tunables', body)[0], 400, body)
        self.assertFalse(AuditLog.objects.filter(action__startswith='tunable').exists())

    def test_every_change_is_audited_with_before_and_after_and_a_no_change_is_not(self):
        os.environ['CVENGINE_TRIAGE_MAX_PER_DAY'] = '900'
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800}})
        entry = AuditLog.objects.get(action='tunable.set')
        self.assertEqual((entry.actor_name, entry.target, entry.detail),
                         ('tun_root', 'triage_max_per_day', {'env': 'CVENGINE_TRIAGE_MAX_PER_DAY', 'before': 900, 'before_source': 'environment', 'after': 800}))
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800}})  # the same again
        self.assertEqual(AuditLog.objects.filter(action='tunable.set').count(), 1)
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': None}})
        reset = AuditLog.objects.get(action='tunable.reset')
        self.assertEqual((reset.target, reset.detail['before'], reset.detail['before_source'], reset.detail['after']), ('triage_max_per_day', 800, 'admin', 900))
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': None}})  # nothing was set
        self.assertEqual(AuditLog.objects.filter(action='tunable.reset').count(), 1)

    def test_only_an_app_admin_may_read_or_change_it(self):
        body = {'values': {'triage_max_per_day': 5}}
        for user in (self.org_admin, self.member):
            other = client_for(user)
            for method, path, payload in (('GET', 'tunables', None), ('PUT', 'tunables', body)):
                self.assertEqual(send(other, method, path, payload)[0], 403, (user.username, method))
            self.assertEqual(other.get('/cve/settings/').status_code, 403)
            with self.assertRaises(PermissionError):  # and the function itself refuses, not only the route
                tunables.update(body['values'], user)
            with self.assertRaises(PermissionError):
                tunables.reset_group(user, 'ai_spend')
        self.assertEqual(self.client.get('/cve/api/settings/tunables').status_code, 302)  # signed out
        self.assertEqual(self.client.put('/cve/api/settings/tunables', json.dumps(body), content_type='application/json').status_code, 302)
        self.assertEqual(TunableSettings.objects.count(), 0)
        self.assertFalse(AuditLog.objects.filter(action__startswith='tunable').exists())

    def test_it_is_not_part_of_the_agent_rest_api_or_mcp(self):
        self.assertEqual(client_for(self.root).get('/api/v1/tunables/').status_code, 404)
        from agentapi import mcp
        self.assertFalse([t for t in mcp.TOOLS if 'tunable' in str(t).lower()] if hasattr(mcp, 'TOOLS') else [])

    def test_configmaxxing_lists_the_cards_and_reset_all_clears_every_group(self):
        send(self.c, 'PUT', 'tunables', {'values': {'triage_max_per_day': 800, 'stage_parallel': 2, 'work_min_gap_hours': 5}})
        listing = send(self.c, 'GET', 'config_maxxing')[1]
        self.assertEqual([c['id'] for c in listing['cards']], ['scan_concurrency', 'ai_spend', 'throughput'])
        status, data = send(self.c, 'POST', 'config_maxxing/reset', {})
        self.assertEqual((status, data['cleared']), (200, {'scan_concurrency': 0, 'ai_spend': 1, 'throughput': 2}))
        self.assertEqual(TunableSettings.current().values, {})
        self.assertTrue(AuditLog.objects.filter(action='config_maxxing.reset_all', actor=self.root).exists())
        groups = AuditLog.objects.filter(action='config_maxxing.tunables_reset_all')
        self.assertEqual(sorted(groups.values_list('target', flat=True)), ['ai_spend', 'throughput'])
        self.assertEqual(AuditLog.objects.filter(action='tunable.reset').count(), 3)

    def test_the_values_are_one_for_the_instance_and_the_page_shows_no_project_data(self):
        status, data = send(self.c, 'GET', 'tunables')
        self.assertEqual(status, 200)
        self.assertEqual(set(data), {'fields', 'groups', 'cache_seconds'})
        allowed = {'key', 'label', 'help', 'group', 'default', 'min', 'max', 'unit', 'value', 'source', 'env_name', 'env_value', 'saved', 'set_by', 'set_at',
                   'applies', 'applies_text'}
        for f in data['fields']:
            self.assertEqual(set(f) - allowed, set(), f['key'])  # nothing about a project, an organization or a target can come along


class PublishTests(Isolated, TestCase):
    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('tun_root', 't@x.io', 'x')

    def test_saving_publishes_to_redis(self):
        tunables.update({'triage_max_per_day': 800}, self.root)
        self.assertEqual(json.loads(resources.redis_client().get(tunables.VALUES_KEY))['values'], {'triage_max_per_day': 800})

    def test_a_flushed_redis_heals_on_the_next_tick_and_the_tick_is_wired_in(self):
        tunables.update({'stage_parallel': 2}, self.root)
        resources.redis_client().delete(tunables.VALUES_KEY)
        tunables.invalidate()
        self.assertEqual(tunables.value('stage_parallel'), 4)  # as far as this process can tell, nothing is saved
        self.assertTrue(tunables.reconcile())
        tunables.invalidate()
        self.assertEqual(tunables.value('stage_parallel'), 2)
        from cveFeed import tasks
        with mock.patch('reNgine.resources.report_state'), mock.patch('cveFeed.scan_concurrency.reconcile'), mock.patch.object(tunables, 'reconcile') as tick:
            tasks.report_resources()
        tick.assert_called_once_with()

    def test_reconcile_never_raises(self):
        with mock.patch.object(tunables, 'saved_values', side_effect=RuntimeError('db down')):
            self.assertFalse(tunables.reconcile())
        with mock.patch.object(resources, 'redis_client', side_effect=OSError('redis down')):
            self.assertFalse(tunables.publish({'stage_parallel': 2}))


class CacheTests(Isolated, SimpleTestCase):
    """Another process sees a change when its cached copy is older than CACHE_SECONDS, with no restart. The clock is injected."""

    def raw_publish(self, values):  # what the web process does, seen from the worker's side
        resources.redis_client().set(tunables.VALUES_KEY, json.dumps({'values': values, 't': 1}))

    def test_a_copy_is_reused_until_it_is_older_than_the_cache_window_and_then_read_again(self):
        self.raw_publish({'stage_parallel': 2})
        self.assertEqual(tunables.stored_values(now_fn=lambda: 1000.0), {'stage_parallel': 2})
        self.raw_publish({'stage_parallel': 3})
        self.assertEqual(tunables.stored_values(now_fn=lambda: 1000.0 + tunables.CACHE_SECONDS - 0.5), {'stage_parallel': 2})
        self.assertEqual(tunables.stored_values(now_fn=lambda: 1000.0 + tunables.CACHE_SECONDS + 0.5), {'stage_parallel': 3})

    def test_a_cache_window_of_a_few_seconds_at_most(self):
        self.assertTrue(0 < tunables.CACHE_SECONDS <= 5)

    def test_redis_down_keeps_the_last_copy_and_with_none_means_the_environment(self):
        self.raw_publish({'stage_parallel': 2})
        self.assertEqual(tunables.stored_values(now_fn=lambda: 10.0), {'stage_parallel': 2})
        with mock.patch.object(resources, 'redis_client', side_effect=OSError('redis down')):
            self.assertEqual(tunables.stored_values(now_fn=lambda: 100.0), {'stage_parallel': 2})
            tunables._cache.update(at=None, values={})
            os.environ['CVENGINE_STAGE_PARALLEL'] = '5'
            self.assertEqual(tunables.value('stage_parallel'), 5)  # no copy at all: the environment, as before this page

    def test_a_copy_that_is_not_an_object_is_ignored(self):
        resources.redis_client().set(tunables.VALUES_KEY, json.dumps({'values': [1, 2]}))
        self.assertEqual(tunables.stored_values(now_fn=lambda: 5.0), {})
        resources.redis_client().set(tunables.VALUES_KEY, 'not json')
        tunables.invalidate()
        self.assertEqual(tunables.stored_values(now_fn=lambda: 5.0), {})


class LivePropagationTests(Isolated, TestCase):
    """Each knob is read by the code that uses it on every use: a save changes what that code does, with no restart and no new process. The
    cache of this process is dropped by the save itself; a worker catches up within CACHE_SECONDS (CacheTests)."""

    def setUp(self):
        super().setUp()
        self.root = User.objects.create_superuser('tun_root', 't@x.io', 'x')

    def save(self, **values):
        tunables.update(values, self.root)

    def test_the_triage_caps(self):
        from cveFeed import triage
        self.assertEqual((triage.cap('TRIAGE_MAX_PER_RUN'), triage.cap('TRIAGE_MAX_PER_PROJECT_DAY'), triage.cap('TRIAGE_MAX_PER_DAY')), (100, 500, 2000))
        os.environ['CVENGINE_TRIAGE_MAX_PER_RUN'] = '40'
        self.assertEqual(triage.cap('TRIAGE_MAX_PER_RUN'), 40)
        self.save(triage_max_per_run=7, triage_max_per_project_day=70, triage_max_per_day=700)
        self.assertEqual((triage.cap('TRIAGE_MAX_PER_RUN'), triage.cap('TRIAGE_MAX_PER_PROJECT_DAY'), triage.cap('TRIAGE_MAX_PER_DAY')), (7, 70, 700))
        self.save(triage_max_per_run=None)
        self.assertEqual(triage.cap('TRIAGE_MAX_PER_RUN'), 40)

    def test_the_validation_caps(self):
        from cveFeed import validation
        self.assertEqual(validation.cap('VALIDATE_MAX_PER_DAY'), 1500)
        self.save(validate_max_per_run=5, validate_max_per_project_day=30, validate_max_per_day=150)
        self.assertEqual((validation.cap('VALIDATE_MAX_PER_RUN'), validation.cap('VALIDATE_MAX_PER_PROJECT_DAY'), validation.cap('VALIDATE_MAX_PER_DAY')), (5, 30, 150))

    def test_the_validation_gap(self):
        from cveFeed import hot_validation
        self.assertEqual(hot_validation.min_gap_hours(), 12.0)
        os.environ['CVENGINE_VALIDATE_MIN_GAP_HOURS'] = '2'
        self.assertEqual(hot_validation.min_gap_hours(), 2.0)
        self.save(validate_min_gap_hours=36)
        self.assertEqual(hot_validation.min_gap_hours(), 36.0)
        self.save(validate_min_gap_hours=0)
        self.assertEqual(hot_validation.min_gap_hours(), 0.0)  # an explicit 0 is a choice: the gap is off

    def test_the_template_budget_and_its_sibling_that_stays_in_the_environment(self):
        from cveFeed import templategen
        self.assertEqual(templategen.generation_limit('TEMPLATE_GEN_MAX_PER_DAY'), 10)
        self.save(template_gen_max_per_day=3)
        self.assertEqual(templategen.generation_limit('TEMPLATE_GEN_MAX_PER_DAY'), 3)
        self.assertEqual(templategen.generation_limit('TEMPLATE_GEN_CVE_DAYS'), 7)
        os.environ['CVENGINE_TEMPLATE_GEN_CVE_DAYS'] = '3'
        self.assertEqual(templategen.generation_limit('TEMPLATE_GEN_CVE_DAYS'), 3)

    def test_the_parallel_window_of_a_stage(self):
        from agentapi import sentinel_dispatch
        self.assertEqual(sentinel_dispatch.stage_parallel(), 4)
        self.save(stage_parallel=1)
        self.assertEqual(sentinel_dispatch.stage_parallel(), 1)  # the serial loop of before
        self.save(stage_parallel=12)
        self.assertEqual(sentinel_dispatch.stage_parallel(), 12)

    def test_the_conductor_gap_and_the_refresh_gap(self):
        from datetime import timedelta

        from cveFeed import conductor, coverage_topup
        self.assertEqual((conductor.min_gap(), coverage_topup.refresh_gap()), (timedelta(hours=2), timedelta(hours=6)))
        self.save(work_min_gap_hours=0, sentinel_refresh_gap_hours=0)
        self.assertEqual((conductor.min_gap(), coverage_topup.refresh_gap()), (timedelta(0), None))  # 0 turns the refresh off
        self.save(work_min_gap_hours=9, sentinel_refresh_gap_hours=48)
        self.assertEqual((conductor.min_gap(), coverage_topup.refresh_gap()), (timedelta(hours=9), timedelta(hours=48)))

    def test_the_bulk_add_batch(self):
        from agentapi import services
        domains = [mock.Mock(id=i) for i in range(60)]

        def queued():
            with mock.patch.object(services, '_start_discoveries', side_effect=lambda d, *a, **k: list(d)), mock.patch('cveFeed.conductor.wanted_depth', return_value=3), \
                    mock.patch('cveFeed.activity.log'), mock.patch('startScan.models.ScanHistory.objects') as scans:
                scans.filter.return_value.count.return_value = 0
                return len(services._discover_new(domains, 'standard', 7)[0])
        self.assertEqual(queued(), 50)
        self.save(bulk_discover_now=12)
        self.assertEqual(queued(), 12)

    def test_a_save_in_the_web_process_reaches_another_process_after_the_cache_window(self):
        """The whole path, with the two processes told apart: the saved row is published, a worker whose copy is older than the window reads it."""
        from cveFeed import triage
        self.assertEqual(tunables.stored_values(now_fn=lambda: 1.0), {})  # the worker has read (and cached) an empty copy at its time 1
        row = TunableSettings.current()
        row.values = {'triage_max_per_day': 123}  # the web process saved it ...
        row.save()
        resources.redis_client().set(tunables.VALUES_KEY, json.dumps({'values': tunables.saved_values(), 't': 1}))  # ... and published it
        self.assertEqual(tunables.stored_values(now_fn=lambda: 2.0), {})  # inside the window the worker still has its old copy
        self.assertEqual(tunables.stored_values(now_fn=lambda: 1.0 + tunables.CACHE_SECONDS + 1), {'triage_max_per_day': 123})
        tunables.invalidate()
        self.assertEqual(triage.cap('TRIAGE_MAX_PER_DAY'), 123)


class DocumentationTests(unittest.TestCase):
    """docs/CONFIGURATION.md has a row for every tunable that says where to set it and what the range is."""

    @classmethod
    def setUpClass(cls):
        cls.rows = [line for line in (ROOT / 'docs' / 'CONFIGURATION.md').read_text().splitlines() if line.startswith('|')]

    def row_for(self, env):
        return next((r for r in self.rows if f'`{env}`' in r), None)

    def test_every_tunable_has_a_row_that_points_to_configmaxxing_and_its_group(self):
        for t in tunables.TUNABLES:
            row = self.row_for(t.env)
            self.assertIsNotNone(row, f'docs/CONFIGURATION.md has no row for {t.env}')
            self.assertIn('configMaxxing', row, t.env)
            self.assertIn(tunables.GROUP_BY_ID[t.group].title, row, t.env)
            self.assertRegex(row, rf'\b{t.low} to {t.high}\b', f'{t.env}: the row does not give the range the page allows')

    def test_the_section_explains_the_precedence_and_the_groups(self):
        text = (ROOT / 'docs' / 'CONFIGURATION.md').read_text()
        self.assertIn('saved value wins over', text)
        for g in tunables.GROUPS:
            self.assertIn(f'**{g.title}**', text, g.id)

    def test_the_changelog_mentions_it_under_unreleased(self):
        changelog = (ROOT / 'CHANGELOG.md').read_text()
        unreleased = changelog.split('## Unreleased', 1)[1].split('\n## ', 1)[0]
        self.assertIn('configMaxxing', unreleased)
        self.assertIn('AI spend', unreleased)


if __name__ == '__main__':
    unittest.main()
