from django.test import SimpleTestCase

from reNgine import time_limits
from reNgine.time_limits import QueueTimeLimits, limits_for


class QueueTimeLimitTests(SimpleTestCase):
    def test_every_default_queue_has_a_hard_limit_inside_the_redelivery_window_and_a_soft_limit_before_it(self):
        ceiling = 12 * 3600 - time_limits.VISIBILITY_MARGIN
        for queue, wanted in time_limits.DEFAULTS.items():
            soft, hard = limits_for(queue, {})
            self.assertEqual(hard, min(wanted, ceiling), queue)
            self.assertEqual(soft, hard - time_limits.SOFT_MARGIN, queue)
            self.assertLess(hard, 12 * 3600)  # a longer task would be delivered to a second worker while it still runs

    def test_scan_queues_get_the_longest_safe_limit_and_light_queues_a_short_one(self):
        # tasks of the scan queues wait for memory inside heavy_job (up to HEAVY_WAIT_SECONDS) before they run: a short limit would kill them
        longest = 12 * 3600 - time_limits.VISIBILITY_MARGIN
        for queue in ('discovery_queue', 'cve_feed_queue', 'validation_priority_queue', 'udp_queue', 'vhost_queue'):
            self.assertEqual(limits_for(queue, {})[1], longest, queue)
        for queue in ('api_queue', 'send_notif_queue', 'geo_localize_queue'):
            self.assertEqual(limits_for(queue, {})[1], 30 * 60, queue)
        self.assertEqual(limits_for('run_command_queue', {})[1], 3600)

    def test_openvas_and_unknown_queues_have_no_default_limit(self):
        # a local OpenVAS task has its own budget of 24 hours per host
        self.assertIsNone(limits_for('openvas_queue', {}))
        self.assertIsNone(limits_for('some_new_queue', {}))
        self.assertIsNone(limits_for(None, {}))

    def test_an_environment_value_overrides_one_queue_and_zero_turns_it_off(self):
        self.assertEqual(limits_for('udp_queue', {'CVENGINE_TIME_LIMIT_UDP': '7200'}), (6900, 7200))
        self.assertIsNone(limits_for('udp_queue', {'CVENGINE_TIME_LIMIT_UDP': '0'}))
        self.assertEqual(limits_for('openvas_queue', {'CVENGINE_TIME_LIMIT_OPENVAS': '36000'}), (35700, 36000))
        self.assertEqual(limits_for('udp_queue', {'CVENGINE_TIME_LIMIT_UDP': 'soon'}), limits_for('udp_queue', {}))  # a bad value is ignored

    def test_the_switch_turns_every_default_off(self):
        self.assertIsNone(limits_for('discovery_queue', {'CVENGINE_TIME_LIMITS': '0'}))

    def test_a_limit_stays_inside_the_visibility_timeout_and_above_a_minute(self):
        env = {'CVENGINE_TIME_LIMIT_DISCOVERY': str(48 * 3600)}
        self.assertEqual(limits_for('discovery_queue', env)[1], 12 * 3600 - time_limits.VISIBILITY_MARGIN)
        env['CELERY_VISIBILITY_TIMEOUT'] = '7200'
        self.assertEqual(limits_for('discovery_queue', env)[1], 7200 - time_limits.VISIBILITY_MARGIN)
        self.assertGreaterEqual(limits_for('udp_queue', {'CVENGINE_TIME_LIMIT_UDP': '5'})[1], 2 * time_limits.MIN_SECONDS)

    def test_a_task_that_declares_its_own_limit_keeps_it(self):
        class Own:
            queue, time_limit, soft_time_limit = 'cve_feed_queue', 3600, None

        class Plain:
            queue, time_limit, soft_time_limit = 'cve_feed_queue', None, None

        self.assertIsNone(QueueTimeLimits().annotate(Own()))
        self.assertEqual(QueueTimeLimits().annotate(Plain())['time_limit'], 12 * 3600 - time_limits.VISIBILITY_MARGIN)

    def test_the_registered_tasks_get_the_limits_of_their_queue(self):
        from reNgine.celery import app
        app.loader.import_default_modules()
        longest = 12 * 3600 - time_limits.VISIBILITY_MARGIN
        self.assertEqual(app.tasks['validate_match_on_demand'].time_limit, longest)
        self.assertEqual(app.tasks['queue_hot_validations'].time_limit, longest)
        self.assertEqual(app.tasks['load_cve_seed'].time_limit, 3600)  # its own limit, unchanged
        self.assertIsNone(app.tasks['openvas_sweep'].time_limit)
