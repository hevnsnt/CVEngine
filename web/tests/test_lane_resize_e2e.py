"""A worker lane resized live by auto-tuning, through celery's own consumer (1.4.0 WP5): ``scan_concurrency.apply_lanes`` finds a real ``celery worker --pool=gevent
--autoscale=4,1`` subprocess whose node is named like the CVE-feed lane (``cve_feed_worker@<host>``, what ``-n cve_feed_worker`` gives), lowers its ceiling with
celery's ``autoscale`` remote control, and the tasks it holds finish (none is killed) while no more than the new number run at once afterwards. The harness is that
of ``tests/test_gevent_worker_e2e.py`` (needs the Redis of CELERY_BROKER; a worker that cannot start on this machine skips the test, CI has what it needs)."""
import os
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock

import redis
from celery import Celery

from tests.test_gevent_worker_e2e import BROKER, WEB, _redis_ok


@unittest.skipUnless(_redis_ok(), 'needs the Redis of CELERY_BROKER')
class LaneResizeEndToEndTests(unittest.TestCase):
    def setUp(self):
        from reNgine.celery import app as real
        self.name = f'lane{uuid.uuid4().hex[:10]}'
        self.queue = f'{self.name}_q'
        self.node = f'cve_feed_worker@{self.name}'
        self.r = redis.Redis.from_url(BROKER)
        self.env = {**os.environ, 'E2E_BROKER': BROKER, 'E2E_NAME': self.name, 'E2E_AUTOSCALER': real.conf.worker_autoscaler or '',
                    'E2E_PREFETCH_REDUCTION': '1' if real.conf.worker_enable_prefetch_count_reduction else '0',
                    'E2E_PREFETCH_MULTIPLIER': str(real.conf.worker_prefetch_multiplier), 'PYTHONPATH': os.pathsep.join([str(WEB)] + [p for p in sys.path if p])}
        self.client = Celery('lane_client', broker=BROKER)
        self.worker = None

    def tearDown(self):
        if self.worker is not None:
            self.worker.kill()
            self.worker.wait(10)
            self.worker.stdout.close()
        self.r.delete(self.queue, f'{self.name}:running', f'{self.name}:max', f'{self.name}:done')
        self.client.close()

    def until(self, condition, seconds, what):
        end = time.time() + seconds
        while time.time() < end:
            if condition():
                return
            time.sleep(0.25)
        self.fail(what)

    def start(self, ceiling, floor=1):
        self.worker = subprocess.Popen(
            [sys.executable, '-m', 'celery', '-A', 'tests.gevent_worker_app', 'worker', '--pool=gevent', '--optimization=fair', f'--autoscale={ceiling},{floor}', '-Q', self.queue,
             '-n', self.node, '--without-gossip', '--without-mingle', '-l', 'info'],
            cwd=WEB, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        end = time.time() + 60
        while time.time() < end and not self.client.control.ping(destination=[self.node], timeout=1):
            if self.worker.poll() is not None:
                self.skipTest('the worker cannot start on this machine: ' + (self.worker.stdout.read() or '')[-300:].replace('\n', ' '))

    def done(self):
        return int(self.r.get(f'{self.name}:done') or 0)

    def test_a_long_task_does_not_stop_a_control_task_at_the_floor_but_does_at_one(self):
        # FC-1. The CVE-feed lane runs the control tasks (auto-tuning, the 30 second reconcile, feed_sentinels, the conductor, the reaper) beside long ones. At the floor of
        # three a long task leaves slots for them; at one it holds the whole lane, which is what the floor prevents.
        from cveFeed import scan_concurrency as sc
        floor = sc.LANE_FLOORS['lane.cve_feed']
        self.assertEqual(floor, 3)
        self.start(floor, floor)  # a pool held at that size, so how fast the autoscaler grows (it differs between celery releases) is not what is tested
        self.client.send_task('e2e.late', args=(25,), queue=self.queue)  # one long task (a CVE correlation, a template update) ...
        self.client.send_task('e2e.late', args=(1,), queue=self.queue)  # ... and a control task behind it
        self.until(lambda: self.done() >= 1, 20, 'at the floor a control task did not run beside one long task')
        self.assertEqual(int(self.r.get(f'{self.name}:running') or 0), 1)  # the long task is still running
        self.worker.kill()
        self.worker.wait(10)
        self.worker.stdout.close()
        self.r.delete(self.queue, f'{self.name}:running', f'{self.name}:max', f'{self.name}:done')
        self.start(1, 1)  # the number the rule used to be able to reach
        self.client.send_task('e2e.late', args=(25,), queue=self.queue)
        self.client.send_task('e2e.late', args=(1,), queue=self.queue)
        time.sleep(8)
        self.assertEqual(self.done(), 0, 'at one slot the control task waited behind the long task')

    def test_lowering_the_lane_resizes_the_running_worker_and_kills_no_task(self):
        from cveFeed import scan_concurrency as sc
        self.start(4)
        self.assertEqual(sc.lane_ceilings('lane.cve_feed', app=self.client), {self.node: 4})
        for _ in range(8):
            self.client.send_task('e2e.late', args=(3,), queue=self.queue)
        self.until(lambda: int(self.r.get(f'{self.name}:running') or 0) == 4, 30, 'four tasks did not run at once')
        with mock.patch.object(sc, '_tuned_from_database', return_value={'lane.cve_feed': 3}):
            out = sc.apply_lanes(app=self.client, saved={})
        self.assertEqual((out['lane.cve_feed']['want'], out['lane.cve_feed']['changed']), (3, [self.node]))
        self.assertEqual(out['lane.classic']['workers'], {})  # no classic lane here: nothing to resize
        self.assertEqual(sc.lane_ceilings('lane.cve_feed', app=self.client), {self.node: 3})
        self.until(lambda: int(self.r.get(f'{self.name}:done') or 0) >= 4, 30, 'the four running tasks did not finish')
        later = []
        end = time.time() + 6
        while time.time() < end:
            later.append(int(self.r.get(f'{self.name}:running') or 0))
            time.sleep(0.25)
        self.assertLessEqual(max(later), 3)
        self.until(lambda: int(self.r.get(f'{self.name}:done') or 0) == 8, 60, 'a task was lost by the resize')
