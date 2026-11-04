"""End to end through celery's own consumer: a real ``celery worker --pool=gevent --autoscale=N,1`` subprocess with the settings ``reNgine.celery``
sets, running acks_late tasks (``run_bbot_discovery`` and ``run_internal_scan`` are acks_late). For those the consumer's prefetch (QoS) is what
bounds how many run at once, so these go through it rather than stubbing the consumer (``tests/test_gevent_autoscale.py`` covers the pool):

* the worker runs as many as its ceiling, never more;
* a ceiling raised live while the worker is idle (configMaxxing's resize) is honoured: celery's own path returned early with no task running;
* after a broker reconnect the worker comes back to its ceiling: celery's prefetch restore read the greenlets running, so it stayed at one;
* an ack lost to a dropped broker connection does not cost a slot: kombu kept counting that delivery against the prefetch, so the worker ran
  one task fewer at once until a restart (``reNgine/broker_acks.py``). The reconnect test hit it when its cut landed on an ack.
* remote control (ping, ``autoscale``) is answered again after a broker reconnect: celery's gevent pidbox loop ended on the
  ``ConnectionError`` and, with kombu 5.7 keeping the consumer, never came back (``reNgine/gevent_pidbox.py``).

Needs the Redis of ``CELERY_BROKER`` (CI has it); skipped without it. Each test uses its own queue and keys and cuts only its own worker's
connections."""
import os
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path

import redis
from celery import Celery

WEB = Path(__file__).resolve().parent.parent
BROKER = os.environ.get('CELERY_BROKER', 'redis://127.0.0.1:6379/0')


def _redis_ok():
    try:
        return redis.Redis.from_url(BROKER, socket_connect_timeout=1).ping()
    except Exception:  # noqa: BLE001
        return False


@unittest.skipUnless(_redis_ok(), 'needs the Redis of CELERY_BROKER')
class GeventWorkerEndToEndTests(unittest.TestCase):

    def setUp(self):
        from reNgine.celery import app as real
        self.name = f'e2e{uuid.uuid4().hex[:10]}'
        self.queue = f'{self.name}_q'
        self.node = f'{self.name}@e2e'
        self.r = redis.Redis.from_url(BROKER)
        self.env = {**os.environ, 'E2E_BROKER': BROKER, 'E2E_NAME': self.name,
                    'E2E_AUTOSCALER': real.conf.worker_autoscaler or '',
                    'E2E_PREFETCH_REDUCTION': '1' if real.conf.worker_enable_prefetch_count_reduction else '0',
                    'E2E_PREFETCH_MULTIPLIER': str(real.conf.worker_prefetch_multiplier),
                    'PYTHONPATH': str(WEB)}
        self.client = Celery('e2e_client', broker=BROKER)
        self.worker = None

    def tearDown(self):
        if self.worker is not None:
            self.worker.kill()
            self.worker.wait(10)
            self.worker.stdout.close()
        self.r.delete(self.queue, f'{self.name}:running', f'{self.name}:max', f'{self.name}:done', f'{self.name}:dropped_ack',
                      f'{self.name}:drop_armed')
        self.client.close()

    def start(self, ceiling):
        self.worker = subprocess.Popen(
            [sys.executable, '-m', 'celery', '-A', 'tests.gevent_worker_app', 'worker', '--pool=gevent', '--optimization=fair',
             f'--autoscale={ceiling},1', '-Q', self.queue, '-n', self.node, '--without-gossip', '--without-mingle', '-l', 'info'],
            cwd=WEB, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.client.control.ping(destination=[self.node], timeout=1):
                return
            self.assertIsNone(self.worker.poll(), 'the worker exited')
        self.fail('the worker did not answer a ping within 60 s')

    def send(self, count, secs):
        for _ in range(count):
            self.client.send_task('e2e.late', args=(secs,), queue=self.queue)

    def running(self):
        return int(self.r.get(f'{self.name}:running') or 0)

    def most(self):
        return int(self.r.get(f'{self.name}:max') or 0)

    def watch(self, seconds, every=0.25):
        out, end = [], time.time() + seconds
        while time.time() < end:
            out.append(self.running())
            time.sleep(every)
        return out

    def cut(self):
        """Kill every broker connection of this worker (they carry its name), as a Redis restart or a network blip does."""
        mine = [line for line in self.r.client_list() if line.get('name') == self.name]
        self.assertTrue(mine, 'the worker\'s broker connections carry its name')
        for client in mine:
            self.r.client_kill_filter(_id=client['id'])

    def test_acks_late_tasks_run_up_to_the_ceiling_and_no_more(self):
        self.start(4)
        self.send(8, 3)
        self.watch(9)
        self.assertEqual(self.most(), 4)
        deadline = time.time() + 20
        while int(self.r.get(f'{self.name}:done') or 0) < 8 and time.time() < deadline:
            time.sleep(0.5)
        self.assertEqual(int(self.r.get(f'{self.name}:done') or 0), 8)

    def test_a_ceiling_raised_while_idle_is_honoured(self):
        self.start(2)
        replies = self.client.control.broadcast('autoscale', arguments={'max': 5}, destination=[self.node], reply=True, timeout=3)
        self.assertIn('max=5', str(replies))
        time.sleep(1)
        self.send(10, 5)
        self.watch(9)
        self.assertEqual(self.most(), 5)

    def test_the_worker_comes_back_to_its_ceiling_after_a_broker_reconnect(self):
        self.start(4)
        self.send(16, 5)
        before = self.watch(8)
        self.assertEqual(max(before), 4)
        self.cut()
        after = self.watch(25)
        # the tasks running at the cut finish within 5 s; from then on the worker must be back at its ceiling, not at one
        self.assertGreaterEqual(max(after[int(7 / 0.25):]), 4, after)

    def test_an_ack_lost_to_a_dropped_broker_connection_does_not_cost_a_slot(self):
        # The reconnect above fails only when the cut lands on an ack (about one run in thirty); this drops the first ack every time. kombu
        # then never freed the delivery, so the prefetch counted it for good and the worker ran 3 at a time from then on (reNgine/broker_acks.py).
        self.env['E2E_DROP_ONE_ACK'] = '1'
        self.start(4)
        self.send(24, 5)
        seen = self.watch(26)
        self.assertTrue(self.r.get(f'{self.name}:dropped_ack'), 'the first ack was dropped')
        # the first ack is about 5 s in; from 12 s on the worker must be running 4 at once again
        self.assertEqual(max(seen[int(12 / 0.25):]), 4, seen)

    def test_remote_control_is_answered_again_after_a_broker_reconnect(self):
        # ping, inspect, autoscale and revoke all go through this loop: scan_concurrency.apply_discovery's resize, the admin worker panel, a
        # revoke, broker_recovery.live_tasks. Before reNgine/gevent_pidbox.py the worker went on running tasks and answered none of them again.
        self.start(4)
        self.send(8, 3)
        time.sleep(2)
        self.cut()
        time.sleep(1)  # let the worker see the cut before asking
        deadline, pinged, resized = time.time() + 30, False, False
        while time.time() < deadline and not resized:
            if not pinged:
                pinged = bool(self.client.control.ping(destination=[self.node], timeout=1))
            if pinged:
                replies = self.client.control.broadcast('autoscale', arguments={'max': 5}, destination=[self.node], reply=True, timeout=2)
                resized = 'max=5' in str(replies)
        self.assertTrue(pinged, 'the worker answered no ping within 30 s of the cut')
        self.assertTrue(resized, 'the worker answered no autoscale within 30 s of the cut')
        # and it still runs its tasks, now up to the new ceiling
        self.send(10, 3)
        self.watch(8)
        self.assertEqual(self.most(), 5)
