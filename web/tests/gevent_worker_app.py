"""A celery app of its own for ``tests/test_gevent_worker_e2e.py``: started as a real ``celery worker --pool=gevent --autoscale=N,1`` subprocess
with the worker settings ``reNgine.celery`` uses (passed in the environment by the test) and what importing ``reNgine.celery`` sets up, so the
consumer, its QoS (prefetch) and the broker connection are celery's and kombu's own, as in a CVEngine worker. Its one task is acks_late, like ``run_bbot_discovery`` and ``run_internal_scan``, and counts how many run at once."""
import os
import time

import redis
from celery import Celery

BROKER = os.environ['E2E_BROKER']
NAME = os.environ['E2E_NAME']

app = Celery('gevent_e2e', broker=BROKER)
app.conf.update(
    task_ignore_result=True,
    worker_prefetch_multiplier=int(os.environ['E2E_PREFETCH_MULTIPLIER']),
    worker_enable_prefetch_count_reduction=os.environ['E2E_PREFETCH_REDUCTION'] == '1',
    broker_transport_options={'client_name': NAME},  # the test finds this worker's broker connections by name to cut them
    broker_connection_retry_on_startup=True,
)
if os.environ.get('E2E_AUTOSCALER'):
    app.conf.worker_autoscaler = os.environ['E2E_AUTOSCALER']
# Every CVEngine worker runs with what importing reNgine.celery sets up besides the worker settings above (``celery -A reNgine``), such as
# reNgine/broker_acks.py's guard of kombu's acks
import reNgine.celery  # noqa: F401

counter = redis.Redis.from_url(BROKER)
ENTER = counter.register_script("local n = redis.call('incr', KEYS[1]) if n > tonumber(redis.call('get', KEYS[2]) or '0') then "
                                "redis.call('set', KEYS[2], n) end return n")


@app.task(name='e2e.late', acks_late=True)
def late(secs):
    ENTER(keys=[f'{NAME}:running', f'{NAME}:max'])
    try:
        time.sleep(secs)
    finally:
        counter.decr(f'{NAME}:running')
        counter.incr(f'{NAME}:done')


if os.environ.get('E2E_DROP_ONE_ACK') == '1':
    # The broker connection drops while the first ack is being sent: its removal from the unacked index raises, as redis-py does for a
    # connection the broker closed (kombu's Redis connection pool does not retry). Recorded so the test knows it happened.
    from kombu.transport import redis as kombu_redis

    _remove_from_indices = kombu_redis.QoS._remove_from_indices

    class _DroppedPipeline:
        def __init__(self, pipe):
            self.pipe = pipe

        def execute(self):
            self.pipe.reset()
            counter.set(f'{NAME}:dropped_ack', 1)
            raise redis.exceptions.ConnectionError('Connection closed by server.')

    def _remove_dropping_the_first(self, delivery_tag, pipe=None):
        out = _remove_from_indices(self, delivery_tag, pipe)
        if pipe is None and counter.set(f'{NAME}:drop_armed', 1, nx=True):
            return _DroppedPipeline(out)
        return out

    kombu_redis.QoS._remove_from_indices = _remove_dropping_the_first


