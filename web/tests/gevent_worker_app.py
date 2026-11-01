"""A Django-free celery app for ``tests/test_gevent_worker_e2e.py``: started as a real ``celery worker --pool=gevent --autoscale=N,1`` subprocess
with the worker settings ``reNgine.celery`` uses (passed in the environment by the test), so the consumer, its QoS (prefetch) and the broker
connection are celery's own. Its one task is acks_late, like ``run_bbot_discovery`` and ``run_internal_scan``, and counts how many run at once."""
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
