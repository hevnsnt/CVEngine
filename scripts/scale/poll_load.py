#!/usr/bin/env python3
"""Clients polling a running server, and what that costs the server and the database.

    cd web && python ../scripts/scale/poll_load.py --clients 10 --seconds 60 --out /tmp/poll.json

Each client is one open dashboard tab: the pollers of static/cve/dashboard.js at their own intervals (stats 6 s, graph 10 s, discovery 2.5 s, activity 2 s,
feed 6 s, graph-live 3 s), the shell's live tick (stats, 8 s), the notifier (scans, 20 s) and the Sentinels page's live poll (5 s); a poll that was given a
validator (ETag) sends it back, as a browser does. The clients are threads of this process, each with its own signed-in Django test client and its own
database connection: the whole stack of a request runs (middleware, views, queries), without a socket or a WSGI server. Reports per endpoint the requests,
the status codes and the latency percentiles, the database's own counters for the fixture database (pg_stat_database deltas: transactions, rows returned and
fetched, buffers) and the CPU this process used (the Python side of the requests; threads share one interpreter lock, as a gunicorn worker's do).
Needs the fixture database (``manage.py seed_scale_fixture``) and its ``scale-admin`` user; refuses a database without "scale" in its name.
"""
import argparse
import json
import os
import random
import statistics
import sys
import threading
import time

sys.path.insert(0, os.getcwd())
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
import django  # noqa: E402

django.setup()

SLUG = 'scale-fixture'
POLLS = [  # (label, path, seconds between polls)
    ('api/stats', f'/cve/api/stats?project={SLUG}', 6),
    ('api/graph', f'/cve/api/graph?v=0&project={SLUG}', 10),
    ('api/discovery', f'/cve/api/discovery?scan=0&after=0&project={SLUG}', 2.5),
    ('api/activity', f'/cve/api/activity?after=0&running=&project={SLUG}', 2),
    ('api/feed', '/cve/api/feed', 6),
    ('api/graph-live', f'/cve/api/graph-live?project={SLUG}', 3),
    ('api/stats (live tick)', f'/cve/api/stats?project={SLUG}', 8),
    ('scans (notifier)', f'/api/v1/projects/{SLUG}/scans?page_size=200', 20),
    ('sentinels/live', '/api/v1/sentinels/live', 5),
]


def db_counters(db):
    from django.db import connection
    with connection.cursor() as c:
        c.execute('select xact_commit, tup_returned, tup_fetched, blks_hit + blks_read from pg_stat_database where datname = %s', [db])
        return c.fetchone()


def client_loop(end, results, lock):
    from django.contrib.auth.models import User
    from django.db import connection
    from django.test import Client
    client = Client(HTTP_HOST='localhost', raise_request_exception=False)
    client.force_login(User.objects.get(username='scale-admin'))
    etags = {}
    due = {label: time.monotonic() + random.uniform(0, interval) for label, _p, interval in POLLS}
    while time.monotonic() < end:
        now = time.monotonic()
        for label, path, interval in POLLS:
            if due[label] > now:
                continue
            due[label] = now + interval * random.uniform(0.9, 1.1)
            extra = {'HTTP_IF_NONE_MATCH': etags[(label, path)]} if (label, path) in etags else {}
            started = time.perf_counter()
            response = client.get(path, **extra)
            ms = (time.perf_counter() - started) * 1000
            if response.headers.get('ETag'):
                etags[(label, path)] = response.headers['ETag']
            with lock:
                results.setdefault(label, []).append((response.status_code, ms))
        time.sleep(0.05)
    connection.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--clients', type=int, default=10)
    ap.add_argument('--seconds', type=int, default=60)
    ap.add_argument('--out', default='')
    args = ap.parse_args()
    from django.db import connection
    db = connection.settings_dict['NAME']
    if 'scale' not in db:
        sys.exit('refusing: the database name must contain "scale"')
    results, lock = {}, threading.Lock()
    before, cpu0 = db_counters(db), sum(os.times()[:2])
    started = time.monotonic()
    end = started + args.seconds
    threads = [threading.Thread(target=client_loop, args=(end, results, lock)) for _ in range(args.clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.monotonic() - started
    after, cpu1 = db_counters(db), sum(os.times()[:2])
    rows, total = [], 0
    for label, got in sorted(results.items()):
        ms = sorted(m for _s, m in got)
        codes = {}
        for s, _m in got:
            codes[s] = codes.get(s, 0) + 1
        total += len(got)
        rows.append({'endpoint': label, 'requests': len(got), 'statuses': codes, 'p50_ms': round(statistics.median(ms), 1),
                     'p95_ms': round(ms[max(0, int(len(ms) * 0.95) - 1)], 1), 'max_ms': round(ms[-1], 1)})
    out = {'clients': args.clients, 'seconds': round(wall), 'requests': total, 'requests_per_second': round(total / wall, 2), 'endpoints': rows,
           'db': {'transactions': after[0] - before[0], 'rows_returned': after[1] - before[1], 'rows_fetched': after[2] - before[2], 'buffers': after[3] - before[3],
                  'transactions_per_second': round((after[0] - before[0]) / wall, 1)},
           'python_cpu_seconds': round(cpu1 - cpu0, 1), 'python_cpu_percent_of_one_core': round((cpu1 - cpu0) / wall * 100, 1)}
    print(json.dumps(out, indent=1))
    if args.out:
        with open(args.out, 'w') as fh:
            json.dump(out, fh, indent=1)


if __name__ == '__main__':
    main()
