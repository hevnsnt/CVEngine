#!/usr/bin/env python3
"""N simulated Sentinels checking in to a running server over HTTP, as the real client does (sentinel/heartbeat, sentinel/tasks/next, accept, result).

    python scripts/scale/sentinel_sim.py --url http://127.0.0.1:28500 --sentinels 10 --seconds 120 --poll-wait 0 --every 3 --out /tmp/sim.json

The bearer keys are the fixture's (``manage.py seed_scale_fixture --sentinels N``: ``cve_scalefx<i>`` plus 32 x). Each Sentinel is a thread with its own
session. ``--poll-wait 0 --every 3`` is a short poll every 3 seconds; ``--poll-wait 15`` is what the shipped client does (a long poll). A task it is
handed is accepted, "worked" for ``--work`` seconds and reported with the contract fixture of its kind (``web/tests/fixtures/sentinel_results``).
Reports per endpoint the requests, status codes and latency percentiles. Synthetic data only; refuses a url that is not loopback or a private address.
"""
import argparse
import json
import os
import random
import statistics
import threading
import time
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, '..', '..', 'web', 'tests', 'fixtures', 'sentinel_results')
KINDS = ['nmap', 'naabu', 'nuclei_light', 'discover']
SHARED = {'nuclei_targeted': 'nuclei_light'}


def result_for(kind):
    path = os.path.join(FIXTURES, f'{SHARED.get(kind, kind)}.json')
    try:
        with open(path) as fh:
            return json.load(fh)
    except OSError:
        return {'outcome': 'error', 'error': 'no fixture'}


def loop(i, args, end, stats, lock):
    token = f'cve_scalefx{i:03d}' + 'x' * 32
    s = requests.Session()
    s.headers['Authorization'] = f'Bearer {token}'
    base = args.url.rstrip('/') + '/api/v1/'
    last_hb = 0.0

    def call(label, method, path, body=None):
        t0 = time.perf_counter()
        try:
            r = s.request(method, base + path, json=body, timeout=60)
            code = r.status_code
        except requests.RequestException as exc:
            r, code = None, type(exc).__name__
        ms = (time.perf_counter() - t0) * 1000
        with lock:
            stats.setdefault(label, []).append((code, ms))
        return r

    time.sleep(random.uniform(0, args.every))
    while time.monotonic() < end:
        if time.monotonic() - last_hb >= args.heartbeat:
            last_hb = time.monotonic()
            call('heartbeat', 'POST', 'sentinel/heartbeat', {'running': []})
        r = call('tasks/next', 'POST', 'sentinel/tasks/next', {'wait': args.poll_wait, 'kinds': KINDS})
        task = None
        if r is not None and r.status_code == 429:  # the per-token rate limit: wait as the answer says, as the shipped client does
            time.sleep(float(r.headers.get('Retry-After', 1) or 1))
            continue
        if r is not None and r.status_code == 200:
            task = (r.json() or {}).get('task')
        if task:
            tid = task['id']
            call('accept', 'POST', f'sentinel/tasks/{tid}/accept')
            time.sleep(args.work)
            body = result_for(task.get('kind', 'nmap'))
            call('result', 'POST', f'sentinel/tasks/{tid}/result', body if 'outcome' in body else {'outcome': 'done', **body})
            continue  # ask again at once, as the client does after a task
        if args.poll_wait == 0:
            time.sleep(args.every * random.uniform(0.9, 1.1))


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * q))] if values else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://127.0.0.1:28500')
    ap.add_argument('--sentinels', type=int, default=10)
    ap.add_argument('--first', type=int, default=0, help='index of the first fixture Sentinel')
    ap.add_argument('--seconds', type=int, default=60)
    ap.add_argument('--poll-wait', type=int, default=0)
    ap.add_argument('--every', type=float, default=3.0)
    ap.add_argument('--heartbeat', type=float, default=60.0)
    ap.add_argument('--work', type=float, default=2.0)
    ap.add_argument('--out', default='')
    args = ap.parse_args()
    host = urllib.parse.urlparse(args.url).hostname or ''
    if not (host in ('localhost',) or host.startswith(('127.', '10.', '192.168.', '172.'))):
        raise SystemExit('refusing: the simulator only talks to a loopback or private address')
    stats, lock = {}, threading.Lock()
    end = time.monotonic() + args.seconds
    threads = [threading.Thread(target=loop, args=(args.first + i, args, end, stats, lock), daemon=True) for i in range(args.sentinels)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(args.seconds + 90)
    out = {}
    for label, rows in sorted(stats.items()):
        ms = [m for _c, m in rows]
        codes = {}
        for c, _m in rows:
            codes[str(c)] = codes.get(str(c), 0) + 1
        out[label] = {'n': len(rows), 'codes': codes, 'p50_ms': round(statistics.median(ms), 1), 'p95_ms': round(pct(ms, .95), 1), 'max_ms': round(max(ms), 1)}
        print(f"{label:12} n={len(rows):6d} codes={codes} p50={out[label]['p50_ms']} p95={out[label]['p95_ms']} max={out[label]['max_ms']}")
    if args.out:
        with open(args.out, 'w') as fh:
            json.dump({'args': vars(args), 'endpoints': out}, fh, indent=1)


if __name__ == '__main__':
    main()
