#!/usr/bin/env python3
"""Measure the slow paths of a large install on a throwaway database.

    cd web && python ../scripts/scale/measure.py --label 3000 --out /tmp/scale-3000.json [--explain] [--only substring]

Needs a database seeded by ``python manage.py seed_scale_fixture --hosts N`` (refuses a database whose name has no "scale" in it). For every
endpoint and background task it records, cold (shared cache emptied) and warm (second call, cache filled): wall time, the number of SQL
statements, the time the database spent on them (the sum of what Django measured around each execute) and the slowest statement. Background
tasks run inside a transaction that is rolled back, so the fixture is the same for the next one. ``--explain`` writes EXPLAIN (ANALYZE, BUFFERS)
of the three slowest SELECTs of each entry beside the JSON.
"""
import argparse
import json
import os
import sys
import time
from datetime import timedelta

sys.path.insert(0, os.getcwd())
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
import django  # noqa: E402

django.setup()

from django.core.cache import cache  # noqa: E402
from django.db import connection, transaction  # noqa: E402
from django.test import Client  # noqa: E402
from django.test.utils import CaptureQueriesContext  # noqa: E402
from django.utils import timezone  # noqa: E402

SLUG = 'scale-fixture'


def endpoints():
    s = SLUG
    since = (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    p = f'/api/v1/projects/{s}'
    return [
        # the dashboard: the shell, then everything dashboard.js polls
        ('dashboard', 'dashboard page shell', f'/cve/?project={s}&skip=1'),
        ('dashboard', 'api/stats (headline counts)', f'/cve/api/stats?project={s}'),
        ('dashboard', 'api/graph (attack-surface map)', f'/cve/api/graph?project={s}'),
        ('dashboard', 'api/graph-live', f'/cve/api/graph-live?project={s}'),
        ('dashboard', 'api/discovery', f'/cve/api/discovery?project={s}&after=0'),
        ('dashboard', 'api/activity', f'/cve/api/activity?project={s}&after=0'),
        ('dashboard', 'api/feed', '/cve/api/feed'),
        ('dashboard', 'coverage (search page_size=1)', f'{p}/search?q=&page_size=1'),
        ('dashboard', 'hygiene top (critical)', f'{p}/hygiene?severity=critical&page_size=100'),
        ('dashboard', 'changes (page_size=1)', f'{p}/changes?since={since}&page_size=1'),
        ('dashboard', 'findings counts (page_size=0)', f'{p}/findings?page_size=0&type=all'),
        ('dashboard', 'stats/history', f'{p}/stats/history'),
        ('dashboard', 'scans (page_size=200)', f'{p}/scans?page_size=200'),
        # the Hosts page
        ('hosts', 'hosts page shell', f'/cve/{s}/hosts/'),
        ('hosts', 'search page 1 (50 rows, facets)', f'{p}/search?q=&sort=score&page=1&page_size=50'),
        ('hosts', 'search page 1 (no facets)', f'{p}/search?q=&sort=score&facets=none&page=1&page_size=50'),
        ('hosts', 'search q=nginx', f'{p}/search?q=nginx&facets=none&page=1&page_size=50'),
        ('hosts', 'hosts list (50 rows)', f'{p}/hosts?page=1&page_size=50'),
        ('hosts', 'hosts list page 40', f'{p}/hosts?page=40&page_size=50'),
        ('hosts', 'targets list', f'{p}/targets?page_size=200'),
        # the Findings page
        ('findings', 'findings page shell', f'/cve/{s}/vulns/'),
        ('findings', 'findings (page 1, 50)', f'{p}/findings?type=all&page=1&page_size=50'),
        ('findings', 'findings (counts only)', f'{p}/findings?type=all&page_size=0'),
        ('findings', 'findings group=cve', f'{p}/findings?type=all&group=cve&page=1&page_size=50'),
        ('findings', 'matches (50)', f'{p}/matches?page=1&page_size=50'),
        ('findings', 'vulnerabilities (50)', f'{p}/vulnerabilities?page=1&page_size=50'),
        ('findings', 'triage (50)', f'{p}/triage?page=1&page_size=50'),
        # the 8 second polling and the Sentinel screens
        ('polling', 'sentinels/live', '/api/v1/sentinels/live'),
        ('polling', 'sentinels/live (304 path)', '/api/v1/sentinels/live', 'etag'),
        ('polling', 'api/stats (304 path)', f'/cve/api/stats?project={s}', 'etag'),
        ('polling', 'scans (poll)', f'{p}/scans?page_size=200', 'etag'),
        ('polling', 'api/alive', '/cve/api/alive'),
        ('polling', 'api/scanner', '/cve/api/scanner'),
        ('polling', 'sentinels (project)', f'{p}/sentinels'),
        ('polling', 'sentinel-tasks', f'{p}/sentinel-tasks'),
        ('polling', 'system/status', '/api/v1/system/status'),
    ]


def tasks():
    """(group, label, Celery task name). Each runs in a rolled-back transaction."""
    return [
        ('queue', 'work_conductor', 'work_conductor'),
        ('queue', 'feed_sentinels', 'feed_sentinels'),
        ('queue', 'stage_runs_tick', 'stage_runs_tick'),
        ('queue', 'reap_stuck_jobs', 'reap_stuck_jobs'),
        ('queue', 'background_full_scan', 'background_full_scan'),
        ('queue', 'weekly_deep_nuclei', 'weekly_deep_nuclei'),
        ('queue', 'retest_sweep', 'retest_sweep'),
        ('queue', 'top_up_host_assessments', 'top_up_host_assessments'),
        ('queue', 'queue_hot_validations', 'queue_hot_validations'),
        ('queue', 'reconcile_invalid_correlations', 'reconcile_invalid_correlations'),
        ('queue', 'evaluate_saved_searches', 'evaluate_saved_searches'),
        ('queue', 'autotune', 'autotune'),
        ('queue', 'report_resources', 'report_resources'),
        ('queue', 'watch_certificates_all', 'watch_certificates_all'),
        ('queue', 'rediscover_archived_hosts', 'rediscover_archived_hosts'),
        ('queue', 'review_inactive_hosts', 'review_inactive_hosts'),
        ('queue', 'review_unresolved_hosts', 'review_unresolved_hosts'),
        ('daily', 'rescore_all_hosts', 'rescore_all_hosts'),
        ('daily', 'run_hygiene_all', 'run_hygiene_all'),
        ('daily', 'triage_sweep', 'triage_sweep'),
        ('daily', 'snapshot_daily_stats', 'snapshot_daily_stats'),
        ('daily', 'validate_sweep', 'validate_sweep'),
    ]


def measure(fn):
    """Run ``fn`` once with every statement captured: ``(result, ms, queries, db_ms, slowest, statements)``."""
    with CaptureQueriesContext(connection) as cq:
        t0 = time.perf_counter()
        try:
            result, err = fn(), None
        except Exception as exc:  # noqa: BLE001 - a failing entry is a row of the table, not the end of the run
            result, err = None, f'{type(exc).__name__}: {str(exc)[:120]}'
        wall = (time.perf_counter() - t0) * 1000
    q = cq.captured_queries
    times = sorted(((float(x['time']) * 1000, x['sql']) for x in q), reverse=True)
    return {'result': result, 'error': err, 'wall_ms': round(wall, 1), 'queries': len(q), 'db_ms': round(sum(t for t, _ in times), 1),
            'slowest_ms': round(times[0][0], 1) if times else 0, 'slowest_sql': times[0][1][:300] if times else '',
            'top_sql': [s for _, s in times[:3]], 'repeats': repeats([x['sql'] for x in q])}


def repeats(statements, top=4):
    """The statements that ran more than once with their literals blanked out: [(times, shape)], most repeated first. An N+1 shows up here."""
    import re
    from collections import Counter
    shape = Counter(re.sub(r'\s+', ' ', re.sub(r"'[^']*'|\b\d+(\.\d+)?\b|\((?:%s|,|\s|\d)+\)", '?', sql))[:230] for sql in statements)
    return [(n, sql) for sql, n in shape.most_common(top) if n > 2]


def explain(sqls, handle, label):
    for i, sql in enumerate(sqls):
        if not sql.lstrip().upper().startswith(('SELECT', 'WITH')):
            continue
        try:
            with connection.cursor() as c, transaction.atomic():
                c.execute('EXPLAIN (ANALYZE, BUFFERS) ' + sql)
                plan = '\n'.join(r[0] for r in c.fetchall())
                transaction.set_rollback(True)
        except Exception as exc:  # noqa: BLE001
            plan = f'explain failed: {exc}'
        handle.write(f'### {label} - statement {i + 1}\n```\n{sql[:2000]}\n```\n```\n{plan}\n```\n\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--label', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--explain', action='store_true')
    ap.add_argument('--only', default='')
    ap.add_argument('--dups', action='store_true', help='print the statements an entry repeats (an N+1 shows up here)')
    ap.add_argument('--warm-runs', type=int, default=3)
    args = ap.parse_args()
    if 'scale' not in connection.settings_dict['NAME']:
        sys.exit('refusing: the database name must contain "scale"')
    from django.contrib.auth.models import User
    user = User.objects.get(username='scale-admin')
    client = Client(HTTP_HOST='localhost', raise_request_exception=False)
    client.force_login(user)
    out = {'label': args.label, 'entries': []}
    plans = open(args.out.replace('.json', '-explain.md'), 'w') if args.explain else None

    from reNgine import settings as rs  # noqa: F401  (the settings are loaded; the import only fails loudly if they are not)
    for entry in endpoints():
        group, label, path = entry[:3]
        mode = entry[3] if len(entry) > 3 else ''
        if args.only and args.only not in label and args.only not in group:
            continue
        cache.clear()
        if mode == 'etag':
            first = client.get(path)
            tag = first.headers.get('ETag')
            call = lambda: client.get(path, HTTP_IF_NONE_MATCH=tag) if tag else client.get(path)  # noqa: E731
            cold = measure(call)
            warm = [measure(call) for _ in range(args.warm_runs)]
        else:
            call = lambda: client.get(path)  # noqa: E731
            cold = measure(call)
            warm = [measure(call) for _ in range(args.warm_runs)]
        warm_best = min(warm, key=lambda m: m['wall_ms'])
        status = cold['result'].status_code if cold['result'] is not None else None
        size = len(cold['result'].content) if cold['result'] is not None else 0
        row = {'group': group, 'label': label, 'path': path, 'status': status, 'bytes': size, 'error': cold['error'],
               'cold': {k: cold[k] for k in ('wall_ms', 'queries', 'db_ms', 'slowest_ms', 'slowest_sql')},
               'warm': {k: warm_best[k] for k in ('wall_ms', 'queries', 'db_ms', 'slowest_ms')}, 'repeats': cold['repeats']}
        out['entries'].append(row)
        print(f"{group:9} {label:38} {status}  cold {cold['wall_ms']:9.1f} ms {cold['queries']:5d} q db {cold['db_ms']:9.1f} | warm {warm_best['wall_ms']:8.1f} ms {warm_best['queries']:4d} q", flush=True)
        if args.dups:
            for n, sql in cold['repeats']:
                print(f'      x{n}: {sql}')
        if plans:
            explain(cold['top_sql'], plans, f'{group}: {label}')

    from reNgine.celery import app
    app.loader.import_default_modules()
    for group, label, dotted in tasks():
        if args.only and args.only not in label and args.only not in group:
            continue
        task = app.tasks[dotted]
        cache.clear()

        def run():
            with transaction.atomic():
                try:
                    return task.run() if hasattr(task, 'run') else task()
                finally:
                    transaction.set_rollback(True)
        m = measure(run)
        out['entries'].append({'group': group, 'label': label, 'path': dotted, 'status': 'task', 'bytes': 0, 'error': m['error'],
                               'cold': {k: m[k] for k in ('wall_ms', 'queries', 'db_ms', 'slowest_ms', 'slowest_sql')}, 'warm': None, 'repeats': m['repeats']})
        print(f"{group:9} {label:38} task  {m['wall_ms']:9.1f} ms {m['queries']:5d} q db {m['db_ms']:9.1f}  {m['error'] or ''}", flush=True)
        if args.dups:
            for n, sql in m['repeats']:
                print(f'      x{n}: {sql}')
        if plans:
            explain(m['top_sql'], plans, f'{group}: {label}')

    out['reports'] = report_entries(args)
    with open(args.out, 'w') as fh:
        json.dump(out, fh, indent=1, default=str)


def report_entries(args):
    """The report: the data builder (``report_data.collect``, whole project and one host), the HTML template, and the PDF render (a child
    process, so only its wall time is meaningful)."""
    if args.only and args.only not in 'report':
        return []
    import tempfile
    from cveFeed import report_data, report_pdf
    from dashboard.models import Project
    from startScan.models import Subdomain
    project = Project.objects.get(slug=SLUG)
    host = Subdomain.objects.filter(target_domain__project=project).order_by('id').values_list('name', flat=True).first()
    rows = []

    def entry(label, fn):
        cache.clear()
        m = measure(fn)
        rows.append({'group': 'report', 'label': label, 'path': '', 'status': 'ok' if not m['error'] else 'error', 'bytes': 0, 'error': m['error'],
                     'cold': {k: m[k] for k in ('wall_ms', 'queries', 'db_ms', 'slowest_ms', 'slowest_sql')}, 'warm': None, 'repeats': m['repeats']})
        print(f"report    {label:38} {m['wall_ms']:9.1f} ms {m['queries']:5d} q db {m['db_ms']:9.1f}  {m['error'] or ''}", flush=True)
        if args.explain:
            with open(args.out.replace('.json', '-explain.md'), 'a') as fh:
                explain(m['top_sql'], fh, f'report: {label}')
        return m['result']
    data = entry('collect (project)', lambda: report_data.collect(project))
    entry('collect (one host)', lambda: report_data.collect(project, host=host))
    entry('collect (project, include closed)', lambda: report_data.collect(project, include_closed=True))
    if data:
        html = entry('build_html (template)', lambda: report_pdf.build_html(data))
        rows[-1]['bytes'] = len(html or '')
        with tempfile.TemporaryDirectory() as d:
            entry('render_pdf (child process)', lambda: report_pdf.render_pdf(html, os.path.join(d, 'r.pdf'), timeout=600))
    return rows


if __name__ == '__main__':
    main()
