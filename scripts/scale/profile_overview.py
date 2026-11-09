"""Time the calls the overview makes (the URLs of the owner's HAR) on a seeded scale database, cold and warm, with the Django query count and
the slowest statements of each; with --explain, EXPLAIN (ANALYZE, BUFFERS) of every statement above --slow-ms.
    python scripts/scale/profile_overview.py [--explain] [--runs 3] [--json out.json]   (run from web/, CI-style env, DB seeded by scripts/scale/seed_*)"""
import argparse, json, os, sys, time
sys.path.insert(0, os.getcwd()); os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
import django; django.setup()
from django.conf import settings
from django.contrib.auth.models import User
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
settings.ALLOWED_HOSTS = ['*']
CALLS = [('stats', '/cve/api/stats?project=_all'), ('graph', '/cve/api/graph?v=&project=_all'),
         ('discovery', '/cve/api/discovery?scan=&after=0&project=_all'), ('search', '/api/v1/projects/_all/search?q=&page_size=1'),
         ('activity-days', '/api/v1/projects/_all/activity-days?days=90&tz=America%2FChicago'),
         ('activity', '/cve/api/activity?after=0&running=&since=&project=_all'), ('graph-live', '/cve/api/graph-live?project=_all'),
         ('feed', '/cve/api/feed'), ('scanner', '/cve/api/scanner')]


def clear():
    from django.core.cache import cache
    try:
        cache.clear()
    except Exception as e:  # noqa: BLE001
        print('cache clear failed', e)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--explain', action='store_true'); ap.add_argument('--runs', type=int, default=2)
    ap.add_argument('--slow-ms', type=float, default=150); ap.add_argument('--json'); ap.add_argument('--page', action='store_true', help='load the page: the four heavy calls at once, cold, as the overview does'); ap.add_argument('--user', default='scale-admin')
    a = ap.parse_args()
    c = Client(HTTP_HOST='localhost'); c.force_login(User.objects.get(username=a.user))
    if a.page:
        import threading
        from django.db import connections
        names = ('stats', 'graph', 'discovery', 'search'); urls = dict(CALLS); res = {}
        clear()
        def go(n):
            cl = Client(HTTP_HOST='localhost'); cl.force_login(User.objects.get(username=a.user)); t = time.perf_counter()
            r = cl.get(urls[n]); res[n] = (round((time.perf_counter() - t) * 1000), r.status_code); connections.close_all()
        ths = [threading.Thread(target=go, args=(n,)) for n in names]; t0 = time.perf_counter()
        [t.start() for t in ths]; [t.join() for t in ths]
        print('page load, four calls at once (cold):', res, 'wall', round((time.perf_counter() - t0) * 1000), 'ms'); return
    out = {}
    for name, url in CALLS:
        rows = []
        for phase in ['cold'] + ['warm'] * (a.runs - 1):
            if phase == 'cold':
                clear()
            with CaptureQueriesContext(connection) as ctx:
                t = time.perf_counter(); r = c.get(url); ms = (time.perf_counter() - t) * 1000
            qs = sorted(ctx.captured_queries, key=lambda q: -float(q['time']))
            rows.append({'phase': phase, 'status': r.status_code, 'ms': round(ms), 'queries': len(ctx.captured_queries),
                         'db_ms': round(sum(float(q['time']) for q in ctx.captured_queries) * 1000), 'bytes': len(r.content),
                         'top': [(round(float(q['time']) * 1000), q['sql'][:2000]) for q in qs[:4]]})
            if phase == 'cold' and a.explain:
                for q in qs:
                    if float(q['time']) * 1000 >= a.slow_ms and q['sql'].lstrip().upper().startswith('SELECT'):
                        with connection.cursor() as cur:
                            cur.execute('EXPLAIN (ANALYZE, BUFFERS) ' + q['sql']); plan = '\n'.join(x[0] for x in cur.fetchall())
                        print(f'--- {name}: {float(q["time"])*1000:.0f} ms\n{q["sql"][:1500]}\n{plan[:4000]}\n')
        out[name] = rows
        cold, warm = rows[0], rows[-1]
        print(f"{name:14} cold {cold['ms']:6} ms {cold['queries']:4} q (db {cold['db_ms']} ms) | warm {warm['ms']:6} ms {warm['queries']:4} q | {cold['status']} {cold['bytes']} B", flush=True)
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1)


main()
