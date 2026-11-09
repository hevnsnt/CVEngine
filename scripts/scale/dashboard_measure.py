#!/usr/bin/env python3
"""Measure the overview page N times in headless Chromium at 1440x900 and print percentiles.

    python scripts/scale/dashboard_measure.py http://127.0.0.1:8801 scale-admin scale-fixture-pw --runs 10 [--before 'shell command'] [--json out.json]

Per run (a fresh page, the session logged in, the server's cache as the --before command leaves it):
  first_panel  seconds from navigation until the first panel shows real content (a tile number, the activity feed, the ticker or the map);
  all_panels   until the headline tiles, the coverage tile, the map, the ticker's counts and the AI activity feed have all filled;
  slowest_api  the slowest answer of any fetch the page made (time to last byte).
Static files are served straight from web/static (what the proxy does in production), so only the API calls and the page itself are timed.
The 95th percentile of the runs is the nearest-rank one (with 10 runs, the slowest).
"""
import argparse
import glob
import json
import mimetypes
import os
import re
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.abspath(os.path.join(HERE, '..', '..', 'web', 'static'))
# A panel is "filled" the first time it holds real content, seen by a MutationObserver inside the page (so a long task that blocks the page does not
# delay the reading), in seconds from the start of the navigation: a tile whose text starts with a digit, the map when it holds a host tile, the ticker's
# counts, the AI activity feed when it has a line. The page's own placeholders are dashes and empty boxes, so none of them reads as filled.
WATCH_JS = """
window.__marks = {};
(() => {
  const specs = {
    tiles: () => /^~?[0-9]/.test(document.querySelector('#s-exposed_hosts')?.textContent || ''),
    coverage: () => /^~?[0-9]/.test(document.querySelector('#s-coverage')?.textContent || ''),
    map: () => document.querySelectorAll('#map a.hx').length > 0,
    ticker: () => /^[0-9]/.test(document.querySelector('#d-counts b')?.textContent || ''),
    feed: () => document.querySelectorAll('#feed > *:not(#feed-empty)').length > 0,
  };
  const check = () => {
    for (const [name, test] of Object.entries(specs)) {
      if (!(name in window.__marks) && test()) window.__marks[name] = performance.now() / 1000;
    }
  };
  new MutationObserver(check).observe(document, { subtree: true, childList: true, characterData: true, attributes: true });
  setInterval(check, 50);
})();
"""
ALL = ('tiles', 'coverage', 'map', 'ticker', 'feed')


def chromium():
    hits = glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome'))
    return hits[0] if hits else None


def pct(values, p):
    values = sorted(values)
    return values[max(0, -(-len(values) * p // 100) - 1)]


def one_run(pw, a):
    b = pw.chromium.launch(executable_path=chromium())
    try:
        ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()

        def static(route):
            rel = re.sub(r'^.*?/staticfiles/', '', route.request.url).split('?')[0]
            path = os.path.join(STATIC, rel)
            if os.path.isfile(path):
                route.fulfill(status=200, body=open(path, 'rb').read(), content_type=mimetypes.guess_type(path)[0] or 'application/octet-stream')
            else:
                route.continue_()
        if not a.proxied:
            ctx.route('**/staticfiles/**', static)
        ctx.add_init_script(WATCH_JS)
        page.goto(a.base + '/login/')
        page.fill('[name=username]', a.user)
        page.fill('[name=password]', a.password)
        page.click('button[type=submit]')
        page.wait_for_url(re.compile(r'/cve/'), timeout=120000)
        if a.forget:
            page.evaluate('localStorage.clear()')
        page.goto('about:blank')
        if a.before:
            subprocess.run(a.before, shell=True, check=True)
        t0 = time.monotonic()
        slow = []
        starts = {}
        page.on('request', lambda r: starts.__setitem__(r, time.monotonic()))

        def done(r):
            if '/staticfiles/' in r.url or r.resource_type not in ('fetch', 'xhr'):
                return
            slow.append((round(time.monotonic() - starts.get(r, t0), 2), r.url.replace(a.base, '')[:80]))
        page.on('requestfinished', done)
        page.goto(a.base + a.path, wait_until='commit')
        marks = {}
        end = t0 + a.timeout
        while time.monotonic() < end and not all(k in marks for k in ALL):
            try:
                marks = page.evaluate('window.__marks') or {}
            except Exception:  # noqa: BLE001 - mid navigation
                pass
            time.sleep(0.05)
        marks = {k: round(v, 2) for k, v in marks.items()}
        first = min(marks.values()) if marks else None
        alls = max(marks.get(k, a.timeout) for k in ALL)
        return {'first_panel': first, 'all_panels': alls, 'marks': marks, 'slowest_api': max((s for s, _ in slow), default=None),
                'slowest_url': max(slow, default=(0, ''))[1], 'finished_api': sorted(slow, reverse=True)[:4]}
    finally:
        b.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('base'); ap.add_argument('user'); ap.add_argument('password')
    ap.add_argument('--runs', type=int, default=10); ap.add_argument('--timeout', type=float, default=90)
    ap.add_argument('--proxied', action='store_true', help='the base serves /staticfiles/ itself (scripts/scale/devproxy.py): no browser-side file interception')
    ap.add_argument('--path', default='/cve/'); ap.add_argument('--json')
    ap.add_argument('--forget', action='store_true', help='clear the browser storage first (a first visit)')
    ap.add_argument('--before', help='shell command run before each measured navigation (e.g. empty the cache for a cold load)')
    a = ap.parse_args()
    runs = []
    with sync_playwright() as pw:
        for i in range(a.runs):
            r = one_run(pw, a)
            runs.append(r)
            print(f"run {i + 1}: first panel {r['first_panel']} s, all panels {r['all_panels']} s, slowest api {r['slowest_api']} s ({r['slowest_url']}) marks {r['marks']}", flush=True)
    fp, ap_ = [r['first_panel'] for r in runs if r['first_panel'] is not None], [r['all_panels'] for r in runs]
    out = {'runs': runs, 'first_panel_p50': pct(fp, 50), 'first_panel_p95': pct(fp, 95), 'all_panels_p50': pct(ap_, 50), 'all_panels_p95': pct(ap_, 95),
           'slowest_api_p95': pct([r['slowest_api'] or 0 for r in runs], 95)}
    print(json.dumps({k: v for k, v in out.items() if k != 'runs'}))
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1)


if __name__ == '__main__':
    sys.exit(main())
