#!/usr/bin/env python3
"""Load the dashboard (/cve/, every project) in headless Chromium against a throwaway server and print one row per API request:
URL, status, time to first byte, total, start offset, then when the Exposed hosts tile, the Hosts scanned tile and the attack-surface map fill.

    python scripts/scale/dashboard_load.py http://127.0.0.1:8765 scale-admin scale-fixture-pw [--seconds 20] [--json out.json]

Static files are served straight from web/static (what the proxy does in production), so only the API calls are timed.
"""
import argparse
import glob
import json
import mimetypes
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.abspath(os.path.join(HERE, '..', '..', 'web', 'static'))


def chromium():
    hits = glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome'))
    return hits[0] if hits else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('base')
    ap.add_argument('user')
    ap.add_argument('password')
    ap.add_argument('--seconds', type=float, default=20, help='how long to watch after navigation')
    ap.add_argument('--json')
    ap.add_argument('--path', default='/cve/')
    ap.add_argument('--forget', action='store_true', help='clear the browser storage first (a first visit: no remembered numbers)')
    ap.add_argument('--before', help='shell command run just before the measured navigation (e.g. empty the cache for a cold load)')
    a = ap.parse_args()
    rows = []
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=chromium())
        ctx = b.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()

        def static(route):
            rel = re.sub(r'^.*?/staticfiles/', '', route.request.url).split('?')[0]
            path = os.path.join(STATIC, rel)
            if os.path.isfile(path):
                route.fulfill(status=200, body=open(path, 'rb').read(), content_type=mimetypes.guess_type(path)[0] or 'application/octet-stream')
            else:
                route.continue_()
        ctx.route('**/staticfiles/**', static)
        page.goto(a.base + '/login/')
        page.fill('[name=username]', a.user)
        page.fill('[name=password]', a.password)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        if a.forget:
            page.evaluate('localStorage.clear()')
        page.goto('about:blank')  # the login landed on the dashboard: leave it before the measured load
        if a.before:
            import subprocess
            subprocess.run(a.before, shell=True, check=True)
        t0 = {}
        starts = {}

        def on_request(req):
            starts[req] = time.monotonic()
        page.on('request', on_request)

        def on_finished(req):
            u = req.url.replace(a.base, '')
            if '/staticfiles/' in u or req.resource_type not in ('fetch', 'xhr', 'document'):
                return
            t = req.timing
            resp = req.response()
            rows.append({'url': u[:110], 'status': resp.status if resp else None, 'at': round(starts.get(req, 0) - t0.get('t', 0), 2),
                         'ttfb_ms': round(t['responseStart'] - t['requestStart']) if t.get('responseStart', -1) > 0 else None,
                         'total_ms': round(t['responseEnd']) if t.get('responseEnd', -1) > 0 else None})
        page.on('requestfinished', on_finished)
        if os.environ.get('DASH_DEBUG'):
            page.on('console', lambda m: print('console', m.type, m.text[:200]))
            page.on('pageerror', lambda e: print('pageerror', str(e)[:300]))
        t0['t'] = time.monotonic()
        page.goto(a.base + a.path, wait_until='commit')
        marks = {}
        js = {
            'exposed_tile_filled': "/^[0-9]/.test(document.getElementById('s-exposed_hosts')?.textContent||'')",
            'coverage_tile_filled': "/[0-9]/.test(document.getElementById('s-coverage')?.textContent||'')",
            'map_drawn': "document.querySelectorAll('#map a, #map button, #map [data-name]').length>0",
            'activity_card_drawn': "document.querySelectorAll('#activity-matrix *, .activity-matrix *').length>0",
        }
        end = t0['t'] + a.seconds
        while time.monotonic() < end:
            for k, expr in js.items():
                if k not in marks:
                    try:
                        if page.evaluate(expr):
                            marks[k] = round(time.monotonic() - t0['t'], 2)
                            if os.environ.get('DASH_DEBUG'): print('mark', k, marks[k], repr(page.evaluate("document.getElementById('s-exposed_hosts').textContent")), page.evaluate('document.documentElement.dataset.snap'))
                    except Exception:
                        pass
            time.sleep(0.05)
        if os.environ.get('DASH_DEBUG'):
            print('end', page.evaluate("[document.documentElement.dataset.snap, document.getElementById('s-hosts').textContent, document.getElementById('snap-note').textContent]"))
        b.close()
    rows.sort(key=lambda r: r['at'])
    print(f"{'at s':>6} {'status':>6} {'ttfb ms':>8} {'total ms':>8}  url")
    for r in rows:
        print(f"{r['at']:>6} {r['status']!s:>6} {r['ttfb_ms']!s:>8} {r['total_ms']!s:>8}  {r['url']}")
    print('marks (seconds from navigation):', json.dumps(marks))
    if a.json:
        json.dump({'rows': rows, 'marks': marks}, open(a.json, 'w'), indent=1)


if __name__ == '__main__':
    sys.exit(main())
