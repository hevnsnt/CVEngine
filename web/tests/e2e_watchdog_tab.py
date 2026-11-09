"""Real-Chromium check of the Administration Watchdog tab against stubbed API answers (no stack needed). Not part of CI.
  python web/tests/e2e_watchdog_tab.py   (run from the repo root; SHOTS=/dir keeps a screenshot)
Serves web/static as /staticfiles, the real admin.js, and a stub of /cve/api/admin/users and /cve/api/admin/watchdog. Asserts: the tab exists for an
App Admin, opening #watchdog draws the panel with the rules and the action table, it polls while open, and stops polling once another tab is opened."""
import glob
import http.server
import json
import os
import socketserver
import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

WEB = Path(__file__).resolve().parent.parent
HITS = {'watchdog': 0}
RULES = [{'code': f'R{i}', 'title': t, 'status': st, 'color': 'green', 'enabled': True, 'does': 'x', 'text': 'Fine at 14:10Z.'} for i, (t, st) in enumerate(
    [('Workers answer', 'ok'), ('Workers take their work', 'ok'), ('Hosts assessed at once is not starved', 'ok'), ('Idle Sentinels are fed', 'watching'),
     ('No message stuck unacknowledged', 'ok'), ('Scheduler ticks', 'ok'), ('Disk and memory have room', 'ok'), ('Database connections have room', 'ok'),
     ('No scan is stuck running', 'ok')], 1)]
WD = {'enabled': True, 'env_off': False, 'running': True, 'tick_age_seconds': 12, 'rules': RULES, 'changes': [],
      'events': [{'at': '2026-11-09T14:10:54+00:00', 'rule': 'R1', 'observation': 'No answer from the discovery lane.', 'action': 'restart-celery', 'result': 'The host carried it out.'}]}
PAGE = b'<!doctype html><html><body><h1>Administration</h1><p id="admin-sub"></p><div id="admin"><div id="view"></div></div><script type="module" src="/staticfiles/cve/admin.js"></script></body></html>'


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, ctype):
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split('?')[0]
        if p == '/cve/admin/':
            return self.send(PAGE, 'text/html')
        if p.startswith('/staticfiles/'):
            f = WEB / 'static' / p[len('/staticfiles/'):]
            if f.is_file():
                return self.send(f.read_bytes(), 'text/javascript' if f.suffix == '.js' else 'text/css')
        if p == '/cve/api/admin/watchdog':
            HITS['watchdog'] += 1
            return self.send(json.dumps(WD).encode(), 'application/json')
        if p.startswith('/cve/api/admin/'):
            return self.send(json.dumps({'actor': {'is_superuser': True}, 'users': [], 'results': [], 'items': []}).encode(), 'application/json')
        self.send_response(404)
        self.end_headers()


srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), H)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{srv.server_address[1]}'
exe = (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what, flush=True)
    if not cond:
        fails.append(what)


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=exe)
    pg = b.new_page(viewport={'width': 1440, 'height': 900})
    errs = []
    pg.on('pageerror', lambda e: errs.append(str(e)))
    pg.goto(base + '/cve/admin/#watchdog')
    pg.wait_for_selector('#watchdog .wd-rule', timeout=15000)
    labels = pg.locator('[role=tab]').all_inner_texts()
    check('Watchdog' in labels, f'the Watchdog tab is listed for an App Admin ({labels})')
    check(pg.locator('[role=tab][aria-selected=true]').inner_text() == 'Watchdog', 'opening #watchdog selects the Watchdog tab')
    check(pg.locator('#watchdog .wd-rule').count() == 9, 'nine rules drawn')
    check('Last pass 12 s ago' in pg.locator('#watchdog').inner_text(), 'the pass age is shown')
    check(pg.locator('#watchdog table tr').count() >= 2, 'the action list has its row')
    if os.environ.get('SHOTS'):
        pg.screenshot(path=os.path.join(os.environ['SHOTS'], 'admin-watchdog-1440.png'))
    first = HITS['watchdog']
    pg.locator('[role=tab]', has_text='People').click()
    time.sleep(33)
    check(HITS['watchdog'] == first, f'polling stops once another tab is opened ({first} then {HITS["watchdog"]})')
    pg.locator('[role=tab]', has_text='Watchdog').click()
    pg.wait_for_selector('#watchdog .wd-rule', timeout=15000)
    check(HITS['watchdog'] == first + 1, 'reopening the tab reads again')
    check(not errs, f'no JavaScript errors {errs[:2]}')
    b.close()
raise SystemExit(1 if fails else 0)
