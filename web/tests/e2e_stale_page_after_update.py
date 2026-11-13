"""Real-Chromium check that no page from BEFORE an update stays on screen AFTER it (issue 140). Not part of CI: run it against a throwaway
checkout with its own database. It starts and stops its own `manage.py runserver`, so run it from `web/` with the environment a test run
uses (database, broker, cache) and a superuser:

  STALE_USER=... STALE_PASS=... STALE_PORT=8171 python3 tests/e2e_stale_page_after_update.py [a b c d ...]

"Updating" here is what a real update does to a page: the served build changes (web/.commit and a static file's content hash) and the web
process restarts. A page is stale when its own script URL carries a hash other than the one the server hands out now. The static file it edits
(static/cve/theme.js, one trailing comment) and web/.commit are put back at the end. Scenarios: a hidden tab, a same-document hash link to
Settings#updates, back/forward, an administrator's page that is watching the update (updatebar.js).
"""
import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

WEB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
THEME = os.path.join(WEB, 'static', 'cve', 'theme.js')
COMMIT = os.path.join(WEB, '.commit')
PORT = os.environ.get('STALE_PORT', '8171')
BASE = f'http://127.0.0.1:{PORT}'
USER, PASS = os.environ['STALE_USER'], os.environ['STALE_PASS']
fails = []
server = None
original = open(THEME).read()


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)


def sha(n):
    return f'{n:x}'.ljust(40, 'a')


def theme_hash():
    return hashlib.md5(open(THEME, 'rb').read()).hexdigest()[:10]


def start():
    global server
    server = subprocess.Popen([sys.executable, 'manage.py', 'runserver', f'127.0.0.1:{PORT}', '--insecure', '--noreload'], cwd=WEB,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + '/login/', timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit('the server did not start')


def stop():
    global server
    if server:
        server.terminate()
        server.wait()
        server = None


def release(n):
    """The server goes down, runs release n, and comes back: what an update does to the files and the process."""
    stop()
    open(THEME, 'w').write(original + f'\n/* simulated release {n} */\n')
    open(COMMIT, 'w').write(sha(n) + '\n')
    start()


def reset_state(n, approved=False):
    code = ("from cveFeed.models import UpdateSettings as U\nfrom django.utils import timezone\nu = U.current()\n"
            f"u.enabled = True\nu.latest_sha = {sha(n + 1)!r}\nu.behind_by = 1\nu.latest_message = 'simulated'\nu.last_checked_at = timezone.now()\n"
            f"u.approved_sha = {sha(n + 1)!r} if {approved} else ''\nu.approved_by = 'e2e'\nu.approved_at = timezone.now() if {approved} else None\nu.save()")
    subprocess.run([sys.executable, 'manage.py', 'shell', '-c', code], cwd=WEB, check=True, capture_output=True)


HIDE = """
window.__hidden = false;
Object.defineProperty(document, 'hidden', {get: () => window.__hidden, configurable: true});
Object.defineProperty(document, 'visibilityState', {get: () => window.__hidden ? 'hidden' : 'visible', configurable: true});
"""
SET_HIDDEN = "(h) => { window.__hidden = h; document.dispatchEvent(new Event('visibilitychange')); }"
THEME_V = "() => { const s = document.querySelector('script[src*=\"cve/theme.js\"]'); return s ? (s.src.match(/v=([0-9a-f]+)/) || [])[1] : null; }"


def login(browser):
    ctx = browser.new_context()
    ctx.add_init_script(HIDE)
    page = ctx.new_page()
    page.goto(BASE + '/login/')
    page.fill('input[name=username]', USER)
    page.fill('input[name=password]', PASS)
    page.click('button[type=submit], input[type=submit]')
    page.wait_for_load_state('networkidle')
    return ctx, page


def page_version(page):
    for _ in range(40):  # a reload may be in flight
        try:
            return page.evaluate(THEME_V)
        except Exception:
            time.sleep(0.25)
    return None


def fresh_within(page, seconds):
    """True when the page shows the server's current build within `seconds` (it reloaded itself)."""
    end = time.time() + seconds
    while time.time() < end:
        if page_version(page) == theme_hash():
            return True
        time.sleep(0.5)
    return page_version(page) == theme_hash()


def scenario_a(browser):
    """A tab in the background while the site updates, then brought to the front."""
    ctx, page = login(browser)
    page.goto(BASE + '/cve/settings/#updates')
    page.wait_for_load_state('networkidle')
    page.evaluate(SET_HIDDEN, True)
    release(2)
    time.sleep(20)  # longer than one poll: a hidden page skips it
    check(page_version(page) != theme_hash(), 'a: while hidden the page still shows the old build (nothing to notice with)')
    page.evaluate(SET_HIDDEN, False)
    check(fresh_within(page, 8), 'a: brought to the front, the page shows the new build within 8 s')
    ctx.close()


def scenario_b(browser):
    """A link to /cve/settings/#updates followed while Settings is already open: same document, same scripts."""
    ctx, page = login(browser)
    page.goto(BASE + '/cve/settings/#ai')
    page.wait_for_load_state('networkidle')
    release(3)  # a short outage: the page's own poll (every 15 s) never sees the site down
    time.sleep(2)
    page.evaluate("() => { const a = document.createElement('a'); a.href = '/cve/settings/#updates'; a.id = 'upd-link'; a.textContent = 'Review'; document.body.prepend(a); }")
    page.click('#upd-link')
    check(fresh_within(page, 6), 'b: the link to Settings#updates lands on the new build within 6 s')
    ctx.close()


def scenario_c(browser):
    """Back and forward: the page left before the update, returned to after it."""
    ctx, page = login(browser)
    page.goto(BASE + '/cve/settings/#ai')
    page.wait_for_load_state('networkidle')
    page.goto(BASE + '/cve/hosts/')
    page.wait_for_load_state('networkidle')
    release(4)
    page.go_back()
    page.wait_for_load_state('networkidle')
    check(page.url.rstrip('/').endswith('settings/#ai') or '/settings/' in page.url, 'c: back went to Settings')
    check(fresh_within(page, 25), 'c: after back, the page shows the new build within 25 s')
    ctx.close()


def scenario_d(browser):
    """An administrator's page that is watching the approved update (updatebar.js) when it finishes."""
    reset_state(5, approved=True)
    open(COMMIT, 'w').write(sha(5) + '\n')
    stop(); start()
    ctx, page = login(browser)
    page.goto(BASE + '/cve/')
    page.wait_for_load_state('networkidle')
    try:
        page.wait_for_selector('.update-live', timeout=8000)
    except Exception:
        pass
    check(page.locator('.update-live').count() == 1, 'd: the watching page shows the update bar')
    release(6)  # the update's files arrive and the web restarts; the row's latest is now what is installed
    ok = False
    end = time.time() + 60
    while time.time() < end:
        if page_version(page) == theme_hash():
            ok = True
            break
        time.sleep(1)
    check(ok, 'd: the watching page ends on the new build')
    ctx.close()


SCENARIOS = {'a': scenario_a, 'b': scenario_b, 'c': scenario_c, 'd': scenario_d}

try:
    release(1)
    reset_state(1)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name in (sys.argv[1:] or list(SCENARIOS)):
            SCENARIOS[name](browser)
            release(1)
            reset_state(1)
        browser.close()
finally:
    stop()
    open(THEME, 'w').write(original)
    if os.path.exists(COMMIT):
        os.remove(COMMIT)
sys.exit(1 if fails else 0)
