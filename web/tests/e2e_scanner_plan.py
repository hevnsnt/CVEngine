"""Real-Chromium check of the Which scanners run status line against a throwaway server, with the host side stubbed by the real scripts/update-state.py.
Not part of CI. Needs a superuser and a server whose application directory is APP_DIR (web/):
  PLAN_BASE=http://127.0.0.1:28071 PLAN_USER=keeper PLAN_PASS=... APP_DIR=/path/to/web SHOTS=/dir python web/tests/e2e_scanner_plan.py
Checks: nothing runs the host -> the line says the host helper is not running; the host's heartbeat appears -> it says the updater has not picked it up;
the host answers ok -> 'Done at HH:MM' with what changed and no 'Applying' left, which clears itself; a failed answer shows the reason and what to do."""
import glob
import os
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

BASE, APP = os.environ['PLAN_BASE'], os.environ['APP_DIR']
ROOT = os.path.dirname(APP)
SHOTS = os.environ.get('SHOTS', '')
EXE = (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def check(cond, what, got=''):
    print(f"{time.strftime('%H:%M:%S')} {'ok   ' if cond else 'FAIL '}{what}{'' if cond else ' got: ' + repr(got)}", flush=True)
    if not cond:
        fails.append(what)


def host(*args):
    subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'update-state.py'), *args], cwd=ROOT, check=True)


def line(page):
    return page.inner_text('#plan-card p[role=status]:last-of-type')


def until(page, pattern, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        text = line(page)
        if pattern in text:
            return text
        time.sleep(0.5)
    return line(page)


def shot(page, name):
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, name + '.png'), clip=page.locator('#plan-card').bounding_box())


for name in ('.scanner-plan-wanted', '.scanner-plan-applied.json', '.updater-heartbeat'):
    try:
        os.remove(os.path.join(APP, name))
    except OSError:
        pass
with sync_playwright() as pw:
    browser = pw.chromium.launch(executable_path=EXE)
    page = browser.new_page(viewport={'width': 1200, 'height': 900})
    page.goto(BASE + '/login/')
    page.fill('[name=username]', os.environ['PLAN_USER'])
    page.fill('[name=password]', os.environ['PLAN_PASS'])
    page.click('button[type=submit]')
    page.wait_for_load_state('networkidle')
    page.goto(BASE + '/cve/sentinels/')
    page.wait_for_selector('#plan-card h2')
    start = line(page)
    other = 'external' if 'built-in scanner only' in start else 'internal'
    words = {'external': 'your own Sentinels only', 'internal': 'the built-in scanner only'}
    page.check(f'#plan-card-{other}', force=True)
    page.click('#plan-card button:has-text("Apply")')
    text = until(page, 'host helper is not running')
    check('Applying the change.' in text and 'The host helper is not running' in text and 'scripts/update-watch.sh' in text, 'no host heartbeat: says the host helper is not running', text)
    shot(page, 'plan-1-host-down')
    host('heartbeat')
    text = until(page, 'has not picked it up yet', 10)
    check('The host updater has not picked it up yet.' in text and 'Asked at ' in text, 'host alive: says the updater has not picked it up yet and when it was asked', text)
    shot(page, 'plan-2-waiting')
    host('plan-done', other, 'ok', f'{words[other]} (stub)')
    text = until(page, 'Done at', 10)
    check(text.startswith('Done at ') and f'now {words[other]}' in text or 'changed from' in text, 'host answered: Done at <time> and what changed', text)
    check('Applying' not in text, 'no Applying left after the answer', text)
    shot(page, 'plan-3-done')
    page.reload()
    page.wait_for_selector('#plan-card h2')
    check(line(page).startswith('Done at '), 'a reload within five minutes still tells the news', line(page))
    page.wait_for_timeout(22000)
    check(line(page).startswith('Now: ' + words[other]), 'after the clear time it says what runs now, the plan the host applied', line(page))
    page.goto(BASE + '/cve/sentinels/')
    page.wait_for_selector('#plan-card h2')
    text = line(page)
    page.check('#plan-card-both', force=True)
    page.click('#plan-card button:has-text("Apply")')
    until(page, 'Applying the change.', 10)
    host('plan-done', 'both', 'failed', 'the choice is saved but the services could not be restarted (see scanner-plan.log)')
    text = until(page, 'Not done', 10)
    check(text.startswith('Not done (') and 'could not be restarted' in text and 'What to do:' in text, 'failed answer: reason and what to do', text)
    shot(page, 'plan-4-failed')
    browser.close()
for name in ('.scanner-plan-wanted', '.scanner-plan-applied.json', '.updater-heartbeat'):
    try:
        os.remove(os.path.join(APP, name))
    except OSError:
        pass
print(f'{len(fails)} failed')
sys.exit(1 if fails else 0)
