"""Real-Chromium check that a page which refreshes itself keeps what the person opened. Not part of CI: run it against a throwaway stack.

Seed (throwaway DB only): a superuser, an org and project, OpenVAS switched on with 33 hosts that are not due, two Sentinels, 60 AI attempts. (web/tests/e2e_keep_open_seed.py)
  KEEP_BASE=http://127.0.0.1:28061 KEEP_USER=keeper KEEP_PASS=... KEEP_BEAT_DIR=/tmp/keepbeat SHOTS=/dir python web/tests/e2e_keep_open.py
with `manage.py shell < web/tests/e2e_keep_open_beat.py` running against the same database (it moves the data the pages poll).

Opens 'Not due' on /cve/sentinels/ and 'Call stages', 'Recent attempts and errors' and the price editor (typing into it) on the AI usage page, waits for
refreshes of the page's own poll, and asserts: still open, scroll unchanged, typed value kept, and that new data from the poll still arrives.
Exit status 1 when any check fails (the pre-fix page fails the 'still open' checks)."""
import glob
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ['KEEP_BASE']
BEAT = os.environ['KEEP_BEAT_DIR']
SHOTS = os.environ.get('SHOTS', '')
EXE = (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def stamp():
    return time.strftime('%Y-%m-%dT%H:%M:%S%z')


def check(cond, what):
    print(f"{stamp()} {'ok   ' if cond else 'FAIL '}{what}", flush=True)
    if not cond:
        fails.append(what)


def shot(page, name):
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, name + '.png'), full_page=False)


def bump():
    open(os.path.join(BEAT, 'bump'), 'w').close()
    deadline = time.time() + 20
    while os.path.exists(os.path.join(BEAT, 'bump')) and time.time() < deadline:
        time.sleep(0.3)


def is_open(page, text):
    return page.evaluate("(t) => { const s = [...document.querySelectorAll('summary')].find(x => x.textContent.trim().startsWith(t)); return s ? s.parentElement.open : null; }", text)


def sentinels(page, tag):
    page.goto(BASE + '/cve/sentinels/')
    page.wait_for_selector('.sl-openvas-deferred summary', timeout=30000)
    page.click('.sl-openvas-deferred summary')
    check(is_open(page, 'Not due'), tag + "'Not due' is open after the click")
    page.evaluate("window.scrollTo(0, Math.min(250, document.documentElement.scrollHeight - innerHeight))")
    y0 = page.evaluate('window.scrollY')
    shot(page, tag.strip('[] ').replace(' ', '-') + '-sentinels-open')
    page.evaluate("document.querySelector('.sl-openvas').__kept = true")  # a property: it survives only on the very same node
    n0 = int(re.search(r'(\d+) not due', page.text_content('.sl-openvas-count')).group(1))
    live = []
    page.on('request', lambda r: live.append(time.strftime('%X')) if '/sentinels/live' in r.url else None)
    # two refreshes of the live list: the beat moves the last check-in, so every poll answers with new data and the page repaints
    deadline = time.time() + 40
    while len(live) < 2 and time.time() < deadline:
        page.wait_for_timeout(500)  # (time.sleep would not let the page's request events through)
    page.wait_for_timeout(2500)
    check(len(live) >= 2, tag + f'the Sentinels page polled itself twice ({live})')
    check(is_open(page, 'Not due'), tag + "'Not due' is STILL open after two refreshes")
    check(abs(page.evaluate('window.scrollY') - y0) <= 2, tag + f"page scroll unchanged ({y0} -> {page.evaluate('window.scrollY')})")
    check(page.evaluate("document.querySelector('.sl-openvas').__kept === true"), tag + 'the OpenVAS queue block did not change, so its node was not replaced')
    check(f'Showing 12 of {n0}' in (page.text_content('.sl-openvas-deferred') or ''), tag + f"the counter reads 'Showing 12 of {n0}'")
    bump()
    try:
        page.wait_for_function("document.querySelector('.sl-openvas-deferred') && document.querySelector('.sl-openvas-deferred').textContent.includes('of %d')" % (n0 + 1), timeout=60000)
        check(True, tag + f"new data from the poll appears ('Showing 12 of {n0 + 1}')")
    except Exception:
        check(False, tag + f"new data from the poll appears ('Showing 12 of {n0 + 1}')")
    check(is_open(page, 'Not due'), tag + "'Not due' is still open after the new data arrived")
    shot(page, tag.strip('[] ').replace(' ', '-') + '-sentinels-after')


def ai_page(page, tag):
    page.goto(BASE + '/cve/setup/')
    page.wait_for_selector('#ai-usage details summary', timeout=30000)
    for t in ('Call stages', 'Recent attempts and errors', 'Set operator supplied pricing'):
        page.evaluate("(t) => [...document.querySelectorAll('summary')].find(x => x.textContent.trim().startsWith(t)).click()", t)
    page.fill('input[name=model]', 'typed-model-id')
    page.click('h2 >> nth=0')  # leave the field: the value stays typed
    page.evaluate("window.scrollTo(0, Math.min(300, document.documentElement.scrollHeight - innerHeight))")
    y0 = page.evaluate('window.scrollY')
    for t in ('Call stages', 'Recent attempts and errors', 'Set operator supplied pricing'):
        check(is_open(page, t), tag + f"'{t}' is open after the click")
    shot(page, tag.strip('[] ').replace(' ', '-') + '-ai-open')
    before = page.inner_text('#ai-usage .ai-usage-grid')
    bump()
    asked = []
    page.on('request', lambda r: asked.append(time.strftime('%X')) if '/settings/ai/usage?' in r.url else None)
    page.wait_for_timeout(36000)  # two 15 s refresh cycles
    check(len(asked) >= 2, tag + f'the AI page refreshed itself twice ({asked})')
    for t in ('Call stages', 'Recent attempts and errors', 'Set operator supplied pricing'):
        check(is_open(page, t), tag + f"'{t}' is STILL open after two refreshes")
    check(page.input_value('input[name=model]') == 'typed-model-id', tag + 'the typed value is kept: ' + repr(page.input_value('input[name=model]')))
    check(abs(page.evaluate('window.scrollY') - y0) <= 2, tag + f"page scroll unchanged ({y0} -> {page.evaluate('window.scrollY')})")
    check(page.inner_text('#ai-usage .ai-usage-grid') != before, tag + 'new data from the poll appears (the counts moved)')
    shot(page, tag.strip('[] ').replace(' ', '-') + '-ai-after')


with sync_playwright() as pw:
    for width, height, mobile in ((1440, 900, False), (390, 844, True)):
        browser = pw.chromium.launch(executable_path=EXE)
        ctx = browser.new_context(viewport={'width': width, 'height': height}, is_mobile=mobile, has_touch=mobile)
        page = ctx.new_page()
        page.goto(BASE + '/login/')
        page.fill('[name=username]', os.environ['KEEP_USER'])
        page.fill('[name=password]', os.environ['KEEP_PASS'])
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        tag = f'[{width}x{height}] '
        sentinels(page, tag)
        ai_page(page, tag)
        browser.close()
print(f'{stamp()} {len(fails)} failed')
sys.exit(1 if fails else 0)
