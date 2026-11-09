"""Real-Chromium check of the API keys page's Connect an agent card. Not part of CI: run it against a throwaway stack.

  KEYS_BASE=http://127.0.0.1:8765 KEYS_USER=... KEYS_PASS=... SHOTS=/dir CHROME=/path/to/chrome python web/tests/e2e_api_keys_card.py

It creates a token, checks every command now carries it (and nothing carried it before), reloads, checks the token is gone from the
page and from storage and the address.
"""
import glob
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ['KEYS_BASE']
SHOTS = os.environ.get('SHOTS', '')
EXE = os.environ.get('CHROME') or (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)


def blocks(page):
    out = {}
    for key in ('tell', 'claude', 'mcp', 'rest'):
        page.click(f'#tab-{key}')
        out[key] = page.inner_text('#connect-panel pre').replace('Copy', '').strip()
    page.click('#tab-tell')
    return out


def run(pw, width, height, mobile):
    browser = pw.chromium.launch(executable_path=EXE)
    ctx = browser.new_context(viewport={'width': width, 'height': height}, is_mobile=mobile, has_touch=mobile)
    ctx.route('**/cve/api/alive*', lambda r: r.fulfill(status=200, body='ok'))
    page = ctx.new_page()
    page.goto(BASE + '/login/')
    page.fill('[name=username]', os.environ['KEYS_USER'])
    page.fill('[name=password]', os.environ['KEYS_PASS'])
    page.click('button[type=submit], input[type=submit]')
    page.wait_for_load_state()
    page.goto('about:blank')
    page.goto(BASE + '/cve/agents/')
    page.wait_for_selector('#connect-body .seg')
    tag = f'{width}'
    check(page.get_attribute('#tab-tell', 'aria-selected') == 'true', f'{tag}: Tell your agent is selected first')
    before = blocks(page)
    check(all('<your token>' in v for v in before.values()), f'{tag}: placeholders before a token exists')
    check('Create a token above and this fills in' in page.inner_text('#connect'), f'{tag}: the hint says it fills in')
    check(f'{BASE}/mcp/' in before['tell'], f'{tag}: the prompt carries this host')
    if SHOTS:
        page.screenshot(path=f'{SHOTS}/keys-before-{tag}.png')
    page.fill('#name', 'e2e-card')
    page.click('#f button[type=submit]')
    page.wait_for_selector('#secret pre')
    token = page.inner_text('#secret pre').replace('Copy', '').strip()
    check(token.startswith('cve_'), f'{tag}: a token was revealed')
    check(page.evaluate("document.activeElement && document.activeElement.closest('#secret') !== null"), f'{tag}: focus moved to the revealed token')
    check(page.inner_text('#connect-live') == 'Token created. Commands updated.', f'{tag}: the update is announced')
    after = blocks(page)
    check(all(token in v and '<your token>' not in v for v in after.values()), f'{tag}: every command carries the token')
    check('only time the token is shown' in page.inner_text('#connect'), f'{tag}: the one-time notice is visible')
    check(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), f'{tag}: no horizontal overflow')
    if SHOTS:
        page.screenshot(path=f'{SHOTS}/keys-after-{tag}.png', full_page=False)
    page.reload()
    page.wait_for_selector('#connect-body .seg')
    html = page.content()
    check(token not in html, f'{tag}: the token is not in the page after a reload')
    check(all('<your token>' in v for v in blocks(page).values()), f'{tag}: placeholders again after a reload')
    check(token not in page.url, f'{tag}: not in the address')
    stored = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage), document.cookie])")
    check(token not in stored, f'{tag}: not in storage or cookies')
    # dismiss path
    page.fill('#name', 'e2e-card-2')
    page.click('#f button[type=submit]')
    page.wait_for_selector('#secret pre')
    page.click('text=I have copied it')
    check(page.is_hidden('#secret') and all('<your token>' in v for v in blocks(page).values()), f'{tag}: dismissing clears the commands')
    # clean up the tokens this run made
    page.evaluate("""async () => { const t = (await (await fetch('/api/v1/tokens')).json()).results.filter(x => x.name.startsWith('e2e-card'));
      const csrf = document.querySelector('[name=csrfmiddlewaretoken]').value;
      for (const x of t) await fetch('/api/v1/tokens/' + x.id, {method: 'DELETE', headers: {'X-CSRFToken': csrf}}); }""")
    browser.close()


with sync_playwright() as pw:
    run(pw, 1440, 900, False)
    run(pw, 390, 844, True)
sys.exit(1 if fails else 0)
