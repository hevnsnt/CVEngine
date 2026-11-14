"""Real-Chromium check of the Your API keys list against a throwaway server (seed: a superuser with two keys named old-dup, others, and a legacy key with no stored ending).
  KEYS_BASE=http://127.0.0.1:28071 KEYS_USER=keeper KEYS_PASS=... SHOTS=/dir python web/tests/e2e_api_keys_list.py
Checks: newest first, a Created column, Last used, a read only badge, 4 + 2 characters of a key and no more, the duplicate-name message in the form, Revoke asks first."""
import glob
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ['KEYS_BASE']
SHOTS = os.environ.get('SHOTS', '')
EXE = (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def check(cond, what, got=''):
    print(f"{time.strftime('%H:%M:%S')} {'ok   ' if cond else 'FAIL '}{what}{'' if cond else ' got: ' + repr(got)}", flush=True)
    if not cond:
        fails.append(what)


with sync_playwright() as pw:
    browser = pw.chromium.launch(executable_path=EXE)
    for width, height, mobile in ((1440, 900, False), (390, 844, True)):
        ctx = browser.new_context(viewport={'width': width, 'height': height}, is_mobile=mobile, has_touch=mobile)
        page = ctx.new_page()
        page.goto(BASE + '/login/')
        page.fill('[name=username]', os.environ['KEYS_USER'])
        page.fill('[name=password]', os.environ['KEYS_PASS'])
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        page.goto(BASE + '/cve/agents/')
        page.wait_for_selector('#list tbody tr')
        tag = f'[{width}x{height}] '
        heads = page.eval_on_selector_all('#list th', 'els => els.map(e => e.textContent)')
        check(heads == ['Name', 'Key', 'Access', 'Created', 'Last used', ''], tag + 'columns Name, Key, Access, Created, Last used', heads)
        rows = page.eval_on_selector_all('#list tbody tr', 'rows => rows.map(r => [...r.querySelectorAll("td")].map(td => td.textContent))')
        names = [r[0] for r in rows]
        check(names == ['viewer', 'reporter-ci', 'old-dup', 'old-dup', 'legacy'] or names[:4] == ['viewer', 'reporter-ci', 'old-dup', 'old-dup'], tag + 'newest first, old duplicates both listed', names)
        created = [r[3] for r in rows]
        check(all(re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d', c) for c in created) and created[:4] == sorted(created[:4], reverse=True), tag + 'Created in the shared local format, descending', created)
        check('read only' in [r[2] for r in rows] and 'full access' in [r[2] for r in rows], tag + 'access badge: read only and full access both shown', [r[2] for r in rows])
        check('never used' in [r[4] for r in rows] and any(re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d', r[4]) for r in rows), tag + 'Last used: a date or never used', [r[4] for r in rows])
        keys = [r[1] for r in rows]
        check(all(re.fullmatch(r'cve_\.\.\.([A-Za-z0-9_-]{2})?', k) for k in keys), tag + 'only 4 + 2 characters of a key', keys)
        check(keys[-1] == 'cve_...', tag + 'a key with no stored ending shows only its start', keys)
        if SHOTS:
            page.locator('.card:has(#list)').screenshot(path=os.path.join(SHOTS, f'keys-{width}.png'))
        if not mobile:
            page.fill('#name', 'VIEWER')
            page.click('button:has-text("Create API key")')
            page.wait_for_selector('#secret-err.msg')
            msg = page.inner_text('#secret-err')
            check(msg == 'You already have an API key named "VIEWER". Pick another name, or revoke the old one first.', 'duplicate name: plain message', msg)
            check(not page.is_visible('#secret.secret-box'), 'no key was created for the duplicate name')
            page.click('#list tbody tr:first-child button:has-text("Revoke")')
            page.wait_for_selector('dialog[open]')
            check('Anything using this key stops working at once' in page.inner_text('dialog[open]'), 'Revoke asks first')
            page.click('dialog[open] button:has-text("Cancel")')
            page.wait_for_timeout(300)
            check(page.locator('#list tbody tr').count() == 5, 'Cancel revokes nothing')
            page.click('#list tbody tr:first-child button:has-text("Revoke")')
            page.click('dialog[open] button:has-text("Revoke")')
            page.wait_for_function('document.querySelectorAll("#list tbody tr").length === 4')
            check(True, 'Revoke in the dialog removes the row')
            page.fill('#name', 'viewer')
            page.click('button:has-text("Create API key")')
            page.wait_for_selector('#secret.secret-box')
            check(True, 'the revoked key freed its name')
            token = page.inner_text('#secret pre')[:60]
            page.click('button:has-text("I have copied it")')
            page.wait_for_function('document.querySelector("#list tbody tr td").textContent === "viewer"')
            first = page.eval_on_selector_all('#list tbody tr', 'rows => rows.map(r => [...r.querySelectorAll("td")].map(td => td.textContent))')[0]
            check(first[0] == 'viewer' and first[1].startswith('cve_...') and len(first[1]) == 9, 'the new key is first, with its 2-character ending', first)
        ctx.close()
    browser.close()
print(f'{len(fails)} failed')
sys.exit(1 if fails else 0)
