"""ui_list_viewport.py: the split lists (Findings, Hosts, CVE matches) and the table lists (Secrets) show a useful number of rows.

A browser check against a running stack seeded with 200+ rows of each (synthetic example.com names). Not part of `manage.py test`: it needs a stack and
Chromium. Run it against a throwaway one:

    BASE=http://127.0.0.1:28151 PROJECT=acme-web USER_NAME=uiadmin PASSWORD=... python scripts/ui_list_viewport.py [--json out.json] [--shots dir]

It measures at 1440x900, 1280x720, 1920x1080, 1366x768 and 390x844 (rows fully visible once the list is in view, the share of the column the rows
take, where the filters end) and asserts: at least 6 full rows on Findings and Hosts, 3 on CVE matches (rows of ~137px) and 5 on Secrets at 1366x768 and 1280x720, the rows window is 70% of the
column or more, the rows are the one scroll container, a closed Filters panel costs the rows nothing and an open one does not push them, "Load more"
shows its busy state and a polite message, appends without moving what was seen, and ends in "All N shown"; a picked row opens its detail at the top.
Exit status 1 when any assertion fails. HIDE_BANNERS=1 hides the scanner-offline notices a scanner-less throwaway stack shows. BROWSER=firefox runs it in Firefox (`playwright install firefox` first).
"""
import glob
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get('BASE', 'http://127.0.0.1:28151')
PROJECT = os.environ.get('PROJECT', 'acme-web')
USER = os.environ.get('USER_NAME', 'uiadmin')
PASSWORD = os.environ.get('PASSWORD', 'UiAudit-Local-9x!')
EXE = os.environ.get('CHROMIUM') or (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome')) or [None])[-1]
SIZES = [(1440, 900), (1280, 720), (1920, 1080), (1366, 768), (390, 844)]
PAGES = {
    'findings-hygiene': ('vulns/?type=hygiene', '.host-rows .host-row', True),
    'findings-all': ('vulns/', '.host-rows .host-row', True),
    'hosts': ('hosts/', '.host-rows .host-row', True),
    'matches': ('matches/', '.host-rows .host-row', True),
    'secrets': ('secrets/', 'main tbody tr', False),
    'suppliers': ('suppliers/', '.supplier-list>*', False),  # measured, not asserted: a page-scroll list under its own intro
    'scans': ('scans/', 'main tbody tr', False),
}
MEASURE = r"""(sel) => {
  const rows = [...document.querySelectorAll(sel)].filter((r) => r.offsetParent);
  if (!rows.length) return {rows: 0, fullRows: 0};
  const vh = innerHeight;
  const scrollers = (e) => { const a = []; for (let x = e.parentElement; x && x !== document.documentElement; x = x.parentElement) { const o = getComputedStyle(x); if (/(auto|scroll)/.test(o.overflowY) && x.scrollHeight > x.clientHeight + 1) a.push(x); } return a; };
  const clip = (r) => { let top = 0, bot = vh; for (const s of scrollers(r)) { const b = s.getBoundingClientRect(); top = Math.max(top, b.top); bot = Math.min(bot, b.bottom); }
    const h = r.closest('.split-list') && r.closest('.split-list').querySelector('.list-head'); if (h) top = Math.max(top, h.getBoundingClientRect().bottom); return [top, bot]; };
  const first = rows[0]; const [t, b] = clip(first); let full = 0;
  for (const r of rows) { const [ct, cb] = clip(r); const q = r.getBoundingClientRect(); if (q.top >= ct - 1 && q.bottom <= cb + 1 && q.top >= 0 && q.bottom <= vh) full++; }
  const col = first.closest('.split-list') || first.closest('main'); const cr = col.getBoundingClientRect();
  const colH = Math.min(cr.bottom, vh) - Math.max(cr.top, 0); const win = Math.max(0, b - Math.max(t, 0));
  const head = document.querySelector('.list-head');
  return {rows: rows.length, rowH: Math.round(first.getBoundingClientRect().height), firstRowTop: Math.round(first.getBoundingClientRect().top), windowH: Math.round(win), fullRows: full,
    scrollers: scrollers(first).map((s) => String(s.className).split(' ')[0]), colH: Math.round(colH), rowsShare: colH ? Math.round(100 * win / colH) : 0, headH: head ? Math.round(head.getBoundingClientRect().height) : 0};
}"""
PIN = "() => { const s = document.querySelector('.split, main table, .supplier-list'); if (s) window.scrollTo(0, Math.max(0, s.getBoundingClientRect().top + scrollY - 70)); }"

fails = []


def check(ok, what):
    print(('ok   ' if ok else 'FAIL ') + what)
    if not ok:
        fails.append(what)


def login(ctx):
    pg = ctx.new_page()
    pg.goto(BASE + '/login/')
    pg.fill('input[name=username]', USER)
    pg.fill('input[name=password]', PASSWORD)
    pg.click('button[type=submit], input[type=submit]')
    pg.wait_for_selector('main', timeout=15000)  # not networkidle: a page that polls never reaches it
    pg.wait_for_timeout(1500)
    return pg


def open_page(pg, path):
    pg.goto(f'{BASE}/cve/{PROJECT}/{path}')
    pg.wait_for_selector('main', timeout=15000)
    if os.environ.get('HIDE_BANNERS'):  # a throwaway stack has no scanner: its offline notices are ~130px (450px on a phone) a healthy install does not show
        pg.add_style_tag(content='.scannerbar{display:none!important}')
    pg.wait_for_timeout(2000)


def measure_all(b, shots):
    out = {}
    for w, h in SIZES:
        ctx = b.new_context(viewport={'width': w, 'height': h})
        pg = login(ctx)
        for name, (path, sel, split) in PAGES.items():
            open_page(pg, path)
            first = pg.evaluate(MEASURE, sel)
            pg.evaluate(PIN)
            pg.wait_for_timeout(250)
            pinned = pg.evaluate(MEASURE, sel)
            out[f'{name}@{w}x{h}'] = {'first_screen': first, 'in_view': pinned}
            if shots and name in ('findings-hygiene', 'hosts'):
                pg.screenshot(path=os.path.join(shots, f'{name}-{w}x{h}.png'))
            if (w, h) in ((1366, 768), (1280, 720)):
                if name in ('suppliers', 'scans'):
                    continue
                need = 6 if name in ('findings-hygiene', 'findings-all', 'hosts') else 3 if name == 'matches' else 5  # a CVE match row is ~137px tall: 3 is what 650px holds
                check(pinned['fullRows'] >= need, f'{name} {w}x{h}: {pinned["fullRows"]} full rows in view (need {need}); first screen {first["fullRows"]}')
                if split:
                    check(pinned['rowsShare'] >= 70, f'{name} {w}x{h}: rows window is {pinned["rowsShare"]}% of the column (need 70)')
                    check(pinned['scrollers'] == ['split-list'], f'{name} {w}x{h}: one scroll container for the rows, got {pinned["scrollers"]}')
            if split and w >= 390:
                check(pinned['fullRows'] >= 3, f'{name} {w}x{h}: at least 3 full rows ({pinned["fullRows"]})')
        ctx.close()
    return out


def filters_and_load_more(b):
    ctx = b.new_context(viewport={'width': 1366, 'height': 768})
    pg = login(ctx)
    open_page(pg, 'vulns/?type=hygiene')
    # the first row is selected by the page, and the list is not scrolled to it
    check(pg.evaluate("document.querySelector('.host-row.sel') === document.querySelector('.host-row')"), 'the first row is selected on arrival')
    check(pg.evaluate("document.querySelector('.split-list').scrollTop") == 0, 'the list is not scrolled on arrival')
    pg.evaluate(PIN)
    pg.wait_for_timeout(250)
    tops = lambda: pg.evaluate("[...document.querySelectorAll('.host-row')].slice(0,6).map(r=>Math.round(r.getBoundingClientRect().top))")
    before = tops()
    check(pg.evaluate("document.querySelector('.filters-pop').hidden"), 'the filters panel is closed by default')
    check('Filters (1)' in pg.inner_text('.filters-btn'), f'Filters button counts the active filter: {pg.inner_text(".filters-btn")!r}')
    pg.click('.filters-btn')
    pg.wait_for_timeout(200)
    check(pg.get_attribute('.filters-btn', 'aria-expanded') == 'true' and tops() == before, 'an open panel does not push the rows')
    pg.keyboard.press('Escape')
    check(pg.evaluate("document.querySelector('.filters-pop').hidden") and pg.evaluate("document.activeElement.classList.contains('filters-btn')"), 'Escape closes the panel and returns focus to the button')
    # a picked row opens its detail at the top, whatever the page scroll
    pg.evaluate("window.scrollTo(0, 400)")
    pg.click('.host-row:nth-child(3)')
    pg.wait_for_timeout(600)
    top = pg.evaluate("document.querySelector('.split-pane').getBoundingClientRect().top")
    # the pane sits under the page head and the summary line; an App Admin's status strip (40px, above the page) moves all of that down by its own height
    strip = pg.evaluate("(() => { const s = document.querySelector('.scannerbar'); return s ? s.getBoundingClientRect().height : 0; })()")
    check(0 <= top < 200 + strip, f'a picked row opens its detail at the top of the screen (pane top {top:.0f}px, status strip {strip:.0f}px)')
    pg.evaluate(PIN)
    # Load more
    n = pg.locator('.host-row').count()
    # record every busy state the button goes through, however short
    pg.evaluate("""() => { window.__busy = []; new MutationObserver(() => { const b = document.querySelector('.more-row button'); if (b && b.getAttribute('aria-busy') === 'true') window.__busy.push([b.disabled, b.textContent]); }).observe(document.querySelector('main'), {subtree: true, attributes: true, childList: true, characterData: true}); }""")
    for _ in range(12):
        btn = pg.locator('.more-row button')
        if not btn.count():
            break
        btn.click()  # Playwright scrolls the button into view first: what counts is what the rows do after the press
        row0 = tops()[0]
        pg.wait_for_timeout(120)
        pg.wait_for_function(f"document.querySelectorAll('.host-row').length > {n}", timeout=15000)
        pg.wait_for_timeout(300)
        n2 = pg.locator('.host-row').count()
        msg = pg.evaluate("(document.querySelector('p.sr[role=status]') || {}).textContent || ''")
        check(n2 > n and tops()[0] == row0, f'Load more appended {n2 - n} rows without moving the first row ({n} -> {n2})')
        check(msg.startswith('Loaded ') and ' more finding' in msg and ' shown' in msg, f'live message: {msg!r}')
        n = n2
    seen_busy = any(d and t.startswith('Loading ') and t.endswith(' more...') for d, t in pg.evaluate('window.__busy'))
    check(seen_busy, 'the button showed disabled, aria-busy and "Loading N more..." while the page was on its way')
    done = pg.locator('.more-done')
    check(done.count() == 1 and done.inner_text().startswith('All ') and done.inner_text().endswith(' shown'), f'the button ends as "{done.inner_text() if done.count() else None}"')
    ctx.close()


def main():
    args = sys.argv[1:]
    out = args[args.index('--json') + 1] if '--json' in args else None
    shots = args[args.index('--shots') + 1] if '--shots' in args else None
    if shots:
        os.makedirs(shots, exist_ok=True)
    with sync_playwright() as p:
        if os.environ.get('BROWSER') == 'firefox':
            b = p.firefox.launch()
        else:
            b = p.chromium.launch(executable_path=EXE) if EXE else p.chromium.launch()
        res = measure_all(b, shots)
        if out:
            json.dump(res, open(out, 'w'), indent=1)
        try:
            filters_and_load_more(b)
        except Exception as e:  # a page without the new head (an older build) fails here: say so and keep the measurements
            check(False, f'filters and Load more checks stopped: {str(e).splitlines()[0]}')
        b.close()
    print(f'{len(fails)} failed')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
