"""ui_first_screen.py: the first screen of the pages people open first shows their data, and nothing on it is cut, covered or off to the side.

A browser check against a running stack, like ui_list_viewport.py (not part of `manage.py test`: it needs a stack and Chromium). Seed the stack the way the
repo's other gates do (scripts/demo/seed_demo.py) and add what these checks need: an App Admin alert strip showing (`AdminAlert`, the strip that costs the
rows 40px and that the gates never ran with), 200+ rows of hosts, CVE matches (some fixed, with retest states), findings and hygiene findings, changes, a few
Sentinels (one with a `status_note` such as "Update failed: could not pull image"), suppliers, and a second project that has never been scanned:

    BASE=http://127.0.0.1:8141 PROJECT=acme-corp EMPTY_PROJECT=harbor-foods USER_NAME=admin PASSWORD=... python scripts/ui_first_screen.py [--json out.json] [--shots dir]

At 1366x768, 1280x720, 1440x900, 1920x1080 and 390x844 (a touch screen) it asserts, per page:
  - none of "[object", "undefined", "null", "NaN" or a bare "?" in the text of any of these pages (a value the server did not send is said in words);
  - no sideways scroll on any page that has rows (Suppliers used to push its Remove button off the right edge);
  - Overview: no button, label or sentence sits on the title, and the purpose sentence is whole or "About this page" shows it;
  - the purpose sentence of Overview, Situations, Hygiene, Sentinels, Suppliers, Secrets and Scans is whole, or an "About this page" button is on screen and
    opens the whole sentence with a tap and with Enter, and Escape closes it again and gives the focus back to the button;
  - Changes: at least 5 data rows fully on the first screen at 1366x768 and 1280x720 (the daily chart is closed under its own line), 1 on a phone;
  - Sentinels: at least 3 rows fully on the first screen on a desktop and 2 on a phone, no summary strip that scrolls sideways, no text cut at the side, and a Sentinel's note
    (why its update failed) is on its closed row;
  - no host name on a list page is broken over two lines;
  - Findings and CVE matches: each row's severity chip is inside the row, whole, not under the row menu, and not faded out;
  - CVE matches has the three retest chips the Findings filter has;
  - an empty, never-scanned project says nothing has been scanned yet on Findings and Hygiene, never "healthy" or "Every finding is fixed";
  - on a phone the Hygiene tile buttons, the project switcher, the Overview map tiles and the About button are at least 44px.
  - Settings, configMaxxing, Auto-tuning: the History's newest five changes are whole on a 1280x720 first screen, each says Why and What happened, none of the text above shows, and on a phone Revert and Apply are 44px;
Rows must be above the bottom bar a phone draws, not only inside the window. Exit status 1 when any assertion fails. CHROMIUM=/path/to/chrome picks the browser.
"""
import glob
import json
import os
import re
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get('BASE', 'http://127.0.0.1:28151')
PROJECT = os.environ.get('PROJECT', 'acme-web')
EMPTY = os.environ.get('EMPTY_PROJECT', '')
ONLY = [x for x in os.environ.get('ONLY', '').split(',') if x]  # ONLY=sentinels,changes runs just those pages (and none of the extra steps); ONLY=touch adds the phone tap-target checks
USER = os.environ.get('USER_NAME', 'uiadmin')
PASSWORD = os.environ.get('PASSWORD', 'UiAudit-Local-9x!')
EXE = os.environ.get('CHROMIUM') or (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome')) or [None])[-1]
SIZES = [(1366, 768), (1280, 720), (1440, 900), (1920, 1080), (390, 844)]
# name: (path under /cve/, rows selector)
PAGES = {
    'overview': (f'?project={PROJECT}', None),
    'changes': (f'{PROJECT}/changes/', 'main tbody tr'),
    'sentinels': ('sentinels/', '.sl-card'),
    'project-sentinels': (f'{PROJECT}/sentinels/', None),
    'suppliers': (f'{PROJECT}/suppliers/', '.supplier-list>*'),
    'situations': (f'{PROJECT}/situations/', '.host-rows .host-row, .sit-row'),
    'hygiene': (f'{PROJECT}/hygiene/', 'main tbody tr'),
    'secrets': (f'{PROJECT}/secrets/', 'main tbody tr'),
    'scans': (f'{PROJECT}/scans/', 'main tbody tr'),
    'findings': (f'{PROJECT}/vulns/', '.host-rows .host-row'),
    'matches': (f'{PROJECT}/matches/', '.host-rows .host-row'),
    'hosts': (f'{PROJECT}/hosts/', '.host-rows .host-row'),
    'targets': (f'{PROJECT}/targets/', 'main tbody tr'),
    'activity': (f'{PROJECT}/activity/', 'main tbody tr'),
}
# text a person must never read on a page: an object printed as text, a missing value, a bare question mark standing for "unknown"
BAD_TEXT = re.compile(r'\[object|\bundefined\b|\bnull\b|\bNaN\b|(?:^|[\s(:>])\?(?:$|[\s),.:])', re.M)
PURPOSE_PAGES = ('overview', 'situations', 'hygiene', 'sentinels', 'suppliers', 'secrets', 'scans')
MEASURE = r"""(sel) => {
  const vis = (e) => { const cs = getComputedStyle(e); return cs.display !== 'none' && cs.visibility !== 'hidden' && e.getClientRects().length > 0; };
  const bar = document.querySelector('.tabbar');
  const floor = bar && getComputedStyle(bar).display !== 'none' ? Math.round(bar.getBoundingClientRect().top) : innerHeight;
  const rows = sel ? [...document.querySelectorAll(sel)].filter(vis) : [];
  let full = 0;
  for (const r of rows) { const q = r.getBoundingClientRect(); if (q.top >= 0 && q.bottom <= floor + 1) full++; }
  const h1 = document.querySelector('main h1');
  let over = [];
  const headBox = document.querySelector('main .page-head');
  if (h1 && headBox && headBox.getBoundingClientRect().width > 8) { const r = h1.getBoundingClientRect();  // a phone does not draw the head: its title cannot be covered
    over = [...document.querySelectorAll('main button, main a, main label, main .sub, main .about-btn')].filter((e) => {
      if (h1.contains(e) || e.contains(h1) || !vis(e)) return false; const q = e.getBoundingClientRect();
      return q.width > 1 && q.height > 1 && q.left < r.right - 1 && q.right > r.left + 1 && q.top < r.bottom - 1 && q.bottom > r.top + 1; }).map((e) => (e.textContent || '').trim().slice(0, 30)); }
  const sub = document.querySelector('main .page-head .sub');
  const head = document.querySelector('main .page-head');
  const hb = head ? head.getBoundingClientRect() : null;
  const drawn = !!(hb && hb.width > 8 && hb.height > 8);
  const about = document.querySelector('main .about-btn');
  const cut = [];
  for (const e of document.querySelectorAll('.sl-sum *, .sl-card .sl-head *, .supplier-head *')) {
    if (!vis(e) || e.children.length) continue;
    if (e.scrollWidth > e.clientWidth + 1 && /(hidden|clip)/.test(getComputedStyle(e).overflowX) && !/-webkit-box/.test(getComputedStyle(e).display)) cut.push((e.textContent || '').trim().slice(0, 40));
  }
  const wrapped = [...document.querySelectorAll('main td a.host-link, main .host-row a.host-link, main td .host-link')].filter((e) => { if (!vis(e)) return false; const r = document.createRange(); r.selectNodeContents(e); return new Set([...r.getClientRects()].map((q) => Math.round(q.top / 4))).size > 1; }).map((e) => e.textContent.trim().slice(0, 40));
  const sum = document.querySelector('.sl-sum');
  const sumScroll = sum ? sum.scrollWidth - sum.clientWidth : 0;
  const SEV = /^(critical|high|medium|low|info|fire|smoke|ice|clean)$/i;
  const chips = [];
  for (const r of rows) for (const c of r.querySelectorAll('.badge')) {
    if (!vis(c) || !SEV.test(c.textContent.trim())) continue;
    const q = c.getBoundingClientRect(), rr = r.getBoundingClientRect(); const why = [];
    if (c.scrollWidth > c.clientWidth + 1) why.push('chip text wider than the chip');
    if (q.right > rr.right + 1 || q.left < rr.left - 1) why.push('outside the row');
    for (let p = c.parentElement; p && p !== r; p = p.parentElement) { const o = getComputedStyle(p), b = p.getBoundingClientRect();
      if (/(hidden|clip)/.test(o.overflowX) && q.right > b.right + 1) why.push('clipped by ' + p.className);
      if (o.maskImage && o.maskImage !== 'none' && q.right > b.right - 24) why.push('faded by ' + p.className); }
    const m = r.querySelector('.row-menu-btn');
    if (m && vis(m)) { const b = m.getBoundingClientRect(); if (b.left < q.right && b.right > q.left && b.top < q.bottom && b.bottom > q.top) why.push('under the row menu'); }
    if (why.length) chips.push(c.textContent.trim() + ': ' + why.join(', '));
  }
  return {rows: rows.length, fullRows: full, firstTop: rows.length ? Math.round(rows[0].getBoundingClientRect().top) : null, floor,
    hscroll: document.documentElement.scrollWidth - innerWidth, over, h1: h1 && h1.textContent.trim(),
    sub: sub && {text: sub.textContent.replace(/\s+/g, ' ').trim(), cut: sub.scrollWidth > sub.clientWidth + 1 || sub.scrollHeight > sub.clientHeight + 1, drawn},
    sumScroll, wrapped,
    about: about && vis(about) ? Math.round(about.getBoundingClientRect().height) : null, cut, chips,
    alert: !!document.querySelector('.ab-row')};
}"""
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
    pg.wait_for_selector('main', timeout=15000)
    return pg


def open_page(pg, path):
    pg.goto(f'{BASE}/cve/{path}')
    pg.wait_for_selector('main', timeout=15000)
    pg.wait_for_timeout(3000)  # a polling page never reaches network idle: wait for the first paint of its rows


def purpose_checks(pg, name, m, tag):
    """The sentence is whole, or the About button is on screen and opens it by tap and by keyboard."""
    sub = m['sub']
    if not sub:
        return
    if sub['drawn'] and not sub['cut']:
        check(True, f'{name} {tag}: the purpose sentence is whole')
        return
    check(m['about'] is not None, f'{name} {tag}: the sentence is cut or not drawn, so "About this page" is on screen')
    if m['about'] is None:
        return
    btn = pg.locator('main .about-btn')
    btn.focus()
    pg.keyboard.press('Enter')
    pg.wait_for_timeout(150)
    panel = pg.locator('main .about-text')
    shown = panel.is_visible()
    whole = panel.evaluate('e => e.scrollWidth <= e.clientWidth + 1 && e.getBoundingClientRect().height > 10') if shown else False
    check(shown and whole and panel.inner_text().strip() == sub['text'] and btn.get_attribute('aria-expanded') == 'true',
          f'{name} {tag}: Enter on "About this page" shows the whole sentence')
    pg.keyboard.press('Escape')
    pg.wait_for_timeout(100)
    check(not panel.is_visible() and pg.evaluate("document.activeElement.classList.contains('about-btn')"), f'{name} {tag}: Escape closes it and the focus is back on the button')
    btn.click()
    pg.wait_for_timeout(100)
    check(panel.is_visible(), f'{name} {tag}: a tap opens it too')
    btn.click()


def measure_all(b, shots):
    out = {}
    for w, h in SIZES:
        touch = w < 500
        ctx = b.new_context(viewport={'width': w, 'height': h}, has_touch=touch, is_mobile=touch)
        pg = login(ctx)
        tag = f'{w}x{h}'
        for name, (path, sel) in PAGES.items():
            if ONLY and name not in ONLY:
                continue
            open_page(pg, path)
            m = pg.evaluate(MEASURE, sel)
            out[f'{name}@{tag}'] = m
            if shots:
                pg.screenshot(path=os.path.join(shots, f'{name}-{tag}.png'))
            text = pg.inner_text('main')
            bad = sorted({text[max(0, x.start() - 25):x.end() + 15].replace('\n', ' ') for x in BAD_TEXT.finditer(text)})[:3]
            check(not bad, f'{name} {tag}: no "[object", "undefined", "null", "NaN" or bare "?" in the page text ({bad})')
            if name == 'overview':
                check(m['alert'], f'{tag}: the alert strip is showing (seed an AdminAlert: the first screen is measured with it)')
            if name != 'project-sentinels':
                check(m['hscroll'] <= 1, f'{name} {tag}: no sideways scroll (page is {m["hscroll"]}px wider than the window)')
            if name == 'overview':
                check(not m['over'], f'{name} {tag}: nothing sits on the title (found {m["over"]})')
            if name in PURPOSE_PAGES:
                purpose_checks(pg, name, m, tag)
            if name == 'changes':
                need = 1 if touch else 5
                if touch or (w, h) in ((1366, 768), (1280, 720)):
                    check(m['fullRows'] >= need, f'changes {tag}: {m["fullRows"]} data rows fully on the first screen, first at y={m["firstTop"]} (need {need})')
            if name in ('changes', 'findings', 'matches', 'hygiene', 'hosts', 'scans', 'secrets', 'situations'):
                check(not m['wrapped'], f'{name} {tag}: no host name is broken over two lines ({m["wrapped"][:3]})')
            if name == 'sentinels':
                need = 2 if touch else 3
                check(m['fullRows'] >= need, f'sentinels {tag}: {m["fullRows"]} Sentinel rows fully on the first screen, first at y={m["firstTop"]} (need {need})')
                check(m['sumScroll'] <= 1, f'sentinels {tag}: the summary does not scroll sideways ({m["sumScroll"]}px hidden)')
                if w in (1280, 390):
                    check(not m['cut'], f'sentinels {tag}: no summary or row text is cut at the side ({m["cut"][:3]})')
                    notes = pg.evaluate("""async () => { const r = await (await fetch('/api/v1/sentinels/live', {credentials: 'same-origin'})).json();
                      const text = [...document.querySelectorAll('.sl-card > .sl-head')].map((e) => e.textContent);
                      return (r.results || []).filter((s) => s.status_note && s.state !== 'suspended').map((s) => [s.name, s.status_note, text.some((t) => t.includes(s.status_note))]); }""")
                    for sname, note, found in notes:
                        check(found, f'sentinels {tag}: the closed row of {sname} says "{note}"')
            if name in ('findings', 'matches') and w in (1366, 1280, 390):
                check(m['rows'] > 0 and not m['chips'], f'{name} {tag}: every severity chip is whole, inside its row and clear of the row menu ({m["chips"][:3]})')
        if touch and (not ONLY or 'touch' in ONLY):
            open_page(pg, f'{PROJECT}/hygiene/')
            small = pg.evaluate("""() => [...document.querySelectorAll('main button.tile, #scope-btn')].filter((e) => e.getClientRects().length).map((e) => [e.id || e.textContent.trim().slice(0, 24), Math.round(e.getBoundingClientRect().height)]).filter(([, hh]) => hh < 44)""")
            check(not small, f'{tag}: the Hygiene tile buttons and the project switcher are 44px high ({small})')
            open_page(pg, f'?project={PROJECT}')
            sample = """() => { const t = [...document.querySelectorAll('.map .hx')].filter((e) => e.getClientRects().length).map((e) => e.getBoundingClientRect()); return [t.length, t.filter((q) => q.width < 43.5 || q.height < 43.5).length]; }"""
            tiles = pg.evaluate(sample)
            for _ in range(20):  # a tile scales in when it appears: measure when two samples, half a second apart, agree
                pg.wait_for_timeout(500)
                again = pg.evaluate(sample)
                if again == tiles:
                    break
                tiles = again
            check(tiles[0] > 0 and tiles[1] == 0, f'{tag}: the Overview map tiles are 44x44 or more ({tiles[1]} of {tiles[0]} are smaller)')
            open_page(pg, f'{PROJECT}/hygiene/')
            about = pg.evaluate("document.querySelector('main .about-btn') ? Math.round(document.querySelector('main .about-btn').getBoundingClientRect().height) : 0")
            check(about >= 44, f'{tag}: the About this page button is 44px high ({about})')
        ctx.close()
    return out


def matches_filter(b):
    ctx = b.new_context(viewport={'width': 1366, 'height': 768})
    pg = login(ctx)
    open_page(pg, f'{PROJECT}/matches/')
    pg.click('.filters-btn')
    pg.wait_for_timeout(300)
    labels = pg.evaluate("[...document.querySelectorAll('.filters-pop .picker button')].map((e) => e.textContent)")
    for want in ('Verified fixed', 'Fixed, not verified', 'Reopened by retest'):
        check(any(want in t for t in labels), f'CVE matches filter has the "{want}" chip')
    ctx.close()


def autotune_history(b):
    """Settings, configMaxxing, Auto-tuning (static/cve/autotune-history.js): the newest five changes are whole on the first screen of a 1280x720 window once the card is
    open, each says what, why and what happened, nothing reads "[object", "undefined", "null", "NaN" or a bare "?", and on a phone the Revert and Apply buttons are 44px."""
    for width, height, touch in ((1280, 720, False), (390, 844, True)):
        ctx = b.new_context(viewport={'width': width, 'height': height}, is_mobile=touch, has_touch=touch)
        pg = login(ctx)
        pg.goto(f'{BASE}/cve/settings/#configmaxxing/autotune')
        pg.wait_for_selector('.at-line', timeout=15000)
        pg.wait_for_timeout(1500)
        m = pg.evaluate("""() => { const lines = [...document.querySelectorAll('.at-line')];
          return {lines: lines.length, whole: lines.slice(0, 5).filter((l) => { const r = l.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; }).length,
                  text: (document.getElementById('configmaxxing-autotune') || document.body).innerText,
                  labelled: lines.slice(0, 5).filter((l) => /Why: /.test(l.innerText) && /What happened: /.test(l.innerText)).length,
                  buttons: [...document.querySelectorAll('.at-line button')].map((e) => Math.round(e.getBoundingClientRect().height)), sideways: document.documentElement.scrollWidth > innerWidth}; }""")
        tag = f'Auto-tuning History at {width}x{height}'
        check(m['lines'] >= 5, f'{tag}: the seeded changes are listed ({m["lines"]})')
        if pg.query_selector('text=Show more'):
            pg.click('text=Show more')
            pg.wait_for_timeout(300)
        words = pg.evaluate("(document.getElementById('configmaxxing-autotune') || document.body).innerText")
        for want in ('proposed by the AI, held back: text aimed at an AI may be in what it read (instructions to an AI)', 'proposed by the AI, not applied: outside what the controller allows now',
                     'nothing has changed yet: apply it to make the change', 'being checked, result at'):
            check(want in words, f'{tag}: a health-check AI line reads "{want[:60]}"')
        check('ai_directive' not in words and ' · the AI' in words, f'{tag}: the AI is named as the AI, and no family code shows')
        if not touch:
            check(m['whole'] == 5, f'{tag}: the newest five changes are whole on the first screen ({m["whole"]})')
        check(m['labelled'] == min(5, m['lines']), f'{tag}: every line says Why and What happened')
        check(not BAD_TEXT.search(m['text']), f'{tag}: no [object, undefined, null, NaN or bare ? in the card')
        check(not m['sideways'], f'{tag}: no sideways scroll')
        if touch:
            check(m['buttons'] and min(m['buttons']) >= 44, f'{tag}: Revert and Apply are 44px high ({m["buttons"]})')
        ctx.close()


def empty_project(b):
    if not EMPTY:
        print('skip the empty-project checks: EMPTY_PROJECT is not set')
        return
    ctx = b.new_context(viewport={'width': 1366, 'height': 768})
    pg = login(ctx)
    for page, path in (('Findings', f'{EMPTY}/vulns/'), ('Hygiene', f'{EMPTY}/hygiene/')):
        open_page(pg, path)
        text = pg.inner_text('main')
        check(not re.search(r'healthy|every finding|looks? (fine|good)|nothing needs action', text, re.I) and re.search(r'scanned', text, re.I) is not None,
              f'{page} of a project nobody scanned says so, and never "healthy" or "every finding is fixed": {text[-160:]!r}')
    ctx.close()


def main():
    args = sys.argv[1:]
    out = args[args.index('--json') + 1] if '--json' in args else None
    shots = args[args.index('--shots') + 1] if '--shots' in args else None
    if shots:
        os.makedirs(shots, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=EXE) if EXE else p.chromium.launch()
        res = measure_all(b, shots)
        if out:
            json.dump(res, open(out, 'w'), indent=1)
        for step in () if ONLY else (matches_filter, empty_project, autotune_history):
            try:
                step(b)
            except Exception as e:  # an older build without the page or the control fails here: say so and keep the rest
                check(False, f'{step.__name__} stopped: {str(e).splitlines()[0]}')
        b.close()
    print(f'{len(fails)} failed')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
