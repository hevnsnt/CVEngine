"""ui_glance_layout.py: the cards at the top of a finding's detail (What was found, Confidence, AI assessment) use the room the pane has.

A browser check against a running throwaway stack with CVE matches that carry a template check (a long check name and a tested time).
Not part of `manage.py test`: it needs a stack and Chromium.

    BASE=http://127.0.0.1:28061 PROJECT=acme-web USER_NAME=gateadmin PASSWORD=... python scripts/ui_glance_layout.py [--shots dir] [--page matches/]

At 1900, 1440, 1280, 1024, 768 and 390 pixels wide it opens the first CVE match and asserts:
  * when the pane holds two 300px cards, What was found and Confidence share the row (together at least 95% of it, each at least 300px);
    when it does not, each one takes the full row;
  * the AI card is a full row of its own, below them;
  * no fact value column is narrower than 180px;
  * no word of a value or a signal is broken across lines (only a token longer than the line may break: none is seeded);
  * the check name is a code chip and the time reads "Nov 7, 2026 12:31 AM" (checked in UTC) with the ISO value in its tooltip;
  * the page and the pane do not scroll sideways.
Exit status 1 when any assertion fails.
"""
import argparse
import glob
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get('BASE', 'http://127.0.0.1:28061')
PROJECT = os.environ.get('PROJECT', 'acme-web')
USER = os.environ.get('USER_NAME', 'gateadmin')
PASSWORD = os.environ.get('PASSWORD', 'Gate-Local-9x!')
EXE = os.environ.get('CHROMIUM') or (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome')) or [None])[-1]
SIZES = [(1900, 1000), (1440, 900), (1280, 720), (1024, 768), (768, 1024), (390, 844)]
MIN_CARD = 300
BASIS = 340  # the card's flex-basis in cve.css: two share a row once the pane holds both

MEASURE = r"""() => {
  const grid = document.querySelector('.gl-grid');
  if (!grid) return null;
  const rect = (e) => { const r = e.getBoundingClientRect(); return {left: r.left, right: r.right, top: r.top, width: r.width, height: r.height}; };
  const found = grid.querySelector('.gl-found'), conf = grid.querySelector('.gl-conf'), ai = grid.querySelector('.gl-ai');
  const g = rect(grid), f = rect(found), c = rect(conf), a = rect(ai);
  // words that wrap in the middle: a word whose range has more than one line box
  const broken = [];
  for (const root of grid.querySelectorAll('.gl-facts dd, .sig-text')) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n; (n = walker.nextNode());) {
      const re = /\S+/g; let m;
      while ((m = re.exec(n.nodeValue))) {
        const r = document.createRange(); r.setStart(n, m.index); r.setEnd(n, m.index + m[0].length);
        const lines = new Set([...r.getClientRects()].filter((q) => q.width > 0).map((q) => Math.round(q.top)));
        if (lines.size > 1) broken.push(m[0]);
      }
    }
  }
  const dds = [...grid.querySelectorAll('.gl-facts dd')].map((d) => Math.round(d.getBoundingClientRect().width));
  const pane = grid.closest('.split-detail, .detail, aside, main') || document.body;
  const code = grid.querySelector('.gl-code'), when = grid.querySelector('time.gl-when');
  const chipBox = code ? rect(code) : null;
  const labelLines = [...grid.querySelectorAll('.gl-facts dt')].map((d) => { const r = document.createRange(); r.selectNodeContents(d); return new Set([...r.getClientRects()].map((q) => Math.round(q.top))).size; });
  return {labelLines, grid: g, found: f, conf: c, ai: a, dds, broken,
    sameRow: Math.abs(f.top - c.top) < 2, factsCols: getComputedStyle(grid.querySelector('.gl-facts') || grid).gridTemplateColumns,
    code: code ? code.textContent : null, codeLines: code ? Math.round(chipBox.height) : 0, when: when ? when.textContent : null, whenTitle: when ? when.title : null,
    docOverflow: document.documentElement.scrollWidth - innerWidth, paneOverflow: pane.scrollWidth - pane.clientWidth,
    sigTemplate: (grid.querySelector('.sig-text') ? [...grid.querySelectorAll('.sig-text')].map((s) => s.textContent) : [])};
}"""

fails = []


def check(ok, what):
    print(('ok   ' if ok else 'FAIL ') + what)
    if not ok:
        fails.append(what)


def run(page, shots, tag, generic=False):
    out = {}
    for w, h in SIZES:
        ctx = b.new_context(viewport={'width': w, 'height': h}, timezone_id='UTC', locale='en-US')  # UTC so the expected clock time is the one in the owner's report
        pg = ctx.new_page()
        pg.goto(BASE + '/login/')
        pg.fill('input[name=username]', USER)
        pg.fill('input[name=password]', PASSWORD)
        pg.click('button[type=submit], input[type=submit]')
        pg.wait_for_load_state('networkidle')
        pg.goto(f'{BASE}/cve/{PROJECT}/{page}')
        pg.add_style_tag(content='.scannerbar{display:none!important}')
        pg.wait_for_selector('.host-row', timeout=20000)
        pg.wait_for_timeout(1500)
        if not pg.query_selector('.gl-grid'):
            pg.click('.host-row')
        pg.wait_for_selector('.gl-grid .gl-found', timeout=20000)
        pg.wait_for_timeout(500)
        m = pg.evaluate(MEASURE)
        out[f'{w}x{h}'] = m
        name = f'{w}x{h}'
        if shots:
            pg.evaluate("() => { document.querySelector('.gl-grid').scrollIntoView({block: 'start'}); const h = document.querySelector('.gl-found .gl-h'); if (h) h.scrollIntoView({block: 'center'}); }")
            pg.wait_for_timeout(200)
            pg.screenshot(path=os.path.join(shots, f'{tag}-{w}x{h}.png'))
        g, f, c, a = m['grid'], m['found'], m['conf'], m['ai']
        gap = c['left'] - f['right'] if m['sameRow'] else 0
        two_fit = g['width'] >= 2 * BASIS + 12
        if two_fit:
            share = (f['width'] + c['width'] + max(gap, 0)) / g['width']
            check(m['sameRow'], f'{name}: the two cards share one row (pane row {g["width"]:.0f}px)')
            check(share >= 0.95, f'{name}: the two cards fill {share * 100:.0f}% of the row (need 95)')
            check(f['width'] >= MIN_CARD and c['width'] >= MIN_CARD, f'{name}: cards are {f["width"]:.0f}px and {c["width"]:.0f}px (need {MIN_CARD})')
            check(abs(f['width'] - c['width']) <= 2, f'{name}: the two cards are equal width')
        else:
            check(not m['sameRow'], f'{name}: the pane is too narrow for two cards, so they stack')
            check(min(f['width'], c['width']) >= 0.95 * g['width'], f'{name}: stacked cards are {f["width"]:.0f}px of {g["width"]:.0f}px')
        check(a['width'] >= 0.95 * g['width'] and a['top'] > max(f['top'], c['top']), f'{name}: the AI card is a full row below ({a["width"]:.0f}px)')
        check(m['dds'] and min(m['dds']) >= 180, f'{name}: narrowest fact value column {min(m["dds"] or [0])}px (need 180)')
        check(not m['broken'], f'{name}: words broken mid-word: {m["broken"][:5]}')
        check(max(m['labelLines'] or [1]) <= 1, f'{name}: every fact label stays on one line {m["labelLines"]}')
        if generic:
            ctx.close()
            continue
        check(m['code'] == 'testssl:secure_client_renego', f'{name}: check name shown as a chip: {m["code"]}')
        check(bool(m['when']) and m['when'] == 'Nov 7, 2026 12:31 AM', f'{name}: time reads for people: {m["when"]}')
        check(bool(m['whenTitle']) and m['whenTitle'].startswith('2026-11-07T00:31:37'), f'{name}: tooltip carries the ISO value')
        check(m['docOverflow'] <= 0 and m['paneOverflow'] <= 1, f'{name}: no sideways scroll (page {m["docOverflow"]}, pane {m["paneOverflow"]})')
        ctx.close()
    return out


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--shots')
    ap.add_argument('--tag', default='glance')
    ap.add_argument('--json')
    ap.add_argument('--page', default='matches/')
    ap.add_argument('--generic', action='store_true', help='other finding kinds: layout, facts, wrapping and overflow only (no check chip or time)')
    ap.add_argument('--no-assert', action='store_true', help='measure and shoot only (the layout before the change)')
    a = ap.parse_args()
    if a.shots:
        os.makedirs(a.shots, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=EXE) if EXE else p.chromium.launch()
        res = run(a.page, a.shots, a.tag, a.generic)
        b.close()
    if a.json:
        json.dump(res, open(a.json, 'w'), indent=1)
    if a.no_assert:
        sys.exit(0)
    print(f'{len(fails)} failed')
    sys.exit(1 if fails else 0)
