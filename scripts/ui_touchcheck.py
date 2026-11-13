"""touchcheck.py <outfile.json> [pages...]  (env BASE default http://127.0.0.1:28021)
Lists visible interactive controls whose hit box is under 44px on a 390px touch screen (pointer:coarse).
A control counts as 44px when its own box or its ::after hit extension (measured by elementFromPoint at +-22px around its centre) answers."""
import sys, os, json, glob
from playwright.sync_api import sync_playwright
BASE = os.environ.get('BASE', 'http://127.0.0.1:28021'); S = os.environ.get('PROJECT', 'acme-web')
EXE = os.environ.get('CHROMIUM') or (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/*/chrome')) or [None])[-1]
PAGES = {'dashboard': '/cve/?project=%s&skip=1' % S, 'settings-ai': '/cve/settings/#ai', 'settings-alerts': '/cve/settings/#alerts',
         'settings-updates': '/cve/settings/#updates', 'settings-scan_policy': '/cve/settings/#scan_policy', 'settings-autotune': '/cve/settings/#configmaxxing/autotune', 'targets': '/cve/%s/targets/' % S,
         'hosts': '/cve/%s/hosts/' % S, 'findings': '/cve/%s/vulns/' % S, 'scans': '/cve/%s/scans/' % S, 'sentinels': '/cve/sentinels/',
         'cve-explorer': '/cve/cves/', 'secrets': '/cve/%s/secrets/' % S, 'matches': '/cve/%s/matches/' % S, 'bounty': '/cve/bounty/?project=%s' % S}
JS = r"""() => {
  const sel = 'a[href],button,input:not([type=hidden]),select,textarea,summary,[role=button],[role=tab],[role=menuitem],[tabindex]:not([tabindex="-1"])';
  const out = [];
  for (const e of document.querySelectorAll(sel)) {
    const cs = getComputedStyle(e); if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    let r = e.getBoundingClientRect(); if (r.width === 0 || r.height === 0) continue;
    if (e.closest('[hidden],[inert]')) continue;
    if (e instanceof SVGElement || e.closest('svg')) continue;      // the graph map is counted separately (see PR)
    if (e.tagName === 'A' && e.getAttribute('tabindex') === '-1') continue;  // a redundant link inside a row that is itself the 44px target
    // a tile that is still scaling in (the Overview map) is measured when it rests: the next scroll step sees it again
    if (e.getAnimations && e.getAnimations().some((a) => a.animationName === 'cellin')) continue;
    // not controls: a focus stop that only shows its tooltip (the totals of the Overview trend rows: tabindex=0, no link, no button, no click handler, WCAG 1.4.13), so a tap on it does nothing
    if (e.getAttribute('tabindex') === '0' && !['A','BUTTON','INPUT','SELECT','TEXTAREA','SUMMARY'].includes(e.tagName) && !e.getAttribute('role') && e.classList.contains('mx-total')) continue;
    // effective hit area: probe a 44x44 box around the centre
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    const hit = (x, y) => { const t = document.elementFromPoint(x, y); return t && (t === e || e.contains(t)); };
    let w = r.width, h = r.height;
    if (cx >= 0 && cy >= 0 && cx < innerWidth && cy < innerHeight) {
      let up = 0; while (up < 30 && hit(cx, cy - r.height / 2 - up - 1)) up++;
      let dn = 0; while (dn < 30 && hit(cx, cy + r.height / 2 + dn + 1)) dn++;
      let lf = 0; while (lf < 30 && hit(cx - r.width / 2 - lf - 1, cy)) lf++;
      let rt = 0; while (rt < 30 && hit(cx + r.width / 2 + rt + 1, cy)) rt++;
      h += up + dn; w += lf + rt;
    }
    if (h < 43.5 || w < 43.5) {
      const inline = e.tagName === 'A' && cs.display === 'inline' && e.parentElement && /\S/.test((e.parentElement.textContent || '').replace(e.textContent, ''));
      out.push({tag: e.tagName, cls: String(e.className).slice(0, 60), txt: (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 30), w: Math.round(w), h: Math.round(h), inlineInSentence: !!inline});
    }
  }
  return out;
}"""
args = [a for a in sys.argv[2:]]
with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=EXE) if EXE else pw.chromium.launch()
    c = b.new_context(viewport={'width': 390, 'height': 844}, is_mobile=True, has_touch=True)
    c.add_init_script("try{localStorage.setItem('cve.theme','light')}catch(e){}")
    p = c.new_page(); p.goto(BASE + '/login/')
    p.fill('[name=username]', os.environ.get('USER_NAME', 'uiadmin')); p.fill('[name=password]', os.environ.get('PASSWORD', 'UiAudit-Local-9x!'))
    p.click('button[type=submit]'); p.wait_for_selector('main', timeout=15000)
    res = {}
    for name, url in PAGES.items():
        if args and name not in args: continue
        p.goto(BASE + url, wait_until='domcontentloaded')
        try: p.wait_for_load_state('networkidle', timeout=8000)
        except Exception: pass
        p.wait_for_timeout(1500)
        # scroll through so elementFromPoint can see everything
        H = p.evaluate('document.documentElement.scrollHeight'); y = 0; items = {}
        while y < H:
            p.evaluate('y=>scrollTo(0,y)', y); p.wait_for_timeout(100)
            for it in p.evaluate(JS):
                items[json.dumps(it, sort_keys=True)] = it
            y += 600
        res[name] = list(items.values())
        print(name, len(res[name]), 'pointer coarse:', p.evaluate("matchMedia('(pointer:coarse)').matches"))
    json.dump(res, open(sys.argv[1], 'w'), indent=1)
# exit status 1 when any control is under 44px, except a link inside a sentence (it keeps the sentence's line height, WCAG 2.5.8 inline exception)
bad = {n: [i for i in v if not i.get('inlineInSentence')] for n, v in res.items()}
bad = {n: v for n, v in bad.items() if v}
for n, v in bad.items():
    print('UNDER 44px', n, [(i['tag'], i['cls'][:20], i['txt'], i['w'], i['h']) for i in v][:6])
sys.exit(1 if bad else 0)
