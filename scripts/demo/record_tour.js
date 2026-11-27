// Records the 1.5 tour: a scripted walk through a demo instance (the rebranded scripts/demo/seed_demo.py plus seed_tour_projects.py) as a WebM, which
// make_gif.sh turns into the README GIF. Run it through make_gif.sh (one command, from a fresh seed); on its own:
//   BASE=http://127.0.0.1:8001 OUT=/tmp/tour STAGE='python3 manage.py shell < /tmp/tour-seed/stage_live.py' STAGE_CWD=web NODE_PATH=$(npm root -g) node scripts/demo/record_tour.js
// Scenes: Overview (the Hosts with open findings tile, the Live discovery card), the All-projects graph (every project a constellation, a card), the demo
// company's own constellations (one per domain, the dive host by host), Shodan-style search typed on camera, CVEs landing on the constellations while a scan
// runs (the second seed step stage_live.py writes them through the product's own code while this records), the CVE matches page, the Internal network page
// (internal hosts by name and address), a printer that is scanned gently, the Sentinels outside and inside the network, and back to the Overview.
const { chromium } = require('playwright');
const { exec } = require('child_process');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8001';
const OUT = process.env.OUT || '/tmp/tour';
const PROJECT = process.env.PROJECT || 'quillfern-group';
const COMPANY = process.env.COMPANY || 'Quillfern Group';  // the demo company's name (scripts/demo/rebrand.py)
const DOMAIN = process.env.DOMAIN || 'quillfern-example.com';
const STAGE = process.env.STAGE || 'python3 manage.py shell < ../scripts/demo/stage_live.py';
const STAGE_CWD = process.env.STAGE_CWD || 'web';
const GO_DIR = process.env.GO_DIR || '';  // OUT as the stage command sees it, when that command runs in a container with OUT mounted elsewhere
const SHOTS = process.env.SHOTS || '';  // a folder: a PNG at the end of each scene, for checking the tour without playing it
const W = 1280, H = 800;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const overlay = `
(() => {
  const css = document.createElement('style');
  css.textContent = '#__cap{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:2147483647;background:rgba(10,10,11,.92);color:#fff;font:600 15px/1.35 Geist,system-ui,sans-serif;padding:10px 18px;border-radius:999px;box-shadow:0 6px 24px rgba(0,0,0,.28);max-width:86%;text-align:center;pointer-events:none;transition:opacity .25s}#__cap b{color:#ff7a2f}#__cap code{font:600 14px/1.35 "Geist Mono",ui-monospace,monospace;color:#ffd2b8}#__fade{position:fixed;left:0;right:0;bottom:0;height:130px;z-index:2147483646;pointer-events:none;background:linear-gradient(to bottom,rgba(244,244,245,0),rgb(244,244,245) 48%)}#__cur{position:fixed;left:0;top:0;width:22px;height:22px;z-index:2147483647;pointer-events:none;transition:transform .02s}#__cur svg{filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}';
  const mount = () => {
    if (!document.getElementById('__cap')) {
      document.head.appendChild(css);
      // a band that fades the page out under the caption, so a list that runs past the frame ends softly instead of on a half row
      const fade = document.createElement('div'); fade.id = '__fade'; document.body.appendChild(fade);
      const rail = document.querySelector('aside, nav.sidebar, .sidebar, nav');  // the page only: the rail's account button stays clear
      const railRight = rail ? rail.getBoundingClientRect().right : 0;
      if (railRight > 0 && railRight < innerWidth / 2) fade.style.left = railRight + 'px';
      const cap = document.createElement('div'); cap.id = '__cap'; document.body.appendChild(cap);
      const cur = document.createElement('div'); cur.id = '__cur';
      cur.innerHTML = '<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2l14 8-6 1.6L8.4 18z" fill="#0a0a0b" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
      document.body.appendChild(cur);
      const last = JSON.parse(sessionStorage.getItem('__pos') || '[640,380]');
      cur.style.transform = 'translate(' + last[0] + 'px,' + last[1] + 'px)';
      addEventListener('mousemove', (e) => { cur.style.transform = 'translate(' + e.clientX + 'px,' + e.clientY + 'px)'; sessionStorage.setItem('__pos', JSON.stringify([e.clientX, e.clientY])); }, true);
      const text = sessionStorage.getItem('__cap') || '';
      cap.innerHTML = text; cap.style.opacity = text ? 1 : 0;
    }
  };
  window.__cap = (html) => { sessionStorage.setItem('__cap', html || ''); const cap = document.getElementById('__cap'); if (cap) { cap.innerHTML = html || ''; cap.style.opacity = html ? 1 : 0; } };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
})();`;

// the second seed step. Django takes seconds to start, so a phase is started early and waits for a file (GO_FILE) that go() creates the moment the rows should be
// written; the page keeps drawing while the product's own code writes them
const stage = (phase, outDir) => {
  const goFile = `${outDir}/go-${phase}`;
  try { fs.unlinkSync(goFile); } catch (_) { /* none yet */ }
  const done = new Promise((resolve, reject) => exec(`PHASE=${phase} GO_FILE=${GO_DIR ? `${GO_DIR}/go-${phase}` : goFile} ${STAGE}`, { cwd: STAGE_CWD, shell: '/bin/bash' },
    (err, out, errOut) => (err ? reject(new Error(`stage ${phase} failed: ${errOut || out}`)) : resolve(out))));
  done.catch(() => {});
  return { go: () => fs.writeFileSync(goFile, ''), done };
};

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});  // CHROME: a Chromium of your own, when playwright's is not installed
  // sign in once, outside the recording
  const login = await browser.newContext({ viewport: { width: W, height: H } });
  const lp = await login.newPage();
  await lp.goto(BASE + '/login/');
  await lp.fill('#username', 'admin'); await lp.fill('#password', 'demo-Tour-2026');
  await lp.click('button[type=submit]'); await lp.waitForLoadState('networkidle');
  // the demo admin has no two-step sign-in: press "Remind me later" on its reminder once, which hides it for this session
  await lp.evaluate(async () => {
    const data = document.getElementById('mfa-nag-data'); const marker = document.querySelector('[data-mfa-nag]');
    if (!data || !marker) return;
    await fetch(JSON.parse(data.textContent).snooze_url, { method: 'POST', headers: { 'X-CSRFToken': marker.dataset.csrf, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'next=/cve/' });
  });
  const state = await login.storageState();
  await login.close();

  const ctx = await browser.newContext({ viewport: { width: W, height: H }, storageState: state, recordVideo: { dir: OUT, size: { width: W, height: H } } });
  await ctx.addInitScript(overlay);
  const p = await ctx.newPage();
  const t0 = Date.now();
  const marks = [];
  const dead = [];  // stretches spent waiting for a page to load: cut out by make_gif.sh (cuts.json); every other frame is kept as filmed
  const now = () => (Date.now() - t0) / 1000;
  const go = async (url) => { const a = now(); await p.goto(url, { waitUntil: 'domcontentloaded' }); dead.push([a, now()]); };
  const mark = async (name) => { marks.push([name, (Date.now() - t0) / 1000]); if (SHOTS) await p.screenshot({ path: `${SHOTS}/${name}.png` }); };
  const cap = async (html) => { await p.evaluate((h) => window.__cap && window.__cap(h), html); };
  const settle = async (ms = 900) => { const a = now(); await p.waitForLoadState('networkidle', { timeout: 2500 }).catch(() => {}); dead.push([a, now()]); await sleep(ms); };
  const moveTo = async (loc, steps = 14) => {
    await loc.scrollIntoViewIfNeeded();
    const box = await loc.boundingBox();
    await p.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps });
    return box;
  };
  const click = async (loc, wait = 900) => { await moveTo(loc); await sleep(250); await loc.click(); await settle(wait); };
  const nav = (name) => p.locator('nav a, aside a, .sidebar a').filter({ hasText: new RegExp('^\\s*' + name + '\\s*$') }).first();
  const tab = (name) => p.locator('main a, main button, [role=tab]').filter({ hasText: new RegExp('^\\s*' + name + '\\s*(\\d+)?\\s*$') }).first();
  // where a host's label is drawn now (the graph pans and zooms, so ask the page)
  const labelAt = (name) => p.evaluate((n) => {
    const s = [...document.querySelectorAll('svg')].filter((x) => x.querySelectorAll('circle').length > 20)[0];
    const t = s && [...s.querySelectorAll('text')].find((x) => x.textContent === n);
    if (!t) return null;
    const r = t.getBoundingClientRect();
    const hub = [...s.querySelectorAll('circle')].map((c) => { const q = c.getBoundingClientRect(); return { x: q.x + q.width / 2, y: q.y + q.height / 2, w: q.width }; })
      .filter((q) => q.w > 5 && q.w < 60).sort((a, b) => Math.hypot(a.x - (r.x - 6), a.y - (r.y + 2)) - Math.hypot(b.x - (r.x - 6), b.y - (r.y + 2)))[0];
    return hub ? [hub.x, hub.y] : [r.x + r.width / 2, r.y];
  }, name);
  const wheel = async (x, y, dy, steps, ms) => { await p.mouse.move(x, y, { steps: 6 }); for (let i = 0; i < steps; i++) { await p.mouse.wheel(0, dy / steps); await sleep(ms / steps); } };
  const smoothScroll = (y) => p.evaluate((yy) => window.scrollTo({ top: yy, behavior: 'smooth' }), y);

  // the phases that need Django to start run in the background from the first second, so the rows are written the moment a scene asks for them
  dead.push([0, 0.4]);
  const arm = stage('arm', OUT), detect = stage('detect', OUT), confirm = stage('confirm', OUT), finish = stage('done', OUT);

  // 1. Overview of all projects, ending on the Live discovery card (the constellations, with the counts under them)
  // the pages around the graphs are filmed with reduced motion (the Overview's discovery map holds still), which keeps the GIF under GitHub's 10 MB;
  // the graph scenes below run with full motion
  const still = (on) => p.emulateMedia({ reducedMotion: on ? 'reduce' : 'no-preference' });
  await still(true);
  await go(`${BASE}/cve/?project=_all`); await settle(900);
  const tile = p.locator('[data-kpi=exposed]').first();
  if (await tile.count()) await moveTo(tile); else await p.mouse.move(820, 330, { steps: 14 });
  await cap('<b>Overview</b> of fictional companies: <b>Hosts with open findings</b>, and what to fix first');
  await sleep(2000);
  await mark('1-overview');
  await smoothScroll(540);
  await cap('<b>Live discovery</b>: every project as a constellation');
  await sleep(2200);
  await mark('1-overview-card');
  await smoothScroll(0);

  // 2. THE STAR: the Graph page, All projects. Every project is a constellation (size is hosts, flares are fire, smoke and ice); open the hot one
  await cap('');
  await still(false);
  await go(`${BASE}/cve/graph/?project=_all`); await settle(300);
  await cap('Every project is a <b>constellation</b>: size is hosts, flares are fire, smoke and ice');
  await smoothScroll(300);
  await sleep(4000);  // let it settle: packets run along the wires, the flares breathe
  await mark('2-all-projects');
  const cloudAt = (label) => p.evaluate((l) => {
    const t = [...document.querySelectorAll('svg g text')].find((x) => x.textContent === l);
    const r = t && t.getBoundingClientRect();
    return r ? [r.x + r.width / 2, r.y + r.height + 40] : null;
  }, label);
  const home = (await cloudAt(COMPANY)) || [830, 480];
  await p.mouse.move(home[0], home[1], { steps: 22 });
  await sleep(300);
  await p.mouse.click(home[0], home[1]);
  await cap('Click one: its hottest hosts, and exactly why they are hot');
  await sleep(2800);
  await mark('2-project-card');
  const closeCard = p.locator('button').filter({ hasText: /^Close$/ }).first();
  if (await closeCard.isVisible()) await click(closeCard, 300);

  // 3. Choose the demo company: one constellation per domain (and IP assets); dive into the hot one host by host
  await cap('');
  await go(`${BASE}/cve/graph/?project=${PROJECT}`); await settle(300);
  await smoothScroll(300);
  await p.mouse.move(640, 640, { steps: 6 });
  await cap('Choose a project: one <b>constellation</b> per domain, and one for the IP assets');
  await sleep(3400);
  await mark('3-constellations');
  const dom = (await cloudAt(DOMAIN)) || [810, 520];
  await p.mouse.move(dom[0], dom[1], { steps: 20 });
  await sleep(250);
  await cap('Double-click one to dive in, host by host');
  await p.mouse.dblclick(dom[0], dom[1]);
  await cap('Inside: every host of this domain, hot ones in colour');
  await sleep(3800);
  await mark('3-dive');
  const cache = await labelAt('cache');
  if (cache) {
    await p.mouse.move(cache[0], cache[1], { steps: 16 });
    await sleep(300);
    for (let tries = 0; tries < 3 && !(await closeCard.isVisible()); tries++) {  // the hosts drift a little: aim again at where the host is now
      const now = (await labelAt('cache')) || cache;
      await p.mouse.move(now[0], now[1], { steps: 4 });
      await p.mouse.click(now[0], now[1]);
      await sleep(900);
    }
    await cap('Live data, not a picture: why this host is on fire');
    await sleep(2000);
    await mark('3-why-fire');
    if (await closeCard.isVisible()) await click(closeCard, 300);
  }
  const backBtn = p.locator('button').filter({ hasText: /^← All of / }).first();
  if (await backBtn.count()) await click(backBtn, 300);
  await sleep(1500);
  await mark('3-back');

  // 3. Shodan-style search, typed on camera
  await cap('');
  await still(true);
  await smoothScroll(0);
  await click(nav('Hosts'), 700);
  const box = p.locator('input[placeholder^="Search hosts"]');
  await moveTo(box); await sleep(150); await box.click();
  const type = async (q, caption, hold) => {
    await box.fill('');
    await cap(caption);
    await box.pressSequentially(q, { delay: 60 });
    await settle(300);
    await sleep(hold);
  };
  await type('tech:php', '<b>Search</b> your own attack surface like Shodan: <code>tech:php</code>', 800);
  await mark('4-search-1');
  await type('port:3389 -host:vpn', 'Remote Desktop exposed, but not on the VPN: <code>port:3389 -host:vpn</code>', 900);
  await mark('4-search');
  await box.fill(''); await sleep(200);

  // 5. CVEs being detected: a scan runs, the constellation it works on lights up, and the detections land while the camera rolls
  await cap('');
  await still(false);
  arm.go(); await arm.done;  // a scan is now running (its Nuclei stage), and the Sentinels have just checked in
  await go(`${BASE}/cve/graph/?project=${PROJECT}`); await settle(300);
  await smoothScroll(300);
  await p.mouse.move(640, 660, { steps: 6 });
  await cap('A scan is running: the <b>constellation</b> it works on lights up');
  await sleep(3200);
  await mark('5-live-before');
  await cap('The scan matches CVEs to hosts: new detections land');
  detect.go(); await detect.done; await sleep(5400);
  await mark('5-live-arrived');
  await cap('A check reproduces the flaw: <b>smoke</b> (version only) turns to <b>fire</b> (confirmed)');
  confirm.go(); await confirm.done; await sleep(5400);
  await mark('5-live');
  finish.go(); await finish.done;  // the scan finishes
  await still(true);
  await cap('');
  await smoothScroll(0);
  await click(nav('Findings'), 500);
  await click(tab('CVE matches'), 900);
  await cap('Every match shows its heat, the exploited-in-the-wild mark, and the proof');
  const row = p.locator('.host-row').filter({ hasText: 'CVE-2020-1938' }).first();  // the confirmed match: its detail shows the check that reproduced it
  if (await row.count()) {
    await row.scrollIntoViewIfNeeded();
    const rb = await row.boundingBox();
    await p.mouse.move(rb.x + 250, rb.y + rb.height / 2, { steps: 20 }); await sleep(250); await p.mouse.click(rb.x + 250, rb.y + rb.height / 2); await settle(900);
  }
  await sleep(1200);
  await mark('5-matches');

  // 6. The internal network: hosts only a Sentinel inside the network scans, written by the name they go by and their address
  await cap('');
  await click(nav('Internal network'), 900);
  await cap('<b>Internal network</b>: hosts only a Sentinel inside the network scans');
  await sleep(2200);
  await mark('6-internal');
  const findings = p.locator('#in-find-h');
  const fy = (await findings.count()) ? await findings.evaluate((h) => h.getBoundingClientRect().top + window.scrollY - 84) : 330;  // just under the top bar
  await smoothScroll(fy);
  await cap('Internal hosts by the name they go by: <code>build01 (10.30.0.15)</code>');
  await sleep(2600);
  await mark('6-internal-findings');
  await smoothScroll(0);

  // 7. A printer on the internal network: its fingerprint showed one, so it is scanned gently
  await cap('');
  await go(`${BASE}/cve/${PROJECT}/hosts/?internal=1`); await settle(500);
  const hostBox = p.locator('input[placeholder^="Search hosts"]');
  await moveTo(hostBox); await sleep(150); await hostBox.click();
  await hostBox.pressSequentially('port:631', { delay: 60 });
  await settle(400);
  const printer = p.locator('.host-row').filter({ hasText: 'print-hq-2f' }).first();
  if (await printer.count()) {
    const pb = await printer.boundingBox();
    await p.mouse.move(pb.x + 120, pb.y + pb.height / 2, { steps: 18 }); await sleep(250);
    await p.mouse.click(pb.x + 120, pb.y + pb.height / 2); await settle(700);
    await p.mouse.move(pb.x + 120, pb.y + pb.height + 160, { steps: 10 });  // off the row, so the badges read clearly
  }
  await cap('A printer is <b>scanned gently</b>: read-only web checks, nothing sent to its print ports');
  await sleep(2600);
  await mark('7-printer');

  // 8. The Sentinels, then back to the Overview
  await cap('');
  await click(nav('Scanners'), 500);
  await click(tab('Sentinels'), 700);
  await cap('<b>Sentinels</b>: one on the internet, two inside the network');
  await sleep(2600);
  await mark('8-sentinels');
  await cap('');
  await click(nav('Overview'), 900);
  await p.mouse.move(820, 330, { steps: 14 });
  await cap('<b>cvENGINE</b>: self-hosted attack-surface assessment, outside and inside');
  await sleep(1400);
  await mark('9-overview');
  await cap('');

  await sleep(400);
  fs.writeFileSync(`${OUT}/marks.json`, JSON.stringify(marks, null, 1));
  fs.writeFileSync(`${OUT}/cuts.json`, JSON.stringify(dead));
  await ctx.close();
  await browser.close();
  const video = fs.readdirSync(OUT).filter((f) => f.endsWith('.webm')).map((f) => OUT + '/' + f).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  console.log('recorded', video);
})().catch((e) => { console.error(e); process.exit(1); });
