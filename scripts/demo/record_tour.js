// Records the 1.4 tour: a scripted walk through a demo instance (scripts/demo/seed_demo.py) as a WebM, which make_gif.sh turns into the README GIF.
// Run it through make_gif.sh (one command, from a fresh seed); on its own:
//   BASE=http://127.0.0.1:8001 OUT=/tmp/tour STAGE='python3 manage.py shell < ../scripts/demo/stage_live.py' STAGE_CWD=web NODE_PATH=$(npm root -g) node scripts/demo/record_tour.js
// Scenes: Overview, the asset graph (hover a hot host), Shodan-style search typed on camera, CVEs arriving while a scan runs (SOC mode, the second seed
// step scripts/demo/stage_live.py writes them through the product's own code while this records), Situations, Sentinels, and back to the Overview.
const { chromium } = require('playwright');
const { exec } = require('child_process');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8001';
const OUT = process.env.OUT || '/tmp/tour';
const PROJECT = process.env.PROJECT || 'acme-corp';
const STAGE = process.env.STAGE || 'python3 manage.py shell < ../scripts/demo/stage_live.py';
const STAGE_CWD = process.env.STAGE_CWD || 'web';
const SHOTS = process.env.SHOTS || '';  // a folder: a PNG at the end of each scene, for checking the tour without playing it
const W = 1280, H = 800;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const overlay = `
(() => {
  const css = document.createElement('style');
  css.textContent = '#__cap{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:2147483647;background:rgba(10,10,11,.92);color:#fff;font:600 15px/1.35 Geist,system-ui,sans-serif;padding:10px 18px;border-radius:999px;box-shadow:0 6px 24px rgba(0,0,0,.28);max-width:86%;text-align:center;pointer-events:none;transition:opacity .25s}#__cap b{color:#ff7a2f}#__cap code{font:600 14px/1.35 "Geist Mono",ui-monospace,monospace;color:#ffd2b8}#__cur{position:fixed;left:0;top:0;width:22px;height:22px;z-index:2147483647;pointer-events:none;transition:transform .02s}#__cur svg{filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}';
  const mount = () => {
    if (!document.getElementById('__cap')) {
      document.head.appendChild(css);
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
  const done = new Promise((resolve, reject) => exec(`PHASE=${phase} GO_FILE=${goFile} ${STAGE}`, { cwd: STAGE_CWD, shell: '/bin/bash' },
    (err, out, errOut) => (err ? reject(new Error(`stage ${phase} failed: ${errOut || out}`)) : resolve(out))));
  done.catch(() => {});
  return { go: () => fs.writeFileSync(goFile, ''), done };
};

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch();
  // sign in once, outside the recording
  const login = await browser.newContext({ viewport: { width: W, height: H } });
  const lp = await login.newPage();
  await lp.goto(BASE + '/login/');
  await lp.fill('#username', 'admin'); await lp.fill('#password', 'demo-Tour-2026');
  await lp.click('button[type=submit]'); await lp.waitForLoadState('networkidle');
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

  // 1. Overview: the counts, and what needs you first
  await go(`${BASE}/cve/?project=${PROJECT}`); await settle(900);
  await p.mouse.move(820, 330, { steps: 14 });
  await cap('<b>Overview</b> of a fictional company: what is exposed, and what to fix first');
  await sleep(1000);
  await p.mouse.move(790, 400, { steps: 14 });
  await sleep(1000);
  await mark('1-overview');

  // 2. The asset graph: every domain, host, address and CVE of the estate; settle, zoom to the hot hosts, open one
  await cap('');
  await click(nav('Hosts'), 500);
  await click(tab('Graph'), 400);
  await cap('The <b>asset graph</b>: every domain, host, address, and the CVEs that hit them');
  await smoothScroll(300);
  await sleep(4000);
  await mark('2-graph');
  const cloud = await p.evaluate(() => {
    const s = [...document.querySelectorAll('svg')].filter((x) => x.querySelectorAll('circle').length > 20)[0];
    const rows = [...s.querySelectorAll('text')].filter((x) => x.textContent === 'acme-example.com').map((t) => t.getBoundingClientRect()).sort((a, b) => b.width - a.width);
    return rows[0] ? [rows[0].x + rows[0].width / 2 + 40, rows[0].y + 45] : [960, 460];
  });
  await wheel(cloud[0], cloud[1], -540, 14, 1200);
  await p.mouse.move(900, 300, { steps: 8 });
  await p.mouse.down(); await p.mouse.move(520, 250, { steps: 16 }); await p.mouse.up();  // pan the hot hosts into the middle
  await sleep(300);
  const cache = await labelAt('cache');
  if (cache) {
    await p.mouse.move(cache[0], cache[1], { steps: 14 });
    await cap('Live data, not a picture: click a hot host to see why it is hot');
    await sleep(600);
    await p.mouse.click(cache[0], cache[1]);
    await sleep(2200);
    await mark('2-graph-hover');
    await click(p.locator('button').filter({ hasText: /^Close$/ }).first(), 300);
  }

  // 3. Shodan-style search, typed on camera
  await cap('');
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
  await mark('3-search-1');
  await type('port:3389 -host:vpn', 'Remote Desktop exposed, but not on the VPN: <code>port:3389 -host:vpn</code>', 900);
  await mark('3-search-2');
  await type('tech:"apache tomcat" sev:high', 'Tomcat hosts with a high finding: <code>tech:"apache tomcat" sev:high</code>', 1200);
  await mark('3-search-3');
  await box.fill(''); await sleep(200);

  // 4. CVEs being detected: a scan is running, SOC mode watches it, and the detections arrive while the camera rolls
  await cap('');
  arm.go(); await arm.done;  // a scan is now running (its Nuclei stage), and the Sentinels have just checked in
  await go(`${BASE}/cve/graph/?project=${PROJECT}`); await settle(1500);
  await click(p.locator('#graph-soc'), 600);
  await cap('<b>SOC mode</b>: a scan is running, the hosts it is checking pulse');
  await sleep(1800);
  await mark('4-soc-before');
  await cap('The scan matches CVEs to hosts: new detections arrive');
  detect.go(); await detect.done; await sleep(3200);
  await mark('4-soc-arrived');
  await cap('A check reproduces the flaw: <b>smoke</b> (version only) turns to <b>fire</b> (confirmed)');
  confirm.go(); await confirm.done; await sleep(5600);
  await mark('4-soc-fire');
  await click(p.locator('#soc-exit'), 500);
  finish.go(); await finish.done;  // the scan finishes
  await cap('');
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
  await mark('4-matches');
  await p.mouse.move(980, 560, { steps: 10 });
  for (let i = 0; i < 12; i++) { await p.mouse.wheel(0, 14); await sleep(40); }
  await sleep(900);
  await mark('4-proof');

  // 5. Situations, then the Sentinels, then back to the Overview
  await cap('');
  await go(`${BASE}/cve/${PROJECT}/situations/`); await settle(900);
  await p.mouse.move(760, 300, { steps: 16 });
  await cap('<b>Situations</b>: what needs you, ranked, one host at a time');
  await sleep(1900);
  await mark('5-situations');
  await cap('');
  await click(nav('Scanners'), 500);
  await click(tab('Sentinels'), 700);
  await cap('<b>Sentinels</b> are the scanners: the built-in one, and your own inside the network');
  await sleep(1200);
  const plan = p.locator('text=Which scanners run').first();
  if (await plan.count()) { await plan.scrollIntoViewIfNeeded(); }
  await sleep(1600);
  await mark('5-sentinels');
  await cap('');
  await click(nav('Overview'), 900);
  await p.mouse.move(820, 330, { steps: 14 });
  await cap('<b>cvENGINE 1.4</b>: self-hosted external attack-surface assessment');
  await sleep(1300);
  await mark('6-overview');
  await cap('');

  await sleep(400);
  fs.writeFileSync(`${OUT}/marks.json`, JSON.stringify(marks, null, 1));
  fs.writeFileSync(`${OUT}/cuts.json`, JSON.stringify(dead));
  await ctx.close();
  await browser.close();
  const video = fs.readdirSync(OUT).filter((f) => f.endsWith('.webm')).map((f) => OUT + '/' + f).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  console.log('recorded', video);
})().catch((e) => { console.error(e); process.exit(1); });
