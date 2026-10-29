// Records the 1.3 tour: a scripted walk through a demo instance (scripts/demo/seed_demo.py) as a WebM, which make_gif.sh turns into the README GIF.
// Usage: BASE=http://127.0.0.1:8001 OUT=/tmp/tour NODE_PATH=$(npm root -g) node scripts/demo/record_tour.js
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8001';
const OUT = process.env.OUT || '/tmp/tour';
const W = 1280, H = 759;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const overlay = `
(() => {
  const css = document.createElement('style');
  css.textContent = '#__cap{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:2147483647;background:rgba(10,10,11,.92);color:#fff;font:600 15px/1.35 Geist,system-ui,sans-serif;padding:10px 18px;border-radius:999px;box-shadow:0 6px 24px rgba(0,0,0,.28);max-width:86%;text-align:center;pointer-events:none;transition:opacity .25s}#__cap b{color:#ff7a2f}#__cur{position:fixed;left:0;top:0;width:22px;height:22px;z-index:2147483647;pointer-events:none;transition:transform .02s}#__cur svg{filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}';
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

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
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
  const cap = async (html) => { await p.evaluate((h) => window.__cap && window.__cap(h), html); };
  const settle = async (ms = 900) => { await p.waitForLoadState('networkidle').catch(() => {}); await sleep(ms); };
  const moveTo = async (loc, steps = 24) => {
    await loc.scrollIntoViewIfNeeded();
    const box = await loc.boundingBox();
    await p.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps });
    return box;
  };
  const click = async (loc, wait = 900) => { await moveTo(loc); await sleep(250); await loc.click(); await settle(wait); };
  const scrollBy = async (dy, ms = 1400) => {
    const steps = 28; for (let i = 0; i < steps; i++) { await p.mouse.wheel(0, dy / steps); await sleep(ms / steps); }
  };
  const nav = (name) => p.locator('nav a, aside a, .sidebar a').filter({ hasText: new RegExp('^\\s*' + name + '\\s*$') }).first();

  // 1. Live
  await p.goto(BASE + '/cve/', { waitUntil: 'domcontentloaded' }); await sleep(1500);
  await p.mouse.move(700, 300, { steps: 10 });
  await cap('<b>Live</b>: every host, how far it has been scanned, and what is exposed');
  await sleep(1800);
  await scrollBy(330, 1100); await cap('Hosts inside <b>private networks</b> have their own tile');
  await sleep(1500);
  await scrollBy(-330, 600);

  // 2. Hosts, internal scope
  await cap('');
  await click(nav('Hosts'), 700);
  await cap('Filter to <b>Internal</b> hosts: a Sentinel inside the network scans them, this server never does');
  await click(p.locator('button').filter({ hasText: /^Internal$/ }).first(), 900);
  await sleep(600);
  const row = p.locator('[class*=row], li, .host-row').filter({ hasText: '10.30.0.4' }).first();
  if (await row.count()) { await click(row, 900); }
  await sleep(1500);

  // 3. Project Sentinels
  await cap('');
  await click(nav('Project Sentinels'), 800);
  await cap('Each project lists its <b>Sentinels</b>, what they are running and what is queued');
  await sleep(1200);
  await scrollBy(420, 1100); await sleep(1100);

  // 4. Sentinels page and the provision form
  await cap('');
  await p.goto(BASE + '/cve/sentinels/', { waitUntil: 'domcontentloaded' }); await sleep(1200);
  await cap('Internal networks, the Sentinel inside each, and when it last looked');
  await sleep(1700);
  await scrollBy(900, 1100);
  await cap('<b>Provision</b> a Sentinel for an organization you manage, chosen from a list');
  const scope = p.locator('#enroll-scope');
  await moveTo(scope, 16); await sleep(200);
  await scope.selectOption('org'); await sleep(900);
  const orgSelect = p.locator('#enroll-org');
  await moveTo(orgSelect, 16); await sleep(200); await orgSelect.selectOption('acme-labs'); await sleep(600);
  const where = p.locator('#enroll-network');
  await moveTo(where, 16); await sleep(200); await where.selectOption('internal');
  await sleep(1300);

  // 5. Settings
  await cap('');
  await p.goto(BASE + '/cve/settings/', { waitUntil: 'domcontentloaded' }); await sleep(1100);
  await cap('<b>Settings</b>: thirteen tabs, grouped, with room to read them');
  await sleep(1700);
  const tab = (name) => p.locator('[role=tab], button.btn').filter({ hasText: new RegExp('^\\s*' + name + '\\s*$') }).first();
  await click(tab('Scan policy'), 600); await sleep(500);
  await click(tab('Notifications'), 600); await sleep(400);
  await click(tab('Email'), 900);
  await cap('New: <b>Email</b>. People you add get a link to set their own password');
  await sleep(2600);
  await cap('');

  await sleep(500);
  await ctx.close();
  await browser.close();
  const video = fs.readdirSync(OUT).filter((f) => f.endsWith('.webm')).map((f) => OUT + '/' + f).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  console.log('recorded', video);
})();
