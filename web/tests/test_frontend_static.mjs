import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import {mock, test} from 'node:test';

// Regression checks for the Thermal UI modules that need no browser: source-level guards against the two crashes a review found
// (a local `history` shadowing window.history, an unimported prefs.js formatter) and the day bucketing of charts.js.
const dir = new URL('../static/cve/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');
const modules = readdirSync(dir).filter((f) => f.endsWith('.js') && !f.endsWith('.min.js'));

test('no module declares a binding that shadows window.history or window.location', () => {
  for (const name of modules) {
    const bad = read(name).match(/\b(?:const|let|var)\s+(?:history|location)\b/);
    assert.equal(bad, null, `${name} declares ${bad && bad[0]}`);
  }
});

test('a module that calls a prefs.js formatter imports or defines it', () => {
  for (const name of modules.filter((f) => f !== 'prefs.js')) {
    const src = read(name);
    const imported = new Set();
    for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*["'][^"']*\/prefs\.js["']/g)) {
      m[1].split(',').forEach((n) => imported.add(n.trim()));
    }
    for (const fn of ['fmtDateTime', 'fmtDay', 'fmtTime', 'zoneLabel', 'tzMode']) {
      const own = new RegExp(`(?:const|let|function)\\s+${fn}\\b`).test(src);
      if (new RegExp(`\\b${fn}\\(`).test(src)) assert.ok(imported.has(fn) || own, `${name} uses ${fn} without importing it`);
    }
  }
});

// charts.js takes the display-zone preference from prefs.js, which reads the DOM; hand it a stand-in.
let zone = 'local';
globalThis.__tzMode = () => zone;
const charts = await import(`data:text/javascript,${encodeURIComponent(
  read('charts.js').replace(/import \{ tzMode \} from "[^"]+";/, 'const tzMode = () => globalThis.__tzMode();'),
)}`);

const withClock = (iso, fn) => {
  mock.timers.enable({apis: ['Date'], now: new Date(iso)});
  try { return fn(); } finally { mock.timers.reset(); }
};

// One event at 12:00 local time on each of the last `n` calendar days.
const everyDay = (n) => {
  const now = new Date();
  return Array.from({length: n}, (_, i) => new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 12).toISOString());
};

test('dailyCounts finds every day across a daylight-saving change', () => {
  // TZ is read when the first Date is built, so set it before the clock is mocked.
  for (const tz of ['America/New_York', 'Europe/Berlin', 'Australia/Sydney', 'UTC']) {
    process.env.TZ = tz;
    // 2026-11-10 is after the US change (11-01) and the European one (10-25); Sydney changes on 2026-10-04.
    withClock('2026-11-10T15:00:00Z', () => {
      const points = charts.dailyCounts(everyDay(45), 45);
      assert.equal(points.length, 45);
      assert.deepEqual(points.map((p) => p.v), Array(45).fill(1), tz);
      const days = points.map((p) => new Date(p.t).getDate());
      assert.equal(new Set(points.map((p) => p.t)).size, 45, `${tz}: every key is a distinct day`);
      assert.ok(days.every((d, i) => i === 0 || d === (days[i - 1] % 31) + 1 || d === 1), `${tz}: consecutive days`);
    });
  }
});

test('dailyCounts follows the UTC display preference', () => {
  process.env.TZ = 'America/New_York';
  zone = 'utc';
  try {
    // 02:30 UTC on the 10th is still the 9th in New York; the UTC view must count it on the 10th.
    withClock('2026-11-10T12:00:00Z', () => {
      const points = charts.dailyCounts(['2026-11-10T02:30:00Z'], 3);
      assert.deepEqual(points.map((p) => p.v), [0, 0, 1]);
      assert.equal(new Date(points[2].t).getDate(), 10);
    });
  } finally {
    zone = 'local';
  }
});

test('request bodies and links the review found wrong stay fixed', () => {
  const app = read('app.js');
  assert.doesNotMatch(app, /note:\s*(?:d\.remediation|\(detail)/, 'a status change must not resend a stored note');
  assert.doesNotMatch(app, /\/scans\/#/, 'a scan is at /scans/<id>/, the list page ignores the hash');
  assert.match(app, /hosts\/\$\{h\.id\}\/screenshot\/\?size=thumb/, 'the gallery asks for thumbnails');
  assert.doesNotMatch(app, /page \* 30\b/, 'Load more counts with the page size the request used');
});

test('a poller does not keep running in a hidden tab', () => {
  assert.match(read('dashboard.js'), /const every = [\s\S]*?document\.hidden/);
  const graphPage = readFileSync(new URL('../cveFeed/templates/cveFeed/graph.html', import.meta.url), 'utf8');
  assert.match(graphPage, /params\.set\('v', version\)/, 'the graph page sends the version so an unchanged graph answers 304');
  assert.doesNotMatch(graphPage, /setInterval\(poll,/);
});

test('a count or a badge asks for the count alone, and an export or a palette preview asks for no facets', () => {
  const app = read('app.js');
  assert.match(app, /peek: async \(\) => \(await api\("GET", `\$\{path\}\?\$\{query\(\{ \.\.\.params\(\), page: 1, page_size: 0 \}\)\}`\)\)\.count/, 'the list peek is a count-only request');
  assert.doesNotMatch(app, /page_size: 1 \}\)\}`\)\)\.(?:count|total)/, 'a filter chip counter must not fetch a row for its count');
  assert.doesNotMatch(app, /page_size: 1 \}\)\}`\)\.then\(\(r\) => r\.count\)/, 'the tile counters must not fetch a row for their count');
  assert.match(app, /search\?\$\{query\(\{ q: q\.value, sort: sortBy\.value, facets: "none", page, page_size: size \}\)\}/, 'the hosts CSV export skips the heat facets');
  assert.match(read('palette-search.js'), /page_size=6&facets=none/, 'the palette preview skips the heat facets');
  // the dashboard coverage line reads the heat facets, so it keeps them
  assert.match(read('dashboard.js'), /search\?q=&page_size=1`/);
});

class SentinelElement {
  constructor(tag, cls = '', text = '') {
    this.tag = tag;
    this.cls = cls;
    this.text = text == null ? '' : String(text);
    this.children = [];
  }
  append(...children) { this.children.push(...children); }
}

const sentinelEl = (tag, cls, text) => new SentinelElement(tag, cls, text);
const sentinelText = (node) => typeof node === 'string' ? node : [node.text, ...node.children.map(sentinelText)].join(' ');
globalThis.localStorage = {getItem: () => null};
globalThis.document = {createTextNode: (text) => new SentinelElement('#text', '', text), getElementById: () => null};
globalThis.__sentinelUi = {el: sentinelEl, badge: (text) => sentinelEl('span', 'badge', text)};
const sentinelSource = read('sentinel-live.js');
const sentinelModule = sentinelSource.replace(/^import .*;\n/gm, '');
const {task, recent, openvasQueue} = await import(`data:text/javascript,${encodeURIComponent(
  `const {el, badge} = globalThis.__sentinelUi;\n${sentinelModule}\nexport {task, recent, openvasQueue};`,
)}`);

test('current and recent Sentinel tasks prefer the server label for multi-host work', () => {
  const item = {kind: 'openvas', status: 'running', host: '', label: 'a.example.test, b.example.test', project: 'north'};
  assert.match(sentinelText(task(item)), /a\.example\.test, b\.example\.test/);
  assert.match(sentinelText(recent(item)), /a\.example\.test, b\.example\.test/);
  assert.match(sentinelText(task({...item, label: '', host: 'fallback.example.test'})), /fallback\.example\.test/);
});

test('Sentinel page renders OpenVAS running, due and deferred hosts with reasons', () => {
  const panel = openvasQueue({
    running: {project: 'north', hosts: ['a.example.test', 'b.example.test'], via: 'sentinel', progress: 40, budget_hours: 3},
    next: [{host: 'next.example.test', project: 'south', heat: 'fire'}],
    not_due: [{host: 'later.example.test', project: 'north', reason: 'scanned yesterday'}],
    counts: {next: 2, not_due: 1},
  });
  const content = sentinelText(panel);
  for (const expected of ['OpenVAS queue', 'Scanning north', 'a.example.test', '40%', 'next.example.test',
    'fire', 'later.example.test', 'scanned yesterday', 'Showing 1 of 2 due hosts']) {
    assert.ok(content.includes(expected), expected);
  }
  assert.equal(panel.tag, 'section');
  assert.match(sentinelSource, /if \(data\.openvas\) mount\.append\(openvasQueue\(data\.openvas\)\)/);
});

test('Sentinel page shows the OpenVAS idle state without a deferred list', () => {
  const panel = openvasQueue({running: null, next: [], not_due: [], counts: {next: 0, not_due: 0}});
  const content = sentinelText(panel);
  assert.match(content, /No OpenVAS scan is running/);
  assert.match(content, /No hosts are due/);
  assert.equal(panel.children.some((child) => child.cls === 'sl-openvas-deferred'), false);
});
