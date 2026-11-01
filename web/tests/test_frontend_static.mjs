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
  constructor(tag, cls = '', text = '', attrs = {}) {
    this.tag = tag;
    this.cls = cls;
    this.text = text == null ? '' : String(text);
    this.attrs = attrs;
    this.children = [];
    this.hidden = false;
    this.value = '';
    this.listeners = {};
    this.classes = new Set();
    this.classList = {toggle: (name, on) => (on ? this.classes.add(name) : this.classes.delete(name))};
  }
  append(...children) { this.children.push(...children); }
  get textContent() { return this.text; }
  set textContent(value) { this.text = String(value); }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  setAttribute(name, value) { this.attrs = {...this.attrs, [name]: value}; }
  removeAttribute(name) { const {[name]: _gone, ...rest} = this.attrs; this.attrs = rest; }
}

const sentinelEl = (tag, cls, text, attrs) => new SentinelElement(tag, cls, text, attrs);
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

const settingsSource = read('sentinel-settings.js').replace(/^import[\s\S]*?from "[^"]*";\n/gm, '');
globalThis.__sentinelUi.button = (label, _fn, cls) => sentinelEl('button', cls, label);
globalThis.__sentinelUi.text = (value = '', attrs = {}) => Object.assign(sentinelEl('input', '', null, attrs), {value});
const {versionBlock, kindState, kindNote, kindChips, kindsChange, modesOffered, canReset, capProblem, defaultHint, kindsPanel} = await import(`data:text/javascript,${encodeURIComponent(
  `const {el, badge, button, text} = globalThis.__sentinelUi;\n${settingsSource}`,
)}`);
const buttonLabels = (node) => (node.tag === 'button' ? [node.text] : []).concat(...node.children.filter((c) => typeof c !== 'string').map(buttonLabels));

test('a Sentinel card has Update now, the built-in scanner does not and says why', () => {
  const detail = {id: 7, name: 'CVEngine Scanner', version: 'abc1234', update: {requested_at: null}, settings: {}};
  const external = versionBlock(detail, {onChange() {}});
  assert.deepEqual(buttonLabels(external), ['Update now', 'Settings']);
  const builtin = versionBlock(detail, {onChange() {}, builtin: true});
  assert.deepEqual(buttonLabels(builtin), ['Settings']);
  assert.match(sentinelText(builtin), /never updates itself/);
  assert.doesNotMatch(sentinelText(external), /never updates itself/);
});

test('the Built-in chip is drawn from the live row flag, and only for the built-in scanner', () => {
  assert.match(sentinelSource, /if \(s\.builtin\) state\.append\(" ", el\("span", "chip sl-builtin", "Built-in"/);
  assert.match(sentinelSource, /versionBlock\(detail, \{ onChange: reload, builtin: s\.builtin \}\)/);
});

// --- the capability policy of a Sentinel (GET agents/{id} `kinds`, PATCH settings.kinds) ---------------------------------------------------------
const kindInfo = (changes = {}) => ({declared: true, effective: true, mode: 'allow', source: 'default', cap: null, held: 0, by: null, at: null, retry_at: null, state: 'on', note: '', ...changes});
const policyKinds = {
  nmap: kindInfo(),
  openvas: kindInfo({mode: 'deny', source: 'agent', by: 'alice', state: 'denied', effective: false}),
  nuclei_light: kindInfo({state: 'cool_off', source: 'cool-off', effective: false, retry_at: '2026-10-31T12:30:00Z'}),
  wpscan: kindInfo({declared: false, effective: false, state: 'unavailable'}),
  testssl: kindInfo({mode: 'deny', source: 'machine', declared: true, effective: false, state: 'machine_off'}),
  naabu: kindInfo({mode: 'prefer', cap: 2}),
};

test('a kind says what it is on this Sentinel, in words that name the cause', () => {
  assert.equal(kindState(policyKinds.nmap), 'on');
  assert.equal(kindState(policyKinds.openvas), 'denied');
  assert.match(kindNote(policyKinds.openvas), /Denied by alice/);
  assert.match(kindNote(policyKinds.wpscan), /Not available on this Sentinel \(tool missing or off on the machine\)/);
  assert.match(kindNote(policyKinds.testssl), /Turned off on the machine/);
  assert.match(kindNote(policyKinds.nuclei_light), /Withheld after repeated failures until/);
  assert.match(kindNote(policyKinds.naabu), /Preferred.*at most 2 at once/);
  assert.match(kindNote({...policyKinds.openvas, source: 'instance default', by: 'root'}), /Denied by the instance default \(set by root\)/);
  // an older server without `state` is read from the other fields
  assert.equal(kindState({declared: true, mode: 'allow', source: 'cool-off'}), 'cool_off');
  assert.equal(kindState({declared: false, mode: 'allow', source: 'default'}), 'unavailable');
  assert.equal(kindState({declared: true, mode: 'deny', source: 'machine'}), 'machine_off');
});

test('the panel offers Allow, Deny and Prefer only for what the Sentinel declares and its machine left on', () => {
  assert.deepEqual(modesOffered(policyKinds.nmap), ['allow', 'deny', 'prefer']);
  assert.deepEqual(modesOffered(policyKinds.openvas), ['allow', 'deny', 'prefer']);
  assert.deepEqual(modesOffered(policyKinds.wpscan), []);
  assert.deepEqual(modesOffered(policyKinds.testssl), []);
  assert.equal(canReset(policyKinds.openvas), true);
  assert.equal(canReset(policyKinds.nmap), false);
});

test('only a kind that changed is sent, a reset sends null, and a bad cap is refused before anything is sent', () => {
  assert.deepEqual(kindsChange(policyKinds, {nmap: {mode: 'allow', cap: ''}, openvas: {mode: 'deny', cap: ''}}), {});
  assert.deepEqual(kindsChange(policyKinds, {openvas: {mode: 'allow', cap: ''}}), {openvas: {mode: 'allow', max_concurrent: null}});
  assert.deepEqual(kindsChange(policyKinds, {nmap: {mode: 'prefer', cap: '3'}}), {nmap: {mode: 'prefer', max_concurrent: 3}});
  assert.deepEqual(kindsChange(policyKinds, {naabu: {mode: 'prefer', cap: ''}}), {naabu: {mode: 'prefer', max_concurrent: null}});
  assert.deepEqual(kindsChange(policyKinds, {openvas: {reset: true}, nmap: {reset: true}}), {openvas: null});
  assert.deepEqual(kindsChange(policyKinds, {wpscan: {mode: 'allow', cap: ''}, testssl: {mode: 'allow', cap: ''}}), {});
  for (const cap of ['0', '11', '2.5', 'abc']) assert.throws(() => kindsChange(policyKinds, {nmap: {mode: 'allow', cap}}), /whole number from 1 to 10/);
});

test('a card shows a chip per kind in three styles, with who or what decided in the tooltip, and none for a kind it does not have', () => {
  const chips = kindChips(policyKinds);
  const byText = Object.fromEntries(chips.children.map((c) => [c.text, c]));
  assert.equal(byText['nmap'].cls, 'chip kind-on');
  assert.equal(byText['OpenVAS (denied)'].cls, 'chip kind-denied');
  assert.match(byText['OpenVAS (denied)'].attrs.title, /Denied by alice/);
  assert.equal(byText['nuclei (light) (withheld)'].cls, 'chip kind-held');
  assert.match(byText['nuclei (light) (withheld)'].attrs.title, /Withheld after repeated failures until/);
  // turned off on the machine is its own style (hatched, dashed, "off on machine"), not the denied one, and says so in words as well
  assert.equal(byText['testssl (off on machine)'].cls, 'chip kind-locked');
  assert.match(byText['testssl (off on machine)'].attrs.title, /Turned off on the machine/);
  assert.notEqual(byText['testssl (off on machine)'].cls, byText['OpenVAS (denied)'].cls);
  assert.ok(byText['naabu (preferred) x2'], 'preferred and capped kinds say so');
  assert.equal(byText['WPScan'], undefined);
  assert.equal(kindChips({wpscan: policyKinds.wpscan}), null);
  assert.equal(kindChips(undefined), null);
});

test('the capability policy is drawn with textContent only', () => {
  for (const name of ['sentinel-settings.js', 'sentinel-live.js', 'scannerbar.js']) {
    assert.doesNotMatch(read(name), /innerHTML|insertAdjacentHTML|outerHTML/, `${name} sets server text with textContent only`);
  }
  assert.match(settingsSource, /settings: \{ kinds: \{ \[kind\]: null \} \}/, 'Use default removes the Sentinel\'s own policy of a kind');
  assert.match(sentinelSource, /kindChips\(detail\.kinds\)/);
  assert.match(read('scannerbar.js'), /disabled_message/);
});

// --- the settings panel: a cap that cannot be saved says why under its field, and the instance default is explained -----------------------------
const walk = (node, found = []) => { found.push(node); (node.children || []).forEach((c) => typeof c !== 'string' && walk(c, found)); return found; };

test('a cap that is not a whole number from 1 to 10 has a sentence of its own, and empty means no limit', () => {
  assert.equal(capProblem(''), '');
  assert.equal(capProblem('  '), '');
  for (const ok of ['1', '3', '10']) assert.equal(capProblem(ok), '');
  for (const bad of ['0', '11', '2.5', '-1', 'abc', '1e1']) assert.match(capProblem(bad), /whole number from 1 to 10, or empty for no limit/);
});

test('the panel marks an invalid cap inline with an alert, tells Save, and clears when it is fixed', () => {
  {
    const validity = [];
    const panel = kindsPanel({nmap: kindInfo()}, async () => {}, (ok) => validity.push(ok));
    assert.equal(validity.at(-1), true, 'a panel that opens clean can be saved');
    const row = walk(panel.node).find((n) => n.cls === 'ss-pol-row');
    const cap = row.children.find((c) => c.tag === 'input');
    const err = row.children.find((c) => c.cls && c.cls.includes('ss-pol-err'));
    assert.equal(err.attrs.role, 'alert');
    assert.equal(err.attrs['aria-live'], 'assertive');
    assert.equal(err.hidden, true);
    cap.value = '99';
    cap.listeners.input();
    assert.match(err.text, /whole number from 1 to 10/);
    assert.equal(err.hidden, false);
    assert.equal(cap.attrs['aria-invalid'], 'true');
    assert.ok(cap.classes.has('invalid'));
    assert.equal(validity.at(-1), false, 'Save is told to stay disabled');
    assert.equal(panel.invalid(), true);
    cap.value = '3';
    cap.listeners.input();
    assert.equal(err.hidden, true);
    assert.equal(cap.attrs['aria-invalid'], undefined);
    assert.equal(validity.at(-1), true);
    assert.equal(panel.invalid(), false);
    cap.validity = {badInput: true};  // letters typed into a number field read as empty, which is not "no limit"
    cap.value = '';
    cap.listeners.input();
    assert.equal(panel.invalid(), true);
  }
});

test('a kind denied by the instance default gets a one-line hint that Allow overrides it for this Sentinel only', () => {
  const builtin = {openvas: kindInfo({mode: 'deny', source: 'instance default', by: 'root', state: 'denied', effective: false}), nmap: kindInfo()};
  assert.match(defaultHint(builtin), /^OpenVAS is denied here by the instance default\. Choosing Allow overrides that default for this Sentinel only\.$/);
  assert.equal(defaultHint({openvas: kindInfo({mode: 'deny', source: 'agent', state: 'denied'})}), '');
  assert.equal(defaultHint({openvas: kindInfo({mode: 'deny', source: 'machine', state: 'machine_off'})}), '');
  assert.equal(defaultHint({openvas: kindInfo({mode: 'deny', source: 'instance default', declared: false, state: 'denied'})}), '', 'nothing to override for a kind the Sentinel does not have');
  assert.match(defaultHint({openvas: builtin.openvas, wpscan: kindInfo({mode: 'deny', source: 'instance default', state: 'denied'})}), /^OpenVAS, WPScan are denied here/);
});

test('the rows keep a stable grid: every row reserves its columns and the note and error take their own lines', () => {
  const css = readFileSync(new URL('../static/cve/cve.css', import.meta.url), 'utf8');
  // the tracks fit any container: fluid (fr) tracks, and the fixed ones add up to well under the narrowest dialog, so the row never overflows it
  const grid = css.match(/\.ss-pol-row\{display:grid;grid-template-columns:([^;]+);/)[1];
  assert.match(grid, /minmax\(0,1\.3fr\)/);
  assert.match(grid, /fr\)/);
  const fixed = [...grid.replace(/minmax\(0,[^)]*\)/g, '').matchAll(/(\d+)px/g)].map((m) => Number(m[1]));
  assert.ok(fixed.reduce((a, b) => a + b, 0) + 3 * 10 <= 360, `fixed tracks ${fixed} plus gaps must stay far under a 530px container`);
  assert.match(css, /\.ss-pol-row\{[^}]*min-width:0;box-sizing:border-box\}/);
  assert.match(css, /\.ss-pol-row>\*\{min-width:0;box-sizing:border-box\}/);
  assert.match(css, /\.ss-pol\{[^}]*min-width:0;max-width:100%\}/);
  assert.match(css, /\.ss-pol-note\{grid-column:1\/-1/);
  assert.match(css, /\.ss-pol-row \[hidden\]\{display:block;visibility:hidden\}/, 'a control a row does not offer keeps its column');
  assert.match(css, /\.chip\.kind-locked\{[^}]*dashed/);
  assert.match(css, /\.chip\.kind-denied\{[^}]*var\(--fire-ink\)/);
  assert.match(settingsSource, /role: "alert"/);
});
