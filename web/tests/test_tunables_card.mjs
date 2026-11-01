import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// Draws the generic tunable cards of Settings, configMaxxing (AI spend, Scan pacing) against a tiny DOM and a fake server.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'hidden') this.hidden = true; }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  remove() {}
  replaceWith() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  scrollIntoView() { this.scrolled = true; }
  get lastChild() { return this.children[this.children.length - 1]; }
  focus() { globalThis.__focused = this.id; }
}
let current = null;  // the host that is drawn now, for getElementById
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: (id) => (current ? find(current, (n) => n.id === id)[0] || null : null),
  activeElement: null,
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
globalThis.setTimeout = () => 0;
globalThis.localStorage = {getItem: () => null, setItem() {}};

const tunable = (over) => ({key: 'triage_max_per_day', label: 'Triage questions per day', help: 'Most AI triage questions asked in a day.', group: 'ai_spend', default: 2000,
  min: 1, max: 50000, unit: 'questions', value: 2000, source: 'default', env_name: 'CVENGINE_TRIAGE_MAX_PER_DAY', env_value: null, saved: null, set_by: null, set_at: null,
  applies: 'live', applies_text: 'Applies within a few seconds, with no restart', ...over});
const snapshot = () => ({
  groups: [{id: 'ai_spend', title: 'AI spend', intro: 'Every call costs money <b>x</b>.'}, {id: 'throughput', title: 'Scan pacing', intro: 'How eagerly scans start.'}],
  fields: [
    tunable(),
    tunable({key: 'validate_max_per_day', label: 'Validation checks per day', default: 1500, value: 300, source: 'admin', saved: 300, set_by: 'alice <i>x</i>', set_at: '2026-10-31T10:00:00Z',
      env_name: 'CVENGINE_VALIDATE_MAX_PER_DAY', max: 20000, unit: 'checks'}),
    tunable({key: 'stage_parallel', label: 'Chunks of one scan stage at once', group: 'throughput', default: 4, value: 6, source: 'environment', env_name: 'CVENGINE_STAGE_PARALLEL', env_value: 6,
      max: 16, unit: 'chunks'}),
    tunable({key: 'work_min_gap_hours', label: 'Hours before rescan', group: 'throughput', default: 2, value: 2, min: 0, max: 168, unit: 'hours', env_name: 'CVENGINE_WORK_MIN_GAP_HOURS', applies: 'restart', applies_text: 'Applies after the next restart'}),
  ],
  cache_seconds: 5,
});

const calls = [];
globalThis.fetch = async (url, opts = {}) => {
  calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
  return {ok: true, status: 200, json: async () => snapshot()};
};

const maxxing = await import('../static/cve/config-maxxing.js');
await import('../static/cve/tunables-card.js');

test('the generic cards register themselves, one per group of the registry, and draw their own title and intro', async () => {
  assert.deepEqual(maxxing.cards().map((c) => c.id), ['ai_spend', 'throughput']);
  assert.deepEqual(maxxing.cards().map((c) => c.title), ['AI spend', 'Scan pacing']);
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  assert.match(host.textContent, /^AI spend/);
  assert.match(host.textContent, /Every call costs money <b>x<\/b>\./);  // text, never markup
  assert.ok(!find(host, (n) => n.tag === 'b').length);
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), ['GET /cve/api/settings/tunables']);
});

test('a card shows only the rows of its own group, with range, default, source, who set it and when it applies', async () => {
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  const inputs = find(host, (n) => n.tag === 'input');
  assert.deepEqual(inputs.map((i) => [i.dataset.key, i.value, i.attrs.min, i.attrs.max]), [['triage_max_per_day', '2000', '1', '50000'], ['validate_max_per_day', '300', '1', '20000']]);
  const text = host.textContent;
  assert.match(text, /Built-in default · allowed 1 to 50000 · Default 2000 · CVENGINE_TRIAGE_MAX_PER_DAY is not set · Applies within a few seconds, with no restart/);
  assert.match(text, /Saved here · allowed 1 to 20000 · Default 1500 · CVENGINE_VALIDATE_MAX_PER_DAY is not set · Set by alice <i>x<\/i> on /);
  assert.ok(!find(host, (n) => n.tag === 'i').length);
  assert.match(text, /questions/);
  const resets = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default');
  assert.deepEqual(resets.map((b) => b.disabled), [true, false]);
});

test('the environment source is named, and a setting read at process start says it applies after a restart', async () => {
  const host = new Node('div');
  await maxxing.cards()[1].build(host);
  const text = host.textContent;
  assert.match(text, /From the environment \(CVENGINE_STAGE_PARALLEL=6\) · allowed 1 to 16 · Default 4/);
  assert.match(text, /Hours before rescan/);
  assert.match(text, /allowed 0 to 168 · Default 2 · CVENGINE_WORK_MIN_GAP_HOURS is not set · Applies after the next restart/);
  assert.doesNotMatch(text, /AI spend/);
});

test('Save sends only what changed, a bad number blocks it, and Reset to default sends null for that key', async () => {
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  assert.equal(save.disabled, true);
  const box = find(host, (n) => n.dataset.key === 'triage_max_per_day')[0];
  box.value = '0';
  box.oninput();
  assert.equal(save.disabled, true);
  const bar = find(host, (n) => n.attrs.role === 'alert')[0];
  assert.equal(bar.hidden, false);
  assert.match(bar.textContent, /Triage questions per day must be from 1 to 50000/);
  box.value = '800';
  box.oninput();
  assert.equal(save.disabled, false);
  assert.equal(bar.hidden, true);
  calls.length = 0;
  await save.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/tunables', method: 'PUT', body: {values: {triage_max_per_day: 800}}});
  calls.length = 0;
  const reset = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default' && !n.disabled)[0];
  await reset.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/tunables', method: 'PUT', body: {values: {validate_max_per_day: null}}});
});

test('the section draws every registered card, the cards share one width, and Reset all stays', async () => {
  const host = new Node('div');
  calls.length = 0;
  await maxxing.buildSection(host);
  assert.match(host.textContent, /^configMaxxing/);
  assert.match(host.textContent, /AI spend/);
  assert.match(host.textContent, /Scan pacing/);
  assert.match(host.textContent, /Reset all configMaxxing settings to defaults/);
  const widths = find(host, (n) => n.className === 'card').map((n) => /max-width:(\d+px)/.exec(n.attrs.style || '')?.[1]);
  assert.equal(new Set(widths).size, 1, String(widths));
});

test('a card that fails to build shows its error line and the others still draw', async () => {
  const host = new Node('div');
  maxxing.registerCard({id: 'ghost', title: 'Ghost', build: async () => { throw new Error('nope'); }});
  await maxxing.buildSection(host);
  assert.match(host.textContent, /nope/);
});

test('the page code and the server registry name the same groups', () => {
  const dir = new URL('../static/cve/', import.meta.url);
  const src = readFileSync(new URL('tunables-card.js', dir), 'utf8');
  assert.deepEqual([...src.matchAll(/registerTunableGroup\("([a-z_]+)", "([^"]+)"\);/g)].map((m) => [m[1], m[2]]), [['ai_spend', 'AI spend'], ['throughput', 'Scan pacing']]);
  assert.match(readFileSync(new URL('settings.js', dir), 'utf8'), /tunables-card\.js/);
});

// --- an environment value the page cannot hold must not lock the card ------------------------------------------------------------------------
const envSnapshot = () => ({
  ...snapshot(),
  fields: [
    tunable({key: 'triage_max_per_day', value: 100000, source: 'environment', env_value: 100000, caution: 'cap'}),  // above the page's maximum of 50000
    tunable({key: 'validate_min_gap_hours', label: 'Hours between validations', default: 12, value: 0.5, source: 'environment', env_name: 'CVENGINE_VALIDATE_MIN_GAP_HOURS',
      env_value: 0.5, min: 0, max: 720, unit: 'hours'}),  // a fraction
    tunable({key: 'validate_max_per_day', label: 'Validation checks per day', default: 1500, value: 1500, max: 20000, env_name: 'CVENGINE_VALIDATE_MAX_PER_DAY', caution: 'cap',
      window_text: 'at the next UTC midnight', used_today: 12, used_since: 'since UTC midnight'}),
    tunable({key: 'stage_parallel', label: 'Chunks', group: 'ai_spend', default: 4, value: 6, source: 'environment', env_name: 'CVENGINE_STAGE_PARALLEL', env_value: 6, max: 16}),
  ],
});
const drawEnv = async () => {
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
    return {ok: true, status: 200, json: async () => envSnapshot()};
  };
  const host = new Node('div');
  current = host;
  await maxxing.cards()[0].build(host);
  return host;
};
const restoreFetch = () => {
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
    return {ok: true, status: 200, json: async () => snapshot()};
  };
};

test('a fractional or out-of-range environment value opens the card without an error and does not block the other boxes', async () => {
  const host = await drawEnv();
  const bar = find(host, (n) => n.attrs.role === 'alert')[0];
  assert.equal(bar.hidden, true, 'the card opened with an error');
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  assert.equal(save.disabled, true);  // nothing changed
  assert.deepEqual(find(host, (n) => n.tag === 'input').map((i) => i.value), ['100000', '0.5', '1500', '6']);
  const other = find(host, (n) => n.dataset.key === 'validate_max_per_day')[0];
  other.value = '1200';
  other.oninput();
  assert.equal(bar.hidden, true);
  assert.equal(save.disabled, false);
  calls.length = 0;
  await save.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/tunables', method: 'PUT', body: {values: {validate_max_per_day: 1200}}});  // the untouched boxes are not sent
  assert.equal(globalThis.__focused, 'tn-validate-max-per-day', 'the focus was lost when the card was drawn again');
  restoreFetch();
});

test('touching the fractional or the out-of-range box validates it, and putting it back clears the error', async () => {
  const host = await drawEnv();
  const bar = find(host, (n) => n.attrs.role === 'alert')[0];
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  const gap = find(host, (n) => n.dataset.key === 'validate_min_gap_hours')[0];
  gap.value = '1.5';
  gap.oninput();
  assert.equal(bar.hidden, false);
  assert.equal(save.disabled, true);
  assert.match(bar.textContent, /must be a whole number from 0 to 720/);
  gap.value = '0.5';
  gap.oninput();
  assert.equal(bar.hidden, true);
  const big = find(host, (n) => n.dataset.key === 'triage_max_per_day')[0];
  big.value = '60000';
  big.oninput();
  assert.match(bar.textContent, /Triage questions per day must be from 1 to 50000/);
  big.value = '40000';
  big.oninput();
  assert.equal(bar.hidden, true);
  assert.equal(save.disabled, false);
  restoreFetch();
});

test('a value from the environment that fits the range can be pinned here, one that does not fit cannot', async () => {
  const host = await drawEnv();
  const pins = find(host, (n) => n.tag === 'button' && n.textContent === 'Save this value');
  assert.equal(pins.length, 1);  // only stage_parallel=6: not 100000 (too big) and not 0.5 (not whole)
  assert.match(pins[0].attrs['aria-label'], /Save the current value of Chunks here/);
  calls.length = 0;
  await pins[0].onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/tunables', method: 'PUT', body: {values: {stage_parallel: 6}}});
  assert.equal(globalThis.__focused, 'tn-stage-parallel');
  restoreFetch();
});

test('soft warnings advise but never block: far below, far above, and a gap of zero', async () => {
  const host = await drawEnv();
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  const warningOf = (key) => find(host, (n) => n.dataset.key === key)[0];
  const warnings = () => find(host, (n) => n.attrs.role === 'status' && n.className === 'msg err');
  assert.ok(warnings().every((w) => w.hidden), 'a warning showed for an untouched card');
  const cap = warningOf('validate_max_per_day');
  cap.value = '100';  // under a quarter of 1500
  cap.oninput();
  assert.equal(save.disabled, false);
  let shown = warnings().filter((w) => !w.hidden).map((w) => w.textContent);
  assert.equal(shown.length, 1);
  assert.match(shown[0], /far below the default \(1500\): work over the cap is deferred and tried again at the next UTC midnight/);
  cap.value = '1400';
  cap.oninput();
  assert.equal(warnings().filter((w) => !w.hidden).length, 0);
  cap.value = '16000';  // above ten times the default
  cap.oninput();
  shown = warnings().filter((w) => !w.hidden).map((w) => w.textContent);
  assert.match(shown[0], /more than ten times the default \(1500\): it raises spend above the documented default/);
  assert.equal(save.disabled, false);
  restoreFetch();
});

test('the warning rules are pure and cover the environment reference and the conductor gap', async () => {
  const L = await import('../static/cve/config-maxxing-logic.js');
  const cap = {min: 1, max: 50000, default: 2000, env_value: null, caution: 'cap', window_text: 'at the next run'};
  assert.equal(L.softWarning(cap, '499') !== '', true);
  assert.equal(L.softWarning(cap, '500'), '');
  assert.equal(L.softWarning(cap, '20000'), '');
  assert.match(L.softWarning(cap, '20001'), /ten times the default \(2000\)/);
  assert.match(L.softWarning({...cap, env_value: 300}, '3001'), /ten times the environment value \(300\)/);
  assert.equal(L.softWarning({...cap, caution: null}, '1'), '');
  assert.equal(L.softWarning(cap, 'x'), '');
  assert.equal(L.softWarning(cap, '99999'), '');  // out of range is the error line's business
  const gap = {min: 0, max: 168, default: 2, caution: 'rescan'};
  assert.match(L.softWarning(gap, '0'), /continuous/);
  assert.equal(L.softWarning(gap, '1'), '');
  assert.equal(L.usageText({used_today: 12, used_since: 'since UTC midnight'}), 'Used since UTC midnight: 12');
  assert.equal(L.usageText({used_today: null, used_since: 'x'}), '');
});

test('the daily caps show what was used, and every Reset button has its own accessible name', async () => {
  const host = await drawEnv();
  assert.match(host.textContent, /Applies within a few seconds, with no restart · Used since UTC midnight: 12/);
  const resets = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default');
  const names = resets.map((b) => b.attrs['aria-label']);
  assert.equal(new Set(names).size, names.length);
  assert.match(names[0], /^Reset Triage questions per day to default$/);
  restoreFetch();
});
