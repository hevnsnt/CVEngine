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
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: () => null,
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
    tunable({key: 'work_min_gap_hours', label: 'Hours before rescan', group: 'throughput', default: 2, value: 2, min: 0, max: 168, unit: 'hours', env_name: 'CVENGINE_WORK_MIN_GAP_HOURS', applies: 'restart'}),
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
  const bar = find(host, (n) => n.tag === 'p' && n.className === 'msg err')[0];
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
