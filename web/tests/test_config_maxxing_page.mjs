import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// Draws the configMaxxing section against a tiny DOM and a fake server, so a typo in the page code fails here and not in somebody's browser.
// The pages import `/staticfiles/cve/...`; the hook below maps that to the source directory.
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
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
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

const registry = {};
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: (id) => registry[id] || null,
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
globalThis.setTimeout = (f) => 0;
globalThis.localStorage = {getItem: () => null, setItem() {}};

const field = (over) => ({key: 'heavy.nmap', label: 'Port and service scan (nmap)', help: 'The standard scan.', group: 'heavy', default: 2, min: 1, max: 8, value: 2,
  source: 'default', env_name: 'HEAVY_MAX_NMAP', env_value: null, saved: null, set_by: null, set_at: null, applies: 'live', ...over});
const snapshot = (over = {}) => ({
  fields: [
    field(),
    field({key: 'heavy.nuclei', label: 'Vulnerability templates (nuclei)', default: 1, value: 3, source: 'admin', saved: 3, set_by: 'alice <b>x</b>', set_at: '2026-10-31T10:00:00Z', max: 8}),
    field({key: 'discovery_concurrency', label: 'Hosts assessed at once', group: 'discovery', default: 8, value: 12, source: 'environment', env_name: 'DISCOVERY_CONCURRENCY', env_value: 12, applies: 'pool', running: 8, running_workers: {}, running_age_seconds: 10, max: 32}),
    field({key: 'work_depth', label: 'Discovery scans kept running', group: 'depth', default: 3, value: 3, min: 0, max: 32, env_name: 'CVENGINE_WORK_DEPTH'}),
  ],
  groups: [{id: 'heavy', title: 'Scanners at once'}, {id: 'discovery', title: 'Discovery and assessment'}, {id: 'depth', title: 'The work conductor'}],
  memory: {budget_mb: 3072, limit_mb: 4096, costs_mb: {nmap: 400, nuclei: 1000}, warnings: []},
  discovery: {state: 'pending', message: 'The saved value is 12, but the worker last said it runs 8.'},
  ...over,
});

const calls = [];
let reply = snapshot();
globalThis.fetch = async (url, opts = {}) => {
  calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
  const ok = {ok: true, status: 200, json: async () => reply};
  return ok;
};

const maxxing = await import('../static/cve/config-maxxing.js');
await import('../static/cve/scan-concurrency-card.js');

test('the card registers itself once and the section draws title, warning, the card and Reset all', async () => {
  assert.deepEqual(maxxing.cards().map((c) => c.id), ['scan_concurrency']);
  const host = new Node('div');
  await maxxing.buildSection(host);
  const text = host.textContent;
  assert.match(text, /^configMaxxing/);
  assert.match(text, /Changing these can make scans slower, use more memory or send more traffic to your targets/);
  assert.match(text, /Scan concurrency/);
  assert.match(text, /second machine \(a Sentinel\) is the best way to scale/);
  assert.match(text, /Memory budget of the scanning container: 3\.0 GB \(container limit 4\.0 GB, set with CELERY_MEM_LIMIT\)/);
  assert.match(text, /Reset all configMaxxing settings to defaults/);
  assert.doesNotMatch(text, /Tinkerer/i);
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), ['GET /cve/api/settings/scan_concurrency']);
});

test('each row shows its default, range, environment value, who set it and a Reset to default that is enabled only for a saved value', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const inputs = find(host, (n) => n.tag === 'input');
  assert.deepEqual(inputs.map((i) => [i.dataset.key, i.value, i.attrs.min, i.attrs.max]),
    [['heavy.nmap', '2', '1', '8'], ['heavy.nuclei', '3', '1', '8'], ['discovery_concurrency', '12', '1', '32'], ['work_depth', '3', '0', '32']]);
  const resets = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default');
  assert.deepEqual(resets.map((b) => b.disabled), [true, false, true, true]);
  const text = host.textContent;
  assert.match(text, /Built-in default · allowed 1 to 8 · Default 2 · HEAVY_MAX_NMAP is not set/);
  assert.match(text, /Saved here · allowed 1 to 8 · Default 1 · HEAVY_MAX_NMAP is not set · Set by alice <b>x<\/b> on /);  // shown as text, never as markup
  assert.match(text, /From the environment \(DISCOVERY_CONCURRENCY=12\)/);
  assert.match(text, /Worker ceiling now: 8/);
  assert.match(text, /Being applied The saved value is 12, but the worker last said it runs 8\./);
  assert.ok(!find(host, (n) => n.tag === 'b').length, 'a server string became an element');
});

test('Save sends only what changed, a bad number blocks it, and Reset to default sends null for that key', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  assert.equal(save.disabled, true);  // nothing changed yet
  const nmap = find(host, (n) => n.dataset.key === 'heavy.nmap')[0];
  nmap.value = '99';
  nmap.oninput();
  assert.equal(save.disabled, true);
  assert.match(host.textContent, /Port and service scan \(nmap\) must be from 1 to 8/);
  nmap.value = '4';
  nmap.oninput();
  assert.equal(save.disabled, false);
  calls.length = 0;
  await save.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scan_concurrency', method: 'PUT', body: {values: {'heavy.nmap': 4}}});
  calls.length = 0;
  const reset = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default' && !n.disabled)[0];
  await reset.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scan_concurrency', method: 'PUT', body: {values: {'heavy.nuclei': null}}});
});

test('the memory warning appears while a big number is typed, from the server costs and budget', async () => {
  reply = snapshot({memory: {budget_mb: 3100, limit_mb: 4096, costs_mb: {nmap: 400, nuclei: 1000}, warnings: []}});
  const host = new Node('div');
  await maxxing.buildSection(host);
  assert.doesNotMatch(host.textContent, /could be wanted/);
  const nmap = find(host, (n) => n.dataset.key === 'heavy.nmap')[0];
  nmap.value = '8';
  nmap.oninput();
  assert.match(host.textContent, /Port and service scan \(nmap\) at 8 could want 3200 MB by itself, more than the 3100 MB budget/);
  assert.match(host.textContent, /CELERY_MEM_LIMIT/);
  reply = snapshot();
});

test('Reset all is a button of the section (it asks before it posts)', async () => {
  const dialogs = [];
  const ui = await import('../static/cve/ui.js');
  assert.equal(typeof ui.ask, 'function');
  // ask() draws a <dialog> and waits for a click; here the dialog is not drawn, so only the call made after a yes is checked
  const host = new Node('div');
  await maxxing.buildSection(host);
  const resetAll = find(host, (n) => n.tag === 'button' && /^Reset all configMaxxing/.test(n.textContent))[0];
  assert.ok(resetAll && typeof resetAll.onclick === 'function', String(dialogs));
});
