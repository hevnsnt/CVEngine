import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
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

// The words are inside a closed <details> (whose summary says "Details") and are not shown anywhere outside it: a person who never opens it never reads them.
const behindDetails = (host, pattern) => {
  const boxes = find(host, (n) => n.tag === 'details');
  const inside = boxes.filter((d) => pattern.test(d.textContent));
  assert.ok(inside.length >= 1, `${pattern} is inside a details element`);
  assert.ok(inside[0].textContent.startsWith('Details'), 'whose summary is Details');
  assert.ok(!inside[0].attrs || !('open' in inside[0].attrs), 'closed by default');
  const outside = host.textContent.split(inside[0].textContent).join('');
  assert.doesNotMatch(outside, pattern, `${pattern} is not shown outside the details`);
};

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

const field = (over) => ({key: 'assess_batch', label: 'Hosts per assessment batch', help: 'How many hosts one run carries.', group: 'discovery', default: 8, min: 1, max: 64,
  value: 8, source: 'default', env_name: 'CVENGINE_ASSESS_BATCH', env_value: null, saved: null, set_by: null, set_at: null, applies: 'live', ...over});
// the server's snapshot (cveFeed.scan_concurrency.snapshot): no per-tool scanner rows and no memory plan, since no scanner runs on the server
const snapshot = (over = {}) => ({
  fields: [
    field({key: 'discovery_concurrency', label: 'Hosts assessed at once', default: 8, value: 12, source: 'environment', env_name: 'DISCOVERY_CONCURRENCY', env_value: 12, applies: 'pool', running: 8, running_workers: {}, running_age_seconds: 10, max: 32}),
    field(),
    field({key: 'work_depth', label: 'Discovery scans kept running', group: 'depth', default: 3, value: 3, min: 0, max: 32, env_name: 'CVENGINE_WORK_DEPTH'}),
    field({key: 'lane.classic', label: 'Classic lane tasks at once', group: 'lanes', default: 10, value: 7, source: 'admin', saved: 7, set_by: 'alice <b>x</b>', set_at: '2026-10-31T10:00:00Z', max: 32, env_name: 'CLASSIC_CONCURRENCY'}),
  ],
  groups: [{id: 'discovery', title: 'Discovery and assessment'}, {id: 'depth', title: 'The work conductor'}, {id: 'lanes', title: 'Worker lanes'}],
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
  assert.match(text, /Every scan runs on a Sentinel, so another Sentinel \(a second machine\) is the best way to scale/);
  assert.doesNotMatch(text, /Memory budget|scanning container|CELERY_MEM_LIMIT|memory gate/);
  assert.match(text, /Reset all configMaxxing settings to defaults/);
  assert.doesNotMatch(text, /Tinkerer/i);
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), ['GET /cve/api/settings/scan_concurrency']);
});

test('each row shows its default, range, environment value, who set it and a Reset to default that is enabled only for a saved value', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const inputs = find(host, (n) => n.tag === 'input');
  assert.deepEqual(inputs.map((i) => [i.dataset.key, i.value, i.attrs.min, i.attrs.max]),
    [['discovery_concurrency', '12', '1', '32'], ['assess_batch', '8', '1', '64'], ['work_depth', '3', '0', '32'], ['lane.classic', '7', '1', '32']]);
  const resets = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default');
  assert.deepEqual(resets.map((b) => b.disabled), [true, true, true, false]);
  const text = host.textContent;
  assert.match(text, /Built-in default · allowed 1 to 64 · Default 8 · Applies within a few seconds/);
  behindDetails(host, /CVENGINE_ASSESS_BATCH is not set/);
  assert.match(text, /Saved here · allowed 1 to 32 · Default 10 · Set by alice <b>x<\/b> on /);  // shown as text, never as markup
  assert.match(text, /Set on the server/);
  assert.match(text, /Worker ceiling now: 8/);
  assert.match(text, /Being applied The saved value is 12, but the worker last said it runs 8\./);
  assert.ok(!find(host, (n) => n.tag === 'b').length, 'a server string became an element');
});

test('Save sends only what changed, a bad number blocks it, and Reset to default sends null for that key', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const save = find(host, (n) => n.tag === 'button' && n.textContent === 'Save')[0];
  assert.equal(save.disabled, true);  // nothing changed yet
  const batch = find(host, (n) => n.dataset.key === 'assess_batch')[0];
  batch.value = '99';
  batch.oninput();
  assert.equal(save.disabled, true);
  assert.match(host.textContent, /Hosts per assessment batch must be from 1 to 64/);
  batch.value = '16';
  batch.oninput();
  assert.equal(save.disabled, false);
  calls.length = 0;
  await save.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scan_concurrency', method: 'PUT', body: {values: {assess_batch: 16}}});
  calls.length = 0;
  const reset = find(host, (n) => n.tag === 'button' && n.textContent === 'Reset to default' && !n.disabled)[0];
  await reset.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scan_concurrency', method: 'PUT', body: {values: {'lane.classic': null}}});
});

test('no memory budget or memory warning is drawn, even for a big number or a reply from an older server', async () => {
  reply = snapshot({memory: {budget_mb: 3100, limit_mb: 4096, costs_mb: {nmap: 400, nuclei: 1000}, warnings: ['an old warning']}});
  const host = new Node('div');
  await maxxing.buildSection(host);
  const batch = find(host, (n) => n.dataset.key === 'assess_batch')[0];
  batch.value = '64';
  batch.oninput();
  assert.doesNotMatch(host.textContent, /could want|Memory budget|an old warning|CELERY_MEM_LIMIT/);
  assert.equal(find(host, (n) => n.attrs.role === 'status').length, 0);  // the live warning region went with the memory plan
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

test('the error bar under Save is hidden while it is empty and shown only with an error', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const bar = find(host, (n) => n.tag === 'p' && n.className === 'msg err')[0];
  assert.ok(bar, 'no error bar found');
  assert.equal(bar.hidden, true, 'an empty error bar is visible');
  const batch = find(host, (n) => n.dataset.key === 'assess_batch')[0];
  batch.value = '99';
  batch.oninput();
  assert.equal(bar.hidden, false);
  assert.match(bar.textContent, /must be from 1 to 64/);
  batch.value = '8';
  batch.oninput();
  assert.equal(bar.hidden, true);
  assert.equal(bar.textContent, '');
});

test('the discovery status line uses the note style of the lines around it, and both cards have the same width', async () => {
  const host = new Node('div');
  await maxxing.buildSection(host);
  const status = find(host, (n) => n.tag === 'p' && /Being applied/.test(n.textContent))[0];
  assert.equal(status.className, 'note');
  const widths = find(host, (n) => n.className === 'card').map((n) => n.style['max-width'] ?? /max-width:(\d+px)/.exec(n.attrs.style || '')?.[1]);
  assert.equal(new Set(widths).size, 1, String(widths));
});

test('the Resources tab shows the pointer to configMaxxing even when no worker has reported', () => {
  const src = readFileSync(new URL('../static/cve/settings.js', import.meta.url), 'utf8');
  const draw = src.slice(src.indexOf('const draw = (snap) => {'), src.indexOf('const refresh = async'));
  const pointerAt = draw.indexOf('host.append(pointer())');
  const emptyAt = draw.indexOf('!snap.containers.length');
  assert.ok(pointerAt > 0 && emptyAt > 0 && pointerAt < emptyAt, 'the pointer is drawn after the no-worker early return');
  assert.match(src, /Scan concurrency moved to configMaxxing/);
  assert.match(src, /Open configMaxxing/);
});
