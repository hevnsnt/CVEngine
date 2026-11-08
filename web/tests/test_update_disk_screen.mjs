import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The Updates card of Settings when the host says there is not enough disk for the update: the sentence in plain words, and Approve update off with that
// reason on it. Drawn from the real static/cve/settings.js against a tiny DOM and a fake server, so a typo fails here and not in somebody's browser.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; this.classList = {add() {}, remove() {}, toggle() {}}; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'title') this.title = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  addEventListener() {}
  querySelectorAll() { return []; }
  querySelector(sel) { return sel.includes('csrf') ? {value: 'csrf-token'} : this.children.find((c) => c.id === sel.slice(1)) || null; }
  remove() {}
  replaceWith() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  get firstChild() { return this.children[0]; }
  get lastChild() { return this.children[this.children.length - 1]; }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };

const view = new Node('div'); view.id = 'view';
const settings = new Node('div');
settings.children.push(view);
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: (id) => (id === 'settings' ? settings : null),
  querySelector: () => null,
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
globalThis.window = {localStorage: {getItem: () => null, setItem() {}}, addEventListener() {}, location: {replace() {}}};
globalThis.localStorage = window.localStorage;
globalThis.location = {hash: '#updates'};
globalThis.history = {replaceState() {}};
globalThis.setTimeout = () => 0;
globalThis.clearTimeout = () => {};

const SENTENCE = 'This update needs about 14 GB of free disk; this server has 9 GB free. Free some space or add disk, then try again.';
const state = (disk) => ({
  status: 'available', enabled: true, repo: 'hevnsnt/CVEngine', branch: 'master', branch_warning: '', has_token: false, installed: 'f45f097', installed_known: true,
  local_commits: 0, common: '', host_comparison: '', latest: '5bce4e3', latest_message: 'The next version', latest_url: '', behind_by: 3, commits: [],
  last_checked_at: '2026-11-08T10:00:00Z', last_error: '', approved_by: '', approved_at: null, phase: 'idle', phase_detail: '', phase_scans_running: null,
  host_updater: {seen: true, alive: true, age_seconds: 4}, certificate: null, mode: 'manual', scanner_choice: {needs_choice: false}, scanner_notice: null, disk,
});
let reply = null;
const calls = [];
globalThis.fetch = async (url, opts = {}) => {
  calls.push({url, method: opts.method});
  return {ok: true, status: 200, json: async () => (url.endsWith('/updates') ? reply : {})};
};

const draw = async (disk) => {
  reply = state(disk);
  view.children = [];
  await import(`../static/cve/settings.js?${Math.random()}`);
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  return view;
};
const approve = (v) => find(v, (n) => n.tag === 'button' && n.textContent === 'Approve update')[0];

test('not enough disk: the sentence is shown and Approve update is off with the reason on it', async () => {
  const v = await draw({known: true, short: true, free_mb: 9500, need_mb: 14000, text: SENTENCE});
  assert.ok(v.textContent.includes(SENTENCE), v.textContent.slice(0, 400));
  const shown = find(v, (n) => n.id === 'update-disk-short');
  assert.equal(shown.length, 1);
  assert.equal(shown[0].textContent, SENTENCE);
  const b = approve(v);
  assert.ok(b, 'the button is still drawn, so it is clear what is missing');
  assert.equal(b.disabled, true);
  assert.equal(b.title, SENTENCE);
  assert.equal(b.attrs['aria-describedby'], 'update-disk-short');
});

test('enough disk, or no measurement yet: no sentence and Approve update is on', async () => {
  for (const disk of [{known: true, short: false, free_mb: 20000, need_mb: 14000, text: ''}, {known: false, short: false, free_mb: null, need_mb: null, text: ''}, undefined]) {
    const v = await draw(disk);
    assert.ok(!v.textContent.includes('free disk'), v.textContent.slice(0, 300));
    assert.equal(find(v, (n) => n.id === 'update-disk-short').length, 0);
    assert.equal(approve(v).disabled, false);
  }
});

test('the sentence has no long dash', () => {
  assert.doesNotMatch(SENTENCE, /[\u2013\u2014]/);
});
