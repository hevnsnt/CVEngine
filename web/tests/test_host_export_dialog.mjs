import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// "Export all hosts" (static/cve/host-export.js): the page-head button, the dialog's choices and the download, against a tiny DOM and a fake server.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

const clicks = [];
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; this.listeners = {}; this.checked = false; this.isConnected = true; this.value = ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'value') this.value = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type) { (this.listeners[type] || []).forEach((fn) => fn({target: this})); }
  showModal() { this.open = true; }
  close() { if (this.open) { this.open = false; this.fire('close'); } }
  focus() {}
  click() { clicks.push(this); }
  remove() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
const named = (root, text) => find(root, (n) => n.tag === 'button' && n.textContent === text)[0];
const selects = (d) => find(d, (n) => n.tag === 'select');
const settle = () => new Promise((resolve) => setImmediate(resolve));

const body = new Node('body');
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: () => null,
  querySelectorAll: () => [],
  cookie: '',
  body,
};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.location = {search: ''};
globalThis.URL.createObjectURL = () => 'blob:fake';
globalThis.URL.revokeObjectURL = () => {};
const timers = [];
globalThis.setTimeout = (fn, ms) => { if (ms >= 60000) return 0; timers.push(fn); return timers.length; };
globalThis.clearTimeout = () => {};

const calls = [];
let fail = null;
const PROJECTS = [
  {slug: 'web', name: 'Web', org: 'acme', org_name: 'Acme'},
  {slug: 'api', name: 'API', org: 'acme', org_name: 'Acme'},
  {slug: 'x', name: 'X', org: 'zeta', org_name: 'Zeta Corp'},
];
let projects = PROJECTS;
globalThis.fetch = async (url, opts = {}) => {
  calls.push(url);
  if (String(url).startsWith('/api/v1/projects?') || url === '/api/v1/projects') return {ok: true, status: 200, json: async () => ({results: projects})};
  if (fail) return {ok: false, status: 404, json: async () => ({error: fail})};
  const headers = new Map([['Content-Disposition', 'attachment; filename="cvengine-hosts-web-2026-11-14.csv"'], ['X-Export-Hosts', '12'], ['X-Export-Entries', '12']]);
  return {ok: true, status: 200, headers, blob: async () => new Blob(['x'])};
};

const {hostExportButton, openHostExport} = await import('../static/cve/host-export.js');
const dialogOf = () => find(body, (n) => n.tag === 'dialog').at(-1);
const toasts = () => find(body, (n) => n.className && n.className.startsWith('toast')).map((t) => t.textContent);

test('the page-head button says Export all hosts and opens the dialog', () => {
  const b = hostExportButton({slug: 'web'});
  assert.equal(b.textContent, 'Export all hosts');
  assert.match(b.className, /head-action/);
  b.onclick();
  const d = dialogOf();
  assert.equal(d.attrs['aria-label'], 'Export all hosts');
  assert.ok(d.open);
  d.close();
});

test('the project dialog offers the format and the scope with the safe defaults, archived off, and no organization picker', () => {
  openHostExport({slug: 'web'});
  const d = dialogOf();
  const [format, scope] = selects(d);
  assert.equal(selects(d).length, 2);
  assert.deepEqual([format.value, scope.value], ['csv', 'external']);
  assert.match(d.textContent, /Spreadsheet/);
  assert.match(d.textContent, /Plain list for tools/);
  assert.match(d.textContent, /Internet-facing only/);
  assert.match(d.textContent, /Include internal hosts/);
  assert.equal(find(d, (n) => n.tag === 'input' && n.attrs.type === 'checkbox')[0].checked, false);
  assert.match(d.textContent, /No findings, notes, owners or scores/);
  d.close();
});

test('Export downloads from the project route with the choices, saves the file the server named and toasts the count', async () => {
  calls.length = 0;
  clicks.length = 0;
  openHostExport({slug: 'web'});
  const d = dialogOf();
  const [format, scope] = selects(d);
  format.value = 'txt';
  scope.value = 'all';
  find(d, (n) => n.tag === 'input' && n.attrs.type === 'checkbox')[0].checked = true;
  await named(d, 'Export').onclick();
  assert.deepEqual(calls, ['/api/v1/projects/web/hosts/export?format=txt&scope=all&archived=1']);
  assert.equal(clicks.length, 1);
  assert.equal(clicks[0].attrs.download, 'cvengine-hosts-web-2026-11-14.csv');
  assert.ok(toasts().includes('Exported 12 hosts (12 names and addresses)'), toasts().join('|'));
  assert.equal(d.open, false);
});

test('the defaults reach the server as csv, external, archived 0', async () => {
  calls.length = 0;
  openHostExport({slug: 'web'});
  await named(dialogOf(), 'Export').onclick();
  assert.deepEqual(calls, ['/api/v1/projects/web/hosts/export?format=csv&scope=external&archived=0']);
});

test('a refusal stays in the dialog with the server\'s words and nothing is saved', async () => {
  clicks.length = 0;
  fail = 'project not found';
  openHostExport({slug: 'web'});
  const d = dialogOf();
  await named(d, 'Export').onclick();
  fail = null;
  assert.equal(clicks.length, 0);
  assert.match(d.textContent, /project not found/);
  assert.ok(d.open);
  assert.equal(named(d, 'Export').disabled, false);
  d.close();
});

test('in All projects the dialog asks for an organization, lists the ones the person can see, and cannot start before one is chosen', async () => {
  calls.length = 0;
  openHostExport({slug: '_all', all: true});
  const d = dialogOf();
  const [org] = selects(d);
  assert.equal(named(d, 'Export').disabled, true);
  await settle();
  assert.deepEqual(find(org, (n) => n.tag === 'option').map((o) => o.textContent), ['Choose an organization…', 'Acme (2 projects)', 'Zeta Corp (1 project)']);
  assert.equal(org.value, '');
  assert.equal(named(d, 'Export').disabled, true);
  org.value = 'zeta';
  org.onchange();
  assert.equal(named(d, 'Export').disabled, false);
  calls.length = 0;
  await named(d, 'Export').onclick();
  assert.deepEqual(calls, ['/api/v1/orgs/zeta/hosts/export?format=csv&scope=external&archived=0']);
});

test('with a single organization it is chosen already', async () => {
  projects = PROJECTS.slice(0, 2);
  openHostExport({slug: '_all', all: true});
  const d = dialogOf();
  await settle();
  assert.equal(selects(d)[0].value, 'acme');
  assert.equal(named(d, 'Export').disabled, false);
  d.close();
  projects = PROJECTS;
});

test('the Hosts page puts the button in the page head, replacing an older one, and leaves the list\'s own CSV button alone', async () => {
  const {readFileSync} = await import('node:fs');
  const src = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');
  assert.match(src, /import \{ hostExportButton \} from "\/staticfiles\/cve\/host-export\.js"/);
  assert.match(src, /document\.querySelector\("\.page-head"\)/);
  assert.match(src, /pageHead\.append\(hostExportButton\(\{ slug, all: ALL \}\)\)/);
  assert.match(src, /const csv = exportButton\(\{/);  // the list's CSV of the current filter stays
});
