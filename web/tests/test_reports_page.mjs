import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The Reporting page (static/cve/reports.js) against a tiny DOM and a fake server: the scope picker, the two tabs, and what Generate asks for.
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
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; this.listeners = {}; this.checked = false; this.isConnected = true; this.value = ''; this.classList = {add() {}, remove() {}}; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'value') this.value = String(v); if (k.startsWith('data-')) this.dataset[k.slice(5)] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type) { return Promise.all((this.listeners[type] || []).map((fn) => fn({target: this, preventDefault() {}}))); }
  click() { clicks.push(this); }
  remove() {}
  focus() {}
  querySelectorAll(sel) { return sel === 'button' ? find(this, (n) => n.tag === 'button') : []; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
const settle = async () => { for (let i = 0; i < 8; i += 1) await new Promise((resolve) => setImmediate(resolve)); };

const root = new Node('div');
root.setAttribute('id', 'reports-root');
root.dataset.project = 'acme-web';
root.dataset.org = '';
root.dataset.slug = '';
const body = new Node('body');
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createElementNS: (ns, tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: (id) => (id === 'reports-root' ? root : null),
  querySelector: () => null,
  querySelectorAll: () => [],
  cookie: '',
  body,
};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.location = {pathname: '/cve/reports/', search: '?project=acme-web', hash: ''};
globalThis.history = {replaceState: (_, __, url) => {  // a relative '#tab' keeps the path and the query, as a browser does
  url = String(url);
  if (url.startsWith('#')) { location.hash = url; return; }
  const [rest, hash = ''] = url.split('#');
  const [path, query = ''] = rest.split('?');
  Object.assign(location, {pathname: path, search: query ? `?${query}` : '', hash: hash ? `#${hash}` : ''});
}};
globalThis.URL.createObjectURL = () => 'blob:fake';
globalThis.URL.revokeObjectURL = () => {};
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms) => { if (ms >= 60000 || ms === 4000) return 0; return realTimeout(fn, 0); };  // the "taking longer" timers never fire, the 2 s poll does at once

const SCOPES = [
  {kind: 'org', slug: 'acme', name: 'Acme Org', projects: 2, whole: true, can_subscribe: false, can_view_subscriptions: true},
  {kind: 'project', slug: 'acme-web', name: 'Acme Web', org: 'acme', org_name: 'Acme Org', role: 'user'},
  {kind: 'project', slug: 'acme-api', name: 'Acme API', org: 'acme', org_name: 'Acme Org', role: 'user'},
];
const posts = [];
const RECENT = {results: [{id: 'r1', status: 'done', kind: 'hosts', format: 'csv', scope: {kind: 'org', slug: 'acme', name: 'Acme Org'}, host: null, created: '2026-11-21T08:00:00Z',
  download_url: '/api/v1/orgs/acme/reports/r1/download'}]};
const json = (data, status = 202) => ({ok: status < 400, status, json: async () => data});
globalThis.fetch = async (url, opts = {}) => {
  const method = opts.method || 'GET';
  if (url === '/api/v1/reporting/scopes') return json({scopes: SCOPES, me_email: 'a@b.co', mail_ready: false, limits: {}}, 200);
  if (url === '/api/v1/reporting/reports') return json(RECENT, 200);
  if (method === 'POST') {
    posts.push([url, JSON.parse(opts.body)]);
    return json({id: 'r2', status: 'queued', status_url: '/api/v1/orgs/acme/reports/r2'});
  }
  if (url === '/api/v1/orgs/acme/reports/r2') return json({id: 'r2', status: 'done', download_url: '/api/v1/orgs/acme/reports/r2/download', summary: {omitted: {rows: 3}}}, 200);
  return {ok: true, status: 200, blob: async () => new Blob(['x'])};
};

await import('../static/cve/reports.js');
await settle();
const select = () => find(root, (n) => n.tag === 'select')[0];
const button = (text) => find(root, (n) => n.tag === 'button' && n.textContent === text)[0];
const tab = (name) => find(root, (n) => n.attrs['data-tab'] === name)[0];
const toasts = () => find(body, (n) => n.className && n.className.startsWith('toast')).map((t) => t.textContent);

test('the picker has an option group per organization and starts on the project in the address', () => {
  const groups = find(select(), (n) => n.tag === 'optgroup');
  assert.deepEqual(groups.map((g) => g.attrs.label), ['Acme Org']);
  assert.deepEqual(find(groups[0], (n) => n.tag === 'option').map((o) => o.textContent), ['Whole organization (2 projects)', 'Acme Web', 'Acme API']);
  assert.equal(select().value, 'project:acme-web');
  assert.equal(location.search + location.hash, '?project=acme-web#findings');
});

test('the Findings tab offers PDF and CSV, the closed-findings switch and Generate, and lists the recent reports', () => {
  assert.match(root.textContent, /PDF report \(summary, every finding with evidence and remediation\)/);
  assert.match(root.textContent, /CSV spreadsheet \(one row per finding\)/);
  assert.match(root.textContent, /Include closed findings/);
  assert.ok(button('Generate'));
  assert.match(root.textContent, /Hosts report, CSV/);
  assert.match(root.textContent, /Acme Org/);
  assert.ok(button('Download'));
});

test('choosing the organization and the Hosts tab, Generate asks the organization route for a hosts CSV and saves the file', async () => {
  select().value = 'org:acme';
  await select().fire('change');
  assert.equal(location.search, '?org=acme');  // the address follows the choice, so it can be shared
  await tab('hosts').onclick();
  await settle();
  assert.match(root.textContent, /Scope list for a testing company \(no findings\)/);
  const csv = find(root, (n) => n.tag === 'input' && n.attrs.type === 'radio' && n.attrs.value === 'csv')[0];
  find(root, (n) => n.tag === 'input' && n.attrs.type === 'radio' && n.attrs.value === 'pdf').forEach((n) => { n.checked = false; });  // a browser unchecks the rest of the group
  csv.checked = true;
  clicks.length = 0;
  await button('Generate').fire('click');
  await settle();
  assert.deepEqual(posts.at(-1), ['/api/v1/orgs/acme/reports', {include_closed: false, kind: 'hosts', format: 'csv'}]);
  assert.equal(clicks.at(-1).attrs.download, 'cvengine-report-acme-hosts.csv');
  assert.ok(toasts().some((t) => /3 items over the report limit/.test(t)), toasts().join('|'));
});
