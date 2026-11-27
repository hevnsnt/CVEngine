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
  showModal() { this.open = true; }
  close() { this.open = false; }
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
  {kind: 'project', slug: 'acme-web', name: 'Acme Web', org: 'acme', org_name: 'Acme Org', role: 'user', can_subscribe: true},
  {kind: 'project', slug: 'acme-api', name: 'Acme API', org: 'acme', org_name: 'Acme Org', role: 'user', can_subscribe: true},
];
const posts = [];
const patches = [];
const zeroWire = [];
const THREATS = [
  {source: 'zero_wire', title: 'nginx2root: update <b>now</b>', summary: 'Prioritize patching.', link: 'https://radar.cloudflare.com/zero-wire/nginx2root', badges: ['Cloudflare Zero Wire', 'CISA KEV'],
    cve_ids: ['CVE-2026-1'], impact_line: '3 of your hosts match by version', impact: 'matched'},
  {source: 'kev', title: 'CVE-2026-2: x', summary: '', link: 'javascript:alert(1)', badges: [], cve_ids: [], impact_line: 'No host in Acme Web is known to run x.', impact: 'none'},
];
const SUB = {id: 7, name: 'Weekly report: Acme Web', scope: {kind: 'project', slug: 'acme-web', name: 'Acme Web'}, recipients: ['a@b.co', 'c@d.co', 'e@f.co'], opted_out: [], cadence: 'weekly',
  weekday: 0, day_of_month: 1, send_time: '08:00', timezone: 'Europe/London', attach: 'pdf', enabled: true, schedule: 'Weekly, Mondays 08:00 (Europe/London)',
  next_run_at: '2026-11-23T08:00:00Z', last_sent_at: '2026-11-17T08:00:00Z', last_status: 'partial', last_error: '1 of 3 failed: the mail server refused the recipient address', can_manage: true};
const RECENT = {results: [{id: 'r1', status: 'done', kind: 'hosts', format: 'csv', scope: {kind: 'org', slug: 'acme', name: 'Acme Org'}, host: null, created: '2026-11-21T08:00:00Z',
  download_url: '/api/v1/orgs/acme/reports/r1/download'}]};
const json = (data, status = 202) => ({ok: status < 400, status, json: async () => data});
globalThis.fetch = async (url, opts = {}) => {
  const method = opts.method || 'GET';
  if (url === '/api/v1/reporting/scopes') return json({scopes: SCOPES, me_email: 'a@b.co', mail_ready: false, limits: {}}, 200);
  if (url === '/api/v1/reporting/reports') return json(RECENT, 200);
  if (String(url).startsWith('/api/v1/reporting/threats')) return json({items: THREATS, note: 'Briefings from Cloudflare Radar Zero Wire (radar.cloudflare.com/zero-wire); summaries quoted from the feed; host counts from cvENGINE\'s own scans.'}, 200);
  if (url === '/api/v1/reporting/zero-wire' && method === 'PUT') { zeroWire.push(JSON.parse(opts.body)); return json({enabled: JSON.parse(opts.body).enabled}, 200); }
  if (url === '/api/v1/reporting/zero-wire') return json({enabled: true, synced_at: '2026-11-21T06:00:00Z', error: '', briefings: 3}, 200);
  if (String(url).startsWith('/api/v1/report-subscriptions?')) return json({results: [SUB], limits: {attach_max_mb: 10}, mail_ready: false, can_create: true}, 200);
  if (method === 'PATCH' || (method === 'POST' && url === '/api/v1/report-subscriptions')) {
    (method === 'PATCH' ? patches : posts).push([url, JSON.parse(opts.body)]);
    return json({...SUB, next_run_at: '2026-11-23T08:00:00Z'}, 201);
  }
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

test('the Email tab says when mail is not set up, lists the cards with their words, and offers New email report', async () => {
  await tab('email').onclick();
  await settle();
  assert.match(root.textContent, /Outgoing mail is not set up/);
  assert.match(root.textContent, /Ask an App Admin to set it up/);
  assert.match(root.textContent, /Weekly report: Acme Web/);
  assert.match(root.textContent, /Weekly, Mondays 08:00 \(Europe\/London\)/);
  assert.match(root.textContent, /To a@b\.co, c@d\.co \+1/);
  assert.match(root.textContent, /PDF attached/);
  assert.match(root.textContent, /1 of 3 failed: the mail server refused the recipient address/);
  assert.ok(button('Edit') && button('Pause') && button('Delete'));
  assert.equal(button('Send test to me').disabled, true);
  assert.ok(button('New email report'));
  assert.equal(select().value, 'org:acme');
});

test('New email report opens the dialog with the default name, and Save sends the choices', async () => {
  select().value = 'project:acme-web';
  await select().fire('change');
  await settle();
  button('New email report').listeners.click[0]();
  const dlg = find(body, (n) => n.tag === 'dialog').at(-1);
  assert.match(dlg.textContent, /New email report/);
  assert.match(dlg.textContent, /Add me/);
  assert.match(dlg.textContent, /Attachments over 10 MB are replaced by a note/);
  const name = find(dlg, (n) => n.tag === 'input' && n.attrs.maxlength === '80')[0];
  assert.equal(name.value, 'Weekly report: Acme Web');
  const area = find(dlg, (n) => n.tag === 'textarea')[0];
  area.value = 'Dana@Example.org, nope';
  await area.fire('input');
  assert.match(dlg.textContent, /nope \(not an address\)/);
  assert.match(dlg.textContent, /1 of 10/);
  await find(dlg, (n) => n.tag === 'button' && n.textContent === 'Save')[0].onclick();
  await settle();
  const [url, payload] = posts.at(-1);
  assert.equal(url, '/api/v1/report-subscriptions');
  assert.equal(payload.project, 'acme-web');
  assert.deepEqual(payload.recipients, ['dana@example.org']);
  assert.deepEqual([payload.cadence, payload.weekday, payload.send_time, payload.attach], ['weekly', 0, '08:00', 'none']);
});

test('the Email tab starts with this week\'s vulnerabilities as text, a link only for an http address, and the footnote', async () => {
  select().value = 'project:acme-web';
  await select().fire('change');
  await tab('email').onclick();
  await settle();
  assert.match(root.textContent, /This week's most important vulnerabilities for Acme Web/);
  assert.match(root.textContent, /nginx2root: update <b>now<\/b>/);  // set as text: the markup is shown, never run
  assert.match(root.textContent, /3 of your hosts match by version/);
  assert.match(root.textContent, /Cloudflare Radar Zero Wire/);
  const links = find(root, (n) => n.tag === 'a' && n.className === 'report-threat-title');
  assert.equal(links.length, 1);
  assert.equal(links[0].attrs.href, 'https://radar.cloudflare.com/zero-wire/nginx2root');
  assert.equal(links[0].attrs.rel, 'noopener noreferrer');
});

test('an App Admin sees the Zero Wire switch and a change is sent as a PUT', async () => {
  root.dataset.superuser = '1';
  await tab('email').onclick();
  await settle();
  const box = find(root, (n) => n.tag === 'input' && n.attrs.id === 'zero-wire-on')[0];
  assert.ok(box);
  assert.equal(box.checked, true);
  assert.match(root.textContent, /3 briefings kept/);
  box.checked = false;
  await box.fire('change');
  await settle();
  assert.deepEqual(zeroWire, [{enabled: false}]);
  root.dataset.superuser = '';
});
