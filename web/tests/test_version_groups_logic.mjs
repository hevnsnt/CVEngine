import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// Many CVEs, one fix: the words of a group by product and version (version-groups-logic.js), the host page's card that draws one collapsed row per
// group and opens it to the CVEs (version-groups.js), and the Findings page's use of both (app.js, finding-groups-logic.js).
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.open = false; this.listeners = {}; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type) { (this.listeners[type] || []).forEach((fn) => fn({type, target: this})); }
  removeAttribute(k) { delete this.attrs[k]; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
globalThis.localStorage = {getItem: () => null, setItem() {}};
const calls = [];
let answer = {results: []};
globalThis.fetch = async (url, opts = {}) => {
  calls.push(`${opts.method || 'GET'} ${url}`);
  return {ok: true, status: 200, json: async () => answer};
};

const VG = await import('../static/cve/version-groups-logic.js');
const FG = await import('../static/cve/finding-groups-logic.js');
const {versionGroupsCard} = await import('../static/cve/version-groups.js');

const NAMES = ['economicprinciples.org', 'www.economicprinciples.org'];
const member = (id, cve, host, extra = {}) => ({kind: 'match', id, cve, host, heat: 'ice', severity: 'high', status: 'open', remediation_status: 'open',
  classification: 'needs_validation', validation_status: 'none', fixed: '1.31.9', ...extra});
const nginxMembers = [];
for (let i = 0; i < 18; i += 1) NAMES.forEach((host, n) => [0, 1].forEach((copy) => nginxMembers.push(member(1000 + i * 4 + n * 2 + copy, `CVE-2026-${100 + i}`, host))));
const groupRow = (members, extra = {}) => ({
  type: 'cve', kind: 'match', id: members[0].id, title: members[0].cve, host: members[0].host, project: 'principles', heat: 'ice', severity: 'high',
  group: {by: 'product', id: 'vabc', product: 'nginx', version: '1.31.1', host_names: NAMES, hosts: 2, cves: 18, findings: members.length, heat: 'ice',
    severity: 'high', triage: {needs_validation: 71, likely: 0, confirmed: 1, other: 0}, fix_text: 'upgrade to 1.31.9',
    fixed_in: {version: '1.31.9', also: [], stated: 18, unstated: [], held_by: []}, registrable_domain: 'economicprinciples.org',
    note: 'These rest on the version read (nginx 1.31.1), not on a check of each flaw: none of them is confirmed on the host.',
    member_ids: members.map((m) => m.id), members, members_truncated: false, status_counts: {open: members.length}, heat_counts: {ice: members.length},
    member_status: Object.fromEntries(members.map((m) => [String(m.id), m.remediation_status])), ruled_out_ids: [], ...extra},
});
const single = {type: 'cve', kind: 'match', id: 7, title: 'CVE-2026-42530', host: 'economicprinciples.org', note: 'nginx 1.31.1', heat: 'fire', severity: 'high'};
const elsewhere = {type: 'cve', kind: 'match', id: 8, title: 'CVE-2026-1', host: 'stage.economicprinciples.org', note: 'nginx 1.18.0', heat: 'ice', severity: 'low'};

test('the collapsed row names the product, the version, the CVEs, the fix and the names', () => {
  const row = groupRow(nginxMembers);
  assert.equal(VG.groupTitle(row.group), 'nginx 1.31.1: 18 CVEs (72 findings), upgrade to 1.31.9, on economicprinciples.org and www.economicprinciples.org');
  assert.equal(VG.groupTitle({...row.group, findings: 18, fix_text: '', host_names: ['a', 'b', 'c'], hosts: 4}),
    'nginx 1.31.1: 18 CVEs, no fixed version stated, on a, b and c and 1 more');
  assert.equal(VG.triageText(row.group), '71 need validation · 1 confirmed');
  assert.equal(VG.triageText({triage: {needs_validation: 1, likely: 4}}), '4 likely · 1 needs validation');
});

test('only a group by product is a version group, and a host keeps only its own names', () => {
  const row = groupRow(nginxMembers);
  assert.equal(VG.isVersionGroup(row), true);
  assert.equal(VG.isVersionGroup({...row, group: {...row.group, by: undefined}}), false);
  assert.equal(VG.isVersionGroup(single), false);
  const {groups, singles} = VG.forHost([row, single, elsewhere, {type: 'hygiene', host: NAMES[0]}], NAMES);
  assert.deepEqual([groups.length, singles.map((s) => s.id)], [1, [7]]);
  assert.equal(VG.countLine(groups, singles), '73 CVE matches in 2 rows: 1 group by product and version, 1 on its own');
});

test('members sort hottest first, then by CVE, and each opens its own finding', () => {
  const g = {members: [member(1, 'CVE-2', 'b'), member(2, 'CVE-1', 'a', {heat: 'smoke'}), member(3, 'CVE-1', 'b')]};
  assert.deepEqual(VG.sortedMembers(g).map((m) => m.id), [2, 3, 1]);
  assert.equal(VG.memberHref('my project', 12), '/cve/my%20project/matches/#12');
  assert.equal(VG.memberText(member(1, 'CVE-1', 'a')), 'CVE-1 on a · fixed in 1.31.9');
});

async function draw(rows) {
  calls.length = 0;
  answer = {results: rows};
  const card = versionGroupsCard({base: '/api/v1/projects/principles', project: 'principles', host: NAMES[0], names: NAMES});
  await new Promise((r) => setImmediate(r));
  return card;
}

test('the host card asks for the grouped CVE matches and draws one collapsed row per group', async () => {
  const card = await draw([groupRow(nginxMembers), single, elsewhere]);
  assert.deepEqual(calls, ['GET /api/v1/projects/principles/findings?type=cve&group=product&host=economicprinciples.org&page_size=200']);
  const rows = find(card, (n) => n.tag === 'details');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].open, false, 'collapsed until opened');
  assert.match(find(rows[0], (n) => n.tag === 'summary')[0].textContent, /nginx 1\.31\.1: 18 CVEs \(72 findings\), upgrade to 1\.31\.9, on economicprinciples\.org and www\.economicprinciples\.org/);
  assert.equal(find(rows[0], (n) => n.tag === 'li').length, 0, 'the members are drawn on the first open');
  assert.match(card.textContent, /73 CVE matches in 2 rows/);
  // the single match stays its own row with its own link; the sibling host's match is not this host's
  const links = find(card, (n) => n.tag === 'a');
  assert.deepEqual(links.map((a) => a.attrs.href), ['/cve/principles/matches/#7']);
  assert.doesNotMatch(card.textContent, /stage\.economicprinciples\.org/);
});

test('opening a group draws every CVE beneath it, each a link to its own finding, with the plain note', async () => {
  const card = await draw([groupRow(nginxMembers)]);
  const row = find(card, (n) => n.tag === 'details')[0];
  row.open = true;
  row.dispatch('toggle');
  row.dispatch('toggle'); // a second toggle draws nothing twice
  const items = find(row, (n) => n.tag === 'li');
  assert.equal(items.length, 72);
  const hrefs = find(row, (n) => n.tag === 'a').map((a) => a.attrs.href);
  assert.equal(new Set(hrefs).size, 72);
  assert.ok(hrefs.every((h) => /^\/cve\/principles\/matches\/#\d+$/.test(h)));
  assert.match(row.textContent, /These rest on the version read \(nginx 1\.31\.1\), not on a check of each flaw: none of them is confirmed on the host\./);
  assert.match(row.textContent, /Triage: 71 need validation · 1 confirmed/);
});

test('a host with nothing grouped says so, and a failure says it could not load', async () => {
  const card = await draw([]);
  assert.match(card.textContent, /No open CVE matches on this host\./);
  globalThis.fetch = async () => ({ok: false, status: 500, json: async () => ({error: 'boom'})});
  const failed = versionGroupsCard({base: '/b', project: 'p', host: 'h', names: ['h']});
  await new Promise((r) => setImmediate(r));
  assert.match(failed.textContent, /could not be loaded: boom/);
});

test('the Findings page groups by product by default and keeps the other modes', () => {
  assert.deepEqual(FG.listParams({type: 'all'}, FG.BY_PRODUCT), {type: 'all', group: 'product'});
  assert.deepEqual(FG.listParams({type: 'all'}, 'nonsense'), {type: 'all', group: 'product'});
  assert.deepEqual(FG.listParams({type: 'all'}, FG.GROUPED), {type: 'all', group: 'cve'});
  assert.deepEqual(FG.listParams({type: 'all'}, FG.EVERY_HOST), {type: 'all'});
  const row = groupRow(nginxMembers.slice(0, 4));
  assert.equal(FG.hostsText(row.group), '18 CVEs in 4 findings on economicprinciples.org and www.economicprinciples.org');
  assert.match(FG.menuLabel(row, 'accepted_risk', 'accepted risk'), /\(4 findings\)$/);
  assert.match(FG.confirmText([row], 'accepted_risk'), /^Mark 4 findings in 1 group as accepted risk\. Each finding keeps its own history\.$/);
  // a group by product sends each member through the per-finding route, as a group of hosts does
  assert.deepEqual(FG.expandForBulk([row]).map((m) => m.id), row.group.member_ids);
  const header = FG.headerParts({group: 'product', total: 15, findings_total: 93, counts: {cve: 80}, groups: 2, grouped_findings: 80});
  assert.match(header.lead, /^93 findings in 15 distinct issues: $/);  // grouped by product, each row is a distinct issue (the numbers stay the server's)
  assert.equal(header.note, FG.ISSUES_NOTE);
  assert.match(FG.headerParts({group: 'product', total: 1, findings_total: 2140}).lead, /^2,140 findings in 1 distinct issue: $/);
  assert.equal(FG.headerParts({group: 'cve', total: 5, findings_total: 15}).note, undefined);  // the other groupings keep their own words
  assert.match(header.grouped, /80 CVE matches shown as 2 rows, one per product version on a host/);
  const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');
  assert.match(app, /import \{ versionGroupsCard \} from "\/staticfiles\/cve\/version-groups\.js"/);
  assert.match(app, /group: FG\.BY_PRODUCT \}/, 'product grouping is the default of the saved views and the URL');
  assert.match(app, /VG\.isVersionGroup\(f\) \? VG\.groupTitle\(f\.group\)/, 'a group row is titled by its product version');
  assert.match(app, /exportParams: filtersNow/, 'the CSV stays one line per finding');
});
