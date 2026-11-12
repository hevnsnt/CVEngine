import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The Situations row and its opened detail, drawn against a tiny DOM: one row per host with its counts, the narrative and the findings in the detail,
// every string from a scan drawn as text, and a link that does not point at one of the existing panes is not a link.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this._text = ''; this.className = ''; this.dataset = {}; this.listeners = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
globalThis.document = {createElement: (t) => new Node(t), createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}), cookie: '', querySelector: () => null,
  querySelectorAll: () => [], getElementById: () => null, body: new Node('body'), createDocumentFragment: () => new Node('#frag')};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setTimeout = () => 0;

const {rowNode, detailNode} = await import('../static/cve/situations.js');
const selectableRow = (id, heat, attr) => { const r = new Node('div'); r.className = 'host-row'; r.dataset[attr] = id; r.dataset.heat = heat; return r; };

const row = (over = {}) => ({
  rank: 1, project: 'sa', project_name: 'Alpha', host: 'proven.sa.test', host_link: '/cve/sa/hosts/?host=proven.sa.test', internal: false, headline: 'Proven: CVE-2099-1',
  rank_reason: 'Proven by a check, known exploited, internet-facing', counts: {proven: 1, likely: 0, exposure: 2, minor: 0}, first_action: 'Update nginx (fixes CVE-2099-1)',
  narrative: 'proven.sa.test is an internet-facing web server running nginx. Do this first: Update nginx.', findings_total: 1, findings_truncated: false,
  findings: [{kind: 'match', id: 5, title: 'CVE-2099-1', tier: 'proven', severity: 'medium', heat: 'smoke', known_exploited: true, set_by_you: false, first_seen: null,
    proof: {check: 'Version probe', at: '2026-11-01'}, link: '/cve/sa/vulns/#match-5'}],
  ...over,
});

test('a row says the rank, the host, the counts, the headline and the first action', () => {
  const r = rowNode(row(), {all: false, selectableRow});
  const text = r.textContent;
  for (const part of ['1', 'proven.sa.test', '1 proven', '2 exposed', 'Proven: CVE-2099-1', 'Next: Update nginx (fixes CVE-2099-1)']) assert.ok(text.includes(part), part);
  assert.equal(r.dataset.heat, 'fire');
  assert.equal(r.attrs['aria-expanded'], 'false');
  assert.ok(!text.includes('Alpha'), 'the project is named only in the all-projects view');
  assert.ok(rowNode(row(), {all: true, selectableRow}).textContent.includes('Alpha'));
});

test('the opened row shows the narrative, why it ranks there and the findings with links to the existing panes', () => {
  const box = detailNode(row());
  assert.ok(box.textContent.includes('is an internet-facing web server running nginx'));
  assert.ok(box.textContent.includes('Why it is here: Proven by a check, known exploited, internet-facing.'));
  const links = find(box, (n) => n.tag === 'a').map((n) => n.attrs.href);
  assert.deepEqual(links, ['/cve/sa/vulns/#match-5', '/cve/sa/hosts/?host=proven.sa.test']);
  assert.ok(box.textContent.includes('reproduced by Version probe'));
  assert.ok(box.textContent.includes('known exploited'));
});

test('text from a scan is text, and an odd link is not a link', () => {
  const evil = '<img src=x onerror=alert(1)>';
  const r = row({host: evil, headline: evil, narrative: evil, findings: [{kind: 'match', id: 1, title: evil, tier: 'likely', severity: 'high', link: 'javascript:alert(1)'}], host_link: 'https://evil.example/'});
  const box = detailNode(r);
  assert.ok(box.textContent.includes(evil), 'shown as the characters it is');
  assert.deepEqual(find(box, (n) => n.tag === 'a'), [], 'no link points anywhere but an existing pane');
  assert.equal(find(box, (n) => n.tag === 'img').length, 0);
  assert.equal(find(rowNode(r, {all: false, selectableRow}), (n) => n.tag === 'img').length, 0);
});

test('a host with more findings than the row carried says so and offers all of them', () => {
  const box = detailNode(row({findings_total: 40, findings_truncated: true}), {onMore: () => {}});
  assert.ok(box.textContent.includes('Showing 1 of 40 findings.'));
  assert.equal(find(box, (n) => n.tag === 'button' && n.textContent === 'Show all').length, 1);
  assert.equal(find(detailNode(row({findings_total: 40, findings_truncated: true})), (n) => n.tag === 'button').length, 0);
});
