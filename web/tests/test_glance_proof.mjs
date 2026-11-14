import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The proof card at the top of a finding's detail, drawn against a tiny DOM: shown when a check reproduced the finding, with what the host answered,
// and not drawn at all otherwise. glance() runs for every finding, so this also proves the cards still draw for one with no proof.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this._text = ''; this.className = ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (roots, pred) => { const out = []; roots.forEach((r) => walk(r, (n) => pred(n) && out.push(n))); return out; };
globalThis.document = {createElement: (t) => new Node(t), createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}), cookie: '', querySelector: () => null, querySelectorAll: () => [], getElementById: () => null, body: new Node('body'), createDocumentFragment: () => new Node('#frag')};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setTimeout = () => 0;

const {glance} = await import('../static/cve/finding-glance.js');
const detail = (validation) => ({
  kind: 'match', title: 'CVE-2024-1', host: 'a.example.com', target: 'a.example.com', severity: 'High', severity_ai: null, why_it_matters: '', confidence: 0.8,
  first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-09T00:00:00Z',
  how_found: {steps: [], excerpts: {}},
  ai: {classification: 'confirmed', status: 'triaged', reason: '', hard_evidence: [], overridden: false, model: '', triaged: null},
  validation, cve: null, remediation: {},
});
const draw = (validation) => glance(detail(validation), {row: null, aiBadge: new Node('span'), note: ''});
const proofCards = (nodes) => find(nodes, (n) => /\bgl-proof\b/.test(n.className));

test('a hit is drawn first, with the check, the request and what the host answered', () => {
  const nodes = draw({
    status: 'hit',
    steps: [{kind: 'nuclei_template', label: 'nuclei check', display: 'nuclei -t cve-2024-1 -u https://a.example.com', result: 'hit', ran_at: '2026-11-09T09:00:00Z', summary: 'matched the marker'}],
    evidence: {nuclei_template: {request: 'GET /admin HTTP/1.1', response: 'HTTP/1.1 200 OK\r\nServer: x'}},
  });
  const [card] = proofCards(nodes);
  assert.ok(card, 'the proof card is drawn');
  assert.equal(nodes[0], card, 'and it is first');
  const text = card.textContent;
  for (const part of ['Proven on this host', 'Reproduced by the nuclei check', 'matched the marker', 'Repeat it yourself', 'nuclei -t cve-2024-1', 'GET /admin HTTP/1.1', 'What the host answered', 'HTTP/1.1 200 OK']) {
    assert.ok(text.includes(part), part);
  }
});

test('a hit with no kept exchange says so, and still names the check', () => {
  const [card] = proofCards(draw({status: 'hit', steps: [{kind: 'script_read', label: 'script read', result: 'hit', ran_at: '2026-11-09T09:00:00Z'}], evidence: {}}));
  assert.ok(card.textContent.includes('Reproduced by the script read'));
  assert.ok(card.textContent.includes('No request or response was kept'));
});

test('no proof card for a finding no check reproduced, and the other cards still draw', () => {
  for (const validation of [{status: 'clean', steps: [{result: 'no_match'}], evidence: {}}, {status: 'none', steps: [], evidence: {}}, {status: 'failed', steps: [{result: 'failed'}], evidence: {}}]) {
    const nodes = draw(validation);
    assert.equal(proofCards(nodes).length, 0, validation.status);
    assert.ok(find(nodes, (n) => /\bgl-grid\b/.test(n.className)).length >= 1, 'the three cards are still there');
  }
});

test('hostile text in the exchange is drawn as text, never as markup', () => {
  const [card] = proofCards(draw({status: 'hit', steps: [{kind: 'fact_probe', label: 'probe', result: 'hit', ran_at: '2026-11-09T09:00:00Z', summary: '<img src=x onerror=alert(1)>'}],
    evidence: {fact_probe: {response: '<script>alert(1)</script>'}}}));
  assert.ok(card.textContent.includes('<script>alert(1)</script>'));
  assert.equal(find([card], (n) => n.tag === 'script' || n.tag === 'img').length, 0);
});

const retestCards = (nodes) => find(nodes, (n) => /\bgl-retest\b/.test(n.className));
const withRetest = (retest) => glance({...detail({status: 'none', steps: [], evidence: {}}), retest}, {row: null, aiBadge: new Node('span'), note: ''});

test('the retest card is first, says the state plainly and names the Sentinel', () => {
  const nodes = withRetest({state: 'not_verified', label: 'Fixed, not verified', text: 'Fixed, not verified: the host did not answer', at: '2026-11-12T10:00:00Z',
    sentinel: 'east-1', reason: 'the host did not answer', can_retest: true});
  const [card] = retestCards(nodes);
  assert.ok(card, 'the retest card is drawn');
  assert.equal(nodes[0], card);
  const text = card.textContent;
  for (const part of ['Retest after the fix', 'Fixed, not verified', 'east-1', 'the host did not answer', 'at most once a day']) assert.ok(text.includes(part), part);
  assert.ok(!/Verified fixed/.test(text), 'never calls it verified');
});

test('verified fixed and still reproduces each draw their own card, and no card for a finding never marked fixed', () => {
  assert.ok(retestCards(withRetest({state: 'verified_fixed', label: 'Verified fixed', text: 'Verified fixed on 2026-11-12', at: '2026-11-12T10:00:00Z', sentinel: 'e', reason: ''}))[0].className.includes('gl-retest-verified-fixed'));
  assert.ok(retestCards(withRetest({state: 'still_reproduces', label: 'Still reproduces, reopened', text: 'x', at: null, sentinel: '', reason: ''}))[0].textContent.includes('reopened'));
  for (const retest of [undefined, null, {state: ''}]) assert.equal(retestCards(withRetest(retest)).length, 0);
});

test('hostile text in a reason is text', () => {
  const [card] = retestCards(withRetest({state: 'not_verified', label: 'Fixed, not verified', text: 't', at: null, sentinel: '<b>x</b>', reason: '<script>alert(1)</script>'}));
  assert.ok(card.textContent.includes('<script>alert(1)</script>'));
  assert.equal(find([card], (n) => n.tag === 'script' || n.tag === 'b').length, 0);
});
