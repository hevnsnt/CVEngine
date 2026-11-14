import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The AI reviewer's newest verdict on a finding, drawn in the AI assessment card (D1). Every model text is set as text: a note that holds
// markup stays text, and a finding with no review draws without the block.
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
const detail = (ai_review) => ({
  kind: 'match', title: 'CVE-2024-1', host: 'a.example.com', target: 'a.example.com', severity: 'High', severity_ai: null, why_it_matters: '', confidence: 0.8,
  first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-09T00:00:00Z', how_found: {steps: [], excerpts: {}},
  ai: {classification: 'confirmed', status: 'triaged', reason: '', hard_evidence: [], overridden: false, model: '', triaged: null},
  validation: null, cve: null, remediation: {}, ai_review,
});
const review = {
  verdict: 'true_open', confidence: 'high', reason_code: 'plausible_exposure', note: '<img src=x onerror=alert(1)> Looks real.', model: 'claude-sonnet-5-5',
  outcome: 'recorded', held_reason: '', at: '2026-11-10T00:00:00+00:00', verdict_text: 'The AI reviewer thinks this is real and still open.',
  outcome_text: 'The opinion is recorded; nothing was changed on the finding.', disputed: false, says_real: true,
};
const draw = (ai_review) => glance(detail(ai_review), {row: null, aiBadge: new Node('span'), note: ''});
const texts = (nodes) => { const out = []; nodes.forEach((n) => walk(n, (x) => { if (x._text) out.push(x._text); })); return out.join('|'); };

test('the newest verdict is drawn in plain words, with confidence, model and what the server did', () => {
  const text = texts(draw(review));
  assert.match(text, /The AI reviewer thinks this is real and still open\./);
  assert.match(text, /Confidence: High/);
  assert.match(text, /claude-sonnet-5-5/);
  assert.match(text, /nothing was changed on the finding/);
  assert.match(text, /plausible exposure/);
});

test('model text is text, never markup: a note with tags is one text node and no element is made of it', () => {
  const nodes = draw(review);
  const notes = find(nodes, (n) => n._text.includes('Looks real.'));
  assert.equal(notes.length, 1);
  assert.equal(notes[0]._text, '<img src=x onerror=alert(1)> Looks real.');
  assert.equal(find(nodes, (n) => n.tag === 'img').length, 0);
});

test('a finding with no review draws without the block, and a verdict with no note draws', () => {
  assert.doesNotMatch(texts(draw(null)), /AI reviewer/);
  assert.match(texts(draw({...review, note: ''})), /The AI reviewer thinks/);
});
