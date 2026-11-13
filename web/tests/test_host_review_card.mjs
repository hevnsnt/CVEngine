import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The "AI review of this host" card of the host page: its words (host-review-logic.js) and its states, drawn against a tiny DOM and a fake server.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.value = ''; }
  addEventListener() {}
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  focus() { globalThis.__focused = this; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
const buttonNamed = (root, text) => find(root, (n) => n.tag === 'button' && n.textContent === text)[0];

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
let timers = [];
globalThis.setTimeout = (fn) => { timers.push(fn); return timers.length; };
globalThis.localStorage = {getItem: () => null, setItem() {}};

const calls = [];
let answers = {};
globalThis.fetch = async (url, opts = {}) => {
  const key = `${opts.method || 'GET'} ${url}`;
  calls.push({key, body: opts.body && JSON.parse(opts.body)});
  const a = answers[key];
  if (a && a.status >= 400) return {ok: false, status: a.status, json: async () => a.body};
  return {ok: true, status: 200, json: async () => (a ? a.body : {})};
};

const logic = await import('../static/cve/host-review-logic.js');
const {hostReviewCard} = await import('../static/cve/host-review-card.js');

const BASE = '/api/v1/projects/p';
const finding = (over = {}) => ({finding: {type: 'match', id: 5}, title: 'CVE-2099-1', verdict: 'true_open', summary: 'real', confidence: 'high', reason_code: 'version_in_range',
  note: 'The version is affected.', outcome: 'recorded', held_reason: '', ...over});
const review = (over = {}) => ({id: 1, status: 'applied', running: false, created: '2026-11-12T10:00:00Z', decided: '2026-11-12T10:01:00Z', model: 'vllm:m', failure: null,
  host_note: 'Read together.', held_for_instructions: false, injection: [], counts: {real: 1, false_positive: 1, uncertain: 0, closed: 1, held: 0},
  findings: [finding(), finding({finding: {type: 'match', id: 6}, title: 'CVE-2099-2', verdict: 'false_positive', summary: 'false_positive', outcome: 'closed', reason_code: 'version_not_affected'})],
  step: {action: 'assess_host', description: 'Run a full assessment of the host.', what_it_touches: 'x', target: null, reason_code: 'needs_proof', note: 'A fresh look would settle it.',
    mode: 'recommend', state: 'proposed', detail: 'the project is set to recommend only', needs_person: false, can_start: true, can_dismiss: true, dismissed_by: null}, ...over});
const data = (over = {}) => ({host_id: 9, host: 'h', mode: 'auto', readiness: {can_request: true, reason_code: '', reason: ''}, status: 'applied', review: review(), ...over});
const none = (code, reason = '') => data({status: 'none', review: null, readiness: {can_request: false, reason_code: code, reason}});

async function draw(d) {
  calls.length = 0; timers = [];
  answers = {[`GET ${BASE}/hosts/9/review`]: {body: d}};
  const card = hostReviewCard({base: BASE, hostId: 9, isCurrent: () => true, openFindings: () => {}});
  await new Promise((r) => setImmediate(r));
  return card;
}

test('an applied review says what it concluded, each verdict with its reason, and the next step with Start and Dismiss', async () => {
  const card = await draw(data());
  const t = card.textContent;
  assert.match(t, /Of 2 findings, 1 looks real, 1 looks like a false positive\. 1 was closed as a false positive\./);
  assert.match(t, /Real finding \(high confidence\)/);
  assert.match(t, /False positive \(high confidence\)/);
  assert.match(t, /Closed as a false positive\./);
  assert.match(t, /version not affected\. The version is affected\./);
  assert.match(t, /Suggested next step/);
  assert.match(t, /Run a full assessment of the host\./);
  assert.match(t, /Not started by itself: the project is set to recommend only/);
  assert.ok(buttonNamed(card, 'Start') && buttonNamed(card, 'Dismiss') && buttonNamed(card, 'Review again'));
});

test('Start and Dismiss call the routes and then show the new state; focus goes back to the card heading', async () => {
  const card = await draw(data());
  answers[`POST ${BASE}/hosts/9/review/step`] = {body: {result: {state: 'started', detail: 'queued'}, review: {}}};
  answers[`GET ${BASE}/hosts/9/review`] = {body: data({review: review({step: {...review().step, state: 'started', mode: 'recommend', detail: 'queued', can_start: false, can_dismiss: false}})})};
  await buttonNamed(card, 'Start').onclick();
  assert.ok(calls.some((c) => c.key === `POST ${BASE}/hosts/9/review/step`));
  assert.match(card.textContent, /Started by a person: Run a full assessment/);
  assert.equal(buttonNamed(card, 'Start'), undefined);
  assert.equal(globalThis.__focused.attrs.id, 'host-review-h-9');
  const again = await draw(data());
  answers[`POST ${BASE}/hosts/9/review/dismiss`] = {body: {review: {}}};
  await buttonNamed(again, 'Dismiss').onclick();
  assert.ok(calls.some((c) => c.key === `POST ${BASE}/hosts/9/review/dismiss`));
});

test('a refused Start says why and the card reloads', async () => {
  const card = await draw(data());
  answers[`POST ${BASE}/hosts/9/review/step`] = {status: 409, body: {error: 'the host is excluded'}};
  await buttonNamed(card, 'Start').onclick();
  assert.ok(calls.filter((c) => c.key === `GET ${BASE}/hosts/9/review`).length >= 1);
});

test('a step started automatically, a refused one and a dismissed one read honestly', () => {
  const step = (over) => logic.stepView({action: 'validate_match', description: 'Run the read-only validation of one CVE match.', target: {title: 'CVE-2099-1'}, mode: 'auto', state: 'started', detail: 'queued', can_start: false, can_dismiss: false, ...over});
  assert.equal(step({}).text, 'Started automatically: Run the read-only validation of one CVE match. (CVE-2099-1).');
  assert.match(step({state: 'refused', detail: 'host is excluded'}).text, /could not be started: host is excluded/);
  assert.match(step({state: 'dismissed', dismissed_by: {username: 'ann'}}).text, /Dismissed by ann/);
  assert.equal(logic.stepView({action: 'none', state: 'done'}).text, 'Nothing more is needed for this host now.');
  assert.equal(logic.stepView({action: 'ask_person', state: 'proposed', can_dismiss: true}).dismiss, true);
});

test('each honest state: no provider, running, failed, stale, held, nothing to review, never reviewed', async () => {
  let t = (await draw(none('no_provider', 'no AI provider is configured'))).textContent;
  assert.match(t, /No AI provider is set up/);
  assert.equal(buttonNamed(await draw(none('no_provider')), 'Review now').disabled, true);
  t = (await draw(none('nothing_open', 'x'))).textContent;
  assert.match(t, /Nothing is open on this host/);
  t = (await draw(none('disabled', 'the AI host review is switched off'))).textContent;
  assert.match(t, /switched off for this installation.*turns it on in Settings.*bills for/);
  t = (await draw(none('off'))).textContent;
  assert.match(t, /switched off for this project/);
  t = (await draw(data({status: 'queued', review: review({status: 'queued', running: true, findings: [], step: null})}))).textContent;
  assert.match(t, /reading this host's findings now/);
  const before = calls.length;
  timers.splice(0).forEach((fn) => fn());
  await new Promise((r) => setImmediate(r));
  assert.ok(calls.length > before, 'a running review is polled');
  t = (await draw(data({status: 'failed', review: review({status: 'failed', failure: 'failed: provider_rate_limit', findings: [], step: null}), readiness: {can_request: true}}))).textContent;
  assert.match(t, /Review failed/);
  assert.match(t, /too busy \(a rate limit\)\. Nothing was changed\./);
  t = (await draw(data({status: 'stale', review: review({status: 'stale', failure: 'stale: the host changed while the AI was reading it', step: null})}))).textContent;
  assert.match(t, /The host changed while the AI was reading it, so nothing was applied/);
  t = (await draw(data({review: review({held_for_instructions: true, injection: ['override']})}))).textContent;
  assert.match(t, /tells AI what to do/);
  t = (await draw(none(''))).textContent.replace(/\s+/g, ' ');
  assert.match(t, /has not reviewed this host yet/);
});

test('model and host text is set as text, never as markup', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const card = await draw(data({review: review({host_note: hostile, findings: [finding({title: hostile, note: hostile})], step: {...review().step, note: hostile}})}));
  assert.ok(card.textContent.includes(hostile));
  assert.equal(find(card, (n) => n.tag === 'img').length, 0);
  for (const src of ['host-review-card.js', 'host-review-logic.js']) {
    const text = (await import('node:fs')).readFileSync(new URL('../static/cve/' + src, import.meta.url), 'utf8');
    assert.doesNotMatch(text, /innerHTML|insertAdjacentHTML|outerHTML/);
  }
});

test('the mode select lists the modes and saves the choice to the project settings', async () => {
  const card = await draw(data());
  const select = find(card, (n) => n.tag === 'select')[0];
  assert.deepEqual(find(select, (n) => n.tag === 'option').map((o) => o.attrs.value), ['auto', 'recommend', 'off']);
  assert.equal(find(card, (n) => n.tag === 'label')[0].attrs.for, select.attrs.id);
  answers[`PUT ${BASE}/settings`] = {body: {host_review_mode: 'recommend'}};
  select.value = 'recommend';
  await select.onchange();
  assert.deepEqual(calls.find((c) => c.key === `PUT ${BASE}/settings`).body, {host_review_mode: 'recommend'});
});

test('a card that cannot read the review says so', async () => {
  calls.length = 0;
  answers = {[`GET ${BASE}/hosts/9/review`]: {status: 500, body: {error: 'boom'}}};
  const card = hostReviewCard({base: BASE, hostId: 9});
  await new Promise((r) => setImmediate(r));
  assert.match(card.textContent, /could not be read: boom/);
});

test('a switched-off review links to Settings only where the page has a Settings link', async () => {
  const link = (list) => (sel) => (sel.includes('csrf') ? {value: 'x'} : sel.includes('/cve/settings') ? list : null);
  const keep = document.querySelector;
  document.querySelector = link({getAttribute: () => '/cve/settings/'});
  let card = await draw(none('disabled', 'the AI host review is switched off'));
  const a = find(card, (n) => n.tag === 'a');
  assert.equal(a.length, 1);
  assert.equal(a[0].attrs.href, '/cve/settings/');
  document.querySelector = link(null);
  card = await draw(none('disabled', 'x'));
  assert.equal(find(card, (n) => n.tag === 'a').length, 0);
  document.querySelector = keep;
});
