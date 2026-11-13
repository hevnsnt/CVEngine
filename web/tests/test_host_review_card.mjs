import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
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
  removeAttribute(k) { delete this.attrs[k]; }
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
const finding = (over = {}) => ({finding: {type: 'match', id: 5}, link: '/cve/p/vulns/#match-5', title: 'CVE-2099-1', verdict: 'true_open', summary: 'real', confidence: 'high',
  reason_code: 'version_in_range', note: 'The version is affected.', outcome: 'recorded', held_reason: '', ...over});
const review = (over = {}) => ({id: 1, status: 'applied', running: false, created: '2026-11-12T10:00:00Z', decided: '2026-11-12T10:01:00Z', model: 'vllm:m', failure: null,
  host_note: '', held_for_instructions: false, injection: [], counts: {real: 1, false_positive: 2, uncertain: 0, closed: 1, held: 1},
  findings: [finding({reason_code: 'confirmed_by_evidence'}),
    finding({finding: {type: 'match', id: 6}, link: '/cve/p/vulns/#match-6', title: 'CVE-2099-2', verdict: 'false_positive', summary: 'false_positive', outcome: 'closed', reason_code: 'version_not_affected', note: ''}),
    finding({finding: {type: 'match', id: 7}, link: '/cve/p/vulns/#match-7', title: 'CVE-2099-3', verdict: 'false_positive', summary: 'false_positive', outcome: 'disputed', held_reason: 'it has hard evidence', reason_code: 'product_mismatch', note: ''})],
  step: {action: 'assess_host', description: 'Run a full assessment of the host.', what_it_touches: 'x', target: null, reason_code: 'needs_proof', note: '',
    mode: 'recommend', state: 'proposed', detail: 'the project is set to recommend only', needs_person: false, can_start: true, can_dismiss: true, dismissed_by: null}, ...over});
const data = (over = {}) => ({host_id: 9, host: 'h', mode: 'recommend', readiness: {can_request: true, reason_code: '', reason: ''}, status: 'applied', review: review(), ...over});
const none = (code, reason = '') => data({status: 'none', review: null, readiness: {can_request: false, reason_code: code, reason}});

async function draw(d, opts = {}) {
  calls.length = 0; timers = [];
  answers = {[`GET ${BASE}/hosts/9/review`]: {body: d}};
  const card = hostReviewCard({base: BASE, hostId: 9, isCurrent: () => true, ago: () => '2 h ago', ...opts});
  await new Promise((r) => setImmediate(r));
  return card;
}
const withSettingsLink = (on) => { document.querySelector = (sel) => (sel.includes('csrf') ? {value: 'x'} : sel.includes('/cve/settings') && on ? {getAttribute: () => '/cve/settings/'} : null); };
withSettingsLink(false);

test('an applied review is a header row, one headline, a quiet line, compact verdict rows and a distinct next-step block', async () => {
  const card = await draw(data());
  const t = card.textContent;
  assert.match(t, /^AI review of this host/);
  assert.match(t, /Reviewed 2 h ago/);
  assert.match(t, /1 of 3 findings looks real\./);
  assert.match(t, /2 look like false positives: 1 closed, 1 stays open because a check reproduced it\./);
  assert.match(t, /cvENGINE's own evidence shows the flaw\./);
  assert.match(t, /The version on this host is outside the range the advisory covers\./);
  assert.match(t, /Closed/);
  assert.match(t, /Kept open: a check reproduced it/);
  assert.match(t, /Suggested next step.*Waiting for you.*Run a full assessment of this host.*A check would show whether the finding is really there\./);
  assert.match(t, /This project only recommends steps, so nothing starts until you press Start\./);
  assert.ok(buttonNamed(card, 'Start') && buttonNamed(card, 'Dismiss') && buttonNamed(card, 'Review again'));
  assert.doesNotMatch(t, /version_not_affected|version not affected|version in range|confirmed_by_evidence/, 'no raw reason code is shown');
  assert.doesNotMatch(t, /11\/12\/2026|10:17/, 'no clock time: the app\'s relative time');
});

test('each CVE is a link to its finding and every control has a name', async () => {
  const card = await draw(data());
  const links = find(card, (n) => n.tag === 'a');
  assert.deepEqual(links.map((a) => a.attrs.href), ['/cve/p/vulns/#match-5', '/cve/p/vulns/#match-6', '/cve/p/vulns/#match-7']);
  assert.equal(links[0].attrs['aria-label'], 'Open CVE-2099-1');
  find(card, (n) => n.tag === 'button').forEach((b) => assert.ok(b.textContent && (b.attrs['aria-label'] || b.textContent), 'a button has a name'));
  assert.equal(buttonNamed(card, 'Start').attrs['aria-label'], 'Start: Run a full assessment of this host');
  const chips = find(card, (n) => /badge/.test(n.className));
  assert.ok(chips.some((c) => c.attrs.title === 'Real, high confidence'), 'the confidence is in the tooltip');
});

test('every reason code the server can send has a sentence, and so do the held reasons and the step reasons', () => {
  const py = readFileSync(new URL('../cveFeed/reviewer.py', import.meta.url), 'utf8');
  const block = py.slice(py.indexOf('REASON_CODES = ('), py.indexOf('\n)', py.indexOf('REASON_CODES = (')));
  const codes = [...block.matchAll(/'([a-z_]+)',/g)].map((m) => m[1]);
  assert.ok(codes.length >= 12, codes.join());
  codes.filter((c) => c !== 'other').forEach((c) => assert.ok(logic.reasonText(c).length > 10, `${c} has a sentence`));
  const host = readFileSync(new URL('../cveFeed/host_review.py', import.meta.url), 'utf8');
  const steps = [...host.match(/STEP_REASONS = \(([^)]*)\)/)[1].matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
  steps.forEach((c) => assert.ok(logic.STEP_WHY[c], `${c} has a sentence`));
  const actions = readFileSync(new URL('../cveFeed/host_actions.py', import.meta.url), 'utf8');
  [...actions.matchAll(/^    '([a-z_]+)': \((?:AUTO|RECOMMEND),/gm)].map((m) => m[1]).forEach((a) => assert.ok(logic.STEP_TITLES[a], `${a} has a title`));
  const held = {'hard evidence: x': 'a check reproduced it', 'a person has worked this finding': 'a person is working on it', 'its evidence carries text aimed at AI agents (override)': "this host's text contains instructions",
    "the reviewer's confidence is low, not high": 'the AI was not sure enough', 'closing false positives is turned off in Settings': 'closing false positives is switched off in Settings',
    'a critical scanner finding is closed by a person': 'a person closes critical scanner findings', 'contradicts the earlier verdict on this state': 'an earlier review called it real'};
  Object.entries(held).forEach(([reason, phrase]) => assert.equal(logic.heldBecause({outcome: 'held', held_reason: reason}), phrase));
  assert.equal(logic.heldBecause({outcome: 'disputed', held_reason: ''}), 'a check reproduced it');
  assert.equal(logic.outcomeTag({summary: 'false_positive', outcome: 'held', held_reason: 'its evidence carries text aimed at AI agents (x)'}).text, "Held: this host's text contains instructions");
});

test('headlines: all real, some real, none real, all false positives, unclear', () => {
  const c = (real, fp, un, closed = 0) => logic.summary({counts: {real, false_positive: fp, uncertain: un, closed, held: 0}, findings: []});
  assert.equal(c(1, 0, 0).headline, 'The finding looks real.');
  assert.equal(c(3, 0, 0).headline, 'All 3 findings look real.');
  assert.equal(c(2, 1, 0, 1).headline, '2 of 3 findings look real.');
  assert.equal(c(0, 2, 0, 2).headline, 'All 2 findings look like false positives.');
  assert.equal(c(0, 2, 0, 2).detail, 'All were closed.');
  assert.equal(c(0, 0, 2).headline, 'The AI could not tell for any of the 2 findings.');
  assert.equal(c(1, 1, 1, 1).detail, '1 looks like a false positive: closed; 1 is unclear.');
});

test('Start and Dismiss call the routes and then show the new state; focus goes back to the card heading', async () => {
  const card = await draw(data());
  answers[`POST ${BASE}/hosts/9/review/step`] = {body: {result: {state: 'started', detail: 'queued'}, review: {}}};
  answers[`GET ${BASE}/hosts/9/review`] = {body: data({review: review({step: {...review().step, state: 'started', mode: 'recommend', detail: 'assessment queued', can_start: false, can_dismiss: false}})})};
  await buttonNamed(card, 'Start').onclick();
  assert.ok(calls.some((c) => c.key === `POST ${BASE}/hosts/9/review/step`));
  assert.match(card.textContent, /Started.*Run a full assessment of this host/);
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

test('the next step in each state reads honestly', () => {
  const step = (over) => logic.stepView({action: 'validate_match', description: 'x', target: {title: 'CVE-2099-1', link: '/l'}, mode: 'auto', state: 'started', detail: 'queued', reason_code: 'needs_check', note: '', can_start: false, can_dismiss: false, ...over});
  assert.equal(step({}).title, 'Run the read-only check for CVE-2099-1');
  assert.equal(step({}).chip, 'Started automatically');
  assert.equal(step({state: 'refused', detail: 'host is excluded'}).help, 'Host is excluded.');
  assert.equal(step({state: 'refused'}).chip, 'Could not start');
  assert.match(step({state: 'dismissed', dismissed_by: {username: 'ann'}}).help, /Dismissed by ann/);
  assert.equal(logic.stepView({action: 'none', state: 'done', reason_code: 'nothing_to_do'}).title, 'Nothing more is needed for this host');
  const ask = logic.stepView({action: 'ask_person', state: 'proposed', can_dismiss: true, reason_code: 'needs_person'});
  assert.equal((ask.chip, ask.dismiss, ask.start), ('Needs a person', true, false) && ask.chip);
  assert.equal(ask.dismiss, true);
});

test('each other state is a header row and one or two lines', async () => {
  let t = (await draw(none('no_provider', 'no AI provider is configured'))).textContent;
  assert.match(t, /No AI provider is set up\./);
  assert.equal(buttonNamed(await draw(none('no_provider')), 'Review now').disabled, true);
  assert.match((await draw(none('nothing_open', 'x'))).textContent, /Nothing is open on this host\./);
  assert.match((await draw(none(''))).textContent, /Not reviewed yet\.The AI reads every open finding/);
  t = (await draw(data({status: 'queued', review: review({status: 'queued', running: true, findings: [], step: null})}))).textContent;
  assert.match(t, /Running.*The AI is reading this host\./);
  const before = calls.length;
  timers.splice(0).forEach((fn) => fn());
  await new Promise((r) => setImmediate(r));
  assert.ok(calls.length > before, 'a running review is polled');
  t = (await draw(data({status: 'failed', review: review({status: 'failed', failure: 'failed: provider_rate_limit', findings: [], step: null}), readiness: {can_request: true}}))).textContent;
  assert.match(t, /Tried 2 h ago/);
  assert.match(t, /The review did not finish\.The AI provider was too busy \(a rate limit\)\. Nothing was changed\. It is tried again later\./);
  t = (await draw(data({status: 'failed', review: review({status: 'failed', failure: 'failed: not reviewed (the packet is too large (176979 characters))', findings: [], step: null}), readiness: {can_request: true}}))).textContent;
  assert.match(t, /This host is too large to review in one go\.It has more to read than the AI can take at once\./);
  t = (await draw(data({status: 'stale', review: review({status: 'stale', failure: 'stale: the host changed while the AI was reading it', step: null})}))).textContent;
  assert.match(t, /The host changed while the AI was reading it\./);
  t = (await draw(data({review: review({held_for_instructions: true, injection: ['override']})}))).textContent;
  assert.match(t, /Text on this host tells AI what to do/);
});

test('when the review is off the card is one line, with no Review now, and a stored review is collapsed and marked as older', async () => {
  withSettingsLink(false);
  let card = await draw(data({status: 'none', review: null, readiness: {can_request: false, reason_code: 'disabled', reason: 'the AI host review is switched off'}}));
  assert.match(card.textContent, /AI host review is off\./);
  assert.equal(buttonNamed(card, 'Review now'), undefined);
  assert.equal(find(card, (n) => n.tag === 'a').length, 0, 'no link for a person who cannot open Settings');
  withSettingsLink(true);
  card = await draw(data({readiness: {can_request: false, reason_code: 'disabled', reason: 'x'}}));
  assert.match(card.textContent, /AI host review is off\./);
  const link = find(card, (n) => n.tag === 'a' && n.attrs.href === '/cve/settings/');
  assert.equal(link.length, 1);
  const old = find(card, (n) => n.tag === 'details' && /hr-old/.test(n.className))[0];
  assert.match(old.textContent, /^Last review, 2 h ago \(from before it was switched off\)/);
  assert.equal(buttonNamed(card, 'Start'), undefined);
  assert.equal(buttonNamed(card, 'Dismiss'), undefined);
  assert.equal(buttonNamed(card, 'Review again'), undefined);
  assert.equal(old.attrs.open, undefined, 'collapsed');
  assert.match((await draw(none('off'))).textContent, /AI host review is off for this project\./);
  withSettingsLink(false);
});

test('model and host text is set as text, never as markup', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const card = await draw(data({review: review({host_note: hostile, findings: [finding({title: hostile, note: hostile})], step: {...review().step, note: hostile}})}));
  assert.ok(card.textContent.includes(hostile));
  assert.equal(find(card, (n) => n.tag === 'img').length, 0);
  for (const src of ['host-review-card.js', 'host-review-logic.js']) {
    const text = readFileSync(new URL('../static/cve/' + src, import.meta.url), 'utf8');
    assert.doesNotMatch(text, /innerHTML|insertAdjacentHTML|outerHTML/);
  }
});

test('the project mode is in a closed disclosure at the foot, for administrators only, and saves to the project settings', async () => {
  let card = await draw(data());
  assert.equal(find(card, (n) => n.tag === 'select').length, 0, 'not shown to a person who cannot open Settings');
  withSettingsLink(true);
  card = await draw(data());
  const box = find(card, (n) => n.tag === 'details' && /hr-settings/.test(n.className))[0];
  assert.match(box.textContent, /^Settings for this project/);
  assert.match(box.textContent, /This applies to every host of the project\./);
  assert.equal(box.attrs.open, undefined, 'closed');
  const select = find(box, (n) => n.tag === 'select')[0];
  assert.deepEqual(find(select, (n) => n.tag === 'option').map((o) => o.attrs.value), ['recommend', 'auto', 'off']);
  assert.equal(find(box, (n) => n.tag === 'label')[0].attrs.for, select.attrs.id);
  answers[`PUT ${BASE}/settings`] = {body: {host_review_mode: 'auto'}};
  select.value = 'auto';
  await select.onchange();
  assert.deepEqual(calls.find((c) => c.key === `PUT ${BASE}/settings`).body, {host_review_mode: 'auto'});
  withSettingsLink(false);
});

test('a card that cannot read the review says so', async () => {
  calls.length = 0;
  answers = {[`GET ${BASE}/hosts/9/review`]: {status: 500, body: {error: 'boom'}}};
  const card = hostReviewCard({base: BASE, hostId: 9});
  await new Promise((r) => setImmediate(r));
  assert.match(card.textContent, /could not be read\.boom/);
});
