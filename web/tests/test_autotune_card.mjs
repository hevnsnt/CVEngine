import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// The Auto-tuning card of Settings, configMaxxing and the auto-tuning line on the rows of the other cards, drawn against a tiny DOM and a fake
// server. The pages import `/staticfiles/cve/...`; the hook below maps that to the source directory.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'hidden') this.hidden = true; }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  remove() {}
  replaceWith() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  scrollIntoView() {}
  get lastChild() { return this.children[this.children.length - 1]; }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };

// The words are inside a closed <details> (whose summary says "Details") and are not shown anywhere outside it: a person who never opens it never reads them.
const behindDetails = (host, pattern) => {
  const boxes = find(host, (n) => n.tag === 'details');
  const inside = boxes.filter((d) => pattern.test(d.textContent));
  assert.ok(inside.length >= 1, `${pattern} is inside a details element`);
  assert.ok(inside[0].textContent.startsWith('Details'), 'whose summary is Details');
  assert.ok(!inside[0].attrs || !('open' in inside[0].attrs), 'closed by default');
  const outside = host.textContent.split(inside[0].textContent).join('');
  assert.doesNotMatch(outside, pattern, `${pattern} is not shown outside the details`);
};
const buttonNamed = (root, text) => find(root, (n) => n.tag === 'button' && n.textContent === text);

globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  getElementById: () => null,
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body: new Node('body'),
};
globalThis.setTimeout = () => 0;
globalThis.localStorage = {getItem: () => null, setItem() {}};

const status = (over = {}) => ({
  mode: 'auto', effective_mode: 'auto', killed: false, changed_by: null, changed_at: null,
  advisor: {enabled: true, provider: true, used_today: 2, cap: 8, interval_hours: 3, last_error: null},
  last_run: {at: '2026-11-01T20:00:00Z', held: null, changes: [{setting: 'heavy.nmap'}]},
  sized_for: '8 cores, 3.4 GB memory budget, 9 Sentinel slots',
  history: [
    {id: 7, at: '2026-11-01T20:00:00Z', setting: 'heavy.nmap', label: 'Port and service scan (nmap)', old_value: 2, new_value: 3, source: 'controller',
      action: 'raise', applied: true, pressure: false, reason: 'nmap runs waited <b>x</b>', resolution: null, can_revert: true, can_apply: false},
    {id: 6, at: '2026-11-01T19:00:00Z', setting: 'stage_parallel', label: 'Chunks of one scan stage at once', old_value: 4, new_value: 5, source: 'ai',
      action: 'raise', applied: false, pressure: false, reason: 'free slots', resolution: null, can_revert: false, can_apply: true},
  ],
  ...over,
});
const field = (over) => ({key: 'heavy.nmap', label: 'Port and service scan (nmap)', help: 'The standard scan.', group: 'heavy', default: 2, min: 1, max: 8, value: 3,
  source: 'auto', env_name: 'HEAVY_MAX_NMAP', env_value: null, saved: null, set_by: null, set_at: null, applies: 'live', ...over});
const concurrency = () => ({
  fields: [
    field({autotune: {managed: true, tuned: true, pinned: false, was: 2, reason: 'nmap runs waited', at: '2026-11-01T20:00:00Z', min: 1, max: 4, step: 1}}),
    field({key: 'heavy.nuclei', label: 'Vulnerability templates (nuclei)', value: 2, source: 'admin', saved: 2, set_by: 'bill',
      autotune: {managed: true, tuned: false, pinned: true, pinned_by: 'bill <i>x</i>', min: 1, max: 3, step: 1}}),
    field({key: 'heavy.wpscan', label: 'WordPress scan (WPScan)', value: 2, source: 'default',
      autotune: {managed: true, tuned: false, pinned: false, min: 1, max: 4, step: 1, suggestion: {id: 9, value: 3, from: 2, reason: 'sites waited', source: 'ai'}}}),
    field({key: 'heavy.naabu', label: 'Fast port discovery (naabu)', value: 1, source: 'default', autotune: {managed: false}}),
  ],
  groups: [{id: 'heavy', title: 'Scanners at once'}],
  memory: {budget_mb: 3072, limit_mb: 4096, costs_mb: {}, warnings: []},
  discovery: {state: 'unknown', message: ''},
  autotune: {mode: 'auto', effective_mode: 'auto', killed: false},
});

const calls = [];
let reply = {status: status(), concurrency: concurrency()};
globalThis.fetch = async (url, opts = {}) => {
  calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
  const body = url.endsWith('/autotune') ? reply.status : url.endsWith('/scan_concurrency') ? reply.concurrency : {};
  return {ok: true, status: 200, json: async () => body};
};

const logic = await import('../static/cve/config-maxxing-logic.js');
const maxxing = await import('../static/cve/config-maxxing.js');
await import('../static/cve/autotune-card.js');
await import('../static/cve/scan-concurrency-card.js');

test('the Auto-tuning card comes first and says it is on by default and how to turn it off', async () => {
  assert.deepEqual(maxxing.cards().map((c) => c.id), ['autotune', 'scan_concurrency']);
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  const text = host.textContent;
  assert.match(text, /^Auto-tuning/);
  assert.match(text, /Auto-tuning is on by default/);
  assert.match(text, /To tune by hand, choose Off/);
  assert.match(text, /CVENGINE_AUTOTUNE=0/);
  assert.match(text, /Used today: 2 of 8/);
  assert.match(text, /Last run .*: 1 change\(s\)\./);
  assert.match(text, /Sized for this machine: 8 cores, 3\.4 GB memory budget, 9 Sentinel slots\./);
  assert.match(text, /Port and service scan \(nmap\) 2 → 3 · auto-tune/);  // the History line: what, who
  assert.match(text, /Why: Nmap runs waited <b>x<\/b>/);  // text, never markup
  assert.ok(!find(host, (n) => n.tag === 'b').length);
  const select = find(host, (n) => n.tag === 'select')[0];
  assert.deepEqual(select.children.map((o) => o.value), ['auto', 'suggest', 'off']);
  assert.equal(select.value, 'auto');
});

test('Save sends the mode and the advisor switch; Revert and Apply post to their decision', async () => {
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  const select = find(host, (n) => n.tag === 'select')[0];
  select.value = 'off';
  const box = find(host, (n) => n.tag === 'input' && n.attrs.type === 'checkbox')[0];
  box.checked = false;
  calls.length = 0;
  await buttonNamed(host, 'Save')[0].onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/autotune', method: 'PUT', body: {mode: 'off', advisor: false}});
  calls.length = 0;
  await buttonNamed(host, 'Apply')[0].onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/autotune/decisions/6/apply', method: 'POST', body: {}});
  assert.equal(buttonNamed(host, 'Revert').length, 1);  // only the newest applied change of a setting offers it
});

test('the agent policy is its own control: Suggest by default, and changing it sends only the policy', async () => {
  reply = {status: status(), concurrency: concurrency()};
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  const selects = find(host, (n) => n.tag === 'select');
  assert.equal(selects.length, 2);
  const policy = selects[1];
  assert.equal(policy.attrs.id, 'autotune-agent-policy');
  assert.equal(policy.value, 'suggest');
  assert.match(host.textContent, /Whether AI agents may change performance settings by themselves/);
  assert.match(host.textContent, /never raise a spend cap/);
  policy.value = 'auto';
  calls.length = 0;
  await policy.onchange();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/autotune', method: 'PUT', body: {agent_policy: 'auto'}});
});

test('the kill switch disables the controls and says why', async () => {
  reply = {status: status({killed: true, effective_mode: 'off'}), concurrency: concurrency()};
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  assert.match(host.textContent, /Auto-tuning is switched off for this whole server by its administrator/);
  behindDetails(host, /For the server's administrator: CVENGINE_AUTOTUNE=0 is set in the environment/);
  assert.equal(find(host, (n) => n.tag === 'select')[0].disabled, true);
  assert.equal(buttonNamed(host, 'Save')[0].disabled, true);
  reply = {status: status(), concurrency: concurrency()};
});

test('rows carry their badge: auto-tuned with what it was, pinned with who and a hand-back, suggested with Apply, nothing for a kind never tuned', async () => {
  const host = new Node('div');
  await maxxing.cards()[1].build(host);
  const text = host.textContent;
  assert.match(text, /Auto-tunedAuto-tuned: 3 \(was 2\) · nmap runs waited · /);
  assert.match(text, /PinnedPinned by bill <i>x<\/i>: auto-tuning leaves this number alone/);
  assert.match(text, /SuggestedSuggested \(AI advisor\): 3 \(now 2\) · sites waited/);
  assert.doesNotMatch(text, /naabu\)[^]*Auto-tuning may move/);
  calls.length = 0;
  await buttonNamed(host, 'Let auto-tune manage this')[0].onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/autotune/release', method: 'POST', body: {setting: 'heavy.nuclei'}});
  calls.length = 0;
  await buttonNamed(host, 'Apply')[0].onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/autotune/decisions/9/apply', method: 'POST', body: {}});
});

test('the line logic: off says nothing, Suggest offers no hand-back, managed says its range and why it was not raised', () => {
  const tuned = {value: 3, autotune: {managed: true, tuned: true, was: 2, reason: 'r'}};
  assert.equal(logic.autoTuneLine(tuned, 'off').text, '');
  assert.equal(logic.autoTuneLine({autotune: {managed: false}}, 'auto').text, '');
  assert.equal(logic.autoTuneLine({value: 1}, 'auto').text, '');
  const pinned = {autotune: {managed: true, pinned: true, pinned_by: 'bill'}};
  assert.equal(logic.autoTuneLine(pinned, 'auto').release, true);
  assert.equal(logic.autoTuneLine(pinned, 'suggest').release, false);
  const managed = logic.autoTuneLine({value: 2, autotune: {managed: true, min: 1, max: 4, step: 1, why_not_raised: 'no nmap run waited'}}, 'auto');
  assert.equal(managed.text, 'Auto-tuning may move this between 1 and 4 · not raised now: no nmap run waited');
  const sized = logic.autoTuneLine({value: 8, autotune: {managed: true, tuned: true, was: 2, reason: 'aim high', sized_for: '8 cores, 3.4 GB memory budget, 9 Sentinel slots', target: 8}}, 'auto');
  assert.match(sized.text, /^Auto-tuned: 8 \(was 2\) · aim high · sized for this machine: 8 cores, 3\.4 GB memory budget, 9 Sentinel slots \(target 8\)$/);
  assert.match(logic.decisionText({setting: 'x', label: 'X', old_value: 2, new_value: 8, source: 'controller', action: 'raise', applied: true, phase: 'aim_high'}), /^X: aimed high 2 -> 8/);
  assert.match(logic.decisionText({setting: 'x', label: 'X', old_value: 8, new_value: 6, source: 'controller', action: 'lower', applied: true, phase: 'back_off', pressure: true}), /^X: backed off 8 -> 6/);
  assert.match(logic.decisionText({setting: 'x', label: 'X', old_value: 6, new_value: 7, source: 'ai', action: 'raise', applied: false, phase: 'probe'}), /suggested raising 6 -> 7 by AI advisor/);
  assert.match(logic.decisionText({setting: 'x', label: 'X', old_value: 4, new_value: 3, source: 'controller', action: 'lower', applied: true, pressure: true, reason: 'db'}),
    /^X: lowered under pressure 4 -> 3 by controller · db$/);
  assert.match(logic.decisionText({setting: 'x', old_value: 3, new_value: 2, source: 'person', actor: 'bill', action: 'revert', applied: true}), /reverted 3 -> 2 by bill/);
  assert.match(logic.modeNotice({effective_mode: 'suggest'}), /nothing changes until you press Apply/);
  assert.equal(logic.lastRunText(null), 'The tuner has not run yet (it runs every ten minutes).');
});

test('the settings page loads the Auto-tuning card before the other cards', () => {
  const src = readFileSync(new URL('../static/cve/settings.js', import.meta.url), 'utf8');
  const at = src.indexOf('autotune-card.js');
  assert.ok(at > 0 && at < src.indexOf('scan-concurrency-card.js') && at < src.indexOf('tunables-card.js'));
});

test('typing the number auto-tuning chose and saving pins it; an untouched box is never sent', async () => {
  const tuned = {key: 'heavy.nmap', label: 'nmap', min: 1, max: 8, value: 4, source: 'auto'};
  const saved = {key: 'heavy.nuclei', label: 'nuclei', min: 1, max: 8, value: 2, source: 'admin'};
  assert.deepEqual(logic.changesFrom([tuned, saved], {'heavy.nmap': '4', 'heavy.nuclei': '2'}).changes, {});
  assert.deepEqual(logic.changesFrom([tuned, saved], {'heavy.nmap': '4', 'heavy.nuclei': '2'}, new Set(['heavy.nmap', 'heavy.nuclei'])).changes, {'heavy.nmap': 4});
  const fraction = {key: 'g', label: 'gap', min: 0, max: 720, value: 0.5, source: 'environment'};
  assert.deepEqual(logic.changesFrom([fraction], {g: '0.5'}, new Set(['g'])), {changes: {}, error: null});  // put back, not invalid
  const host = new Node('div');
  await maxxing.cards()[1].build(host);
  const nmap = find(host, (n) => n.dataset.key === 'heavy.nmap')[0];
  const save = buttonNamed(host, 'Save')[0];
  assert.equal(save.disabled, true);
  nmap.value = '3';
  nmap.oninput();
  nmap.value = '3';  // the auto-tuned number of this row is 3: typed in again on purpose
  nmap.oninput();
  assert.equal(save.disabled, false);
  calls.length = 0;
  await save.onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scan_concurrency', method: 'PUT', body: {values: {'heavy.nmap': 3}}});
});

test('an environment pin says where it comes from and offers no hand-back', () => {
  const line = logic.autoTuneLine({value: 1, autotune: {managed: true, pinned: true, pinned_by: null, pinned_env: 'HEAVY_MAX_NMAP=1'}}, 'auto');
  assert.equal(line.text, "Fixed by the server's own settings: save a value here to take it over");
  assert.equal(line.release, false);
});

// --- the History: one entry per change, the newest five on the first screen, a Show more for the rest ----------------------------------
const BAD = /\[object|undefined|\bnull\b|NaN|(^|[\s(:→>])\?($|[\s),.:])/;
const entry = (id, over = {}) => ({id, at: new Date(Date.now() - id * 60000).toISOString(), setting: 'discovery_concurrency', label: 'Hosts assessed at once', old_value: 12, new_value: 14,
  source: 'controller', action: 'raise', applied: true, pressure: false, phase: 'probe', reason: 'work waited', resolution: null, can_revert: false, can_apply: false, ...over});
const lines = (host) => find(host, (n) => n.tag === 'li' && /at-line/.test(n.className));
const buildCard = async (history) => {
  reply = {status: status({history}), concurrency: concurrency()};
  const host = new Node('div');
  await maxxing.cards()[0].build(host, {focus: buildCard.focus});
  buildCard.focus = null;
  return host;
};

test('History: the newest five lines, then Show more for the rest, and every line says what, why and what happened', async () => {
  const host = await buildCard(Array.from({length: 8}, (_, i) => entry(i + 1, i === 0 ? {can_revert: true, outcome: 'helped', baseline: {metric: 'discovery_queue', value: 12, after: {metric: 'discovery_queue', value: 3, trouble: 0}}} : {})));
  assert.equal(lines(host).length, 5);
  const first = lines(host)[0];
  assert.match(first.textContent, /^Hosts assessed at once 12 → 14 · auto-tune · 1 min agoWhy: Work waitedWhat happened: scans waiting in the queue 12 → 3, no memory pressure; kept/);
  assert.equal(first.attrs.id, 'configmaxxing-autotune-line-1');
  assert.equal(buttonNamed(host, 'Revert').length, 1);  // only the line the server marks can_revert has one
  const more = find(host, (n) => n.tag === 'button' && /^Show more/.test(n.textContent));
  assert.equal(more.length, 1);
  assert.equal(more[0].textContent, 'Show more (3)');
  await more[0].onclick();
  assert.equal(lines(host).length, 8);
});

test('History: with five lines or fewer there is no Show more, and an empty history is one line', async () => {
  const few = await buildCard([entry(1), entry(2)]);
  assert.equal(lines(few).length, 2);
  assert.equal(find(few, (n) => n.tag === 'button' && /^Show more/.test(n.textContent)).length, 0);
  const none = await buildCard([]);
  assert.equal(lines(none).length, 0);
  assert.match(none.textContent, /No change yet: auto-tune writes a line here for every change it makes\./);
});

test('History: a line the page is pointed at (an alert link) is shown even when it is older than the first five, and is marked', async () => {
  buildCard.focus = '7';
  const host = await buildCard(Array.from({length: 8}, (_, i) => entry(i + 1)));
  assert.equal(lines(host).length, 7);
  assert.match(find(host, (n) => n.attrs.id === 'configmaxxing-autotune-line-7')[0].className, /at-focus/);
  assert.equal(lines(host).filter((n) => /at-focus/.test(n.className)).length, 1);
});

test('History: every decision shape draws without "[object Object]", "undefined", "null", "NaN" or a bare "?", and an undone or revert line has no button', async () => {
  const shapes = [
    entry(1, {outcome: 'regressed', resolution: 'reverted', can_revert: true, baseline: {metric: 'wait_share', value: 0.4, after: {metric: 'wait_share', value: 0.8, trouble: 1}}}),
    entry(2, {action: 'revert', phase: 'verify', pressure: true, outcome: 'reverted', undoes: 1, reason: 'verification of the change of 2026-11-13T13:00: put 14 back to 12', old_value: 14, new_value: 12}),
    entry(3, {applied: false, can_apply: true, mode: 'suggest'}),
    entry(4, {source: 'agent', actor: 'ci-agent', verify_at: new Date(Date.now() + 600000).toISOString()}),
    entry(5, {source: 'ai', outcome: 'unknown', outcome_detail: 'too few measurements'}),
    entry(6, {source: 'person', action: 'revert', actor: 'bill', old_value: null, new_value: null}),
    entry(7, {action: 'release', source: 'person', old_value: null}),
    {id: 8}, {},
  ];
  const host = await buildCard(shapes);
  await find(host, (n) => n.tag === 'button' && /^Show more/.test(n.textContent))[0].onclick();
  assert.equal(lines(host).length, 9);
  lines(host).forEach((n) => assert.doesNotMatch(n.textContent, BAD, n.textContent));
  const undone = lines(host)[0];
  assert.equal(buttonNamed(undone, 'Revert').length, 0);
  assert.equal(buttonNamed(lines(host)[1], 'Revert').length, 0);
  assert.equal(buttonNamed(lines(host)[2], 'Apply').length, 1);
  assert.match(lines(host)[3].textContent, /being checked, result at \d\d:\d\d/);
  assert.match(lines(host)[3].textContent, /an agent \(ci-agent\)/);
});

test('a link can name one History line after the card: #configmaxxing/autotune/12', () => {
  assert.equal(logic.hashItem('#configmaxxing/autotune/12'), '12');
  assert.equal(logic.hashItem('#configmaxxing/autotune'), '');
  assert.equal(logic.hashItem('#configmaxxing'), '');
  assert.equal(logic.hashItem(undefined), '');
  assert.deepEqual(logic.parseHash('#configmaxxing/autotune/12'), {section: 'configmaxxing', card: 'autotune'});
});

test('the advisor note says in words when today\'s count is not known', async () => {
  const unknown = status();
  unknown.advisor = {...unknown.advisor, used_today: null};
  reply = {status: unknown, concurrency: concurrency()};
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  assert.match(host.textContent, /Used today: not known yet, limit 8/);
  assert.doesNotMatch(host.textContent, /\?/);
  reply = {status: status(), concurrency: concurrency()};
});

test('the AI advisor switch says it also covers the health check\'s proposals', async () => {
  const host = await buildCard([]);
  assert.match(host.textContent, /This switch covers the AI advisor and the changes the server health check .* may propose\. The health check is an AI agent: its proposals follow the mode above and the setting for AI agents below, and are suggestions unless both are Automatic\./);
});

test('a worker lane left alone says why, in words', () => {
  const line = logic.autoTuneLine({value: 3, autotune: {managed: false, why_not_managed: 'this lane is set to 3, which is at or below its floor of 3'}}, 'auto');
  assert.match(line.text, /^Not auto-tuned: this lane is set to 3/);
  assert.equal(logic.autoTuneLine({value: 3, autotune: {managed: false, why_not_managed: 'x'}}, 'off').text, '');
});
