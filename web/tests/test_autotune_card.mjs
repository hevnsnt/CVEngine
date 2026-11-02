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
  assert.match(text, /Port and service scan \(nmap\): raised 2 -> 3 by controller · nmap runs waited <b>x<\/b>/);  // text, never markup
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

test('the kill switch disables the controls and says why', async () => {
  reply = {status: status({killed: true, effective_mode: 'off'}), concurrency: concurrency()};
  const host = new Node('div');
  await maxxing.cards()[0].build(host);
  assert.match(host.textContent, /CVENGINE_AUTOTUNE=0 is set in the environment/);
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
  assert.equal(line.text, 'Pinned by the environment (HEAVY_MAX_NMAP=1): remove it from .env, or save a value here');
  assert.equal(line.release, false);
});
