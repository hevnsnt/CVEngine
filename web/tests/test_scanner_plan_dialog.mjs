import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// The Update button's question and the Sentinels page's "Which scanners run" control (static/cve/scanner-plan.js), against a tiny DOM and a fake server.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this._text = ''; this.className = ''; this.disabled = false; this.hidden = false; this.listeners = {}; this.checked = false; this.isConnected = true; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'value') this.value = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  appendChild(k) { this.children.push(k); return k; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  fire(type) { (this.listeners[type] || []).forEach((fn) => fn({target: this})); }
  showModal() { this.open = true; }
  close() { if (this.open) { this.open = false; this.fire('close'); } }
  focus() { globalThis.focused = this; }
  remove() {}
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
const named = (root, text) => find(root, (n) => n.tag === 'button' && n.textContent === text)[0];

const body = new Node('body');
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: (sel) => (sel.includes('csrf') ? {value: 'csrf-token'} : null),
  querySelectorAll: () => [],
  cookie: '',
  body,
};
globalThis.localStorage = {getItem: () => null, setItem() {}};
const timers = [];
globalThis.setTimeout = (fn) => { timers.push(fn); return timers.length; };
globalThis.clearTimeout = () => {};
const flush = () => { while (timers.length) timers.shift()(); };

const calls = [];
let settings = null;
let refuse = false;
globalThis.fetch = async (url, opts = {}) => {
  calls.push({url, method: opts.method, body: opts.body && JSON.parse(opts.body)});
  if (refuse) return {ok: false, status: 403, json: async () => ({error: 'superuser only'})};
  return {ok: true, status: 200, json: async () => settings};
};

const choice = (over = {}) => ({
  needs_choice: true, recommended: 'external', memory_line: 'This server has 4.5 GB of memory; the built-in scanner reserves up to 1 GB.',
  options: [
    {value: 'external', recommended: true, label: 'Use my own Sentinels only (recommended: you have 2 live; frees up to 1 GB)'},
    {value: 'internal', recommended: false, label: 'Use the built-in scanner only'},
    {value: 'both', recommended: false, label: 'Use both'},
  ], ...over,
});

const {askScannerPlan, mountScannerPlan, planChoices} = await import('../static/cve/scanner-plan.js');
const dialogOf = () => find(body, (n) => n.tag === 'dialog').at(-1);

test('the dialog says the memory fact in one line, offers three radios and one button, and checks the recommended one', async () => {
  const answer = askScannerPlan(choice());
  const d = dialogOf();
  assert.equal(d.attrs['aria-label'], 'Which scanners should run?');
  assert.ok(d.open);
  const text = d.textContent;
  assert.match(text, /This server has 4\.5 GB of memory; the built-in scanner reserves up to 1 GB\./);
  assert.match(text, /Use my own Sentinels only \(recommended: you have 2 live; frees up to 1 GB\)/);
  assert.match(text, /Use the built-in scanner only/);
  assert.match(text, /Use both/);
  const radios = find(d, (n) => n.tag === 'input' && n.attrs.type === 'radio');
  assert.deepEqual(radios.map((r) => r.attrs.value), ['external', 'internal', 'both']);
  assert.deepEqual(radios.map((r) => r.checked), [true, false, false]);
  assert.equal(new Set(radios.map((r) => r.attrs.name)).size, 1);  // one group: the arrow keys move between them
  const buttons = find(d, (n) => n.tag === 'button').map((b) => b.textContent);
  assert.deepEqual(buttons, ['Cancel', 'Update now']);
  named(d, 'Update now').onclick();
  assert.equal(await answer, 'external');
});

test('focus starts on the chosen radio, so Enter and the arrow keys work from the keyboard', async () => {
  const answer = askScannerPlan(choice());
  flush();
  const d = dialogOf();
  assert.equal(globalThis.focused, find(d, (n) => n.tag === 'input' && n.checked)[0]);
  d.close();  // Escape closes a native dialog: nothing is started
  assert.equal(await answer, null);
});

test('another radio, then Update now, answers with that one; Cancel answers nothing', async () => {
  let answer = askScannerPlan(choice({recommended: 'both'}));
  let d = dialogOf();
  const radios = find(d, (n) => n.tag === 'input' && n.attrs.type === 'radio');
  radios.forEach((r) => { r.checked = r.attrs.value === 'internal'; });
  named(d, 'Update now').onclick();
  assert.equal(await answer, 'internal');
  answer = askScannerPlan(choice());
  d = dialogOf();
  named(d, 'Cancel').onclick();
  assert.equal(await answer, null);
});

test('every choice sits in a label that is the target, and the style gives it at least 44px', () => {
  const group = planChoices(choice().options, 'both').group;
  assert.ok(find(group, (n) => n.tag === 'label' && n.className === 'plan-opt').length === 3);
  const css = readFileSync(new URL('../static/cve/cve.css', import.meta.url), 'utf8');
  assert.match(css, /\.plan-opt\{[^}]*min-height:44px/);
  assert.ok(find(group, (n) => n.tag === 'legend').length === 1);
});

test('no wording of the control or the dialog has a long dash', () => {
  const source = readFileSync(new URL('../static/cve/scanner-plan.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /[\u2013\u2014]/);
  const css = readFileSync(new URL('../static/cve/cve.css', import.meta.url), 'utf8');
  assert.doesNotMatch(css.slice(css.indexOf('which scanners run')), /[\u2013\u2014]/);
});

const state = (over = {}) => ({...choice(), plan: 'internal', pending_plan: '', waiting: false, applied: null, notice: null, ...over});

test('the Sentinels page control shows the notice and the three options, and Apply posts the choice', async () => {
  settings = state({notice: {text: 'The built-in scanner was kept at 1 GB. You have 2 Sentinels of your own: switch to Sentinels only in Settings > Sentinels to free the memory.'}});
  const host = new Node('div');
  await mountScannerPlan(host);
  assert.equal(host.hidden, false);
  assert.match(host.textContent, /^Which scanners run/);
  assert.match(host.textContent, /The built-in scanner was kept at 1 GB\. You have 2 Sentinels of your own/);
  const radios = find(host, (n) => n.tag === 'input' && n.attrs.type === 'radio');
  assert.deepEqual(radios.map((r) => r.checked), [false, true, false]);  // the plan now (internal), not the recommendation
  assert.match(host.textContent, /Now: the built-in scanner only\./);
  radios.forEach((r) => { r.checked = r.attrs.value === 'external'; });
  calls.length = 0;
  settings = state({waiting: true, pending_plan: 'external'});
  await named(host, 'Apply').onclick();
  assert.deepEqual(calls[0], {url: '/cve/api/settings/scanner_plan', method: 'POST', body: {plan: 'external'}});
  assert.match(host.textContent, /Applying the change\./);
});

test('someone who may not change it sees nothing', async () => {
  refuse = true;
  const host = new Node('div');
  await mountScannerPlan(host);
  assert.equal(host.hidden, true);
  assert.equal(host.textContent, '');
  refuse = false;
});

test('the host answer is shown in words', async () => {
  settings = state({plan: 'external', applied: {plan: 'external', ok: true, note: 'Sentinels of your own only (the built-in scanner is removed); the built-in scanner was removed'}});
  const host = new Node('div');
  await mountScannerPlan(host);
  assert.match(host.textContent, /Done: Sentinels of your own only/);
});

// ---- the status line is truthful: what it waits on, "Done at", the reason when it failed, and no stale words ----
const {planLine} = await import('../static/cve/scanner-plan.js');
const {fmtTime} = await import('../static/cve/prefs.js');
const hhmm = (epoch) => fmtTime(new Date(epoch * 1000).toISOString(), false);
const T0 = 1_800_000_000;

test('while it waits the line says what it waits on, in plain words, and when it was asked', () => {
  const on = (code, text) => planLine(state({waiting: true, pending_plan: 'external', asked_at: T0, waiting_on: {code, text}}));
  for (const [code, text] of [
    ['pickup', 'The host updater has not picked it up yet. It looks every few seconds.'],
    ['scans', '3 scans are running. The change is applied when they finish, because the server restarts to read it.'],
    ['update', 'An update is building and restarting this server. The change is applied by the host once it has finished.'],
    ['host_down', 'The host helper is not running, so nothing will apply this. It has never reported in on this server.'],
  ]) {
    const line = on(code, text);
    assert.equal(line.kind, 'busy');
    assert.ok(line.text.startsWith('Applying the change. ' + text), line.text);
    assert.ok(line.text.endsWith(`Asked at ${hhmm(T0)}.`), line.text);
  }
});

test('done: "Done at" the local time, what changed, and the host note', () => {
  const s = state({plan: 'external', applied: {plan: 'external', ok: true, note: 'Sentinels of your own only (the built-in scanner is removed)', at: T0}});
  const line = planLine(s, {now: (T0 + 3) * 1000, before: 'internal'});
  assert.equal(line.kind, 'ok');
  assert.equal(line.text, `Done at ${hhmm(T0)}: changed from the built-in scanner only to your own Sentinels only. The host says: Sentinels of your own only (the built-in scanner is removed).`);
  assert.match(planLine(s, {now: (T0 + 3) * 1000}).text, /^Done at \d\d:\d\d: now your own Sentinels only\./);
});

test('a finished answer is not shown again once cleared or after five minutes: the line says what runs now', () => {
  const s = state({plan: 'external', applied: {plan: 'external', ok: true, note: 'n', at: T0}});
  assert.equal(planLine(s, {now: (T0 + 20) * 1000, cleared: T0}).text, 'Now: your own Sentinels only.');
  assert.equal(planLine(s, {now: (T0 + 301) * 1000}).text, 'Now: your own Sentinels only.');
  assert.equal(planLine(s, {now: (T0 + 299) * 1000}).kind, 'ok');
});

test('a failure shows the reason and what to do, and stays until the next Apply', () => {
  const s = state({applied: {plan: 'external', ok: false, note: 'the choice is saved but the services could not be restarted (see /x/scanner-plan.log)', at: T0}});
  const line = planLine(s, {now: (T0 + 3600) * 1000});
  assert.equal(line.kind, 'err');
  assert.match(line.text, /^Not done \(\d\d:\d\d\): the choice is saved but the services could not be restarted/);
  assert.match(line.text, /What to do: open scanner-plan\.log in the host's update state directory/);
  assert.match(line.text, /press Apply again\.$/);
});

test('the page: waiting, then the host answers, shows Done at, and the answer clears itself', async () => {
  const realNow = Date.now;
  const at = Math.floor(realNow() / 1000);
  settings = state({waiting: true, pending_plan: 'external', asked_at: at, waiting_on: {code: 'pickup', text: 'The host updater has not picked it up yet. It looks every few seconds.'}});
  const host = new Node('div');
  timers.length = 0;
  await mountScannerPlan(host);
  assert.match(host.textContent, /Applying the change\. The host updater has not picked it up yet\./);
  settings = state({plan: 'external', applied: {plan: 'external', ok: true, note: 'done', at}});
  timers.shift()();  // the poll
  await new Promise((r) => setImmediate(r));
  assert.match(host.textContent, new RegExp(`Done at ${hhmm(at)}: now your own Sentinels only`));
  assert.doesNotMatch(host.textContent, /Applying the change/);
  assert.equal(timers.length, 1);  // no more polling, only the clear timer
  timers.shift()();
  assert.match(host.textContent, /Now: your own Sentinels only\./);
  assert.doesNotMatch(host.textContent, /Done at/);
});

test('the poll does not leave "Applying" up when the server cannot be reached or the person is signed out', async () => {
  settings = state({waiting: true, pending_plan: 'external', waiting_on: {code: 'pickup', text: 'x'}});
  const host = new Node('div');
  timers.length = 0;
  await mountScannerPlan(host);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ok: false, status: 502, json: async () => { throw new Error('html'); }});
  for (let i = 0; i < 2; i++) { timers.shift()(); await new Promise((r) => setImmediate(r)); }
  assert.match(host.textContent, /Cannot reach the server to see how the change is going/);
  assert.doesNotMatch(host.textContent, /Applying the change/);
  assert.equal(timers.length, 1);  // still trying
  globalThis.fetch = async () => ({ok: true, status: 200, json: async () => { throw new Error('login page'); }});  // a login page: 200 and no JSON
  timers.shift()(); await new Promise((r) => setImmediate(r));
  assert.match(host.textContent, /You are signed out/);
  assert.equal(timers.length, 0);
  globalThis.fetch = realFetch;
});
