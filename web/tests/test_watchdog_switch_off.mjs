import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// Switching a watchdog rule (or the whole watchdog) off asks first and says what stops being watched; switching on does not ask.
// What a rule does is visible text under its title, not only a hover tooltip.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
class Dialog extends Page {
  showModal() { this.open = true; }
  close() { this.open = false; this.fire('close'); }
}
globalThis.document = {
  createElement: (tag) => (tag === 'dialog' ? new Dialog(tag) : new Page(tag)), body: new Page('body'), cookie: '', querySelector: () => null,
  querySelectorAll: () => [], addEventListener() {}, removeEventListener() {}, visibilityState: 'visible', activeElement: null,
  defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => { const t = realSetTimeout(fn, ms > 1000 ? 1e9 : ms, ...a); t.unref?.(); return t; };

const DOES = 'Restarts a worker lane that has stopped taking work.';
const state = (on) => ({
  enabled: true, env_off: false, running: true, tick_age_seconds: 3, changes: [], events: [],
  rules: [{code: 'R1', title: 'Quiet lane', does: DOES, status: on ? 'ok' : 'off', color: 'green', text: 'Fine.', enabled: on}],
});
const posts = [];
globalThis.fetch = async (url, opts = {}) => {
  if (opts.method === 'POST') posts.push(JSON.parse(opts.body));
  const body = opts.method === 'POST' && posts.length ? state(posts[posts.length - 1].enabled !== false) : state(true);
  return {ok: true, status: 200, headers: {get: () => null}, json: async () => body};
};
const tick = () => new Promise((r) => realSetTimeout(r, 20));
const press = (b) => (b.onclick ? b.onclick() : b.fire('click'));
const button = (label, within = document.body) => within.querySelectorAll('button').find((b) => b.textContent === label);

const {watchdogPanel} = await import('../static/cve/watchdog-panel.js');
const mount = new Page('div');
document.body.append(mount);
await watchdogPanel(mount);

test('what a rule does is visible text, not only a tooltip', () => {
  assert.match(mount.textContent, /Restarts a worker lane that has stopped taking work\./);
});

test('Switch off on a rule asks first, names what stops being watched, and sends nothing until confirmed', async () => {
  const rule = mount.querySelectorAll('li')[0];
  press(button('Switch off', rule));
  await tick();
  assert.equal(posts.length, 0, 'nothing sent before the answer');
  const dlg = document.body.querySelectorAll('dialog')[0];
  assert.ok(dlg, 'a confirmation dialog');
  assert.match(dlg.textContent, /stops/i);
  assert.match(dlg.textContent, /Restarts a worker lane/);
  press(button('Cancel', dlg));
  await tick();
  assert.equal(posts.length, 0, 'Cancel sends nothing');
});

test('Confirming sends the switch-off once', async () => {
  const rule = mount.querySelectorAll('li')[0];
  press(button('Switch off', rule));
  await tick();
  const dlg = document.body.querySelectorAll('dialog')[0];
  press(button('Switch it off', dlg));
  await tick();
  assert.deepEqual(posts, [{rule: 'R1', enabled: false}]);
});

test('Switching the whole watchdog off asks too, and says every rule stops', async () => {
  posts.length = 0;
  const head = mount.querySelectorAll('div').find((d) => /wd-head/.test(d.className));
  press(button('Switch off', head));
  await tick();
  assert.equal(posts.length, 0);
  const dlg = document.body.querySelectorAll('dialog')[0];
  assert.match(dlg.textContent, /every rule|all the rules|nothing is watched/i);
  press(button('Cancel', dlg));
});

test('a watchdog switched off by the server says so in plain words; the variable name is behind Details', async () => {
  const off = {...state(true), env_off: true, enabled: true};
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ok: true, status: 200, headers: {get: () => null}, json: async () => off});
  const box = new Page('div');
  document.body.append(box);
  await watchdogPanel(box);
  const badges = box.querySelectorAll('span').filter((s) => /(^| )badge( |$)/.test(s.className)).map((s) => s.textContent);
  assert.ok(badges.some((t) => /Switched off by the server's administrator/.test(t)), badges.join('|'));
  assert.ok(!badges.some((t) => /CVENGINE_/.test(t)), 'no variable name in the badge');
  assert.match(box.textContent, /Details/);
  globalThis.fetch = realFetch;
});
