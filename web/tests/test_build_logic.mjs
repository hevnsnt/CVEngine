import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {buildAction} from '../static/cve/build-logic.js';

// What a page does when the server runs another build than the one that rendered it (static/cve/build-logic.js), and how sitewatch.js acts on it.
const base = {page: 'aaa', server: 'bbb', hidden: false, dirty: false, dialog: false, reloadedFor: null};

test('the same build, or one nobody knows, does nothing', () => {
  assert.equal(buildAction({...base, server: 'aaa'}), 'none');
  assert.equal(buildAction({...base, server: ''}), 'none');
  assert.equal(buildAction({...base, page: ''}), 'none'); // a page from before pages carried a build
});

test('a visible, idle page reloads; a background page waits until it is shown', () => {
  assert.equal(buildAction(base), 'reload');
  assert.equal(buildAction({...base, hidden: true}), 'wait');
});

test('typed input or an open dialog is never reloaded away: the bar is offered instead', () => {
  assert.equal(buildAction({...base, dirty: true}), 'bar');
  assert.equal(buildAction({...base, dialog: true}), 'bar');
});

test('a tab that already reloaded for this build gets the bar, never a second reload; a newer build reloads again', () => {
  assert.equal(buildAction({...base, reloadedFor: 'bbb'}), 'bar');
  assert.equal(buildAction({...base, reloadedFor: 'ccc'}), 'reload');
});

// --- sitewatch.js itself, with just enough of a browser ---------------------------------------------------------------------------------------
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

const listeners = {};
const appended = [];
let pageBuild = 'aaa';
const store = new Map();
let dialogOpen = false;
const reloads = [];
const element = () => ({setAttribute() {}, append(...n) { this.kids = n; }, remove() {}, hidden: false});
globalThis.document = {
  hidden: false,
  body: {append: (n) => appended.push(n)},
  querySelector: (q) => (q.startsWith('meta') ? {getAttribute: () => pageBuild} : q.startsWith('dialog') ? (dialogOpen ? {} : null) : null),
  querySelectorAll: () => [],
  createElement: element,
  documentElement: {classList: {add() {}, remove() {}}},
  addEventListener: (type, fn) => ((listeners[type] ||= []).push(fn)),
};
globalThis.window = globalThis;
globalThis.addEventListener = (type, fn) => ((listeners['window:' + type] ||= []).push(fn));
globalThis.location = {href: 'http://x/cve/settings/', origin: 'http://x', reload: () => reloads.push('reload'), replace: (u) => reloads.push(u)};
globalThis.sessionStorage = {getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v)};
globalThis.performance = {getEntriesByType: () => []};
globalThis.fetch = async () => ({ok: true, status: 200, text: async () => '', json: async () => ({ok: true})});
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (...a) => { const t = realSetTimeout(...a); t.unref?.(); return t; };

const {noteBuild} = await import('../static/cve/sitewatch.js');
const settle = () => new Promise((r) => realSetTimeout(r, 30));

test('a build mismatch reloads once, remembers it, and the next mismatch for the same build shows the bar', async () => {
  noteBuild('bbb');
  await settle();
  assert.deepEqual(reloads, ['reload']);
  assert.equal(store.get('cvengine-build-reloaded'), 'bbb');
  noteBuild('bbb');
  await settle();
  assert.deepEqual(reloads, ['reload']);
  assert.equal(appended.length, 1);
  assert.equal(appended[0].className, 'toast notice');
});

test('an open dialog, typed input or an unusable storage get the bar and no reload', async () => {
  store.clear();
  appended.length = 0;
  reloads.length = 0;
  dialogOpen = true;
  noteBuild('ccc');
  await settle();
  assert.deepEqual(reloads, []);
  dialogOpen = false;
  globalThis.sessionStorage = {getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); }};
  noteBuild('ddd');
  await settle();
  assert.deepEqual(reloads, []);
});

test('a page that comes back to the front is checked at once', async () => {
  let asked = 0;
  globalThis.fetch = async () => { asked += 1; return {ok: true, status: 200, text: async () => '', json: async () => ({ok: true, build: 'aaa'})}; };
  assert.ok(listeners.visibilitychange.length);
  for (const f of listeners.visibilitychange) f();
  await settle();
  assert.ok(asked >= 1);
});

test('what the person typed keeps the page from being reloaded away (an untrusted, scripted input event does not)', async () => {
  store.clear();
  appended.length = 0;
  reloads.length = 0;
  globalThis.sessionStorage = {getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v)};
  listeners.input[0]({isTrusted: false});
  noteBuild('eee');
  await settle();
  assert.deepEqual(reloads, ['reload']);
  store.clear();
  listeners.input[0]({isTrusted: true});
  noteBuild('fff');
  await settle();
  assert.deepEqual(reloads, ['reload']); // typed: no second reload (the bar made earlier is still the one on screen)
});
