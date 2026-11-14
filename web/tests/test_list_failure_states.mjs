import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';
import {Text} from './fake_dom.mjs';

// A list that could not be read says so and offers Retry; it never reads as an empty list ("No Sentinel has registered yet", "No organization").
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.document = {
  createElement: (tag) => new Page(tag), createTextNode: (t) => new Text(t), getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
  addEventListener() {}, removeEventListener() {}, visibilityState: 'visible', cookie: '', body: new Page('body'), activeElement: null,
  defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};

// the page polls on intervals; none of them may keep the test process alive
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };

let answerWith = () => ({ok: false, status: 503, headers: {get: () => null}, json: async () => ({error: 'down'})});
let calls = 0;
globalThis.fetch = async () => { calls += 1; return answerWith(); };
const tick = () => new Promise((r) => setTimeout(r, 20));
const retryOf = (root) => root.querySelectorAll('button').find((b) => b.textContent === 'Retry');

test('the Sentinels list: placeholder first, then "could not be read" with Retry, never "No Sentinel has registered yet"', async () => {
  const {sentinelLive} = await import('../static/cve/sentinel-live.js');
  const mount = new Page('div');
  const stop = sentinelLive(mount);
  assert.match(mount.textContent, /Checking the Sentinels/);
  await tick();
  assert.match(mount.textContent, /could not be read/);
  assert.doesNotMatch(mount.textContent, /No Sentinel has registered/);
  assert.ok(retryOf(mount), 'a Retry button');
  const before = calls;
  retryOf(mount).fire('click');
  await tick();
  assert.ok(calls > before, 'Retry asks again');
  stop(); // the page polls on a timer; stop it so the test process can end
});

test('the API keys scope list: a failed read of organizations or projects is not "create one first"', async () => {
  const {apiKeysPanel} = await import('../static/cve/api-keys-panel.js');
  const mount = new Page('div');
  await apiKeysPanel(mount);
  assert.match(mount.textContent, /could not be read/);
  assert.doesNotMatch(mount.textContent, /Create an organization or a project first/);
  assert.ok(retryOf(mount));
});


test('API keys scopes: organizations failed but projects loaded still says the organizations could not be read, above the rest', async () => {
  const {apiKeysPanel} = await import('../static/cve/api-keys-panel.js');
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (/\/admin\/orgs\/?(\?|$)/.test(u)) return {ok: false, status: 503, headers: {get: () => null}, json: async () => ({error: 'down'})};
    if (/\/api\/v1\/projects\/?(\?|$)/.test(u)) return {ok: true, status: 200, headers: {get: () => null}, json: async () => ({results: [{slug: 'p1', name: 'Project one'}]})};
    return {ok: true, status: 200, headers: {get: () => null}, json: async () => ({results: [], services: []})};
  };
  try {
    const mount = new Page('div');
    await apiKeysPanel(mount);
    assert.match(mount.textContent, /could not be read/, 'the failed read is said');
    assert.ok(retryOf(mount), 'with Retry');
    assert.match(mount.textContent, /Project one/, 'and the project that did load is still offered');
  } finally {
    globalThis.fetch = real;
  }
});
