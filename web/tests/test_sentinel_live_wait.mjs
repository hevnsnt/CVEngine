import assert from 'node:assert/strict';
import {register} from 'node:module';
import {mock, test} from 'node:test';

import {Page} from './fake_page.mjs';

// The Sentinels page with fake timers: a first read that never answers ends in "could not be read" with Retry after the time limit; Retry starts
// the "taking longer than usual" count again; stopping the page clears its timers.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.document = {
  createElement: (tag) => new Page(tag), getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
  addEventListener() {}, removeEventListener() {}, visibilityState: 'visible', cookie: '', body: new Page('body'), activeElement: null,
  defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
let calls = 0;
globalThis.fetch = (url, init = {}) => new Promise((resolve, reject) => {
  calls += 1;
  if (init.signal) init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})));
});
const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r)); };
const retryOf = (root) => root.querySelectorAll('button').find((b) => b.textContent === 'Retry');

mock.timers.enable({apis: ['setTimeout', 'setInterval']});
const {REQUEST_MS} = await import('../static/cve/poll.js');
const {SLOW_MS} = await import('../static/cve/ui.js');
const {sentinelLive} = await import('../static/cve/sentinel-live.js');
const mount = new Page('div');
const stop = sentinelLive(mount);

test('a first read that never answers ends in "could not be read" with Retry', async () => {
  assert.match(mount.textContent, /Checking the Sentinels/);
  mock.timers.tick(SLOW_MS + 1);
  await flush();
  assert.match(mount.textContent, /taking longer than usual/);
  mock.timers.tick(REQUEST_MS);
  await flush();
  assert.match(mount.textContent, /could not be read/);
  assert.doesNotMatch(mount.textContent, /Checking the Sentinels|No Sentinel has registered/);
  assert.ok(retryOf(mount), 'a Retry button');
});

test('Retry starts the wait again, with its own "taking longer than usual" mark', async () => {
  const before = calls;
  retryOf(mount).fire('click');
  await flush();
  assert.ok(calls > before, 'Retry asks again');
  assert.match(mount.textContent, /Checking the Sentinels/);
  assert.doesNotMatch(mount.textContent, /taking longer than usual/, 'the count began again');
  mock.timers.tick(SLOW_MS + 1);
  await flush();
  assert.match(mount.textContent, /taking longer than usual/);
});

test('stopping the page clears its timers: the mark does not arrive after the stop', async () => {
  mock.timers.tick(REQUEST_MS);
  await flush();
  retryOf(mount).fire('click');
  await flush();
  stop();
  mock.timers.tick(SLOW_MS + 1);
  await flush();
  assert.doesNotMatch(mount.textContent, /taking longer than usual/);
});
