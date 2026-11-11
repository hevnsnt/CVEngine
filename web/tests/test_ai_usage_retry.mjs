import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// AI usage page: Retry on "could not be read" puts the waiting placeholder back while the read runs again (the error box does not stay on screen).
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
const mount = new Page('div');
globalThis.document = {
  createElement: (tag) => new Page(tag), createTextNode: (t) => ({nodeType: 3, textContent: t}), getElementById: (id) => (id === 'ai-usage' ? mount : null), querySelector: () => null, querySelectorAll: () => [],
  addEventListener() {}, removeEventListener() {}, visibilityState: 'hidden', cookie: '', body: new Page('body'), activeElement: null,
  defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };
const pending = [];
let failNext = true;
globalThis.fetch = (url) => new Promise((resolve) => {
  if (failNext) { failNext = false; resolve({ok: false, status: 503, headers: {get: () => null}, json: async () => ({error: 'down'})}); return; }
  pending.push(resolve);
});
const tick = () => new Promise((r) => setTimeout(r, 20));

test('Retry swaps the error box for the waiting placeholder while the read runs again', async () => {
  await import('../static/cve/ai-usage.js');
  await tick();
  assert.match(mount.textContent, /could not be read/);
  const retry = mount.querySelectorAll('button').find((b) => b.textContent === 'Retry');
  assert.ok(retry, 'a Retry button');
  retry.fire('click');
  await tick();
  assert.equal(pending.length, 1, 'the read was asked again');
  assert.match(mount.textContent, /Loading recorded AI attempts/);
  assert.doesNotMatch(mount.textContent, /could not be read|Checking again/);
});
