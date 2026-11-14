import assert from 'node:assert/strict';
import {register} from 'node:module';
import {mock, test} from 'node:test';

import {Page} from './fake_page.mjs';

// api() GET: the 75 second limit covers the body. A fake response whose json() never settles ends as an error, not a page that waits for ever;
// a write has no limit.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.document = {createElement: (tag) => new Page(tag), body: new Page('body'), cookie: '', querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, documentElement: new Page('html')};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};

const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r)); };
mock.timers.enable({apis: ['setTimeout']});
const {api} = await import('../static/cve/ui.js');
const {REQUEST_MS} = await import('../static/cve/poll.js');

test('api GET: headers arrive, json() never settles: TimeoutError after the limit', async () => {
  globalThis.fetch = async () => ({ok: true, status: 200, json: () => new Promise(() => {})});
  let outcome = 'pending';
  api('GET', '/x').then(() => { outcome = 'ok'; }, (e) => { outcome = e.name; });
  await flush();
  assert.equal(outcome, 'pending');
  mock.timers.tick(REQUEST_MS + 1);
  await flush();
  assert.equal(outcome, 'TimeoutError');
});

test('api GET with a body that arrives returns it; an error status still carries the server message', async () => {
  globalThis.fetch = async () => ({ok: true, status: 200, json: async () => ({a: 1})});
  assert.deepEqual(await api('GET', '/x'), {a: 1});
  globalThis.fetch = async () => ({ok: false, status: 400, json: async () => ({error: 'Bad scope.'})});
  await assert.rejects(api('GET', '/x'), /Bad scope\./);
});

test('api POST has no time limit', async () => {
  globalThis.fetch = (url, init) => { assert.equal(init.signal, undefined); return Promise.resolve({ok: true, status: 200, json: async () => ({saved: 1})}); };
  assert.deepEqual(await api('POST', '/x', {a: 1}), {saved: 1});
});
