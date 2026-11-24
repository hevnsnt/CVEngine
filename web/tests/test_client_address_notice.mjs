import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// The client address notice in the status strip (cveFeed/client_address.py, alertbar.js, client-address-notice.js): an alert the server marks with
// `snippet` carries Show the lines, Copy and Check again. The lines hold the install's secret, so nothing fetches them until a button is pressed,
// Copy puts exactly what the server sent on the clipboard, and a passing Check again takes the notice away.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier === '/staticfiles/cve/statusstrip.js') {
    return {url: 'data:text/javascript,export const setNotices=(k,i)=>{globalThis.__notices=i;};', format: 'module', shortCircuit: true};
  }
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.document = {createElement: (tag) => new Page(tag), querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, hidden: false, body: new Page('body')};
globalThis.window = globalThis;
globalThis.isSecureContext = true;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
const copied = [];
Object.defineProperty(globalThis, 'navigator', {value: {clipboard: {writeText: async (t) => { copied.push(t); }}}, configurable: true});
const LINES = 'proxy_set_header X-Forwarded-For $remote_addr;\nproxy_set_header X-CVEngine-Upstream "s3cret";\n';
const calls = [];
let passes = false;
globalThis.fetch = async (url, opts = {}) => {
  calls.push([url, opts.method || 'GET']);
  if (url === '/cve/api/settings/client_address/snippet') return {ok: true, status: 200, json: async () => ({snippet: LINES})};
  if (url === '/cve/api/settings/client_address/recheck') return {ok: true, status: 200, json: async () => ({kind: passes ? 'ok' : 'unknown', notice: passes ? null : {id: 1}})};
  return {ok: true, status: 200, json: async () => ({alerts: [
    {id: 1, code: 'client_address', title: "Visitors' own addresses do not reach cvENGINE yet", severity: 'warning', detail: 'd', snippet: true},
    {id: 2, code: 'memory', title: 'A lane is near its limit', severity: 'warning', detail: 'd'}]})};
};
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };
await import('../static/cve/alertbar.js');
await new Promise((r) => setTimeout(r, 20));

const buttonsOf = (node) => node.querySelectorAll('button').filter((b) => b.textContent !== 'Dismiss');
const press = async (b) => { for (const [type, fn] of b.listeners || []) if (type === 'click') await fn(); };

test('only the notice the server marks carries the tools, and nothing is fetched before a press', () => {
  const [notice, other] = globalThis.__notices.filter((i) => i.kind === 'alert');
  assert.deepEqual(buttonsOf(notice.node).map((b) => b.textContent), ['Show the lines', 'Copy', 'Check again']);
  assert.deepEqual(buttonsOf(other.node), []);
  assert.equal(calls.filter(([u]) => u.includes('client_address')).length, 0);
});

test('Copy puts the lines the server sent on the clipboard', async () => {
  const [notice] = globalThis.__notices.filter((i) => i.kind === 'alert');
  await press(buttonsOf(notice.node)[1]);
  assert.deepEqual(copied, [LINES]);
});

test('Check again posts, and a passing check takes the notice away', async () => {
  let [notice] = globalThis.__notices.filter((i) => i.kind === 'alert');
  await press(buttonsOf(notice.node)[2]);
  assert.deepEqual(calls.at(-1), ['/cve/api/settings/client_address/recheck', 'POST']);
  assert.equal(globalThis.__notices.filter((i) => i.kind === 'alert').length, 2);  // not yet
  passes = true;
  [notice] = globalThis.__notices.filter((i) => i.kind === 'alert');
  await press(buttonsOf(notice.node)[2]);
  assert.deepEqual(globalThis.__notices.filter((i) => i.kind === 'alert').map((i) => i.text), ['A lane is near its limit']);
});
