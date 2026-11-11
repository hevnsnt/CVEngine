import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// More than three open admin alerts: the overflow line is a link to the Scanners page (where the operations problems are laid out), not a
// sentence about the AI model.
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
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
const five = Array.from({length: 5}, (_, i) => ({id: `a${i}`, title: `Alert ${i}`, severity: 'warning', detail: ''}));
globalThis.fetch = async () => ({ok: true, status: 200, json: async () => ({alerts: five})});
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };

globalThis.__log = []; await import('../static/cve/alertbar.js').catch((e) => console.log('IMPORT', e));
await new Promise((r) => setTimeout(r, 20));

test('the overflow notice is a link to the Scanners page and does not mention the AI model', () => {
  const more = globalThis.__notices.find((i) => i.kind === 'more');
  assert.ok(more, 'an overflow notice');
  const a = more.node.tagName.toLowerCase() === 'a' ? more.node : more.node.querySelectorAll('a')[0];
  assert.ok(a, 'an anchor');
  assert.equal(a.getAttribute('href'), '/cve/scanners/');
  assert.match(more.node.textContent, /2 more alerts/);
  assert.doesNotMatch(more.node.textContent, /AI model/);
  assert.doesNotMatch(more.text, /AI model/);
});
