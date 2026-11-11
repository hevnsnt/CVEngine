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

const alertRows = () => globalThis.__notices.filter((i) => i.kind === 'alert');
const moreItem = () => globalThis.__notices.find((i) => i.kind === 'more');
const toggleOf = (item) => item.node.querySelectorAll('button')[0];

test('more than three alerts: the overflow line is a button, not a link to another page', () => {
  const more = moreItem();
  assert.ok(more, 'an overflow notice');
  assert.equal(more.node.querySelectorAll('a').length, 0, 'no link: no other page lists the alerts');
  assert.match(more.node.textContent, /2 more alerts/);
  assert.doesNotMatch(more.node.textContent, /AI model|Open Scanners/);
  assert.equal(alertRows().length, 3);
});

test('pressing it opens the full list in place, and Show fewer folds it back', () => {
  toggleOf(moreItem()).fire('click');
  assert.equal(alertRows().length, 5, 'all five alerts are listed');
  assert.deepEqual(alertRows().map((i) => i.text), ['Alert 0', 'Alert 1', 'Alert 2', 'Alert 3', 'Alert 4']);
  assert.equal(toggleOf(moreItem()).getAttribute('aria-expanded'), 'true');
  assert.match(moreItem().node.textContent, /Show fewer/);
  toggleOf(moreItem()).fire('click');
  assert.equal(alertRows().length, 3);
});
