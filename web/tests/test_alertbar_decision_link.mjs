import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// An open alert that auto-tune answered (the server sends `decision_id`, cveFeed/reviewer.py ``answering_decision``) links to that decision's line in
// Settings, configMaxxing, Auto-tuning; an alert it did not answer has no link.
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
globalThis.fetch = async () => ({ok: true, status: 200, json: async () => ({alerts: [
  {id: 'm', title: 'A lane is near its limit', severity: 'warning', detail: 'd', decision_id: 12},
  {id: 'n', title: 'Templates are old', severity: 'info', detail: 'd', decision_id: null},
  {id: 'o', title: 'No such field', severity: 'info', detail: 'd'}]})});
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...a) => { const t = realSetInterval(...a); t.unref?.(); return t; };
await import('../static/cve/alertbar.js');
await new Promise((r) => setTimeout(r, 20));

test('the alert that led to a change links to its decision, with a link text a person can read', () => {
  const [answered, plain, old] = globalThis.__notices.filter((i) => i.kind === 'alert');
  const links = answered.node.querySelectorAll('a');
  assert.equal(links.length, 1);
  assert.equal(links[0].getAttribute('href'), '/cve/settings/#configmaxxing/autotune/12');
  assert.equal(links[0].textContent, 'See what auto-tune did about this');
  assert.equal(plain.node.querySelectorAll('a').length, 0);
  assert.equal(old.node.querySelectorAll('a').length, 0);
});
