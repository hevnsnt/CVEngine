import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// Ten open admin alerts: the alert bar lists three and a "7 more alerts. Show all." button, and tells the strip there are ten notices (the strip
// said "4 notices": three rows and the button). Dismiss takes an alert out of the list and the count at once, drawn without waiting, and a poll
// whose answer was made before the dismissal was stored does not bring it back.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier === '/staticfiles/cve/statusstrip.js') {
    return {url: 'data:text/javascript,export const setNotices=(k,i,o)=>{globalThis.__notices=i;globalThis.__opts=o;};', format: 'module', shortCircuit: true};
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
globalThis.location = {pathname: '/cve/'};
const ten = Array.from({length: 10}, (_, i) => ({id: i + 1, title: `Alert ${i + 1}`, severity: 'warning', detail: ''}));
let pending = null; // a poll whose answer is held back until the test releases it
globalThis.fetch = async (url, opts = {}) => {
  if (opts.method === 'POST') return {ok: true, status: 200, json: async () => ({})};
  if (pending) {
    const answer = pending;
    pending = null;
    await answer.gate;
    return {ok: true, status: 200, json: async () => ({alerts: answer.alerts})};
  }
  return {ok: true, status: 200, json: async () => ({alerts: ten})};
};
const intervals = [];
globalThis.setInterval = (fn) => { intervals.push(fn); return 0; };

await import('../static/cve/alertbar.js');
await new Promise((r) => setTimeout(r, 20));

const alertRows = () => globalThis.__notices.filter((i) => i.kind === 'alert');
const dismissOf = (item) => item.node.querySelectorAll('button')[0];

test('ten open alerts: three rows and the Show all button, and the strip is told there are ten notices', () => {
  assert.equal(alertRows().length, 3);
  assert.ok(globalThis.__notices.find((i) => i.kind === 'more'));
  assert.equal(globalThis.__opts.count, 10);
});

test('Dismiss takes the alert out of the count at once, drawn now, and an older poll answer does not bring it back', async () => {
  let release;
  pending = {gate: new Promise((r) => { release = r; }), alerts: ten}; // this poll began before the click: its answer still lists alert 1
  intervals[0]();
  dismissOf(alertRows()[0]).fire('click');
  assert.equal(globalThis.__opts.count, 9, 'the count drops with the click');
  assert.equal(globalThis.__opts.force, true, 'drawn at once, not after the person stops using the strip');
  assert.deepEqual(alertRows().map((i) => i.text), ['Alert 2', 'Alert 3', 'Alert 4']);
  await new Promise((r) => setTimeout(r, 5));
  release();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(globalThis.__opts.count, 9, 'the answer made before the dismissal was stored does not re-add it');
  assert.ok(!alertRows().some((i) => i.text === 'Alert 1'));
});
