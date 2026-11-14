import assert from 'node:assert/strict';
import {register} from 'node:module';
import {mock, test} from 'node:test';

import {Page} from './fake_page.mjs';

// The Scanners page with fake timers: (1) a request that never answers ends in "could not be read" with Retry once the time limit passes (no
// placeholder for ever), (2) the page polls with one chain only, however often the tab is shown again, (3) a placeholder that is still waiting is
// the same node when another cell answers.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

const root = new Page('div');
root.dataset.appAdmin = '1';
const handlers = {};
globalThis.document = {
  createElement: (tag) => new Page(tag),
  getElementById: (id) => (id === 'health' ? root : null),
  querySelector: () => null, querySelectorAll: () => [], visibilityState: 'visible', cookie: '', activeElement: null,
  addEventListener: (name, fn) => { handlers[name] = fn; },
  defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};

// a fetch that never answers by itself, but honours the abort signal like the real one
const calls = [];
globalThis.fetch = (url, init = {}) => new Promise((resolve, reject) => {
  const call = {url: String(url).split('?')[0], resolve, reject, done: false, signal: init.signal};
  calls.push(call);
  if (init.signal) init.signal.addEventListener('abort', () => { call.done = true; reject(Object.assign(new Error('aborted'), {name: 'AbortError'})); });
});
const BODIES = {
  '/api/v1/sentinels/live': {results: [{state: 'working'}], queued: 0},
  '/cve/api/scanner': {},
  '/cve/api/admin/health': {workers_state: 'responding', beat: {state: 'running', seconds_since_tick: 3}, jobs: {scans: {pending: 0, running: 0}}},
};
const answerAll = () => calls.filter((c) => !c.done).forEach((c) => { c.done = true; c.resolve({ok: true, status: 200, json: async () => BODIES[c.url]}); });
const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r)); };
const cells = () => root.querySelectorAll('div').filter((d) => /health-cell/.test(d.className));
const cellNamed = (title) => cells().find((c) => c.textContent.startsWith(title));

mock.timers.enable({apis: ['setTimeout']});
const {REQUEST_MS} = await import('../static/cve/poll.js');
await import('../static/cve/scanners.js');

test('the time limit is longer than the slowest real answer (a cold Sentinels read: 55 s) and shorter than for ever', () => {
  assert.ok(REQUEST_MS > 55000 && REQUEST_MS <= 120000);
});

test('a request that never answers ends in "could not be read" with Retry once the limit passes', async () => {
  assert.equal(calls.length, 3);
  assert.match(root.textContent, /Checking the Sentinels/, 'placeholders first');
  mock.timers.tick(REQUEST_MS + 1);
  await flush();
  for (const title of ['Sentinels', 'Work waiting', 'Workers and scheduler']) {
    const c = cellNamed(title);
    assert.match(c.textContent, /could not be read/, `${title} ends in the failure state`);
    assert.ok(c.querySelectorAll('button').some((b) => b.textContent === 'Retry'), `${title} offers Retry`);
  }
  assert.doesNotMatch(root.textContent, /Checking|taking longer/);
});

test('Retry waits again, and a retry that answers fills the cell in', async () => {
  const before = calls.length;
  cellNamed('Sentinels').querySelectorAll('button').find((b) => b.textContent === 'Retry').fire('click');
  await flush();
  assert.equal(calls.length, before + 1);
  assert.match(cellNamed('Sentinels').textContent, /Checking the Sentinels/);
  answerAll();
  await flush();
  assert.match(cellNamed('Sentinels').textContent, /1 of 1 online/);
});

test('a waiting placeholder stays the same node while another part of the page answers', async () => {
  cellNamed('Workers and scheduler').querySelectorAll('button').find((b) => b.textContent === 'Retry').fire('click');
  await flush();
  const node = cellNamed('Workers and scheduler');
  assert.match(node.textContent, /Checking the workers/);
  mock.timers.tick(30000); // the next round starts: the page asks for everything again
  await flush();
  const strip = calls.filter((c) => !c.done && c.url === '/cve/api/scanner');
  assert.equal(strip.length, 1);
  strip[0].done = true;
  strip[0].resolve({ok: true, status: 200, json: async () => ({})});
  await flush(); // the page redrew because the strip answered
  assert.equal(cellNamed('Workers and scheduler'), node, 'the placeholder was not rebuilt');
  answerAll();
  await flush();
  assert.match(root.textContent, /All responding/);
});

test('showing the tab again while a round is running does not start a second polling chain', async () => {
  // a round is armed now (30 s). Count the requests a few visits and two more rounds cause.
  const start = calls.length;
  handlers.visibilitychange(); // tab shown: a round starts at once (none running)
  await flush();
  assert.equal(calls.length - start, 3, 'one round');
  handlers.visibilitychange(); // shown again while that round is still waiting
  handlers.visibilitychange();
  await flush();
  assert.equal(calls.length - start, 3, 'no second round while one is running');
  answerAll();
  await flush();
  mock.timers.tick(30000);
  await flush();
  assert.equal(calls.length - start, 6, 'exactly one round after 30 s');
  answerAll();
  await flush();
  mock.timers.tick(30000);
  await flush();
  assert.equal(calls.length - start, 9, 'and again exactly one: a single chain');
  answerAll();
  await flush();
});

// The strip read (the one-sentence extra in the work cell) has the same limit as the cells: a round waits for it, so a strip that stalls would
// stop the page polling. Observable: the round must end and the next one start. Swapped to a plain fetch, both tests fail (no abort, no next round).
const roundAfterStall = async (answerStrip) => {
  mock.timers.tick(30000); // the next round starts
  await flush();
  const mine = calls.filter((c) => !c.done);
  assert.equal(mine.length, 3, 'a round of three requests');
  for (const c of mine) {
    if (c.url === '/cve/api/scanner') { answerStrip(c); continue; }
    c.done = true;
    c.resolve({ok: true, status: 200, json: async () => BODIES[c.url]});
  }
  await flush();
  mock.timers.tick(REQUEST_MS + 1);
  await flush();
  const strip = mine.find((c) => c.url === '/cve/api/scanner');
  assert.ok(strip.signal, 'the strip read carries an abort signal (it goes through the time limit)');
  assert.equal(strip.signal.aborted, true, 'and the limit aborted it');
  const before = calls.length;
  mock.timers.tick(30000);
  await flush();
  assert.equal(calls.length - before, 3, 'the round ended, so the next one started');
  answerAll();
  await flush();
};

test('a strip read that never answers is cut off by the limit and does not stop the polling', async () => {
  await roundAfterStall(() => {});
});

test('a strip read whose headers arrive but whose body stalls is cut off by the limit too', async () => {
  await roundAfterStall((c) => { c.done = true; c.resolve({ok: true, status: 200, json: () => new Promise(() => {})}); });
});
