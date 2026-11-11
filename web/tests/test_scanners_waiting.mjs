import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Element, Text} from './fake_dom.mjs';

// The Scanners page (static/cve/scanners.js) must paint its frame at once: every health cell is a placeholder that says what is being checked,
// and each cell fills in by itself when its own request answers. A request that failed says "could not be read" and offers Retry; it never
// reads as "None registered". The page imports `/staticfiles/cve/...`; the hook maps that to the source directory.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Page extends Element {
  constructor(tag) { super(tag); this.dataset = {}; this.onclick = null; }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this.setAttribute('class', v); }
  get classList() { return {add: (c) => { this.className = `${this.className} ${c}`.trim(); }}; }
  set textContent(v) { this.childNodes.splice(0).forEach((c) => { c.parentNode = null; }); if (v !== '') this.appendChild(new Text(v)); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  get isConnected() { return this._connected !== false; }
  append(...kids) { kids.forEach((k) => this.appendChild(typeof k === 'string' ? new Text(k) : k)); }
  replaceChildren(...kids) { this.childNodes.splice(0).forEach((c) => { c.parentNode = null; }); this.append(...kids); }
}
const root = new Page('div');
root.dataset.appAdmin = '1';
globalThis.document = {
  createElement: (tag) => new Page(tag),
  getElementById: (id) => (id === 'health' ? root : null),
  querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, visibilityState: 'visible', cookie: '',
  activeElement: null, defaultView: {scrollX: 0, scrollY: 0, scrollTo() {}, getSelection: () => ({isCollapsed: true, anchorNode: null})},
};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};

// every request waits until the test answers it
const pending = {};
globalThis.fetch = (url) => new Promise((resolve, reject) => { pending[String(url).split('?')[0]] = {resolve, reject}; });
const answer = (url, body, ok = true) => pending[url].resolve({ok, status: ok ? 200 : 500, json: async () => body});
const tick = () => new Promise((r) => setImmediate(r));
const text = () => root.textContent;
const cells = () => root.querySelectorAll('div').filter((d) => /health-cell/.test(d.className));
const cellNamed = (title) => cells().find((c) => c.textContent.startsWith(title));
const waitingIn = (c) => c.querySelectorAll('div').some((d) => /\bwait\b/.test(d.className) && d.getAttribute('role') === 'status' && d.getAttribute('aria-live') === 'polite');

await import('../static/cve/scanners.js');

test('before any request answers, every cell is a placeholder that says what is being checked', () => {
  assert.equal(cells().length, 3);
  for (const title of ['Sentinels', 'Work waiting', 'Workers and scheduler']) assert.ok(waitingIn(cellNamed(title)), `${title} shows a placeholder`);
  assert.match(text(), /Checking the Sentinels/);
  assert.doesNotMatch(text(), /None registered/);
});

test('each cell fills in on its own when its request answers', async () => {
  answer('/cve/api/admin/health', {workers_state: 'responding', beat: {state: 'running', seconds_since_tick: 3}, jobs: {scans: {pending: 0, running: 1}}});
  await tick();
  assert.match(text(), /All responding/);
  assert.ok(waitingIn(cellNamed('Sentinels')), 'the Sentinel cell still waits for its own answer');
  assert.ok(waitingIn(cellNamed('Work waiting')), 'so does the work cell');
});

test('a Sentinel list that failed says it could not be read and offers Retry, never "None registered"', async () => {
  answer('/api/v1/sentinels/live', {error: 'down'}, false);
  await tick();
  assert.match(cellNamed('Sentinels').textContent, /could not be read/);
  assert.doesNotMatch(text(), /None registered/);
  const retry = cellNamed('Sentinels').querySelectorAll('button').find((b) => b.textContent === 'Retry');
  assert.ok(retry, 'a Retry button');
  delete pending['/api/v1/sentinels/live'];
  retry.fire('click');
  await tick();
  assert.ok(waitingIn(cellNamed('Sentinels')), 'the cell waits again while the retry runs');
  answer('/api/v1/sentinels/live', {results: [{state: 'working'}], queued: 2});
  await tick();
  assert.match(cellNamed('Sentinels').textContent, /1 of 1 online/);
  assert.ok(!waitingIn(cellNamed('Work waiting')));
});

test('the page frame in the template is a status region with a placeholder before any script runs', async () => {
  const {readFileSync} = await import('node:fs');
  const html = readFileSync(new URL('../cveFeed/templates/cveFeed/scanners.html', import.meta.url), 'utf8');
  assert.match(html, /class="wait"[^>]*role="status"[^>]*aria-live="polite"/);
});

test('after the slow mark the line says it is taking longer than usual and the page fills in by itself', async () => {
  const {waiting} = await import('../static/cve/ui.js');
  const box = waiting('Checking the Sentinels', {slowMs: 5});
  assert.doesNotMatch(box.textContent, /longer than usual/);
  await new Promise((r) => setTimeout(r, 30));
  assert.match(box.textContent, /taking longer than usual/);
  assert.match(box.textContent, /fills in by itself/);
  assert.match(waiting('Checking', {slow: true}).textContent, /taking longer than usual/);
});
