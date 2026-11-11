import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

import {Page} from './fake_page.mjs';

// An error message stays until the person dismisses it, is announced as an alert and can be dismissed from the keyboard;
// a success message still goes by itself. Several errors stack, none replaces another.
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

const timers = [];
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => { timers.push({fn, ms}); return {unref() {}}; };

const {toast} = await import('../static/cve/ui.js');
const alerts = () => document.body.querySelectorAll('[role=alert]');

test('an error toast is an alert with a Dismiss button and no timer that removes it', () => {
  timers.length = 0;
  toast('The report could not be built.', true);
  assert.equal(alerts().length, 1);
  assert.match(alerts()[0].textContent, /The report could not be built\./);
  assert.ok(!timers.some((t) => t.ms === 4000), 'no 4 second removal');
  const dismiss = document.body.querySelectorAll('button').find((b) => /dismiss/i.test(b.getAttribute('aria-label') || b.textContent));
  assert.ok(dismiss, 'a Dismiss button');
});

test('a second error stacks next to the first; the same words are one card with a count', () => {
  toast('The save failed.', true);
  toast('The save failed.', true);
  assert.equal(alerts().length, 2);
  assert.match(alerts()[1].textContent, /The save failed\. \(2 times\)/);
});

test('Dismiss removes only that error', () => {
  const dismiss = document.body.querySelectorAll('button').find((b) => /dismiss/i.test(b.getAttribute('aria-label') || b.textContent));
  dismiss.fire('click');
  assert.equal(alerts().length, 1);
});

test('a success toast still goes by itself after a few seconds', () => {
  timers.length = 0;
  toast('Saved.');
  const t = timers.find((x) => x.ms === 4000);
  assert.ok(t, 'a removal timer');
  t.fn();
  assert.equal(document.body.querySelectorAll('*').filter((n) => /(^| )toast( |$)/.test(n.className) && /Saved/.test(n.textContent)).length, 0);
});

test('at most three error cards are drawn; the rest are one line whose Show button draws them all, losing none', () => {
  const closeAll = () => { while (alerts().length) alerts()[0].querySelectorAll('button')[0].fire('click'); };
  closeAll();
  for (let i = 1; i <= 6; i += 1) toast(`Failure number ${i}.`, true);
  assert.equal(alerts().length, 4, 'three cards and one line for the other three');
  assert.match(alerts()[3].textContent, /3 more errors\./);
  assert.doesNotMatch(alerts()[3].textContent, /Dismiss to see/, 'the line does not promise what Dismiss does not do');
  assert.doesNotMatch(document.body.textContent, /Failure number 4/);
  const show = alerts()[3].querySelectorAll('button')[0];
  assert.match(show.textContent, /Show/);
  show.fire('click');
  assert.equal(alerts().length, 6, 'every error is a card now');
  for (let i = 1; i <= 6; i += 1) assert.match(document.body.textContent, new RegExp(`Failure number ${i}\\.`));
  assert.doesNotMatch(document.body.textContent, /more errors/);
  closeAll();
  assert.equal(alerts().length, 0);
});

test('Dismiss on a card still shows the next hidden one, and the line goes when none is hidden', () => {
  for (let i = 1; i <= 5; i += 1) toast(`Again ${i}.`, true);
  assert.equal(alerts().length, 4);
  alerts()[0].querySelectorAll('button')[0].fire('click');
  assert.match(document.body.textContent, /Again 4/);
  assert.equal(alerts().length, 4, 'three cards and a line for the one left');
  alerts()[0].querySelectorAll('button')[0].fire('click');
  assert.equal(alerts().length, 3, 'nothing hidden, no line');
  while (alerts().length) alerts()[0].querySelectorAll('button')[0].fire('click');
});

test('ten different errors never draw more than four alerts', () => {
  for (let i = 0; i < 10; i += 1) toast(`Different ${i}.`, true);
  assert.ok(alerts().length <= 4);
});
