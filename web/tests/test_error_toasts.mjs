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

test('a second error stacks next to the first; the same words are not shown twice', () => {
  toast('The save failed.', true);
  toast('The save failed.', true);
  assert.equal(alerts().length, 2);
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
