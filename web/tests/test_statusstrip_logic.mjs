import assert from 'node:assert/strict';
import {test} from 'node:test';

import {afterPoll, noticeCount, visibleItems} from '../static/cve/statusstrip-logic.js';

// The status strip's line says how many notices there are. With ten open alerts the alert bar draws three rows and a "7 more alerts. Show all."
// button; the line said "4 notices" (three rows and the button). It counts the notices: every open alert, never the button.
const alertRows = (n) => Array.from({length: n}, (_, i) => ({kind: 'alert', text: `Alert ${i}`, rank: 2}));
const more = {kind: 'more', text: '7 more alerts. Show all.', rank: 3};

test('ten open alerts read as ten notices, not three rows and the Show all button', () => {
  const entries = [{items: [...alertRows(3), more], count: 10}];
  assert.equal(noticeCount(entries, []), 10);
  assert.equal(visibleItems(entries, []).length, 4, 'the rows drawn are unchanged');
});

test('the scanner notices count as before, one each, beside the alerts', () => {
  const scanner = {items: [{kind: 'warn', text: 'The scanner is paused', rank: 1, dismissible: true}, {kind: 'info', text: 'Two scans wait', rank: 1}]};
  assert.equal(noticeCount([scanner], []), 2);
  assert.equal(noticeCount([scanner, {items: [...alertRows(3), more], count: 10}], []), 12);
  assert.equal(noticeCount([scanner], ['The scanner is paused']), 1, 'a scanner note dismissed for the session is not counted');
  assert.equal(visibleItems([scanner], ['The scanner is paused']).length, 1);
});

test('a source without a count counts its items, never a "more" button', () => {
  assert.equal(noticeCount([{items: [...alertRows(3), more]}], []), 3);
  assert.equal(noticeCount([], []), 0);
});

test('a dismissed alert leaves the count at once, and a poll that began before the dismissal does not bring it back', () => {
  const alerts = [{id: 1}, {id: 2}, {id: 3}];
  const dismissedAt = new Map([[2, 1000]]);
  assert.deepEqual(afterPoll(alerts, dismissedAt, 900).map((a) => a.id), [1, 3], 'the poll began before the dismissal was stored');
  assert.deepEqual(afterPoll(alerts, new Map([[2, Infinity]]), 5000).map((a) => a.id), [1, 3], 'the dismissal is still on its way');
  assert.deepEqual(afterPoll(alerts, dismissedAt, 1100).map((a) => a.id), [1, 2, 3], 'a later answer is the server\'s word: it shows the alert again only when the server does');
});
