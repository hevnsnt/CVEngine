import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as LM from '../static/cve/loadmore-logic.js';

const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');

test('shown, left and next count follow the page arithmetic and never go negative', () => {
  assert.equal(LM.shownCount(217, 1, 30), 30);
  assert.equal(LM.shownCount(217, 3, 30), 90);
  assert.equal(LM.shownCount(217, 8, 30), 217);
  assert.equal(LM.shownCount(0, 1, 30), 0);
  assert.equal(LM.leftCount(217, 3, 30), 127);
  assert.equal(LM.leftCount(217, 8, 30), 0);
  assert.equal(LM.nextCount(127, 30), 30);
  assert.equal(LM.nextCount(7, 30), 7);
  assert.equal(LM.nextCount(0, 30), 0);
});

test('the idle button says how many are left', () => {
  assert.deepEqual(LM.moreView({total: 217, page: 1, size: 30}), {kind: 'button', label: 'Load more (187 left)', busy: false, disabled: false});
  assert.equal(LM.moreView({total: 217, page: 3, size: 30}).label, 'Load more (127 left)');
});

test('the busy button is disabled, busy, and says how many are on the way', () => {
  const v = LM.moreView({phase: 'busy', total: 217, page: 1, size: 30});
  assert.deepEqual(v, {kind: 'button', label: 'Loading 30 more...', busy: true, disabled: true});
  // the last page is smaller
  assert.equal(LM.moreView({phase: 'busy', total: 217, page: 7, size: 30}).label, 'Loading 7 more...');
});

test('finished: "All N shown" replaces the button, but only after the reader asked for more', () => {
  assert.deepEqual(LM.moreView({total: 217, page: 8, size: 30}), {kind: 'done', label: 'All 217 shown', busy: false, disabled: false});
  assert.equal(LM.moreView({total: 12, page: 1, size: 30}).kind, 'none');
  assert.equal(LM.moreView({total: 0, page: 1, size: 30}).kind, 'none');
  assert.equal(LM.moreView({phase: 'busy', total: 217, page: 8, size: 30}).kind, 'done');
});

test('the live message says what was added and how many are shown', () => {
  assert.equal(LM.loadedMessage(30, 90, 217, 'finding', 'findings'), 'Loaded 30 more findings, 90 of 217 shown');
  assert.equal(LM.loadedMessage(1, 217, 217, 'finding', 'findings'), 'Loaded 1 more finding, 217 of 217 shown');
  assert.equal(LM.loadedMessage(30, 60, 100), 'Loaded 30 more items, 60 of 100 shown');
});

test('a whole run of presses ends in All N shown, with every message in order', () => {
  const total = 217, size = 30;
  const messages = [];
  let page = 1;
  while (LM.moreView({total, page, size}).kind === 'button') {
    page += 1;
    const shown = LM.shownCount(total, page, size);
    const added = shown - LM.shownCount(total, page - 1, size);
    messages.push(LM.loadedMessage(added, shown, total, 'finding', 'findings'));
  }
  assert.equal(messages.length, 7);
  assert.equal(messages[0], 'Loaded 30 more findings, 60 of 217 shown');
  assert.equal(messages.at(-1), 'Loaded 7 more findings, 217 of 217 shown');
  assert.equal(LM.moreView({total, page, size}).label, 'All 217 shown');
});

test('createList draws the button through these words and keeps it as one element', () => {
  assert.match(app, /import \* as LM from "\/staticfiles\/cve\/loadmore-logic\.js"/);
  const list = app.slice(app.indexOf('function createList('), app.indexOf('function ageTags('));
  for (const call of ['LM.moreView(', 'LM.loadedMessage(', 'LM.busyLabel(', 'LM.shownCount(']) assert.ok(list.includes(call), call);
  assert.ok(list.includes('"aria-busy", "true"'));
  assert.ok(list.includes('role: "status", "aria-live": "polite"'));
  assert.ok(list.includes('moreBtn.disabled = true'));
  // the rows already shown are not cleared when a further page is asked for
  assert.ok(list.includes('if (reset) {\n      more.textContent = "";'));
});
