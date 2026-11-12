import assert from 'node:assert/strict';
import {test} from 'node:test';

// The Overview's "your first look is still under way" note (static/cve/first-note-logic.js, drawn by dashboard.js paintFirstNote).
const {firstNoteHidden} = await import('../static/cve/first-note-logic.js');

test('it shows only when the wizard sent the user here and no host is known yet', () => {
  assert.equal(firstNoteHidden('1', {hosts: 0}), false);
});

test('it goes away as soon as the first host is in the inventory', () => {
  assert.equal(firstNoteHidden('1', {hosts: 1}), true);
  assert.equal(firstNoteHidden('1', {hosts: 250}), true);
});

test('it never shows without the first-run marker, with or without hosts', () => {
  assert.equal(firstNoteHidden('', {hosts: 0}), true);
  assert.equal(firstNoteHidden(undefined, {hosts: 0}), true);
  assert.equal(firstNoteHidden('', {hosts: 5}), true);
});

test('it stays hidden until the first counts have arrived', () => {
  assert.equal(firstNoteHidden('1', null), true);
});
