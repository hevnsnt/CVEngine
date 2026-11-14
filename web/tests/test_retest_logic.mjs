import assert from 'node:assert/strict';
import {test} from 'node:test';
import * as RT from '../static/cve/retest-logic.js';

// The words and tones of a finding's retest state (cveFeed/fix_retest.py sends `retest`), kept free of the DOM so they can be pinned here.
const r = (state, extra = {}) => ({retest: {state, label: {verifying: 'Fixed, verifying', verified_fixed: 'Verified fixed', still_reproduces: 'Still reproduces, reopened',
  not_verified: 'Fixed, not verified', no_check: 'Marked fixed, cannot be re-checked automatically'}[state], text: '', at: null, sentinel: '', reason: '', can_retest: true, ...extra}});

test('a finding with no retest state draws nothing', () => {
  for (const item of [null, {}, {retest: null}, {retest: {state: ''}}, {retest: {state: 'bogus'}}]) assert.equal(RT.retestOf(item), null);
});

test('only verified fixed is green, and a finding that came back is red', () => {
  assert.equal(RT.toneOf(r('verified_fixed').retest), 'fixed');
  assert.equal(RT.toneOf(r('still_reproduces').retest), 'high');
  for (const state of ['verifying', 'not_verified', 'no_check']) assert.notEqual(RT.toneOf(r(state).retest), 'fixed', state);
});

test('the chip says the state in the words the user is promised', () => {
  assert.equal(RT.chipText(r('verifying').retest), 'Fixed, verifying');
  assert.equal(RT.chipText(r('not_verified', {text: 'Fixed, not verified: the host did not answer'}).retest), 'Fixed, not verified');
});

test('the sentence names the Sentinel that ran the check', () => {
  const item = r('verified_fixed', {text: 'Verified fixed on 2026-11-12', sentinel: 'east-1'});
  assert.equal(RT.sentence(item.retest), 'Verified fixed on 2026-11-12. Checked by Sentinel east-1.');
  assert.equal(RT.sentence(null), '');
});

test('the card never calls an unverified fix verified', () => {
  for (const state of ['verifying', 'not_verified', 'no_check']) {
    assert.ok(!/\bverified fixed\b/i.test(RT.cardNote(r(state).retest).replace(/not verified/gi, '')), state);
  }
  assert.ok(RT.cardNote(r('no_check').retest).includes('cannot be re-checked automatically'));
  assert.ok(RT.cardNote(r('still_reproduces').retest).includes('reopened'));
});

test('the card facts are the time, the Sentinel and the reason, only when known', () => {
  assert.deepEqual(RT.cardFacts(r('not_verified', {at: '2026-11-12T10:00:00Z', sentinel: 'east-1', reason: 'the host did not answer'}).retest),
    [['Checked', '2026-11-12T10:00:00Z'], ['By Sentinel', 'east-1'], ['Why not verified', 'the host did not answer']]);
  assert.deepEqual(RT.cardFacts(r('no_check').retest), []);
});

test('Retest now is offered for a fixed finding with a check, and not while one runs', () => {
  assert.equal(RT.canRetestNow({...r('not_verified'), status: 'fixed'}), true);
  assert.equal(RT.canRetestNow({...r('verified_fixed'), remediation_status: 'fixed'}), true);
  assert.equal(RT.canRetestNow({...r('verifying'), status: 'fixed'}), false);
  assert.equal(RT.canRetestNow({...r('no_check', {can_retest: false}), status: 'fixed'}), false);
  assert.equal(RT.canRetestNow({...r('still_reproduces'), status: 'open'}), false);
});

test('the filters and the counts line', () => {
  assert.deepEqual(RT.FILTERS.map(([k]) => k), ['verified_fixed', 'unverified_fixed', 'reopened']);
  assert.equal(RT.countsLine({verified_fixed: 3, unverified_fixed: 2, reopened: 1}), '3 verified fixed, 2 fixed, not verified, 1 reopened');
  assert.equal(RT.countsLine({verified_fixed: 0, unverified_fixed: 0, reopened: 0}), '');
});
