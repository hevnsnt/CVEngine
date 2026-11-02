import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as C from '../static/cve/closure-logic.js';
import * as G from '../static/cve/finding-groups-logic.js';

const read = (name) => readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8');
const app = read('app.js');
const bulk = read('bulk.js');
const suppliers = read('suppliers.js');
const graph = read('graph.js');

test('false positive is a status everywhere the UI lists one, and a closed one', () => {
  assert.deepEqual(C.STATUS_VALUES, ['open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive']);
  assert.deepEqual(C.STATUS_OPTIONS.at(-1), ['false_positive', 'False positive']);
  assert.deepEqual(C.CLOSED, ['fixed', 'accepted_risk', 'false_positive']);
  assert.deepEqual(G.STATUS_VALUES, C.STATUS_VALUES);
  assert.deepEqual(G.CLOSED, C.CLOSED);
  assert.ok(C.isClosing('false_positive') && C.isClosing('fixed') && !C.isClosing('in_progress') && !C.isClosing('open'));
  assert.equal(C.statusLabel('false_positive'), 'False positive');
  assert.equal(C.statusLabel('ruled out'), 'ruled out');
});

test('a group leaves its false-positive hosts alone like its fixed ones, and Undo can put one back', () => {
  const group = {member_ids: [1, 2, 3], member_status: {1: 'open', 2: 'false_positive', 3: 'fixed'}, ruled_out_ids: []};
  assert.deepEqual(G.targetsOf(group, 'in_progress'), {ids: [1], closed: 2, same: 0});
  assert.equal(G.closedCount(group), 2);
  assert.equal(G.priorOf({kind: 'match', id: 9, status: 'false_positive'}), 'false_positive');
  assert.match(G.statusSplit({status_counts: {false_positive: 2, open: 1}}), /^1 open · 2 false positive$/);
});

test('every closing status asks for a note; a false positive will not close without one', () => {
  assert.equal(C.asksForNote('open'), false);
  assert.equal(C.asksForNote('in_progress'), false);
  for (const s of C.CLOSED) assert.equal(C.asksForNote(s), true, s);
  assert.equal(C.noteRequired('false_positive'), true);
  assert.equal(C.noteRequired('fixed'), false);
  assert.equal(C.noteRequired('accepted_risk'), false);
  assert.match(C.noteProblem('false_positive', '   '), /why/i);
  assert.equal(C.noteProblem('fixed', ''), null);
  assert.equal(C.noteProblem('false_positive', 'only a redirect'), null);
  assert.match(C.noteProblem('fixed', 'x'.repeat(2001)), /2000/);
  assert.equal(C.noteProblem('fixed', 'x'.repeat(2000)), null);
});

test('the note prompt says what is being closed and how many', () => {
  const one = C.notePrompt('false_positive', 1);
  assert.match(one.title, /false positive/i);
  assert.equal(one.required, true);
  assert.match(one.ok, /False positive/);
  const many = C.notePrompt('accepted_risk', 12);
  assert.match(many.title, /12 findings/);
  assert.equal(many.required, false);
  assert.match(many.help, /optional/i);
  assert.match(C.notePrompt('fixed', 3).help, /all 3/);
});

test('a note is cleaned the way the server cleans it', () => {
  assert.equal(C.cleanNote('  a\u0000b\u001bc\u202ed\r\ne\tf  '), 'abcd\ne\tf');
  assert.equal(C.cleanNote(null), '');
});

test('the status tooltip says who closed it, when and why, and an automatic closure says so', () => {
  const by = C.closureText({remediation_status: 'false_positive', closure_note: 'jQuery is never loaded', closed_by: {name: 'Alice'}, closed_at: '2026-11-02T10:00:00Z'});
  assert.equal(by, 'False positive by Alice on 2026-11-02: jQuery is never loaded');
  const auto = C.closureText({status: 'ruled out', closure_note: 'Closed automatically: different product', closed_automatically: true, closed_at: null});
  assert.equal(auto, 'Closed automatically: different product');
  assert.equal(C.closureText({status: 'open', closure_note: null}), '');
  assert.equal(C.closureText({status: 'fixed', closure_note: '', closed_by: null}), 'Fixed');
});

test('supplier findings close as accepted or false positive', () => {
  assert.deepEqual(C.SUPPLIER_CLOSE_OPTIONS, [['accepted', 'Accepted'], ['false_positive', 'False positive']]);
  assert.equal(C.noteRequired('false_positive'), true);
});

test('the pages use the shared list and ask for the note', () => {
  assert.match(app, /import \* as CL from "\/staticfiles\/cve\/closure-logic\.js"/);
  assert.doesNotMatch(app, /\["accepted_risk", "Accepted risk"\]\]/); // no hand-written status lists left
  assert.match(app, /options: CL\.STATUS_OPTIONS/);
  assert.match(app, /askClosureNote/);
  assert.match(app, /findings\/status`, \{ items: chunk\.map\(\(i\) => \(\{ kind: itemKind\(i\), id: i\.id \}\)\), status: value, \.\.\.noteField/);
  assert.match(bulk, /action\.detail/);
  assert.match(suppliers, /SUPPLIER_CLOSE_OPTIONS/);
  assert.match(graph, new RegExp(`const CLOSED_STATUSES = ${JSON.stringify(C.CLOSED).replace(/[[\]]/g, '\\$&').replace(/,/g, ', ')};`));
  assert.doesNotMatch(graph, /\["fixed", "accepted_risk"\]\.includes/);
});
