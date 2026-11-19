import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/config-maxxing-logic.js';

const dir = new URL('../static/cve/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');

const field = (over = {}) => ({key: 'assess_batch', label: 'Hosts per assessment batch', group: 'discovery', default: 8, min: 1, max: 64, value: 8, source: 'default',
  env_name: 'CVENGINE_ASSESS_BATCH', env_value: null, set_by: null, set_at: null, applies: 'live', ...over});
const depth = (over = {}) => field({key: 'work_depth', label: 'Discovery scans kept running', group: 'depth', default: 3, min: 0, max: 32, value: 3,
  env_name: 'CVENGINE_WORK_DEPTH', ...over});

test('the section is called configMaxxing, with that capitalisation, and has no subtitle', () => {
  assert.equal(L.SECTION_LABEL, 'configMaxxing');
  assert.equal(L.SECTION_ID, 'configmaxxing');
  for (const name of ['config-maxxing.js', 'config-maxxing-logic.js', 'scan-concurrency-card.js', 'tunables-card.js', 'settings.js']) {
    const src = read(name);
    assert.doesNotMatch(src, /Tinkerer settings/i, `${name} carries a subtitle`);
    assert.doesNotMatch(src, /config-maxing|"tinkerer"|#tinkerer/i, `${name} uses another name or an alias`);
  }
  assert.match(L.WARNING_TEXT, /slower, use more memory or send more traffic to your targets/);
  assert.match(L.EXPLANATION_TEXT, /Every scan runs on a Sentinel/);
  assert.match(L.EXPLANATION_TEXT, /another Sentinel \(a second machine\) is the best way to scale/);
  assert.doesNotMatch(L.EXPLANATION_TEXT, /memory gate/);  // no scanner runs on the server, so no gate holds work back here
});

test('the anchor is #configmaxxing, and one card can be named after a slash', () => {
  assert.deepEqual(L.parseHash('#configmaxxing'), {section: 'configmaxxing', card: ''});
  assert.deepEqual(L.parseHash('#configmaxxing/scan_concurrency'), {section: 'configmaxxing', card: 'scan_concurrency'});
  assert.equal(L.isSectionHash('#configmaxxing'), true);
  assert.equal(L.isSectionHash('#configmaxxing/scan_concurrency'), true);
  for (const other of ['', '#ai', '#tinkerer', '#config-maxing', undefined]) assert.equal(L.isSectionHash(other), false, String(other));
});

test('the section is collapsed by default and the choice is remembered, without storage it still works', () => {
  const store = new Map();
  const storage = {getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v)};
  assert.equal(L.readOpen(storage), false);
  assert.equal(L.writeOpen(storage, true), true);
  assert.equal(L.readOpen(storage), true);
  L.writeOpen(storage, false);
  assert.equal(L.readOpen(storage), false);
  const blocked = {getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); }};
  assert.equal(L.readOpen(blocked), false);
  assert.equal(L.writeOpen(blocked, true), false);
  assert.equal(L.readOpen(null), false);
  assert.equal(L.writeOpen(null, true), false);
});

test('a box accepts only whole numbers inside the field range', () => {
  const f = field();
  assert.deepEqual(L.checkDraft(f, '4'), {ok: true, value: 4});
  assert.deepEqual(L.checkDraft(f, ' 64 '), {ok: true, value: 64});
  for (const bad of ['', '0', '65', '-1', '2.5', 'two', '1e1', null, undefined]) {
    const result = L.checkDraft(f, bad);
    assert.equal(result.ok, false, String(bad));
    assert.match(result.error, /^Hosts per assessment batch must be (a whole number )?from 1 to 64$/);
  }
  assert.deepEqual(L.checkDraft(depth(), '0'), {ok: true, value: 0});
});

test('only the boxes that differ from what is in effect are sent, and one bad box blocks the save with its message', () => {
  const fields = [field(), depth()];
  assert.deepEqual(L.changesFrom(fields, {assess_batch: '8', work_depth: '3'}), {changes: {}, error: null});
  assert.deepEqual(L.changesFrom(fields, {assess_batch: '16', work_depth: '3'}), {changes: {assess_batch: 16}, error: null});
  const bad = L.changesFrom(fields, {assess_batch: '16', work_depth: '99'});
  assert.match(bad.error, /Discovery scans kept running must be from 0 to 32/);
  assert.deepEqual(bad.changes, {assess_batch: 16});
});

test('each row says where its number comes from, the default, the environment value and who set it', () => {
  assert.equal(L.sourceLabel(field()), 'Built-in default');
  assert.equal(L.sourceLabel(field({source: 'environment', env_value: 12})), 'Set on the server');
  assert.equal(L.sourceLabel(field({source: 'admin'})), 'Saved here');
  const lines = L.originLines(field({source: 'admin', value: 16, env_value: 12, set_by: 'alice', set_at: '2026-10-31T10:00:00Z'}), (d) => `<${d}>`);
  assert.deepEqual(lines, ['Default 8', 'Set by alice on <2026-10-31T10:00:00Z>']);
  assert.deepEqual(L.originLines(field()), ['Default 8']);
  assert.equal(L.serverSetting(field()), 'CVENGINE_ASSESS_BATCH is not set');
  assert.equal(L.serverSetting(field({env_value: 12})), 'CVENGINE_ASSESS_BATCH=12');
  assert.equal(L.rangeText(field()), '1 to 64');
});

test('Reset to default is offered only for a value that was saved here', () => {
  assert.equal(L.canReset(field()), false);
  assert.equal(L.canReset(field({source: 'environment', env_value: 12})), false);
  assert.equal(L.canReset(field({source: 'admin'})), true);
});

test('fields are grouped in the order the server gave, and an empty group is left out', () => {
  const fields = [field(), depth()];
  const groups = L.groupFields(fields, [{id: 'discovery', title: 'A'}, {id: 'lanes', title: 'B'}, {id: 'depth', title: 'C'}]);
  assert.deepEqual(groups.map((g) => [g.id, g.fields.length]), [['discovery', 1], ['depth', 1]]);
});

test('there is no scanner memory plan any more: no budget, no per-tool limits, no warning', () => {
  for (const gone of ['memoryPlan', 'formatMb', 'OVERCOMMIT']) assert.equal(L[gone], undefined, gone);
  const card = read('scan-concurrency-card.js');
  assert.doesNotMatch(card, /memoryPlan|formatMb|Memory budget|"heavy"|f\.group === "heavy"/);
  assert.doesNotMatch(read('config-maxxing-logic.js'), /heavy|memory gate|CELERY_MEM_LIMIT/i);
});

test('the discovery pool never claims a number the worker did not report', () => {
  const pool = field({key: 'discovery_concurrency', applies: 'pool', value: 12, running: null});
  assert.equal(L.runningText(pool), 'Worker ceiling now: not reported yet');
  assert.equal(L.runningText({...pool, running: 8}), 'Worker ceiling now: 8');
  assert.equal(L.runningText(field()), 'Applies within a few seconds, with no restart');
  assert.equal(L.runningText(field({applies: 'restart'})), 'Applies after the next restart');  // a tunable read once at process start says so
  assert.equal(L.discoveryNotice(pool, {message: 'Saved 12, runs 8'}), 'Saved 12, runs 8');
  assert.match(L.discoveryNotice(pool, null), /not known/);
});

test('the new pages build the DOM with textContent only, never innerHTML, and register their card', () => {
  for (const name of ['config-maxxing.js', 'config-maxxing-logic.js', 'scan-concurrency-card.js', 'tunables-card.js']) {
    const src = read(name);
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/, `${name} writes markup`);
  }
  assert.match(read('scan-concurrency-card.js'), /registerCard\(\{ id: "scan_concurrency"/);
  assert.doesNotMatch(read('config-maxxing-logic.js'), /^\s*import\s/m, 'the logic module must stay importable by node');
});

test('Settings has the configMaxxing group, collapsed by default, with a pointer from Resources', () => {
  const src = read('settings.js');
  assert.match(src, /SECTION_LABEL/);
  assert.match(src, /async \[SECTION_ID\]\(m\)/);
  assert.match(src, /setCmOpen\(readOpen\(storage\), false\)/);
  assert.match(src, /"aria-controls": "set-cm-items"/);
  assert.match(src, /Scan concurrency moved to configMaxxing/);
  assert.match(src, /isSectionHash\(location\.hash\)/);
  assert.doesNotMatch(src, /innerHTML/);
  assert.match(src, /try \{\s*storage = window\.localStorage;\s*\} catch/);
});
