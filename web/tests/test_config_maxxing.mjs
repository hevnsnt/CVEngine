import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/config-maxxing-logic.js';

const dir = new URL('../static/cve/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');

const field = (over = {}) => ({key: 'heavy.nmap', label: 'Port and service scan (nmap)', group: 'heavy', default: 2, min: 1, max: 8, value: 2, source: 'default',
  env_name: 'HEAVY_MAX_NMAP', env_value: null, set_by: null, set_at: null, applies: 'live', ...over});

test('the section is called configMaxxing, with that capitalisation, and has no subtitle', () => {
  assert.equal(L.SECTION_LABEL, 'configMaxxing');
  assert.equal(L.SECTION_ID, 'configmaxxing');
  for (const name of ['config-maxxing.js', 'config-maxxing-logic.js', 'scan-concurrency-card.js', 'tunables-card.js', 'settings.js']) {
    const src = read(name);
    assert.doesNotMatch(src, /Tinkerer settings/i, `${name} carries a subtitle`);
    assert.doesNotMatch(src, /config-maxing|"tinkerer"|#tinkerer/i, `${name} uses another name or an alias`);
  }
  assert.match(L.WARNING_TEXT, /slower, use more memory or send more traffic to your targets/);
  assert.match(L.EXPLANATION_TEXT, /second machine \(a Sentinel\) is the best way to scale/);
  assert.match(L.EXPLANATION_TEXT, /memory gate still holds work back/);
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
  assert.deepEqual(L.checkDraft(f, ' 8 '), {ok: true, value: 8});
  for (const bad of ['', '0', '9', '-1', '2.5', 'two', '1e1', null, undefined]) {
    const result = L.checkDraft(f, bad);
    assert.equal(result.ok, false, String(bad));
    assert.match(result.error, /1 to 8|from 1 to 8/);
  }
  assert.deepEqual(L.checkDraft(field({key: 'work_depth', min: 0, max: 32, label: 'x'}), '0'), {ok: true, value: 0});
});

test('only the boxes that differ from what is in effect are sent, and one bad box blocks the save with its message', () => {
  const fields = [field(), field({key: 'heavy.nuclei', label: 'nuclei', value: 1, default: 1})];
  assert.deepEqual(L.changesFrom(fields, {'heavy.nmap': '2', 'heavy.nuclei': '1'}), {changes: {}, error: null});
  assert.deepEqual(L.changesFrom(fields, {'heavy.nmap': '4', 'heavy.nuclei': '1'}), {changes: {'heavy.nmap': 4}, error: null});
  const bad = L.changesFrom(fields, {'heavy.nmap': '4', 'heavy.nuclei': '99'});
  assert.match(bad.error, /nuclei/);
  assert.deepEqual(bad.changes, {'heavy.nmap': 4});
});

test('each row says where its number comes from, the default, the environment value and who set it', () => {
  assert.equal(L.sourceLabel(field()), 'Built-in default');
  assert.equal(L.sourceLabel(field({source: 'environment', env_value: 3})), 'From the environment (HEAVY_MAX_NMAP=3)');
  assert.equal(L.sourceLabel(field({source: 'admin'})), 'Saved here');
  const lines = L.originLines(field({source: 'admin', value: 4, env_value: 3, set_by: 'alice', set_at: '2026-10-31T10:00:00Z'}), (d) => `<${d}>`);
  assert.deepEqual(lines, ['Default 2', 'HEAVY_MAX_NMAP=3', 'Set by alice on <2026-10-31T10:00:00Z>']);
  assert.deepEqual(L.originLines(field()), ['Default 2', 'HEAVY_MAX_NMAP is not set']);
  assert.equal(L.rangeText(field()), '1 to 8');
});

test('Reset to default is offered only for a value that was saved here', () => {
  assert.equal(L.canReset(field()), false);
  assert.equal(L.canReset(field({source: 'environment', env_value: 3})), false);
  assert.equal(L.canReset(field({source: 'admin'})), true);
});

test('fields are grouped in the order the server gave, and an empty group is left out', () => {
  const fields = [field(), field({key: 'work_depth', group: 'depth'})];
  const groups = L.groupFields(fields, [{id: 'heavy', title: 'A'}, {id: 'discovery', title: 'B'}, {id: 'depth', title: 'C'}]);
  assert.deepEqual(groups.map((g) => [g.id, g.fields.length]), [['heavy', 1], ['depth', 1]]);
});

test('the memory warning follows the typed numbers like the server does', () => {
  const costs = {nmap: 400, nuclei: 1000, 'bbot-deep': 2400};
  const defaults = {nmap: 2, nuclei: 1, 'bbot-deep': 1};
  assert.deepEqual(L.memoryPlan(defaults, costs, 3072, defaults).warnings, []);
  assert.deepEqual(L.memoryPlan({nmap: 1, nuclei: 1, 'bbot-deep': 1}, costs, 100, defaults).warnings, []);
  assert.deepEqual(L.memoryPlan({nmap: 8, nuclei: 8, 'bbot-deep': 4}, costs, null, defaults).warnings, []);
  const plan = L.memoryPlan({nmap: 8, nuclei: 4, 'bbot-deep': 1}, costs, 3072, defaults);
  assert.equal(plan.total, 9600);
  const text = plan.warnings.join(' ');
  assert.match(text, /9600 MB/);
  assert.match(text, /more than 2 times the 3072 MB/);
  assert.deepEqual(L.memoryPlan({nmap: 4, nuclei: 2, 'bbot-deep': 1}, costs, 3072, defaults).warnings, []);
  assert.match(text, /CELERY_MEM_LIMIT/);
  assert.match(text, /second machine/);
  const alone = L.memoryPlan({nmap: 2, nuclei: 4, 'bbot-deep': 1}, costs, 3000, defaults, {nuclei: 'nuclei'});
  assert.ok(alone.warnings.some((w) => w.startsWith('nuclei at 4') && w.includes('by itself')));
});

test('sizes are written in MB or GB, and unknown stays unknown', () => {
  assert.equal(L.formatMb(512), '512 MB');
  assert.equal(L.formatMb(3072), '3.0 GB');
  assert.equal(L.formatMb(null), 'unknown');
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
