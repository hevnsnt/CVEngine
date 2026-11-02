import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as G from '../static/cve/finding-groups-logic.js';

const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');

const member = (id, host, extra = {}) => ({id, host, heat: 'ice', status: 'open', remediation_status: 'open', classification: 'needs_validation',
  validation_status: 'none', ...extra});
const groupRow = (members, extra = {}) => ({
  type: 'cve', kind: 'match', id: members[0].id, title: 'CVE-2020-11023', host: members[0].host, project: 'bluegrace', status: members[0].status,
  group: {id: 'gabc', hosts: members.length, findings: members.length, registrable_domain: 'mybluegrace.com', member_ids: members.map((m) => m.id),
    members, members_truncated: false, status_counts: {open: members.length}, heat_counts: {ice: members.length}, ...extra},
});
const keyOf = (i) => `${i.kind}-${i.id}`;
const six = ['www', 'blog', 'info', 'careers', 'bgu', 'givinggrace'].map((h, i) => member(10 + i, `${h}.mybluegrace.com`));

test('the list asks for groups by default and for every host when toggled', () => {
  assert.deepEqual(G.listParams({type: 'all'}, G.GROUPED), {type: 'all', group: 'cve'});
  assert.deepEqual(G.listParams({type: 'all'}, G.EVERY_HOST), {type: 'all'});
});

test('a group is a row with more than one member; a lone match is an ordinary row', () => {
  assert.equal(G.isGroup(groupRow(six)), true);
  assert.equal(G.isGroup(groupRow([six[0]])), false);
  assert.equal(G.isGroup({kind: 'match', id: 3}), false);
});

test('the chips count rows when grouped and findings otherwise', () => {
  assert.deepEqual(G.chipCounts({total: 4, counts: {cve: 14, scanner: 1}, row_counts: {cve: 3, scanner: 1}}), {all: 4, cve: 3, scanner: 1});
  assert.deepEqual(G.chipCounts({total: 15, counts: {cve: 14, scanner: 1}}), {all: 15, cve: 14, scanner: 1});
});

test('a group sends every member through the per-finding route, with nothing else', () => {
  const lone = {kind: 'vulnerability', id: 7, project: 'bluegrace'};
  const out = G.expandForBulk([groupRow(six), lone]);
  assert.deepEqual(out.map(keyOf), [...six.map((m) => `match-${m.id}`), 'vulnerability-7']);
  assert.ok(out.slice(0, 6).every((m) => m.project === 'bluegrace' && m.__groupOf === 'gabc'));
  assert.equal(out[1].host, 'blog.mybluegrace.com');
  // member_ids beyond the members listed in full are still sent
  const big = groupRow(six.slice(0, 2), {member_ids: [10, 11, 99], members_truncated: true});
  assert.deepEqual(G.expandForBulk([big]).map((m) => m.id), [10, 11, 99]);
});

test('a group succeeds when every member did, and a failure keeps only the members that failed', () => {
  const row = groupRow(six);
  const members = G.expandForBulk([row]);
  const all = G.foldResults([row], {ok: members, failed: []}, keyOf);
  assert.deepEqual(all, {ok: [row], failed: []});
  const failedOne = members.find((m) => m.id === 12);
  const some = G.foldResults([row], {ok: members.filter((m) => m !== failedOne), failed: [{item: failedOne, error: 'finding not found'}]}, keyOf);
  assert.deepEqual(some.ok, []);
  assert.equal(some.failed.length, 1);
  assert.equal(G.isGroup(some.failed[0].item), false);  // one member left: its own finding
  assert.deepEqual([some.failed[0].item.kind, some.failed[0].item.id, some.failed[0].item.host], ['match', 12, 'info.mybluegrace.com']);
  assert.match(some.failed[0].error, /^1 of 6 hosts not updated: finding not found$/);
  // a retry of the failed row touches only that member
  assert.deepEqual(G.expandForBulk([some.failed[0].item]).map((m) => m.id), [12]);
  const two = members.filter((m) => m.id === 12 || m.id === 14);
  const pair = G.foldResults([{...row, __bulkKey: 'match-10'}], {ok: members.filter((m) => !two.includes(m)), failed: two.map((m) => ({item: m, error: 'nope'}))}, keyOf);
  assert.deepEqual(pair.failed[0].item.group.member_ids, [12, 14]);
  assert.equal(pair.failed[0].item.__bulkKey, 'match-10');
  assert.deepEqual(G.expandForBulk([pair.failed[0].item]).map((m) => m.id), [12, 14]);
  // ordinary rows pass through as they were
  const lone = {kind: 'hygiene', id: 5};
  assert.deepEqual(G.foldResults([lone], {ok: [lone], failed: []}, keyOf), {ok: [lone], failed: []});
});

test('undo puts each member back to its own earlier status, and is not offered when not every member is known', () => {
  const mixed = groupRow([six[0], member(11, 'blog.mybluegrace.com', {status: 'in_progress', remediation_status: 'in_progress'}), six[2]]);
  const prior = G.priorOf(mixed);
  assert.deepEqual(prior, {byMember: {10: 'open', 11: 'in_progress', 12: 'open'}});
  const batches = new Map(G.restoreBatches([mixed], () => prior).map(([was, items]) => [was, items.map((i) => i.id)]));
  assert.deepEqual(Object.fromEntries(batches), {open: [10, 12], in_progress: [11]});
  assert.equal(G.priorOf(groupRow(six, {members_truncated: true})), undefined);
  assert.equal(G.priorOf(groupRow([six[0], member(11, 'b', {status: 'ruled out', remediation_status: ''})])), undefined);
  assert.equal(G.priorOf({kind: 'match', id: 1, status: 'fixed'}), 'fixed');
  assert.equal(G.priorOf({kind: 'match', id: 1, remediation_status: 'accepted_risk'}), 'accepted_risk');
  assert.equal(G.priorOf({kind: 'match', id: 1, status: 'ruled out'}), undefined);
});

test('the row says how many hosts and how their own states split, worst first', () => {
  const g = groupRow(six, {status_counts: {fixed: 1, open: 4, in_progress: 1}, heat_counts: {ice: 4, fire: 2}}).group;
  assert.equal(G.hostsText(g), 'on 6 hosts');
  assert.equal(G.statusSplit(g), '4 open · 1 in progress · 1 fixed');
  assert.equal(G.heatSplit(g), '2 fire · 4 ice');
  assert.equal(G.heatSplit(groupRow(six).group), '');
  const sorted = G.sortedMembers({members: [member(1, 'b.x', {heat: 'ice'}), member(2, 'a.x', {heat: 'fire'}), member(3, 'a.x', {heat: 'ice'})]});
  assert.deepEqual(sorted.map((m) => m.id), [2, 3, 1]);
});

test('a member links to its own finding on this page', () => {
  assert.equal(G.memberHash({id: 12}, 'bluegrace', false), 'match-12');
  assert.equal(G.memberHash({id: 12}, 'bluegrace', true), 'bluegrace:match-12');
});

test('the header keeps findings per host and says what the rows are', () => {
  const flat = G.headerParts({total: 15, counts: {cve: 14, scanner: 1}});
  assert.equal(flat.lead, '15 findings: ');
  assert.equal(flat.grouped, '');
  const grouped = G.headerParts({group: 'cve', total: 5, findings_total: 15, groups: 2, grouped_findings: 12, counts: {cve: 14, scanner: 1}});
  assert.equal(grouped.lead, '15 findings in 5 rows: ');
  assert.deepEqual(grouped.counts, {cve: 14, scanner: 1});
  assert.match(grouped.grouped, /^12 CVE matches on sibling hosts shown as 2 rows/);
});

test('the Findings page wires the grouping in', () => {
  assert.match(app, /import \* as FG from "\/staticfiles\/cve\/finding-groups-logic\.js"/);
  assert.match(app, /Show every host/);
  assert.match(app, /FG\.expandForBulk\(items\)/);
  assert.match(app, /exportParams: filtersNow/);  // the CSV stays one line per host
  assert.match(app, /data-finding-key/);
});
