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
    members, members_truncated: false, status_counts: {open: members.length}, heat_counts: {ice: members.length},
    member_status: Object.fromEntries(members.map((m) => [String(m.id), m.remediation_status])), ruled_out_ids: [], ...extra},
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
  assert.deepEqual(all, {ok: [{...row, __changedIds: [10, 11, 12, 13, 14, 15]}], failed: []});
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

test('undo puts each member back to its own earlier status, from the full status map even past the listed members', () => {
  const mixed = groupRow([six[0], member(11, 'blog.mybluegrace.com', {status: 'in_progress', remediation_status: 'in_progress'}), six[2]]);
  const prior = G.priorOf(mixed);
  assert.deepEqual(prior, {byMember: {10: 'open', 11: 'in_progress', 12: 'open'}});
  const batches = new Map(G.restoreBatches([mixed], () => prior).map(([was, items]) => [was, items.map((i) => i.id)]));
  assert.deepEqual(Object.fromEntries(batches), {open: [10, 12], in_progress: [11]});
  // only the members the action changed go back
  const changed = new Map(G.restoreBatches([{...mixed, __changedIds: [10, 11]}], () => prior).map(([was, items]) => [was, items.map((i) => i.id)]));
  assert.deepEqual(Object.fromEntries(changed), {open: [10], in_progress: [11]});
  // 150 members, 100 listed: member_status still knows every one
  const many = Array.from({length: 150}, (_, i) => member(100 + i, `h${i}.x.com`));
  const big = groupRow(many.slice(0, 100), {member_ids: many.map((m) => m.id), members_truncated: true,
    member_status: Object.fromEntries(many.map((m, i) => [String(m.id), i === 149 ? 'fixed' : 'open']))});
  assert.equal(Object.keys(G.priorOf(big).byMember).length, 150);
  assert.equal(G.priorOf(big).byMember[249], 'fixed');
  assert.equal(G.priorOf({kind: 'match', id: 1, status: 'fixed'}), 'fixed');
  assert.equal(G.priorOf({kind: 'match', id: 1, remediation_status: 'accepted_risk'}), 'accepted_risk');
  assert.equal(G.priorOf({kind: 'match', id: 1, status: 'ruled out'}), undefined);
});

// the probe from the review: four open hosts, one accepted risk, one fixed
const probe = () => {
  const ms = [...six.slice(0, 4), member(14, 'bgu.mybluegrace.com', {status: 'accepted_risk', remediation_status: 'accepted_risk'}),
    member(15, 'givinggrace.mybluegrace.com', {status: 'fixed', remediation_status: 'fixed'})];
  return groupRow(ms, {status_counts: {open: 4, accepted_risk: 1, fixed: 1}});
};

test('a group action changes only the open and in progress hosts it actually changes, unless closed ones are included', () => {
  const row = probe();
  assert.deepEqual(G.targetsOf(row.group, 'in_progress'), {ids: [10, 11, 12, 13], closed: 2, same: 0});
  assert.deepEqual(G.expandForBulk([row], 'in_progress').map((m) => m.id), [10, 11, 12, 13]);  // the accepted host is not reopened
  assert.deepEqual(G.targetsOf(row.group, 'fixed'), {ids: [10, 11, 12, 13], closed: 1, same: 1});
  assert.deepEqual(G.targetsOf(row.group, 'open'), {ids: [], closed: 2, same: 4});
  assert.deepEqual(G.expandForBulk([row], 'in_progress', {includeClosed: true}).map((m) => m.id), [10, 11, 12, 13, 14, 15]);
  assert.deepEqual(G.expandForBulk([row], 'fixed', {includeClosed: true}).map((m) => m.id), [10, 11, 12, 13, 14]);
  // a member the AI ruled out is left alone by default too
  const ruled = groupRow(six, {ruled_out_ids: [15]});
  assert.deepEqual(G.targetsOf(ruled.group, 'fixed').ids, [10, 11, 12, 13, 14]);
  assert.equal(G.closedCount(probe().group), 2);
});

test('the confirmation says how many hosts change and how many settled ones are left as they are', () => {
  assert.equal(G.confirmText([probe()], 'in_progress'),
    'Mark 4 hosts in 1 group as in progress (2 already fixed, accepted or ruled out left as they are). Each host keeps its own history.');
  assert.match(G.confirmText([probe(), {kind: 'vulnerability', id: 3}], 'fixed'), /^Mark 4 hosts in 1 group and 1 other finding as fixed \(1 already fixed, accepted or ruled out left as they are; 1 already fixed\)/);
  assert.equal(G.confirmText([{kind: 'match', id: 3}], 'fixed'), null);  // no group: no question, as before
  assert.equal(G.menuLabel(probe(), 'in_progress', 'In progress'), 'Mark as In progress (4 hosts; 2 fixed or accepted left as they are)');
  assert.equal(G.menuLabel(probe(), 'in_progress', 'In progress', {includeClosed: true}), 'Mark as In progress, including closed hosts (6 hosts)');
});

test('the done message counts findings and sites, not rows', () => {
  const a = {...probe(), __changedIds: [10, 11, 12, 13]};
  const b = {...groupRow([member(30, 'www.other.org'), member(31, 'blog.other.org')]), group: {...groupRow([member(30, 'www.other.org'), member(31, 'blog.other.org')]).group, registrable_domain: 'other.org'}};
  assert.equal(G.doneSummary([a, b, {kind: 'hygiene', id: 2, host: 'mail.x.com'}]), '7 findings on 3 sites');
  assert.equal(G.doneSummary([{kind: 'match', id: 1, host: 'a.x'}]), '1 finding on 1 site');
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
  assert.equal(grouped.truncated, '');
  assert.equal(G.headerParts({group: 'cve', total: 5, group_scan_truncated: true}).truncated,
    'Showing the first 20,000 matches grouped; narrow the filters or use Show every host.');
  assert.equal(G.headerParts({total: 5, group_scan_truncated: true}).truncated, '');
});

test('the dashboard shows the grouped count only when it is smaller and exact', () => {
  assert.equal(G.dashboardNote(14, 4, false).text, 'in 4');
  assert.match(G.dashboardNote(14, 4, false).title, /^14 matches, one per host, are 4 distinct findings/);
  assert.deepEqual(G.dashboardNote(14, 4, true), {text: '', title: ''});  // the pass hit its cap: no number rather than a wrong one
  assert.deepEqual(G.dashboardNote(4, 4, false), {text: '', title: ''});
  assert.deepEqual(G.dashboardNote(undefined, undefined, undefined), {text: '', title: ''});
});

test('the Findings page wires the grouping in', () => {
  assert.match(app, /import \* as FG from "\/staticfiles\/cve\/finding-groups-logic\.js"/);
  assert.match(app, /Show every host/);
  assert.match(app, /FG\.expandForBulk\(items, value, opts\)/);
  assert.match(app, /exportParams: filtersNow/);  // the CSV stays one line per host
  assert.match(app, /data-finding-key/);
  assert.match(app, /group-truncated/);  // the truncation note is drawn
  assert.match(app, /confirm: \(n, items, value\) => FG\.confirmText\(items, value\)/);
  const bulk = readFileSync(new URL('../static/cve/bulk.js', import.meta.url), 'utf8');
  assert.match(bulk, /result\.summary \?/);
  const dash = readFileSync(new URL('../static/cve/dashboard.js', import.meta.url), 'utf8');
  assert.match(dash, /dashboardNote\(s\.matches, s\.match_groups, s\.match_groups_truncated\)/);
});
