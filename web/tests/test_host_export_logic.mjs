import assert from 'node:assert/strict';
import {test} from 'node:test';

// "Export all hosts" (static/cve/host-export-logic.js, drawn by host-export.js): the choices, the route, the words after the download.
const L = await import('../static/cve/host-export-logic.js');

test('a project export goes to the project route and an organization export to the organization route', () => {
  assert.equal(L.exportPath({slug: 'acme-web'}), '/api/v1/projects/acme-web/hosts/export');
  assert.equal(L.exportPath({org: 'acme'}), '/api/v1/orgs/acme/hosts/export');
  assert.equal(L.exportPath({slug: 'ignored', org: 'acme'}), '/api/v1/orgs/acme/hosts/export');
  assert.equal(L.exportPath({slug: 'a b/c'}), '/api/v1/projects/a%20b%2Fc/hosts/export');
});

test('the default choice is the safe one: CSV, internet-facing hosts only, no archived hosts', () => {
  assert.equal(L.exportQuery(), 'format=csv&scope=external&archived=0');
  assert.deepEqual(L.DEFAULTS, {format: 'csv', scope: 'external', archived: false});
});

test('each choice reaches the query, and a value nobody offered falls back to the default', () => {
  assert.equal(L.exportQuery({format: 'txt', scope: 'all', archived: true}), 'format=txt&scope=all&archived=1');
  assert.equal(L.exportQuery({format: 'xlsx', scope: 'everything', archived: 'yes'}), 'format=csv&scope=external&archived=1');
});

test('the dialog offers the two formats and the two scopes, internet-facing first', () => {
  assert.deepEqual(L.FORMATS.map(([v]) => v), ['csv', 'txt']);
  assert.deepEqual(L.SCOPES.map(([v]) => v), ['external', 'all']);
  assert.match(L.SCOPES[0][1], /Internet-facing only/);
  assert.match(L.SCOPES[1][1], /Include internal/);
  assert.match(L.FORMATS[0][1], /Spreadsheet/);
  assert.match(L.FORMATS[1][1], /Plain list for tools/);
});

test('the organization picker lists each organization the person can see once, by name, with its projects', () => {
  const projects = [
    {slug: 'p1', org: 'zeta', org_name: 'Zeta Corp'},
    {slug: 'p2', org: 'acme', org_name: 'Acme'},
    {slug: 'p3', org: 'acme', org_name: 'Acme'},
    {slug: 'p4', org: null, org_name: null},
  ];
  assert.deepEqual(L.organizationsOf(projects), [
    {slug: 'acme', name: 'Acme', projects: 2},
    {slug: 'zeta', name: 'Zeta Corp', projects: 1},
  ]);
  assert.deepEqual(L.organizationsOf([]), []);
  assert.deepEqual(L.organizationsOf(undefined), []);
});

test('an organization export cannot start before an organization is chosen; a project export always can', () => {
  assert.equal(L.canExport({all: true, org: ''}), false);
  assert.equal(L.canExport({all: true, org: 'acme'}), true);
  assert.equal(L.canExport({all: false, org: ''}), true);
});

test('the file name is the server\'s, and only a plain one is trusted', () => {
  assert.equal(L.filenameFrom('attachment; filename="cvengine-hosts-acme-2026-11-14.csv"', 'x.csv'), 'cvengine-hosts-acme-2026-11-14.csv');
  assert.equal(L.filenameFrom('attachment; filename=cvengine-hosts-acme-2026-11-14.txt', 'x.txt'), 'cvengine-hosts-acme-2026-11-14.txt');
  assert.equal(L.filenameFrom('attachment; filename="../../etc/passwd"', 'x.csv'), 'x.csv');
  assert.equal(L.filenameFrom(null, 'x.csv'), 'x.csv');
});

test('the toast says how many hosts the file holds', () => {
  assert.equal(L.doneMessage({hosts: 1, entries: 1, format: 'csv'}), 'Exported 1 host');
  assert.equal(L.doneMessage({hosts: 1234, entries: 1234, format: 'csv'}), 'Exported 1,234 hosts');
  assert.equal(L.doneMessage({hosts: 3, entries: 5, format: 'txt'}), 'Exported 3 hosts (5 names and addresses)');
  assert.equal(L.doneMessage({hosts: 0, entries: 0, format: 'csv'}), 'Exported an empty list: no host matches these choices');
  assert.equal(L.doneMessage({hosts: NaN, entries: NaN, format: 'csv'}), 'Exported the host list');
});

test('the counts are read from the headers the server sends, and a missing header is not a count', () => {
  const headers = new Map([['X-Export-Hosts', '42'], ['X-Export-Entries', '80']]);
  assert.deepEqual(L.countsFrom(headers), {hosts: 42, entries: 80});
  const none = L.countsFrom(new Map());
  assert.ok(Number.isNaN(none.hosts) && Number.isNaN(none.entries));
});

test('what the dialog promises the file holds says nothing of findings, notes or owners being in it', () => {
  assert.match(L.CONTAINS, /No findings, notes, owners or scores/);
});

// --- one host ----------------------------------------------------------------------------------------------------------------------------

test('the address selects a host by its id, and nothing else counts as a selection', () => {
  assert.equal(L.hostIdFromHash('#40413'), 40413);
  assert.equal(L.hostIdFromHash('40413'), 40413);
  assert.equal(L.hostIdFromHash('#40413&validate'), 40413);
  for (const hash of ['', '#', '#0', '#abc', '#12abc', '#-4', '#certs', null, undefined]) assert.equal(L.hostIdFromHash(hash), null, String(hash));
});

test('the label: Export all hosts with no selection, Export host with one, and back after a deselect', () => {
  assert.equal(L.buttonLabel(L.hostIdFromHash('')), 'Export all hosts');
  assert.equal(L.buttonLabel(L.hostIdFromHash('#40413')), 'Export host');
  assert.equal(L.buttonLabel(L.hostIdFromHash('#41')), 'Export host');  // a hash change to another host
  assert.equal(L.buttonLabel(L.hostIdFromHash('')), 'Export all hosts');  // deselected
  assert.match(L.buttonTitle(null), /penetration testing/);
  assert.match(L.buttonTitle(5), /ZIP/);
});

test('one host goes to its own route under the project', () => {
  assert.equal(L.hostExportPath({slug: 'acme-web', id: 40413}), '/api/v1/projects/acme-web/hosts/40413/export');
  assert.equal(L.hostExportPath({slug: 'a b', id: 1}), '/api/v1/projects/a%20b/hosts/1/export');
});

test('the one-host dialog says what the file holds and that secrets are masked', () => {
  const all = L.HOST_CONTAINS.join(' ');
  for (const word of ['host.json', 'Services', 'finding', 'history', 'inventory', 'Screenshots', 'certificates', 'masked']) assert.match(all, new RegExp(word));
  assert.match(L.HOST_NOTE, /audit log/);
});

test('the toast after one host: its name and the counts, or just the name when a proxy dropped the headers', () => {
  const h = (o) => ({get: (k) => o[k]});
  assert.deepEqual(L.hostCountsFrom(h({'X-Export-Findings': '3', 'X-Export-Screenshots': '1'})), {findings: 3, screenshots: 1});
  assert.equal(L.hostDoneMessage({name: 'www.example.com', findings: 3, screenshots: 1}), 'Exported www.example.com (3 findings, 1 screenshot)');
  assert.equal(L.hostDoneMessage({name: 'a', findings: 1, screenshots: NaN}), 'Exported a (1 finding)');
  assert.equal(L.hostDoneMessage({name: '', findings: NaN}), 'Exported the host');
});
