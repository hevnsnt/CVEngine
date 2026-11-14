import assert from 'node:assert/strict';
import {test} from 'node:test';

// The Ctrl+K palette folds the rail, a page's tab and the hidden index into one row per page and name (static/cve/nav-fold.js).
const {foldNav} = await import('../static/cve/nav-fold.js');
const link = (label, href) => ({label, href});

test('a page listed in the rail, a tab and the hidden index is one row', () => {
  const rows = foldNav([link('Hygiene', '/cve/a/hygiene/'), link('Hygiene', '/cve/a/hygiene/'), link('Hygiene', '/cve/a/hygiene/'), link('Hosts', '/cve/a/hosts/')]);
  assert.deepEqual(rows.map((r) => r.label), ['Hygiene', 'Hosts']);
  assert.deepEqual(rows.map((r) => r.href), ['/cve/a/hygiene/', '/cve/a/hosts/']);
});

test('the same name on two different pages stays two rows, and one page under two names stays two rows', () => {
  assert.equal(foldNav([link('Scans', '/cve/a/scans/'), link('Scans', '/cve/b/scans/')]).length, 2);
  assert.equal(foldNav([link('Hosts', '/cve/a/hosts/'), link('Assets', '/cve/a/hosts/')]).length, 2);
});

test('the first entry of each page keeps its place and its section', () => {
  const rows = foldNav([link('Overview', '/cve/'), link('Findings', '/cve/a/vulns/'), link('Overview', '/cve/')]);
  assert.deepEqual(rows.map((r) => [r.label, r.hint, r.section]), [['Overview', 'Go to', 'Go to'], ['Findings', 'Go to', 'Go to']]);
});
