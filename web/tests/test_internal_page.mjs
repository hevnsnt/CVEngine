import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/internal-logic.js';

const NOW = Date.parse('2026-11-26T12:00:00Z');
const page = readFileSync(new URL('../static/cve/internal.js', import.meta.url), 'utf8');

test('an offline Sentinel says the network is not being scanned', () => {
  const n = {cidr: '192.168.1.0/24', sentinel: {state: 'offline', total: 1, sentinels: [{name: 'haxxxK', state: 'offline'}]}};
  assert.match(L.rangeWarning(n), /offline, so this network is not being scanned/);
  assert.equal(L.sentinelText(n.sentinel), 'Offline: not checking in. haxxxK (offline)');
  assert.equal(L.nextDiscoveryText({...n, next_discovery: {state: 'waiting'}}, NOW), 'Waits for a Sentinel inside the network');
});

test('a range never discovered says so and is due', () => {
  const n = {cidr: '10.0.0.0/24', hosts: 0, last_discovery_at: null, last_discovery_hosts: null, sentinel: {state: 'online', total: 1}, next_discovery: {state: 'due'}};
  assert.equal(L.lastDiscoveryText(n, NOW), 'Never swept');
  assert.equal(L.nextDiscoveryText(n, NOW), 'Due now: first sweep');
  assert.equal(L.liveHostsText(n), 'Not swept yet');
  assert.match(L.rangeWarning(n), /never swept yet/);
});

test('a discovery error is named before a scan error', () => {
  const n = {cidr: '10.0.0.0/24', last_discovery_error: 'no Sentinel inside the network answered for 10.0.0.0/24', last_error: 'scan failed',
             last_discovery_at: '2026-11-26T11:00:00Z', sentinel: {state: 'online', total: 1}};
  assert.equal(L.lastErrorText(n), 'Discovery: no Sentinel inside the network answered for 10.0.0.0/24');
  assert.match(L.rangeWarning(n), /the last discovery failed/);
  assert.equal(L.lastErrorText({last_error: 'scan failed'}), 'Scan: scan failed');
  assert.equal(L.lastErrorText({}), '');
});

test('a swept range with a live Sentinel reads plainly', () => {
  const n = {cidr: '192.168.1.0/24', hosts: 55, last_discovery_hosts: 55, last_discovery_at: '2026-11-26T09:00:00Z',
             next_discovery: {state: 'scheduled', at: '2026-12-03T09:00:00Z'}, sentinel: {state: 'online', total: 1, sentinels: [{name: 'haxxxK', state: 'online'}]}};
  assert.equal(L.liveHostsText(n), '55 at last sweep');
  assert.equal(L.lastDiscoveryText(n, NOW), '3 hours ago');
  assert.equal(L.nextDiscoveryText(n, NOW), 'In 7 days');
  assert.equal(L.rangeWarning(n), '');
  assert.equal(L.sentinelNames(n.sentinel), 'haxxxK (online)');
});

test('the page builds its DOM with text only and reads the one internal endpoint', () => {
  assert.doesNotMatch(page, /innerHTML/);
  assert.match(page, /\/cve\/api\/internal\?project=/);
});

test('no words on the page use dashes as punctuation', () => {
  const src = readFileSync(new URL('../static/cve/internal-logic.js', import.meta.url), 'utf8') + page;
  for (const s of src.match(/"[^"\n]*"|`[^`\n]*`/g) || []) {
    assert.doesNotMatch(s, /\u2014|\u2013|\x2d\x2d/, s);
  }
});
