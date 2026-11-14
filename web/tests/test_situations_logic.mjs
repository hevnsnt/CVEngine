import assert from 'node:assert/strict';
import {test} from 'node:test';

import {chipsOf, countLine, heatOf, moreFindings, safeLink, stateView} from '../static/cve/situations-logic.js';

test('chips list the tiers a situation has, worst first, and leave out the empty ones', () => {
  assert.deepEqual(chipsOf({proven: 2, likely: 0, exposure: 1, minor: 4}).map((c) => c.label), ['2 proven', '1 exposed', '4 minor']);
  assert.deepEqual(chipsOf({}), []);
  assert.deepEqual(chipsOf(null), []);
});

test('the edge colour is the worst tier: proof is fire, likely is smoke, the rest is not coloured', () => {
  assert.equal(heatOf({proven: 1, likely: 3}), 'fire');
  assert.equal(heatOf({proven: 0, likely: 1}), 'smoke');
  assert.equal(heatOf({exposure: 5, minor: 1}), '');
});

test('a link may only open one of the existing panes of a project', () => {
  for (const ok of ['/cve/sa/vulns/#match-12', '/cve/sa/vulns/#vulnerability-3', '/cve/sa/hygiene/#hygiene-9', '/cve/sa/secrets/?open=4', '/cve/sa/hosts/?host=a.example.com', '/cve/_all/vulns/']) {
    assert.equal(safeLink(ok), ok, ok);
  }
  for (const bad of ['javascript:alert(1)', 'https://evil.example/cve/sa/vulns/', '//evil.example/cve/sa/vulns/', '/cve/sa/../admin/', '/cve/sa/vulns/#"><img src=x>', '/cve/sa/settings/', '', null, undefined, 5]) {
    assert.equal(safeLink(bad), '', String(bad));
  }
});

test('the three empty states come from the server state and are never mixed up', () => {
  const clear = stateView({state: 'clear', hosts: 12, last_scan_at: '2026-11-10T09:00:00Z', count: 0});
  assert.equal(clear.title, 'Nothing needs you');
  assert.equal(clear.tone, 'calm');
  assert.match(clear.body, /12 hosts were checked/);
  assert.match(clear.body, /2026-11-10/);
  assert.equal(stateView({state: 'clear', hosts: 1}).body.startsWith('1 host was checked and nothing open on it'), true);
  const fresh = stateView({state: 'unscanned', hosts: 0, count: 0});
  assert.equal(fresh.title, 'Nothing has been scanned yet');
  assert.notEqual(fresh.title, clear.title);
  assert.equal(fresh.tone, '');
  const none = stateView({state: 'attention', count: 0}, {filtered: true});
  assert.equal(none.kind, 'nomatch');
  assert.match(none.body, /Clear the search/);
  assert.notEqual(none.title, 'Nothing needs you');
  // unknown or missing answers are never "nothing needs you"
  assert.equal(stateView(undefined).kind, 'nomatch');
  assert.equal(stateView({}).kind, 'nomatch');
});

test('counts and the truncated-findings line', () => {
  assert.equal(countLine({count: 1}), '1 situation');
  assert.equal(countLine({count: 0}), '0 situations');
  assert.equal(countLine({}), '');
  assert.equal(moreFindings({findings: [1, 2], findings_total: 9, findings_truncated: true}), 'Showing 2 of 9 findings.');
  assert.equal(moreFindings({findings: [1], findings_total: 1, findings_truncated: false}), '');
});
