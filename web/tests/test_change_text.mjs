import assert from 'node:assert/strict';
import {test} from 'node:test';

// Every kind of change the server can write (cveFeed/models.py AssetChange.KINDS) goes through the renderer, with the shapes the real code writes
// (cveFeed/changes.py, route_auth.py) and with the values missing: the Changes page must say a plain sentence, never "[object Object]", "undefined",
// "null", "NaN" or a bare "?".
const {changeDetail} = await import('../static/cve/change-text.js');

const STATE = {ips: {'203.0.113.7': {ports: {'443/tcp': {service: 'https', product: 'nginx', version: '1.24'}}}}, techs: ['nginx:1.24']};
const REAL = [
  {kind: 'host_new', after: STATE},
  {kind: 'host_returned', after: {evidence: 'scannable address in a new scan'}},
  {kind: 'host_returned', after: STATE},
  {kind: 'host_retired', before: {ips: ['203.0.113.7']}, after: null},
  {kind: 'host_retired', before: {ips: []}, after: {tcp_alive: ['203.0.113.7:22']}},
  {kind: 'port_opened', ip: '203.0.113.7', port: 443, after: {port: '443/tcp', service: 'https', product: 'nginx', version: '1.24'}},
  {kind: 'port_opened', ip: '203.0.113.7', port: 8443, after: {port: '8443/tcp', service: '', product: '', version: ''}},
  {kind: 'port_closed', ip: '203.0.113.7', port: 22, before: {port: '22/tcp', service: 'ssh', product: 'OpenSSH', version: '8.9'}},
  {kind: 'service_changed', ip: '203.0.113.7', port: 22, before: {port: '22/tcp', product: 'OpenSSH', version: '8.9'}, after: {port: '22/tcp', product: 'OpenSSH', version: '9.6'}},
  {kind: 'service_changed', port: 80, before: {port: '80/tcp', product: 'nginx', version: '1.18'}, after: {port: '80/tcp', product: '', version: ''}},
  {kind: 'service_changed', port: 80, before: {port: '80/tcp', product: '', version: '1.2'}, after: {port: '80/tcp', product: 'nginx', version: '1.2'}},
  {kind: 'tech_added', before: null, after: 'nginx:1.24'},
  {kind: 'tech_added', before: null, after: 'wordpress'},
  {kind: 'tech_removed', before: 'php:7.4', after: null},
  {kind: 'tech_version_changed', before: 'php:7.4', after: 'php:8.2'},
  {kind: 'cert_changed', port: 443, before: {subject: 'a.example.com', issuer: 'R3', sans: [], not_after: '2026-12-01T00:00:00+00:00', key_description: ''}, after: {subject: 'a.example.com', issuer: 'E5', sans: [], not_after: null, key_description: ''}},
  {kind: 'cert_changed', port: 443, before: {subject: 'a', issuer: 'R3', sans: ['x'], not_after: '2026-12-01', key_description: 'rsa'}, after: {subject: 'a', issuer: 'R3', sans: ['y'], not_after: '2026-12-01', key_description: 'rsa'}},
  {kind: 'auth_changed', before: {auth_state: 'login', url: 'https://a.example.com/admin'}, after: {auth_state: 'open', url: 'https://a.example.com/admin', http_status: 200}},
  {kind: 'sensitive_found', before: {types: []}, after: {url: 'https://a.example.com/export', types: ['email', 'aws_key'], counts: {email: 3, aws_key: 1}}},
  {kind: 'zombie_host', before: {ips: ['203.0.113.7']}, after: {alive: ['203.0.113.7:443']}},
  {kind: 'zombie_cleared', before: {zombie_since: '2026-11-01T00:00:00+00:00'}, after: null},
  {kind: 'route_retired', before: {auth_state: 'login', url: 'https://a.example.com/old'}, after: {url: 'https://a.example.com/old', auth_state: 'not_found', http_status: 404}},
  {kind: 'zombie_route', before: {endpoint_status: 'retired', scan_id: 4}, after: {url: 'https://a.example.com/old', auth_state: 'open', http_status: 200}},
  {kind: 'zombie_route', before: {retired_at: '2026-11-01T00:00:00+00:00', url: 'https://a.example.com/old'}, after: {url: 'https://a.example.com/old', auth_state: 'open', http_status: 200}},
  {kind: 'screenshot_changed', before: {hash: 'ab', subdomain_id: 1}, after: {hash: 'cd', subdomain_id: 2, distance: 18, root_auth: 'login'}},
];
const KINDS = ['host_new', 'host_returned', 'host_retired', 'port_opened', 'port_closed', 'service_changed', 'tech_added', 'tech_removed', 'tech_version_changed',
  'cert_changed', 'auth_changed', 'sensitive_found', 'zombie_host', 'zombie_cleared', 'route_retired', 'zombie_route', 'screenshot_changed'];
const BAD = /\[object|undefined|\bnull\b|NaN|(^|[\s(:→>])\?($|[\s),.:])/;

test('every kind the server can write has a case in the test', () => {
  KINDS.forEach((k) => assert.ok(REAL.some((c) => c.kind === k), `no real-shaped example of ${k}`));
});

test('every real-shaped change reads as a plain sentence', () => {
  REAL.forEach((c) => {
    const t = changeDetail(c);
    assert.equal(typeof t, 'string');
    assert.ok(t.length > 4, `${c.kind}: too short: ${t}`);
    assert.doesNotMatch(t, BAD, `${c.kind}: ${t}`);
  });
});

test('a change with nothing in it still says words, not a placeholder', () => {
  KINDS.forEach((k) => {
    [{kind: k}, {kind: k, before: null, after: null}, {kind: k, before: {}, after: {}}, {kind: k, before: {port: 443}, after: {port: 443}}, {kind: k, before: 5, after: [1, 2]}].forEach((c) => {
      assert.doesNotMatch(changeDetail(c), BAD, `${k} ${JSON.stringify(c)}: ${changeDetail(c)}`);
    });
  });
});

test('the examples from the review read as short sentences', () => {
  assert.equal(changeDetail({kind: 'tech_added', after: 'nginx:1.24'}), 'nginx 1.24 added');
  assert.equal(changeDetail(REAL[8]), 'OpenSSH 8.9 → 9.6 on port 22/tcp');
  assert.equal(changeDetail({kind: 'service_changed', port: 443, before: {product: 'nginx'}, after: {}}), 'nginx no longer named on port 443');
});
