import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as F from '../static/cve/service-features-logic.js';

const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');

// one host row's `service_features`, as agentapi.services._host returns it (cveFeed.service_features.readings_for)
const http2 = (value, meaning, extra = {}) => ({port: 443, transport: 'tcp', feature: 'http2', label: 'HTTP/2', value, meaning, detail: value === 'yes' ? 'ALPN h2' : 'ALPN http/1.1',
                                                source: 'hygiene_check', observed_at: '2026-11-19T10:00:00+00:00', fresh: true, ...extra});

test('a reading says its value and what it means for a CVE that needs the feature', () => {
  assert.equal(F.featureLine([http2('yes', 'exposed')], 443), 'HTTP/2: yes, supports CVEs that need it (ALPN h2, read 2026-11-19)');
  assert.equal(F.featureLine([http2('no', 'ruled_out')], 443), 'HTTP/2: no, rules out CVEs that need it (ALPN http/1.1, read 2026-11-19)');
});

test('the value is printed as read, never a yes/no guess (a feature may hold several tokens)', () => {
  const ssh = {port: 22, feature: 'ssh_kex', label: 'SSH key exchange', value: 'curve25519-sha256,chacha20-poly1305@openssh.com', meaning: 'exposed', detail: '',
               observed_at: '2026-11-19T10:00:00+00:00', fresh: true};
  assert.match(F.featureLine([ssh], 22), /^SSH key exchange: curve25519-sha256,chacha20-poly1305@openssh.com, supports/);
  assert.doesNotMatch(F.featureLine([http2('yes', 'exposed'), ssh], 443), /not offered/);
  assert.equal(F.featureLine([{...ssh, meaning: ''}], 22), 'SSH key exchange: curve25519-sha256,chacha20-poly1305@openssh.com (read 2026-11-19)');  // no rule reads it
});

test('a stale reading says it is no longer used, and other ports are not shown', () => {
  assert.equal(F.featureLine([http2('no', 'ruled_out', {fresh: false})], 443), 'HTTP/2: no (ALPN http/1.1, read 2026-11-19, stale: no longer used)');
  assert.equal(F.featureLine([http2('yes', 'exposed')], 8443), '');
  assert.equal(F.featureLine(undefined, 443), '');
});

test('the host page draws the readings with this module', () => {
  assert.match(app, /import \{ featureLine \} from "\/staticfiles\/cve\/service-features-logic\.js";/);
  assert.match(app, /featureLine\(h\.service_features, p\.number\)/);
  assert.doesNotMatch(app, /f\.offered/);
});
