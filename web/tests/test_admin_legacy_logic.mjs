import test from 'node:test';
import assert from 'node:assert/strict';
import { legacyAdminTarget } from '../static/cve/admin-legacy-logic.js';

test('the old Agents tab link goes to the Sentinels page', () => {
  assert.equal(legacyAdminTarget('#agents'), '/cve/sentinels/');
});
test('other tabs stay on the Administration page', () => {
  for (const h of ['', '#users', '#audit', '#openvas', '#agentsx']) assert.equal(legacyAdminTarget(h), null);
});
