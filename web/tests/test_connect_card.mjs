import test from 'node:test';
import assert from 'node:assert/strict';
import { PLACEHOLDER, TABS, commands, createCard } from '../static/cve/connect-card-logic.js';

const O = 'https://cve.example.com';

test('before a token exists every block carries the placeholder and says to create one', () => {
  const v = createCard(O).view();
  assert.equal(v.filled, false);
  assert.match(v.hint, /Create a token above and this fills in/);
  for (const k of ['tell', 'claude', 'mcp', 'rest']) assert.ok(v.commands[k].includes(PLACEHOLDER), k);
  assert.equal(v.announce, '');
});

test('a created token rewrites every block, announces it and warns it is shown once', () => {
  const c = createCard(O);
  c.reveal('cve_abc123');
  const v = c.view();
  assert.equal(v.filled, true);
  for (const k of ['tell', 'claude', 'mcp', 'rest']) { assert.ok(v.commands[k].includes('cve_abc123'), k); assert.ok(!v.commands[k].includes(PLACEHOLDER), k); }
  assert.match(v.hint, /only time the token is shown/);
  assert.equal(v.announce, 'Token created. Commands updated.');
});

test('dismiss (and so reload, which makes a new card) goes back to placeholders and keeps nothing', () => {
  const c = createCard(O);
  c.reveal('cve_abc123');
  c.dismiss();
  const v = c.view();
  assert.equal(v.filled, false);
  assert.equal(v.token, null);
  assert.ok(!JSON.stringify(v).includes('cve_abc123'));
  assert.equal(createCard(O).view().filled, false);
});

test('the prompt names this host, the transport, the header and the confirming calls; the others are exact', () => {
  const c = commands({ origin: O, token: 'T' });
  assert.equal(c.tell, 'Add the cvENGINE MCP server to your tools: URL https://cve.example.com/mcp/, transport Streamable HTTP, header Authorization: Bearer T. Then call whoami and list_projects to confirm it works.');
  assert.equal(c.claude, 'claude mcp add --transport http cvengine https://cve.example.com/mcp/ --header "Authorization: Bearer T"');
  assert.deepEqual(JSON.parse(c.mcp), { mcpServers: { cvengine: { url: 'https://cve.example.com/mcp/', headers: { Authorization: 'Bearer T' } } } });
  assert.equal(c.rest, 'curl -H "Authorization: Bearer T" https://cve.example.com/api/v1/me');
});

test('Tell your agent is first and the default; an unknown tab is ignored', () => {
  assert.equal(TABS[0][0], 'tell');
  const c = createCard(O);
  assert.equal(c.view().tab, 'tell');
  c.select('rest'); assert.equal(c.view().tab, 'rest');
  c.select('nope'); assert.equal(c.view().tab, 'rest');
});
