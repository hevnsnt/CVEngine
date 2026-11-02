import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/addtargets-logic.js';

const dialog = readFileSync(new URL('../static/cve/addtargets.js', import.meta.url), 'utf8');

test('a leading = is kept in front of the normalized host, as agentapi.services.normalize_target keeps it', () => {
  assert.equal(L.normalizeTarget('=example.com'), '=example.com');
  assert.equal(L.normalizeTarget('=App.Example.com.'), '=app.example.com');
  assert.equal(L.normalizeTarget('=https://admin:pw@App.Example.com:8443/x?a=b#f'), '=app.example.com');
  assert.equal(L.normalizeTarget('=*.example.com'), '=example.com');
  assert.equal(L.normalizeTarget('=203.0.113.7/32'), '=203.0.113.7');
  assert.equal(L.normalizeTarget('==example.com'), '==example.com'); // stays invalid: the server reports it
  assert.equal(L.normalizeTarget('=-example.com'), '=-example.com');
});

test('the mark does not collide with an exclusion or with an = inside a URL', () => {
  assert.equal(L.normalizeTarget('-example.com'), '-example.com');
  assert.equal(L.normalizeTarget('https://example.com/?next=a.com'), 'example.com');
  assert.equal(L.normalizeTarget('example.com'), 'example.com');
});

test('the count matches what the server adds: a marked and an unmarked copy of one name are one target', () => {
  assert.equal(L.countEntries('=a.example\na.example\nb.example'), 2);
  assert.equal(L.countHostOnly('=a.example\na.example\nb.example'), 1);
  assert.equal(L.countExclusions('=a.example\n-c.example'), 1);
  assert.equal(L.countLabel('=a.example\nb.example\n-c.example'), '2 targets (1 this host only), 1 exclusion');
  assert.equal(L.countLabel('a.example'), '1 target');
  assert.equal(L.countLabel('##Acme\n#Web\n=a.example\n#Ops\nb.example'), '2 targets (1 this host only) across 2 projects');
  assert.equal(L.countEntries('a.example # =commented.example'), 1);
});

test('a mark standing alone belongs to the next entry on its line, as on the server', () => {
  assert.deepEqual([...L.tokensOf(['= spaced.example'])], ['=spaced.example']);
  assert.deepEqual([...L.tokensOf(['a.example =', 'b.example'])], ['a.example', '=', 'b.example']);
  assert.equal(L.countLabel('= spaced.example'), '1 target (1 this host only)');
  assert.equal(L.countLabel('=  "quoted.example", b.example'), '2 targets (1 this host only)');
});

test('marks the server refuses count as nothing: a bare =, ==x and =-x', () => {
  for (const text of ['=', '==a.com', '=-a.com', 'a.com =']) {
    assert.equal(L.countHostOnly(text), 0, text);
  }
  assert.equal(L.countEntries('=\n==a.com\n=-b.com'), 0);
  assert.equal(L.countEntries('a.com ='), 1);
  assert.equal(L.countExclusions('-=a.com'), 0);
});

test('the Scope choice: auto first and sent as nothing, the others sent as scope_mode', () => {
  assert.deepEqual(L.SCOPE_CHOICES.map(([v]) => v), ['auto', 'host', 'parent']);
  assert.equal(L.DEFAULT_SCOPE, 'auto');
  assert.deepEqual(L.scopeBody('auto'), {});
  assert.deepEqual(L.scopeBody(undefined), {});
  assert.deepEqual(L.scopeBody('host'), {scope_mode: 'host'});
  assert.deepEqual(L.scopeBody('parent'), {scope_mode: 'parent'});
  assert.deepEqual(L.scopeBody('everything'), {});
  assert.match(L.SCOPE_HINT, /=example\.com/);
});

test('the dialog draws the Scope choice and its hint, and sends the choice with the paste', () => {
  assert.match(dialog, /from "\/staticfiles\/cve\/addtargets-logic\.js"/);
  assert.match(dialog, /SCOPE_CHOICES\.forEach/);
  assert.match(dialog, /el\('p', 'note', SCOPE_HINT/);
  assert.match(dialog, /\.\.\.scopeBody\(scope\.value\)/);
  assert.doesNotMatch(dialog, /const normalizeTarget/, 'the dialog keeps a second copy of the parser');
});
