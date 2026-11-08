import assert from 'node:assert/strict';
import {test} from 'node:test';

// The Provision a Sentinel form (static/cve/provision-form.js): nothing is pre-selected and Provision stays off until every required field has a
// real choice. A Sentinel provisioned to the wrong customer is a data-isolation error; Full runs OpenVAS and is heavy.
const {missingChoice} = await import('../static/cve/provision-form.js');
const full = {scope: 'project', project: 'alpha', org: '', network: 'external', profile: 'light'};

test('an untouched form is missing the scope first', () => {
  assert.equal(missingChoice({scope: '', project: '', org: '', network: '', profile: ''}), 'Choose a scope to continue.');
});

test('a project scope needs a project, an organization scope an organization, the instance scope neither', () => {
  assert.equal(missingChoice({...full, project: ''}), 'Choose a project.');
  assert.equal(missingChoice({...full, scope: 'org', project: ''}), 'Choose an organization.');
  assert.equal(missingChoice({...full, scope: 'org', project: '', org: 'one'}), '');
  assert.equal(missingChoice({...full, scope: 'instance', project: ''}), '');
});

test('where it runs and size are never defaulted', () => {
  assert.equal(missingChoice({...full, network: ''}), 'Choose where it runs.');
  assert.equal(missingChoice({...full, profile: ''}), 'Choose a size.');
});

test('only a complete form says nothing is missing; an unknown scope is not a choice', () => {
  assert.equal(missingChoice(full), '');
  assert.notEqual(missingChoice({...full, scope: 'everything'}), '');
});
