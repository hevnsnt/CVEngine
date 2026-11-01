import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The state line of a Sentinel card on the Sentinels page (static/cve/sentinel-live.js). A suspended Sentinel says why on that line, so the
// reason of a suspension never reads as a remark under "Idle, waiting for work". The page imports `/staticfiles/cve/...`; the hook maps that to
// the source directory, and a bare document lets the modules load without a page.
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.document = {getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}};
globalThis.window = globalThis;
globalThis.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};

const {actionsFor, stateLine} = await import('../static/cve/sentinel-live.js');
const NOTE = 'Sentinel "old-box" (#1) of the same user was revoked on 2026-03-02. Reinstate this one to use it, and reinstate or delete #1 so new agents start normally';

test('a suspended Sentinel reads "Suspended: <reason>", never idle', () => {
  const line = stateLine({state: 'suspended', status: 'suspended', status_note: NOTE});
  assert.equal(line, `Suspended: ${NOTE}`);
  assert.doesNotMatch(line, /Idle|waiting for work/);
});

test('a suspended Sentinel with no reason reads "Suspended"', () => {
  assert.equal(stateLine({state: 'suspended', status: 'suspended', status_note: ''}), 'Suspended');
});

test('the other states keep their words, whatever note an administrator left', () => {
  assert.equal(stateLine({state: 'idle', status: 'active', status_note: 'watch it'}), 'Idle, waiting for work');
  assert.equal(stateLine({state: 'pending', status: 'pending', status_note: ''}), 'Waiting for approval');
  assert.equal(stateLine({state: 'working', status: 'active', status_note: ''}), 'Working');
  assert.equal(stateLine({state: 'offline', status: 'active', status_note: ''}), 'Offline');
});

const HELD = {state: 'suspended', status: 'suspended', status_note: NOTE, held_by: {id: 1, name: 'old-box', status: 'revoked', deleted: false}};

test('a held Sentinel the viewer may decide on offers Reinstate and Delete of the revoked agent', () => {
  assert.deepEqual(actionsFor({...HELD, can_manage: true}), ['reinstate', 'delete', 'revoke']);
});

test('no button that would be refused: an org admin\'s own held Sentinel, or a user of another tenant too', () => {
  assert.deepEqual(actionsFor({...HELD, can_manage: false}), []);
  assert.deepEqual(actionsFor({...HELD}), []);  // an older server that does not say: nothing offered
});

test('Delete only for a revoked agent that is known', () => {
  const ids = (held_by) => actionsFor({...HELD, can_manage: true, held_by});
  assert.ok(!ids({id: 1, name: 'old-box', status: 'suspended'}).includes('delete'));  // suspended: reinstate or revoke it first
  assert.ok(!ids({id: null, deleted: true}).includes('delete'));
  assert.ok(!ids({id: null, deleted: false, hidden: true}).includes('delete'));
  assert.ok(!ids(null).includes('delete'));
});

test('pending and active cards keep their buttons', () => {
  assert.deepEqual(actionsFor({state: 'pending', status: 'pending', can_manage: true, held_by: HELD.held_by}), ['approve', 'delete', 'suspend', 'revoke']);
  assert.deepEqual(actionsFor({state: 'idle', status: 'active', can_manage: true, held_by: null}), ['suspend', 'revoke']);
});
