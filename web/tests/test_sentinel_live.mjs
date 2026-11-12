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

const {actionsFor, glanceText, plannerRows, routingText, stageRunsText, stateLine} = await import('../static/cve/sentinel-live.js');
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

test('the stages waiting without a worker read as one sentence, and nothing at all when none waits (Q4)', () => {
  assert.equal(stageRunsText({waiting: 0, resumed_1h: 0}), '');
  assert.equal(stageRunsText(undefined), '');
  const text = stageRunsText({waiting: 3, waiting_by_kind: {nmap_scan: 2, 'sweep.testssl': 1}, oldest_wait_seconds: 125,
                              callback_latency_p50_seconds: 0.4, callback_latency_p95_seconds: 2, freed_seconds_1h: 3720, resumed_1h: 9});
  assert.match(text, /^3 stages wait on Sentinels without holding a worker \(nmap 2, TLS audit 1\), the oldest for 2m 5s/);
  assert.match(text, /continues 0s after its last task typically, 2s at worst/);
  assert.match(text, /1h 2m of worker time given back in the last hour\.$/);
});

test('the routing sentence says the built-in scanner is the last resort and how the day was shared', () => {
  assert.equal(routingText(undefined), '');
  const base = {explanation: 'The built-in scanner is the path of last resort.', builtin_24h: 1, external_24h: 40, externals: 2};
  const text = routingText(base);
  assert.match(text, /^The built-in scanner is the path of last resort\./);
  assert.match(text, /handled 1 task and external Sentinels handled 40 tasks\./);
  assert.doesNotMatch(text, /No external Sentinel is set up/);
  assert.match(routingText({...base, externals: 0, builtin_24h: 7, external_24h: 0}), /No external Sentinel is set up, so the built-in scanner does all the scanning\.$/);
  assert.match(routingText({...base, builtin_24h: 0, external_24h: 0}), /No task was finished by a Sentinel in the last 24 hours\./);
});

test('the planner line and the due table come from the server and nothing else', () => {
  const planner = {enabled: true, line: 'Planner: queued 25 SSH checks and 40 secret checks, 3,102 hosts still due for secret checks, next run in 40 s',
    kinds: [{label: 'SSH checks', applicable: 1217, due: 949, awaiting: 0, in_flight: 25}, {label: 'secret checks', applicable: 2815, due: 3102, awaiting: 12, in_flight: 40}]};
  const out = plannerRows(planner);
  assert.equal(out.line, planner.line);
  assert.deepEqual(out.head, ['Check', 'Applies to', 'Due', 'Waiting for the route check', 'Queued or running']);
  assert.deepEqual(out.rows[0], ['SSH checks', '1,217', '949', '0', '25']);
  assert.deepEqual(out.rows[1], ['secret checks', '2,815', '3,102', '12', '40']);
});

test('a planner that is off shows its line and no table, and an older server shows nothing', () => {
  const off = plannerRows({enabled: false, line: 'Planner: off (Settings, Work planner). Sentinels only get work from scans.', kinds: [{label: 'SSH checks', applicable: 1, due: 1, awaiting: 0, in_flight: 0}]});
  assert.match(off.line, /^Planner: off/);
  assert.deepEqual(off.rows, []);
  assert.equal(plannerRows(null), null);
  assert.equal(plannerRows({enabled: true, line: ''}), null);
});

// the one line a collapsed Sentinel row says about what it is doing
test('a collapsed row names a problem first, then the work in hand, then the last hour', () => {
  const stats = {done_1h: 14, failed_1h: 2};
  assert.equal(glanceText({state: 'offline', problem: 'Wrong contract version', stats, current: []}), 'Wrong contract version');
  assert.equal(glanceText({state: 'working', stats, current: [{kind: 'nmap', label: 'host001.example.com'}]}), 'nmap on host001.example.com');
  assert.equal(glanceText({state: 'working', stats, current: [{kind: 'nmap', host: 'a.example.com'}, {kind: 'naabu'}, {kind: 'testssl'}]}), 'nmap on a.example.com and 2 more');
  assert.equal(glanceText({state: 'offline', stats, current: []}), 'Not taking work until it checks in again.');
  assert.equal(glanceText({state: 'idle', stats, current: []}), 'Ready, nothing to do right now. 14 done, 2 failed in the last hour.');
  assert.equal(glanceText({state: 'suspended', stats: {}, current: []}), '0 done, 0 failed in the last hour.');
});
