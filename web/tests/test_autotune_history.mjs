import assert from 'node:assert/strict';
import {register} from 'node:module';
import {test} from 'node:test';

// The History lines of the Auto-tuning card (static/cve/autotune-history.js): every shape of decision the server can write (cveFeed/autotune.py
// ``serialize``: a calm change, a back-off, a cap, an emergency, a restore, a recommendation, a person's apply, a person's revert, the tuner's own
// revert after a verdict, a release, a change by an agent or the AI, and a source this version does not know), each with its outcome or without, and
// with values missing, must read as plain words: never "[object Object]", "undefined", "null", "NaN" or a bare "?".
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));
globalThis.localStorage = {getItem: () => 'utc', setItem() {}};
globalThis.document = {querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, documentElement: {setAttribute() {}, removeAttribute() {}, dataset: {}}};
globalThis.window = globalThis;
const h = await import('../static/cve/autotune-history.js');

const NOW = Date.parse('2026-11-13T14:00:00Z');
const iso = (minutes) => new Date(NOW + minutes * 60000).toISOString();
const BAD = /\[object|undefined|\bnull\b|NaN|(^|[\s(:→>])\?($|[\s),.:])/;
const base = (over = {}) => ({id: 7, at: iso(-12), setting: 'discovery_concurrency', label: 'Hosts assessed at once', old_value: 12, new_value: 14, mode: 'auto', source: 'controller',
  action: 'raise', layer: 'auto', applied: true, pressure: false, phase: 'probe', reason: 'two healthy hours, work waiting in 3 measurements in a row, 40% memory free: probed 12 to 14',
  actor: null, resolution: null, expected: null, baseline: null, verify_at: null, verified_at: null, outcome: null, outcome_detail: null, alerts: [], undoes: null,
  can_revert: false, can_apply: false, ...over});
const measured = (metric, before, after, extra = {}) => ({metric, better: 'lower', value: before, trouble: 0, kills: 0, oom: 0, n: 3, after: {metric, value: after, trouble: 0, kills: 0, oom: 0, n: 3}, ...extra});

const SHAPES = {
  helped: base({outcome: 'helped', verified_at: iso(-2), baseline: measured('assess_oldest_s', 3120, 540), outcome_detail: 'age of the oldest waiting assessment (seconds): 3120 before, 540 after', can_revert: true}),
  helped_queue: base({outcome: 'helped', baseline: measured('discovery_queue', 12, 3), outcome_detail: 'scans waiting in the discovery queue: 12 before, 3 after'}),
  no_effect: base({outcome: 'no_effect', baseline: measured('wait_share', 0.4, 0.4), outcome_detail: 'x: 0.4 before, 0.4 after'}),
  regressed_undone: base({outcome: 'regressed', resolution: 'reverted', baseline: measured('discovery_queue', 3, 9, {after: {metric: 'discovery_queue', value: 9, trouble: 1, kills: 0, oom: 0, n: 3}}), outcome_detail: 'trouble for this setting appeared after the change'}),
  regressed_killed: base({outcome: 'regressed', resolution: 'reverted', baseline: measured('wait_share', 0.1, 0.1, {after: {metric: 'wait_share', value: 0.1, trouble: 0, kills: 2, oom: 0, n: 3}}), outcome_detail: '2 memory kill(s) after the change, 0 before'}),
  regressed_kept: base({outcome: 'regressed', pressure: true, phase: 'back_off', action: 'lower', old_value: 14, new_value: 10, outcome_detail: 'trouble for this setting appeared after the change'}),
  unknown: base({outcome: 'unknown', outcome_detail: 'only 2 measurement(s) came after the change, so it was not judged'}),
  unknown_gone: base({outcome: 'unknown', outcome_detail: 'the setting is no longer auto-tuned, so the change was not judged'}),
  unknown_empty: base({outcome: 'unknown'}),
  being_checked: base({verify_at: iso(18)}),
  being_checked_late: base({verify_at: iso(-3)}),
  aim_high: base({phase: 'aim_high', reason: 'aim high for this machine (8 cores, 5.9 GB memory budget): 12 to 14'}),
  cap: base({phase: 'cap', action: 'lower', old_value: 20, new_value: 14, reason: 'the target for this machine is 14 (sized): lowered 20 to 14'}),
  emergency: base({phase: 'emergency', action: 'lower', pressure: true, reason: 'the database did not answer'}),
  recover: base({phase: 'recover', reason: 'the database answers again: restored 8 to 12'}),
  back_off: base({phase: 'back_off', pressure: true, action: 'lower', old_value: 14, new_value: 10, reason: 'the scanning container has 6% memory free: backed off 14 to 10', baseline: measured('trouble', 1, 0), outcome: 'helped', outcome_detail: 'trouble for this setting (1 yes, 0 no): 1 before, 0 after'}),
  recommendation: base({applied: false, mode: 'suggest', layer: '', can_apply: true, phase: 'probe'}),
  recommendation_ai: base({applied: false, mode: 'suggest', layer: '', source: 'ai', can_apply: true, reason: 'free slots'}),
  recommendation_applied: base({applied: false, resolution: 'applied', resolved_by: 'bill'}),
  recommendation_replaced: base({applied: false, resolution: 'superseded'}),
  person_apply: base({source: 'person', action: 'apply', actor: 'bill', phase: null, reason: 'bill applied the recommendation of 2026-11-13T13:00', can_revert: true}),
  person_revert: base({source: 'person', action: 'revert', actor: 'bill', phase: null, old_value: 14, new_value: 12, reason: 'bill reverted the change of 2026-11-13T13:00', outcome: null}),
  auto_revert: base({action: 'revert', phase: 'verify', pressure: true, old_value: 14, new_value: 12, outcome: 'reverted', undoes: 6, reason: 'verification of the change of 2026-11-13T13:00: trouble for this setting appeared after the change; put 14 back to 12', outcome_detail: 'undid decision 6: trouble for this setting appeared after the change'}),
  release: base({source: 'person', action: 'release', actor: 'bill', old_value: null, new_value: 12, phase: null, reason: ''}),
  agent: base({source: 'agent', actor: 'ci-agent', reason: 'asked by an agent to raise the pool'}),
  agent_named: base({source: 'agent', actor: 'bill', agent_name: 'capacity-bot'}),
  ai: base({source: 'ai', reason: 'free slots'}),
  future_source: base({source: 'robot'}),
  html_reason: base({reason: 'queued <b>scans</b> waited & "grew"'}),
  no_reason: base({reason: '', phase: 'cap'}),
  no_numbers: base({old_value: null, new_value: null, label: undefined, setting: 'work_depth'}),
  empty: {},
  nothing_but_id: {id: 3},
  garbage: {id: 'x', at: 'never', label: 5, old_value: 'a', new_value: {}, reason: ['x'], baseline: 'text', outcome: 'helped', source: 3, actor: {}, verify_at: 'soon'},
  baseline_wrong_metric: base({outcome: 'helped', baseline: {metric: 'wait_share', value: 1, after: {metric: 'discovery_queue', value: 2}}, outcome_detail: 'it is better'}),
  baseline_text_only: base({outcome: 'helped', baseline: {metric: 'nothing'}, outcome_detail: ''}),
};

test('every shape of decision reads as plain words', () => {
  Object.entries(SHAPES).forEach(([name, d]) => {
    const line = h.historyLine(d, NOW);
    for (const key of ['what', 'why', 'happened', 'who', 'when']) {
      assert.equal(typeof line[key], 'string', `${name}.${key}`);
      assert.doesNotMatch(line[key], BAD, `${name}.${key}: ${line[key]}`);
    }
    assert.ok(line.what.length > 2, `${name}: a What`);
    assert.ok(line.who.length > 2, `${name}: a Who`);
    assert.ok(['good', 'bad', 'wait', 'neutral'].includes(line.tone), name);
  });
});

test('the design lines: what, why, what happened', () => {
  const helped = h.historyLine(SHAPES.helped, NOW);
  assert.equal(helped.what, 'Hosts assessed at once 12 → 14');
  assert.equal(helped.why, 'Two healthy hours, work waiting in 3 measurements in a row, 40% memory free');
  assert.equal(helped.happened, 'oldest waiting assessment 52 → 9 min, no memory pressure; kept');
  assert.equal(helped.who, 'auto-tune');
  assert.equal(helped.when, '12 min ago');
  assert.equal(helped.tone, 'good');
  assert.equal(h.historyLine(SHAPES.back_off, NOW).happened, 'the trouble is gone, no memory pressure; kept');
  assert.match(h.historyLine(SHAPES.helped_queue, NOW).happened, /^scans waiting in the queue 12 → 3, no memory pressure; kept$/);
  assert.match(h.historyLine(SHAPES.no_effect, NOW).happened, /^runs waiting for their turn 40% → 40%, no memory pressure; no effect, kept$/);
  assert.equal(h.historyLine(SHAPES.regressed_undone, NOW).happened, 'made it worse: scans waiting in the queue 3 → 9, trouble for this setting; undone');
  assert.equal(h.historyLine(SHAPES.regressed_undone, NOW).tone, 'bad');
  assert.match(h.historyLine(SHAPES.regressed_killed, NOW).happened, /^made it worse: runs waiting for their turn 10% → 10%, 2 memory kills; undone$/);
  assert.equal(h.historyLine(SHAPES.regressed_kept, NOW).happened, 'made it worse: trouble for this setting appeared after the change; kept');
  assert.equal(h.historyLine(SHAPES.being_checked, NOW).happened, 'being checked, result at 14:18');
  assert.equal(h.historyLine(SHAPES.being_checked, NOW).tone, 'wait');
  assert.equal(h.historyLine(SHAPES.being_checked_late, NOW).happened, 'being checked, result due now');
  assert.equal(h.historyLine(SHAPES.person_apply, NOW).happened, 'not judged: a person changed it');
  assert.equal(h.historyLine(SHAPES.unknown, NOW).happened, 'not judged: only 2 measurement(s) came after the change');
  assert.equal(h.historyLine(SHAPES.unknown_empty, NOW).happened, 'not judged');
});

test('who made the change, in words', () => {
  assert.equal(h.whoText(SHAPES.helped), 'auto-tune');
  assert.equal(h.whoText(SHAPES.ai), 'the AI');
  assert.equal(h.whoText(SHAPES.person_apply), 'bill');
  assert.equal(h.whoText({source: 'person'}), 'a person');
  assert.equal(h.whoText(SHAPES.agent), 'an agent (ci-agent)');
  assert.equal(h.whoText(SHAPES.agent_named), 'an agent (capacity-bot)');
  assert.equal(h.whoText({source: 'agent'}), 'an agent');
  assert.equal(h.whoText(SHAPES.future_source), 'robot');
});

test('a recommendation, a revert row and a release say what they are', () => {
  const rec = h.historyLine(SHAPES.recommendation, NOW);
  assert.equal(rec.apply, true);
  assert.equal(rec.revert, false);
  assert.equal(rec.happened, 'nothing has changed yet: apply it to make the change');
  assert.equal(h.historyLine(SHAPES.recommendation_applied, NOW).happened, 'applied by a person');
  assert.equal(h.historyLine(SHAPES.recommendation_replaced, NOW).happened, 'replaced by a newer recommendation');
  const person = h.historyLine(SHAPES.person_revert, NOW);
  assert.equal(person.what, 'Hosts assessed at once put back 14 → 12');
  assert.equal(person.happened, 'undone by bill');
  const auto = h.historyLine(SHAPES.auto_revert, NOW);
  assert.equal(auto.why, 'Undone because the change before it made things worse');
  assert.equal(auto.happened, 'put back: trouble for this setting appeared after the change');  // not "undid decision 6: ..."
  assert.equal(h.historyLine(SHAPES.release, NOW).what, 'Hosts assessed at once handed back to auto-tune at 12');
});

test('Revert is offered only where the server says it can be and the line is not already undone', () => {
  assert.equal(h.historyLine(SHAPES.helped, NOW).revert, true);
  assert.equal(h.historyLine(SHAPES.regressed_undone, NOW).revert, false);
  assert.equal(h.historyLine({...SHAPES.regressed_undone, can_revert: true}, NOW).revert, false);  // already undone: no button whatever the flag says
  assert.equal(h.historyLine({...SHAPES.auto_revert, can_revert: true}, NOW).revert, false);
  assert.equal(h.historyLine({...SHAPES.release, can_revert: true}, NOW).revert, false);
  assert.equal(h.historyLine(SHAPES.regressed_undone, NOW).undone, true);
});

test('the reason is text, one sentence, and a long one is cut', () => {
  assert.equal(h.historyLine(SHAPES.html_reason, NOW).why, 'Queued <b>scans</b> waited & "grew"');
  assert.ok(h.historyLine(base({reason: 'word '.repeat(200)}), NOW).why.length <= 160);
  assert.equal(h.historyLine(SHAPES.no_reason, NOW).why, 'Brought down to what this machine can carry');
});

test('times: relative words, and nothing when the time is missing', () => {
  assert.equal(h.ago(iso(-0.2), NOW), 'just now');
  assert.equal(h.ago(iso(-5), NOW), '5 min ago');
  assert.equal(h.ago(iso(-180), NOW), '3 h ago');
  assert.equal(h.ago(iso(-60 * 24 * 4), NOW), '4 days ago');
  assert.equal(h.ago(null, NOW), '');
  assert.equal(h.ago('never', NOW), '');
});
