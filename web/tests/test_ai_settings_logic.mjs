import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as L from '../static/cve/ai-settings-logic.js';

const dir = new URL('../static/cve/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');

// the shape of GET /cve/api/settings/ai (what the server sends; cveFeed/settings_api.ai_get)
const LIMITS = {
  request_timeout: {min: 10, max: 3600, unit: 'seconds'}, connect_timeout: {min: 1, max: 300, unit: 'seconds'},
  max_tokens: {min: 64, max: 32768, unit: 'tokens'}, context_tokens: {min: 512, max: 1048576, unit: 'tokens'},
};
const DEFAULTS = {
  anthropic: {request_timeout: 120, connect_timeout: 10, max_tokens: 2048, triage_max_tokens: null, structured: false, structured_possible: false, reasoning_sent: true},
  openai: {request_timeout: 120, connect_timeout: 10, max_tokens: null, triage_max_tokens: null, structured: false, structured_possible: true, reasoning_sent: true},
  openrouter: {request_timeout: 120, connect_timeout: 10, max_tokens: null, triage_max_tokens: null, structured: false, structured_possible: true, reasoning_sent: false},
  ollama: {request_timeout: 120, connect_timeout: 10, max_tokens: 2048, triage_max_tokens: 400, structured: true, structured_possible: true, reasoning_sent: true},
  lmstudio: {request_timeout: 300, connect_timeout: 10, max_tokens: 2048, triage_max_tokens: 400, structured: true, structured_possible: true, reasoning_sent: false},
  vllm: {request_timeout: 120, connect_timeout: 10, max_tokens: 2048, triage_max_tokens: 400, structured: true, structured_possible: true, reasoning_sent: false},
};
const state = (over = {}) => ({
  provider: 'anthropic', providers: Object.keys(DEFAULTS), limits: LIMITS, env: {}, provider_defaults: DEFAULTS,
  applies_to: {context_tokens: ['ollama'], keep_alive: ['ollama']},
  choices: {structured_mode: ['auto', 'all', 'off'], reasoning: ['default', 'off', 'low', 'medium', 'high', 'max']},
  request_timeout: null, connect_timeout: null, max_tokens: null, context_tokens: null, structured_mode: '', reasoning: '', keep_alive: '', ...over,
});

test('every provider the server lists is in a group, hosted ones first, and the labels name what a user would look for', () => {
  const listed = GROUP_IDS();
  assert.deepEqual(L.GROUPS.map(([title]) => title), ['Hosted', 'Your own server']);
  assert.deepEqual(listed.sort(), Object.keys(DEFAULTS).sort());
  assert.match(L.labelOf('vllm'), /llama\.cpp/);
  assert.match(L.labelOf('vllm'), /OpenAI-compatible/);
  assert.equal(L.labelOf('somethingnew'), 'somethingnew');
});
function GROUP_IDS() { return L.GROUPS.flatMap(([, ids]) => ids); }

test('a number is a whole number in its range, or empty', () => {
  const s = state();
  assert.deepEqual(L.checkDraft(s, 'request_timeout', ''), {ok: true, value: ''});
  assert.deepEqual(L.checkDraft(s, 'request_timeout', ' 600 '), {ok: true, value: '600'});
  assert.deepEqual(L.checkDraft(s, 'request_timeout', '0600'), {ok: true, value: '600'});
  assert.deepEqual(L.checkDraft(s, 'max_tokens', '64'), {ok: true, value: '64'});
  assert.deepEqual(L.checkDraft(s, 'max_tokens', '32768'), {ok: true, value: '32768'});
  for (const [key, bad] of [['request_timeout', '9'], ['request_timeout', '3601'], ['connect_timeout', '0'], ['connect_timeout', '301'], ['max_tokens', '63'],
    ['max_tokens', '32769'], ['context_tokens', '511'], ['context_tokens', '1048577'], ['request_timeout', 'soon'], ['request_timeout', '1.5'],
    ['request_timeout', '-10'], ['request_timeout', '1e3'], ['request_timeout', '60 0'], ['request_timeout', '9'.repeat(12)]]) {
    const r = L.checkDraft(s, key, bad);
    assert.equal(r.ok, false, `${key} ${bad}`);
    assert.match(r.error, /whole number|number between/);
  }
  assert.match(L.checkDraft(s, 'request_timeout', '9').error, /between 10 and 3,600 seconds/);
  assert.match(L.checkDraft(s, 'context_tokens', '1').error, /between 512 and 1,048,576 tokens/);
});

test('keep-alive and the two choices accept what the server accepts', () => {
  const s = state();
  for (const ok of ['30m', '1h', '90s', '0', '-1', '24H']) assert.equal(L.checkDraft(s, 'keep_alive', ok).ok, true, ok);
  assert.equal(L.checkDraft(s, 'keep_alive', '30M').value, '30m');
  for (const bad of ['forever', '1d', '-2', '5 m', '123456s']) assert.equal(L.checkDraft(s, 'keep_alive', bad).ok, false, bad);
  assert.deepEqual(L.checkDraft(s, 'keep_alive', ''), {ok: true, value: ''});
  for (const v of ['', 'auto', 'all', 'off']) assert.equal(L.checkDraft(s, 'structured_mode', v).ok, true, v);
  assert.equal(L.checkDraft(s, 'structured_mode', 'sometimes').ok, false);
  for (const v of ['', 'default', 'off', 'low', 'medium', 'high', 'max']) assert.equal(L.checkDraft(s, 'reasoning', v).ok, true, v);
  assert.equal(L.checkDraft(s, 'reasoning', 'xhigh').ok, false);
});

test('the save body holds every setting, empty ones as empty strings, and a bad one is reported by name', () => {
  const s = state({request_timeout: 600});
  const drafts = L.initialDrafts(s);
  assert.deepEqual(drafts, {request_timeout: '600', connect_timeout: '', max_tokens: '', context_tokens: '', structured_mode: '', reasoning: '', keep_alive: ''});
  const ok = L.collect(s, {...drafts, max_tokens: '4096', reasoning: 'low'}, 'ollama');
  assert.deepEqual(ok.errors, {});
  assert.deepEqual(ok.values, {request_timeout: '600', connect_timeout: '', max_tokens: '4096', context_tokens: '', structured_mode: '', reasoning: 'low', keep_alive: ''});
  const bad = L.collect(s, {...drafts, connect_timeout: '999', keep_alive: 'x'}, 'ollama');
  assert.deepEqual(Object.keys(bad.errors).sort(), ['connect_timeout', 'keep_alive']);
  assert.equal(L.FIELDS.length, 7);
  assert.deepEqual(L.FIELDS.map((f) => f.key), ['request_timeout', 'connect_timeout', 'max_tokens', 'context_tokens', 'structured_mode', 'reasoning', 'keep_alive']);
});

test('a box the chosen provider does not use is neither checked nor sent, so a hidden mistake cannot block a save', () => {
  const s = state({context_tokens: 8192, keep_alive: '30m'});
  const drafts = {...L.initialDrafts(s), context_tokens: '4k', keep_alive: 'forever', max_tokens: '4096'};
  const vllm = L.collect(s, drafts, 'vllm');
  assert.deepEqual(vllm.errors, {});
  assert.equal('context_tokens' in vllm.values, false);
  assert.equal('keep_alive' in vllm.values, false);
  assert.equal(vllm.values.max_tokens, '4096');
  const ollama = L.collect(s, drafts, 'ollama');
  assert.deepEqual(Object.keys(ollama.errors).sort(), ['context_tokens', 'keep_alive']);  // visible there, so reported
  assert.deepEqual(Object.keys(L.collect(s, drafts).errors).sort(), ['context_tokens', 'keep_alive']);  // no provider named: everything is checked
});

test('the section opens when something is customised', () => {
  assert.equal(L.anySet(state()), false);
  assert.equal(L.anySet(state({max_tokens: 4096})), true);
  assert.equal(L.anySet(state({reasoning: 'default'})), true);
  assert.equal(L.anySet(state({keep_alive: '0'})), true);
});

test('the context window and keep-alive belong to Ollama only', () => {
  const s = state();
  for (const p of Object.keys(DEFAULTS)) {
    assert.equal(L.applies(s, 'context_tokens', p), p === 'ollama', p);
    assert.equal(L.applies(s, 'keep_alive', p), p === 'ollama', p);
    assert.equal(L.applies(s, 'max_tokens', p), true);
    assert.equal(L.applies(s, 'request_timeout', p), true);
  }
  assert.match(L.effective(s, 'context_tokens', 'vllm', '8192').text, /Not used by/);
});

test('a number says where its value comes from: here, the environment, or the provider default', () => {
  const s = state({env: {request_timeout: '400', max_tokens: 'lots'}});
  const typed = L.effective(s, 'request_timeout', 'anthropic', '900');
  assert.deepEqual([typed.source, typed.value], ['setting', 900]);
  const env = L.effective(s, 'request_timeout', 'anthropic', '');
  assert.deepEqual([env.source, env.value], ['env', 400]);
  assert.match(env.text, /CVENGINE_AI_TIMEOUT/);
  assert.match(env.text, /A value here replaces it/);
  const notNumber = L.effective(s, 'max_tokens', 'anthropic', '');  // an environment value the server ignores is not shown as in force
  assert.deepEqual([notNumber.source, notNumber.value], ['default', 2048]);
  assert.equal(L.effective(s, 'request_timeout', 'lmstudio', 'x').value, 400);  // a draft that is not valid falls back to what is in force
  assert.equal(L.effective(state(), 'request_timeout', 'lmstudio', '').value, 300);
  assert.equal(L.effective(state({env: {request_timeout: '5'}}), 'request_timeout', 'anthropic', '').source, 'default');  // out of range in the environment: ignored
});

test('the reply limit says what a provider sends by default, the triage limit included, and that OpenAI sends none', () => {
  const s = state();
  assert.match(L.effective(s, 'max_tokens', 'anthropic', '').text, /Using 2,048 tokens, the default for Anthropic/);
  assert.match(L.effective(s, 'max_tokens', 'ollama', '').text, /2,048 tokens \(400 for a finding triage\)/);
  assert.match(L.effective(s, 'max_tokens', 'openai', '').text, /Nothing is sent: OpenAI keeps its own limit/);
  assert.equal(L.effective(s, 'max_tokens', 'openai', '').value, undefined);
  assert.doesNotMatch(L.effective(s, 'max_tokens', 'ollama', '1000').text, /triage/);
});

test('JSON mode says whether a schema goes to this provider', () => {
  const s = state();
  assert.match(L.effective(s, 'structured_mode', 'vllm', '').text, /a JSON Schema is sent to vLLM/);
  assert.match(L.effective(s, 'structured_mode', 'openai', '').text, /no JSON Schema is sent to OpenAI/);
  assert.match(L.effective(s, 'structured_mode', 'openai', 'all').text, /a JSON Schema is sent to OpenAI/);
  assert.match(L.effective(s, 'structured_mode', 'vllm', 'off').text, /no JSON Schema is sent/);
  assert.match(L.effective(s, 'structured_mode', 'anthropic', 'all').text, /no JSON Schema is sent to Anthropic/);
  const env = L.effective(state({env: {structured_mode: 'off'}}), 'structured_mode', 'ollama', '');
  assert.equal(env.source, 'env');
  assert.match(env.text, /CVENGINE_AI_STRUCTURED/);
  assert.equal(L.effective(state({env: {structured_mode: 'banana'}}), 'structured_mode', 'ollama', '').source, 'default');
});

test('reasoning says what is sent, and that vLLM, LM Studio and OpenRouter are not sent a field', () => {
  const s = state();
  assert.match(L.effective(s, 'reasoning', 'openai', '').text, /Nothing is sent/);
  assert.match(L.effective(s, 'reasoning', 'openai', 'low').text, /Asks for low/);
  assert.match(L.effective(s, 'reasoning', 'vllm', 'low').text, /not sent a reasoning field: switch it on the server/);
  assert.match(L.effective(s, 'reasoning', 'openrouter', 'high').text, /not sent a reasoning field/);
  assert.match(L.effective(s, 'reasoning', 'ollama', 'off').text, /Asks for off/);
  const withEnv = state({env: {reasoning: 'high'}});
  assert.deepEqual([L.effective(withEnv, 'reasoning', 'openai', '').source, L.effective(withEnv, 'reasoning', 'openai', 'low').source], ['env', 'setting']);
  const off = L.effective(withEnv, 'reasoning', 'openai', 'default');
  assert.match(off.text, /Nothing is sent, even if the server's environment sets a level/);
});

test('keep-alive explains its special values', () => {
  const s = state();
  assert.match(L.effective(s, 'keep_alive', 'ollama', '').text, /five minutes/);
  assert.match(L.effective(s, 'keep_alive', 'ollama', '0').text, /Unloads/);
  assert.match(L.effective(s, 'keep_alive', 'ollama', '-1').text, /Keeps the model loaded\./);
  assert.match(L.effective(s, 'keep_alive', 'ollama', '30m').text, /for 30m/);
});

test('a long generation on a short request timeout is warned about, because a request that times out here is still billed', () => {
  const s = state();
  const none = {request_timeout: '', connect_timeout: '', max_tokens: '', reasoning: ''};
  const long = (over, p = 'anthropic') => L.warnings(s, p, {...none, ...over}).filter((w) => /still bills it/.test(w));
  assert.equal(long({}).length, 0);
  assert.equal(long({max_tokens: '16384'}).length, 1);
  assert.match(long({max_tokens: '16384'})[0], /120-second request timeout/);
  assert.equal(long({max_tokens: '16383'}).length, 0);
  assert.equal(long({reasoning: 'high'}).length, 1);
  assert.equal(long({reasoning: 'max'}).length, 1);
  assert.equal(long({reasoning: 'low'}).length, 0);
  assert.equal(long({reasoning: 'high', request_timeout: '600'}).length, 0);  // the room is there
  assert.equal(long({max_tokens: '32768', request_timeout: '300'}).length, 1);
  assert.equal(long({max_tokens: '32768', request_timeout: '301'}).length, 0);
  assert.equal(long({reasoning: 'high'}, 'lmstudio').length, 1);  // LM Studio waits 300 by default: still short
  assert.equal(L.warnings(state({env: {max_tokens: '20000'}}), 'anthropic', none).filter((w) => /still bills it/.test(w)).length, 1);  // from the environment too
  assert.equal(L.warnings(state({env: {reasoning: 'high'}}), 'anthropic', {...none, reasoning: 'default'}).filter((w) => /still bills it/.test(w)).length, 0);
});

test('Anthropic is told that older Claude models refuse a very large reply limit, and the help describes the triage retry', () => {
  const s = state();
  assert.match(L.effective(s, 'max_tokens', 'anthropic', '').text, /Older Claude models refuse a very large limit with a 400/);
  assert.match(L.effective(s, 'max_tokens', 'anthropic', '30000').text, /Older Claude models/);
  assert.doesNotMatch(L.effective(s, 'max_tokens', 'ollama', '').text, /Older Claude/);
  assert.doesNotMatch(L.effective(s, 'request_timeout', 'anthropic', '').text, /Older Claude/);
  const help = L.FIELDS.find((f) => f.key === 'max_tokens').help;
  assert.match(help, /twice the limit, up to 32,768/);
  assert.doesNotMatch(help, /longest answer/);
});

test('warnings: a short limit, thinking on a short limit, and a connect timeout longer than the answer timeout', () => {
  const s = state();
  const none = {request_timeout: '', connect_timeout: '', max_tokens: '', reasoning: ''};
  assert.deepEqual(L.warnings(s, 'ollama', none), []);
  assert.equal(L.warnings(s, 'ollama', {...none, max_tokens: '500'}).length, 1);
  assert.equal(L.warnings(s, 'ollama', {...none, max_tokens: '999'}).length, 1);
  assert.equal(L.warnings(s, 'ollama', {...none, max_tokens: '1000'}).length, 0);
  assert.equal(L.warnings(s, 'ollama', {...none, request_timeout: '600', max_tokens: '2048', reasoning: 'high'}).length, 1);
  assert.equal(L.warnings(s, 'ollama', {...none, max_tokens: '2048', reasoning: 'off'}).length, 0);
  assert.equal(L.warnings(s, 'ollama', {...none, request_timeout: '600', max_tokens: '8192', reasoning: 'high'}).length, 0);
  assert.equal(L.warnings(s, 'ollama', {...none, request_timeout: '600', reasoning: 'high'}).length, 0);  // no limit set here: nothing to warn about
  assert.equal(L.warnings(s, 'ollama', {...none, request_timeout: '20', connect_timeout: '60'}).length, 1);
  assert.equal(L.warnings(s, 'ollama', {...none, max_tokens: 'x'}).length, 0);  // an invalid draft is reported as an error, not a warning
});

test('the page draws only with textContent, shows the provider groups, keeps its Base URL rules and sends every setting', () => {
  const src = read('settings.js');
  const ai = src.slice(src.indexOf('async ai(m)'), src.indexOf('const seedState'));
  assert.doesNotMatch(ai, /innerHTML|insertAdjacentHTML|outerHTML/);
  assert.match(read('settings.js'), /from "\/staticfiles\/cve\/ai-settings-logic\.js"/);
  assert.match(ai, /\.\.\.values,/, 'the validated request settings are part of the save');
  assert.match(ai, /optgroup/);
  assert.match(ai, /say\(err\.message, false\)/, 'a failed test stays on the page');
  assert.match(ai, /Object\.assign\(s, saved\)/, 'the page follows what the server stored');
  assert.match(ai, /collect\(s, drafts\(\), provider\.value\)/, 'only the boxes the provider uses are checked');
  assert.doesNotMatch(ai, /"aria-live": "polite" \}\);\n\s+wrap\.append\(hint\)/, 'a hint is not its own live region');
  assert.match(ai, /aria-describedby/, 'each box is tied to its hint');
  assert.match(ai, /say\(message, false\)/, 'a refused save shows on the page as well as in the toast');
  assert.match(ai, /refreshHints\(false\)/, 'a keystroke does not rewrite the announced region');
});
