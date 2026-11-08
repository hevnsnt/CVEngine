import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import * as M from '../static/cve/ai-models-logic.js';

const dir = new URL('../static/cve/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');

const LIST = [{id: 'claude-sonnet-5-5', price: null}, {id: 'claude-haiku-5-5', price: null}, {id: 'claude-opus-5-5', price: null}];
const PRICED = [{id: 'vendor/big', price: 3}, {id: 'vendor/small', price: 0.8}, {id: 'vendor/free', price: 0}, {id: 'vendor/tiny', price: 0.004}];
const values = (built) => built.options.map((o) => o.value);

test('prices read as dollars per million input tokens, and are empty when the provider reported none', () => {
  assert.equal(M.formatPrice(0.8), '$0.80 per million input tokens');
  assert.equal(M.formatPrice(3), '$3.00 per million input tokens');
  assert.equal(M.formatPrice(0), 'free');
  assert.equal(M.formatPrice(0.004), 'under $0.01 per million input tokens');
  for (const none of [null, undefined, '', 'abc', NaN]) assert.equal(M.formatPrice(none), '', String(none));
});

test('the default row starts with the newest cheapest model, named, and lists the provider models after it', () => {
  const b = M.buildOptions({job: 'default', models: LIST, recommended: 'claude-haiku-5-5', provider: 'anthropic'});
  assert.equal(b.options[0].value, '');
  assert.equal(b.options[0].label, 'Newest cheapest (recommended: claude-haiku-5-5)');
  assert.deepEqual(values(b), ['', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-opus-5-5']);
  assert.equal(b.selected, '');
});

test('the recommended model is marked in the list, with or without a price', () => {
  const plain = M.buildOptions({models: LIST, recommended: 'claude-haiku-5-5', provider: 'anthropic'});
  assert.equal(plain.options.find((o) => o.value === 'claude-haiku-5-5').label, 'claude-haiku-5-5 (recommended)');
  const priced = M.buildOptions({models: PRICED, recommended: 'vendor/small', provider: 'openrouter'});
  assert.equal(priced.options.find((o) => o.value === 'vendor/small').label, 'vendor/small ($0.80 per million input tokens, recommended)');
  assert.equal(priced.options.find((o) => o.value === 'vendor/big').label, 'vendor/big ($3.00 per million input tokens)');
  assert.equal(priced.options.filter((o) => /recommended\)$/.test(o.label) && o.kind === 'model').length, 1);
});

test('a saved model the provider did not list is still an option, and is the one selected', () => {
  const b = M.buildOptions({models: LIST, recommended: 'claude-haiku-5-5', saved: 'my-tuned-model', provider: 'anthropic'});
  assert.ok(values(b).includes('my-tuned-model'));
  assert.equal(b.selected, 'my-tuned-model');
  assert.match(b.options.find((o) => o.value === 'my-tuned-model').label, /saved, not in the provider's list/);
  // the same holds while the list is loading, when it failed, and when it is empty
  for (const listState of ['loading', 'failed', 'empty', 'idle']) {
    const x = M.buildOptions({models: [], saved: 'my-tuned-model', provider: 'anthropic', listState});
    assert.ok(values(x).includes('my-tuned-model'), listState);
    assert.equal(x.selected, 'my-tuned-model', listState);
  }
  // a saved model that is in the list is not added twice
  const once = M.buildOptions({models: LIST, saved: 'claude-opus-5-5', provider: 'anthropic'});
  assert.equal(values(once).filter((v) => v === 'claude-opus-5-5').length, 1);
});

test('a reviewer row starts with Same as the default model, with no recommended price line of its own', () => {
  const b = M.buildOptions({job: 'reviewer', models: LIST, provider: 'openai'});
  assert.deepEqual(b.options[0], {value: '', label: 'Same as the default model', kind: 'auto'});
  assert.equal(b.selected, '');
  const saved = M.buildOptions({job: 'reviewer', models: LIST, saved: 'claude-opus-5-5', provider: 'openai'});
  assert.equal(saved.selected, 'claude-opus-5-5');
});

test('on Anthropic the empty choice of a reviewer row names the built-in model, because that is what it really uses', () => {
  const built = {review: 'claude-sonnet-5-5', ops: 'claude-haiku-5-5'};
  assert.equal(M.sameLabel('anthropic', 'review', built), 'Built-in choice for this job: claude-sonnet-5-5');
  assert.equal(M.sameLabel('anthropic', 'ops', built), 'Built-in choice for this job: claude-haiku-5-5');
  assert.equal(M.sameLabel('openai', 'review', built), 'Same as the default model');
  assert.equal(M.sameLabel('anthropic', 'review', null), 'Same as the default model');
});

test('"Other (type a model name)" is offered for your own servers, gateways, and a list that could not be loaded', () => {
  const other = (args) => M.buildOptions({models: LIST, ...args}).options.some((o) => o.value === M.OTHER);
  for (const provider of ['ollama', 'vllm', 'lmstudio']) assert.ok(other({provider}), provider);
  assert.ok(other({provider: 'openai', baseUrl: 'https://gateway.example.com/v1'}));
  assert.ok(other({provider: 'anthropic', listState: 'failed'}));
  assert.ok(other({provider: 'anthropic', listState: 'empty'}));
  assert.ok(!other({provider: 'anthropic', listState: 'ready'}), 'a hosted provider with a good list has no free text');
  assert.ok(!other({provider: 'openai', baseUrl: '   ', listState: 'ready'}));
  const last = M.buildOptions({models: LIST, provider: 'ollama'}).options.at(-1);
  assert.deepEqual([last.value, last.label], [M.OTHER, 'Other (type a model name)...']);
});

test('the value of a row: a listed model, the typed name under Other, or nothing', () => {
  assert.equal(M.valueOf('claude-opus-5-5', 'ignored'), 'claude-opus-5-5');
  assert.equal(M.valueOf(M.OTHER, '  llama3.1:8b '), 'llama3.1:8b');
  assert.equal(M.valueOf(M.OTHER, ''), '');
  assert.equal(M.valueOf('', 'ignored'), '');
  assert.equal(M.valueOf(M.CHOOSE, 'ignored'), '');
});

test('a typed model name follows the server rule', () => {
  for (const ok of ['', 'llama3.1:8b', 'org/model-7b@q4', 'claude-sonnet-5-5']) assert.equal(M.checkModel(ok), null, ok);
  for (const bad of ['a model; rm -rf /', 'x'.repeat(101), 'with space', '<b>']) assert.match(M.checkModel(bad), /letters, digits/, bad);
});

test('a provider that needs a pick has no empty option and says "Choose a model" until one is picked', () => {
  const none = M.buildOptions({job: 'default', models: PRICED, provider: 'openrouter', selectable: ['openrouter', 'ollama'], recommended: ''});
  assert.ok(!values(none).includes(''), 'an empty option was offered');
  assert.equal(none.options[0].value, M.CHOOSE);
  assert.equal(none.options[0].disabled, true);
  assert.equal(none.selected, M.CHOOSE);
  const picked = M.buildOptions({job: 'default', models: PRICED, provider: 'openrouter', selectable: ['openrouter'], saved: 'vendor/small'});
  assert.ok(!values(picked).includes(''));
  assert.ok(!values(picked).includes(M.CHOOSE));
  assert.equal(picked.selected, 'vendor/small');
  // a provider that does not need a pick still has the automatic choice
  assert.ok(values(M.buildOptions({models: LIST, provider: 'anthropic', selectable: ['openrouter']})).includes(''));
  // a reviewer row of such a provider still follows the default
  assert.ok(values(M.buildOptions({job: 'reviewer', models: PRICED, provider: 'openrouter', selectable: ['openrouter']})).includes(''));
});

test('the connection line says in words whether it works', () => {
  assert.deepEqual(M.connectionLine({phase: 'ready', count: 13, label: 'Anthropic'}), {tone: 'ok', text: 'Connected: 13 models available'});
  assert.equal(M.connectionLine({phase: 'ready', count: 1, label: 'Anthropic'}).text, 'Connected: 1 model available');
  assert.equal(M.connectionLine({phase: 'ready', count: 0, label: 'Ollama'}).text, 'Connected: Ollama listed no models');
  assert.deepEqual(M.connectionLine({phase: 'failed', error: 'the key was refused', label: 'Anthropic'}), {tone: 'err', text: 'Could not reach Anthropic: the key was refused'});
  assert.equal(M.connectionLine({phase: 'loading', label: 'OpenAI'}).text, 'Checking OpenAI...');
  assert.match(M.connectionLine({phase: 'idle', needsKey: true, label: 'OpenAI'}).text, /Enter an API key/);
  assert.match(M.connectionLine({phase: 'idle', needsAddress: true, label: 'Ollama'}).text, /address of your Ollama server/);
});

test('nothing is asked for until the key (or a keyless provider) and a required address are there', () => {
  const base = {keyless: ['ollama', 'vllm', 'lmstudio'], needsUrl: ['ollama', 'vllm', 'lmstudio']};
  assert.deepEqual(M.readyToFetch({...base, provider: 'anthropic', typedKey: '', hasKey: false}), {ok: false, needsKey: true});
  assert.deepEqual(M.readyToFetch({...base, provider: 'anthropic', typedKey: '', hasKey: true}), {ok: true});
  assert.deepEqual(M.readyToFetch({...base, provider: 'anthropic', typedKey: 'k', hasKey: false}), {ok: true});
  assert.deepEqual(M.readyToFetch({...base, provider: 'anthropic', typedKey: '', hasKey: true, sameAsSaved: false}), {ok: false, needsKey: true});
  assert.deepEqual(M.readyToFetch({...base, provider: 'ollama', typedKey: '', hasKey: false, baseUrl: ''}), {ok: false, needsAddress: true});
  assert.deepEqual(M.readyToFetch({...base, provider: 'ollama', typedKey: '', hasKey: false, baseUrl: 'http://h:11434'}), {ok: true});
});

// --- the source: one request per change, aborted when stale, cached ----------------------------------------------------------------
function harness(fetcher) {
  const timers = [];
  const controllers = [];
  const src = M.createModelSource({
    fetcher, delay: 500,
    setTimer: (fn) => { timers.push(fn); return timers.length; },
    clearTimer: (id) => { if (id) timers[id - 1] = null; },
    makeController: () => { const c = new AbortController(); controllers.push(c); return c; },
  });
  const fire = () => { const live = timers.filter(Boolean); timers.length = 0; return Promise.all(live.map((fn) => fn())); };
  return {src, fire, controllers, timers};
}
const P = (over = {}) => ({provider: 'openai', api_key: '', base_url: '', ...over});

test('typing makes one request after the pause, not one per keystroke', async () => {
  const calls = [];
  const h = harness(async (p) => { calls.push(p); return {models: [{id: 'a'}], recommended: 'a'}; });
  for (const k of ['s', 'sk', 'sk-', 'sk-1']) h.src.request(P({api_key: k}));
  await h.fire();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].api_key, 'sk-1');
  assert.equal(h.src.state.phase, 'ready');
});

test('a newer request aborts the older one, and a late answer of the older one is dropped', async () => {
  const pending = [];
  const h = harness((p, signal) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})));
    pending.push({p, resolve});
  }));
  const first = h.src.now(P({provider: 'openai'}));
  const second = h.src.now(P({provider: 'anthropic'}));
  assert.equal(h.controllers[0].signal.aborted, true);
  pending[1].resolve({models: [{id: 'claude'}], recommended: ''});
  await second;
  pending[0].resolve({models: [{id: 'gpt'}], recommended: ''}); // too late
  await first;
  assert.deepEqual(h.src.state.models.map((m) => m.id), ['claude']);
  assert.equal(h.src.state.phase, 'ready');
});

test('a list is kept for the life of the page per provider and address, and Refresh asks again', async () => {
  let n = 0;
  const h = harness(async () => { n += 1; return {models: [{id: `m${n}`}], recommended: ''}; });
  await h.src.now(P({provider: 'openai'}));
  await h.src.now(P({provider: 'anthropic'}));
  await h.src.now(P({provider: 'openai'})); // from memory
  assert.equal(n, 2);
  assert.deepEqual(h.src.state.models.map((m) => m.id), ['m1']);
  await h.src.now(P({provider: 'openai', base_url: 'https://gw.example.com/v1/'})); // another address: another list
  assert.equal(n, 3);
  await h.src.now(P({provider: 'openai', base_url: 'https://GW.example.com/v1'})); // the same address, written differently
  assert.equal(n, 3);
  await h.src.refresh(P({provider: 'openai'}));
  assert.equal(n, 4);
  assert.deepEqual(h.src.state.models.map((m) => m.id), ['m4']);
});

test('the refresh request tells the server to skip its own cache, an ordinary one does not', async () => {
  const seen = [];
  const h = harness(async (p) => { seen.push(p.refresh); return {models: [], recommended: ''}; });
  await h.src.now(P());
  await h.src.refresh(P());
  assert.deepEqual(seen, [undefined, true]);
});

test('a failure keeps the plain reason, empties the list, and is not remembered as a list', async () => {
  let fail = true;
  const h = harness(async () => { if (fail) throw new Error('the key was refused'); return {models: [{id: 'a'}], recommended: 'a'}; });
  await h.src.now(P());
  assert.equal(h.src.state.phase, 'failed');
  assert.equal(h.src.state.error, 'the key was refused');
  assert.deepEqual(h.src.state.models, []);
  assert.equal(h.src.cacheSize, 0);
  fail = false;
  await h.src.now(P());
  assert.equal(h.src.state.phase, 'ready');
});

test('another provider never shows the models of the previous one while it loads', async () => {
  const pending = [];
  const h = harness((p) => new Promise((resolve) => pending.push(resolve)));
  const a = h.src.now(P({provider: 'openai'}));
  pending[0]({models: [{id: 'gpt'}], recommended: 'gpt'});
  await a;
  h.src.now(P({provider: 'anthropic'}));
  assert.equal(h.src.state.phase, 'loading');
  assert.deepEqual(h.src.state.models, []);
});

test('a typed key is not part of what the cache remembers as text', () => {
  const k = M.cacheKey('openai', 'https://x', 'sk-secret-key');
  assert.ok(!k.includes('sk-secret-key'));
  assert.notEqual(k, M.cacheKey('openai', 'https://x', 'sk-other'));
  assert.equal(M.cacheKey('openai', 'https://x/', ''), M.cacheKey('openai', 'https://X', ''));
});

test('the shared module is used by Settings, the wizard and the connect page, and the old Load models button is gone', () => {
  assert.match(read('settings.js'), /from "\/staticfiles\/cve\/ai-models\.js"/);
  assert.match(read('welcome.js'), /from '\/staticfiles\/cve\/ai-models\.js'/);
  const onboarding = readFileSync(new URL('../cveFeed/templates/cveFeed/onboarding.html', import.meta.url), 'utf8');
  assert.match(onboarding, /staticfiles\/cve\/ai-models\.js/);
  assert.doesNotMatch(read('settings.js'), /Load models/);
  assert.doesNotMatch(read('settings.js'), /datalist/);
  assert.doesNotMatch(onboarding, /<input id="model"/);
});

test('no UI text added here has an em or en dash', () => {
  for (const name of ['ai-models.js', 'ai-models-logic.js']) assert.doesNotMatch(read(name), /[\u2013\u2014]/, name);
});
