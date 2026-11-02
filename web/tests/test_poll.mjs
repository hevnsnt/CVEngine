import assert from 'node:assert/strict';
import {test} from 'node:test';

import {createGet, createPace, every, jitter, retryAfterMs, staleRows} from '../static/cve/poll.js';

// A response stand-in: the status, headers by name (case-insensitive) and a JSON body.
const reply = (status, body = {}, headers = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  headers: {get: (name) => Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1] ?? null},
  json: async () => body,
});

// A document stand-in with a visibility flag and listeners, and a timer queue the test runs by hand.
const fakeDoc = (hidden = false) => {
  const listeners = [];
  return {
    hidden,
    addEventListener: (type, fn) => listeners.push([type, fn]),
    removeEventListener: (type, fn) => listeners.splice(0, listeners.length, ...listeners.filter(([t, f]) => !(t === type && f === fn))),
    listeners,
    show() {
      this.hidden = false;
      listeners.filter(([t]) => t === 'visibilitychange').forEach(([, fn]) => fn());
    },
  };
};
const fakeTimers = () => {
  const queue = [];
  let id = 0;
  return {
    queue,
    set: (fn, delay) => {
      id += 1;
      queue.push({id, fn, delay});
      return id;
    },
    clear: (which) => {
      const i = queue.findIndex((t) => t.id === which);
      if (i >= 0) queue.splice(i, 1);
    },
    async fire() {
      const next = queue.shift();
      if (next) await next.fn();
      return next;
    },
  };
};
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('jitter spreads a wait over 0.85 to 1.15 of it', () => {
  assert.equal(jitter(1000, () => 0), 850);
  assert.equal(jitter(1000, () => 0.5), 1000);
  assert.equal(jitter(1000, () => 0.999999), 1150);
  for (let i = 0; i < 200; i += 1) {
    const ms = jitter(6000);
    assert.ok(ms >= 5100 && ms <= 6900, `${ms}`);
  }
});

test('Retry-After is read as seconds or as a date, capped, and ignored when unreadable', () => {
  assert.equal(retryAfterMs(reply(429, {}, {'Retry-After': '7'})), 7000);
  assert.equal(retryAfterMs(reply(503, {}, {'retry-after': '1.5'})), 1500);
  assert.equal(retryAfterMs(reply(503, {}, {'Retry-After': '99999'})), 120000);
  const now = Date.parse('2026-11-01T12:00:00Z');
  assert.equal(retryAfterMs(reply(503, {}, {'Retry-After': 'Sun, 01 Nov 2026 12:00:30 GMT'}), now), 30000);
  assert.equal(retryAfterMs(reply(503, {}, {'Retry-After': 'Sun, 01 Nov 2026 11:00:00 GMT'}), now), 0);
  assert.equal(retryAfterMs(reply(503, {}, {'Retry-After': 'soon'})), 0);
  assert.equal(retryAfterMs(reply(503)), 0);
  assert.equal(retryAfterMs(null), 0);
});

test('a GET remembers the ETag per URL, sends it back, and answers null for a 304', async () => {
  const seen = [];
  const answers = [reply(200, {n: 1}, {ETag: '"a"'}), reply(304), reply(200, {n: 2}, {ETag: '"b"'}), reply(200, {n: 3})];
  const get = createGet({fetchImpl: async (url, init) => (seen.push([url, init.headers['If-None-Match']]), answers.shift())});
  assert.deepEqual(await get('/x'), {n: 1});
  assert.equal(await get('/x'), null);
  assert.deepEqual(await get('/x'), {n: 2});
  assert.deepEqual(await get('/x'), {n: 3}); // an answer with no ETag forgets the old one
  assert.deepEqual(seen, [['/x', undefined], ['/x', '"a"'], ['/x', '"a"'], ['/x', '"b"']]);
  seen.length = 0;
  answers.push(reply(200, {}, {ETag: '"q"'}));
  await get('/other');
  assert.deepEqual(seen, [['/other', undefined]], 'another URL has its own tag');
});

test('a GET sends cookies and keeps the caller\'s own headers', async () => {
  let sent;
  const get = createGet({fetchImpl: async (url, init) => ((sent = init), reply(200, {}))});
  await get('/x', {headers: {Accept: 'application/json'}});
  assert.equal(sent.credentials, 'same-origin');
  assert.equal(sent.headers.Accept, 'application/json');
});

test('the ETag map is bounded: a cursor in the URL does not grow it for ever', async () => {
  const sent = new Map();
  const get = createGet({entries: 3, fetchImpl: async (url, init) => (sent.set(url, init.headers['If-None-Match']), reply(200, {}, {ETag: `"${url}"`}))});
  for (const url of ['/1', '/2', '/3', '/4']) await get(url);
  sent.clear();
  for (const url of ['/1', '/4']) await get(url);
  assert.equal(sent.get('/1'), undefined, 'the oldest was dropped');
  assert.equal(sent.get('/4'), '"/4"');
});

test('a failure throws its status, and a 429 or 503 carries Retry-After for the pace', async () => {
  const get = createGet({fetchImpl: async (url) => (url === '/busy' ? reply(429, {}, {'Retry-After': '9'}) : url === '/down' ? reply(503) : reply(500, {}, {'Retry-After': '9'}))});
  await assert.rejects(get('/busy'), (e) => e.status === 429 && e.retryAfter === 9000);
  await assert.rejects(get('/down'), (e) => e.status === 503 && e.retryAfter === 0);
  await assert.rejects(get('/broken'), (e) => e.status === 500 && e.retryAfter === undefined);
});

test('the pace doubles per failure up to 16 times, resets on success and never undercuts Retry-After', () => {
  let t = 0;
  const pace = createPace(() => t);
  assert.equal(pace.wait(1000), 1000);
  pace.fail(new Error('x'));
  assert.equal(pace.wait(1000), 2000);
  for (let i = 0; i < 10; i += 1) pace.fail(new Error('x'));
  assert.equal(pace.wait(1000), 16000);
  pace.ok();
  assert.equal(pace.wait(1000), 1000);
  pace.fail(Object.assign(new Error('429'), {retryAfter: 30000}));
  assert.equal(pace.wait(1000), 30000);
  t = 25000;
  assert.equal(pace.wait(1000), 5000, 'the hold counts down');
  t = 31000;
  assert.equal(pace.wait(1000), 2000);
});

test('every runs one at a time, re-arms after each run with a jittered wait, and stops', async () => {
  const doc = fakeDoc();
  const timers = fakeTimers();
  let running = 0;
  let peak = 0;
  let calls = 0;
  let release;
  const fn = () => {
    running += 1;
    peak = Math.max(peak, running);
    calls += 1;
    return new Promise((resolve) => {
      release = () => {
        running -= 1;
        resolve();
      };
    });
  };
  const poller = every(fn, 1000, {doc, timers, random: () => 0});
  await settle();
  assert.equal(calls, 1);
  poller.tick(); // a tick while one is in flight does nothing
  poller.tick();
  assert.equal(calls, 1);
  assert.equal(timers.queue.length, 0, 'nothing is armed while the request is in flight');
  release();
  await settle();
  assert.equal(timers.queue.length, 1);
  assert.equal(timers.queue[0].delay, 850, '1000 x the lowest jitter');
  timers.fire();
  await settle();
  assert.equal(calls, 2);
  assert.equal(peak, 1);
  release();
  await settle();
  poller.stop();
  assert.equal(timers.queue.length, 0);
  assert.equal(doc.listeners.length, 0, 'the visibility listener is removed');
});

test('a throwing poller is still asked again', async () => {
  const timers = fakeTimers();
  every(async () => {
    throw new Error('boom');
  }, 500, {doc: fakeDoc(), timers, random: () => 0.5});
  await settle();
  assert.equal(timers.queue.length, 1);
  assert.equal(timers.queue[0].delay, 500);
});

test('every waits longer while the pace fails and honours Retry-After', async () => {
  const timers = fakeTimers();
  let now = 0;
  const pace = createPace(() => now);
  every(async () => pace.fail(Object.assign(new Error('503'), {retryAfter: 40000})), 2000, {doc: fakeDoc(), timers, pace, random: () => 0.5});
  await settle();
  assert.equal(timers.queue[0].delay, 40000, 'the server asked for 40 s; the doubled 4 s is shorter');
});

test('a hidden tab does not poll, and polls at once when it is shown again', async () => {
  const doc = fakeDoc(true);
  const timers = fakeTimers();
  let calls = 0;
  every(async () => {
    calls += 1;
  }, 1000, {doc, timers});
  await settle();
  assert.equal(calls, 0);
  assert.equal(timers.queue.length, 0);
  doc.show();
  await settle();
  assert.equal(calls, 1);
  assert.equal(timers.queue.length, 1);
  // hidden while a request is in flight: it finishes, re-arms, and the next tick finds the tab hidden and stops
  doc.hidden = true;
  await timers.fire();
  await settle();
  assert.equal(calls, 1);
  assert.equal(timers.queue.length, 0);
});

test('slow mode keeps polling a hidden tab four times as seldom and resumes on return', async () => {
  const doc = fakeDoc(true);
  const timers = fakeTimers();
  let calls = 0;
  every(async () => {
    calls += 1;
  }, 20000, {doc, timers, hidden: 'slow', slow: 4, random: () => 0.5});
  await settle();
  assert.equal(calls, 1, 'a hidden tab still watches');
  assert.equal(timers.queue[0].delay, 80000);
  doc.show();
  await settle();
  assert.equal(calls, 2, 'and asks at once on return');
  assert.equal(timers.queue.length, 1);
  assert.equal(timers.queue[0].delay, 20000, 'then at the normal pace');
});

test('staleRows picks the rows with no detail, a moved key, or a detail older than the safety net', () => {
  const rows = [{id: 1, k: 'a'}, {id: 2, k: 'b'}, {id: 3, k: 'c'}, {id: 4, k: 'd'}];
  const have = new Set([1, 2, 3]);
  const seen = new Map([[1, {key: 'a', at: 1000}], [2, {key: 'OLD', at: 1000}], [3, {key: 'c', at: 0}]]);
  const stale = staleRows(rows, seen, {key: (r) => r.k, has: (id) => have.has(id), now: 100000, safetyMs: 120000});
  assert.deepEqual(stale.map((r) => r.id), [2, 4], 'row 2 moved, row 4 was never fetched; 1 and 3 are fresh');
  const later = staleRows(rows, seen, {key: (r) => r.k, has: (id) => have.has(id), now: 130000, safetyMs: 120000});
  assert.deepEqual(later.map((r) => r.id), [1, 2, 3, 4], 'the net catches the rest');
});
