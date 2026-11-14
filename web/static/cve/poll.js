// Polling helpers shared by the live pages (the dashboard, the graph, the Sentinels page, scan notifications).
//
// A page that asks the server every few seconds has to be a good guest: one request in flight per poller (the next round is armed when the last one
// finishes, never by a bare setInterval, which piled requests on a busy server), every wait jittered so a room of tabs does not fire in step, no
// polling while the tab is hidden (or a slow one, for a watcher that must keep watching), a longer wait while the server fails, the server's own
// Retry-After honoured on a 429 or 503, and a conditional GET so an unchanged answer costs a 304 and no body.
//
// No dependencies and nothing touches the page unless it is called: tests/test_poll.mjs drives it with fakes.

export const JITTER_LOW = 0.85;
export const JITTER_HIGH = 1.15;

// How long a page waits for one read before it gives up and shows "could not be read" with Retry. The slowest answer that is still a real answer
// is the Sentinels list on a cold cache, which has taken up to 55 seconds on the server (the worker inspection behind the Scanners page waits at
// most 5 seconds, so it is far inside this). A limit under 55 seconds would cut off a good answer and show a false failure; 75 seconds leaves
// room above it. The page says "taking longer than usual" after 4 seconds, so nobody waits in silence meanwhile.
export const REQUEST_MS = 75000;

/**
 * Runs ``work(signal)`` with a real time limit that covers all of it: the limit stays armed until the promise ``work`` returns settles, so a
 * server that sends its headers and then stalls the body is cut off too. After ``ms`` the signal aborts and the promise rejects with an Error
 * named TimeoutError (it rejects at once, even when ``work`` ignores the signal and never settles). A signal the caller passes is honoured too.
 */
export function within(work, ms = REQUEST_MS, outer = null) {
  const control = new AbortController();
  let timer = null;
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => {
      control.abort();
      const slow = new Error("The server did not answer in time.");
      slow.name = "TimeoutError";
      reject(slow);
    }, ms);
    if (timer && timer.unref) timer.unref(); // a pending limit never keeps a script or a test alive
  });
  if (outer) outer.addEventListener("abort", () => control.abort(), { once: true });
  const job = Promise.resolve().then(() => work(control.signal));
  job.catch(() => {}); // when the limit wins, a later failure of the abandoned work is not an unhandled rejection
  return Promise.race([job, late]).finally(() => clearTimeout(timer));
}

/** fetch with a time limit on the response headers only: use ``readWithin`` when the body is read too. */
export function fetchWithin(url, init = {}, ms = REQUEST_MS, fetchImpl = (...a) => fetch(...a)) {
  return within((signal) => fetchImpl(url, { ...init, signal }), ms, init.signal);
}

/** fetch and read the body (``read(response)``, e.g. ``(r) => r.json()``) inside one time limit: headers, body and parsing all count. */
export function readWithin(url, init = {}, read = (r) => r, ms = REQUEST_MS, fetchImpl = (...a) => fetch(...a)) {
  return within(async (signal) => read(await fetchImpl(url, { ...init, signal })), ms, init.signal);
}

export const MAX_RETRY_AFTER_MS = 120000; // a server that says "come back in an hour" is waited on for two minutes, then asked again
const MAX_FAILURE_DOUBLINGS = 4; // the wait doubles up to 16 times while requests keep failing

/** ``ms`` x a random factor between 0.85 and 1.15 (``random`` returns [0, 1), Math.random by default). */
export function jitter(ms, random = Math.random) {
  return Math.round(ms * (JITTER_LOW + (JITTER_HIGH - JITTER_LOW) * random()));
}

/** The Retry-After header of ``response`` as milliseconds (seconds or an HTTP date), capped; 0 when absent or unreadable. */
export function retryAfterMs(response, now = Date.now()) {
  const raw = response && response.headers && response.headers.get ? response.headers.get("Retry-After") : null;
  if (raw == null || String(raw).trim() === "") return 0;
  const text = String(raw).trim();
  let ms = /^\d+(\.\d+)?$/.test(text) ? Number(text) * 1000 : Date.parse(text) - now;
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  return Math.min(ms, MAX_RETRY_AFTER_MS);
}

/** How long a poller waits: its own interval, doubled per failure in a row, and never less than what the server asked for. */
export function createPace(now = () => Date.now()) {
  const pace = {
    failures: 0,
    holdUntil: 0,
    ok() {
      pace.failures = 0;
      pace.holdUntil = 0;
    },
    fail(error) {
      pace.failures += 1;
      const hold = error && error.retryAfter ? error.retryAfter : 0;
      pace.holdUntil = hold ? now() + hold : 0;
    },
    wait(ms) {
      return Math.max(ms * 2 ** Math.min(pace.failures, MAX_FAILURE_DOUBLINGS), pace.holdUntil - now());
    },
  };
  return pace;
}

/**
 * A GET that returns parsed JSON and remembers each URL's ETag. The next GET of the same URL sends If-None-Match, and a 304 resolves to ``null``:
 * "nothing changed since the copy you hold", so the caller returns before parsing or redrawing anything. Only URLs whose answer carried an ETag
 * are conditional. A failure throws an Error with ``status`` and, on a 429 or 503, ``retryAfter`` (milliseconds) for ``createPace().fail``.
 * ``entries`` bounds the map: a poller whose URL carries a moving cursor would otherwise remember every cursor it ever used.
 */
export function createGet({ fetchImpl = (u, i) => fetch(u, i), entries = 64, now = () => Date.now(), ms = REQUEST_MS } = {}) {
  const tags = new Map();
  return (url, init = {}) => within((signal) => read(url, { ...init, signal }), ms, init.signal);
  async function read(url, init) {
    const headers = { ...(init.headers || {}) };
    const known = tags.get(url);
    if (known) headers["If-None-Match"] = known;
    const response = await fetchImpl(url, { credentials: "same-origin", ...init, headers });
    if (response.status === 304) return null;
    if (!response.ok) {
      const error = new Error(String(response.status));
      error.status = response.status;
      if (response.status === 429 || response.status === 503) error.retryAfter = retryAfterMs(response, now());
      throw error;
    }
    const tag = response.headers && response.headers.get ? response.headers.get("ETag") : null;
    const body = await response.json(); // read before the tag is kept: a body that never arrives must not leave a tag for a copy never held
    tags.delete(url);
    if (tag) {
      tags.set(url, tag);
      while (tags.size > entries) tags.delete(tags.keys().next().value);
    }
    return body;
  }
}

/**
 * The rows whose detail has to be asked for again: those with no detail in hand, whose ``key(row)`` differs from the one recorded when it was last asked
 * for (``seen``: id -> {key, at}), or that were asked for more than ``safetyMs`` ago (the net under a key that failed to move).
 */
export function staleRows(rows, seen, { key, has, now = Date.now(), safetyMs = 120000 }) {
  return rows.filter((row) => {
    const was = seen.get(row.id);
    return !has(row.id) || !was || was.key !== key(row) || now - was.at > safetyMs;
  });
}

/**
 * Runs ``fn`` now and then again ``ms`` (jittered) after each run finishes, never two at once. ``hidden`` says what a hidden tab does: "pause" (the
 * default: nothing runs until the tab is visible again, which runs it at once) or "slow" (it keeps running, ``slow`` times as seldom, and runs at once on
 * return). The wait follows ``pace`` (failures and Retry-After), and is never less than ``backoff`` times how long the run itself took: a server
 * that needs ten seconds to answer is asked again after at least twenty, so a slow answer is not met with more of the same question (a room of tabs
 * polling a busy server every few seconds is what kept it busy). Returns ``{stop, tick}``.
 */
export function every(fn, ms, { pace = createPace(), doc = globalThis.document, hidden = "pause", slow = 4, backoff = 2, random = Math.random, timers, clock = () => Date.now() } = {}) {
  const set = timers ? timers.set : (f, d) => setTimeout(f, d);
  const clear = timers ? timers.clear : (t) => clearTimeout(t);
  let timer = 0;
  let busy = false;
  let stopped = false;
  const arm = (delay) => {
    clear(timer);
    timer = set(tick, jitter(delay, random));
  };
  async function tick() {
    if (stopped || busy) return;
    if (doc.hidden && hidden === "pause") return;
    busy = true;
    const started = clock();
    try {
      await fn();
    } catch (_) {
      /* a poller handles its own errors; one that throws must still be asked again */
    } finally {
      busy = false;
      const took = Math.max(0, clock() - started);
      if (!stopped) arm(Math.max(pace.wait(ms), took * backoff) * (doc.hidden && hidden === "slow" ? slow : 1));
    }
  }
  const onVisible = () => {
    if (doc.hidden || stopped) return;
    clear(timer);
    tick();
  };
  doc.addEventListener("visibilitychange", onVisible);
  tick();
  return {
    tick,
    stop() {
      stopped = true;
      clear(timer);
      doc.removeEventListener("visibilitychange", onVisible);
    },
  };
}
