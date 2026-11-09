// The dashboard's tiles load independently: one slow or failing call cannot hold the others, and the first paint asks for one thing.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ageText, lastKnown, remember, startWhenIdle, tileState } from "../static/cve/tile-loader.js";

test("the age is said only when the snapshot is older than two minutes", () => {
  const now = Date.parse("2026-11-08T12:00:00Z");
  const ago = (s) => new Date(now - s * 1000).toISOString();
  assert.equal(ageText(null, now), "");
  assert.equal(ageText(ago(30), now), "");
  assert.equal(ageText(ago(119), now), "");
  assert.equal(ageText(ago(121), now), "as of 2 minutes ago");
  assert.equal(ageText(ago(3600), now), "as of 1 hour ago");
  assert.equal(ageText(ago(5 * 3600), now), "as of 5 hours ago");
  assert.equal(ageText(ago(3 * 86400), now), "as of 3 days ago");
  assert.equal(ageText("not a date", now), "");
});

test("a tile is pending only when there is nothing to show; otherwise a number is shown and marked updating", () => {
  const now = Date.parse("2026-11-08T12:00:00Z");
  const at = (s) => new Date(now - s * 1000).toISOString();
  assert.equal(tileState(undefined, { now }), "pending");
  assert.equal(tileState({ ready: false }, { now }), "pending");
  assert.equal(tileState({ ready: false }, { remembered: true, now }), "updating"); // the last visit's numbers are on screen
  assert.equal(tileState(null, { remembered: true, now }), "updating");
  assert.equal(tileState({ ready: true, partial: true, as_of: at(1) }, { now }), "updating");
  assert.equal(tileState({ ready: true, stale: true, as_of: at(1) }, { now }), "updating");
  assert.equal(tileState({ ready: true, as_of: at(500) }, { now }), "updating");
  assert.equal(tileState({ ready: true, as_of: at(20) }, { now }), "fresh");
});

test("the last known numbers survive a missing, full or broken storage", () => {
  const store = new Map();
  const storage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v) };
  assert.equal(lastKnown(storage, "k"), null);
  remember(storage, "k", { hosts: 3 }, 5);
  assert.deepEqual(lastKnown(storage, "k"), { at: 5, value: { hosts: 3 } });
  store.set("k", "{nope");
  assert.equal(lastKnown(storage, "k"), null);
  assert.equal(lastKnown(undefined, "k"), null);
  assert.doesNotThrow(() => remember({ setItem: () => { throw new Error("quota"); } }, "k", 1));
  assert.doesNotThrow(() => remember(undefined, "k", 1));
});

test("the pollers other than the numbers start when the browser is idle, one after another", () => {
  const log = [];
  const timers = [];
  let idleRun = null;
  const n = startWhenIdle([() => log.push("graph"), () => log.push("discovery"), () => log.push("feed")], {
    idle: (fn, opts) => { idleRun = fn; log.push(`idle:${opts.timeout}`); },
    later: (fn, ms) => timers.push([ms, fn]),
    gap: 100,
  });
  assert.equal(n, 3);
  assert.deepEqual(log, ["idle:1500"]); // nothing has started yet
  idleRun();
  assert.deepEqual(timers.map((t) => t[0]), [0, 100, 200]);
  timers.forEach(([, fn]) => fn());
  assert.deepEqual(log, ["idle:1500", "graph", "discovery", "feed"]);
});

test("without requestIdleCallback the pollers still start", () => {
  const timers = [];
  startWhenIdle([() => {}], { idle: null, later: (fn, ms) => timers.push(ms) });
  assert.deepEqual(timers, [0]);
});

test("each tile has its own poller: none waits for another, so a slow call holds back only its own tile", () => {
  const source = readFileSync(new URL("../static/cve/dashboard.js", import.meta.url), "utf8");
  const pollers = ["pollStats", "pollGraph", "pollDiscovery", "pollAgent", "pollFeed", "pollScanning"];
  for (const name of pollers) {
    const start = source.indexOf(`async function ${name}(`);
    assert.ok(start >= 0, `${name} exists`);
    const body = source.slice(start, source.indexOf("\n}\n", start));
    for (const other of pollers.filter((o) => o !== name)) {
      assert.ok(!new RegExp(`await ${other}\\(|return ${other}\\(`).test(body), `${name} must not wait for ${other}`);
    }
  }
  // the tiles read their own answers: the headline counts carry the coverage, so the Hosts scanned tile does not wait for a second request
  assert.match(source, /paintCoverage\(s\.coverage\)/);
});

test("the dashboard asks for one thing at first paint and reads coverage from the headline counts", () => {
  const source = readFileSync(new URL("../static/cve/dashboard.js", import.meta.url), "utf8");
  assert.ok(!/search\?q=/.test(source), "the Hosts scanned tile must not call the host search");
  const started = source.split("\n").filter((line) => /^poll\(/.test(line));
  assert.deepEqual(started, ["poll(pollStats, 6000);"]); // every other poller is in the deferred list
  assert.match(source, /startWhenIdle\(deferred\)/);
  for (const name of ["pollGraph", "pollDiscovery", "pollAgent", "pollFeed", "pollScanning"]) {
    assert.match(source, new RegExp(`poll\\(${name}, \\d+\\)`));
    assert.ok(!new RegExp(`^poll\\(${name}`, "m").test(source), `${name} must not start at load`);
  }
  assert.match(source, /paintCoverage\(s\.coverage\)/);
});
