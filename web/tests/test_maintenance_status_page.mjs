// The maintenance page's status model (web/static/cve/maintenance.html, between "BEGIN maint-model" and "END maint-model"): a pure function of the
// status file the updater writes and the clock. Rendered states: working, slow build, stalled, failed and restored, failed and not restored, done,
// and the plain page when there is no status.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = readFileSync(path.join(here, "..", "static", "cve", "maintenance.html"), "utf8");
const code = html.slice(html.indexOf("// BEGIN maint-model"), html.indexOf("// END maint-model"));
assert.ok(code.length > 200, "the model is in the page");
const { maintModel, maintDuration } = new Function(`${code}; return { maintModel, maintDuration };`)();

const NOW = 1_800_000_000;
const status = (extra = {}) => ({
  v: 1,
  state: "working",
  step: "build",
  steps: [],
  detail: "Building the new version. This is the longest step: a small server can take 10 to 25 minutes.",
  sha: "abcdef123456",
  started_at: NOW - 600,
  step_started_at: NOW - 300,
  updated_at: NOW - 2,
  last_output_at: NOW - 3,
  ...extra,
});

test("no status file: the plain page", () => {
  assert.equal(maintModel(null, NOW).mode, "plain");
  assert.equal(maintModel({}, NOW).mode, "plain");
  assert.equal(maintModel({ state: "bogus" }, NOW).mode, "plain");
  assert.equal(maintModel("<script>", NOW).mode, "plain");
});

test("working: the current step is highlighted, earlier ones are done, with elapsed time, sha and the plain detail", () => {
  const m = maintModel(status(), NOW);
  assert.equal(m.mode, "working");
  assert.deepEqual(m.steps.map((s) => s.state), ["done", "done", "now", "todo", "todo", "todo", "todo", "todo"]);
  assert.equal(m.steps.find((s) => s.state === "now").key, "build");
  assert.equal(m.elapsed, "10 minutes");
  assert.equal(m.startedAtMs, (NOW - 600) * 1000);
  assert.equal(m.sha, "abcdef123456");
  assert.match(m.detail, /longest step/);
  assert.match(m.detail, /This step has run for about 5 minutes/);
  assert.equal(m.warning, "");
  assert.equal(m.headline, "We are rebuilding cvENGINE.");
});

test("slow build: said calmly, and that it is still working", () => {
  const m = maintModel(status({ step_started_at: NOW - 15 * 60, started_at: NOW - 17 * 60 }), NOW);
  assert.equal(m.mode, "slow");
  assert.match(m.warning, /taking longer than usual/);
  assert.match(m.warning, /still working/);
  assert.equal(m.warningLevel, "info");
});

test("stalled build: no output for N minutes is a warning", () => {
  const m = maintModel(status({ last_output_at: NOW - 7 * 60, step_started_at: NOW - 9 * 60 }), NOW);
  assert.equal(m.mode, "stalled");
  assert.match(m.warning, /No output for 7 minutes/);
  assert.equal(m.warningLevel, "warn");
});

test("a silent build is not stalled before five minutes, another step is after three", () => {
  assert.equal(maintModel(status({ last_output_at: NOW - 4 * 60 }), NOW).mode, "working");
  assert.equal(maintModel(status({ step: "migrating", last_output_at: NOW - 4 * 60, step_started_at: NOW - 4 * 60 }), NOW).mode, "stalled");
});

test("an updater that stopped refreshing the status is an error level warning", () => {
  const m = maintModel(status({ updated_at: NOW - 5 * 60 }), NOW);
  assert.equal(m.mode, "stalled");
  assert.equal(m.warningLevel, "error");
  assert.match(m.warning, /has not reported for 5 minutes/);
});

test("failed and restored: what failed, that the old version runs again, what to do, the log", () => {
  const log = Array.from({ length: 30 }, (_, i) => `line ${i}`);
  const m = maintModel(
    status({ state: "failed", error: { summary: "The new version could not be built.", restored: true, next: "On the server, read the log, then run make up.", log } }),
    NOW
  );
  assert.equal(m.mode, "failed_restored");
  assert.match(m.headline, /did not finish/);
  assert.match(m.headline, /previous version is running again/);
  assert.equal(m.error.summary, "The new version could not be built.");
  assert.match(m.error.restoredText, /running again/);
  assert.match(m.error.next, /make up/);
  assert.equal(m.error.log.length, 20);
  assert.equal(m.error.log.at(-1), "line 29");
  assert.equal(m.steps.find((s) => s.state === "bad").key, "build");
});

test("failed and not restored: the administrator is fixing it, nothing is lost", () => {
  const m = maintModel(status({ state: "failed", error: { summary: "The new version was installed but did not start.", restored: false, next: "Run make up.", log: [] } }), NOW);
  assert.equal(m.mode, "failed_not_restored");
  assert.equal(m.headline, "The update did not finish.");
  assert.match(m.error.restoredText, /not running/);
  assert.match(m.error.restoredText, /administrator is fixing it/);
  assert.match(m.status, /Waiting for the administrator/);
  const unknown = maintModel(status({ state: "failed", error: { summary: "x", restored: null, next: "", log: [] } }), NOW);
  assert.equal(unknown.mode, "failed_not_restored");
  assert.match(unknown.error.restoredText, /administrator is fixing it/);
});

test("done: every step is done", () => {
  const m = maintModel(status({ state: "done" }), NOW);
  assert.equal(m.mode, "done");
  assert.ok(m.steps.every((s) => s.state === "done"));
});

test("hostile values are bounded text: a long field is cut and a bad sha is dropped", () => {
  const m = maintModel(status({ sha: "<img src=x onerror=1>", detail: "x".repeat(5000), error: undefined }), NOW);
  assert.equal(m.sha, "");
  assert.ok(m.detail.length < 400);
  const f = maintModel(status({ state: "failed", error: { summary: "s".repeat(1000), restored: true, next: "n".repeat(1000), log: ["l".repeat(1000)] } }), NOW);
  assert.ok(f.error.summary.length <= 200 && f.error.next.length <= 300 && f.error.log[0].length <= 200);
});

test("durations are plain", () => {
  assert.equal(maintDuration(1), "1 second");
  assert.equal(maintDuration(59), "59 seconds");
  assert.equal(maintDuration(60), "1 minute");
  assert.equal(maintDuration(25 * 60), "25 minutes");
  assert.equal(maintDuration(125 * 60), "2 hours 5 min");
});

test("the page has no external request, an aria-live region, a no-JS refresh and no long dashes", () => {
  assert.doesNotMatch(html, /<link[^>]+href=/);
  assert.doesNotMatch(html, /<script[^>]+src=/);
  assert.doesNotMatch(html, /<img\b/);
  assert.doesNotMatch(html, /@import|url\(\s*["']?(https?:|\/)/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<noscript><meta http-equiv="refresh"/);
  assert.match(html, /name="viewport"/);
  assert.doesNotMatch(html, /[\u2013\u2014]/);
  assert.match(html, /"\/maintenance-status\.json\?t="/);
});
