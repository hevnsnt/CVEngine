import test from "node:test";
import assert from "node:assert/strict";
import { expiry, jobLine, megabytes, stats, withheld } from "../static/cve/seed-card-logic.js";

const manifest = { count: 40867, tiers: { fire: 30000, smoke: 9000, ice: 1867 }, with_detection: 10665, bytes: 13552569, sha256: "ab".repeat(32),
  manual_withheld: 2, dropped: { records: 1, detections: 3, reasons: { secret: 2, tenant_host: 2 }, ids: [] } };

test("stats shows the numbers of the manifest", () => {
  const s = Object.fromEntries(stats(manifest));
  assert.equal(s.CVEs, "40,867");
  assert.ok(s["By tier (fire, smoke, ice)"]);
  assert.equal(s["With a detection record"], "10,665");
  assert.equal(s.Size, "13 MB");
  assert.equal(s["SHA-256"].length, 64);
  assert.deepEqual(stats(null), []);
});

test("withheld says how many and why, never what", () => {
  const lines = withheld(manifest).join("\n");
  assert.match(lines, /2 detection records written by a person/);
  assert.match(lines, /1 CVE record dropped whole/);
  assert.match(lines, /3 detection records left out/);
  assert.match(lines, /2 looked like a password, key or token/);
  assert.match(lines, /2 named one of this install's domains or hosts/);
});

test("an old manifest without the scrub block still reads", () => {
  const lines = withheld({ count: 1 });
  assert.match(lines.join(" "), /found nothing/);
});

test("jobLine for running, failed and imported jobs", () => {
  assert.match(jobLine({ kind: "export", state: "running", stage: "Writing the catalog", count: 5000 }), /Writing the catalog.*5,000 CVEs so far/);
  assert.match(jobLine({ kind: "import", state: "failed", error: "bad checksum" }), /Import failed: bad checksum/);
  assert.match(jobLine({ kind: "import", state: "done", result: { created: 7, detections: 3, skipped: 1, invalid: 0, verified: true } }), /Imported 7 new CVEs.*matched its manifest/);
  assert.match(jobLine({ kind: "import", state: "done", result: { created: 0, detections: 0, skipped: 0, invalid: 0, verified: false } }), /not checked/);
  assert.equal(jobLine(null), "");
});

test("expiry and megabytes", () => {
  assert.match(expiry(new Date(Date.now() + 5 * 3600000).toISOString()), /about 5 hours/);
  assert.match(expiry(new Date(Date.now() - 1000).toISOString()), /about to be removed/);
  assert.equal(megabytes(2621440), "2.5 MB");
});
