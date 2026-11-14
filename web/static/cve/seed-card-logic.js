// The CVE catalog seed card: what to say about a status the API returned. Pure functions (no DOM), tested in tests/test_seed_card.mjs.

export const REASON_TEXT = {
  tenant_name: "named an organization or project of this install",
  tenant_host: "named one of this install's domains or hosts",
  tenant_address: "held one of this install's IP addresses",
  private_address: "held a private network address",
  secret: "looked like a password, key or token",
  internal_path: "held a path inside this install",
};

const n = (v) => Number(v || 0).toLocaleString("en-US");

export function megabytes(bytes) {
  const mb = Number(bytes || 0) / 1048576;
  return mb >= 10 ? `${Math.round(mb)} MB` : `${mb.toFixed(1)} MB`;
}

// The numbers of a finished export, as [label, value] pairs for the page.
export function stats(manifest) {
  if (!manifest) return [];
  const t = manifest.tiers || {};
  return [
    ["CVEs", n(manifest.count)],
    ["By tier (fire, smoke, ice)", `${n(t.fire)}, ${n(t.smoke)}, ${n(t.ice)}`],
    ["With a detection record", n(manifest.with_detection)],
    ["Size", megabytes(manifest.bytes)],
    ["SHA-256", String(manifest.sha256 || "")],
  ];
}

// What the scrub kept out, in plain sentences. Never says what text was found, only how many and what kind.
export function withheld(manifest) {
  if (!manifest) return [];
  const d = manifest.dropped || { records: 0, detections: 0, reasons: {} };
  const lines = [];
  const manual = Number(manifest.manual_withheld || 0);
  lines.push(manual ? `${n(manual)} detection record${manual === 1 ? "" : "s"} written by a person here stayed out: they are never shared.` : "No hand-written detection records were left out (they are never shared).");
  if (!d.records && !d.detections) {
    lines.push("The privacy check found nothing of this install in the file, so it dropped nothing.");
    return lines;
  }
  if (d.records) lines.push(`${n(d.records)} CVE record${d.records === 1 ? "" : "s"} dropped whole.`);
  if (d.detections) lines.push(`${n(d.detections)} detection record${d.detections === 1 ? "" : "s"} left out (the CVE itself is in the file).`);
  Object.entries(d.reasons || {})
    .sort((a, b) => b[1] - a[1])
    .forEach(([reason, count]) => lines.push(`${n(count)} ${REASON_TEXT[reason] || reason}.`));
  return lines;
}

// One sentence for the running or last job.
export function jobLine(job) {
  if (!job) return "";
  const what = job.kind === "import" ? "Import" : "Seed file";
  if (job.state === "running") {
    const done = job.count ? ` ${n(job.count)} CVEs so far.` : "";
    return `${what}: ${job.stage || "working"}.${done}`;
  }
  if (job.state === "failed") return `${what} failed: ${job.error || "see the worker log"}.`;
  if (job.kind === "import" && job.result) {
    const r = job.result;
    return `Imported ${n(r.created)} new CVEs and ${n(r.detections)} detection records; ${n(r.skipped)} were already here, ${n(r.invalid)} lines were unusable. ${r.verified ? "The file matched its manifest." : "No manifest was given, so the checksum was not checked."}`;
  }
  return "";
}

export function expiry(iso, now = Date.now()) {
  if (!iso) return "";
  const ms = Date.parse(iso) - now;
  if (!(ms > 0)) return "It is about to be removed.";
  const hours = Math.max(1, Math.round(ms / 3600000));
  return `The file is removed from the server in about ${hours} hour${hours === 1 ? "" : "s"}, or when the next one is created.`;
}
