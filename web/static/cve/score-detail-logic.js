// The lines of a host's score, ready to show: pure functions, no DOM (tests/test_score_detail.mjs).
// cveFeed/scoring.py stores every contributor of a score as {label, points, kind, text, ref}. ``ref`` names the evidence a line stands on;
// ``refHref`` turns it into the page that shows that evidence. A line stored before the sentences existed has a label and points only.

const enc = encodeURIComponent;

// Where a ref's evidence lives. ``slug`` is the project, ``host`` the host name. Null when the line has nothing to open.
export function refHref(ref, { slug, host }) {
  if (!ref || typeof ref !== "object" || !slug) return null;
  const base = `/cve/${enc(slug)}`;
  const id = Number.isInteger(ref.id) && ref.id > 0 ? ref.id : null;
  switch (ref.type) {
    case "match": return id ? `${base}/matches/#${id}` : `${base}/matches/?host=${enc(host || "")}`;
    case "matches": return `${base}/matches/?host=${enc(host || "")}`;
    case "vulnerability": return id ? `${base}/vulns/#vulnerability-${id}` : `${base}/vulns/?type=scanner`;
    case "hygiene": return id ? `${base}/vulns/#hygiene-${id}` : `${base}/hygiene/`;
    case "hygiene_list": return `${base}/hygiene/`;
    case "secret": return id ? `${base}/secrets/?open=${id}` : `${base}/secrets/`;
    case "host_tab": return `${base}/hosts/?host=${enc(host || "")}&tab=${enc(ref.tab || "overview")}`;
    default: return null;
  }
}

const EVIDENCE_WORDS = {
  match: "Open the CVE match",
  matches: "See the CVE matches of this host",
  vulnerability: "Open the finding",
  hygiene: "Open the configuration finding",
  hygiene_list: "See the configuration checks",
  secret: "Open the secret",
  host_tab: "Open on the host page",
};
export const evidenceWord = (ref) => (ref && EVIDENCE_WORDS[ref.type]) || "";

// {lines, sum, total, capped, hidden}: every line of ``parts`` in order, the points they add up to and the score the page shows (at most 100).
// ``limit`` folds the lines past the first ``limit`` into ``hidden`` (an "N more" row with its own total) when a small tile cannot show them all.
export function scoreLines(parts, ctx, { limit = Infinity } = {}) {
  const lines = (Array.isArray(parts) ? parts : [])
    .filter((p) => p && typeof p === "object")
    .map((p) => ({
      label: String(p.label || ""),
      text: String(p.text || ""),
      points: Number.isFinite(Number(p.points)) ? Number(p.points) : 0,
      kind: String(p.kind || ""),
      ref: p.ref && typeof p.ref === "object" ? p.ref : null,
      href: refHref(p.ref, ctx || {}),
    }));
  const sum = lines.reduce((n, l) => n + l.points, 0);
  const shown = lines.slice(0, limit);
  const rest = lines.slice(limit);
  return {
    lines: shown,
    hidden: rest.length ? { count: rest.length, points: rest.reduce((n, l) => n + l.points, 0), lines: rest } : null,
    sum,
    total: Math.min(100, sum),
    capped: sum > 100,
  };
}

// The sentence under the lines that says how they become the number: "Total 43", or why the number is lower than the sum.
export function totalNote({ sum, total, capped }, score) {
  if (capped) return `the lines add up to ${sum}, and a score stops at 100.`;
  if (score != null && Number(score) !== total) return `the lines add up to ${total}, but the score of ${score} was stored before the last rescore.`;
  return "the sum of the lines above.";
}
