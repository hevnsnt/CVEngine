// Pure helpers of the Situations page (no DOM, no imports): the words, the three empty states and what a link may point at.
// tests/test_situations_logic.mjs runs them under `node --test`.

export const TIER_WORDS = { proven: "proven", likely: "likely", exposure: "exposed", minor: "minor" };
const ORDER = ["proven", "likely", "exposure", "minor"];

// [{key, n, label}] of the tiers a situation has, worst first: "2 proven", "1 likely", "3 exposed", "4 minor"
export function chipsOf(counts) {
  const c = counts || {};
  return ORDER.filter((k) => Number(c[k]) > 0).map((k) => ({ key: k, n: Number(c[k]), label: `${Number(c[k])} ${TIER_WORDS[k]}` }));
}

// the colour of a row's edge: the worst tier it holds (proof is fire, likely is smoke, nothing else is coloured)
export function heatOf(counts) {
  const c = counts || {};
  return c.proven > 0 ? "fire" : c.likely > 0 ? "smoke" : "";
}

// which page may a finding link open: the existing panes of this project only
const LINK = /^\/cve\/[-\w]+\/(vulns|hygiene|secrets|hosts)\/(\?[-\w=%.&]*)?(#[-\w]*)?$/;
export const safeLink = (href) => (typeof href === "string" && LINK.test(href) ? href : "");

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
export const countLine = (data) => (data && data.count != null ? plural(data.count, "situation", "situations") : "");

// What an empty list says, from the server's `state` (never from the rows): {kind, title, body, tone}.
//   attention + no rows: the search or the filter matched nothing (a plain line, not a celebration)
//   clear:     hosts were scanned and nothing open needs a person
//   unscanned: nothing has been scanned yet, which is not the same thing
export function stateView(data, { slug = "", filtered = false } = {}) {
  const d = data || {};
  if (d.state === "unscanned") {
    return { kind: "unscanned", icon: "target", tone: "", title: "Nothing has been scanned yet", body: "Situations appear once a scan has looked at your hosts. Add a target to start one." };
  }
  if (d.state === "clear") {
    const when = d.last_scan_at ? ` The last scan finished ${String(d.last_scan_at).slice(0, 10)}.` : "";
    return { kind: "clear", icon: "shield", tone: "calm", title: "Nothing needs you", body: `${plural(d.hosts || 0, "host was", "hosts were")} checked and nothing open on ${d.hosts === 1 ? "it" : "them"} needs a person.${when}` };
  }
  return { kind: "nomatch", title: "", body: filtered ? "No situation matches. Clear the search or the filter." : "No situation to show." };
}

// the line under the detail's findings when the row carried fewer than the host has
export const moreFindings = (row) => (row && row.findings_truncated ? `Showing ${row.findings.length} of ${row.findings_total} findings.` : "");
