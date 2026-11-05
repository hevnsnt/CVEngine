// The CVE explorer's logic that needs no browser: what the address says (?q=, severity, kev, page, id), the API address for it, the
// Ctrl+K palette row that opens the explorer, and the small formatters the rows use. explorer.js draws; tests/test_cve_explorer.mjs checks this.

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const EXPLORER = "/cve/cves/";

// The same rule as cveFeed/cve_explorer.looks_like_id: "CVE-2024-6387", "2024-6387", "cve-2024", or a bare number of 4+ digits.
const ID_SHAPES = [/^CVE-?\d{0,4}(-\d*)?$/, /^\d{4}-\d*$/, /^\d{4,}$/];
export const looksLikeId = (q) => {
  const t = String(q || "").trim().toUpperCase();
  return Boolean(t) && ID_SHAPES.some((re) => re.test(t));
};

// The explorer's state from a location.search string (or URLSearchParams). Unknown values fall back to the defaults.
export function stateFrom(search) {
  const p = search instanceof URLSearchParams ? search : new URLSearchParams(search || "");
  const page = Number.parseInt(p.get("page") || "1", 10);
  const severity = p.get("severity") || "";
  return {
    q: (p.get("q") || "").trim().slice(0, 120),
    severity: SEVERITIES.includes(severity) ? severity : "",
    kev: p.get("kev") === "1",
    page: Number.isFinite(page) && page > 0 ? page : 1,
    id: /^[A-Za-z0-9-]{1,64}$/.test(p.get("id") || "") ? p.get("id").toUpperCase() : "",
  };
}

// "?q=ssh&kev=1": only what differs from the defaults, so a shared link stays short. "" when everything is a default.
export function queryString(state, { withId = true } = {}) {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.severity) p.set("severity", state.severity);
  if (state.kev) p.set("kev", "1");
  if (state.page > 1) p.set("page", String(state.page));
  if (withId && state.id) p.set("id", state.id);
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const apiUrl = (state) => `/cve/api/cves${queryString(state, { withId: false })}`;
export const detailUrl = (cveId) => `/cve/api/cves/${encodeURIComponent(cveId)}`;
export const explorerHref = (q) => `${EXPLORER}${queryString({ q: String(q || "").trim(), page: 1 })}`;

// The palette row "Search CVEs for ..." for what is typed: a bare word or id, never a host filter (port:22, -host:x, "a phrase").
export function cvePaletteRow(text) {
  const q = String(text || "").trim();
  if (q.length < 2 || /[:"]/.test(q) || q.startsWith("-")) return null;
  return {
    label: `Search CVEs for “${q}”`,
    sub: looksLikeId(q) ? "Open it in the CVE explorer" : "Products, vendors and titles in the CVE catalog",
    hint: "CVE catalog",
    href: explorerHref(q),
    section: "Search",
  };
}

export const epssText = (score) => (typeof score === "number" ? `EPSS ${(score * 100).toFixed(score < 0.01 ? 2 : 0)}%` : "EPSS");

// One affected range as text: "8.5p1 to before 9.8p1", "up to 9.7p1", "from 2.0".
export function rangeText(r) {
  if (!r) return "";
  const from = r.introduced && r.introduced !== "0" ? r.introduced : "";
  if (r.fixed) return from ? `${from} to before ${r.fixed}` : `before ${r.fixed}`;
  if (r.lastAffected) return from ? `${from} to ${r.lastAffected}` : `up to ${r.lastAffected}`;
  return from ? `from ${from}` : "every version";
}

export const productName = (a) => [a.vendor, a.product || a.package].filter(Boolean).join(" ") || a.package || "Unnamed product";

export const hostsText = (n) => (n ? `${n.toLocaleString()} of your host${n === 1 ? "" : "s"}` : "None of your hosts");
