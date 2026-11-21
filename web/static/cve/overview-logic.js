// Pure helpers of the Overview (no DOM, no imports): the words that are not already in the server's summary, the sparkline, and what a link may point at.
// tests/test_overview_logic.mjs runs them under `node --test`. The sentences of the status block, the tiles' feet and the threat cards are built by
// cveFeed/overview.py (templates filled from counts); this file only lays them out.

const SLUG = /^[-\w]+$/;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const ZERO_WIRE = "https://radar.cloudflare.com/zero-wire/";

const plural = (n, one, many) => `${Number(n).toLocaleString("en-US")} ${Number(n) === 1 ? one : many}`;

// The points of a sparkline (a polyline in a width x height box, the lowest value at the bottom). One value is a flat line, none is no line.
export function sparkPoints(values, { w = 120, h = 32, pad = 3 } = {}) {
  const v = (values || []).map(Number).filter(Number.isFinite);
  if (!v.length) return "";
  const lo = Math.min(...v);
  const span = Math.max(...v) - lo || 1;
  const xs = v.length === 1 ? [w / 2] : v.map((_, i) => (i / (v.length - 1)) * (w - pad * 2) + pad);
  return v.map((x, i) => `${xs[i].toFixed(1)},${(h - pad - ((x - lo) / span) * (h - pad * 2)).toFixed(1)}`).join(" ");
}

const num = (x) => Number(x).toLocaleString("en-US", { maximumFractionDigits: 1 });

// What a screen reader hears for a sparkline: the figure's name, how many days and where it went ("Externally facing hosts over 14 days, rising from 41 to 55").
export function sparkLabel(label, values) {
  const v = (values || []).map(Number).filter(Number.isFinite);
  if (v.length < 2) return `${label}: not enough days to draw a trend yet`;
  const first = v[0];
  const last = v[v.length - 1];
  const way = last > first ? `rising from ${num(first)} to ${num(last)}` : last < first ? `falling from ${num(first)} to ${num(last)}` : `flat at ${num(last)}`;
  return `${label} over ${v.length} days, ${way}`;
}

// The tile's colour word: worse is fire, better is ok, anything else is not coloured.
export const toneClass = (tone) => (tone === "worse" ? "worse" : tone === "better" ? "better" : "");
export const pillClass = (tone) => (tone === "fire" || tone === "ok" || tone === "smoke" ? tone : "smoke");

// Where a tile goes (the Overview's slug may be a project's or the reserved _all).
export function kpiHref(key, slug) {
  if (!SLUG.test(slug || "")) return "";
  const base = `/cve/${slug}`;
  return { exposed: `${base}/hosts/?exposed=1`, needs: `${base}/matches/`, critical: `${base}/vulns/?severity=critical`, mttf: `${base}/vulns/?status=fixed` }[key] || "";
}

// The hosts of a threat card: the Hosts page with the group's own search (a CVE id, or the product).
export function hostsHref(slug, group) {
  if (!SLUG.test(slug || "") || !group || !group.hosts_query) return "";
  return `/cve/${slug}/hosts/?q=${encodeURIComponent(group.hosts_query)}`;
}

// A card's second link: the Zero Wire briefing when it is one (only an address on radar.cloudflare.com/zero-wire/ is used), else the CVE catalog entry of the first CVE.
export function readLink(group) {
  if (group && typeof group.link === "string" && group.link.startsWith(ZERO_WIRE)) return { href: group.link, label: group.link_label || "Read the briefing", external: true };
  const ids = ((group && group.cve_ids) || []).filter((c) => CVE_ID.test(c));
  if (!ids.length) return null;
  return { href: `/cve/cves/?id=${encodeURIComponent(ids[0])}`, label: ids.length === 1 ? `Read ${ids[0]}` : `Read ${ids[0]} and ${ids.length - 1} more`, external: false };
}

const breakdown = (rows) => (rows || []).filter((r) => r.n > 0).map((r) => `${r.n} ${r.project}`);

// The impact panel of a card: {matched: {big, text} | null, unknown: {big, text} | null}. In the all-projects view the hosts are split by project.
export function impactPanel(group) {
  const g = group || {};
  const by = g.by_project || null;
  const out = { matched: null, unknown: null };
  if (g.matched) {
    const where = by ? breakdown(by.matched) : [];
    const all = where.length === 1 ? `, all in ${by.matched[0].project}` : where.length > 1 ? ` (${where.join(", ")})` : "";
    out.matched = { big: plural(g.matched, "host", "hosts"), text: `${g.matched === 1 ? "matches" : "match"} by version${all}${g.confirmed ? `, ${g.confirmed} confirmed by a check` : ""}` };
  }
  if (g.product_only) {
    const where = by ? breakdown(by.product_only) : [];
    const name = g.product || "the product";
    out.unknown = { big: `${g.matched ? "+" : ""}${plural(g.product_only, "host", "hosts")}`, text: `${g.product_only === 1 ? "runs" : "run"} ${name}, version unknown${where.length ? ` (${where.join(", ")})` : ""}` };
  }
  return out;
}

export const foldedTitle = (n) => `${n} more checked: none of your hosts run ${n === 1 ? "it" : "them"}`;
export const allHostsText = (total) => `All ${Number(total).toLocaleString("en-US")} ${Number(total) === 1 ? "host that needs" : "hosts that need"} you →`;
export const seeHostsText = (n) => `See the ${plural(n, "host", "hosts")}`;

// "Sentinel line" and the clock: the line is hidden unless the server sent it (it does for an App Admin only).
export const sentinelText = (s) => (s && typeof s.text === "string" ? s.text : "");

// A fix-first row's host link may only open a pane of a project.
const PANE = /^\/cve\/[-\w]+\/(hosts|situations)\/(\?[-\w=%.&~]*)?$/;
export const rowHref = (href) => (typeof href === "string" && PANE.test(href) ? href : "");

// The changes link: the Changes page narrowed to the week (the server sends the start as an ISO time; only its date is used).
export function changesHref(slug, since) {
  if (!SLUG.test(slug || "")) return "";
  const day = typeof since === "string" && /^\d{4}-\d{2}-\d{2}/.test(since) ? since.slice(0, 10) : "";
  return `/cve/${slug}/changes/${day ? `?since=${day}` : ""}`;
}
