// The CVE explorer page (/cve/cves/): search the whole catalog by id or technology, fifty rows a page, and open one CVE in a drawer with
// its summary, CVSS, affected ranges, references and the hosts of yours it matches. The address keeps the search (?q=, severity, kev,
// page) and the open CVE (?id=), so a link shows the same thing. DOM is built with textContent only.
import { emptyState, el } from "/staticfiles/cve/ui.js";
import { fmtDay } from "/staticfiles/cve/prefs.js";
import { cveHref, hostHref } from "/staticfiles/cve/links.js";
import {
  apiUrl, detailUrl, epssText, hostsText, productName, queryString, rangeText, stateFrom,
} from "/staticfiles/cve/explorer-logic.js";

const $ = (id) => document.getElementById(id);
const form = $("cvx-form");
const input = $("cve-q");
const sev = $("cve-sev");
const kev = $("cve-kev");
const list = $("cvx-list");
const empty = $("cvx-empty");
const count = $("cvx-count");
const pager = $("cvx-pager");

let state = stateFrom(location.search);
let seq = 0;
let typing = null;

async function getJson(url, signal) {
  const res = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" }, signal });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    /* not JSON */
  }
  if (!res.ok) throw Object.assign(new Error(data.error || `Request failed (${res.status})`), { status: res.status });
  return data;
}

function remember(push) {
  const url = `${location.pathname}${queryString(state)}`;
  if (url !== `${location.pathname}${location.search}`) (push ? history.pushState : history.replaceState).call(history, null, "", url);
}

const flags = (c) => {
  const out = [];
  if (c.kev) out.push(el("span", "badge critical", "KEV", { title: "Listed in CISA's Known Exploited Vulnerabilities" }));
  if (c.exploit_db) out.push(el("span", "badge high", "Exploit", { title: "A public exploit is known" }));
  if (c.epss) out.push(el("span", "badge medium", epssText(c.epss_score), { title: "FIRST EPSS: likely to be exploited in the next 30 days" }));
  return out;
};

function row(c) {
  const li = el("li", "cvx-row", null, { "data-tier": c.tier });
  const open = el("button", "cvx-open", null, { type: "button", "aria-haspopup": "dialog" });
  const top = el("span", "cvx-top");
  top.append(el("span", `tier ${c.tier}`, c.tier), el("span", "cvx-id", c.cve_id));
  if (c.severity) top.append(el("span", `badge ${c.severity}`, c.cvss != null ? `${c.severity} ${c.cvss}` : c.severity));
  top.append(...flags(c));
  open.append(top, el("span", "cvx-title", c.title || "No description yet"));
  const meta = el("span", "cvx-meta");
  meta.append(el("span", "", c.published_at ? `Published ${fmtDay(c.published_at)}` : "Not yet published"));
  meta.append(el("span", c.hosts ? "hit" : "", hostsText(c.hosts)));
  open.append(meta);
  open.addEventListener("click", () => openDetail(c.cve_id, true));
  li.append(open);
  return li;
}

function drawList(data) {
  list.textContent = "";
  empty.textContent = "";
  const n = data.count || 0;
  const what = state.q ? `for “${state.q}”` : "in the catalog";
  count.textContent = `${n.toLocaleString()} CVE${n === 1 ? "" : "s"} ${what}`;
  data.items.forEach((c) => list.append(row(c)));
  if (!data.items.length) {
    const filtered = state.severity || state.kev;
    empty.append(
      emptyState(
        n && state.page > 1
          ? { icon: "search", title: "No more results", body: "This page is past the end of the list.", actions: [{ label: "First page", run: () => go({ page: 1 }) }] }
          : {
              icon: "search",
              title: state.q ? "No CVE matches" : "The catalog is empty",
              body: state.q
                ? `Nothing in the catalog matches “${state.q}”${filtered ? " with these filters" : ""}. Try a product name (openssh, php) or part of an id (2024-6387).`
                : "CVEs arrive as the feed publishes them.",
              actions: filtered ? [{ label: "Clear filters", run: () => go({ severity: "", kev: false, page: 1 }) }] : [],
            },
      ),
    );
  }
  const pages = Math.max(1, Math.ceil(n / (data.page_size || 50)));
  pager.hidden = pages <= 1;
  $("cvx-page").textContent = `Page ${state.page.toLocaleString()} of ${pages.toLocaleString()}`;
  $("cvx-prev").disabled = state.page <= 1;
  $("cvx-next").disabled = !data.has_next;
}

let inflight = null;
async function load() {
  const mine = ++seq;
  if (inflight) inflight.abort();
  inflight = new AbortController();
  count.textContent = "Searching…";
  try {
    const data = await getJson(apiUrl(state), inflight.signal);
    if (mine === seq) drawList(data);
  } catch (err) {
    if (err.name === "AbortError" || mine !== seq) return;
    list.textContent = "";
    empty.textContent = "";
    count.textContent = "Search failed";
    empty.append(emptyState({ icon: "info", title: "The search did not run", body: err.message, actions: [{ label: "Try again", run: load }] }));
  }
}

function go(change, push = true) {
  state = { ...state, ...change };
  input.value = state.q;
  sev.value = state.severity;
  kev.checked = state.kev;
  remember(push);
  load();
}

// --- the detail drawer ------------------------------------------------------------------------
const drawer = el("aside", "drawer cvx-drawer", null, { "aria-labelledby": "cvx-dh", role: "dialog" });
drawer.inert = true;
const dhead = el("div", "drawer-head");
const dtitle = el("h2", "", "CVE", { id: "cvx-dh" });
const dclose = el("button", "btn ghost sm", "Close", { type: "button", "aria-label": "Close the CVE details" });
const dbody = el("div", "drawer-body cvx-detail", null, { "aria-live": "polite" });
dhead.append(dtitle, dclose);
drawer.append(dhead, dbody);
document.body.append(drawer);
let opener = null;
let shown = 0;

function closeDetail(push = true) {
  shown += 1;
  drawer.classList.remove("open");
  drawer.inert = true;
  if (state.id) {
    state = { ...state, id: "" };
    remember(push);
  }
  if (opener && document.contains(opener)) opener.focus();
  opener = null;
}
dclose.addEventListener("click", () => closeDetail());
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && drawer.classList.contains("open") && !document.querySelector("dialog[open]")) closeDetail();
});

const section = (title, ...kids) => {
  const s = el("section", "cvx-sec");
  s.append(el("h3", "", title), ...kids);
  return s;
};

function detailView(d) {
  const box = el("div");
  const head = el("div", "cvx-dtop");
  head.append(el("span", `tier ${d.tier}`, d.tier));
  if (d.severity) head.append(el("span", `badge ${d.severity}`, d.severity));
  head.append(...flags(d));
  box.append(el("p", "cvx-did mono", d.cve_id), head);
  if (d.title) box.append(el("p", "cvx-dtitle", d.title));
  const summary = d.summary || d.description;
  box.append(section("Summary", el("p", "", summary || "No description yet.")));
  if (d.summary && d.description && d.description !== d.summary) {
    const more = el("details", "cvx-more");
    more.append(el("summary", "", "The advisory's own words"), el("p", "", d.description));
    box.lastChild.append(more);
  }
  const facts = el("dl", "cvx-facts");
  const fact = (k, v) => facts.append(el("dt", "", k), el("dd", "mono", v));
  fact("CVSS", d.cvss != null ? String(d.cvss) : "Not scored");
  if (d.cvss_vector) fact("Vector", d.cvss_vector);
  fact("EPSS", typeof d.epss_score === "number" ? `${(d.epss_score * 100).toFixed(1)}%${typeof d.epss_percentile === "number" ? ` (top ${Math.max(0.1, (1 - d.epss_percentile) * 100).toFixed(1)}%)` : ""}` : d.epss ? "Above 10%" : "Below 10% or unknown");
  fact("KEV", d.kev ? "Known exploited" : "Not listed");
  fact("Published", d.published_at ? fmtDay(d.published_at) : "Not yet");
  box.append(section("Scores", facts));
  const affected = el("ul", "cvx-affected");
  d.affected.forEach((a) => {
    const li = el("li");
    li.append(el("b", "", productName(a)));
    const ranges = a.ranges.length ? a.ranges.map(rangeText).join("; ") : "No version range given";
    li.append(el("span", "note", ranges));
    affected.append(li);
  });
  box.append(section("Affected", d.affected.length ? affected : el("p", "note", "The record names no affected product yet.")));
  const hosts = el("ul", "cvx-hosts");
  d.hosts.forEach((h) => {
    const li = el("li", "", null, { "data-heat": h.heat });
    li.append(el("a", "host-link", h.host, { href: hostHref(h.project, h.host) }));
    const what = [h.project_name, [h.product, h.version].filter(Boolean).join(" "), h.status !== "open" ? h.status : ""].filter(Boolean).join(" · ");
    li.append(el("span", "note", what));
    li.append(el("a", `badge ${h.heat}`, h.heat, { href: cveHref(h.project, d.cve_id, h.match_id), title: "The match on this host" }));
    hosts.append(li);
  });
  const hostNote = d.host_count > d.hosts.length ? `Showing ${d.hosts.length.toLocaleString()} of ${d.host_count.toLocaleString()}.` : "";
  box.append(
    section(
      `Your hosts (${d.host_count.toLocaleString()})`,
      d.hosts.length
        ? hosts
        : emptyState({ icon: "shield", tone: "calm", title: "None of your hosts", body: "No host in the projects you can see matches this CVE." }),
      ...(hostNote ? [el("p", "note", hostNote)] : []),
    ),
  );
  const refs = el("ul", "cvx-refs");
  d.references.slice(0, 40).forEach((r) => {
    const li = el("li");
    li.append(el("a", "", r.url, { href: r.url, target: "_blank", rel: "noopener noreferrer" }));
    if (r.type) li.append(el("span", "badge", r.type));
    refs.append(li);
  });
  box.append(section(`References (${d.references.length})`, d.references.length ? refs : el("p", "note", "None listed.")));
  return box;
}

async function openDetail(cveId, push) {
  const mine = ++shown;
  if (!drawer.classList.contains("open")) opener = document.activeElement;
  drawer.inert = false;
  drawer.classList.add("open");
  dtitle.textContent = cveId;
  dbody.replaceChildren(el("div", "skeleton"), el("div", "skeleton"));
  if (state.id !== cveId) {
    state = { ...state, id: cveId };
    remember(push);
  }
  try {
    const d = await getJson(detailUrl(cveId));
    if (mine !== shown) return;
    dbody.replaceChildren(detailView(d));
  } catch (err) {
    if (mine !== shown) return;
    dbody.replaceChildren(
      emptyState({ icon: "info", title: err.status === 404 ? "Not in the catalog" : "Could not load it", body: err.status === 404 ? `${cveId} is not in the CVE catalog.` : err.message }),
    );
  }
  dclose.focus();
}

// --- wiring -------------------------------------------------------------------------------
form.addEventListener("submit", (e) => {
  e.preventDefault();
  clearTimeout(typing);
  go({ q: input.value.trim(), page: 1 });
});
input.addEventListener("input", () => {
  clearTimeout(typing);
  typing = setTimeout(() => go({ q: input.value.trim(), page: 1 }, false), 300);
});
sev.addEventListener("change", () => go({ severity: sev.value, page: 1 }));
kev.addEventListener("change", () => go({ kev: kev.checked, page: 1 }));
$("cvx-prev").addEventListener("click", () => {
  go({ page: Math.max(1, state.page - 1) });
  form.scrollIntoView({ block: "start" });
});
$("cvx-next").addEventListener("click", () => {
  go({ page: state.page + 1 });
  form.scrollIntoView({ block: "start" });
});
window.addEventListener("popstate", () => {
  state = stateFrom(location.search);
  input.value = state.q;
  sev.value = state.severity;
  kev.checked = state.kev;
  load();
  if (state.id) openDetail(state.id, false);
  else if (drawer.classList.contains("open")) closeDetail(false);
});

input.value = state.q;
input.focus();
const end = input.value.length;
input.setSelectionRange(end, end);
remember(false);
load();
if (state.id) openDetail(state.id, false);
