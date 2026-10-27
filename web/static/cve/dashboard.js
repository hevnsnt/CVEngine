// Live dashboard: discovery graph + event ticker, the AI activity feed, KPIs and the CVE feed.
// Every panel reads one endpoint each, so the numbers can never disagree with the lists beside them.
import { mountGraph, showNodeDetails } from "/staticfiles/cve/graph.js";
import { cveHref, hostAnchor, ipAnchor, linkify } from "/staticfiles/cve/links.js";
import { sinceLastVisit } from "/staticfiles/cve/seen.js";
import { fmtTime } from "/staticfiles/cve/prefs.js";
import { activityMatrix, dailyCounts, sparkline } from "/staticfiles/cve/charts.js";
import { reportButton } from "/staticfiles/cve/report-export.js";

const dash = document.getElementById("dash");
const csrf = dash.querySelector("[name=csrfmiddlewaretoken]").value;
const slug = dash.dataset.slug;
// The dashboard is scoped to the selected project; "_all" (or none) means every project the viewer can see.
const projParam = slug ? `project=${encodeURIComponent(slug)}` : "";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};
const get = (url) =>
  fetch(url, { credentials: "same-origin" }).then((r) => {
    if (!r.ok) throw new Error(r.status);
    return r.json();
  });
const post = (url, body) =>
  fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: JSON.stringify(body),
  }).then((r) =>
    r.json().then((d) => {
      if (!r.ok) throw new Error(d.error || r.status);
      return d;
    }),
  );
const ago = (iso) => {
  const sec = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000));
  if (sec < 5) return "now";
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
};
const clock = (iso) => fmtTime(iso);
const STATUS = {
  "-1": "queued",
  0: "failed",
  1: "running",
  2: "finished",
  3: "aborted",
};
let online = true;
const setOnline = (ok) => {
  online = ok;
  $("live").className = ok ? "live" : "live off";
  $("ai-live").className = ok ? "live" : "live off";
};

// --- KPIs ---------------------------------------------------------------------------
// Numbers count up to their new value and flash when they change, so a change is noticed without staring.
const shown = {};
function setNum(id, value) {
  const n = $(id);
  if (!n || value == null) return;
  const from = shown[id];
  shown[id] = value;
  if (from === undefined || from === value || !Number.isFinite(value)) {
    n.textContent = value;
    return;
  }
  const t0 = performance.now();
  const dur = 600;
  const tick = (now) => {
    const k = Math.min((now - t0) / dur, 1);
    n.textContent = Math.round(from + (value - from) * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  n.classList.remove("bump");
  void n.offsetWidth;
  n.classList.add("bump");
}

// The biggest hygiene problems, worst first: the open issues grouped by what was checked, so the strip says what is wrong
// (expired certificates, no DMARC) and not only how many. Reads the worst three severities; a group counts what those pages hold.
const HY_AREA = { tls_expired: "Expired certificates", tls_expiring: "Certificates expiring", tls_legacy: "Old TLS versions", tls_weak: "Weak TLS" };
const HY_PREFIX = { spf: "SPF", dkim: "DKIM", dmarc: "DMARC", caa: "CAA", mx: "Mail exchangers", mta_sts: "MTA-STS", smtp_tlsrpt: "TLS reporting", dane: "DANE", tls: "TLS" };
const HY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const hyName = (check) => {
  if (HY_AREA[check]) return HY_AREA[check];
  const word = check.replace(/_/g, " ");
  const area = Object.keys(HY_PREFIX).sort((a, b) => b.length - a.length).find((k) => check === k || check.startsWith(`${k}_`));
  const rest = area ? word.slice(area.length).trim() : word;
  return area ? `${HY_PREFIX[area]}${rest ? ` ${rest}` : ""}` : word.charAt(0).toUpperCase() + word.slice(1);
};
// The longest-open critical or high item (stats keys oldest_open_days / _kind / _id, null when nothing qualifies). Hidden until the server sends it.
const OLDEST_KIND = { cve: ["CVE match", "matches", ""], scanner: ["Scanner finding", "vulns", "?type=scanner"], hygiene: ["Hygiene issue", "hygiene", ""] };
function paintOldest(s) {
  const tile = $("n-oldest");
  if (!tile) return;
  const days = s.oldest_open_days;
  tile.hidden = days == null;
  if (days == null) return;
  setNum("s-oldest_open_days", days);
  const kind = OLDEST_KIND[s.oldest_open_kind];
  $("s-oldest_note").textContent = kind ? `a ${kind[0].toLowerCase()}` : "";
  if (kind && slug) tile.href = `/cve/${encodeURIComponent(slug)}/${kind[1]}/${kind[2]}`;
  tile.classList.toggle("old", days >= 30);
}
// Scan coverage: the share of hosts a scan has looked at. The host search already counts every temperature, so one request answers it.
let coverageAt = 0;
async function paintCoverage() {
  if (!$("n-coverage") || Date.now() - coverageAt < 30000) return;
  coverageAt = Date.now();
  try {
    const r = await get(`/api/v1/projects/${encodeURIComponent(slug || "_all")}/search?q=&page_size=1`);
    const heat = (r.facets && r.facets.heat) || {};
    const total = Object.values(heat).reduce((n, v) => n + v, 0);
    const never = heat.unscanned || 0;
    if (!total) return;
    $("s-coverage").textContent = `${Math.round((100 * (total - never)) / total)}%`;
    $("s-coverage_note").textContent = never ? `${never} of ${total} hosts never scanned` : `all ${total} hosts scanned`;
  } catch (_) {
    coverageAt = 0;
  }
}
let hygieneSig = null;
async function paintHygiene(open) {
  const box = $("hy-top");
  if (!box || open === hygieneSig) return;
  hygieneSig = open;
  try {
    const path = `/api/v1/projects/${encodeURIComponent(slug || "_all")}/hygiene`;
    const pages = await Promise.all(["critical", "high", "medium"].map((sev) => get(`${path}?severity=${sev}&page_size=100`).catch(() => ({ results: [] }))));
    const groups = new Map();
    pages.flatMap((p) => p.results || []).forEach((f) => {
      const g = groups.get(f.check) || { check: f.check, worst: f.severity, n: 0 };
      g.n += 1;
      if ((HY_RANK[f.severity] || 0) > (HY_RANK[g.worst] || 0)) g.worst = f.severity;
      groups.set(f.check, g);
    });
    const top = [...groups.values()].sort((a, b) => (HY_RANK[b.worst] || 0) - (HY_RANK[a.worst] || 0) || b.n - a.n).slice(0, 3);
    box.textContent = "";
    top.forEach((g) => {
      const li = el("li", `sev-${g.worst}`);
      li.append(el("i", "hy-dot"), el("span", "", hyName(g.check)), el("b", "", String(g.n)));
      box.append(li);
    });
    if (!top.length) box.append(el("li", "hy-none", open ? "Low severity only" : "All clear"));
  } catch (_) {
    hygieneSig = null;
  }
}

async function pollStats() {
  try {
    const s = await get(`/cve/api/stats${projParam ? "?" + projParam : ""}`);
    const flat = {
      hosts: s.hosts,
      exposed_hosts: s.exposed_hosts,
      fire: s.tiers.fire,
      smoke: s.tiers.smoke,
      ice: s.tiers.ice,
      matches: s.matches,
      scanner_findings: s.scanner_findings,
      hygiene_open: s.hygiene_open,
      certs_expiring: s.certs_expiring,
    };
    Object.entries(flat).forEach(([k, v]) => setNum(`s-${k}`, v));
    statsNow = s;
    paintMapCount();
    const certNote = $("s-certs_total_note");
    if (certNote) certNote.textContent = s.certs_total ? `of ${s.certs_total} tracked` : "";
    paintHygiene(s.hygiene_open);
    const stuck = $("n-queue");
    if (stuck) {
      // the activity feed also shows scans that run under a finished scan record (weekly deep Nuclei, host rescans): those are work, so not stuck
      stuck.hidden = !(s.scans_queued > 0 && s.scans_running === 0 && running.size === 0);
      setNum("s-scans_queued", s.scans_queued);
    }
    paintCoverage();
    paintOldest(s);
    const pct = s.hosts ? Math.round((100 * s.exposed_hosts) / s.hosts) : 0;
    $("m-exposed").style.width = `${pct}%`;
    const top = Math.max(s.tiers.fire, s.tiers.smoke, s.tiers.ice, 1);
    ["fire", "smoke", "ice"].forEach((t) => {
      $(`b-${t}`).style.width = `${Math.round((100 * s.tiers[t]) / top)}%`;
    });
  } catch (_) {
    /* keep last values */
  }
}

// --- attack surface map: one square per host, colored by its worst threat -------------
const HEAT_ORDER = ["fire", "smoke", "ice", "clean", "unscanned"];
const HEAT_LABEL = { fire: "Fire", smoke: "Smoke", ice: "Ice", clean: "Clean", unscanned: "Not scanned" };
const cells = new Map();
let mapReady = false;
const tip = el("div", "map-tip");
// the hover card for a map tile: the asset's score and state, its worst CVE/finding, and the top score reasons
function fillTip(cell) {
  let info = {};
  try { info = JSON.parse(cell.dataset.info || "{}"); } catch (_) {}
  tip.textContent = "";
  const head = el("div", "tip-head");
  head.append(el("b", "", `Score ${cell.dataset.score || 0}`), el("span", `tip-dot ${cell.dataset.heat}`));
  head.append(el("span", "tip-heat", HEAT_LABEL[cell.dataset.heat] || ""));
  tip.append(head);
  tip.append(el("div", "tip-name", cell.dataset.name));
  if (info.project) tip.append(el("div", "tip-project", info.project));
  const facts = [];
  if (info.ips) facts.push(`${info.ips} IP${info.ips === 1 ? "" : "s"}`);
  if (info.cves) facts.push(`${info.cves} CVE${info.cves === 1 ? "" : "s"}`);
  if (info.findings) facts.push(`${info.findings} finding${info.findings === 1 ? "" : "s"}`);
  if (facts.length) tip.append(el("div", "tip-facts", facts.join("  ·  ")));
  if (info.top_cve) {
    const row = el("div", "tip-vuln");
    row.append(el("span", `tip-tag ${info.top_tier || ""}`, (info.top_tier || "").toUpperCase() || "CVE"));
    row.append(document.createTextNode(` ${info.top_cve}`));
    tip.append(row);
  } else if (info.max_sev) {
    tip.append(el("div", "tip-vuln", `Worst finding: ${info.max_sev}`));
  }
  if ((info.score_parts || []).length) {
    (info.score_parts || []).forEach((part) => tip.append(el("div", "tip-reason", `${part.label}: +${part.points}`)));
  } else {
    (info.reasons || []).slice(0, 3).forEach((r) => tip.append(el("div", "tip-reason", r)));
  }
}
tip.hidden = true;
document.body.append(tip);

// The dashboard spans every project the viewer can see, so a host opens in its own project, not the selected one
function hostsHref(name, project) {
  const where = project || slug;
  return where ? `/cve/${encodeURIComponent(where)}/hosts/?host=${encodeURIComponent(name)}` : "#";
}

const MAP_POOL = 400; // tiles built; the layout below shows as many of the highest-scoring hosts as fill the card in whole rows
const MAP_GAP = 6;
const MAP_MIN_SCORE = 30; // hosts that score lower are left off the map (they are still on the Hosts page)
// Tile tiers, richest first: the minimum size each needs. The layout picks the richest tier that holds every host, then stretches the
// tiles to fill the card exactly. A tier with room to spare shows more about each host; when even the smallest tier cannot hold them
// all, the map keeps only whole rows (never a ragged last row) and the tiles grow to fill the freed space.
const MAP_TIERS = [
  { name: "rich", size: "xl", w: 96, h: 104 },
  { name: "card", size: "xl", w: 92, h: 64 },
  { name: "chip", size: "l", w: 50, h: 40 },
  { name: "dot", size: "s", w: 34, h: 32 },
];
function fitTier(W, H, n, t) {
  let best = null;
  const maxCols = Math.floor((W + MAP_GAP) / (t.w + MAP_GAP));
  for (let c = 1; c <= Math.min(maxCols, n); c++) {
    const r = Math.ceil(n / c);
    const tw = (W - (c - 1) * MAP_GAP) / c;
    const th = (H - (r - 1) * MAP_GAP) / r;
    if (th < t.h) continue;
    const aspect = tw / th;
    const shape = aspect >= 0.9 && aspect <= 2 ? 1 : 0.6; // prefer tiles that are not slivers
    const score = Math.min(tw, 210) * Math.min(th, 150) * (n / (c * r)) * shape;
    if (!best || score > best.score) best = { cols: c, rows: r, tw, th, score };
  }
  return best;
}
function planMap(W, H, n) {
  for (const t of MAP_TIERS) {
    const fit = fitTier(W, H, n, t);
    if (fit) return { tier: t, show: n, ...fit };
  }
  const t = MAP_TIERS[MAP_TIERS.length - 1];
  const cols = Math.max(1, Math.floor((W + MAP_GAP) / (t.w + MAP_GAP)));
  const rows = Math.max(1, Math.floor((H + MAP_GAP) / (t.h + MAP_GAP)));
  return { tier: t, show: Math.min(n, cols * rows), cols, rows, tw: (W - (cols - 1) * MAP_GAP) / cols, th: (H - (rows - 1) * MAP_GAP) / rows };
}
let mapOrdered = [];
function layoutMap() {
  const map = $("map");
  const W = map.clientWidth;
  const H = map.clientHeight;
  if (!W || !H || !mapOrdered.length) return;
  const plan = planMap(W, H, mapOrdered.length);
  map.dataset.size = plan.tier.size;
  map.dataset.tier = plan.tier.name;
  map.dataset.narrow = plan.tw < 170 ? "1" : "0"; // narrow tiles drop the long "why" lines, which would only be cut off
  map.dataset.lines = String(plan.tier.name === "rich" ? Math.max(1, Math.min(5, Math.floor((plan.th - 50) / 15))) : 0);
  map.style.setProperty("--cols", plan.cols);
  map.style.setProperty("--rows", plan.rows);
  mapOrdered.forEach((h, i) => {
    const cell = cells.get(h.id);
    if (cell) cell.hidden = i >= plan.show;
  });
  if (mapDrawn !== plan.show) {
    mapDrawn = plan.show;
    paintMapCount();
  }
}
new ResizeObserver(() => requestAnimationFrame(layoutMap)).observe($("map"));
// The header of the attack-surface map reads the same numbers as the Exposed hosts tile, so the two cannot disagree: the map
// draws live hosts (they resolved, or answered over HTTP), the tile counts every host the Hosts page lists.
let statsNow = null;
let mapDrawn = null; // squares on the map right now
let mapBelow = 0; // live hosts under the score threshold
let mapEligible = 0; // live hosts that score high enough to be on the map
function paintMapCount() {
  const n = $("map-count");
  paintMapEmpty($("map").querySelectorAll(".hx:not([hidden])").length);
  if (!statsNow || !statsNow.hosts) {
    n.textContent = "";
    n.removeAttribute("title");
    return;
  }
  const live = statsNow.hosts_live;
  const shown = mapDrawn != null && mapDrawn < mapEligible ? `Top ${mapDrawn} of ${mapEligible} scoring ${MAP_MIN_SCORE}+` : `${mapEligible} scoring ${MAP_MIN_SCORE}+`;
  n.textContent = `${shown} · ${live} live`;
  n.title = `One square per live host that scores ${MAP_MIN_SCORE} or more (a live host resolved to an address or answered over HTTP), highest score first. ${live} hosts are live and ${statsNow.hosts} are in the inventory; the rest are on the Hosts page.`;
}

// An empty map says why it is empty: nothing added yet, or hosts known but none live (resolved or answering).
function paintMapEmpty(shown) {
  const map = $("map");
  let box = map.querySelector(".map-empty");
  if (shown) {
    if (box) box.remove();
    return;
  }
  const known = statsNow ? statsNow.hosts || 0 : 0;
  const key = mapBelow ? `low:${mapBelow}` : known ? `known:${known}` : "none";
  if (box && box.dataset.key === key) return;
  if (box) box.remove();
  box = el("div", "map-empty");
  box.dataset.key = key;
  if (mapBelow) {
    box.append(
      el("b", "", `No host scores ${MAP_MIN_SCORE} or more`),
      el("p", "", `${mapBelow} live host${mapBelow === 1 ? " scores" : "s score"} lower and ${mapBelow === 1 ? "is" : "are"} left off the map. They are all on the Hosts page.`),
    );
    if (slug) box.append(el("a", "btn ghost sm", "Open hosts", { href: `/cve/${encodeURIComponent(slug)}/hosts/` }));
  } else if (known) {
    box.append(
      el("b", "", "No live hosts yet"),
      el("p", "", `${known} host${known === 1 ? " is" : "s are"} in the inventory, but none has resolved to an address or answered over HTTP. Squares appear here as they do.`),
    );
    if (slug) box.append(el("a", "btn ghost sm", "Open hosts", { href: `/cve/${encodeURIComponent(slug)}/hosts/` }));
  } else {
    box.append(el("b", "", "Nothing to map yet"), el("p", "", "Add a target and discovery draws every host it finds here, colored by its worst threat."));
    const add = el("button", "btn sm", "Add targets", { type: "button" });
    add.setAttribute("data-add-targets", "");
    box.append(add);
  }
  map.append(box);
}

// The extra lines a roomy tile shows: the worst CVE or finding, the counts, then the biggest reasons for the score.
function hostDetails(info) {
  const box = el("span", "hx-details");
  if (info.top_cve) {
    box.append(el("span", "hx-d hx-cve", info.top_cve));
  } else if (info.max_sev) {
    box.append(el("span", "hx-d", `Worst finding: ${info.max_sev}`));
  } else {
    box.append(el("span", "hx-d", "No CVEs"));
  }
  if (info.cves) box.append(el("span", "hx-d", `${info.cves} CVE${info.cves === 1 ? "" : "s"}`));
  if (info.findings) box.append(el("span", "hx-d", `${info.findings} finding${info.findings === 1 ? "" : "s"}`));
  if (info.ips) box.append(el("span", "hx-d", `${info.ips} IP${info.ips === 1 ? "" : "s"}`));
  if ((info.aliases || []).length) box.append(el("span", "hx-d", `Also ${info.aliases.slice(0, 3).join(", ")}${info.aliases.length > 3 ? ` +${info.aliases.length - 3}` : ""}`));
  const reasons = (info.score_parts || []).length ? info.score_parts.map((p) => `${p.label} +${p.points}`) : (info.reasons || []);
  reasons.slice(0, 3).forEach((r) => box.append(el("span", "hx-d hx-why", r)));
  return box;
}

function hostTag(info) {
  const tier = info.top_tier || (info.top_cve ? "cve" : "");
  return tier ? el("i", `hx-tag ${info.top_tier || ""}`, tier.toUpperCase()) : null;
}

// What a tile calls its host. An address is shown whole (cutting it at the first dot leaves "52" or "20"); a name is shown as its
// first part ("staging", "www"), with the domain it belongs to underneath, so two "www" tiles from different targets can be told apart.
const IP_LIKE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+)$/i;
const tileName = (h) => {
  const label = String(h.label || "");
  const target = String(h.target || "").toLowerCase();
  if (IP_LIKE.test(label) || (target && label.toLowerCase() === target)) return label;
  return label.split(".")[0];
};
function hostName(short, h) {
  const name = el("span", IP_LIKE.test(short) ? "hx-name ip" : "hx-name", short);
  const target = String(h.target || "");
  if (target && target.toLowerCase() !== String(h.label || "").toLowerCase() && !IP_LIKE.test(String(h.label || ""))) name.append(el("small", "hx-target", target));
  return name;
}

function drawMap(nodes) {
  const liveHosts = nodes.filter((n) => n.kind === "subdomain");
  const hosts = liveHosts.filter((h) => (h.score || 0) >= MAP_MIN_SCORE);
  mapEligible = hosts.length;
  mapBelow = liveHosts.length - hosts.length;
  const map = $("map");
  const counts = {};
  const seen = new Set();
  const heatOf = (h) => (HEAT_ORDER.includes(h.heat) ? h.heat : "unscanned");
  hosts.forEach((h) => (counts[heatOf(h)] = (counts[heatOf(h)] || 0) + 1));
  const ordered = hosts
    .slice()
    .sort((a, b) => (b.score || 0) - (a.score || 0) || HEAT_ORDER.indexOf(a.heat) - HEAT_ORDER.indexOf(b.heat) || a.label.localeCompare(b.label))
    .slice(0, MAP_POOL);
  const cellsInOrder = ordered.map((h, i) => {
    const heat = heatOf(h);
    seen.add(h.id);
    let cell = cells.get(h.id);
    if (!cell) {
      cell = el("a", "hx enter", null, { role: "listitem" });
      cell.style.animationDelay = mapReady ? "0s" : `${Math.min(i * 18, 500)}ms`;
      if (mapReady) cell.classList.add("new");
      // the entrance animation plays once, when the tile is created; never again on a later refresh
      setTimeout(() => cell.classList.remove("enter", "new"), mapReady ? 2800 : 1200);
      const place = (e) => {
        // a small card tied to the cursor, kept inside the viewport and flipped above/left near the edges
        const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
        let x = e.clientX + pad, y = e.clientY + pad;
        if (x + w > window.innerWidth - 8) x = e.clientX - w - pad;
        if (y + h > window.innerHeight - 8) y = e.clientY - h - pad;
        tip.style.left = `${Math.max(8, x)}px`;
        tip.style.top = `${Math.max(8, y)}px`;
      };
      cell.addEventListener("mouseenter", (e) => { fillTip(cell); tip.hidden = false; place(e); });
      cell.addEventListener("mousemove", place);
      cell.addEventListener("mouseleave", () => (tip.hidden = true));
      cells.set(h.id, cell);
    }
    const score = h.score || 0;
    const short = tileName(h);
    const infoJson = JSON.stringify(h.info || {});
    if (cell.dataset.score !== String(score) || cell.dataset.short !== short + String(h.target || "") || cell.dataset.info !== infoJson) {
      cell.textContent = "";
      cell.append(el("span", "score", String(score)), hostName(short, h), hostDetails(h.info || {}));
      const tag = hostTag(h.info || {});
      if (tag) cell.append(tag);
      cell.dataset.short = short + String(h.target || "");
    }
    cell.dataset.name = h.label;
    cell.dataset.score = score;
    cell.dataset.info = infoJson;
    if (cell.dataset.heat !== heat) {
      cell.dataset.heat = heat;
      HEAT_ORDER.forEach((k) => cell.classList.toggle(k, k === heat));
    }
    const href = hostsHref(h.label, h.project);
    if (cell.getAttribute("href") !== href) cell.setAttribute("href", href);
    cell.setAttribute("aria-label", `${h.label}: ${HEAT_LABEL[heat]}`);
    return cell;
  });
  // put the tiles in order without detaching the ones already in place (re-attaching restarts CSS animations)
  let ref = map.firstElementChild;
  cellsInOrder.forEach((cell) => {
    if (cell === ref) ref = ref.nextElementSibling;
    else map.insertBefore(cell, ref);
  });
  cells.forEach((cell, id) => {
    if (!seen.has(id)) {
      cell.remove();
      cells.delete(id);
    }
  });
  mapReady = true;
  mapOrdered = ordered;
  layoutMap();
  paintMapEmpty(hosts.length);
  paintMapCount();
  const sig = HEAT_ORDER.map((k) => counts[k] || 0).join(",");
  const legend = $("map-legend");
  if (legend.dataset.sig !== sig) {
    legend.dataset.sig = sig;
    legend.textContent = "";
    HEAT_ORDER.filter((k) => counts[k]).forEach((k) => {
      const item = el("span");
      item.append(el("i", k), document.createTextNode(`${HEAT_LABEL[k]} `), el("b", "", counts[k]));
      legend.append(item);
    });
  }
}

// --- live discovery -----------------------------------------------------------------
let followScan = dash.dataset.follow || "";
const graph = mountGraph($("d-graph"), {
  pods: true,
  onSelect: (d) => showNodeDetails($("d-detail"), d),
  pinKey: () => `cve.pins.${slug || "all"}`, // where nodes were dropped; the graph spans the project, so the key is the project
});
showNodeDetails($("d-detail"), null);
let lastEvent = 0;
let shownScan = null;
const tickerMax = 100; // lines kept in the live discovery ticker; the rest fall off the bottom
const agentMax = 100; // and in the AI activity card

// New lines prepend at the top. A reader who scrolled down to an earlier line keeps their place: the list only
// follows the newest line while it is at (or near) the top. Browsers differ on scroll anchoring, so do it by hand.
function keepPlace(list, change) {
  const reading = list.scrollTop > 8;
  const before = list.scrollHeight;
  const top = list.scrollTop;
  change();
  if (reading) list.scrollTop = top + (list.scrollHeight - before);
}

function drawCounts(c) {
  const box = $("d-counts");
  box.textContent = "";
  [
    ["hosts", "Hosts"],
    ["ips", "IPs"],
    ["ports", "Open ports"],
  ].forEach(([k, label]) => {
    const item = el("span", "count");
    item.append(el("b", "", c[k] ?? 0), document.createTextNode(` ${label}`));
    box.append(item);
  });
}

// what discovery just saw: a host name or an address links to its record; anything else (an open port, a URL) is text
let followedProject = slug || "";
function eventLabel(e) {
  const label = el("span", "ev-label");
  const text = e.label || e.host || "";
  if (followedProject && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) label.append(ipAnchor(followedProject, text));
  else if (followedProject && (e.type === "DNS_NAME" || e.type === "DNS_NAME_UNRESOLVED") && text === e.host) label.append(hostAnchor(followedProject, text));
  else label.textContent = text;
  return label;
}

function tickerLine(e) {
  const li = el("li", "", null, { "data-id": e.id });
  li.append(
    el(
      "span",
      `ev ev-${e.type.toLowerCase()}`,
      e.type.replace("_", " ").toLowerCase(),
    ),
    eventLabel(e),
  );
  if (e.module) li.append(el("span", "ev-mod", e.module));
  return li;
}

// The graph always shows the whole project (every domain CVEngine knows about and how they relate),
// polled on its own so it stays populated even between scans or once one finishes. The discovery card's
// status badge, counts and ticker follow one scan (the one just started, else whatever is running or most
// recent) without ever narrowing what the graph itself draws.
let graphNodeCount = 0;
let graphVersion = ""; // the server answers 304 while the graph has not changed, so an idle dashboard costs almost nothing

async function pollGraph() {
  try {
    const r = await fetch(`/cve/api/graph?v=${encodeURIComponent(graphVersion)}${projParam ? "&" + projParam : ""}`, { credentials: "same-origin" });
    if (r.status === 304) return;
    if (!r.ok) throw new Error(r.status);
    const g = await r.json();
    graphVersion = g.version || "";
    graphNodeCount = graph.sync(g).nodes;
    $("d-empty").style.display = graphNodeCount ? "none" : "";
    drawMap(g.nodes);
  } catch (_) {
    setOnline(false);
  }
}

async function pollDiscovery() {
  try {
    const d = await get(
      `/cve/api/discovery?scan=${followScan}&after=${lastEvent}${projParam ? "&" + projParam : ""}`,
    );
    setOnline(true);
    if (!d.scan) {
      $("d-status").style.display = "none";
      $("d-target").textContent = "No discovery has run yet.";
      return;
    }
    if (shownScan !== d.scan.id) {
      shownScan = d.scan.id;
      lastEvent = 0;
      $("d-ticker").textContent = "";
      return pollDiscovery();
    }
    const badge = $("d-status");
    badge.style.display = "";
    badge.textContent =
      d.scan.status === -1 && d.scan.queue_position != null
        ? `queued, ${d.scan.queue_position} ahead`
        : STATUS[d.scan.status] || d.scan.status;
    badge.className = `badge ${d.scan.status === 1 ? "running" : d.scan.status === 2 ? "success" : d.scan.status === 0 ? "failed" : ""}`;
    followedProject = d.scan.project || slug || "";
    const target = $("d-target");
    target.textContent = "";
    linkify(
      target,
      d.scan.status === 1
        ? `Discovering ${d.scan.target} now`
        : d.scan.status === -1
          ? `Waiting to discover ${d.scan.target}`
          : `Last discovery: ${d.scan.target} (${STATUS[d.scan.status] || ""})`,
      followedProject,
      { kinds: ["host"] },
    );
    drawCounts(d.counts);
    const list = $("d-ticker");
    keepPlace(list, () =>
      d.events.forEach((e) => {
        lastEvent = Math.max(lastEvent, e.id);
        if (list.querySelector(`[data-id="${e.id}"]`)) return; // a slow answer can repeat what an earlier one already drew
        list.prepend(tickerLine(e));
      }),
    );
    while (list.children.length > tickerMax) list.lastChild.remove();
  } catch (_) {
    setOnline(false);
  }
}

// Adding targets is the shared dialog (addtargets.js); when it starts a scan, follow it right away.
document.addEventListener("cve:targets-added", (e) => {
  if (e.detail.scan_ids && e.detail.scan_ids.length) {
    followScan = String(e.detail.scan_ids[0]);
    pollDiscovery();
  }
});

// --- AI activity --------------------------------------------------------------------
const KIND = {
  feed: "read feed",
  inventory: "inventory",
  target: "target",
  confirm: "reasoning",
  write_check: "writing",
  run_check: "running",
  validate: "validate",
  discovery: "discover",
  scan: "scan",
  hygiene: "hygiene",
  changes: "changes",
  saved_search: "saved search",
};
let lastActivity = 0;
let activityNow = ""; // the server's clock at the last answer, to ask which lines were repeated since
const running = new Map();
let activityPollActive = false;

function agentLine(a) {
  const li = el("li", `a-${a.status}`, null, { "data-id": a.id, "data-msg": `${a.kind}|${a.message}` });
  li.append(
    el("span", `kind k-${a.kind}`, KIND[a.kind] || a.kind),
    linkify(el("span", "a-msg"), a.message, a.project || slug),
    el("time", "a-time", ago(a.created), { datetime: a.created, title: clock(a.created) }),
  );
  if (a.repeat > 1) li.querySelector(".a-msg").append(el("span", "a-repeat", ` ×${a.repeat}`));
  if (a.status === "running")
    li.append(el("span", "spin", "", { role: "img", "aria-label": "in progress" }));
  return li;
}

// keep the relative times honest between polls
setInterval(() => {
  document.querySelectorAll("#agent time[datetime]").forEach((t) => {
    t.textContent = ago(t.getAttribute("datetime"));
  });
}, 10000);

async function pollAgent() {
  if (activityPollActive) return;
  activityPollActive = true;
  try {
    const ids = [...running.keys()].join(",");
    const d = await get(
      `/cve/api/activity?after=${lastActivity}&running=${ids}&since=${encodeURIComponent(activityNow)}${projParam ? "&" + projParam : ""}`,
    );
    activityNow = d.now || activityNow;
    setOnline(true);
    const list = $("agent");
    keepPlace(list, () => {
    d.settled.forEach((a) => {
      const old = running.get(a.id);
      if (old) {
        const fresh = agentLine(a);
        old.replaceWith(fresh);
        running.delete(a.id);
      }
    });
    (d.bumped || []).forEach((a) => {
      const old = list.querySelector(`[data-id="${a.id}"]`);
      if (!old) return;
      const fresh = agentLine(a);
      old.remove();
      list.prepend(fresh); // reported again just now: back to the top with its ×N
    });
    d.items.forEach((a) => {
      lastActivity = Math.max(lastActivity, a.id);
      if (list.querySelector(`[data-id="${a.id}"]`)) return; // same cursor in two overlapping requests: show it once
      const above = list.firstElementChild;
      if (above && a.status !== "running" && above.dataset.msg === `${a.kind}|${a.message}`) return; // the same line twice in a row
      const li = agentLine(a);
      list.prepend(li);
      if (a.status === "running") running.set(a.id, li);
    });
    });
    while (list.children.length > agentMax) {
      const old = list.lastChild;
      running.delete(Number(old.dataset.id));
      old.remove(); // older history remains available on the full Activity page
    }
    $("agent-empty").style.display = list.children.length ? "none" : "";
  } catch (_) {
    setOnline(false);
  } finally {
    activityPollActive = false;
  }
}

// --- CVE feed -----------------------------------------------------------------------
const feed = $("feed");
let newest = 0;
let tierFilter = "";
function applyFilter() {
  let visible = 0;
  feed.querySelectorAll("li").forEach((li) => {
    li.hidden = Boolean(tierFilter) && li.dataset.tier !== tierFilter;
    if (!li.hidden) visible += 1;
  });
  $("feed-filter").textContent = tierFilter ? `${tierFilter} only` : "All temperatures";
  const empty = $("feed-empty");
  empty.style.display = visible ? "none" : "";
  empty.textContent = tierFilter
    ? `No ${tierFilter} CVEs in the feed yet.`
    : "Waiting for CVEs. They arrive as cve.now publishes them.";
  document.querySelectorAll(".temp").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.tier === tierFilter)));
}
document.querySelectorAll(".temp").forEach((b) =>
  b.addEventListener("click", () => {
    tierFilter = tierFilter === b.dataset.tier ? "" : b.dataset.tier;
    applyFilter();
    if (tierFilter) feed.closest(".feed-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }),
);
function cveRow(c) {
  const li = el("li", "", null, { "data-tier": c.tier, "data-id": c.id });
  li.append(
    el("span", `tier ${c.tier}`, c.tier),
    c.matches
      ? Object.assign(el("a", "cve-id", c.cve_id, { href: cveHref(slug || "_all", c.cve_id) }), { title: "The hosts this CVE matches" })
      : el("span", "cve-id", c.cve_id),
    el("span", "cve-title", c.title || "No description yet"),
  );
  const meta = el("div", "meta");
  if (c.cvss != null) meta.append(el("span", "", `CVSS ${c.cvss}`));
  if (c.kev) meta.append(el("span", "", "KEV"));
  if (c.exploit_db) meta.append(el("span", "", "Exploit-DB"));
  if (c.matches)
    meta.append(
      Object.assign(el("a", "hit", `${c.matches} host match${c.matches > 1 ? "es" : ""}`, { href: cveHref(slug || "_all", c.cve_id) }), { title: "The hosts this CVE matches" }),
    );
  li.append(meta);
  return li;
}
async function pollFeed() {
  try {
    const d = await get(`/cve/api/feed${newest ? `?after=${newest}` : ""}`);

    const first = !newest;
    const ordered = first ? d.items : d.items.slice().reverse();
    ordered.forEach((c) => {
      newest = Math.max(newest, c.id);
      if (feed.querySelector(`[data-id="${c.id}"]`)) return;
      const li = cveRow(c);
      if (first) feed.append(li);
      else feed.prepend(li);
    });
    applyFilter();
  } catch (_) {
    /* next tick */
  }
}

// Each poller re-arms itself when its request finishes, instead of firing from setInterval: when the server is busy
// with scans several requests were in flight with the same cursor, and each one drew the same lines again.
const every = (fn, ms) => {
  const tick = async () => {
    try {
      await fn();
    } finally {
      setTimeout(tick, ms);
    }
  };
  tick();
};
every(pollStats, 6000);
every(pollGraph, 10000);
every(pollDiscovery, 2500);
every(pollAgent, 2000);
every(pollFeed, 6000);

// --- changes since you last looked ---------------------------------------------------------------
// A one-line strip above the instrument panel: how many inventory changes arrived since this browser last had the Live page
// open, with a link to the Changes page narrowed to that moment. The baseline is per browser and moves forward when you leave.
(async () => {
  if (!slug) return;
  const baseline = sinceLastVisit("live", slug);
  if (!baseline) return;
  try {
    const r = await get(`/api/v1/projects/${encodeURIComponent(slug)}/changes?since=${encodeURIComponent(baseline)}&page_size=1`);
    if (!r.count) return;
    const strip = document.getElementById("since-strip");
    strip.href = `/cve/${encodeURIComponent(slug)}/changes/?since=${encodeURIComponent(baseline)}`;
    strip.textContent = "";
    strip.append(el("b", "", `${r.count} change${r.count === 1 ? "" : "s"}`), el("span", "", `since you last looked, ${ago(baseline)}`), el("em", "", "See what changed"));
    strip.hidden = false;
  } catch (_) {
    /* the strip is a convenience: stay hidden when the answer does not come */
  }
})();

// --- trends ---------------------------------------------------------------------------------------
// Two charts under the counters (new findings per day, inventory changes per day) and a small trend line in the CVE matches and
// scanner findings counters. They are built in the browser from the dates the API already returns, so they show what arrived
// and when; an "exposed over time" and a "time to fix" line need history the server does not keep yet (requested).
(async () => {
  if (!slug) return;
  const TIERS = ["fire", "smoke", "ice"];
  const base = `/api/v1/projects/${encodeURIComponent(slug)}`;
  const PAGES = 5;
  const collect = async (path) => {
    const rows = [];
    for (let page = 1; page <= PAGES; page += 1) {
      const sep = path.includes("?") ? "&" : "?";
      const data = await get(`${base}/${path}${sep}page=${page}&page_size=200`);
      const got = data.results || [];
      rows.push(...got);
      if (got.length < 200) break;
    }
    return rows;
  };
  try {
    const [findings, changes] = await Promise.all([collect("findings?status=all"), collect("changes?since=365d")]);
    const section = $("trends");
    if (!findings.length && !changes.length) return;
    const tierOf = (f) => {
      if (TIERS.includes(f.heat)) return f.heat;
      const sev = String(f.severity || "").toLowerCase();
      return sev === "critical" || sev === "high" ? "fire" : sev === "medium" ? "smoke" : "ice";
    };
    section.append(
      activityMatrix({
        title: "Activity",
        rows: [
          { key: "findings", label: "New findings", unit: "findings", tiered: true, items: findings.map((f) => ({ date: f.detected, tier: tierOf(f) })) },
          { key: "changes", label: "Inventory changes", unit: "changes", items: changes.map((c) => ({ date: c.detected })) },
        ],
      }),
    );
    section.hidden = false;
    const spark = (anchorId, dates, label) => {
      const a = $(anchorId);
      if (!a || !dates.length) return;
      const values = dailyCounts(dates, 14).map((p) => p.v);
      const svg = sparkline(values);
      const sr = el("span", "sr", `${label}: ${values.reduce((n, v) => n + v, 0)} new in the last 14 days`);
      a.append(svg, sr);
    };
    spark("n-matches", findings.filter((f) => f.type === "cve").map((f) => f.detected), "CVE matches");
    spark("n-findings", findings.filter((f) => f.type === "scanner").map((f) => f.detected), "Scanner findings");
  } catch (_) {
    /* trends are extra: leave the section hidden when the data does not come */
  }
})();

// --- scanning now ---------------------------------------------------------------------------------
// What is being worked on right now, so it can be told apart on the graph: the domains and hosts of the running scans (the server's
// graph-live view) plus the addresses and names the running AI-activity lines mention ("Background full port scan of 198.51.100.34").
// They pulse on the graph and are listed as chips above it; a chip pans and zooms the graph to its node.
const SCAN_TOKEN = /\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi;
const MAX_CHIPS = 6;
async function pollScanning() {
  if (document.hidden) return;
  try {
    const live = await get(`/cve/api/graph-live${projParam ? "?" + projParam : ""}`);
    const labels = new Set();
    running.forEach((li) => (String(li.dataset.msg || "").split("|").slice(1).join("|").match(SCAN_TOKEN) || []).forEach((t) => labels.add(t.toLowerCase())));
    graph.setActive(live.domains, live.hosts, [...labels]);
    const box = $("d-scanning");
    const targets = new Map(); // name -> stage
    live.scans.forEach((s) => targets.set(s.domain.toLowerCase(), s.stage || ""));
    labels.forEach((l) => { if (!targets.has(l) && graph.hasLabel(l)) targets.set(l, ""); });
    box.textContent = "";
    if (!targets.size) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    box.append(el("span", "eyebrow", "Scanning now"));
    [...targets].slice(0, MAX_CHIPS).forEach(([name, stage]) => {
      const chip = el("button", "scan-chip", name, { type: "button", title: `Show ${name} on the graph` });
      if (stage) chip.append(el("small", "", stage));
      chip.addEventListener("click", () => graph.locate(name));
      box.append(chip);
    });
    if (targets.size > MAX_CHIPS) box.append(el("span", "note", `+${targets.size - MAX_CHIPS} more`));
  } catch (_) {
    /* the next poll tries again */
  }
}
pollScanning();
setInterval(pollScanning, 3000);

// The "Group CVEs" toggle: fold each host's CVEs into its bubble (default), or draw every CVE as its own dot.
{
  const toggle = $("d-pods");
  if (toggle)
    toggle.addEventListener("click", () => {
      const on = toggle.getAttribute("aria-pressed") !== "true";
      toggle.setAttribute("aria-pressed", String(on));
      graph.setPods(on);
    });
}

// --- PDF report ----------------------------------------------------------------------------------
// A report is about one project, so the button is offered once a project is selected (not in the combined All projects view).
if (slug && slug !== "_all") {
  const head = document.querySelector(".page-head");
  if (head) head.append(reportButton({ slug }));
}
