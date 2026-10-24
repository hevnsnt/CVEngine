// Live dashboard: discovery graph + event ticker, the AI activity feed, KPIs and the CVE feed.
// Every panel reads one endpoint each, so the numbers can never disagree with the lists beside them.
import { mountGraph, showNodeDetails } from "/staticfiles/cve/graph.js";

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
const clock = (iso) =>
  new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
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

async function pollStats() {
  try {
    const s = await get(`/cve/api/stats${projParam ? "?" + projParam : ""}`);
    const flat = {
      targets: s.targets,
      hosts: s.hosts,
      exposed_hosts: s.exposed_hosts,
      fire: s.tiers.fire,
      smoke: s.tiers.smoke,
      ice: s.tiers.ice,
      matches: s.matches,
      scanner_findings: s.scanner_findings,
      autofire_runs: s.autofire_runs,
      templates: s.templates,
      certs_expiring: s.certs_expiring,
      scans_running: s.scans_running,
    };
    Object.entries(flat).forEach(([k, v]) => setNum(`s-${k}`, v));
    const scansLabel = $("s-scans_label");
    if (scansLabel)
      scansLabel.textContent = s.scans_queued
        ? `Scans running, ${s.scans_queued} queued`
        : "Scans running";
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

// --- attack surface map: one square per host, coloured by its worst threat -------------
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

function drawMap(nodes) {
  const hosts = nodes.filter((n) => n.kind === "subdomain");
  const map = $("map");
  const counts = {};
  const seen = new Set();
  map.dataset.size = hosts.length <= 12 ? "xl" : hosts.length <= 60 ? "l" : "s";
  const ordered = hosts
    .slice()
    .sort((a, b) => (b.score || 0) - (a.score || 0) || HEAT_ORDER.indexOf(a.heat) - HEAT_ORDER.indexOf(b.heat) || a.label.localeCompare(b.label));
  const cellsInOrder = ordered.map((h, i) => {
    const heat = HEAT_ORDER.includes(h.heat) ? h.heat : "unscanned";
    counts[heat] = (counts[heat] || 0) + 1;
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
    if (cell.dataset.score !== String(score)) {
      cell.textContent = "";
      cell.append(el("span", "score", String(score)));
    }
    cell.dataset.name = h.label;
    cell.dataset.score = score;
    cell.dataset.info = JSON.stringify(h.info || {});
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
  const empty = map.querySelector(".map-empty");
  if (!hosts.length && !empty) map.append(el("span", "map-empty", "No hosts yet. Add a target and they appear here."));
  else if (hosts.length && empty) empty.remove();
  $("map-count").textContent = hosts.length ? `${hosts.length} host${hosts.length === 1 ? "" : "s"}` : "";
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

function tickerLine(e) {
  const li = el("li", "", null, { "data-id": e.id });
  li.append(
    el(
      "span",
      `ev ev-${e.type.toLowerCase()}`,
      e.type.replace("_", " ").toLowerCase(),
    ),
    el("span", "ev-label", e.label || e.host),
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
    $("d-target").textContent =
      d.scan.status === 1
        ? `Discovering ${d.scan.target} now`
        : d.scan.status === -1
          ? `Waiting to discover ${d.scan.target}`
          : `Last discovery: ${d.scan.target} (${STATUS[d.scan.status] || ""})`;
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
};
let lastActivity = 0;
let activityNow = ""; // the server's clock at the last answer, to ask which lines were repeated since
const running = new Map();
let activityPollActive = false;

function agentLine(a) {
  const li = el("li", `a-${a.status}`, null, { "data-id": a.id, "data-msg": `${a.kind}|${a.message}` });
  li.append(
    el("span", `kind k-${a.kind}`, KIND[a.kind] || a.kind),
    el("span", "a-msg", a.message),
    el("time", "a-time", clock(a.created)),
  );
  if (a.repeat > 1) li.querySelector(".a-msg").append(el("span", "a-repeat", ` ×${a.repeat}`));
  if (a.status === "running")
    li.append(el("span", "spin", "", { "aria-label": "in progress" }));
  return li;
}

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
    el("span", "cve-id", c.cve_id),
    el("span", "cve-title", c.title || "No description yet"),
  );
  const meta = el("div", "meta");
  if (c.cvss != null) meta.append(el("span", "", `CVSS ${c.cvss}`));
  if (c.kev) meta.append(el("span", "", "KEV"));
  if (c.exploit_db) meta.append(el("span", "", "Exploit-DB"));
  if (c.matches)
    meta.append(
      el("span", "hit", `${c.matches} host match${c.matches > 1 ? "es" : ""}`),
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
