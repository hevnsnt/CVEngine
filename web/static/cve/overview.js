// The Overview's front: the status sentences, the four tiles, this week's threats, Fix first and What changed.
// One endpoint (GET /cve/api/overview, cveFeed/overview.py) holds all of it, shared for a minute by everyone who sees the same projects; this file draws its
// answer on the same cadence the page polls its counters, with the same pace and conditional GET (static/cve/poll.js), so an unchanged answer is a 304 and
// no redraw. Every string that came from a scan or a third-party feed is set with textContent, never as markup, and every link is checked by overview-logic.js.
// The AI activity box and the Live discovery card are dashboard.js's and are not touched here.
import { fmtTime } from "/staticfiles/cve/prefs.js";
import { createGet, createPace, every } from "/staticfiles/cve/poll.js";
import {
  allHostsText, changesHref, foldedTitle, hostsHref, impactPanel, kpiHref, pillClass, readLink, rowHref, seeHostsText, sentinelText, sparkLabel, sparkPoints, toneClass,
} from "/staticfiles/cve/overview-logic.js";

const root = document.getElementById("ov");
if (root) {
  const slug = root.dataset.slug || "";
  const all = slug === "_all";
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text, attrs = {}) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
    return n;
  };
  const svg = (tag, attrs = {}) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
    return n;
  };
  const pace = createPace();
  const conditional = createGet();
  const get = (url) =>
    conditional(url).then(
      (d) => {
        pace.ok();
        return d;
      },
      (err) => {
        pace.fail(err);
        throw err;
      },
    );

  // --- status -------------------------------------------------------------------------
  function paintStatus(s, sentinels) {
    const pill = $("ov-pill");
    pill.className = `ov-pill ${pillClass(s.tone)}`;
    $("ov-pill-text").textContent = s.pill;
    $("status-h").textContent = s.headline;
    const sub = $("status-sub");
    sub.textContent = s.sub || "";
    sub.hidden = !s.sub;
    const line = sentinelText(sentinels);
    const box = $("ov-sentinels");
    box.hidden = !line;
    if (line) {
      $("ov-sentinels-text").textContent = line;
      box.classList.toggle("off", !(sentinels.live > 0));
    }
  }

  // --- tiles --------------------------------------------------------------------------
  function paintKpis(kpis) {
    const wrap = $("ov-kpis");
    kpis.forEach((k) => {
      const tile = wrap.querySelector(`[data-kpi="${k.key}"]`);
      if (!tile) return;
      const href = kpiHref(k.key, slug);
      if (href) tile.setAttribute("href", href);
      const value = tile.querySelector(".ov-kpi-value");
      value.textContent = k.value_text;
      if (k.unit && k.value != null) value.append(el("small", "", ` ${k.unit}`));
      const spark = tile.querySelector(".ov-spark");
      spark.textContent = "";
      const pts = sparkPoints(k.series);
      if (k.series.length > 1 && pts) {
        spark.setAttribute("aria-label", sparkLabel(k.label, k.series));
        spark.append(svg("polyline", { points: pts, fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linejoin": "round", "stroke-linecap": "round" }));
        spark.hidden = false;
      } else {
        spark.hidden = true;
      }
      const delta = tile.querySelector(".ov-delta");
      delta.textContent = k.delta_text || "";
      delta.className = `ov-delta ${toneClass(k.tone)}`;
      tile.querySelector(".ov-foot").textContent = (k.foot ? ` ${k.foot}` : "");
      tile.title = k.as_of ? `As of ${k.as_of}` : "";
      tile.setAttribute("aria-busy", "false");
    });
  }

  // --- threats ------------------------------------------------------------------------
  function badge(b) {
    return el("span", `ov-badge ${b.kind || ""}`, b.text);
  }
  function threatCard(g) {
    const art = el("article", "ov-threat");
    const main = el("div", "ov-threat-main");
    const badges = el("div", "ov-badges");
    badges.append(el("span", "ov-badge reach", g.matched ? "Reaches your hosts" : "May reach your hosts"));
    (g.badges || []).forEach((b) => badges.append(badge(b)));
    main.append(badges, el("h3", "", g.title));
    if (g.summary) main.append(el("p", "ov-threat-text", g.summary));
    if (g.fix) {
      const p = el("p", "ov-fix-line");
      p.append(el("strong", "", "Fix:"), ` ${g.fix}`);
      main.append(p);
    }
    if (g.cve_ids && g.cve_ids.length) main.append(el("p", "ov-cves", g.cve_ids.join(" · ")));
    const side = el("div", "ov-impact");
    const panel = impactPanel(g);
    if (panel.matched) {
      const d = el("div", "ov-impact-row");
      d.append(el("span", "ov-impact-big hot", panel.matched.big), el("span", "ov-impact-text", panel.matched.text));
      side.append(d);
    }
    if (panel.unknown) {
      const d = el("div", "ov-impact-row");
      d.append(el("span", `ov-impact-big${panel.matched ? " small" : " hot"}`, panel.unknown.big), el("span", "ov-impact-text", panel.unknown.text));
      side.append(d);
    }
    const actions = el("div", "ov-actions-row");
    const hosts = hostsHref(slug, g);
    const n = g.matched || g.product_only;
    if (hosts && n) actions.append(el("a", "btn sm", seeHostsText(n), { href: hosts }));
    const link = readLink(g);
    if (link) actions.append(el("a", "btn ghost sm", link.label, link.external ? { href: link.href, rel: "noopener noreferrer", target: "_blank" } : { href: link.href }));
    side.append(actions);
    art.append(main, side);
    return art;
  }
  function paintThreats(t) {
    const body = $("threats-body");
    const open = body.querySelector("details.ov-folded")?.open === true;
    body.textContent = "";
    $("threats-period").textContent = t.period ? `${t.period} · CISA KEV, new critical CVEs with an exploit${t.note && /Zero Wire/.test(t.note) ? ", Cloudflare Zero Wire" : ""}` : "";
    if (t.failed) {
      body.append(el("p", "ov-empty", "This week's threats could not be read just now. They will be tried again."));
      return;
    }
    t.groups.forEach((g) => body.append(threatCard(g)));
    if (t.folded.length) {
      const d = el("details", "ov-folded");
      d.open = open;
      const sum = el("summary");
      sum.append(el("span", "ov-chev", null, { "aria-hidden": "true" }), el("span", "ov-folded-title", foldedTitle(t.folded.length)));
      if (t.folded_note) sum.append(el("span", "ov-folded-note", t.folded_note));
      const ul = el("ul");
      t.folded.forEach((f) => {
        const li = el("li");
        const what = el("span", "ov-folded-what");
        what.append(el("strong", "", f.product || "Unknown product"), f.title ? ` ${f.title}` : "");
        li.append(what, el("span", "ov-folded-detail", f.detail));
        ul.append(li);
      });
      d.append(sum, ul);
      const wrap = el("div", "ov-folded-wrap");
      wrap.append(d);
      body.append(wrap);
    }
    if (!t.groups.length && !t.folded.length) body.append(el("p", "ov-empty", t.empty || "No new KEV or critical CVEs this week."));
    if (t.note && (t.groups.length || t.folded.length)) body.append(el("p", "ov-note", t.note));
  }

  // --- fix first ----------------------------------------------------------------------
  const CHIP = { proven: "proven", likely: "likely", hygiene: "hygiene", exposure: "exposure", minor: "minor" };
  function fixRow(r) {
    const li = el("li", "ov-fix-row");
    li.append(el("span", "ov-rank", String(r.rank), { "aria-hidden": "true" }));
    const mid = el("div", "ov-fix-mid");
    const head = el("div", "ov-fix-head");
    const href = rowHref(r.link);
    head.append(href ? el("a", "ov-fix-host", r.title, { href }) : el("span", "ov-fix-host", r.title));
    head.append(el("span", `ov-chip ${CHIP[r.lead] || ""}`, r.chip));
    if (all && r.project_name) head.append(el("span", "ov-fix-project", r.project_name));
    if (r.internal) head.append(el("span", "ov-fix-project", "internal"));
    mid.append(head, el("span", "ov-fix-reason", r.reason));
    li.append(mid);
    if (href) li.append(el("a", "btn ghost sm ov-fix-action", r.action, { href }));
    return li;
  }
  function paintFix(f) {
    const list = $("fix-list");
    const link = $("fix-all");
    list.textContent = "";
    $("fix-empty").hidden = true;
    link.hidden = !f.total;
    if (f.total) {
      link.textContent = allHostsText(f.total);
    }
    f.rows.forEach((r) => list.append(fixRow(r)));
    list.hidden = !f.rows.length;
    if (!f.rows.length) {
      const empty = $("fix-empty");
      empty.hidden = false;
      empty.textContent = f.state === "unscanned" ? "Nothing has been scanned yet, so there is nothing to fix. Add a target to start a first look." : "Nothing needs fixing right now.";
    }
  }

  // --- what changed -------------------------------------------------------------------
  function paintChanged(c) {
    const list = $("changed-list");
    list.textContent = "";
    c.lines.forEach((l) => {
      const li = el("li", "ov-changed-row");
      li.append(el("span", `ov-changed-n ${toneClass(l.tone)}`, l.value));
      const t = el("span", "ov-changed-text");
      t.append(el("strong", "", l.title), document.createElement("br"), l.detail);
      li.append(t);
      list.append(li);
    });
    const href = changesHref(slug, c.since);
    const link = $("changed-all");
    if (href) link.setAttribute("href", href);
  }

  // --- the poll -----------------------------------------------------------------------
  let drawn = false;
  async function poll() {
    try {
      const s = await get(`/cve/api/overview${slug ? `?project=${encodeURIComponent(slug)}` : ""}`);
      $("ov-updated").textContent = `Updated ${fmtTime(new Date().toISOString(), false)}`; // a 304 is a look that found the same: it is as fresh
      if (s === null) return;
      root.setAttribute("aria-busy", "false");
      paintStatus(s.status, s.sentinels);
      paintKpis(s.kpis);
      paintThreats(s.threats);
      paintFix(s.fix_first);
      paintChanged(s.what_changed);
      drawn = true;
    } catch (_) {
      if (!drawn) $("status-h").textContent = "The overview could not be read just now.";
    }
  }
  every(poll, 6000, { pace });
}
