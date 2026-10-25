// Bug bounty: programs and scope from the platforms' public data, your own targets matched against them, engagements with a recorded
// policy acknowledgement, and reports drafted from scanner findings, checked, and tracked. Every value from the server is shown with
// textContent; every link has to be https. The server decides who may use this page and what each action may do.
import { ask, api, badge, button, dialog, el, field, selectOf, shortDate, table, tabs, text, toast } from "/staticfiles/cve/ui.js";

const API = "/cve/api/bounty";
const root = document.getElementById("view");
const holder = document.getElementById("bounty");
const project = holder.dataset.project || "";
let current = root;

const PLATFORMS = { hackerone: "HackerOne", bugcrowd: "Bugcrowd", intigriti: "Intigriti", yeswehack: "YesWeHack" };
const SCOPE_BADGE = { in_scope: "success", out_of_scope: "critical", ambiguous: "medium", not_listed: "info" };
const SCOPE_LABEL = { in_scope: "in scope", out_of_scope: "out of scope", ambiguous: "unclear", not_listed: "not listed" };
const STATUS_BADGE = { draft: "info", ready: "low", submitted: "running", triaged: "medium", needs_info: "high", resolved: "success", duplicate: "info", informative: "info", not_applicable: "info", spam: "critical", closed: "info" };
const STATUS_LABEL = { needs_info: "needs info", not_applicable: "not applicable" };
const CHANGE_LABEL = { program_added: "program added", program_removed: "program removed", asset_added: "scope added", asset_removed: "scope removed", asset_flipped: "scope moved" };
const SEVERITIES = [["", "Choose"], ["none", "None"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"]];
const STATUSES = (s) => STATUS_LABEL[s] || s;

const url = (path, params = {}) => {
  const q = new URLSearchParams();
  Object.entries({ project, ...params }).forEach(([k, v]) => { if (v !== "" && v != null && !(k === "project" && !v)) q.set(k, v); });
  const s = q.toString();
  return `${API}/${path}${s ? `?${s}` : ""}`;
};
const get = (path, params) => api("GET", url(path, params));
const send = (method, path, body = {}) => api(method, `${API}/${path}`, { project, ...body });
const safeHref = (u) => (typeof u === "string" && /^https:\/\//i.test(u) ? u : "");
const link = (label, href) => {
  const ok = safeHref(href);
  if (!ok) return el("span", "", label);
  return Object.assign(el("a", "", label), { href: ok, target: "_blank", rel: "noopener noreferrer" });
};
const pre = (value) => el("pre", "bb-pre", value);
const para = (value, cls = "note") => el("p", cls, value);
const card = (title, ...kids) => { const c = el("section", "card"); if (title) c.append(el("h2", "", title)); c.append(...kids); return c; };
const row = (...kids) => { const r = el("div", "tools"); r.append(...kids); return r; };
const money = (p) => {
  if (p.offers_bounties === false) return "no bounty";
  const cur = p.currency || (p.platform === "hackerone" ? "" : "USD");
  if (p.max_bounty == null) return p.offers_bounties ? "pays" : "unknown";
  const fmt = (n) => n.toLocaleString("en-US");
  return `${p.min_bounty ? `${fmt(p.min_bounty)} to ` : "up to "}${fmt(p.max_bounty)}${cur ? ` ${cur}` : ""}`;
};
const hours = (h) => (h == null ? "" : h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} d`);
const loading = (panel) => { panel.textContent = ""; panel.append(el("div", "skeleton"), el("div", "skeleton")); };
async function copy(value, what = "Copied") { try { await navigator.clipboard.writeText(value); toast(what); } catch (_) { toast("Copy failed: select the text and copy it by hand", true); } }
const needProject = (panel) => { if (project) return false; panel.append(para("There is no project yet. Add one, then come back.", "msg busy")); return true; };

function platformBadge(p) { return badge(PLATFORMS[p] || p, "info"); }
function scopeBadge(state) { return badge(SCOPE_LABEL[state] || state, SCOPE_BADGE[state] || "info"); }
function pager(shown, total, more) {
  const w = el("div", "more-row");
  if (shown < total) w.append(button(`Show more (${shown} of ${total})`, more, "btn ghost"));
  else if (total) w.append(para(`${total} shown`));
  return w;
}

// ------------------------------------------------------------------------------ overview
async function overviewTab(panel) {
  loading(panel);
  const [status, stats] = await Promise.all([get("status"), project ? get("stats") : Promise.resolve(null)]);
  panel.textContent = "";
  const loaded = status.catalogue.some((c) => c.loaded);

  const cat = card("Program catalogue");
  cat.append(para(`Public scope data for ${Object.values(PLATFORMS).join(", ")}, from ${status.source}. It is read from raw.githubusercontent.com; nothing about you or your targets is sent.`));
  const t = table(
    [
      { label: "Platform", render: (c) => c.label },
      { label: "Programs", render: (c) => (c.loaded ? c.programs : "not loaded") },
      { label: "Scope entries", render: (c) => (c.loaded ? c.assets : "") },
      { label: "Last change", render: (c) => (c.changed ? shortDate(c.changed) : "") },
      { label: "Status", render: (c) => (c.error ? badge("error", "critical") : c.loaded ? badge("ok", "success") : badge("waiting", "info")) },
    ],
    status.catalogue,
  );
  cat.append(t);
  status.catalogue.filter((c) => c.error).forEach((c) => cat.append(para(`${c.label}: ${c.error}`, "msg err")));
  cat.append(row(button(loaded ? "Refresh now" : "Load the catalogue", async () => {
    await api("POST", `${API}/catalogue/refresh`, {});
    toast("Loading. This takes under a minute; reload the page after.");
  }, "btn sm"), para(loaded ? "It refreshes by itself every hour." : "Loading it once also turns on the hourly refresh.")));
  panel.append(cat);

  if (stats) {
    const tiles = el("div", "bb-grid");
    const tile = (label, value, hint) => { const c = el("div", "card bb-tile"); c.append(el("div", "bb-n", String(value)), el("div", "bb-l", label)); if (hint) c.append(para(hint)); return c; };
    const r = stats.reports;
    const open = (r.submitted || 0) + (r.triaged || 0) + (r.needs_info || 0);
    tiles.append(
      tile("Drafts", (r.draft || 0) + (r.ready || 0), "not sent yet"),
      tile("Open at programs", open, "submitted, triaged or needs info"),
      tile("Resolved", r.resolved || 0),
      tile("Engagements", Object.values(stats.engagements).reduce((a, b) => a + b, 0), `${stats.engagements.active || 0} active`),
    );
    stats.paid.forEach((p) => tiles.append(tile(`Paid ${p.currency}`.trim(), p.total, `${p.count} report${p.count === 1 ? "" : "s"}`)));
    panel.append(tiles);
    const attn = [];
    stats.scope_changed.forEach((s) => attn.push(`${s.program}: the scope changed after you read its policy. Read it again.`));
    stats.stale.forEach((s) => attn.push(`Report ${s.id} (${s.title}): ${s.why} (${s.days} days).`));
    if (attn.length) { const c = card("Needs attention"); attn.forEach((a) => c.append(para(a, "msg busy"))); panel.append(c); }
  }
  if (!loaded) panel.append(card("Start here", para("1. Load the catalogue above. 2. Programs: find one that pays and lists scope you can test. 3. Work it: read the policy, record that you did, import the scope as targets. 4. Reports: draft from a finding, fix what the checks flag, send. The Playbook tab says why each step is there, with sources.")));
}

// ------------------------------------------------------------------------------ programs
function programFilters(state, onChange) {
  const q = text(state.q || "", { type: "search", placeholder: "Search name, handle or domain" });
  const plat = selectOf([["", "All platforms"], ...Object.entries(PLATFORMS)], state.platform || "");
  const pays = selectOf([["", "Any reward"], ["1", "Pays a bounty"]], state.bounty || "");
  const harbor = selectOf([["", "Any safe harbor"], ["full", "Full safe harbor (Bugcrowd data only)"], ["any", "Full or partial (Bugcrowd data only)"]], state.harbor || "");
  const fresh = selectOf([["", "Any age"], ["7", "New in 7 days"], ["30", "New in 30 days"]], state.new_days || "");
  const moved = selectOf([["", "Any scope change"], ["7", "Scope changed in 7 days"], ["30", "Scope changed in 30 days"]], state.scope_days || "");
  const sort = selectOf([["changed", "Latest scope change"], ["payout", "Highest payout"], ["scope", "Largest scope"], ["response", "Fastest first response"], ["name", "Name"]], state.sort || "changed");
  const go = () => onChange({ q: q.value.trim(), platform: plat.value, bounty: pays.value, harbor: harbor.value === "any" ? "partial" : harbor.value, new_days: fresh.value, scope_days: moved.value, sort: sort.value });
  [plat, pays, harbor, fresh, moved, sort].forEach((s) => s.addEventListener("change", go));
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  const bar = el("div", "tools");
  bar.append(q, plat, pays, harbor, fresh, moved, sort, button("Search", async () => go(), "btn sm"));
  return bar;
}

async function programsTab(panel) {
  const state = {};
  const list = el("div");
  let all = [];
  async function load(reset) {
    if (reset) { all = []; list.textContent = ""; }
    const res = await get("programs", { ...state, page: Math.floor(all.length / 25) + 1 });
    all = all.concat(res.results);
    list.textContent = "";
    if (!res.count) { list.append(para("No program matches. If the catalogue is empty, load it on the Overview tab.", "msg busy")); return; }
    list.append(table(programColumns(), all), pager(all.length, res.count, () => load(false)));
  }
  panel.append(programFilters(state, (v) => { Object.assign(state, v); load(true); }), list);
  await load(true);
}

function programColumns() {
  return [
    { label: "Program", cls: "full", render: (p) => { const d = el("div", "row-card"); d.append(el("span", "cve-id", p.name), el("span", "note", `${PLATFORMS[p.platform] || p.platform} · ${p.handle}`)); return d; } },
    { label: "Reward", render: (p) => money(p) },
    { label: "Safe harbor", render: (p) => (p.safe_harbor ? badge(p.safe_harbor, p.safe_harbor === "full" ? "success" : "medium") : "") },
    { label: "In scope", render: (p) => `${p.in_scope}${p.bounty_scope ? ` (${p.bounty_scope} pay)` : ""}` },
    { label: "First response", render: (p) => hours(p.first_response_hours) },
    { label: "Scope changed", render: (p) => (p.scope_changed ? shortDate(p.scope_changed) : "") },
    { label: "", render: (p) => button(p.engaged ? "Open (working)" : "Open", async () => openProgram(p.id), "btn ghost sm") },
  ];
}

async function openProgram(id) {
  const p = await get(`programs/${id}`);
  dialog(p.name, (body, close) => {
    body.append(para(`${PLATFORMS[p.platform] || p.platform} · ${p.handle}`));
    const facts = el("dl", "node-rows");
    [["Reward", money(p)], ["Safe harbor", p.safe_harbor || (p.platform === "bugcrowd" ? "none listed" : "not in this platform's data: read the policy")], ["State", p.state], ["Managed by the platform", p.managed ? "yes" : ""],
      ["Reports answered", p.response_efficiency != null ? `${p.response_efficiency}%` : ""], ["Average first response", hours(p.first_response_hours)],
      ["Average time to resolve", hours(p.resolved_hours)], ["In scope", `${p.in_scope} entries, ${p.bounty_scope} eligible for a bounty`], ["Scope last changed", p.scope_changed ? shortDate(p.scope_changed) : ""]]
      .filter(([, v]) => v !== "" && v != null).forEach(([k, v]) => facts.append(el("dt", "", k), el("dd", "", String(v))));
    body.append(facts);
    if (safeHref(p.url)) body.append(row(link("Read the program's policy on the platform", p.url)));
    body.append(para("The policy on the platform is the authority. This list is a copy of public data and can lag it."));
    const acts = row();
    if (project) {
      acts.append(p.engagement
        ? para(`Working it: ${p.engagement.status}${p.engagement.policy_ack_at ? ", policy read" : ", policy not read yet"}. See the Engagements tab.`)
        : button("Work this program", async () => { await send("POST", "engagements", { program_id: p.id }); toast("Added to Engagements"); close(); }, "btn sm"));
    }
    body.append(acts);
    const host = text("", { placeholder: "host, URL or IP to check against this scope" });
    const res = el("div");
    body.append(field("Is it in scope?", host), button("Check", async () => {
      const r = await api("POST", `${API}/scope-check`, { program_id: p.id, host: host.value });
      res.textContent = "";
      r.results.forEach((x) => { const l = row(scopeBadge(x.state), para(`${x.host}: ${x.reason}`)); res.append(l); });
    }, "btn ghost sm"), res);
    const ins = p.assets.filter((a) => a.in_scope), outs = p.assets.filter((a) => !a.in_scope);
    const assetTable = (rows) => table([
      { label: "Entry", cls: "full", render: (a) => { const d = el("div", "row-card"); d.append(el("span", "mono", a.identifier)); if (a.instruction) d.append(el("span", "note", a.instruction.slice(0, 200))); return d; } },
      { label: "Kind", render: (a) => a.kind }, { label: "Pays", render: (a) => (a.eligible_for_bounty === true ? "yes" : a.eligible_for_bounty === false ? "no" : "") },
      { label: "Max severity", render: (a) => a.max_severity },
    ], rows);
    body.append(el("h2", "", `In scope (${ins.length})`, { style: "margin-top:18px" }), ins.length ? assetTable(ins) : para("none listed"));
    body.append(el("h2", "", `Out of scope (${outs.length})`, { style: "margin-top:18px" }), outs.length ? assetTable(outs) : para("none listed"));
    if (p.assets_truncated) body.append(para("The list was cut at 3000 entries; open the policy for the rest."));
    if (p.changes.length) body.append(el("h2", "", "Recent changes", { style: "margin-top:18px" }), table([
      { label: "When", render: (c) => shortDate(c.at) }, { label: "Change", render: (c) => CHANGE_LABEL[c.kind] || c.kind }, { label: "Entry", render: (c) => c.identifier }], p.changes));
    body.append(row(button("Close", async () => close(), "btn ghost")));
  });
}

// ------------------------------------------------------------------------------ scope changes and your targets
async function changesTab(panel) {
  const state = { days: "7" };
  const list = el("div");
  const days = selectOf([["1", "Last day"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]], "7");
  const kind = selectOf([["", "All changes"], ["asset_added", "Scope added"], ["asset_flipped", "Scope moved"], ["asset_removed", "Scope removed"], ["program_added", "New programs"], ["program_removed", "Programs removed"]], "");
  const plat = selectOf([["", "All platforms"], ...Object.entries(PLATFORMS)], "");
  const pays = selectOf([["", "Any reward"], ["1", "Pays a bounty"]], "");
  const mine = selectOf([["", "All programs"], ["1", "Only programs I work"]], "");
  async function load() {
    loading(list);
    const r = await get("changes", { days: days.value, kind: kind.value, platform: plat.value, bounty: pays.value, mine: mine.value, in_scope: kind.value === "asset_added" ? "1" : "" });
    list.textContent = "";
    if (!r.count) { list.append(para("No changes in this window. The first load records the starting state; changes show from the next refresh on.", "msg busy")); return; }
    list.append(table([
      { label: "When", render: (c) => shortDate(c.at) }, { label: "Change", render: (c) => badge(CHANGE_LABEL[c.kind] || c.kind, c.kind === "asset_added" || c.kind === "program_added" ? "success" : c.kind === "asset_removed" || c.kind === "program_removed" ? "info" : "medium") },
      { label: "Entry", cls: "full", render: (c) => { const d = el("div", "row-card"); d.append(el("span", "mono", c.identifier || c.program.name), el("span", "note", `${c.in_scope ? "in scope" : "out of scope"}${c.asset_kind ? ` · ${c.asset_kind}` : ""}`)); return d; } },
      { label: "Program", render: (c) => c.program.name }, { label: "Reward", render: (c) => money(c.program) },
      { label: "", render: (c) => button("Open", async () => openProgram(c.program.id), "btn ghost sm") }], r.results));
    if (r.count > r.results.length) list.append(para(`Showing the first ${r.results.length} of ${r.count}. Narrow the filters to see the rest.`));
  }
  [days, kind, plat, pays, mine].forEach((s) => s.addEventListener("change", load));
  panel.append(para("What changed in programs' scope since the catalogue was first loaded. New scope has had the least testing."), row(days, kind, plat, pays, mine), list);
  await load();
}

async function matchesTab(panel) {
  if (needProject(panel)) return;
  loading(panel);
  const r = await get("matches");
  panel.textContent = "";
  panel.append(para(`Programs that list a domain you already track in this project. ${r.targets_checked} domain target${r.targets_checked === 1 ? "" : "s"} checked; IP targets are not matched here.`));
  if (!r.results.length) { panel.append(para("No program names your targets. Importing a program's scope is the other way round: see Engagements.", "msg busy")); return; }
  panel.append(table([
    { label: "Program", cls: "full", render: (m) => { const d = el("div", "row-card"); d.append(el("span", "cve-id", m.program.name), el("span", "note", `${PLATFORMS[m.program.platform]} · ${money(m.program)}`)); return d; } },
    { label: "Your targets", cls: "full", render: (m) => { const d = el("div", "row-card"); m.targets.slice(0, 6).forEach((t) => d.append(row(scopeBadge(t.state), para(`${t.target}: ${t.reason}`)))); if (m.count > 6) d.append(para(`and ${m.count - 6} more`)); return d; } },
    { label: "", render: (m) => button("Open", async () => openProgram(m.program.id), "btn ghost sm") }], r.results));
}

// ------------------------------------------------------------------------------ engagements
async function engagementsTab(panel) {
  if (needProject(panel)) return;
  loading(panel);
  const r = await get("engagements");
  panel.textContent = "";
  panel.append(para("A program you decided to work. Read its policy, record that you did, then import its scope. Nothing is scanned until you confirm the policy allows automated tools."));
  if (!r.results.length) { panel.append(para("None yet. Open a program and choose Work this program.", "msg busy")); return; }
  r.results.forEach((e) => panel.append(engagementCard(e, () => engagementsTab(reset(panel)))));
}
const reset = (panel) => { panel.textContent = ""; return panel; };

function engagementCard(e, done) {
  const c = el("section", "card", null, { style: "margin-bottom:14px" });
  const head = el("div", "tools");
  head.append(el("h2", "", e.program.name, { style: "margin:0;flex:1" }), platformBadge(e.program.platform), badge(e.status, e.status === "active" ? "success" : "info"));
  c.append(head);
  c.append(para(`${money(e.program)} · ${e.program.in_scope} in scope · ${e.targets} imported target${e.targets === 1 ? "" : "s"} · ${e.reports} report${e.reports === 1 ? "" : "s"}`));
  const policy = e.policy_ack_at ? (e.scope_changed_since_ack ? badge("scope changed since you read it", "high") : badge(`policy read ${shortDate(e.policy_ack_at)} by ${e.policy_ack_by || "someone"}`, "success")) : badge("policy not read", "medium");
  c.append(row(policy, safeHref(e.policy_url) ? link("Open the policy", e.policy_url) : el("span")));
  const acts = row();
  acts.append(button(e.policy_ack_at && !e.scope_changed_since_ack ? "I read it again" : "I read the policy", async () => {
    if (!(await ask("This records that you read the program's policy and that testing the listed scope is allowed under it. It is kept in the audit log.", { title: `Policy of ${e.program.name}`, ok: "I read it", danger: false }))) return;
    await send("PATCH", `engagements/${e.id}`, { acknowledge: true }); done();
  }, "btn ghost sm"));
  const auto = el("input", "", null, { type: "checkbox" });
  auto.checked = e.automated_ok; auto.disabled = !e.policy_ack_at;
  auto.addEventListener("change", async () => { try { await send("PATCH", `engagements/${e.id}`, { automated_ok: auto.checked }); toast("Saved"); } catch (err) { auto.checked = !auto.checked; toast(err.message, true); } });
  const lab = el("label", "note"); lab.style.cssText = "display:flex;gap:8px;align-items:center";
  lab.append(auto, document.createTextNode("The policy allows automated scanning (starts discovery when I import)"));
  c.append(acts, lab);
  const status = selectOf([["watching", "Watching"], ["active", "Active"], ["paused", "Paused"], ["done", "Done"]], e.status);
  status.addEventListener("change", async () => { try { await send("PATCH", `engagements/${e.id}`, { status: status.value }); done(); } catch (err) { toast(err.message, true); status.value = e.status; } });
  const notes = el("textarea", "", null, { rows: "3", maxlength: "20000", placeholder: "Notes: accounts, rules, ideas" });
  notes.value = e.notes;
  c.append(field("Status", status), field("Notes", notes));
  const more = row(
    button("Save notes", async () => { await send("PATCH", `engagements/${e.id}`, { notes: notes.value }); toast("Saved"); }, "btn ghost sm"),
    button("Import scope as targets", async () => importDialog(e, done), "btn sm"),
    button("New report", async () => newReportDialog(e, null), "btn ghost sm"),
    button("Remove", async () => { if (!(await ask("The engagement and its notes are deleted. Imported targets stay.", { title: "Remove this engagement?", ok: "Remove" }))) return; await api("DELETE", url(`engagements/${e.id}`)); done(); }, "btn ghost sm"),
  );
  c.append(more);
  return c;
}

async function importDialog(e, done) {
  const plan = await api("POST", `${API}/engagements/${e.id}/import`, { project, dry_run: true });
  dialog(`Import the scope of ${e.program.name}`, (body, close) => {
    body.append(para(`${plan.total} target${plan.total === 1 ? "" : "s"} can be imported. Wildcards become their base domain; a URL becomes its host. ${plan.discovery ? "Discovery will start for new targets, because you confirmed the policy allows automated scanning." : "Discovery will NOT start: you have not confirmed the policy allows automated scanning. Targets are only added."}`));
    if (!e.policy_ack_at) { body.append(para("Record that you read the policy first.", "msg err")); body.append(button("Close", async () => close(), "btn ghost")); return; }
    const boxes = [];
    const list = el("div", "bb-scroll");
    plan.targets.forEach((t) => {
      const cb = el("input", "", null, { type: "checkbox" }); cb.checked = true; boxes.push([cb, t.value]);
      const l = el("label", "note"); l.style.cssText = "display:flex;gap:8px;align-items:center;padding:3px 0"; l.append(cb, el("span", "mono", t.value));
      if (t.note) l.append(el("span", "note", ` ${t.note}`)); list.append(l);
    });
    body.append(list);
    if (plan.skipped.length) {
      body.append(el("h2", "", `Not imported (${plan.skipped.length})`, { style: "margin-top:14px" }));
      body.append(table([{ label: "Entry", render: (s) => s.asset }, { label: "Why", render: (s) => s.reason }], plan.skipped.slice(0, 50)));
    }
    body.append(row(button("Import selected", async () => {
      const values = boxes.filter(([cb]) => cb.checked).map(([, v]) => v);
      const r = await api("POST", `${API}/engagements/${e.id}/import`, { project, dry_run: false, values });
      toast(`${r.created} added, ${r.already_exists} already there${r.discovery_started ? ", discovery started" : ""}`);
      close(); done();
    }), button("Cancel", async () => close(), "btn ghost")));
  });
}

// ------------------------------------------------------------------------------ reports
async function reportsTab(panel) {
  if (needProject(panel)) return;
  loading(panel);
  const r = await get("reports");
  panel.textContent = "";
  panel.append(row(button("New report from a finding", async () => newReportDialog(null, null), "btn sm"), button("Blank report", async () => newReportDialog(null, "blank"), "btn ghost sm")));
  if (!r.results.length) { panel.append(para("No reports yet. Start from a scanner finding: the draft carries the request and leaves the impact for you.", "msg busy")); return; }
  panel.append(table([
    { label: "Report", cls: "full", render: (x) => { const d = el("div", "row-card"); d.append(el("span", "cve-id", x.title || "(untitled)"), el("span", "note", `${x.program || "no program"} · ${x.asset || ""}`)); return d; } },
    { label: "Status", render: (x) => badge(STATUSES(x.status), STATUS_BADGE[x.status] || "info") },
    { label: "Severity", render: (x) => (x.severity ? badge(x.severity, x.severity === "none" ? "info" : x.severity) : "") },
    { label: "Bounty", render: (x) => (x.bounty_amount ? `${x.bounty_amount} ${x.bounty_currency}` : "") },
    { label: "Updated", render: (x) => shortDate(x.updated) },
    { label: "", render: (x) => button("Open", async () => openReport(panel, x.id), "btn ghost sm") }], r.results));
}

async function newReportDialog(engagement, mode) {
  const eng = engagement ? [engagement] : (await get("engagements")).results;
  dialog("New report", (body, close) => {
    const sel = selectOf([["", "No program yet"], ...eng.map((e) => [String(e.id), `${e.program.name} (${PLATFORMS[e.program.platform]})`])], engagement ? String(engagement.id) : "");
    body.append(field("Program", sel, "The scope check and the platform's fields depend on it. You can start without one."));
    const create = async (vuln) => {
      const payload = { engagement_id: sel.value ? Number(sel.value) : undefined, ...(vuln ? { vulnerability_id: vuln } : {}) };
      const r = await api("POST", `${API}/reports`, { project, ...payload });
      close(); openReport(current, r.id, r);
    };
    if (mode === "blank") { body.append(button("Create the draft", async () => create(null))); return; }
    const q = text("", { type: "search", placeholder: "Search findings by name, URL or host" });
    const list = el("div");
    async function load() {
      loading(list);
      const r = await get("findings", { q: q.value.trim() });
      list.textContent = "";
      if (!r.count) { list.append(para("No findings match. Scanner findings of severity low and up appear here.", "msg busy")); return; }
      list.append(table([
        { label: "Finding", cls: "full", render: (f) => { const d = el("div", "row-card"); d.append(el("span", "cve-id", f.name), el("span", "note", `${f.host || ""} ${f.url || ""}`.trim().slice(0, 160))); return d; } },
        { label: "Severity", render: (f) => badge(f.severity, f.severity) }, { label: "Drafts", render: (f) => (f.reports.length ? `#${f.reports.join(", #")}` : "") },
        { label: "", render: (f) => button("Draft", async () => create(f.id), "btn ghost sm") }], r.results));
    }
    q.addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
    body.append(field("Finding", q), list);
    load();
  });
}

const FIELDS = [["title", "Title", "input", "Bug class, where it is, what it allows"], ["asset", "Affected asset", "input", "host name"], ["location_url", "URL or location", "input", ""],
  ["summary", "Summary", "textarea", "One short paragraph"], ["steps", "Steps to reproduce", "textarea", "Numbered, with URLs, parameters and the role needed"],
  ["impact", "Impact", "textarea", "What an attacker gains, against whom, and what it takes"], ["remediation", "Suggested fix", "textarea", "Optional"], ["references", "References", "textarea", "One address per line"]];

async function openReport(panel, id, known) {
  const r = known || (await get(`reports/${id}`));
  panel.textContent = "";
  const locked = !["draft", "ready"].includes(r.status);
  const back = button("Back to reports", async () => reportsTab(reset(panel)), "btn ghost sm");
  panel.append(row(back, badge(STATUSES(r.status), STATUS_BADGE[r.status] || "info"), el("span", "note", r.program || "no program"), r.platform_url ? link("Open on the platform", r.platform_url) : el("span")));
  r.warnings.forEach((w) => panel.append(para(w, "msg busy")));

  const form = el("div", "bb-ed");
  const inputs = {};
  FIELDS.forEach(([key, label, kind, help]) => {
    const i = kind === "textarea" ? el("textarea", "", null, { rows: key === "steps" ? "10" : "5", maxlength: "40000" }) : el("input", "", null, { maxlength: "500" });
    i.value = r[key] || ""; i.disabled = locked; inputs[key] = i;
    form.append(field(label, i, help));
  });
  const sev = selectOf(SEVERITIES, r.severity || ""); sev.disabled = locked;
  const cvss = text(r.cvss_score == null ? "" : String(r.cvss_score), { placeholder: "0 to 10", inputmode: "decimal" }); cvss.disabled = locked;
  const cvssV = text(r.cvss_vector || "", { placeholder: "CVSS vector" }); cvssV.disabled = locked;
  const cwe = text(r.cwe || "", { placeholder: "CWE-79" }); cwe.disabled = locked;
  form.append(field("Severity", sev), field("CVSS score", cvss), field("CVSS vector", cvssV), field("Weakness (CWE)", cwe));

  const vrtBox = el("div"); let vrtId = r.vrt || "";
  const vrtShow = para(r.vrt_label ? `${r.vrt_label.label}${r.vrt_label.priority ? ` (priority ${r.vrt_label.priority})` : ""}` : "No category chosen.");
  const vrtQ = text("", { type: "search", placeholder: "Search the Bugcrowd taxonomy (sql, xss, takeover...)" }); vrtQ.disabled = locked;
  const vrtRes = el("div");
  const setVrt = (v) => { vrtId = v.id; vrtShow.textContent = `${v.label}${v.priority ? ` (priority ${v.priority})` : ""}`; vrtRes.textContent = ""; };
  vrtQ.addEventListener("input", async () => {
    if (vrtQ.value.trim().length < 2) { vrtRes.textContent = ""; return; }
    const t = await get("taxonomy", { q: vrtQ.value.trim() });
    vrtRes.textContent = "";
    t.results.slice(0, 12).forEach((v) => vrtRes.append(button(`${v.label}${v.priority ? ` · P${v.priority}` : ""}`, async () => setVrt(v), "btn ghost sm")));
  });
  vrtBox.append(vrtShow, vrtQ, vrtRes);
  form.append(field("Bugcrowd category (VRT)", vrtBox, "Bugcrowd's Vulnerability Rating Taxonomy. Priority 1 is the most severe, 5 the least. Optional on HackerOne."));
  panel.append(form);

  const list = el("div"); const checks = {};
  r.checklist_items.forEach((c) => { const cb = el("input", "", null, { type: "checkbox" }); cb.checked = !!(r.checklist || {})[c.key]; cb.disabled = locked; checks[c.key] = cb;
    const l = el("label", "note"); l.style.cssText = "display:flex;gap:8px;align-items:flex-start;padding:4px 0"; l.append(cb, document.createTextNode(c.label)); list.append(l); });
  panel.append(card("Before it goes out", list));

  const body = () => ({ ...Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value])), severity: sev.value, cvss_score: cvss.value, cvss_vector: cvssV.value, cwe: cwe.value, vrt: vrtId,
    checklist: Object.fromEntries(Object.entries(checks).map(([k, cb]) => [k, cb.checked])) });
  const save = async () => { const x = await send("PATCH", `reports/${r.id}`, body()); toast("Saved"); return x; };

  const cc = card("Checks");
  const sc = r.scope ? row(scopeBadge(r.scope.state), para(r.scope.reason)) : para("No program chosen, so scope is not checked.");
  cc.append(sc);
  r.checks.forEach((c) => cc.append(row(badge(c.level === "block" ? "blocks" : c.level, c.level === "block" ? "critical" : c.level === "warn" ? "medium" : "info"), para(c.message))));
  if (!r.checks.length) cc.append(para("Nothing to fix.", "msg ok"));
  panel.append(cc);

  const acts = row();
  if (!locked) {
    acts.append(button("Save", async () => { const x = await save(); openReport(panel, r.id, x); }, "btn sm"),
      button("Mask secrets", async () => { await save(); const x = await send("POST", `reports/${r.id}/redact`); toast(`${x.masked} masked`); openReport(panel, r.id, x.report); }, "btn ghost sm"));
  }
  acts.append(button("Copy as Markdown", async () => { const x = await get(`reports/${r.id}/export`, { format: "md" }); await copy(x.content, "Markdown copied"); }, "btn ghost sm"),
    button("Fields for the platform", async () => platformFields(r), "btn ghost sm"));
  if (!locked) {
    if (r.can_submit) acts.append(button("Submit to HackerOne", async () => submitDialog(panel, r, save), "btn sm"));
    else if (r.program_id && r.platform !== "hackerone") acts.append(button("I sent it on the platform", async () => markDialog(panel, r, save), "btn sm"));
    r.next_states.filter((s) => !["submitted"].includes(s)).forEach((s) => acts.append(button(s === "ready" ? "Mark ready" : `Set ${STATUSES(s)}`, async () => { await save(); const x = await send("PATCH", `reports/${r.id}`, { status: s }); openReport(panel, r.id, x); }, "btn ghost sm")));
    acts.append(button("Delete draft", async () => { if (!(await ask("The draft is deleted for good.", { title: "Delete this draft?", ok: "Delete" }))) return; await api("DELETE", url(`reports/${r.id}`)); reportsTab(reset(panel)); }, "btn ghost sm"));
  } else {
    const st = selectOf([["", "Move to..."], ...r.next_states.map((s) => [s, STATUSES(s)])], "");
    const amount = text(r.bounty_amount || "", { placeholder: "Bounty amount", inputmode: "decimal" }); const cur = text(r.bounty_currency || "", { placeholder: "USD", maxlength: "8" });
    const note = text("", { placeholder: "Note for the timeline" });
    acts.append(st, button("Update", async () => { const b = {}; if (st.value) b.status = st.value; if (amount.value !== (r.bounty_amount || "")) b.bounty_amount = amount.value; b.bounty_currency = cur.value; if (note.value.trim()) b.note = note.value; const x = await send("PATCH", `reports/${r.id}`, b); openReport(panel, r.id, x); }, "btn sm"));
    panel.append(card("Outcome", row(amount, cur), row(note)));
  }
  panel.append(acts);
  panel.append(card("Timeline", table([{ label: "When", render: (e) => shortDate(e.at) }, { label: "Event", render: (e) => e.kind }, { label: "Detail", cls: "full", render: (e) => e.note }, { label: "By", render: (e) => e.by || "" }], r.events.slice().reverse())));
}

async function platformFields(r) {
  const fmt = r.platform || "hackerone";
  const x = await get(`reports/${r.id}/export`, { format: fmt });
  dialog("Fields for " + (PLATFORMS[fmt] || fmt), (body, close) => {
    body.append(para("Paste each into the platform's own form. Bugcrowd does not let you edit a submission after it is sent, so read it through first."));
    x.fields.forEach((f) => { const t = el("textarea", "", null, { rows: f.value.length > 200 ? "8" : "2", readonly: "" }); t.value = f.value; body.append(field(f.name, t), button(`Copy ${f.name.toLowerCase()}`, async () => copy(f.value, "Copied"), "btn ghost sm")); });
    if (safeHref(x.url)) body.append(row(link("Open the program on the platform", x.url)));
    body.append(row(button("Close", async () => close(), "btn ghost")));
  });
}

function submitDialog(panel, r, save) {
  dialog("Submit to HackerOne", (body, close) => {
    body.append(para(`This sends the report to ${r.program} on HackerOne under your own HackerOne account. A submitted report cannot be recalled from here. Type the program handle to confirm.`));
    const handle = text("", { placeholder: "program handle", autocomplete: "off" });
    body.append(field("Program handle", handle), row(button("Submit", async () => {
      await save();
      try { const x = await send("POST", `reports/${r.id}/submit`, { confirm: handle.value.trim() }); toast("Submitted"); close(); openReport(panel, r.id, x); }
      catch (err) { toast(err.message, true); throw err; }
    }), button("Cancel", async () => close(), "btn ghost")));
  });
}

function markDialog(panel, r, save) {
  dialog("Record that you sent it", (body, close) => {
    body.append(para("Use this after you sent the report on the platform yourself. The text is then locked here."));
    const link2 = text("", { placeholder: "https:// address of the report (optional)" }); const id = text("", { placeholder: "report id (optional)" });
    body.append(field("Report address", link2), field("Report id", id), row(button("Mark submitted", async () => {
      await save(); const x = await send("POST", `reports/${r.id}/mark-submitted`, { platform_url: link2.value.trim(), platform_report_id: id.value.trim() }); close(); openReport(panel, r.id, x);
    }), button("Cancel", async () => close(), "btn ghost")));
  });
}

// ------------------------------------------------------------------------------ playbook and accounts
async function playbookTab(panel) {
  loading(panel);
  const pb = await get("playbook");
  panel.textContent = "";
  panel.append(para(`How to take part and how to report, from the platforms' own published guidance. Updated ${pb.updated}.`));
  pb.sections.forEach((s) => {
    const c = card(s.title, para(s.summary));
    if (s.table) c.append(table([{ label: "State", render: (x) => x[0] }, { label: "What it means", cls: "full", render: (x) => x[1] }], s.table));
    const ul = el("ul", "bb-list"); s.points.forEach((p) => ul.append(el("li", "", p))); c.append(ul);
    const src = el("p", "note"); src.append(document.createTextNode("Sources: "));
    s.sources.forEach((k, i) => { if (i) src.append(document.createTextNode(" · ")); src.append(link(pb.sources[k].label, pb.sources[k].url)); });
    c.append(src); panel.append(c);
  });
  const lim = card("What this page does not do"); const ul = el("ul", "bb-list"); pb.limits.forEach((p) => ul.append(el("li", "", p))); lim.append(ul); panel.append(lim);
}

async function accountsTab(panel) {
  loading(panel);
  const s = await get("status");
  panel.textContent = "";
  const h1 = s.credentials.hackerone;
  const c = card("HackerOne", para("Reports go out only under your own HackerOne account, never a shared key. Create an API token in your HackerOne settings and enter it here. It is stored encrypted and is never shown again."));
  const user = text(h1 || "", { placeholder: "API identifier", autocomplete: "off" });
  const token = el("input", "", null, { type: "password", placeholder: h1 ? "saved; enter a new token to replace it" : "API token", autocomplete: "new-password" });
  c.append(field("API identifier", user), field("API token", token));
  c.append(row(button("Save", async () => { const x = await api("PUT", `${API}/credentials/hackerone`, { username: user.value, token: token.value }); token.value = ""; toast(x.verified === true ? "Saved and accepted by HackerOne" : x.verified === false ? "Saved, but HackerOne refused them" : "Saved; HackerOne could not be reached to check", x.verified === false); accountsTab(reset(panel)); }, "btn sm"),
    h1 ? button("Test", async () => { const x = await api("POST", `${API}/credentials/hackerone/test`, {}); toast(x.verified === true ? "HackerOne accepts them" : x.verified === false ? "HackerOne refuses them" : "Could not reach HackerOne", x.verified !== true); }, "btn ghost sm") : el("span"),
    h1 ? button("Remove", async () => { await api("DELETE", `${API}/credentials/hackerone`); accountsTab(reset(panel)); }, "btn ghost sm") : el("span")));
  panel.append(c, card("Other platforms", para("Bugcrowd, Intigriti and YesWeHack have no submit button here. Copy the finished fields into the platform and mark the report submitted.")));
}

const tracked = (fn) => (panel) => { current = panel; return fn(panel); };
tabs(root, {
  overview: { label: "Overview", open: tracked(overviewTab) },
  programs: { label: "Programs", open: tracked(programsTab) },
  changes: { label: "Scope changes", open: tracked(changesTab) },
  matches: { label: "Your targets", open: tracked(matchesTab) },
  engagements: { label: "Engagements", open: tracked(engagementsTab) },
  reports: { label: "Reports", open: tracked(reportsTab) },
  playbook: { label: "Playbook", open: tracked(playbookTab) },
  accounts: { label: "My accounts", open: tracked(accountsTab) },
}, "overview");
