// The detail of one exposed secret, as a side panel: what was found in plain words, where (with a link that opens the page and the masked text
// around the match), why it is rated as it is, how many other places serve it, and what to do. Built with textContent only. No value ever reaches
// this page: the API sends the mask, the kind and where it was seen (docs/SECRETS-PLAN.md section 11).
import { api, badge, button, el, field, selectOf, shortDate, toast } from "/staticfiles/cve/ui.js";
import {
  STATUS_WORDS, contextView, decisionButtons, memberLabel, openableUrl, otherPlaces, validationWords, whereLine,
} from "/staticfiles/cve/secret-detail-logic.js";

const SEV_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const CLASS_WORDS = { P: "Browser key", S: "Server secret", I: "Identifier" };
const SHOWN_PLACES = 5;

const section = (title, ...kids) => {
  const box = el("section", "sd-section");
  box.append(el("h3", "", title), ...kids);
  return box;
};

function placeCard(o) {
  const card = el("li", "sd-place");
  const head = el("div", "sd-place-head");
  const href = openableUrl(o.url);
  head.append(href ? el("a", "sd-url", whereLine(o), { href, target: "_blank", rel: "noopener noreferrer", title: "Opens the page in a new tab" }) : el("span", "sd-url", whereLine(o)));
  card.append(head);
  card.append(el("p", "note sd-meta", `${o.source_label || o.source} · rule ${o.rule_id} · ${o.retired_at ? `gone since ${shortDate(o.retired_at)}` : `last seen ${shortDate(o.last_seen)}`}`));
  const ctx = contextView(o);
  if (ctx.text) {
    card.append(el("pre", "sd-context", ctx.text, { "aria-label": "The text around the match, with the value masked" }));
  } else {
    card.append(el("p", "note sd-nocontext", ctx.note));
  }
  return card;
}

function places(s) {
  const list = el("ol", "sd-places", null, { "aria-label": "Where the secret was found" });
  const live = s.occurrence_list.filter((o) => !o.retired_at);
  const gone = s.occurrence_list.filter((o) => o.retired_at);
  const ordered = [...live, ...gone];
  ordered.slice(0, SHOWN_PLACES).forEach((o) => list.append(placeCard(o)));
  const box = el("div");
  box.append(list);
  if (ordered.length > SHOWN_PLACES) {
    const more = el("details", "sd-more");
    more.append(el("summary", "", `${ordered.length - SHOWN_PLACES} more place${ordered.length - SHOWN_PLACES === 1 ? "" : "s"}`));
    const rest = el("ol", "sd-places");
    ordered.slice(SHOWN_PLACES).forEach((o) => rest.append(placeCard(o)));
    more.append(rest);
    box.append(more);
  }
  return box;
}

function facts(s) {
  const rows = [
    ["Status", STATUS_WORDS[s.status] || s.status],
    ["Assigned to", s.assignee ? memberLabel(s.assignee) : "No one"],
    ["First seen", shortDate(s.first_seen)],
    ["Last seen", shortDate(s.last_seen)],
    ["Rule", (s.rule_ids || []).join(", ")],
    ["Length", s.length ? `${s.length} characters` : ""],
  ];
  if (s.facts && s.facts.exp) rows.push(["Expires (JWT exp, unverified)", new Date(s.facts.exp * 1000).toISOString().slice(0, 10)]);
  if (s.status_note) rows.push(["Note", `${s.status_note}${s.status_by ? ` (${s.status_by.name})` : ""}`]);
  const dl = el("dl", "supplier-kv");
  rows.filter(([, v]) => v).forEach(([k, v]) => dl.append(el("dt", "", k), el("dd", "", v)));
  return dl;
}

function actions(slug, id, s, reload) {
  const box = el("div", "sd-actions");
  const note = el("textarea", "", null, { rows: "2", maxlength: "2000", placeholder: "Why (optional)", "aria-label": "Why you are taking this decision" });
  const help = el("p", "note sd-help", "", { role: "status" });
  const row = el("div", "sd-buttons");
  decisionButtons(s.status).forEach((d) => {
    const b = el("button", `btn sm${d.current ? "" : " ghost"}`, d.label, { type: "button", "aria-pressed": String(d.current) });
    b.onmouseenter = b.onfocus = () => (help.textContent = d.help);
    b.onclick = async () => {
      b.disabled = true;
      try {
        await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/status`, { status: d.status, note: note.value });
        toast(`${d.label}: saved`);
        reload(true);
      } catch (err) {
        b.disabled = false;
        toast(err.message, true);
      }
    };
    row.append(b);
  });
  box.append(row, help, field("Note", note));
  box.append(assignRow(slug, id, s, reload));
  const v = s.validation_available;
  if (v && v.enabled && v.can_switch && !v.blocked_reason) {
    box.append(button("Validate now", async () => {
      const out = await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/validate`);
      toast(`Queued: the built-in scanner reads ${out.hosts.length} host${out.hosts.length === 1 ? "" : "s"} again`);
    }, "btn ghost sm"));
  }
  return box;
}

function assignRow(slug, id, s, reload) {
  const row = el("div", "sd-assign");
  const pick = selectOf([["", "Pick a person"]], "");
  pick.setAttribute("aria-label", "Assign to");
  const go = el("button", "btn ghost sm", s.assignee ? "Reassign" : "Assign", { type: "button" });
  go.disabled = true;
  pick.onchange = () => (go.disabled = !pick.value);
  go.onclick = async () => {
    go.disabled = true;
    try {
      await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/assign`, { assignee: Number(pick.value) });
      toast("Assigned");
      reload(true);
    } catch (err) {
      go.disabled = false;
      toast(err.message, true);
    }
  };
  row.append(pick, go);
  if (s.assignee) {
    const un = el("button", "btn ghost sm", "Unassign", { type: "button" });
    un.onclick = async () => {
      await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/assign`, { assignee: null });
      reload(true);
    };
    row.append(un);
  }
  api("GET", `/api/v1/projects/${encodeURIComponent(slug)}/members?page_size=100`)
    .then((r) => (r.results || []).forEach((m) => pick.append(Object.assign(el("option", "", memberLabel(m)), { value: String(m.id) }))))
    .catch(() => { pick.disabled = true; });
  return row;
}

function render(body, slug, id, s, reload) {
  const head = el("div", "sd-head");
  head.append(badge(s.severity, SEV_BADGE[s.severity] || "info"), el("code", "sd-mask", s.masked), el("span", "note", CLASS_WORDS[s.class] || ""));
  body.append(head);
  const ex = s.explain;
  body.append(section("What was found", el("p", "", ex.what), el("p", "", `${ex.abuse}`)));
  body.append(section("Where", el("p", "note", otherPlaces(s)), places(s)));
  body.append(section(`Why it is rated ${s.severity}`, el("p", "", ex.rating), el("p", "note", ex.catalogue), el("p", "note", validationWords(s))));
  body.append(facts(s));
  const fix = section("How to fix", el("p", "", ex.how_to_fix));
  if (ex.provider_fix) fix.append(el("p", "note", ex.provider_fix));
  if (s.docs) fix.append(el("a", "", "Provider documentation", { href: s.docs, target: "_blank", rel: "noopener noreferrer" }));
  body.append(fix);
  if (s.resources.length) body.append(section("Resources it points at", el("p", "note", s.resources.map((r) => `${r.kind}: ${r.identifier}`).join(", "))));
  if (s.can_write) body.append(section("Decide", actions(slug, id, s, reload)));
}

// Opens the secret ``id`` of project ``slug`` in a panel at the side of the page (a sheet on a phone). ``refresh`` runs after a decision, so a list
// behind the panel shows the new status. Focus starts on the title; Escape and the Close button put it back where it was.
export function openSecret(slug, id, { refresh = () => {} } = {}) {
  const back = document.activeElement;
  const backLabel = back && back.getAttribute ? back.getAttribute("aria-label") : null; // a list that redraws after a decision replaces the button: find its twin
  const d = el("dialog", "dlg side-panel", null, { "aria-labelledby": "sd-title" });
  const body = el("div", "dlg-body");
  const title = el("h2", "", "Secret", { id: "sd-title", tabindex: "-1" });
  const top = el("div", "sd-top");
  const shut = el("button", "btn ghost sm", "Close", { type: "button", "aria-label": "Close the secret" });
  shut.onclick = () => d.close();
  top.append(title, shut);
  body.append(top);
  d.append(body);
  document.body.append(d);
  d.addEventListener("close", () => {
    d.remove();
    const target = back && back.isConnected ? back : backLabel ? [...document.querySelectorAll("button, a")].find((n) => n.getAttribute("aria-label") === backLabel) : null;
    if (target && target.focus) target.focus();
  });
  d.addEventListener("click", (e) => { if (e.target === d) d.close(); });
  const rest = el("div", "sd-body");
  body.append(rest);
  async function load(changed = false) {
    try {
      const s = await api("GET", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}`);
      rest.textContent = "";
      title.textContent = s.explain.title;
      render(rest, slug, id, s, load);
      if (changed) refresh();
    } catch (err) {
      rest.textContent = "";
      rest.append(el("p", "msg err", err.message));
    }
  }
  d.showModal();
  title.focus();
  load();
  return d;
}
