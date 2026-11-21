// The Email reports tab of the Reporting page: the cards of a scope's email reports, the create and edit dialog, the preview and the test send.
// Everything comes from /api/v1/report-subscriptions and /api/v1/reporting/digest-preview; the server decides who may do what and this only hides what
// would be refused. Names, addresses and server messages are set with textContent only, and the preview is a sandboxed frame without scripts.
import { api, ask, badge, couldNotRead, dialog, el, emptyState, field, selectOf, toast, waiting } from "/staticfiles/cve/ui.js";
import { fmtDateTime } from "/staticfiles/cve/prefs.js";
import { attachRowMenu } from "/staticfiles/cve/rowmenu.js";
import { attachText, defaultName, fieldOfError, lastResultText, MAX_RECIPIENTS, nextSendText, parseRecipients, recipientsText, scheduleSummary, statusPill } from "/staticfiles/cve/reports-logic.js";

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const BASE = "/api/v1/report-subscriptions";
const narrow = () => typeof matchMedia === "function" && matchMedia("(max-width: 619px)").matches;
const when = (iso) => fmtDateTime(iso) || String(iso || "").slice(0, 16).replace("T", " ");
const query = (scope) => (scope.kind === "org" ? `org=${encodeURIComponent(scope.slug)}` : `project=${encodeURIComponent(scope.slug)}`);

function zones() {
  try {
    if (typeof Intl.supportedValuesOf === "function") return Intl.supportedValuesOf("timeZone");
  } catch (_) { /* an older browser */ }
  return [];
}

function localZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch (_) { return "UTC"; }
}

// --- the preview ---------------------------------------------------------------------------------------------------------------

/** Opens the preview of an email: ``path`` is the preview address without a format (it may already hold a query). */
export function openPreview(path) {
  const join = (format) => `${path}${path.includes("?") ? "&" : "?"}format=${format}`;
  dialog("Preview of the email", (body, close) => {
    const head = el("p", "note", "Building the preview…");
    const toggle = el("div", "tools");
    const frame = el("iframe", "report-preview", null, { sandbox: "", title: "Preview of the email report", loading: "lazy" });
    const plain = el("pre", "report-plain");
    plain.hidden = true;
    const htmlBtn = el("button", "btn ghost sm", "HTML", { type: "button", "aria-pressed": "true" });
    const textBtn = el("button", "btn ghost sm", "Plain text", { type: "button", "aria-pressed": "false" });
    const show = (isHtml) => {
      frame.hidden = !isHtml;
      plain.hidden = isHtml;
      htmlBtn.setAttribute("aria-pressed", String(isHtml));
      textBtn.setAttribute("aria-pressed", String(!isHtml));
    };
    htmlBtn.onclick = () => show(true);
    textBtn.onclick = () => show(false);
    const open = el("a", "btn ghost sm", "Open in a new tab", { href: join("html"), target: "_blank", rel: "noopener" });
    toggle.append(htmlBtn, textBtn, open);
    const done = el("button", "btn", "Close", { type: "button" });
    done.onclick = close;
    const actions = el("div", "actions");
    actions.append(done);
    body.append(head, toggle, frame, plain, actions);
    api("GET", join("json"))
      .then((data) => {
        head.textContent = `Preview of the email for the period ${data.digest.period.label} (built now; the real email is built when it is sent).`;
        plain.textContent = `${data.subject}\n\n${data.text}`;
        frame.setAttribute("src", join("html"));
      })
      .catch((err) => { head.textContent = err.message; });
  });
}

// --- the create and edit dialog -------------------------------------------------------------------------------------------------

function segmented(options, value, onChange) {
  const box = el("div", "tools report-seg", null, { role: "group" });
  const buttons = options.map(([v, label]) => {
    const b = el("button", "btn ghost sm", label, { type: "button", "aria-pressed": String(v === value) });
    b.addEventListener("click", () => {
      buttons.forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      onChange(v);
    });
    box.append(b);
    return b;
  });
  return box;
}

/**
 * The dialog to create (``sub`` null) or edit an email report. ``env``: {scopes (can_subscribe ones are offered), scope (the selected one), me_email,
 * done()} .
 */
function editDialog(sub, env) {
  const choices = env.scopes.filter((s) => s.can_subscribe);
  const state = { cadence: sub ? sub.cadence : "weekly", scope: sub ? null : (choices.find((s) => s.kind === env.scope.kind && s.slug === env.scope.slug) || choices[0] || env.scope) };
  dialog(sub ? "Edit email report" : "New email report", (body, close) => {
    const errors = {};
    const wrap = (key, label, input, help) => {
      const f = field(label, input, help);
      errors[key] = el("p", "msg err", "", { role: "alert" });
      errors[key].hidden = true;
      f.append(errors[key]);
      return f;
    };
    // name
    const name = Object.assign(el("input", "", null, { type: "text", maxlength: "80" }), { value: sub ? sub.name : "" });
    let touched = Boolean(sub);
    name.addEventListener("input", () => { touched = true; });
    const scopeName = () => (sub ? sub.scope.name : state.scope.name);
    const rename = () => { if (!touched) name.value = defaultName(state.cadence, scopeName()); };
    if (!sub) name.value = defaultName(state.cadence, scopeName());
    body.append(wrap("name", "Name", name));
    // scope
    if (sub) {
      body.append(el("p", "note", `Scope: ${sub.scope.name} (${sub.scope.kind === "org" ? "whole organization" : "project"}). To change it, delete this report and make a new one.`));
    } else {
      const pick = selectOf((choices.length ? choices : [env.scope]).map((s) => [`${s.kind}:${s.slug}`, s.kind === "org" ? `Whole organization: ${s.name}` : s.name]), `${state.scope.kind}:${state.scope.slug}`, "Scope");
      pick.addEventListener("change", () => { state.scope = choices.find((s) => `${s.kind}:${s.slug}` === pick.value); rename(); });
      body.append(field("Scope", pick));
    }
    // recipients
    const recipients = el("textarea", "", null, { rows: "3", "aria-label": "Recipients", placeholder: "name@example.org, other@example.org" });
    recipients.value = sub ? sub.recipients.join("\n") : "";
    const chips = el("div", "chips");
    const count = el("p", "note");
    const optedBox = el("div");
    let optedChecks = [];
    const addMe = el("button", "btn ghost sm", "Add me", { type: "button" });
    addMe.disabled = !env.me_email;
    const paintRecipients = () => {
      const parsed = parseRecipients(recipients.value, MAX_RECIPIENTS);
      chips.textContent = "";
      parsed.valid.forEach((e) => chips.append(el("span", "chip", e)));
      parsed.invalid.forEach((e) => chips.append(el("span", "chip bad", `${e} (not an address)`)));
      parsed.over.forEach((e) => chips.append(el("span", "chip bad", `${e} (over the limit)`)));
      count.textContent = `${parsed.valid.length} of ${MAX_RECIPIENTS}${parsed.duplicates.length ? `, ${parsed.duplicates.length} repeated` : ""}`;
      optedBox.textContent = "";
      optedChecks = [];
      const out = ((sub && sub.opted_out) || []).filter((o) => parsed.valid.includes(o.email));
      out.forEach((o) => {
        const row = el("label", "plan-opt");
        const box = el("input", "", null, { type: "checkbox", "data-opted": o.email });
        optedChecks.push(box);
        row.append(box, el("span", "", `${o.email} unsubscribed on ${String(o.at).slice(0, 10)}; tick to add back`));
        optedBox.append(row);
      });
      return parsed;
    };
    recipients.addEventListener("input", paintRecipients);
    addMe.addEventListener("click", () => {
      if (!parseRecipients(recipients.value).valid.includes(env.me_email.toLowerCase())) recipients.value = `${recipients.value.trim()}${recipients.value.trim() ? "\n" : ""}${env.me_email}`;
      paintRecipients();
    });
    const rf = wrap("recipients", "Recipients", recipients, "Separate addresses with a comma, a semicolon or a new line.");
    rf.append(chips, count, optedBox, addMe);
    body.append(rf);
    // schedule
    const weekday = selectOf(WEEKDAYS.map((d, i) => [String(i), d]), String(sub ? sub.weekday : 0), "Weekday");
    const day = selectOf(Array.from({ length: 28 }, (_, i) => [String(i + 1), String(i + 1)]), String(sub ? sub.day_of_month : 1), "Day of the month");
    const weekdayField = wrap("weekday", "Day of the week", weekday);
    const dayField = wrap("day_of_month", "Day of the month", day, "Day 1 covers the whole previous month");
    const showCadence = () => { weekdayField.hidden = state.cadence !== "weekly"; dayField.hidden = state.cadence !== "monthly"; };
    body.append(field("How often", segmented([["weekly", "Weekly"], ["monthly", "Monthly"]], state.cadence, (v) => { state.cadence = v; showCadence(); rename(); })), weekdayField, dayField);
    showCadence();
    const time = Object.assign(el("input", "", null, { type: "time", step: "900" }), { value: sub ? sub.send_time : "08:00" });
    body.append(wrap("send_time", "Time", time));
    const zoneList = zones();
    const here = sub ? sub.timezone : localZone();
    const zone = zoneList.length
      ? selectOf((zoneList.includes(here) ? zoneList : [here, ...zoneList]).map((z) => [z, z]), here, "Time zone")
      : Object.assign(el("input", "", null, { type: "text", maxlength: "64" }), { value: here });
    body.append(wrap("timezone", "Time zone", zone));
    const attach = selectOf([["none", "None"], ["pdf", "PDF"], ["csv", "CSV"]], sub ? sub.attach : "none", "Attach the full report");
    body.append(wrap("attach", "Attach the full report", attach, `Attachments over ${env.limits.attach_max_mb} MB are replaced by a note with a link to cvENGINE.`));

    const status = el("p", "note", "", { role: "status", "aria-live": "polite" });
    const actions = el("div", "actions");
    const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
    cancel.onclick = close;
    const preview = el("button", "btn ghost", "Preview", { type: "button" });
    preview.onclick = () => {
      const scope = sub ? sub.scope : state.scope;
      openPreview(`/api/v1/reporting/digest-preview?${query(scope)}&cadence=${state.cadence}&timezone=${encodeURIComponent(zone.value)}`);
    };
    const save = el("button", "btn", "Save", { type: "button" });
    save.onclick = async () => {
      Object.values(errors).forEach((e) => { e.hidden = true; });
      status.textContent = "";
      const payload = {
        name: name.value, recipients: parseRecipients(recipients.value, 1000).valid, cadence: state.cadence, weekday: Number(weekday.value), day_of_month: Number(day.value),
        send_time: time.value, timezone: zone.value, attach: attach.value,
        confirm_opted_out: optedChecks.some((i) => i.checked),
      };
      if (!sub) Object.assign(payload, state.scope.kind === "org" ? { org: state.scope.slug } : { project: state.scope.slug });
      save.disabled = true;
      try {
        const saved = await api(sub ? "PATCH" : "POST", sub ? `${BASE}/${sub.id}` : BASE, payload);
        toast(saved.next_run_at ? `Saved. The next email goes out ${when(saved.next_run_at)}.` : "Saved.");
        close();
        env.done();
      } catch (err) {
        const key = fieldOfError(err.message);
        const target = errors[key];
        if (target) { target.textContent = err.message; target.hidden = false; } else status.textContent = err.message;
        toast(err.message, true);
        save.disabled = false;
      }
    };
    actions.append(cancel, preview, save);
    body.append(status, actions);
    paintRecipients();
  });
}

// --- the cards ------------------------------------------------------------------------------------------------------------------

function card(sub, env) {
  const box = el("div", "card report-sub");
  const head = el("div", "card-head");
  head.append(el("h3", "", sub.name));
  const [label, tone] = statusPill(sub);
  head.append(badge(label, tone));
  box.append(head);
  const meta = el("p", "note");
  meta.append(el("span", "chip", sub.scope.kind === "org" ? `Organization: ${sub.scope.name}` : sub.scope.name));
  box.append(meta);
  const lines = [
    scheduleSummary(sub),
    `To ${recipientsText(sub.recipients)}`,
    attachText(sub.attach),
    sub.enabled ? `Next email: ${nextSendText(sub.next_run_at)}` : "Next email: not scheduled",
    `Last result: ${lastResultText(sub, when)}`,
  ];
  lines.forEach((l) => box.append(el("p", "note report-line", l)));
  if (!sub.enabled && sub.last_status === "disabled" && sub.last_error) box.append(el("p", "msg err", sub.last_error));
  const act = {
    preview: () => openPreview(`${BASE}/${sub.id}/preview`),
    test: async () => {
      if (!env.mail_ready) return toast("Outgoing mail is not set up.", true);
      const r = await api("POST", `${BASE}/${sub.id}/test`);
      toast(`A test email is on its way to ${r.to}.`);
    },
    edit: () => editDialog(sub, env),
    pause: async () => {
      await api("PATCH", `${BASE}/${sub.id}`, { enabled: !sub.enabled });
      toast(sub.enabled ? "Paused." : "Resumed.");
      env.done();
    },
    remove: async () => {
      if (!(await ask(`Delete the email report '${sub.name}'? It stops at once and its history is removed.`, { title: 'Delete this email report?', ok: 'Delete' }))) return;
      await api("DELETE", `${BASE}/${sub.id}`);
      toast("Deleted.");
      env.done();
    },
  };
  const guard = (fn) => async () => { try { await fn(); } catch (err) { toast(err.message, true); } };
  const items = [["Preview", act.preview, true], ["Send test to me", act.test, false], ["Edit", act.edit, false],
    [sub.enabled ? "Pause" : "Resume", act.pause, false], ["Delete", act.remove, false]].filter(([, , readOnlyOk]) => sub.can_manage || readOnlyOk);
  if (narrow()) {
    attachRowMenu(box, sub.name, () => items.map(([text, run]) => ({ label: text, run: guard(run), danger: text === "Delete" })));
  } else {
    const row = el("div", "report-actions");
    items.forEach(([text, run]) => {
      const b = el("button", `btn ghost sm${text === "Delete" ? " danger-ghost" : ""}`, text, { type: "button" });
      if (text === "Send test to me" && !env.mail_ready) {
        b.disabled = true;
        b.title = env.mailNote;
      }
      b.addEventListener("click", guard(run));
      row.append(b);
    });
    box.append(row);
  }
  return box;
}

/**
 * Draws the tab into ``panel``. ``env``: {scopes, scope (the selected scope of the page), me_email, isAppAdmin, limits (from the scopes route)}.
 */
export async function emailTab(panel, env) {
  const root = el("div", "report-email");
  panel.append(root);
  let everything = false;
  async function draw() {
    root.textContent = "";
    root.append(waiting("Reading the email reports"));
    let data;
    try {
      data = await api("GET", everything ? BASE : `${BASE}?${query(env.scope)}`);
    } catch (err) {
      root.textContent = "";
      root.append(couldNotRead("The email reports", draw, err.message));
      return;
    }
    root.textContent = "";
    const mailNote = env.isAppAdmin ? "Outgoing mail is not set up. Set it up in Settings, Email." : "Outgoing mail is not set up. Ask an App Admin to set it up; email reports are kept and start sending once it is.";
    const local = { ...env, mail_ready: data.mail_ready, limits: data.limits || env.limits, mailNote, done: draw };
    if (!data.mail_ready) {
      root.append(emptyState({ icon: "report", tone: "warn", title: "Outgoing mail is not set up", body: mailNote.replace(/^Outgoing mail is not set up\. /, ""),
        actions: env.isAppAdmin ? [{ label: "Open Settings, Email", href: "/cve/settings/#alerts" }] : [] }));
    }
    const tools = el("div", "tools");
    const filter = selectOf([["scope", "This scope"], ["all", "Everything I can see"]], everything ? "all" : "scope", "Which email reports");
    filter.addEventListener("change", () => { everything = filter.value === "all"; draw(); });
    tools.append(filter);
    if (data.can_create && !everything) {
      const add = el("button", "btn", "New email report", { type: "button" });
      add.addEventListener("click", () => editDialog(null, local));
      tools.append(add);
    }
    root.append(tools);
    if (!everything && !data.can_create) {
      root.append(el("p", "note", "Only project members with write access (or an Org Admin, for a whole organization) can create email reports."));
    }
    if (!data.results.length) {
      root.append(el("p", "note", everything ? "No email reports yet." : "No email reports for this scope yet."));
      return;
    }
    data.results.forEach((sub) => root.append(card(sub, local)));
  }
  await draw();
}
