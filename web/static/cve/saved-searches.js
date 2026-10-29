// Saved searches with alerts, on the Hosts page. A saved search is a query in the search box's own syntax that the server keeps
// (private to you, per project) and re-runs on a schedule; it can tell you about new matches. This module only draws the controls
// and calls /api/v1/projects/<slug>/saved-searches: the server validates the query and does all the evaluating.
//
// The browser-only views (views.js) keep working beside it. "Import browser views" turns the ones that hold a search into saved
// searches (alerts off) and leaves the local copies alone.
import { loadViews } from "/staticfiles/cve/views.js";
import {
  api,
  ask,
  badge,
  button,
  dialog,
  el,
  field,
  selectOf,
  shortDate,
  table,
  text,
  toast,
} from "/staticfiles/cve/ui.js";

const FREQUENCIES = [
  ["hourly", "Every hour"],
  ["daily", "Every day"],
  ["weekly", "Every week"],
];
const CHANNEL_LABEL = { slack: "Slack", discord: "Discord", telegram: "Telegram", lark: "Lark" };
const STATUS_NOTE = {
  too_broad: ["too broad", "failed"],
  alert_failed: ["alert not delivered, will retry", "failed"],
  error: ["error", "failed"],
  disabled: ["switched off", "failed"],
};

const check = (label, checked) => {
  const input = el("input", "", null, { type: "checkbox" });
  input.checked = checked;
  const wrap = el("label", "check");
  wrap.append(input, el("span", "", label));
  return { wrap, input };
};

function alertSummary(s) {
  const bits = [];
  if (s.alert_new) bits.push("new matches");
  if (s.alert_gone) bits.push("hosts that stop matching");
  if (s.threshold) bits.push(`${s.threshold}+ matches`);
  return bits.length ? bits.join(", ") : "no alerts";
}

/**
 * @param {{slug: string, read: () => string, apply: (query: string) => void}} cfg
 *   read(): the query in the search box now. apply(query): put a saved query in the box and run it.
 * @returns {{node: HTMLElement, refresh: () => void}}
 */
export function savedSearches({ slug, read, apply }) {
  const base = `/api/v1/projects/${encodeURIComponent(slug)}/saved-searches`;
  const node = el("div", "views", null, { role: "group", "aria-label": "Saved searches" });
  let list = { results: [], limits: {}, channels_available: [] };
  let loaded = false;

  async function load() {
    try {
      list = await api("GET", base);
      loaded = true;
    } catch (_) {
      loaded = false; // an older server without saved searches: the controls stay hidden
    }
    draw();
  }

  function editor(existing, seed = {}) {
    dialog(existing ? "Edit saved search" : "Save this search", (body, close) => {
      const s = existing || {};
      const name = text(s.name || seed.name || "", { maxlength: "80", placeholder: "Exposed Postgres", autocomplete: "off", required: "" });
      const query = text(s.query || seed.query || "", { maxlength: "1000", placeholder: "port:5432 -ip:10.0.0.0/8", autocomplete: "off", required: "", class: "mono" });
      const frequency = selectOf(FREQUENCIES, s.frequency || "daily");
      const enabled = check("Check it on schedule", s.enabled !== false);
      const alertNew = check("Alert when a host starts to match", s.alert_new !== false);
      const alertGone = check("Alert when a host stops matching", Boolean(s.alert_gone));
      const threshold = text(s.threshold || "", { type: "number", min: "1", max: String(list.limits.matches || 1000), placeholder: "Optional" });
      const f = el("form");
      f.append(
        field("Name", name, "Only you see your saved searches."),
        field("Search", query, "The same syntax as the search box. The first check only records the hosts that match now; alerts begin with the next one."),
        field("How often", frequency),
        enabled.wrap,
        alertNew.wrap,
        alertGone.wrap,
        field("Alert when the match count reaches", threshold, "Once each time the count rises to this number."),
      );
      const channels = (list.channels_available || []).map((c) => [c, check(CHANNEL_LABEL[c] || c, !(s.channels || []).length || s.channels.includes(c))]);
      if (channels.length) {
        const box = el("div", "field");
        box.append(el("label", "", "Send alerts to"));
        channels.forEach(([, c]) => box.append(c.wrap));
        f.append(box);
      } else {
        f.append(el("p", "note", "No notification channel is switched on in Settings, so alerts show only in the activity feed."));
      }
      const msg = el("p", "msg err");
      msg.hidden = true;
      const actions = el("div", "actions");
      actions.append(el("span", "grow"), button("Cancel", close, "btn ghost"), el("button", "btn", existing ? "Save changes" : "Save search", { type: "submit" }));
      f.append(msg, actions);
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        const picked = channels.filter(([, c]) => c.input.checked).map(([k]) => k);
        const payload = {
          name: name.value.trim(),
          query: query.value.trim(),
          frequency: frequency.value,
          enabled: enabled.input.checked,
          alert_new: alertNew.input.checked,
          alert_gone: alertGone.input.checked,
          threshold: threshold.value ? Number(threshold.value) : null,
          channels: picked.length === channels.length ? [] : picked, // every channel ticked is "whatever Settings has on"
        };
        try {
          await (existing ? api("PATCH", `${base}/${existing.id}`, payload) : api("POST", base, payload));
        } catch (err) {
          msg.textContent = err.message;
          msg.hidden = false;
          return;
        }
        close();
        toast(existing ? "Saved search updated" : `Saved "${payload.name}". It is checked shortly; alerts begin with the check after.`);
        await load();
      });
      body.append(f);
      name.focus();
    });
  }

  async function runNow(s, reopen) {
    try {
      const out = await api("POST", `${base}/${s.id}/run`);
      if (out.status === "ok")
        toast(out.baseline ? `${out.count} host${out.count === 1 ? "" : "s"} match now. Alerts begin with the next check.` : `${out.count} match, ${out.new_count} new${out.alerted ? ", alert sent" : ""}.`);
      else toast(out.reason || `The search could not be run (${out.status}).`, true);
    } catch (err) {
      toast(err.message, true);
    }
    await load();
    reopen();
  }

  async function patch(s, change) {
    try {
      await api("PATCH", `${base}/${s.id}`, change);
    } catch (err) {
      toast(err.message, true);
    }
    await load();
  }

  async function remove(s) {
    if (!(await ask(`"${s.name}" and its alerts will be deleted.`, { title: "Delete this saved search?", ok: "Delete" }))) return;
    try {
      await api("DELETE", `${base}/${s.id}`);
    } catch (err) {
      toast(err.message, true);
    }
    await load();
  }

  function importable() {
    const have = new Set(list.results.map((s) => s.query));
    return loadViews("hosts", slug).filter((v) => v.params && String(v.params.q || "").trim() && !have.has(String(v.params.q).trim()));
  }

  async function importViews(views) {
    let made = 0;
    for (const v of views) {
      try {
        await api("POST", base, { name: v.name, query: String(v.params.q).trim(), alert_new: false });
        made += 1;
      } catch (err) {
        toast(`"${v.name}": ${err.message}`, true);
      }
    }
    if (made) toast(`Imported ${made} view${made === 1 ? "" : "s"} as saved searches. Switch alerts on from the list.`);
    await load();
  }

  function manage() {
    dialog("Saved searches", (body, close) => {
      const reopen = () => {
        close();
        manage();
      };
      body.append(el("p", "note", `Private to you. ${list.results.length} of ${list.limits.per_user || 25} used. Alerts go out as at most one message per search per check.`, { style: "margin-bottom:12px" }));
      if (!list.results.length) body.append(el("p", "empty", "Nothing saved yet. Type a search, then choose Save search."));
      else
        body.append(
          table(
            [
              {
                label: "Search",
                render: (s) => {
                  const cell = el("div");
                  const open = el("button", "view-open", s.name, { type: "button", title: "Show these hosts" });
                  open.onclick = () => {
                    close();
                    apply(s.query);
                  };
                  cell.append(open, el("div", "note mono", s.query));
                  return cell;
                },
              },
              {
                label: "Checked",
                render: (s) => {
                  const cell = el("div");
                  const [label, tone] = STATUS_NOTE[s.last_status] || [];
                  cell.append(el("span", "note", s.enabled ? `${FREQUENCIES.find(([k]) => k === s.frequency)?.[1] || s.frequency}` : "Off"));
                  if (label) cell.append(document.createTextNode(" "), badge(label, tone));
                  cell.append(el("div", "note", s.last_run_at ? `${s.last_match_count} host${s.last_match_count === 1 ? "" : "s"}, ${shortDate(s.last_run_at)}` : "Not checked yet"));
                  if (s.last_error) cell.append(el("div", "note", s.last_error));
                  return cell;
                },
              },
              { label: "Alerts", render: alertSummary },
              {
                label: "",
                render: (s) => {
                  const row = el("div", "dlg-tools");
                  if (s.enabled) row.append(button("Run now", () => runNow(s, reopen), "btn ghost sm"));
                  row.append(
                    button("Edit", () => { close(); editor(s); }, "btn ghost sm"),
                    button(s.enabled ? "Switch off" : "Switch on", async () => { await patch(s, { enabled: !s.enabled }); reopen(); }, "btn ghost sm"),
                    button("Delete", async () => { await remove(s); reopen(); }, "btn ghost sm"),
                  );
                  return row;
                },
              },
            ],
            list.results,
          ),
        );
      const old = importable();
      const actions = el("div", "actions");
      if (old.length) actions.append(button(`Import ${old.length} browser view${old.length === 1 ? "" : "s"}`, async () => { await importViews(old); reopen(); }, "btn ghost"));
      actions.append(el("span", "grow"), button("Close", close, "btn"));
      body.append(actions);
    });
  }

  function draw() {
    node.textContent = "";
    node.hidden = !loaded;
    if (!loaded) return;
    const query = read().trim();
    if (query && !list.results.some((s) => s.query === query)) {
      const add = el("button", "view-save", "Save search", { type: "button", title: "Keep this search and get alerts about it" });
      add.onclick = () => editor(null, { query });
      node.append(add);
    }
    const open = el("button", "view-save", `Saved searches (${list.results.length})`, { type: "button" });
    open.onclick = manage;
    node.append(open);
    window.cveCommands = (window.cveCommands || []).filter((c) => c.owner !== "saved-searches");
    list.results.forEach((s) =>
      window.cveCommands.push({ owner: "saved-searches", label: `Run saved search: ${s.name}`, hint: "Search", run: () => apply(s.query) }),
    );
  }

  load();
  return { node, refresh: draw };
}
