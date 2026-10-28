// A Sentinel's settings, version and updates on the Sentinels page. GET /api/v1/agents/{id} reports, for a Sentinel, `settings` (each one
// {value, source: "server"|"sentinel", at, by}: the effective value, and whether it was last set from this dashboard or in the Sentinel's
// own .env, the most recent change winning), `version` and `update` ({status, phase, detail, from, to, at, requested_at}). PATCH the same
// address with {settings: {...}} (null hands a setting back to the Sentinel's .env) or {update: "now"}. A server or Sentinel too old to
// report them simply leaves the keys out, and then nothing here is drawn. Everything the machine reports is set with textContent.
import {
  api,
  ask,
  badge,
  button,
  dialog,
  el,
  field,
  text,
  toast,
} from "/staticfiles/cve/ui.js";

export const SENTINEL_KINDS = [
  "nmap",
  "naabu",
  "nuclei_light",
  "nuclei_targeted",
  "nuclei_deep",
  "testssl",
  "nmap_udp",
  "wpscan",
  "openvas",
  "discover",
];
const KIND_WORDS = {
  nmap: "nmap",
  naabu: "naabu",
  nuclei_light: "nuclei (light)",
  nuclei_targeted: "nuclei (targeted)",
  nuclei_deep: "nuclei (deep)",
  testssl: "testssl",
  nmap_udp: "nmap UDP",
  wpscan: "WPScan",
  openvas: "OpenVAS",
  discover: "internal discovery",
};
const MAX_CONCURRENT = 10; // agent_broker.MAX_CONCURRENT_CAP; the server says so in its 400 if this changes
const UPDATE_WORDS = {
  waiting: "Update waiting",
  draining: "Finishing running tasks",
  updating: "Updating",
  done: "Updated",
  failed: "Update failed",
};
const UPDATE_TONE = {
  waiting: "queued",
  draining: "queued",
  updating: "running",
  done: "success",
  failed: "fire",
};
const MANUAL_NOTE =
  "Drains the running tasks first, then updates. In Manual mode a Sentinel only updates when you press this.";

const detailUrl = (id) => `/api/v1/agents/${id}`;
const reported = (d) =>
  Boolean(d && (d.settings || d.version !== undefined || d.update));

function ago(iso) {
  if (!iso) return "";
  const s = Math.max(
    0,
    Math.round((Date.now() - new Date(iso).getTime()) / 1000),
  );
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// "Set from this dashboard by alice, 2h ago" or "Set on the Sentinel's machine, 1d ago"
export function sourceLine(setting) {
  if (!setting) return "Not set";
  const when = setting.at ? `, ${ago(setting.at)}` : "";
  return setting.source === "server"
    ? `Set from this dashboard${setting.by ? ` by ${setting.by}` : ""}${when}`
    : `Set on the Sentinel's machine${when}`;
}

const shown = (key, value) => {
  if (value == null || (Array.isArray(value) && !value.length))
    return key === "disabled_kinds" ? "none" : "not set";
  if (key === "disabled_kinds")
    return value.map((k) => KIND_WORDS[k] || k).join(", ");
  if (key === "network")
    return value === "internal" ? "Internal network" : "External";
  if (key === "profile")
    return value === "light" ? "Light (no OpenVAS)" : "Full";
  return String(value);
};

// The version and update line of one card, and its "Update now" and "Settings" buttons. ``d`` is the agent detail; nothing is drawn
// when it does not report these keys.
export function versionBlock(d, { onChange }) {
  if (!reported(d)) return null;
  const box = el("div", "ss-version");
  const line = el("p", "ss-vline");
  line.append(
    el("span", "note", "Version"),
    el("b", "mono", d.version || "not reported"),
  );
  const u = d.update || {};
  const pending = Boolean(u.requested_at);
  if (u.status && u.status !== "idle") {
    line.append(
      badge(
        u.status === "done" && u.to
          ? `Updated to ${u.to}`
          : UPDATE_WORDS[u.status] || u.status,
        UPDATE_TONE[u.status] || "",
      ),
    );
  } else if (pending) {
    line.append(badge("Update requested", "queued"));
  }
  box.append(line);
  const sub =
    u.status === "failed"
      ? u.detail
      : ["waiting", "draining", "updating"].includes(u.status)
        ? [u.phase, u.from && u.to ? `${u.from} to ${u.to}` : ""]
            .filter(Boolean)
            .join(" · ")
        : "";
  if (sub)
    box.append(
      el(
        "p",
        u.status === "failed" ? "msg err ss-detail" : "note ss-detail",
        sub,
      ),
    );
  const actions = el("div", "ss-actions");
  const now = button(
    pending ? "Update requested" : "Update now",
    async () => {
      await api("PATCH", detailUrl(d.id), { update: "now" });
      toast(`Update requested for ${d.name}`);
      onChange();
    },
    "btn sm ghost",
  );
  now.title = MANUAL_NOTE;
  now.disabled =
    pending || ["waiting", "draining", "updating"].includes(u.status);
  actions.append(now);
  if (d.settings)
    actions.append(
      button("Settings", async () => openSettings(d, onChange), "btn sm ghost"),
    );
  box.append(actions);
  return box;
}

function control(key, value) {
  if (key === "name")
    return text(value || "", {
      maxlength: "64",
      autocomplete: "off",
      spellcheck: "false",
    });
  if (key === "network" || key === "profile") {
    const s = el("select");
    const opts =
      key === "network"
        ? [
            ["external", "External: reaches the internet-facing targets"],
            ["internal", "Internal: inside a private network"],
          ]
        : [
            ["full", "Full: also runs OpenVAS"],
            ["light", "Light: never runs OpenVAS"],
          ];
    if (value == null) s.append(el("option", "", "not set", { value: "" }));
    opts.forEach(([v, label]) =>
      s.append(el("option", "", label, { value: v })),
    );
    s.value = value || "";
    return s;
  }
  if (key === "max_concurrent")
    return text(value == null ? "" : String(value), {
      type: "number",
      min: "1",
      max: String(MAX_CONCURRENT),
      step: "1",
      inputmode: "numeric",
    });
  // disabled_kinds: one box per kind; a ticked box is a kind this Sentinel never takes
  const box = el("div", "ss-kinds", null, {
    role: "group",
    "aria-label": "Task kinds this Sentinel never takes",
  });
  SENTINEL_KINDS.forEach((k) => {
    const label = el("label", "ss-kind");
    const c = el("input", "", null, { type: "checkbox", value: k });
    c.checked = (value || []).includes(k);
    label.append(c, document.createTextNode(` ${KIND_WORDS[k]}`));
    box.append(label);
  });
  return box;
}

function readControl(key, node) {
  if (key === "disabled_kinds")
    return [...node.querySelectorAll("input:checked")].map((c) => c.value);
  if (key === "max_concurrent")
    return node.value.trim() === "" ? undefined : Number(node.value);
  const v = node.value.trim();
  return v === "" ? undefined : v;
}

const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

const ROWS = [
  ["name", "Name", "How it appears in cvENGINE."],
  [
    "network",
    "Where it runs",
    "Internal Sentinels scan the private networks declared for a project.",
  ],
  ["profile", "Size", "Light never runs OpenVAS."],
  [
    "disabled_kinds",
    "Never takes",
    "Task kinds this Sentinel refuses, whatever its capabilities.",
  ],
  [
    "max_concurrent",
    "Tasks at once",
    `A whole number from 1 to ${MAX_CONCURRENT}.`,
  ],
];

export function openSettings(first, onChange) {
  dialog(`Settings of ${first.name}`, (body, close) => {
    body.classList.add("ss-dialog");
    body.append(
      el(
        "p",
        "note",
        "The most recent change wins, wherever it was made: a later edit of the Sentinel's own .env takes over again. Changes reach the Sentinel within a heartbeat or so; this panel refreshes by itself.",
      ),
    );
    let d = first;
    const rows = new Map();
    const form = el("div", "ss-rows");
    ROWS.forEach(([key, label, help]) => {
      const row = el("div", "ss-row");
      const head = el("div", "ss-row-head");
      const now = el("b", "ss-now");
      const src = el("span", "note ss-src");
      head.append(el("span", "ss-label", label), now);
      const input = control(key, d.settings[key] && d.settings[key].value);
      const reset = button(
        "Reset to the Sentinel's value",
        async () => {
          if (
            !(await ask(
              `Hand ${label.toLowerCase()} back to the Sentinel's own .env?`,
              { title: "Reset setting", ok: "Reset", danger: false },
            ))
          )
            return;
          d = await api("PATCH", detailUrl(d.id), {
            settings: { [key]: null },
          });
          toast(`${label} handed back to the Sentinel`);
          paint(true);
          onChange();
        },
        "btn sm ghost ss-reset",
      );
      row.append(head, src, field(help, input), reset);
      form.append(row);
      rows.set(key, { now, src, input, reset, label });
    });
    body.append(form);
    const msg = el("p", "note ss-msg");
    const actions = el("div", "actions");
    actions.append(
      msg,
      el("span", "grow"),
      button("Close", async () => close(), "btn ghost"),
      button("Save changes", async () => {
        const change = {};
        rows.forEach((r, key) => {
          const next = readControl(key, r.input);
          const cur = d.settings[key] ? d.settings[key].value : undefined;
          if (next !== undefined && !same(next, cur)) change[key] = next;
          if (key === "disabled_kinds" && same(next, []) && cur && cur.length)
            change[key] = [];
        });
        if (!Object.keys(change).length) {
          msg.textContent = "Nothing changed.";
          return;
        }
        if (
          "max_concurrent" in change &&
          !(
            Number.isInteger(change.max_concurrent) &&
            change.max_concurrent >= 1 &&
            change.max_concurrent <= MAX_CONCURRENT
          )
        )
          throw new Error(
            `Tasks at once must be a whole number from 1 to ${MAX_CONCURRENT}.`,
          );
        d = await api("PATCH", detailUrl(d.id), { settings: change });
        toast("Saved. The Sentinel picks it up at its next heartbeat.");
        paint(true);
        onChange();
      }),
    );
    body.append(actions);

    // the effective value and why it has it; the inputs are only refilled after a save or a reset, never while someone is typing
    function paint(refill) {
      rows.forEach((r, key) => {
        const s = d.settings[key];
        r.now.textContent = shown(key, s && s.value);
        r.src.textContent = sourceLine(s);
        r.reset.hidden = !(s && s.source === "server");
        if (refill) {
          const fresh = control(key, s && s.value);
          r.input.replaceWith(fresh);
          fresh.id = r.input.id;
          r.input = fresh;
        }
      });
    }
    paint(false);
    const poll = setInterval(async () => {
      try {
        const next = await api("GET", detailUrl(d.id));
        if (next && next.settings) {
          d = next;
          paint(false);
        }
      } catch (_) {
        /* keep what is shown */
      }
    }, 5000);
    body.closest("dialog").addEventListener("close", () => clearInterval(poll));
  });
}

// The detail of every Sentinel on the page, asked for now and then: the list does not carry settings, version or update.
export function detailCache(onUpdate) {
  const cache = new Map();
  let busy = false;
  return {
    get: (id) => cache.get(id),
    async refresh(ids) {
      if (busy) return;
      busy = true;
      try {
        const got = await Promise.all(
          ids.map((id) => api("GET", detailUrl(id)).catch(() => null)),
        );
        ids.forEach((id, i) => {
          if (got[i]) cache.set(id, got[i]);
        });
        [...cache.keys()].forEach((id) => {
          if (!ids.includes(id)) cache.delete(id);
        });
      } finally {
        busy = false;
      }
      onUpdate();
    },
  };
}
