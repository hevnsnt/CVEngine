// A Sentinel's settings, version, updates and capability policy on the Sentinels page. GET /api/v1/agents/{id} reports `settings` with value, source,
// at and by, and `kinds`: per task kind whether the Sentinel declares it, whether cvENGINE offers it work of that kind, its policy (allow, deny, prefer),
// who decided that, and its per-kind cap. The settings panel edits that policy (PATCH {settings: {kinds: {kind: {mode, max_concurrent}|null}}}); the chips
// of a card show it (allowed, denied with who or what decided, withheld after repeated failures with the retry time). Network also reports its server grant and machine setting, with value showing the usable location. PATCH the same
// address with {settings: {...}} (network null restores its provisioned grant; other null values clear the dashboard setting)
// or {update: "now"}. A server or Sentinel too old to
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
  if (setting.server_grant) {
    const machine = setting.machine_value || "not reported";
    const grant = setting.managed
      ? `Set by an administrator${setting.grant_by ? ` (${setting.grant_by})` : ""}${setting.grant_at ? `, ${ago(setting.grant_at)}` : ""}`
      : "No dashboard override";
    return `Server grant: ${setting.server_grant}. Machine setting: ${machine}. Effective: ${setting.value}. ${grant}.`;
  }
  const when = setting.at ? `, ${ago(setting.at)}` : "";
  const limit = setting.limited_by_machine
    ? ` (limited by this machine's setting${setting.machine_value ? `: ${setting.machine_value}` : ""}, so this does not take effect)`
    : "";
  return (
    (setting.source === "server"
      ? `Set from this dashboard${setting.by ? ` by ${setting.by}` : ""}${when}`
      : `Set on the Sentinel's machine${when}`) + limit
  );
}

const shown = (key, value) => {
  if (value == null) return "not set";
  if (key === "network")
    return value === "internal" ? "Internal network" : "External";
  if (key === "profile")
    return value === "light" ? "Light (no OpenVAS)" : "Full";
  return String(value);
};

// --- the capability policy: what a Sentinel declares, and what an administrator lets it take ------------------------------------------------
const MODE_WORDS = { allow: "Allow", deny: "Deny", prefer: "Prefer" };
export const UNAVAILABLE_NOTE =
  "Not available on this Sentinel (tool missing or off on the machine).";
export const MACHINE_NOTE =
  "Turned off on the machine. Only a change there lifts it.";
export const kindWord = (k) => KIND_WORDS[k] || k;

// The one word for what a kind is on this Sentinel: `on`, `denied`, `machine_off`, `unavailable` (not declared), `cool_off` or `outdated`.
// The server says it (`state`); an older server that does not is read from the other fields.
export function kindState(info) {
  if (!info) return "unavailable";
  if (info.state) return info.state;
  if (info.source === "machine") return "machine_off";
  if (info.mode === "deny") return "denied";
  if (!info.declared) return "unavailable";
  if (info.source === "cool-off") return "cool_off";
  if (info.source === "contract") return "outdated";
  return "on";
}

const clock = (iso) =>
  iso
    ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "";

// The sentence behind a chip or a row: who decided, and what to do about it.
export function kindNote(info) {
  const state = kindState(info);
  if (state === "machine_off") return MACHINE_NOTE;
  if (state === "unavailable") return UNAVAILABLE_NOTE;
  if (state === "outdated") return "Its client is too old to run this; update it.";
  if (state === "cool_off")
    return `Withheld after repeated failures until ${clock(info.retry_at) || "the retry time"}; then tried again.`;
  const when = info.at ? `, ${ago(info.at)}` : "";
  if (state === "denied") {
    if (info.source === "instance default")
      return `Denied by the instance default${info.by ? ` (set by ${info.by})` : ""}${when}.`;
    return `Denied${info.by ? ` by ${info.by}` : ""}${when}.`;
  }
  const cap = info.cap ? `at most ${info.cap} at once` : "";
  const mode = info.mode === "prefer" ? "Preferred: other Sentinels wait a moment so this one gets the work first" : "Allowed";
  return [mode, cap].filter(Boolean).join(", ") + ".";
}

// The modes an administrator may pick for a kind: none for a kind the Sentinel does not declare (it cannot be enabled) or one its machine turned off.
export const modesOffered = (info) =>
  info && info.declared && kindState(info) !== "machine_off" ? ["allow", "deny", "prefer"] : [];
export const canReset = (info) => Boolean(info && info.source === "agent");
const validCap = (cap) =>
  cap == null || (Number.isInteger(cap) && cap >= 1 && cap <= MAX_CONCURRENT);

// What to PATCH: ``picks`` is {kind: {mode, cap, reset}} read from the panel; only a kind whose mode or cap differs from what the server shows is sent
// (null removes the Sentinel's own policy for it, which hands the kind back to the instance default).
export function kindsChange(kinds, picks) {
  const out = {};
  Object.entries(picks).forEach(([k, p]) => {
    const info = (kinds || {})[k] || {};
    if (p.reset) {
      if (canReset(info)) out[k] = null;
      return;
    }
    if (!p.mode || !modesOffered(info).length) return;
    const cap = p.cap == null || p.cap === "" ? null : Number(p.cap);
    if (!validCap(cap))
      throw new Error(`${kindWord(k)}: at once must be a whole number from 1 to ${MAX_CONCURRENT}, or empty.`);
    if (p.mode === info.mode && cap === (info.cap ?? null)) return;
    out[k] = { mode: p.mode, max_concurrent: cap };
  });
  return out;
}

// The capability chips of a card, in three styles: allowed (`kind-on`), denied (`kind-denied`, the title says by whom or what) and withheld after
// failing or too old (`kind-held`, the title says until when). A kind the Sentinel does not declare has no chip. Returns null when there is nothing to show.
export function kindChips(kinds) {
  const box = el("div", "chips sl-kinds", null, { role: "list", "aria-label": "Capabilities" });
  let n = 0;
  Object.entries(kinds || {}).forEach(([k, info]) => {
    const state = kindState(info);
    if (state === "unavailable") return;
    const tone =
      state === "on" ? "kind-on" : state === "cool_off" || state === "outdated" ? "kind-held" : "kind-denied";
    const word = `${kindWord(k)}${state === "on" && info.mode === "prefer" ? " (preferred)" : ""}${info.cap && state === "on" ? ` x${info.cap}` : ""}`;
    const note = kindNote(info);
    box.append(
      el("span", `chip ${tone}`, word, { role: "listitem", title: note, "aria-label": `${kindWord(k)}: ${note}` }),
    );
    n += 1;
  });
  return n ? box : null;
}

// The per-kind rows of the settings panel: Allow / Deny / Prefer and a cap each, the note of who decided, and "Use default" where the Sentinel has a policy of
// its own. A kind the Sentinel does not declare, or its machine turned off, shows why and offers nothing.
export function kindsPanel(kinds, onReset) {
  const box = el("div", "ss-pol", null, { role: "group", "aria-label": "What this Sentinel may take" });
  const rows = new Map();
  SENTINEL_KINDS.forEach((k) => {
    const row = el("div", "ss-pol-row");
    const note = el("span", "note ss-pol-note");
    const mode = el("select", "ss-pol-mode", null, { "aria-label": `${kindWord(k)} policy` });
    Object.entries(MODE_WORDS).forEach(([v, t]) => mode.append(el("option", "", t, { value: v })));
    const cap = text("", {
      type: "number", min: "1", max: String(MAX_CONCURRENT), step: "1", inputmode: "numeric",
      placeholder: "no limit", "aria-label": `${kindWord(k)} at once`,
    });
    const reset = button("Use default", async () => onReset(k), "btn sm ghost");
    row.append(el("b", "ss-pol-name", kindWord(k)), note, mode, cap, reset);
    box.append(row);
    rows.set(k, { row, note, mode, cap, reset });
  });
  // refill: the inputs take the server's values (after a save or a reset), never while someone is typing
  function paint(next, refill) {
    rows.forEach((r, k) => {
      const info = (next || {})[k];
      const offered = modesOffered(info).length > 0;
      r.row.setAttribute("data-state", kindState(info));
      r.note.textContent = kindNote(info);
      r.mode.hidden = r.cap.hidden = !offered;
      r.reset.hidden = !canReset(info);
      if (refill && info) {
        r.mode.value = info.mode || "allow";
        r.cap.value = info.cap == null ? "" : String(info.cap);
      }
    });
  }
  function read() {
    const picks = {};
    rows.forEach((r, k) => {
      if (!r.mode.hidden) picks[k] = { mode: r.mode.value, cap: r.cap.value.trim() };
    });
    return picks;
  }
  paint(kinds, true);
  return { node: box, paint, read };
}

// The version and update line of one card, and its "Update now" and "Settings" buttons. ``d`` is the agent detail; nothing is drawn
// when it does not report these keys.
// ``builtin`` (the install's own scanner) has no "Update now": it never updates itself, so the button would promise what cannot happen.
export function versionBlock(d, { onChange, builtin = false }) {
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
  if (builtin) box.append(el("p", "note ss-detail", "The built-in scanner never updates itself, so there is no Update now."));
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
  if (!builtin) actions.append(now);
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
  return text(value || "");
}

function readControl(key, node) {
  if (key === "max_concurrent")
    return node.value.trim() === "" ? undefined : Number(node.value);
  const v = node.value.trim();
  return v === "" ? undefined : v;
}

const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
const controlValue = (key, setting) =>
  key === "network" ? setting?.server_grant ?? setting?.value : setting?.value;

const ROWS = [
  ["name", "Name", "How it appears in cvENGINE."],
  [
    "network",
    "Where it runs",
    "Choose the server grant. Internal Sentinels scan declared private networks only when their machine setting allows it.",
  ],
  ["profile", "Size", "Light never runs OpenVAS."],
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
        "For most settings, the most recent change wins. Private network access comes from provisioning or an administrator, and the Sentinel's own setting can limit it. Changes reach the Sentinel within a heartbeat or so; this panel refreshes by itself.",
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
      const input = control(key, controlValue(key, d.settings[key]));
      const reset = button(
        key === "network" ? "Restore provisioned location" : "Reset to the Sentinel's value",
        async () => {
          if (
            !(await ask(
              key === "network"
                ? "Restore the network access granted when this Sentinel was provisioned? A Sentinel without an enrollment returns to external."
                : `Hand ${label.toLowerCase()} back to the Sentinel's own .env?`,
              { title: "Reset setting", ok: "Reset", danger: false },
            ))
          )
            return;
          d = await api("PATCH", detailUrl(d.id), {
            settings: { [key]: null },
          });
          toast(key === "network" ? "Provisioned network access restored" : `${label} handed back to the Sentinel`);
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
    let panel = null;
    if (d.kinds) {
      body.append(
        el("h4", "ss-pol-title", "What it may take"),
        el(
          "p",
          "note",
          "Allow offers the kind, Deny never does, Prefer also holds the work back from the others for a moment while this Sentinel has room. The number caps how many of that kind it runs at once. Only what the Sentinel declares can be enabled.",
        ),
      );
      panel = kindsPanel(d.kinds, async (kind) => {
        d = await api("PATCH", detailUrl(d.id), { settings: { kinds: { [kind]: null } } });
        toast(`${kindWord(kind)} handed back to the default`);
        paint(true);
        onChange();
      });
      body.append(panel.node);
    }
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
          const cur = controlValue(key, d.settings[key]);
          if (next !== undefined && !same(next, cur)) change[key] = next;
        });
        const kindChange = panel ? kindsChange(d.kinds, panel.read()) : {};
        if (Object.keys(kindChange).length) change.kinds = kindChange;
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
      if (panel) panel.paint(d.kinds, refill);
      rows.forEach((r, key) => {
        const s = d.settings[key];
        r.now.textContent = shown(key, s && s.value);
        r.src.textContent = sourceLine(s);
        r.reset.hidden = !(s && (key === "network" ? (s.managed ?? (s.source === "server")) : s.source === "server"));
        if (refill) {
          const fresh = control(key, controlValue(key, s));
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
