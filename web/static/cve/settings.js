// Admin settings: AI, API keys, Tailscale, OpenVAS, notifications, email, scan policy, proxy. Superuser only (the API enforces it).
// DOM is built with textContent / value only; secrets are write-only (blank keeps the stored value).
import { ask } from "/staticfiles/cve/ui.js";
import { openvasPanel } from "/staticfiles/cve/openvas-panel.js";
import { apiKeysPanel } from "/staticfiles/cve/api-keys-panel.js";

const root = document.getElementById("settings");
const csrf = root.querySelector("[name=csrfmiddlewaretoken]").value;
const API = "/cve/api/settings";

const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

async function api(method, path, body) {
  const res = await fetch(`${API}/${path}`, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    /* empty */
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function toast(message, isError = false) {
  const t = el("div", `toast${isError ? " err" : ""}`, message, {
    role: "status",
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// --- tiny form kit -------------------------------------------------------------
let uid = 0;
function field(label, input, help) {
  const id = `f${(uid += 1)}`;
  input.id = id;
  const wrap = el("div", "field");
  wrap.append(el("label", "", label, { for: id }), input);
  if (help) wrap.append(el("p", "note", help, { style: "margin:6px 0 0" }));
  return wrap;
}
const text = (value = "", attrs = {}) =>
  Object.assign(el("input", "", null, attrs), { value });
const secret = (isSet, label) =>
  el("input", "", null, {
    type: "password",
    autocomplete: "new-password",
    placeholder: isSet ? "saved (leave blank to keep)" : label || "not set",
  });
function check(label, checked) {
  const box = el("input", "", null, {
    type: "checkbox",
    style: "width:auto;min-height:0",
  });
  box.checked = !!checked;
  const wrap = el("label", "", null, {
    style:
      "display:flex;gap:10px;align-items:center;margin:0 0 12px;font-weight:400",
  });
  wrap.append(box, document.createTextNode(label));
  return { wrap, box };
}
function selectOf(options, value) {
  const s = el("select");
  options.forEach(([v, t]) =>
    s.append(Object.assign(el("option", "", t), { value: v })),
  );
  s.value = value == null ? "" : value;
  return s;
}
function button(label, onClick, cls = "btn") {
  const b = el("button", cls, label, { type: "button" });
  b.onclick = async () => {
    const idle = b.textContent;
    b.disabled = true;
    b.textContent = "Working…";
    try {
      await onClick();
    } catch (err) {
      toast(err.message, true);
    }
    b.textContent = idle;
    b.disabled = false;
  };
  return b;
}
const card = (title, ...kids) => {
  const c = el("div", "card");
  c.style.maxWidth = "640px";
  c.append(el("h2", "", title), ...kids);
  c.firstChild.style.marginBottom = "12px";
  return c;
};

// --- sections ------------------------------------------------------------------
const sections = {
  async ai(m) {
    const s = await api("GET", "ai");
    const LABELS = {
      anthropic: "Anthropic",
      openai: "OpenAI",
      openrouter: "OpenRouter",
      ollama: "Ollama",
      vllm: "vLLM",
      lmstudio: "LM Studio",
    };
    const provider = selectOf(
      s.providers.map((p) => [p, LABELS[p] || p]),
      s.provider,
    );
    const model = text(s.model, { list: "ai-models", autocomplete: "off" });
    const models = el("datalist", "", null, { id: "ai-models" });
    const modelNote = el("p", "note", "", { style: "margin:6px 0 0" });
    const key = secret(s.has_key, "API key");
    const base = text(s.base_url);
    const keyField = field("API key", key);
    const baseField = field("Base URL", base);
    const BASE_HINT = {
      ollama: "required, e.g. http://100.64.0.5:11434 (Tailscale or remote), or http://localhost:11434 if it runs on this server",
      vllm: "required, e.g. http://100.64.0.5:8000/v1, or http://localhost:8000/v1 if it runs on this server",
      lmstudio: "required, e.g. http://100.64.0.5:1234/v1, or http://localhost:1234/v1 if it runs on this server (the API key is only needed when you turned on authentication in LM Studio)",
      openrouter: "optional, defaults to https://openrouter.ai/api/v1",
    };
    const sync = () => {
      const p = provider.value;
      const pick = s.selectable.includes(p);
      model.placeholder = pick
        ? "choose a model (Load models)"
        : "automatic: newest, cheapest";
      modelNote.textContent = pick
        ? `${LABELS[p]} serves whichever models you pick or host, so choose one.`
        : `Leave blank for the newest cheapest ${LABELS[p]} model, or choose another.`;
      key.placeholder = s.keyless.includes(p)
        ? "optional"
        : s.has_key && p === s.provider
          ? "saved (leave blank to keep)"
          : "API key";
      base.placeholder = BASE_HINT[p] || "optional";
      baseField.style.display = ["anthropic", "openai"].includes(p) ? "none" : "";
      keyField.style.display = p === "ollama" ? "none" : "";
    };
    const load = async () => {
      const r = await api("POST", "ai/models", {
        provider: provider.value,
        api_key: key.value,
        base_url: base.value,
      });
      models.textContent = "";
      r.models.forEach((x) =>
        models.append(
          Object.assign(el("option"), {
            value: x.id,
            label:
              x.price != null ? `${x.id} ($${x.price.toFixed(2)}/M in)` : x.id,
          }),
        ),
      );
      modelNote.textContent =
        `${r.models.length} models available.` +
        (r.recommended ? ` Newest cheapest: ${r.recommended}.` : "");
      if (r.recommended && !model.value) model.placeholder = r.recommended;
    };
    provider.addEventListener("change", () => {
      model.value = "";
      models.textContent = "";
      sync();
    });
    sync();
    const enabled = check("Use this model to confirm CVE matches", s.enabled);
    const fire = check(
      "Auto-fire: on a new FIRE or SMOKE CVE, pick affected targets and test their hosts",
      s.auto_fire,
    );
    const max = text(s.auto_fire_max_scans, {
      type: "number",
      min: "1",
      max: "5000",
    });
    const planTotal = text(s.plan_daily_total, {
      type: "number",
      min: "0",
      max: "100000",
    });
    const planProject = text(s.plan_daily_per_project, {
      type: "number",
      min: "0",
      max: "100000",
    });
    const guideDaily = text(s.cve_guidance_daily, { type: "number", min: "0", max: "100000" });
    const gp = s.cve_guidance;
    const guideNote = el("p", "note", gp
      ? `${gp.cves.toLocaleString()} CVEs: guidance written by rules for ${gp.rules.toLocaleString()}, by the model for ${gp.ai.toLocaleString()}, by a person for ${gp.manual.toLocaleString()}. ${gp.local_only.toLocaleString()} are only usable from the host itself and never matched. ${gp.ai_pending.toLocaleString()} still wait for the model${gp.days_left ? `: about ${gp.days_left.toLocaleString()} day${gp.days_left === 1 ? "" : "s"} at ${gp.daily_budget.toLocaleString()} a day` : ""}. The model handled ${gp.ai_last_day.toLocaleString()} in the last day.`
      : "CVE guidance progress is not available yet.");
    const guideNow = text("200", { type: "number", min: "1", max: "5000" });
    const guideRun = button("Write now", async () => {
      const r = await api("POST", "cve_guidance/run", { count: guideNow.value });
      guideNote.textContent = `Queued: the model writes guidance for the next ${r.queued} CVEs. Progress shows here after a refresh.`;
    }, "btn ghost sm");
    const save = async () => {
      await api("PUT", "ai", {
        cve_guidance_daily: guideDaily.value,
        plan_daily_total: planTotal.value,
        plan_daily_per_project: planProject.value,
        provider: provider.value,
        model: model.value,
        api_key: key.value,
        base_url: base.value,
        enabled: enabled.box.checked,
        auto_fire: fire.box.checked,
        auto_fire_max_scans: max.value,
      });
      key.value = "";
      key.placeholder = "saved (leave blank to keep)";
    };
    m.append(
      card(
        "AI model",
        field("Provider", provider),
        (() => {
          const f = field("Model", model);
          f.append(models, modelNote, button("Load models", load, "btn ghost sm"));
          return f;
        })(),
        keyField,
        baseField,
        enabled.wrap,
        field("Validation planning requests per day, all projects", planTotal),
        field("Validation planning requests per day, one project", planProject),
        (() => {
          const f = field("CVE guidance written by the model per day (each CVE is one paid request; 0 turns it off)", guideDaily);
          f.append(guideNote);
          const row = el("div", "tools guide-now");
          row.append(el("span", "note", "Or, from what is left of today's budget, write the next"), guideNow, el("span", "note", "CVEs now"), guideRun);
          f.append(row);
          return f;
        })(),
        button("Save", async () => {
          await save();
          toast("Saved");
        }),
        document.createTextNode(" "),
        button(
          "Save and test",
          async () => {
            await save();
            const r = await api("POST", "ai/test");
            toast(`Connection OK: ${r.reply}`);
          },
          "btn ghost",
        ),
      ),
    );
    const seedState = await api("GET", "cve_seed");
    const seedNote = el("p", "note", "");
    const showSeed = (st) => {
      const b = st.built;
      seedNote.textContent = st.building
        ? "Building the seed: this takes a few minutes. Refresh to see it."
        : b
          ? `Last build ${new Date(b.generated_at).toLocaleString()}: ${b.count.toLocaleString()} CVEs (fire ${b.tiers.fire.toLocaleString()}, smoke ${b.tiers.smoke.toLocaleString()}, ice ${b.tiers.ice.toLocaleString()}), ${b.with_detection.toLocaleString()} with guidance, ${Math.round(b.bytes / 1048576)} MB.`
          : "No seed has been built on this server yet.";
    };
    showSeed(seedState);
    const seedLinks = el("div", "tools");
    if (seedState.file) {
      seedLinks.append(
        el("a", "btn ghost sm", "Download the seed", { href: "/cve/api/settings/cve_seed/download/seed" }),
        el("a", "btn ghost sm", "Download its manifest", { href: "/cve/api/settings/cve_seed/download/manifest" }),
      );
    }
    m.append(
      el("div", "", null, { style: "height:16px" }),
      card(
        "CVE catalog seed",
        el("p", "note", "A new install loads this file on first start, so it begins with every CVE and its guidance instead of rebuilding them one by one. Build it here once the guidance is written, then attach both files to the cve-seed release on GitHub (scripts/publish-cve-seed.sh does it from a machine with gh)."),
        seedNote,
        button("Build the seed", async () => {
          showSeed(await api("POST", "cve_seed/build").then(() => ({ building: true })));
          toast("Building the seed");
        }),
        seedLinks,
      ),
    );
    m.append(
      el("div", "", null, { style: "height:16px" }),
      card(
        "Auto-fire",
        fire.wrap,
        field("Max hosts tested per CVE", max),
        button("Save", async () => {
          await save();
          toast("Saved");
        }),
      ),
    );
  },

  async updates(m) {
    const host = el("div");
    const sourceHost = el("div");
    m.append(host, sourceHost);
    const when = (iso) => (iso ? new Date(iso).toLocaleString() : "never");
    const ago = (ms) => {
      const sec = Math.max(0, Math.round(ms / 1000));
      return sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${String(sec % 60).padStart(2, "0")} s`;
    };
    // What happens after Approve, in order, with what to expect. `at` is the step the host is on now (1 = waiting for the host).
    const UPDATE_STEPS = [
      ["Approved", "Done."],
      ["The host picks it up", "Within a few seconds once the host updater is installed. Nothing happens until it is."],
      ["New scans pause, running scans finish", "As long as the longest running scan: minutes for most, up to a few hours for a deep scan."],
      ["The files are updated", "About 10 seconds."],
      ["The services rebuild and restart", "2 to 5 minutes. The page greys out and comes back on its own."],
      ["Scanning resumes", "Immediately; the page reloads."],
    ];
    const SETUP_COMMAND = "cd /opt/cvengine && git pull --ff-only && sudo scripts/install-updater.sh";
    const stepAt = (s, hu) => {
      if (s.phase === "resuming" || s.phase === "done") return 5;
      if (s.phase === "applying") return /^merging/.test(s.phase_detail || "") ? 3 : 4;
      if (s.phase === "draining" && !/could not reach|local changes/.test(s.phase_detail || "")) return 2;
      return 1;
    };
    const copyButton = (value) =>
      button("Copy command", async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast("Copied");
        } catch (_) {
          toast("Select the command and copy it");
        }
      }, "btn ghost");
    // Shown while no host updater is listening: say what is missing and give the one command that fixes it.
    const setupBox = (s) => {
      const box = el("div", "", null, { style: "border:1px solid var(--border,#ccc);border-radius:8px;padding:12px 14px;margin:12px 0" });
      box.append(
        el("p", "", "One-time setup on the server", { style: "font-weight:600;margin:0 0 6px" }),
        el("p", "note", "CVEngine cannot restart itself: the web app has no Docker access on purpose. A small script on the server does the update, and it is not installed or not running there, so Approve has nothing to wake. Run this once on the server, as the user that owns the CVEngine folder (adjust the folder if it is not /opt/cvengine):"),
        el("pre", "", SETUP_COMMAND, { style: "margin:8px 0;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;user-select:all;font-size:13px;background:var(--surface-2,#f4f4f4);border-radius:6px" }),
        el("p", "note", s.status === "approved" ? "It pulls this version, starts the watcher, and applies the update you approved straight away. From then on every update starts within seconds of Approve and nothing more is needed on the server." : "It pulls this version and starts the watcher. After that, Approve starts an update within seconds and nothing more is needed on the server."),
        copyButton(SETUP_COMMAND),
      );
      return box;
    };
    const timeline = (s, hu) => {
      const at = stepAt(s, hu);
      const wrap = el("div", "", null, { style: "margin:12px 0" });
      const waited = s.approved_at ? Date.now() - Date.parse(s.approved_at) : 0;
      wrap.append(el("p", "", `Approved ${ago(waited)} ago. Typical total once the host is listening and no scan is running: about 3 to 6 minutes.`, { style: "margin:0 0 8px;font-weight:500" }));
      const list = el("ol", "", null, { style: "list-style:none;margin:0;padding:0" });
      UPDATE_STEPS.forEach(([title, expect], i) => {
        const blocked = i === 1 && at === 1 && !hu.alive;
        const mark = i < at ? "\u2713" : i === at ? (blocked ? "!" : "\u25CF") : "\u25CB";
        const live = i === at ? (s.phase_detail && !blocked ? ` ${s.phase_detail}.` : blocked ? " Not happening: no host updater is listening." : "") : "";
        const row = el("li", "", null, { style: `display:flex;gap:10px;padding:4px 0;${i > at ? "opacity:.55" : ""}` });
        row.append(
          el("span", "", mark, { style: "width:1.2em;flex:none;text-align:center", "aria-hidden": "true" }),
          el("span", "", null),
        );
        row.lastChild.append(el("strong", "", title), el("span", "note", ` ${i < at ? "Done." : expect}${live}`));
        list.append(row);
      });
      wrap.append(list);
      return wrap;
    };
    let timer = 0;
    const draw = (s) => {
      clearTimeout(timer);
      host.textContent = "";
      const head = {
        up_to_date: "CVEngine is up to date.",
        available: "A newer version is available.",
        dismissed: "A newer version is available (dismissed).",
        approved: "Update approved. Waiting for the host updater to apply it.",
        error: "The last check failed.",
        unknown: "Whether a newer version is available cannot be told.",
        disabled: "Update checks are turned off.",
      }[s.status];
      const kids = [el("p", "", head, { style: "font-weight:500;margin:0 0 6px" })];
      kids.push(
        el(
          "p",
          "note",
          `Installed ${s.installed_known ? s.installed : "unknown"}, latest ${s.latest || "unknown"} on ${s.repo}@${s.branch}. Last checked ${when(s.last_checked_at)}.`,
        ),
      );
      if (s.last_error) kids.push(el("p", "msg err", s.last_error));
      const hu = s.host_updater || {};
      // How updates are installed. Manual is the default: the code of this server never changes unless an administrator chose Automatic.
      const modeBox = el("fieldset", "", null, { style: "border:0;padding:0;margin:12px 0" });
      modeBox.append(el("legend", "", "How updates are installed", { style: "font-weight:600;padding:0;margin-bottom:6px" }));
      [
        ["manual", "Manual", "CVEngine tells you when a new version exists. Nothing is installed until you click Approve."],
        ["auto", "Automatic", "When the twice-daily check finds a new version, CVEngine approves it and the server installs it shortly after: scans pause and finish first, then the services restart. The code on this server changes without you being asked."],
      ].forEach(([value, label, help]) => {
        const row = el("label", "", null, { style: "display:flex;gap:10px;align-items:flex-start;margin:6px 0;cursor:pointer" });
        const radio = el("input", "", null, { type: "radio", name: "update-mode", value });
        radio.checked = (s.mode || "manual") === value;
        radio.onchange = async () => {
          try {
            draw(await api("PUT", "updates", { mode: value }));
            toast(value === "auto" ? "Updates are now installed automatically" : "Updates are now manual");
          } catch (err) {
            toast(err.message);
            draw(s);
          }
        };
        const text = el("span", "");
        text.append(el("strong", "", label), el("span", "note", ` ${help}`));
        row.append(radio, text);
        modeBox.append(row);
      });
      kids.push(modeBox);
      // The web interface certificate renews itself 30 days before it ends (the host's renewal check); this speaks up only when it did not.
      const cert = s.certificate || {};
      if (cert.problem) kids.push(el("p", "msg err", cert.problem));
      else if (cert.known && cert.days_left != null)
        kids.push(el("p", "note", `Web interface certificate: valid for ${cert.days_left} more days, renewed automatically when fewer than 30 remain${cert.last_renewed_at ? ` (last renewed ${when(cert.last_renewed_at)})` : ""}.`));
      if (s.mode === "auto" && !hu.alive)
        kids.push(el("p", "msg err", "Automatic needs something on the server to install the update: the host updater (below), or automatic deployment (scripts/install-auto-deploy.sh). The host updater is not reporting; if this server uses automatic deployment you can ignore this."));
      if (["available", "dismissed", "approved", "up_to_date"].includes(s.status)) {
        if (hu.alive) {
          kids.push(el("p", "note", `Host updater: listening (last seen ${hu.age_seconds} s ago). An approved update starts within seconds.`));
        } else if (hu.seen) {
          kids.push(el("p", "msg err", `The host updater stopped reporting ${Math.max(1, Math.round(hu.age_seconds / 60))} minutes ago, so an approved update will not start. On the server, check that cron is running and run scripts/install-updater.sh.`));
        } else if (s.status !== "up_to_date") {
          kids.push(el("p", "msg err", "The host updater has not reported in, so Approve will not start anything yet."));
        }
        if (!hu.alive && s.status !== "up_to_date") kids.push(setupBox(s));
      }
      if (s.status === "approved") kids.push(timeline(s, hu));
      // a server with commits of its own cannot be moved forward for the administrator: say what to do, never offer Approve
      if (s.local_commits > 0 && s.behind_by > 0 && ["diverged", "dismissed"].includes(s.status))
        kids.push(el("p", "msg err", `The branch has ${s.behind_by} new commit${s.behind_by === 1 ? "" : "s"}, but this server has ${s.local_commits} of its own on top of ${s.common || "it"}, so an update cannot be applied for you (it moves the checkout forward and never merges). On the server run git fetch origin, then git merge origin/${s.branch}, then scripts/update.sh or make up.`));
      else if (s.local_commits > 0 && s.status === "up_to_date")
        kids.push(el("p", "note", `This server has ${s.local_commits} commit${s.local_commits === 1 ? "" : "s"} of its own on top of ${s.branch}; everything on the branch is included.`));
      if (s.status === "unknown" && !s.last_error)
        kids.push(el("p", "msg err", "Whether this server is behind cannot be told: GitHub has never seen the commit it was built from (commits of its own that were not pushed), and the host has not said which commit it shares with the branch. The host updater reports that within half an hour of running; if it is not installed, run scripts/install-updater.sh."));
      if (s.host_comparison) kids.push(el("p", "note", s.host_comparison));
      if (["available", "dismissed", "approved", "diverged"].includes(s.status)) {
        kids.push(
          el(
            "p",
            "",
            `${s.latest_message}${s.behind_by ? ` (${s.behind_by} commit${s.behind_by === 1 ? "" : "s"} ahead)` : ""}`,
            { style: "margin:10px 0 4px" },
          ),
        );
        if (s.commits.length) {
          const list = el("ul", "note", null, { style: "margin:0 0 10px;padding-left:18px" });
          s.commits.forEach((c) => list.append(el("li", "", `${c.sha}  ${c.message}`)));
          kids.push(list);
        }
        if (s.latest_url) kids.push(el("a", "note", "View on GitHub", { href: s.latest_url, target: "_blank", rel: "noopener noreferrer", style: "display:block;margin:0 0 14px" }));
      }
      if (s.branch_warning) kids.push(el("p", "msg err", s.branch_warning, { style: "margin-top:10px" }));
      if (s.status === "approved") {
        kids.push(
          el("p", "note", s.approved_by === "automatic" ? `Approved automatically at ${when(s.approved_at)} because updates are set to Automatic.` : `Approved by ${s.approved_by} at ${when(s.approved_at)}.`, { style: "margin-top:10px" }),
          button("Cancel approval", async () => { draw(await api("POST", "updates/cancel")); toast("Approval cancelled"); }, "btn ghost"),
        );
      } else if (["available", "dismissed"].includes(s.status)) {
        kids.push(
          button("Approve update", async () => {
            const note = (s.branch_warning ? s.branch_warning + " " : "") + (hu.alive
              ? "Scans are paused, running ones finish, then the host rebuilds and restarts the services."
              : "The host updater is not reporting, so nothing will start until it is installed on the server (scripts/install-updater.sh).");
            if (!(await ask(note, { title: `Update CVEngine to ${s.latest}?`, ok: "Approve update", danger: false }))) return;
            draw(await api("POST", "updates/approve"));
            toast("Approved");
          }),
        );
        if (s.status === "available")
          kids.push(document.createTextNode(" "), button("Dismiss", async () => { draw(await api("POST", "updates/dismiss")); }, "btn ghost"));
      }
      kids.push(document.createTextNode(" "), button("Check now", async () => { draw(await api("POST", "updates/check")); toast("Checked"); }, "btn ghost"));
      host.append(card("Updates", ...kids));
      if (s.status === "approved")
        timer = setTimeout(async () => {
          if (!host.isConnected) return;
          try {
            draw(await api("GET", "updates"));
          } catch (_) {
            timer = setTimeout(() => draw(s), 4000); // the services restart during an update: keep trying
          }
        }, 4000);
    };
    const drawSource = (s) => {
      const enabled = check("Check GitHub for updates twice a day", s.enabled);
      const repo = text(s.repo);
      const branch = text(s.branch);
      const token = secret(s.has_token, "only for a private repository");
      sourceHost.append(
        el("div", "", null, { style: "height:16px" }),
        card(
          "Update source",
          enabled.wrap,
          field("GitHub repository (owner/name)", repo),
          field("Branch", branch, "Changing it makes the next approved update move this server to that branch, when that is safe (it must keep every database migration that is installed). If it is not, Settings says why and nothing moves."),
          field("Access token", token, "A fine-grained token with read-only Contents access. Stored write-only."),
          button("Save", async () => {
            const changed = repo.value !== s.repo || branch.value !== s.branch;
            let next = await api("PUT", "updates", { enabled: enabled.box.checked, repo: repo.value, branch: branch.value, token: token.value });
            if (changed) next = await api("POST", "updates/check"); // a different source: look at it straight away
            draw(next);
            toast(changed ? "Saved, and checked the new source" : "Saved");
          }),
        ),
      );
    };
    const first = await api("GET", "updates");
    drawSource(first);
    draw(first);
  },

  async reset(m) {
    const s = await api("GET", "factory_reset");
    const list = el("ul", "note", null, { style: "margin:6px 0 12px;padding-left:18px" });
    [
      `${s.organizations} organization${s.organizations === 1 ? "" : "s"} and ${s.projects} project${s.projects === 1 ? "" : "s"}`,
      `${s.targets} target${s.targets === 1 ? "" : "s"}, ${s.hosts} host${s.hosts === 1 ? "" : "s"} and ${s.scans} scan${s.scans === 1 ? "" : "s"} with all their results, files and screenshots`,
      `${s.users} other user${s.users === 1 ? "" : "s"}, memberships and API tokens`,
      "the AI model settings, API keys, notification, email, proxy and report settings, IP allowlist and bans",
      "the CVE feed, matches, generated checks, AI activity, audit log, scheduled scans and update settings",
    ].forEach((t) => list.append(el("li", "", t)));
    const keep = el(
      "p",
      "note",
      "Kept: your own account (same password and two-step sign-in), the scan engines and installed tools. Afterwards you land in the setup wizard, as on a new install. This cannot be undone.",
      { style: "margin:0 0 18px" },
    );
    const phrase = text("", { placeholder: s.phrase, autocomplete: "off", spellcheck: "false" });
    const password = el("input", "", null, { type: "password", autocomplete: "current-password" });
    const force = check(
      `${s.running_scans} scan${s.running_scans === 1 ? " is" : "s are"} still running or queued: reset anyway`,
      false,
    );
    const go = button(
      "Reset to factory settings",
      async () => {
        const r = await api("POST", "factory_reset", {
          confirm: phrase.value,
          password: password.value,
          force: force.box.checked,
        });
        password.value = "";
        toast("Reset complete");
        location.href = r.redirect;
      },
      "btn danger",
    );
    const kids = [
      el("p", "", "This removes everything below and starts the instance over.", { style: "font-weight:500;margin:0" }),
      list,
      keep,
      field(`Type ${s.phrase} to confirm`, phrase),
      field("Your password", password),
    ];
    if (s.running_scans) kids.push(force.wrap);
    kids.push(go);
    m.append(card("Factory reset", ...kids));
  },

  async resources(m) {
    const host = el("div");
    m.append(host);
    const mb = (v) => (v == null ? "?" : v >= 1024 ? `${(v / 1024).toFixed(1)} GB` : `${v} MB`);
    const secs = (n) => (n >= 3600 ? `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m` : n >= 60 ? `${Math.floor(n / 60)}m ${n % 60}s` : `${n}s`);
    const list = (title, rows, empty) => {
      const wrap = el("div", "", null, { style: "margin-top:12px" });
      wrap.append(el("p", "sec", title));
      if (!rows.length) wrap.append(el("p", "note", empty));
      rows.forEach((r) => wrap.append(el("div", "find", r)));
      return wrap;
    };
    const draw = (snap) => {
      host.textContent = "";
      if (!snap.containers.length) {
        host.append(card("Resources", el("p", "note", "No worker has reported yet. The celery worker publishes its memory every 30 seconds.")));
        return;
      }
      snap.containers.forEach((c) => {
        const mem = c.memory || {};
        const total = mem.total_mb || 1;
        const pct = Math.min(100, Math.round(((mem.used_mb || 0) / total) * 100));
        const bar = el("div", "", null, { style: "height:12px;border-radius:3px;background:var(--sunk);overflow:hidden;margin:8px 0" });
        const fill = el("div", "", null, { style: `height:100%;width:${pct}%;transition:width .6s ease;background:${pct > 90 ? "var(--fire)" : pct > 75 ? "var(--smoke)" : "var(--ok)"}` });
        bar.append(fill);
        const kids = [
          el("p", "", `${mb(mem.used_mb)} used of ${mb(mem.limit_mb || mem.total_mb)}${mem.limit_mb ? " (container limit)" : ""}; ${mb(mem.available_mb)} free`, { style: "margin:0;font-weight:500" }),
          bar,
          el("p", "note", `Heavy jobs (bbot, nmap, nuclei) start only while their estimated memory fits the budget of ${mb(c.budget_mb)} and ${mb(c.headroom_mb)} stays free. If free memory drops under ${mb(c.critical_mb)}, the biggest job is stopped and retried lighter, so the worker is never lost.`),
          list(
            `Running (${c.running.length})`,
            c.running.map((j) => `${j.label}: reserved ${mb(j.reserved_mb)}, using ${mb(j.rss_mb)}, ${secs(j.seconds)}`),
            "Nothing heavy is running.",
          ),
          list(
            `Waiting for memory (${c.waiting.length})`,
            c.waiting.map((j) => `${j.label}: needs ${mb(j.needs_mb)}, waiting ${secs(j.seconds)}`),
            "Nothing is waiting.",
          ),
          list(
            `Stopped for memory in the last 24 hours (${c.memory_kills.length})`,
            c.memory_kills.map((k) => `${new Date(k.t * 1000).toLocaleTimeString()}  ${k.kind} on ${k.label}: used ${mb(k.rss_mb)}, ${mb(k.available_mb)} free`),
            "None. The queue is keeping up.",
          ),
        ];
        if (c.age_seconds > 120) kids.push(el("p", "msg err", `This worker last reported ${secs(c.age_seconds)} ago.`));
        host.append(card(`Container ${c.host}`, ...kids), el("div", "", null, { style: "height:16px" }));
      });
      host.append(
        card(
          "Tuning",
          el("p", "note", "Container ceilings come from CELERY_MEM_LIMIT, WEB_MEM_LIMIT and BEAT_MEM_LIMIT (docker-compose, default 4g, 1g, 512m). Memory reserved per job (an estimate at first, raised to what real runs needed): " +
            Object.entries(snap.costs_mb || {}).map(([k, v]) => `${k} ${mb(v)}`).join(", ") +
            ". Override with HEAVY_COST_SCALE, HEAVY_MEMORY_BUDGET_MB or HEAVY_COST_<KIND>_MB in the celery environment. DISCOVERY_CONCURRENCY (default 3) sets how many discoveries may queue at once."),
        ),
      );
    };
    let timer = null;
    const refresh = async () => {
      try {
        draw(await api("GET", "resources"));
      } catch (err) {
        host.textContent = "";
        host.append(el("p", "msg err", err.message));
      }
      if (document.body.contains(host)) timer = setTimeout(refresh, 5000);
    };
    await refresh();
  },

  async tailscale(m) {
    const wrap = el("div");
    m.append(wrap);
    const lines = (box) => box.value.split(/[\s,]+/).filter(Boolean);
    const when = (iso) => (iso ? new Date(iso).toLocaleString() : "never");
    const statusBadge = (l) => {
      const cls = { ok: "", partial: "medium", error: "failed", never: "" }[l.last_status] || "";
      const word = { ok: "synced", partial: "synced with notes", error: "error", never: "not synced yet" }[l.last_status] || l.last_status;
      return el("span", `badge ${cls}`.trim(), l.enabled ? word : "off");
    };
    // one card: an existing link, or (link === null) the form that connects a tailnet to a project
    const linkCard = (link, projects, redraw) => {
      const l = link || {};
      const project = link
        ? null
        : selectOf(projects.map((p) => [p.id, p.org ? `${p.name} (${p.org})` : p.name]), projects[0] && projects[0].id);
      const kind = l.credential_kind;
      const clientId = text("", { autocomplete: "off", placeholder: kind === "oauth" ? "saved (leave blank to keep)" : "OAuth client id" });
      const clientSecret = secret(kind === "oauth", "OAuth client secret");
      const token = secret(kind === "token", "or an API access token (tskey-api-...)");
      const routing = selectOf(
        [
          ["auto", "This server's Tailscale node (the compose `tailscale` profile)"],
          ["host", "Already routed: the Docker host is on the tailnet"],
        ],
        l.routing || "auto",
      );
      const enabled = check("Keep this project's targets in step with the tailnet (sync every 15 minutes)", link ? l.enabled : true);
      const local = check("Also read this server's own Tailscale node (the compose `tailscale` profile), no credential needed", link ? l.use_local : true);
      const policy = check("Read the tailnet policy file for tailnet-wide findings (needs the policy_file:read scope)", link ? l.check_policy : true);
      const auto = check("Auto-scan: queue the normal discovery and scan pipeline for new and changed online devices", !!l.auto_scan);
      const cap = text(l.max_devices || 100, { type: "number", min: "1", max: "5000" });
      const onlyTags = text((l.only_tags || []).join(" "), { placeholder: "tag:server tag:prod (empty: any device)" });
      const skipTags = text((l.skip_tags || []).join(" "), { placeholder: "tag:printer" });
      const onlyOs = text((l.only_os || []).join(" "), { placeholder: "linux windows (empty: any)" });
      const body = () => ({
        enabled: enabled.box.checked,
        use_local: local.box.checked,
        routing: routing.value,
        check_policy: policy.box.checked,
        auto_scan: auto.box.checked,
        max_devices: cap.value,
        only_tags: lines(onlyTags),
        skip_tags: lines(skipTags),
        only_os: lines(onlyOs),
        client_id: clientId.value,
        client_secret: clientSecret.value,
        access_token: token.value,
      });
      const pid = () => (link ? l.project.id : project.value);
      const kids = [];
      if (link) {
        const status = el("div", "", null, { style: "display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px" });
        status.append(
          statusBadge(l),
          el("span", "note", `${l.tailnet || "tailnet not named yet"}: ${l.device_count} device${l.device_count === 1 ? "" : "s"} on the tailnet, ${l.imported} imported (${l.online} online, ${l.offline} offline, ${l.departed} departed). Last sync ${when(l.last_sync_at)}.`, { style: "margin:0" }),
        );
        kids.push(status);
        if (l.last_error) kids.push(el("p", "msg err", l.last_error));
        if (!l.scan_reachable) kids.push(el("p", "note", "Scans cannot reach this tailnet yet, so its devices are listed and checked but not scanned."));
        const node = l.local && l.local.backend_state ? `This server's node is ${l.local.backend_state}${l.local.self_name ? ` as ${l.local.self_name}` : ""}, running Tailscale ${l.local.version || "?"}.` : "";
        if (node) kids.push(el("p", "note", node));
      } else {
        kids.push(field("Project the tailnet's devices become targets of", project));
      }
      kids.push(
        el("p", "note", "Credentials are stored encrypted and never shown again. Create an OAuth client with only these read-only scopes: devices:core:read, devices:routes:read, policy_file:read and devices:posture_attributes:read (policy_file:read needs the other two).", { style: "margin:0 0 10px" }),
        field("OAuth client id", clientId),
        field("OAuth client secret", clientSecret),
        field("API access token (alternative to an OAuth client)", token, "An access token expires after at most 90 days; an OAuth client does not and can be revoked."),
        enabled.wrap,
        field("How scans reach the tailnet", routing, "Scanning needs a route: with the compose profile this server joins the tailnet itself. Choose Already routed only if the Docker host is on the tailnet and containers can reach 100.x addresses through it; that is taken on your word. Without a route devices are still listed and checked from API data, but never scanned."),
        local.wrap,
        policy.wrap,
        auto.wrap,
        field("Most devices one sync imports or queues for scanning", cap, "The rest follow on the next sync. Existing devices are always kept up to date."),
        field("Only devices tagged", onlyTags),
        field("Never devices tagged", skipTags),
        field("Only these operating systems", onlyOs),
        el("p", "note", "Devices shared into your tailnet from another tailnet are never imported, and neither is this server's own node. Hosts excluded for the organization are never added or scanned.", { style: "margin:0 0 12px" }),
      );
      const out = el("p", "note", "", { style: "margin:8px 0 0" });
      const actions = el("div", "", null, { style: "display:flex;gap:8px;flex-wrap:wrap" });
      actions.append(
        button(link ? "Save" : "Connect", async () => {
          if (!link && !project.value) throw new Error("Choose a project first");
          await api("PUT", `tailscale/${pid()}`, body());
          toast("Saved");
          await redraw();
        }),
        button("Test connection", async () => {
          const r = await api("POST", `tailscale/${pid()}/test`, body());
          out.className = r.ok ? "note" : "msg err";
          out.textContent = r.ok
            ? `Connected${r.tailnet ? ` to ${r.tailnet}` : ""}: ${r.devices} device${r.devices === 1 ? "" : "s"}.${r.policy ? ` Policy file: ${r.policy}.` : ""}${r.local && r.local.backend_state ? ` This server's node: ${r.local.backend_state}.` : ""}${r.local && r.local.error ? ` This server's node: ${r.local.error}.` : ""}`
            : r.error;
        }, "btn ghost"),
      );
      if (link) {
        actions.append(
          button("Sync now", async () => {
            await api("POST", `tailscale/${pid()}/sync`);
            toast("Sync queued: refresh in a minute");
          }, "btn ghost"),
          button("Disconnect", async () => {
            if (!(await ask("The project keeps its targets and findings; the devices are archived and their tailnet addresses can no longer be scanned.", { title: "Disconnect this tailnet?", ok: "Disconnect" }))) return;
            await api("DELETE", `tailscale/${pid()}`);
            toast("Disconnected");
            await redraw();
          }, "btn ghost"),
        );
      }
      return card(link ? `Tailnet of ${l.project.name}` : "Connect a tailnet", ...kids, actions, out);
    };
    const draw = async () => {
      wrap.textContent = "";
      const s = await api("GET", "tailscale");
      wrap.append(
        card(
          "Tailscale",
          el("p", "note", "Connect a tailnet to a project and its devices become targets automatically, are scanned like any other host and are checked for Tailscale-specific problems (outdated clients with known security fixes, key expiry, stale devices, broad subnet routes, an allow-all policy, broad SSH rules). Connecting is what authorises scanning the addresses of the devices it imports (100.64.0.0/10 and fd7a:115c:a1e0::/48), and nothing else in those ranges."),
          el("p", "note", "Scanning needs this server's own Tailscale node (the compose `tailscale` profile, see docs/TAILSCALE.md) or a Docker host that is already on the tailnet. Without a route, devices are still listed and checked from API data, but never scanned."),
        ),
        el("div", "", null, { style: "height:16px" }),
      );
      s.links.forEach((link) => {
        wrap.append(linkCard(link, [], draw), el("div", "", null, { style: "height:16px" }));
      });
      if (s.projects.length) wrap.append(linkCard(null, s.projects, draw));
    };
    await draw();
  },

  async openvas(m) {
    await openvasPanel(m);
  },

  async keys(m) {
    await apiKeysPanel(m);
  },

  async notifications(m) {
    const s = await api("GET", "notifications");
    const hooks = {
      slack_hook_url: secret(s.has_slack_hook_url, "Slack webhook URL"),
      discord_hook_url: secret(s.has_discord_hook_url, "Discord webhook URL"),
      lark_hook_url: secret(s.has_lark_hook_url, "Lark webhook URL"),
      telegram_bot_token: secret(
        s.has_telegram_bot_token,
        "Telegram bot token",
      ),
      telegram_bot_chat_id: secret(
        s.has_telegram_bot_chat_id,
        "Telegram chat id",
      ),
    };
    const labels = {
      slack_hook_url: "Slack webhook",
      discord_hook_url: "Discord webhook",
      lark_hook_url: "Lark webhook",
      telegram_bot_token: "Telegram bot token",
      telegram_bot_chat_id: "Telegram chat id",
    };
    const flags = {};
    const channelKits = [
      ["send_to_slack", "Send to Slack"],
      ["send_to_discord", "Send to Discord"],
      ["send_to_lark", "Send to Lark"],
      ["send_to_telegram", "Send to Telegram"],
    ].map(([f, l]) => {
      flags[f] = check(l, s[f]);
      return flags[f].wrap;
    });
    const eventKits = [
      ["send_scan_status_notif", "Scan status"],
      ["send_vuln_notif", "New vulnerabilities"],
      ["send_interesting_notif", "Interesting findings"],
      ["send_subdomain_changes_notif", "Subdomain changes"],
      ["send_scan_output_file", "Attach scan output files"],
      ["send_scan_tracebacks", "Include tracebacks"],
    ].map(([f, l]) => {
      flags[f] = check(l, s[f]);
      return flags[f].wrap;
    });
    m.append(
      card(
        "Notifications",
        el("h3", "", "Channels", { style: "font-size:14px;margin:0 0 8px" }),
        ...channelKits,
        ...Object.entries(hooks).map(([k, input]) => field(labels[k], input)),
        el("h3", "", "Send notifications for", {
          style: "font-size:14px;margin:16px 0 8px",
        }),
        el(
          "p",
          "note",
          "These channels are shared by the whole instance, not by one project. New vulnerabilities sends at most one message per feed sync for fire-level CVE matches on your hosts, one message per auto-fire run for the hosts its template tests confirmed vulnerable (batched, however many CVEs ran), and one per scan; each names a few hosts and counts the rest. A message can therefore mention hosts of several projects.",
          { style: "margin:0 0 8px" },
        ),
        ...eventKits,
        button("Save", async () => {
          const body = {};
          Object.entries(flags).forEach(([f, c]) => {
            body[f] = c.box.checked;
          });
          Object.entries(hooks).forEach(([k, input]) => {
            if (input.value) body[k] = input.value;
          });
          await api("PUT", "notifications", body);
          Object.values(hooks).forEach((i) => {
            i.value = "";
            i.placeholder = "saved (leave blank to keep)";
          });
          toast("Saved");
        }),
      ),
    );
  },

  async email(m) {
    const s = await api("GET", "email");
    const on = check(
      "Send email (people you add get an onboarding email with a link to choose their password)",
      s.enabled,
    );
    const host = text(s.host, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      placeholder: "smtp.example.com",
    });
    const port = text(String(s.port), { inputmode: "numeric" });
    const security = selectOf(
      [
        ["starttls", "STARTTLS (usually port 587)"],
        ["ssl", "SSL/TLS (usually port 465)"],
        ["none", "None (port 25 relay, no login)"],
      ],
      s.security,
    );
    const user = text(s.username, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
    });
    const pass = secret(s.has_password, "not set");
    const fromAddress = text(s.from_address, {
      type: "email",
      autocomplete: "off",
      placeholder: "cvengine@example.com",
    });
    const fromName = text(s.from_name, { placeholder: "cvENGINE" });
    const verify = check(
      "Verify the server certificate (turn off only for a relay you trust that uses a private or self-signed certificate)",
      s.verify_certificate,
    );
    const linkBase = text(s.link_base, {
      autocomplete: "off",
      spellcheck: "false",
      autocapitalize: "none",
      placeholder: s.link_effective,
    });
    const status = el("p", "note", "", { style: "margin:12px 0 0" });
    const showTest = (t) => {
      status.textContent = t
        ? `Last test ${t.ok ? "worked" : "failed"} (${new Date(t.at).toLocaleString()}, to ${t.to})${t.ok ? "." : `: ${t.error}`}`
        : "No test message sent yet.";
      status.className = `note${t && !t.ok ? " err" : ""}`;
    };
    showTest(s.last_test);
    const body = () => {
      const b = {
        enabled: on.box.checked,
        host: host.value,
        port: port.value,
        security: security.value,
        username: user.value,
        from_address: fromAddress.value,
        from_name: fromName.value,
        verify_certificate: verify.box.checked,
        link_base: linkBase.value,
      };
      if (pass.value) b.password = pass.value;
      return b;
    };
    const save = async () => {
      await api("PUT", "email", body());
      pass.value = "";
      pass.placeholder = "saved (leave blank to keep)";
    };
    const to = text("", {
      type: "email",
      autocomplete: "off",
      placeholder: "your own address",
    });
    m.append(
      card(
        "Email",
        el(
          "p",
          "note",
          "The mail server cvENGINE sends through. When someone is added with an email address, they receive their username and a one-time link to choose a password, so no password is handed around. With mail off, or no address on the account, you are shown a temporary password as before. The password is write-only: once saved it is never shown again.",
          { style: "margin:0 0 12px" },
        ),
        on.wrap,
        field("Mail server", host),
        field("Port", port),
        field("Security", security),
        field("User name", user, "Leave empty for a relay that needs no login."),
        field("Password", pass),
        field("From address", fromAddress),
        field("From name", fromName),
        verify.wrap,
        field(
          "Link address (optional)",
          linkBase,
          `Links in the email start with this address. Leave empty to use ${s.link_effective}, built from this server's DOMAIN_NAME. Set it when people reach cvENGINE at a different address, such as https://scanner.example.com.`,
        ),
        button("Save", async () => {
          await save();
          toast("Saved");
        }),
        el("h3", "", "Send a test message", {
          style: "font-size:14px;margin:20px 0 8px",
        }),
        field(
          "Send it to",
          to,
          "Saves the settings above first. Empty sends it to the address on your own account.",
        ),
        button(
          "Send test message",
          async () => {
            await save();
            const r = await api("POST", "email/test", { to: to.value });
            showTest(r.last_test);
            toast(
              r.ok ? `Test message sent to ${r.to}` : r.error,
              !r.ok,
            );
          },
          "btn ghost",
        ),
        status,
      ),
    );
  },

  async scan_policy(m) {
    const policy = await api("GET", "scan_policy");
    const everything = check(
      "Let scans run every Nuclei template that is installed (turn off to run only the read-only ones)",
      policy.nuclei_all_templates,
    );
    const policyCard = card(
      "Nuclei templates",
      el(
        "p",
        "note",
        "By default scans run the whole template library Nuclei ships, including checks that send requests other than plain reads. Turn this off to run only templates that read (plain GET, HEAD or OPTIONS requests to the scanned host). Templates the AI writes always stay read-only, and Nuclei's denial-of-service templates stay excluded.",
      ),
      everything.wrap,
      button("Save", async () => {
        await api("PUT", "scan_policy", {
          nuclei_all_templates: everything.box.checked,
        });
        toast("Saved");
      }),
    );
    policyCard.style.maxWidth = "none";
    m.append(policyCard);
    m.append(
      el(
        "p",
        "note",
        "Every scan runs the same fixed pipeline (discovery, nmap, the read-only checks, correlation, triage). There are no per-scan engines to edit: earlier versions listed editable engine configurations inherited from reNgine, but nothing ever read them, so they were removed.",
      ),
    );
  },

  async ip_allowlist(m) {
    const wrap = el("div");
    m.append(wrap);
    const draw = async () => {
      wrap.textContent = "";
      const s = await api("GET", "ip_allowlist");
      const use = check(
        `Restrict access to the IPs/CIDRs below (your current IP: ${s.your_ip})`,
        s.enabled,
      );
      const rows = el("div", "grid");
      s.entries.forEach((e) => {
        const row = el("div");
        row.append(
          el("span", "", e.label ? `${e.cidr} (${e.label})` : e.cidr),
          document.createTextNode(" "),
          button(
            "Remove",
            async () => {
              await api("DELETE", `ip_allowlist/entries/${e.id}`);
              toast("Removed");
              await draw();
            },
            "btn ghost sm",
          ),
        );
        rows.append(row);
      });
      const cidr = text("", {
        placeholder: "e.g. 203.0.113.4 or 203.0.113.0/24",
      });
      const label = text("", { placeholder: "optional label" });
      const addRow = el("div", "inline-add");
      addRow.append(
        cidr,
        label,
        button(
          "Add my current IP",
          () => {
            cidr.value = s.your_ip;
          },
          "btn ghost",
        ),
        button("Add", async () => {
          await api("POST", "ip_allowlist/entries", {
            cidr: cidr.value,
            label: label.value,
          });
          toast("Added");
          await draw();
        }),
      );
      wrap.append(
        card(
          "IP allowlist",
          el(
            "p",
            "note",
            "When enabled, every request to this app (web UI, admin, API) from an IP not listed below is blocked.",
          ),
          use.wrap,
          rows,
          addRow,
          el("div", "", null, { style: "height:8px" }),
          button("Save", async () => {
            await api("PUT", "ip_allowlist", { enabled: use.box.checked });
            toast("Saved");
            await draw();
          }),
        ),
      );
    };
    await draw();
  },

  async reports(m) {
    const s = await api("GET", "reports");
    const inputs = {
      company_name: text(s.company_name, { placeholder: "Acme Security" }),
      company_address: text(s.company_address),
      company_email: text(s.company_email, { type: "email" }),
      company_website: text(s.company_website, { placeholder: "https://example.com" }),
      footer_text: text(s.footer_text),
      primary_color: text(s.primary_color, { type: "color", style: "min-height:44px;padding:4px" }),
      secondary_color: text(s.secondary_color, { type: "color", style: "min-height:44px;padding:4px" }),
    };
    const summary = Object.assign(el("textarea", "", null, { rows: "7", spellcheck: "false" }), { value: s.executive_summary_description });
    const exec = check("Include an executive summary", s.show_executive_summary);
    const footer = check("Show a footer on every page", s.show_footer);
    const credit = check("Show the CVEngine credit line", s.show_banner);
    m.append(
      card(
        "Reports",
        el("p", "note", "Branding for the PDF and HTML reports you download from a scan. Nothing here is sent anywhere.", { style: "margin:0 0 14px" }),
        field("Company name", inputs.company_name),
        field("Address", inputs.company_address),
        field("Contact email", inputs.company_email),
        field("Website", inputs.company_website),
        field("Accent colour", inputs.primary_color),
        field("Heading colour", inputs.secondary_color),
        exec.wrap,
        field(
          "Executive summary text",
          summary,
          "Markdown. Placeholders: {company_name} {target_name} {scan_date} {subdomain_count} {vulnerability_count} {critical_count} {high_count} {medium_count} {low_count} {info_count}",
        ),
        footer.wrap,
        field("Footer text", inputs.footer_text),
        credit.wrap,
        button("Save", async () => {
          await api("PUT", "reports", {
            ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value])),
            executive_summary_description: summary.value,
            show_executive_summary: exec.box.checked,
            show_footer: footer.box.checked,
            show_banner: credit.box.checked,
          });
          toast("Saved");
        }),
      ),
    );
  },

  async proxy(m) {
    const s = await api("GET", "proxy");
    const use = check(
      "Route scan traffic through the proxies below",
      s.use_proxy,
    );
    const list = Object.assign(
      el("textarea", "", null, {
        rows: "6",
        spellcheck: "false",
        placeholder: "http://127.0.0.1:8080\nsocks5://127.0.0.1:9050",
        style:
          "width:100%;font:13px/1.5 var(--mono);padding:10px 12px;border:0;border-radius:6px;box-shadow:var(--ring)",
      }),
      { value: s.proxies },
    );
    m.append(
      card(
        "Proxy",
        el(
          "p",
          "note",
          "When on, scans that run on this server send their traffic to your targets through one of these proxies, picked per request in turn: the web probes and checks, nuclei, bbot, WPScan, testssl.sh and wafw00f. If a proxy is down the request fails; it never falls back to a direct connection.",
        ),
        el(
          "p",
          "note",
          "Not covered, still sent directly from this server: nmap, naabu, the UDP sweeps, the database and RDP checks and OpenVAS, because they need raw sockets that an HTTP or SOCKS proxy cannot carry. A Sentinel runs on its own machine and keeps its own connection; it does not use this list. Calls to outside services (CVE feeds, AI providers, Shodan, GitHub and the like) are not proxied either. Do not rely on this setting for anonymity of those.",
        ),
        el(
          "p",
          "note",
          "Use http://host:port, socks5://host:port or socks5h://host:port. An https:// proxy works for the external tools only, and testssl.sh takes only an http:// proxy without a login. When no proxy suits a tool, that tool does not run. Loopback and this stack's own services are never proxied; the server's CVENGINE_PROXY_BYPASS lists more.",
        ),
        use.wrap,
        field("Proxies (one per line)", list),
        button("Save", async () => {
          await api("PUT", "proxy", {
            use_proxy: use.box.checked,
            proxies: list.value,
          });
          toast("Saved");
        }),
      ),
    );
  },
};

// --- tabs ------------------------------------------------------------------------
// Thirteen tabs never fit on one line, so they are grouped: a column beside the panel on a wide screen, wrapped rows on a narrow one.
const view = root.querySelector("#view");
view.classList.add("set-layout");
const tabs = el("nav", "set-nav", null, {
  role: "tablist",
  "aria-label": "Settings",
});
const panel = el("div", "set-panel");
view.append(tabs, panel);
const groups = [
  ["AI and access", ["ai", "keys", "tailscale"]],
  ["Scanning", ["scan_policy", "openvas", "ip_allowlist", "proxy", "resources"]],
  ["Alerts and reports", ["notifications", "email", "reports"]],
  ["System", ["updates", "reset"]],
];
const labels = {
  ai: "AI model",
  keys: "API keys",
  tailscale: "Tailscale",
  openvas: "OpenVAS",
  notifications: "Notifications",
  email: "Email",
  scan_policy: "Scan policy",
  ip_allowlist: "IP allowlist",
  proxy: "Proxy",
  reports: "Reports",
  resources: "Resources",
  updates: "Updates",
  reset: "Factory reset",
};

async function open(name) {
  tabs
    .querySelectorAll("button")
    .forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.tab === name)),
    );
  panel.textContent = "";
  history.replaceState(null, "", `#${name}`);
  try {
    await sections[name](panel);
  } catch (err) {
    panel.append(el("p", "msg err", err.message));
  }
}
groups.forEach(([title, names]) => {
  const group = el("div", "set-group", null, { role: "presentation" });
  group.append(el("span", "set-group-title", title, { "aria-hidden": "true" }));
  names.forEach((name) => {
    const b = el("button", "btn ghost sm", labels[name], {
      role: "tab",
      "data-tab": name,
      "aria-selected": "false",
    });
    b.type = "button";
    b.onclick = () => open(name);
    group.append(b);
  });
  tabs.append(group);
});
// an old link to #engines (the tab this replaced) opens the scan policy
const legacyTabs = { engines: "scan_policy" };
const hashTab = legacyTabs[location.hash.slice(1)] || location.hash.slice(1);
open(sections[hashTab] ? hashTab : "ai");
