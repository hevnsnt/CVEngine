// Settings > API keys: the keys of the outside services cvENGINE really calls, and nothing else. Discovery keys feed bbot's modules on every
// scan, WPScan's feeds the WordPress pass, runZero's the scheduled inventory sync, and Chaos also has one instance-wide fallback. A key is
// set for an organization (all its projects, present and future) or for one project, which then overrides its organization's. Secrets are
// write-only. Everything from the server is set with textContent.
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
import { fmtDateTime, zoneLabel } from "/staticfiles/cve/prefs.js";

const PROJECTS = "/api/v1/projects";
const ORGS = "/cve/api/admin/orgs";
const VAULT = "/cve/api/settings/keys";

// what each key does, in a line; a service the server lists but nothing below names is shown with its own label only
const WHAT = {
  shodan: "Subdomains from Shodan's DNS data",
  censys: "Subdomains from Censys certificates (legacy Search API)",
  virustotal: "Subdomains VirusTotal has seen",
  securitytrails: "Current and historical DNS, subdomains",
  fullhunt: "Subdomains from FullHunt's attack-surface data",
  leakix: "Exposed services and subdomains",
  hunterio: "Email addresses on the domain",
  chaos: "ProjectDiscovery's subdomain dataset",
  github: "Code and organization search on GitHub",
  otx: "Passive DNS from AlienVault OTX",
  c99: "C99's subdomain finder",
  bevigil: "Subdomains and URLs found in mobile apps",
  builtwith: "Technologies and related domains",
  bufferoverrun: "Subdomains from TLS certificate scans",
  wpscan:
    "WordPress core, plugin and theme vulnerabilities for the WPScan pass",
  runzero: "Imports the runZero asset inventory on a schedule",
};
const GROUPS = [
  [
    "discovery",
    "Discovery",
    "Passed to bbot's matching module on every discovery scan, in every scan mode. Without a key that module runs unauthenticated or skips itself.",
  ],
  ["scanners", "Scanners", "Used by cvENGINE's own scanner passes."],
  ["sync", "Inventory sync", "Read by a scheduled job, not during a scan."],
];
const groupOf = (svc) =>
  svc.used_by_sync
    ? "sync"
    : svc.service === "wpscan"
      ? "scanners"
      : "discovery";
// a key matters only when something reads it; a retired service stays listed only while a stored key still has to be removed
const wired = (svc) =>
  svc.retired ? svc.configured : svc.used_in_scans || svc.used_by_sync;

function initials(label) {
  const words = label
    .replace(/\(.*\)/, "")
    .trim()
    .split(/[\s.]+/)
    .filter(Boolean);
  return (
    words.length > 1 ? words[0][0] + words[1][0] : label.slice(0, 2)
  ).toUpperCase();
}

export async function apiKeysPanel(mount) {
  const page = el("div", "ak");
  mount.append(page);
  const head = el("div", "card ak-head");
  head.append(
    el("h2", "", "API keys"),
    el(
      "p",
      "note",
      "Only the keys cvENGINE actually uses are listed. An organization key applies to all its projects, present and future; a project key overrides it for that project. Secrets are write-only and never shown again.",
    ),
  );
  page.append(head);

  // where the key applies: every organization (App Admins see all) and every project
  const scopes = [];
  const [orgs, projects] = await Promise.all([
    api("GET", ORGS)
      .then((d) => d.results || [])
      .catch(() => []),
    api("GET", PROJECTS)
      .then((d) => d.results || [])
      .catch(() => []),
  ]);
  orgs.forEach((o) =>
    scopes.push({
      value: `org:${o.id}`,
      kind: "org",
      name: o.name,
      path: `${ORGS}/${o.id}/api-keys`,
    }),
  );
  projects.forEach((p) =>
    scopes.push({
      value: `project:${p.slug}`,
      kind: "project",
      name: p.name || p.slug,
      slug: p.slug,
      path: `${PROJECTS}/${encodeURIComponent(p.slug)}/api-keys`,
    }),
  );
  const pick = el("select", "", null, { "aria-label": "Where the keys apply" });
  [
    ["org", "Organizations (all their projects)"],
    ["project", "Projects (overrides)"],
  ].forEach(([kind, label]) => {
    const list = scopes.filter((s) => s.kind === kind);
    if (!list.length) return;
    const group = el("optgroup", "", null, { label });
    list.forEach((s) =>
      group.append(el("option", "", s.name, { value: s.value })),
    );
    pick.append(group);
  });
  const bar = el("div", "ak-scope");
  bar.append(field("Keys for", pick));
  const scopeNote = el("p", "note ak-scope-note");
  bar.append(scopeNote);
  head.append(bar);
  const body = el("div", "ak-body");
  page.append(body);

  if (!scopes.length) {
    body.append(
      el(
        "p",
        "empty",
        "Create an organization or a project first: keys belong to one of them.",
      ),
    );
    return;
  }
  const remembered = (() => {
    try {
      return localStorage.getItem("cve.keys.scope");
    } catch (_) {
      return null;
    }
  })();
  pick.value = scopes.some((s) => s.value === remembered)
    ? remembered
    : scopes[0].value;
  const selected = () => scopes.find((s) => s.value === pick.value);

  let vault = null; // the instance-wide Chaos fallback (Settings' own store)
  let runzero = null; // the selected project's runZero sync status
  async function loadVault() {
    vault = await api("GET", VAULT).catch(() => null);
  }

  function editor(svc, scope, reload) {
    dialog(
      `${svc.retired ? "Remove" : svc.configured && (scope.kind === "org" || svc.scope === "project") ? "Change" : "Add"} ${svc.label}`,
      (box, close) => {
        if (svc.retired) box.append(el("p", "note", svc.retired));
        else
          box.append(
            el(
              "p",
              "note",
              scope.kind === "org"
                ? `For organization ${scope.name}: every project in it uses this key unless the project has its own.`
                : svc.scope === "org"
                  ? `Project ${scope.name} uses its organization's key now. A key saved here overrides it for this project only.`
                  : `For project ${scope.name} only.`,
            ),
          );
        const own =
          scope.kind === "org" ? svc.configured : svc.scope === "project";
        const inputs = (svc.retired ? [] : svc.fields).map((f) => {
          const input = text("", {
            type: f.secret ? "password" : "text",
            autocomplete: "off",
            spellcheck: "false",
            placeholder:
              own && svc.set[f.name] ? "saved (leave blank to keep)" : "",
          });
          box.append(field(f.label, input));
          return { name: f.name, input };
        });
        const actions = el("div", "actions");
        if (own)
          actions.append(
            button(
              "Remove",
              async () => {
                const ok = await ask(
                  scope.kind === "org"
                    ? `Remove ${svc.label} for organization ${scope.name}? Projects with their own key keep it; the others lose this one.`
                    : `Remove project ${scope.name}'s own ${svc.label} key?${svc.scope === "project" ? " Its organization's key applies again if there is one." : ""}`,
                  { title: "Remove key", ok: "Remove key" },
                );
                if (!ok) return;
                await api("DELETE", `${scope.path}/${svc.service}`);
                toast(`${svc.label} key removed`);
                close();
                reload();
              },
              "btn ghost",
            ),
          );
        actions.append(
          el("span", "grow"),
          button("Cancel", async () => close(), "btn ghost"),
        );
        if (!svc.retired)
          actions.append(
            button("Save", async () => {
              const values = Object.fromEntries(
                inputs
                  .map((i) => [i.name, i.input.value.trim()])
                  .filter(([, v]) => v),
              );
              if (!Object.keys(values).length)
                throw new Error("Enter a value to save.");
              await api("PUT", `${scope.path}/${svc.service}`, values);
              toast(`${svc.label} key saved`);
              close();
              reload();
            }),
          );
        box.append(actions);
      },
    );
  }

  function chaosFallback(reload) {
    const row = el("div", "ak-fallback");
    const on = Boolean(vault && vault.chaos && vault.chaos.has_key);
    row.append(
      el("span", "ak-fb-label", "Instance-wide fallback"),
      badge(on ? "set" : "not set", on ? "success" : "queued"),
      el(
        "span",
        "note",
        "Used where neither the organization nor the project has a Chaos key.",
      ),
    );
    row.append(
      button(
        on ? "Change" : "Add",
        async () =>
          dialog("Chaos instance-wide fallback", (box, close) => {
            const input = text("", {
              type: "password",
              autocomplete: "off",
              placeholder: on ? "saved (leave blank to keep)" : "",
            });
            box.append(
              el(
                "p",
                "note",
                "Every project without its own or its organization's Chaos key uses this one.",
              ),
              field("API key", input),
            );
            const actions = el("div", "actions");
            if (on)
              actions.append(
                button(
                  "Remove",
                  async () => {
                    if (
                      !(await ask("Remove the instance-wide Chaos key?", {
                        title: "Remove key",
                        ok: "Remove key",
                      }))
                    )
                      return;
                    await api("PUT", VAULT, { chaos: { clear: true } });
                    toast("Chaos fallback removed");
                    close();
                    reload();
                  },
                  "btn ghost",
                ),
              );
            actions.append(
              el("span", "grow"),
              button("Cancel", async () => close(), "btn ghost"),
              button("Save", async () => {
                if (!input.value.trim())
                  throw new Error("Enter a value to save.");
                await api("PUT", VAULT, { chaos: { key: input.value.trim() } });
                toast("Chaos fallback saved");
                close();
                reload();
              }),
            );
            box.append(actions);
          }),
        "btn sm ghost",
      ),
    );
    return row;
  }

  // runZero: the sync's state and its import settings, for a project whose key is set
  function runzeroPanel(rz, scope, canEdit, reload) {
    const path = `${scope.path.replace(/\/api-keys$/, "")}/runzero`;
    const box = el("div", "ak-sync");
    box.append(
      el(
        "p",
        "note",
        rz.state === "running"
          ? "Syncing now"
          : rz.last_sync_at
            ? `${rz.last_error ? "Last sync failed" : "Last sync"} ${fmtDateTime(rz.last_sync_at)} ${zoneLabel()} · every ${rz.interval_hours} hours`
            : `Not synced yet · every ${rz.interval_hours} hours`,
      ),
    );
    if (rz.last_error) box.append(el("p", "msg err", rz.last_error));
    const c = rz.counts || {};
    if (rz.last_ok_at && c.assets != null) {
      const bits = [`${c.assets} assets read`, `${c.matched_hosts} hosts matched`, `${c.updated_hosts} updated`];
      if (c.cve_reports) bits.push(`${c.cve_reports} CVE reports`);
      if (c.imported != null) bits.push(`${c.imported} targets imported`);
      if (c.truncated) bits.push("list was cut at the size limit");
      box.append(el("p", "note", bits.join(", ")));
    }
    if (!canEdit) return box;
    const importBox = el("input", "", null, { type: "checkbox" });
    importBox.checked = rz.import_enabled;
    const row = el("label", "note ak-check");
    row.append(importBox, ` Add runZero addresses cvENGINE does not know as targets (at most ${rz.import_max} per sync, through the same checks as Add targets)`);
    const search = text(rz.search || "", { spellcheck: "false", autocomplete: "off", maxlength: "300" });
    const actions = el("div", "actions");
    actions.append(
      button(
        "Save import settings",
        async () => {
          await api("PUT", path, { import_enabled: importBox.checked, search: search.value });
          toast("runZero settings saved");
          reload();
        },
        "btn sm ghost",
      ),
      button(
        "Sync now",
        async () => {
          await api("POST", `${path}/sync`, {});
          toast("runZero sync queued");
          setTimeout(reload, 4000);
        },
        "btn sm",
      ),
    );
    box.append(row, field("runZero search that limits the import", search), actions);
    return box;
  }

  function tile(svc, scope, canEdit, reload) {
    const t = el(
      "article",
      `ak-tile${svc.configured ? " on" : ""}${svc.retired ? " retired" : ""}`,
    );
    const top = el("div", "ak-top");
    top.append(
      el("span", "ak-mark", initials(svc.label), { "aria-hidden": "true" }),
    );
    const name = el("div", "ak-name");
    name.append(
      el("b", "", svc.label.replace(/\s*\(.*\)$/, "")),
      el(
        "span",
        "note",
        svc.retired ? "Retired service" : WHAT[svc.service] || "",
      ),
    );
    top.append(name);
    t.append(top);
    const state = el("div", "ak-state");
    if (svc.retired) state.append(badge("not used", "fire"));
    else if (!svc.configured) state.append(badge("not set", "queued"));
    else if (scope.kind === "org")
      state.append(badge("set for the organization", "success"));
    else
      state.append(
        badge(
          svc.scope === "project"
            ? "this project's own key"
            : "from the organization",
          "success",
        ),
      );
    if (canEdit)
      state.append(
        button(
          svc.retired
            ? "Remove"
            : svc.configured &&
                (scope.kind === "org" || svc.scope === "project")
              ? "Change"
              : "Add",
          async () => editor(svc, scope, reload),
          `btn sm${svc.configured ? " ghost" : ""}`,
        ),
      );
    t.append(state);
    if (svc.service === "chaos") t.append(chaosFallback(reload));
    if (svc.service === "runzero" && svc.configured && runzero) t.append(runzeroPanel(runzero, scope, canEdit, reload));
    return t;
  }

  let version = 0;
  async function draw() {
    const scope = selected();
    const mine = ++version;
    try {
      localStorage.setItem("cve.keys.scope", scope.value);
    } catch (_) {}
    scopeNote.textContent =
      scope.kind === "org"
        ? `Organization ${scope.name}: defaults for all its projects. A project's own key wins.`
        : `Project ${scope.name}: keys marked "from the organization" are inherited; adding one here overrides it.`;
    body.setAttribute("aria-busy", "true");
    const [data] = await Promise.all([
      api("GET", scope.path),
      loadVault(),
    ]).catch((err) => {
      body.textContent = "";
      body.append(
        el(
          "p",
          "msg err",
          `Could not load the keys of ${scope.name}: ${err.message}`,
        ),
      );
      return [null];
    });
    if (mine !== version || !data) return;
    runzero = scope.kind === "project" ? await api("GET", `${PROJECTS}/${encodeURIComponent(scope.slug)}/runzero`).catch(() => null) : null;
    if (mine !== version) return;
    body.removeAttribute("aria-busy");
    body.textContent = "";
    const canEdit = scope.kind === "org" || data.can_edit !== false;
    const services = (data.results || []).filter(wired);
    const set = services.filter((s) => s.configured && !s.retired).length;
    const summary = el("p", "ak-summary");
    summary.append(
      el("b", "", `${set} of ${services.filter((s) => !s.retired).length}`),
      document.createTextNode(" keys set here"),
    );
    body.append(summary);
    GROUPS.forEach(([key, title, note]) => {
      const list = services.filter((s) => !s.retired && groupOf(s) === key);
      if (!list.length) return;
      const section = el("section", "ak-group");
      section.append(el("h3", "", title), el("p", "note", note));
      const grid = el("div", "ak-grid");
      list
        .sort(
          (a, b) =>
            Number(b.configured) - Number(a.configured) ||
            a.label.localeCompare(b.label),
        )
        .forEach((s) => grid.append(tile(s, scope, canEdit, draw)));
      section.append(grid);
      body.append(section);
    });
    const retired = services.filter((s) => s.retired);
    if (retired.length) {
      const section = el("section", "ak-group");
      section.append(
        el("h3", "", "Retired"),
        el("p", "note", "Nothing reads these any more. Remove the stored key."),
      );
      const grid = el("div", "ak-grid");
      retired.forEach((s) => grid.append(tile(s, scope, canEdit, draw)));
      section.append(grid);
      body.append(section);
    }
    if (!canEdit)
      body.append(el("p", "note", "Your role in this project is read only."));
  }
  pick.onchange = draw;
  await draw();
}
