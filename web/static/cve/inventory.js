// Host inventory in the UI: the host page's Inventory tab and the "Host inventory" dialog (reporter commands, reports waiting for an
// administrator, and the project's policy). Plain ES module over the REST API; DOM is built with textContent only, because every
// name in a report came from the machine that sent it.
import { api, badge, button, copyText, dialog, el, field, shortDate, table, text, toast } from "/staticfiles/cve/ui.js";
import { ageWord, snippets } from "/staticfiles/cve/inventory-snippets.js";

const projectBase = (project) => `/api/v1/projects/${encodeURIComponent(project)}`;
const osLine = (os) => [os.name, os.version, os.build && `build ${os.build}`, os.kernel && `kernel ${os.kernel}`, os.arch].filter(Boolean).join(" · ");

// a command with a Copy button; the text is the command exactly as it will be pasted
function codeBlock(command) {
  const box = el("div", "code");
  box.append(document.createTextNode(command));
  const copy = el("button", "copy", "Copy", { type: "button" });
  copy.onclick = async () => {
    try {
      await copyText(command);
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1500);
    } catch (_) {
      toast("Copy was blocked: select the command and copy it by hand", true);
    }
  };
  box.append(copy);
  return box;
}

const kvBox = (rows) => {
  const box = el("div", "kvs");
  rows.filter(([, v]) => v !== "" && v != null).forEach(([k, v]) => {
    const line = el("div", "kv");
    line.append(el("span", "k", k), el("span", "v", String(v)));
    box.append(line);
  });
  return box;
};

// the badge next to a host's name: how old the host's own report is, and whether it still counts
export function inventoryBadge(inv) {
  if (!inv) return null;
  const b = badge(`Inventory ${ageWord(inv.age_hours)}`, inv.stale ? "smoke" : "success");
  b.title = inv.stale
    ? `The host's report is older than ${inv.stale_after_days} days: it creates no findings until the host reports again.`
    : "The host reported about itself recently.";
  return b;
}

function listOf(title, items, render) {
  const box = el("div", "why");
  box.append(el("h3", "sec", title));
  if (!items.length) box.append(el("p", "note", "None reported."));
  else box.append(render(items));
  return box;
}

function packagesCard(project, host, detail) {
  const box = el("div", "why");
  const head = el("h3", "sec", `Packages (${detail.packages})`);
  const search = text("", { placeholder: "Filter by package name", "aria-label": "Filter packages" });
  const out = el("div");
  let page = 1;
  async function load() {
    const q = new URLSearchParams({ q: search.value, page: String(page), page_size: "50" });
    const data = (await api("GET", `${projectBase(project)}/hosts/${encodeURIComponent(host)}/inventory?${q}`)).packages_page;
    out.textContent = "";
    out.append(
      table(
        [
          { label: "Package", render: (p) => p.name },
          { label: "Version", render: (p) => p.version },
          { label: "Source", render: (p) => p.ecosystem + (p.arch ? ` · ${p.arch}` : "") },
          { label: "purl", render: (p) => el("span", "mono note", p.purl) },
        ],
        data.results,
      ),
    );
    const pages = Math.max(1, Math.ceil(data.count / data.page_size));
    const nav = el("div", "tools");
    const prev = button("Previous", async () => { page -= 1; await load(); }, "btn ghost sm");
    const next = button("Next", async () => { page += 1; await load(); }, "btn ghost sm");
    prev.disabled = page <= 1;
    next.disabled = page >= pages;
    nav.append(prev, el("span", "note", `page ${page} of ${pages} (${data.count} match)`), next);
    out.append(nav);
  }
  search.oninput = () => {
    clearTimeout(search._t);
    search._t = setTimeout(() => { page = 1; load().catch((e) => toast(e.message, true)); }, 300);
  };
  box.append(head, search, out);
  load().catch((e) => out.append(el("p", "note", e.message)));
  return box;
}

function renderDetail(box, project, host, d) {
  const run = d.runtime || {};
  const sec = d.security || {};
  const state = el("div", "why");
  state.append(el("h3", "sec", "Operating system"));
  state.append(
    kvBox([
      ["System", osLine(d.os)],
      ["Distribution", (d.os_detail || {}).pretty],
      ["Last boot", (d.os_detail || {}).last_boot && shortDate(d.os_detail.last_boot)],
      ["Last package change", (d.os_detail || {}).last_update && shortDate(d.os_detail.last_update)],
      ["Reboot needed", run.reboot_required == null ? "" : run.reboot_required ? "yes" : "no"],
      ["Kernels installed", (run.kernels_installed || []).join(", ")],
      ["Reporter", d.script],
      ["Matched by", d.match_basis],
    ]),
  );
  box.append(state);
  const posture = Object.entries(sec);
  if (posture.length) box.append(listOf("Security settings", posture, (items) => kvBox(items.map(([k, v]) => [k.replace(/_/g, " "), v]))));
  if (d.findings && d.findings.total) {
    const note = el("div", "why");
    note.append(el("h3", "sec", "What this report found"));
    note.append(
      el("p", "note", `${d.findings.total} open CVE match${d.findings.total === 1 ? "" : "es"} come from this report${d.findings.local_only ? `, ${d.findings.local_only} only usable from the host itself` : ""}. They are labelled as reported by the host.`),
    );
    note.append(el("a", "", "Open them", { href: `/cve/${encodeURIComponent(project)}/matches/?host=${encodeURIComponent(host)}` }));
    box.append(note);
  }
  const assessment = d.assessment || {};
  (assessment.notes || []).forEach((n) => box.append(el("p", "note", n)));
  box.append(
    listOf("Listening services", d.services || [], (items) =>
      table(
        [
          { label: "Port", render: (s) => `${s.n}/${s.p}` },
          { label: "Address", render: (s) => s.a },
          { label: "Process", render: (s) => s.x || "" },
        ],
        items.slice(0, 200),
      ),
    ),
    listOf("Installed updates", d.patches || [], (items) =>
      table(
        [
          { label: "Update", render: (p) => p.i },
          { label: "Installed", render: (p) => p.t },
          { label: "Description", render: (p) => p.d },
        ],
        items.slice(0, 100),
      ),
    ),
  );
  if ((run.containers || []).length) {
    box.append(listOf("Containers running", run.containers, (items) => el("p", "note mono", items.map((c) => `${c.rt}: ${c.image}`).join("\n"), { style: "white-space:pre-wrap" })));
  }
  if ((run.features || []).length) box.append(listOf("Roles and features", run.features, (items) => el("p", "note", items.join(", "))));
  if (d.packages) box.append(packagesCard(project, host, d));
  box.append(
    listOf("Report history", d.history || [], (items) =>
      table(
        [
          { label: "Reported", render: (r) => shortDate(r.reported_at) },
          { label: "Packages", render: (r) => String(r.packages) },
          { label: "Changed", render: (r) => (r.changes.first ? "first report" : `+${r.changes.added} -${r.changes.removed} ~${r.changes.changed}${r.changes.os_changed ? ", OS changed" : ""}${(r.changes.names || []).length ? `: ${r.changes.names.join(", ")}` : ""}`) },
        ],
        items,
      ),
    ),
  );
}

// The host page's Inventory tab. ``h.inventory`` is the brief the host record carries (null when the host never reported). Returns the
// function that fetches the full report: the page calls it when the tab is first opened, so a host nobody looks at the tab of costs nothing.
export function renderHostInventory(box, { h, project, readOnly }) {
  const inv = h.inventory;
  if (!inv) {
    box.append(
      el("p", "note", "This host has not reported about itself. A report from the host gives its exact operating system build, installed packages and patch level, which an outside scan cannot see: that makes kernel and other local-only CVEs decidable and sharpens the rest."),
    );
    if (!readOnly) box.append(button("Set up host reporting", async () => openInventoryDialog({ project }), "btn sm"));
    return () => {};
  }
  const head = el("div", "why");
  head.append(el("h3", "sec", "Reported by the host"));
  head.append(inventoryBadge(inv));
  head.append(
    kvBox([
      ["Reported", shortDate(inv.reported_at)],
      ["System", osLine(inv.os)],
      ["Packages", inv.packages],
      ["Addresses", (inv.ips || []).join(", ")],
    ]),
  );
  if (inv.stale) head.append(el("p", "note", `This report is more than ${inv.stale_after_days} days old, so it creates no findings and closes none until the host reports again.`));
  box.append(head);
  const body = el("div", "host-col");
  box.append(body);
  if (!readOnly) box.append(button("Reporting commands", async () => openInventoryDialog({ project }), "btn ghost sm"));
  let loaded = false;
  return () => {
    if (loaded) return;
    loaded = true;
    api("GET", `${projectBase(project)}/hosts/${encodeURIComponent(h.host)}/inventory`)
      .then((d) => renderDetail(body, project, h.host, d))
      .catch((e) => body.append(el("p", "note", e.message)));
  };
}

// --- the dialog -----------------------------------------------------------------------------------------------------------

function commandsSection(project, origin) {
  const wrap = el("div");
  let privateCa = true;
  const shown = el("div");
  const ca = el("input", "", null, { type: "checkbox", id: "inv-ca", checked: "checked" });
  const caLabel = el("label", "check", null, { for: "inv-ca" });
  caLabel.append(ca, document.createTextNode(" This server uses the installer's private certificate authority (copy secrets/certs/ca.crt from the server next to the script as ca.crt)"));
  const paint = () => {
    shown.textContent = "";
    const s = snippets({ origin, project, privateCa });
    shown.append(
      el("h3", "sec", "Linux and macOS"),
      codeBlock(s.linux),
      el("h3", "sec", "Python 3.6+ (Linux and macOS, no dependencies)"),
      codeBlock(s.python),
      el("h3", "sec", "Windows (PowerShell 5.1 or 7)"),
      codeBlock(s.windows),
      el("p", "note", "From a server with a private authority, Windows also needs the authority to download the script (import ca.crt into Trusted Root Certification Authorities, or download the .ps1 in a browser that trusts it)."),
      el("h3", "sec", "See what would be sent first, and schedule it"),
      codeBlock(`${s.check}\n${s.checkWindows}`),
      codeBlock(`${s.schedule}\n${s.scheduleWindows}`),
      el("p", "note", "These print what they would send, or a cron line, systemd timer or scheduled task for you to apply. They change nothing. A scheduled run reads the token from a file only root can read (--token-file, -TokenFile): the Linux and macOS command above already saved it as cvengine-inventory.token, so move that file there; on Windows save the token to a file restricted to SYSTEM and Administrators."),
    );
  };
  ca.onchange = () => {
    privateCa = ca.checked;
    paint();
  };
  const name = text("", { placeholder: `inventory reporter for ${project}`, maxlength: "100", "aria-label": "Token name" });
  const secret = el("div");
  const create = button("Create a reporter token", async () => {
    const made = await api("POST", "/api/v1/tokens", { name: name.value || `inventory reporter for ${project}`, scope: "inventory", project });
    secret.textContent = "";
    secret.append(
      el("p", "note", `Copy this token now: it is shown once, and it expires ${shortDate(made.expires)}. Run a command below and paste the token when it asks: the commands never contain it, so it stays out of shell history and the process list.`),
      codeBlock(made.token),
    );
  });
  wrap.append(
    el("p", "note", "Run one of these on the machine, as a user that can read the package database (root for the fullest report). The script only reads: it lists the operating system, packages, listening ports and a few security settings, sends them over HTTPS, and changes nothing. It never sends passwords, keys, tokens, shell history, environment variables or file contents."),
    el("p", "note", "The token can only post this project's inventory reports, for a year. It acts with your role and stops working if you are removed. A machine belongs to the token that first reported it."),
  );
  const row = el("div", "dlg-tools");
  row.append(name, create);
  wrap.append(row, secret, caLabel, shown);
  paint();
  return wrap;
}

async function reportsSection(project) {
  const wrap = el("div");
  const list = el("div");
  const render = async () => {
    const data = await api("GET", `${projectBase(project)}/inventory?page_size=100`);
    list.textContent = "";
    if (!data.results.length) {
      list.append(el("p", "note", "No host has reported yet."));
      return;
    }
    list.append(
      table(
        [
          { label: "Machine", render: (r) => r.fqdn || r.hostname || (r.ips || [])[0] || "unknown" },
          { label: "System", render: (r) => osLine(r.os) },
          { label: "Reported", render: (r) => `${shortDate(r.reported_at)}${r.stale ? " (stale)" : ""}` },
          {
            label: "Host",
            render: (r) => {
              if (r.matched) return r.host;
              const cell = el("div", "dlg-tools");
              if (r.claimed_host) cell.append(el("span", "note", `wanted ${r.claimed_host}, which another machine already reports for`));
              const to = text("", { placeholder: "host it is", "aria-label": `Host that ${r.hostname || "this machine"} is` });
              cell.append(
                to,
                button("Tie", async () => {
                  await api("POST", `${projectBase(project)}/inventory/${r.id}/adopt`, { host: to.value });
                  toast("Tied to the host");
                  await render();
                }, "btn sm"),
                button("Add as target", async () => {
                  await api("POST", `${projectBase(project)}/inventory/${r.id}/adopt`, { create: true });
                  toast("Added as a target; discovery started");
                  await render();
                }, "btn ghost sm"),
              );
              return cell;
            },
          },
          {
            label: "",
            render: (r) => button("Delete", async () => {
              await api("DELETE", `${projectBase(project)}/inventory/${r.id}`);
              await render();
            }, "btn ghost sm"),
          },
        ],
        data.results,
      ),
    );
  };
  const clear = button("Delete every unmatched report", async () => {
    const done = await api("POST", `${projectBase(project)}/inventory/delete-unmatched`, {});
    toast(`Deleted ${done.deleted} unmatched report${done.deleted === 1 ? "" : "s"}`);
    await render();
  }, "btn ghost sm");
  wrap.append(
    el("p", "note", "A report that matches no host the project scans waits here (at most 500; ones nobody adopts are dropped after 30 days). Tie it to a host you already scan, or add the machine as a target (refused for a host your organization excluded). A machine that wants a host another machine already reports for waits here too: only you can decide which one is the host."),
    list,
    clear,
  );
  await render().catch((e) => list.append(el("p", "note", e.message)));
  return wrap;
}

async function policySection(project) {
  const wrap = el("div");
  const current = (await api("GET", `${projectBase(project)}/settings`)).inventory;
  const create = el("input", "", null, { type: "checkbox", id: "inv-create" });
  create.checked = !!current.create_hosts;
  const label = el("label", "check", null, { for: "inv-create" });
  label.append(create, document.createTextNode(" A report from a host nobody scans yet adds it to this project as a target and starts discovery (otherwise it waits above for an administrator)"));
  const days = text(String(current.stale_days), { type: "number", min: "1", max: "365", "aria-label": "Days until a report is stale" });
  const save = button("Save", async () => {
    await api("PUT", `${projectBase(project)}/settings`, { inventory: { create_hosts: create.checked, stale_days: Number(days.value) } });
    toast("Saved");
  }, "btn sm");
  wrap.append(label, field("Days until a report is stale", days, "A stale report creates no findings and closes none, until the host reports again."), save);
  return wrap;
}

export function openInventoryDialog({ project, origin = window.location.origin }) {
  return dialog("Host inventory", (body) => {
    body.append(el("p", "note", "Have a host tell cvENGINE what it is: operating system and version, packages, patches. An outside scan cannot see any of it."));
    body.append(el("h3", "sec", "Report from a host"), commandsSection(project, origin));
    const reports = el("div");
    const policy = el("div");
    body.append(el("h3", "sec", "Reports from hosts"), reports, el("h3", "sec", "Settings"), policy);
    reportsSection(project).then((s) => reports.append(s)).catch((e) => reports.append(el("p", "note", e.message)));
    policySection(project).then((s) => policy.append(s)).catch((e) => policy.append(el("p", "note", e.message)));
  });
}
