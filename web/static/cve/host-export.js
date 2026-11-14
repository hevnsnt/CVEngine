// "Export all hosts": a button in the Hosts page head and the small dialog behind it. The server writes the file (agentapi/host_export.py);
// this fetches it with the page's own sign-in and saves it. Not the CSV button of the list: that one exports the current filter, with the internal columns.
import { api, dialog, el, field, selectOf, toast } from "/staticfiles/cve/ui.js";
import { CONTAINS, DEFAULTS, FORMATS, SCOPES, canExport, countsFrom, doneMessage, exportPath, exportQuery, filenameFrom, organizationsOf } from "/staticfiles/cve/host-export-logic.js";

async function save(url, fallbackName) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) {
    let message = `Export failed (${res.status})`;
    try {
      message = (await res.json()).error || message;
    } catch (_) {
      /* not JSON */
    }
    throw new Error(message);
  }
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = el("a", "", "", { href, download: filenameFrom(res.headers.get("Content-Disposition"), fallbackName) });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
  return countsFrom(res.headers);
}

/**
 * Open the dialog. ``all`` is the All projects view: the dialog then asks for an organization and uses the organization route.
 * @param {{slug: string, all?: boolean}} options
 */
export function openHostExport({ slug, all = false }) {
  dialog("Export all hosts", (body, close) => {
    body.append(el("p", "note", all
      ? "Every discovered host of one organization (all of its projects you can access), as a file to hand to a penetration testing company."
      : "Every discovered host of this project, as a file to hand to a penetration testing company."));
    body.append(el("p", "note", CONTAINS));
    let orgPick = null;
    if (all) {
      orgPick = selectOf([["", "Loading organizations…"]], "", "Organization");
      orgPick.disabled = true;
      body.append(field("Organization", orgPick));
    }
    const format = selectOf(FORMATS, DEFAULTS.format, "Format");
    const scope = selectOf(SCOPES, DEFAULTS.scope, "Which hosts");
    const archived = el("input", "", null, { type: "checkbox" });
    archived.checked = DEFAULTS.archived;
    const archivedRow = el("label", "note");
    archivedRow.append(archived, document.createTextNode(" Include archived hosts"));
    body.append(field("Format", format), field("Which hosts", scope, "Internet-facing only leaves out hosts in a declared internal network and private addresses."), archivedRow);
    const status = el("p", "note", "", { role: "status", "aria-live": "polite" });
    const actions = el("div", "actions");
    const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
    cancel.onclick = close;
    const go = el("button", "btn", "Export", { type: "button" });
    actions.append(cancel, go);
    body.append(status, actions);
    const ready = () => {
      go.disabled = !canExport({ all, org: orgPick ? orgPick.value : "" });
    };
    if (orgPick) {
      go.disabled = true;
      orgPick.onchange = ready;
      api("GET", "/api/v1/projects")
        .then((d) => {
          const orgs = organizationsOf(d.results);
          orgPick.textContent = "";
          if (!orgs.length) {
            orgPick.append(Object.assign(el("option", "", "No organization to export"), { value: "" }));
            return;
          }
          if (orgs.length > 1) orgPick.append(Object.assign(el("option", "", "Choose an organization…"), { value: "" }));
          orgs.forEach((o) => orgPick.append(Object.assign(el("option", "", `${o.name} (${o.projects} project${o.projects === 1 ? "" : "s"})`), { value: o.slug })));
          const wanted = new URLSearchParams(location.search).get("org");
          orgPick.value = orgs.some((o) => o.slug === wanted) ? wanted : orgs.length === 1 ? orgs[0].slug : "";
          orgPick.disabled = false;
          ready();
        })
        .catch((err) => {
          status.textContent = err.message;
        });
    }
    go.onclick = async () => {
      const choice = { format: format.value, scope: scope.value, archived: archived.checked };
      const url = `${exportPath(all ? { org: orgPick.value } : { slug })}?${exportQuery(choice)}`;
      go.disabled = true;
      go.textContent = "Exporting…";
      status.textContent = "";
      try {
        const counts = await save(url, `cvengine-hosts.${choice.format}`);
        toast(doneMessage({ ...counts, format: choice.format }));
        close();
      } catch (err) {
        status.textContent = err.message;
        toast(err.message, true);
        go.textContent = "Export";
        ready();
      }
    };
  });
}

/** The page-head button of the Hosts page. */
export function hostExportButton({ slug, all = false }) {
  const b = el("button", "btn sm head-action", "Export all hosts", {
    type: "button",
    title: "Download every discovered host as a file to hand to a penetration testing company (no findings or notes in it)",
  });
  b.onclick = () => openHostExport({ slug, all });
  return b;
}
