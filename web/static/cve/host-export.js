// "Export all hosts" and "Export host": a button in the Hosts page head and the small dialog behind it. The server writes the file
// (agentapi/host_export.py for every host, agentapi/host_export_one.py for one); this fetches it with the page's own sign-in and saves it.
// Not the CSV button of the list: that one exports the current filter, with the internal columns.
import { api, dialog, el, field, selectOf, toast } from "/staticfiles/cve/ui.js";
import {
  CONTAINS, DEFAULTS, FORMATS, HOST_CONTAINS, HOST_NOTE, SCOPES, buttonLabel, buttonTitle, canExport, countsFrom, doneMessage, exportPath, exportQuery,
  filenameFrom, hostCountsFrom, hostDoneMessage, hostExportPath, hostIdFromHash, organizationsOf,
} from "/staticfiles/cve/host-export-logic.js";

async function save(url, fallbackName, counts = countsFrom) {
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
  return counts(res.headers);
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

/**
 * The dialog of one host: no choices, only what the file holds and Download. Same dialog, keys and focus as Export all hosts.
 * @param {{slug: string, id: number, name?: string}} options
 */
export function openSingleHostExport({ slug, id, name = "" }) {
  dialog("Export host", (body, close) => {
    body.append(el("p", "note", name ? `Everything cvENGINE knows about ${name}, as one ZIP file.` : "Everything cvENGINE knows about this host, as one ZIP file."));
    const list = el("ul", "note");
    HOST_CONTAINS.forEach((line) => list.append(el("li", "", line)));
    body.append(list, el("p", "note", HOST_NOTE));
    const status = el("p", "note", "", { role: "status", "aria-live": "polite" });
    const actions = el("div", "actions");
    const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
    cancel.onclick = close;
    const go = el("button", "btn", "Download", { type: "button" });
    actions.append(cancel, go);
    body.append(status, actions);
    go.onclick = async () => {
      go.disabled = true;
      go.textContent = "Exporting…";
      status.textContent = "";
      try {
        const counts = await save(hostExportPath({ slug, id }), `host-${id}.zip`, hostCountsFrom);
        toast(hostDoneMessage({ ...counts, name }));
        close();
      } catch (err) {
        status.textContent = err.message;
        toast(err.message, true);
        go.textContent = "Download";
        go.disabled = false;
      }
    };
  });
}

/**
 * The page-head button of the Hosts page. It reads "Export host" while the address selects a host (#40413) and "Export all hosts" on the list;
 * ``sync()`` repaints it (the page calls it whenever it shows or leaves a host, since history.replaceState fires no event), and a hash change or a
 * back or forward step repaints it on its own. ``hostOf(id)`` gives the loaded host ({host, project}) for the dialog's words and, in All projects,
 * its project.
 * @param {{slug: string, all?: boolean, hostOf?: (id: number) => any}} options
 */
export function hostExportButton({ slug, all = false, hostOf = () => null }) {
  const b = el("button", "btn sm head-action", buttonLabel(null), { type: "button", title: buttonTitle(null) });
  b.sync = () => {
    const id = hostIdFromHash(location.hash);
    b.textContent = buttonLabel(id);
    b.setAttribute("title", buttonTitle(id));
    return id;
  };
  const follow = () => {
    if (b.isConnected === false) {
      window.removeEventListener("hashchange", follow);
      window.removeEventListener("popstate", follow);
      return;
    }
    b.sync();
  };
  if (typeof window !== "undefined" && window.addEventListener) {
    window.addEventListener("hashchange", follow);
    window.addEventListener("popstate", follow);
  }
  b.onclick = () => {
    const id = b.sync();
    if (!id) {
      openHostExport({ slug, all });
      return;
    }
    const host = hostOf(id) || null;
    const project = all ? host && host.project : slug;
    if (!project) {
      toast("The host is still loading: try again in a moment", true);
      return;
    }
    openSingleHostExport({ slug: project, id, name: host ? host.host : "" });
  };
  b.sync();
  return b;
}
