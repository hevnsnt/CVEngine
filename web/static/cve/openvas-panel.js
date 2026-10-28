// OpenVAS, as simple as it can be: say what to scan. Used by Settings > OpenVAS (App Admins) and Administration > OpenVAS (App Admins and Org Admins).
// The server decides what a person may choose (the organizations they administer); this page only shows it. Switching a choice on switches the
// add-on on, starts the containers and makes the scanner's login, so there is nothing to type here. Everything from the server is set with textContent.
import { api, badge, button, el, toast } from "/staticfiles/cve/ui.js";

const A = "/cve/api/admin/openvas";
const POLL_MS = 15000;
const TONE = { off: "queued", starting: "queued", loading: "queued", ready: "success", problem: "fire" };

function statusCard(data, redraw) {
  const e = data.engine;
  const c = el("div", "card ov-status");
  const head = el("div", "ov-head");
  head.append(el("h2", "", "OpenVAS scanner"), badge(e.headline, TONE[e.state] || ""));
  c.append(head, el("p", "note", e.detail));
  if (e.state === "off" || e.state === "problem") {
    c.append(
      el(
        "p",
        "note",
        "OpenVAS is a second vulnerability scanner that looks deeper than the built-in checks. It uses about 4 GB of memory while it runs and scans slowly on purpose, a few hosts at a time, without denial-of-service or brute-force tests.",
      ),
    );
  }
  const actions = el("div", "ov-actions");
  if (e.state === "problem") {
    actions.append(
      button("Try again", async () => {
        await api("POST", `${A}/check`, {});
        await redraw();
      }),
    );
  }
  if (e.enabled && e.can_switch_off) {
    actions.append(
      button("Switch off", async () => {
        await api("PUT", A, { enabled: false });
        toast("OpenVAS is switched off. Your choices are kept.");
        await redraw();
      }, "btn ghost"),
    );
  }
  if (actions.children.length) c.append(actions);
  return c;
}

function projectRow(org, project, save) {
  const id = `ov-p${project.id}`;
  const row = el("label", "ov-row", null, { for: id });
  const box = el("input", "", null, { type: "checkbox", id });
  box.checked = org.enabled || project.enabled;
  box.disabled = org.enabled; // the organization choice covers it
  box.onchange = () => save({ projects: { [project.id]: box.checked } });
  const text = el("span", "ov-name");
  text.append(el("span", "", project.name));
  if (org.enabled) text.append(el("span", "note", "covered by the organization"));
  else if (project.last_run) {
    const r = project.last_run;
    text.append(el("span", "note", r.error ? `last scan failed: ${r.error}` : `last scan ${r.status}${r.status === "running" ? ` (${r.progress}%)` : ""}`));
  }
  row.append(box, text);
  return row;
}

function orgCard(org, save) {
  const c = el("div", "card ov-org");
  const id = `ov-o${org.id}`;
  const head = el("label", "ov-row ov-org-head", null, { for: id });
  const box = el("input", "", null, { type: "checkbox", id });
  box.checked = org.enabled;
  box.onchange = () => save({ orgs: { [org.id]: box.checked } });
  const name = el("span", "ov-name");
  name.append(el("b", "", org.name), el("span", "note", `Scan every project in ${org.name}, including ones added later`));
  head.append(box, name);
  c.append(head);
  if (org.projects.length) {
    const list = el("div", "ov-projects");
    org.projects.forEach((p) => list.append(projectRow(org, p, save)));
    c.append(list);
  } else c.append(el("p", "note", "This organization has no projects yet."));
  return c;
}

export async function openvasPanel(mount) {
  const wrap = el("div", "ov");
  mount.append(wrap);
  let timer = 0;
  const draw = (data) => {
    wrap.textContent = "";
    const save = async (change) => {
      try {
        draw(await api("PUT", A, change));
        toast("Saved");
      } catch (err) {
        toast(err.message, true);
        await redraw();
      }
    };
    wrap.append(statusCard(data, redraw));
    if (!data.orgs.length) {
      wrap.append(el("p", "note", "You do not administer any organization, so there is nothing to choose here."));
    } else {
      wrap.append(el("h3", "ov-h", data.who === "app_admin" ? "What should it scan?" : "What should it scan in your organizations?"));
      wrap.append(el("p", "note", "Pick whole organizations or single projects. Only hosts that belong to them are scanned, and excluded, archived and private-network hosts are always left out."));
      data.orgs.forEach((o) => wrap.append(orgCard(o, save)));
    }
    clearTimeout(timer);
    // while it starts or loads its feeds the page asks the worker to look again, which also makes the login the moment the scanner answers
    if (["starting", "loading"].includes(data.engine.state)) timer = setTimeout(poll, POLL_MS);
  };
  const redraw = async () => draw(await api("GET", A));
  const poll = async () => {
    if (!wrap.isConnected) return;
    try {
      draw(await api("POST", `${A}/check`, {}));
    } catch (_) {
      timer = setTimeout(poll, POLL_MS);
    }
  };
  await redraw();
}
