// Agents of the organizations an administrator manages: who registered, scope and limits (Manage), work no live agent can take, and the queue.
// It lived on the Administration page; it now sits on the API keys page (agents.html), for administrators only. Sentinels also have their own page.
import { ask, api, badge, button, dialog, el, field, shortDate, table, text, toast } from "/staticfiles/cve/ui.js";

// ---------------------------------------------------------------------------- agents
const AG = "/api/v1";
const csv = (value) => value.split(",").map((v) => v.trim()).filter(Boolean);
const scopeText = (scope) =>
  [["orgs", scope.orgs], ["projects", scope.projects], ["hosts", scope.hosts]]
    .filter(([, list]) => list && list.length)
    .map(([k, list]) => `${k}: ${list.slice(0, 4).join(", ")}${list.length > 4 ? ` +${list.length - 4}` : ""}`)
    .join(" · ") || "no scope declared";

function manageAgent(agent, done) {
  dialog(`Agent ${agent.name}`, (body, close) => {
    body.append(
      el("p", "note", `${agent.kind} agent of ${agent.owner}, token ${agent.token.prefix}...`),
      el("p", "note", `Scope: ${scopeText(agent.scope)}`),
      el("p", "note", `Declared capabilities: ${agent.capabilities.join(", ") || "none"}`),
    );
    if (agent.held_by) body.append(el("p", "msg", `${agent.status === "pending" ? "Waiting for approval" : "Suspended"} automatically: ${agent.status_note || "another agent of this user is suspended or revoked"}`));
    const eff = agent.effective;
    if (eff) body.append(el("p", "note", `Right now it can reach ${eff.projects.length} project(s) with ${eff.capabilities.length} capability(ies)${eff.problem ? `, but ${eff.problem}` : ""}.`));
    const note = text(agent.status_note, { maxlength: "200" });
    const caps = text((agent.limits.capabilities || []).join(", "), { placeholder: "no limit" });
    const projects = text((agent.limits.projects || []).join(", "), { placeholder: "no limit" });
    const concurrent = text(agent.limits.max_concurrent || "", { type: "number", min: "1", max: "10", placeholder: `no limit (agent asks for ${agent.max_concurrent})` });
    body.append(
      field("Note (shown to the agent's owner)", note),
      field("Limit to these capabilities", caps, "Comma separated. The agent keeps only the declared capabilities that are listed."),
      field("Limit to these project slugs", projects),
      field("Most tasks at once", concurrent),
    );
    const send = async (patch, message) => {
      await api("PATCH", `${AG}/agents/${agent.id}`, { note: note.value, ...patch });
      toast(message);
      close();
      done();
    };
    const limits = () => ({
      capabilities: caps.value.trim() ? csv(caps.value) : null,
      projects: projects.value.trim() ? csv(projects.value) : null,
      max_concurrent: concurrent.value ? Number(concurrent.value) : null,
    });
    const actions = el("div", "actions");
    actions.append(button("Cancel", async () => close(), "btn ghost"), el("span", "grow"));
    if (agent.can_manage === false) {
      // their own agent, or a user who also works for an organization they do not administer: every change would be refused
      body.append(el("p", "note", "Another administrator (or an App Admin) decides on this agent."), actions);
      return;
    }
    actions.append(button("Save limits", () => send({ limits: limits() }, "Limits saved"), "btn ghost"));
    if (agent.status === "active") {
      actions.append(
        button("Suspend", () => send({ status: "suspended" }, "Agent suspended; its tasks went back to the queue"), "btn ghost"),
        button("Revoke", async () => {
          if (await ask(`Revoke ${agent.name}? It loses its tasks now and cannot register again until you reinstate it.`, { ok: "Revoke" })) {
            await send({ status: "revoked" }, "Agent revoked");
          }
        }, "btn danger"),
      );
    } else {
      if (agent.status === "revoked") {
        actions.append(button("Delete", async () => {
          if (!(await ask(`Delete ${agent.name} and revoke its token? It no longer holds back new agents of ${agent.owner}. This cannot be undone.`, { ok: "Delete" }))) return;
          const out = await api("DELETE", `${AG}/agents/${agent.id}`);
          const held = out.still_held || [];
          toast(held.length ? `Agent deleted. Still suspended until you reinstate them: ${held.map((h) => h.name).join(", ")}` : "Agent deleted");
          close();
          done();
        }, "btn danger"));
      }
      actions.append(button(agent.status === "pending" ? "Approve" : "Reinstate", () => send({ status: "active" }, "Agent is active"), "btn"));
    }
    body.append(actions);
  });
}

const liveBadge = (a) => (a.status !== "active" ? badge(a.status, a.status === "revoked" ? "failed" : "medium") : a.live ? badge("live", "success") : badge("offline", "info"));

export async function agentsAdmin(panel) {
  const output = el("div");
  panel.append(
    el("p", "note", "Agents are API tokens that registered what they are responsible for and what they can do. The broker hands them validation and remediation work only inside that scope, and only while their user can still reach it. An agent that stops checking in loses its tasks to the queue."),
    output,
  );
  async function load() {
    const [agents, unassignable, tasks] = await Promise.all([
      api("GET", `${AG}/agents?page_size=200`),
      api("GET", `${AG}/projects/_all/agent-tasks/unassignable`),
      api("GET", `${AG}/projects/_all/agent-tasks?status=active&page_size=50`),
    ]);
    if (!panel.isConnected) return;
    output.textContent = "";
    output.append(el("h3", "", "Registered agents"));
    const waiting = agents.results.filter((a) => a.status === "pending").length;
    if (waiting) output.append(el("p", "msg", `${waiting} agent${waiting === 1 ? " is" : "s are"} waiting for approval and get no work until you approve them (Manage, Approve).`));
    const named = agents.results.filter((a) => a.kind !== "scanner"); // Sentinels are managed on Scanners, Sentinels
    output.append(el("p", "note", "Sentinels are on Scanners, Sentinels."));
    agents.results = named;
    if (!agents.results.length) output.append(el("p", "empty", "No agent has registered yet. An agent calls register_agent (MCP) or PUT /api/v1/agent."));
    else {
      output.append(table([
        { label: "Agent", cls: "full", render: (a) => { const b = el("div", "row-card"); b.append(el("span", "cve-id", a.name), el("span", "note", `${a.kind} · ${a.owner} · ${a.token.prefix}...`)); return b; } },
        { label: "State", render: liveBadge },
        { label: "Responsible for", render: (a) => scopeText(a.scope) },
        { label: "Can do", render: (a) => (a.capabilities.join(", ") || "nothing declared") + (a.os.length ? ` · ${a.os.join("/")}` : "") },
        { label: "Last seen", render: (a) => shortDate(a.last_seen) },
        { label: "Tasks", render: (a) => `${a.tasks.open} open · ${a.tasks.completed} done · ${a.tasks.failed} failed` },
        { label: "", render: (a) => button("Manage", async () => manageAgent((await api("GET", `${AG}/agents/${a.id}`)), load), "btn ghost sm") },
      ], agents.results));
    }
    output.append(el("h3", "", "Work no live agent can take"));
    if (!unassignable.results.length) output.append(el("p", "note", "Nothing is stuck: every queued task has an agent that could take it."));
    else {
      output.append(table([
        { label: "Project", render: (t) => t.project },
        { label: "Host", render: (t) => t.host },
        { label: "Work", render: (t) => `${t.kind} ${t.finding.cve || ""} (${t.mode})` },
        { label: "Why", cls: "full", render: (t) => t.reason },
        { label: "", render: (t) => button("Cancel", async () => { await api("POST", `${AG}/projects/${t.project}/agent-tasks/${t.id}/cancel`, {}); toast("Task cancelled"); await load(); }, "btn ghost sm") },
      ], unassignable.results));
    }
    output.append(el("h3", "", "Queued and running"));
    if (!tasks.results.length) output.append(el("p", "note", "No agent work is queued or running."));
    else {
      output.append(table([
        { label: "Project", render: (t) => t.project },
        { label: "Host", render: (t) => t.host },
        { label: "Work", render: (t) => `${t.kind} ${t.finding.cve || ""} (${t.mode})` },
        { label: "Status", render: (t) => badge(t.status, t.status === "running" ? "success" : "info") },
        { label: "Agent", render: (t) => (t.agent ? t.agent.name : "waiting") },
        { label: "Lease until", render: (t) => (t.lease_expires_at ? shortDate(t.lease_expires_at) : "-") },
      ], tasks.results));
    }
  }
  panel.prepend(button("Refresh", load, "btn ghost sm"));
  await load();
}

