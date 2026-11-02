// Administration: people, organizations, projects, timings, audit log. The API decides what each admin may do;
// this page just shows what it allows.
import {
  ask,
  api,
  badge,
  button,
  dialog,
  el,
  field,
  selectOf,
  shortDate,
  table,
  tabs,
  text,
  toast,
} from "/staticfiles/cve/ui.js";
import { openvasPanel } from "/staticfiles/cve/openvas-panel.js";

const A = "/cve/api/admin";
const root = document.getElementById("view");
let me = { is_superuser: false };
let emailReady = false; // outgoing mail is set up (Settings, Email), so a new person can be invited by email

const ROLE_OPTIONS = {
  org: [
    ["admin", "Org Admin"],
    ["user", "Org Member"],
    ["audit", "Audit (read only)"],
  ],
  project: [
    ["user", "Project Member"],
    ["audit", "Audit (read only)"],
  ],
};

function revealPassword(title, username, password, why) {
  dialog(title, (body, close) => {
    if (why)
      body.append(
        el("p", "note", `The email could not be sent (${why}).`),
      );
    body.append(
      el(
        "p",
        "note",
        `Give ${username} this temporary password. It is shown once and they must choose their own at first sign-in.`,
      ),
    );
    const box = el("input", "mono-box", null, {
      readonly: "",
      value: password,
      "aria-label": "Temporary password",
    });
    box.addEventListener("focus", () => box.select());
    body.append(box);
    const actions = el("div", "actions");
    actions.append(
      el("span", "grow"),
      button(
        "Copy",
        async () => {
          await navigator.clipboard.writeText(password);
          toast("Copied");
        },
        "btn ghost",
      ),
      button("Done", async () => close()),
    );
    body.append(actions);
  });
}

// ---------------------------------------------------------------------------- users
async function usersTab(panel) {
  const [users, orgs, projects] = await Promise.all([
    api("GET", `${A}/users`),
    api("GET", `${A}/orgs`),
    api("GET", `${A}/projects`),
  ]);
  me = users.actor;
  emailReady = !!users.email_ready;
  const tools = el("div", "tools");
  const q = text("", {
    type: "search",
    placeholder: "Search people",
    "aria-label": "Search people",
  });
  tools.append(
    q,
    button(
      "+ New person",
      () =>
        newUser(orgs.results, projects.results, () => usersTab(reset(panel))),
      "btn sm",
    ),
  );
  const list = el("div");
  panel.append(tools, list);
  const draw = () => {
    list.textContent = "";
    const term = q.value.toLowerCase();
    const rows = users.results.filter(
      (u) =>
        !term ||
        `${u.username} ${u.name} ${u.email}`.toLowerCase().includes(term),
    );
    if (!rows.length) {
      list.append(el("p", "empty", "Nobody here yet."));
      return;
    }
    list.append(
      table(
        [
          {
            label: "Person",
            cls: "full",
            render: (u) => {
              const b = el("div", "row-card");
              b.append(
                el("span", "cve-id", u.name),
                el(
                  "span",
                  "note",
                  `${u.username}${u.email ? ` · ${u.email}` : ""}`,
                ),
              );
              return b;
            },
          },
          { label: "Role", render: (u) => u.role_label },
          {
            label: "Two-step",
            render: (u) =>
              u.mfa_enabled ? badge("on", "success") : badge("off", "medium"),
          },
          {
            label: "Bug bounty",
            render: (u) =>
              u.is_superuser
                ? badge("always", "success")
                : u.bugbounty_enabled
                  ? badge("authorized", "success")
                  : badge("no", "info"),
          },
          { label: "Last sign-in", render: (u) => shortDate(u.last_login) },
          {
            label: "Status",
            render: (u) =>
              u.is_active
                ? u.invite_pending
                  ? badge("invited", "info")
                  : u.must_change_password
                  ? badge("temp password", "medium")
                  : badge("active", "success")
                : badge("disabled", "critical"),
          },
          {
            label: "",
            render: (u) =>
              button(
                "Manage",
                () =>
                  manageUser(u, orgs.results, projects.results, () =>
                    usersTab(reset(panel)),
                  ),
                "btn ghost sm",
              ),
          },
        ],
        rows,
      ),
    );
  };
  q.addEventListener("input", draw);
  draw();
}
const reset = (panel) => {
  panel.textContent = "";
  return panel;
};

function scopePicker(orgs, projects) {
  const scope = selectOf([
    ["org", "Organization"],
    ["project", "One project"],
  ]);
  const target = selectOf(orgs.map((o) => [o.id, o.name]));
  const role = selectOf(ROLE_OPTIONS.org, "user");
  const sync = () => {
    const isOrg = scope.value === "org";
    target.textContent = "";
    (isOrg
      ? orgs.map((o) => [o.id, o.name])
      : projects.map((p) => [p.id, `${p.name} (${p.org_name})`])
    ).forEach(([v, t]) =>
      target.append(Object.assign(el("option", "", t), { value: v })),
    );
    role.textContent = "";
    ROLE_OPTIONS[scope.value].forEach(([v, t]) =>
      role.append(Object.assign(el("option", "", t), { value: v })),
    );
    role.value = "user";
  };
  scope.addEventListener("change", sync);
  return { scope, target, role, sync };
}

function newUser(orgs, projects, done) {
  if (!orgs.length) {
    toast("Create an organization first.", true);
    return;
  }
  dialog("New person", (body, close) => {
    const username = text("", {
      autocapitalize: "none",
      autocomplete: "off",
      spellcheck: "false",
    });
    const first = text("");
    const last = text("");
    const email = text("", { type: "email" });
    const pick = scopePicker(orgs, projects);
    pick.sync();
    const emailNote = el("p", "note", "", { style: "margin:-6px 0 12px" });
    const showNote = () => {
      emailNote.textContent = !emailReady
        ? "Outgoing mail is not set up (Settings, Email), so you will be shown a temporary password to hand over."
        : email.value.trim()
          ? "They will get an onboarding email with their username and a link to choose a password."
          : "Add an email address to send them an onboarding email; without one you will be shown a temporary password.";
    };
    email.addEventListener("input", showNote);
    showNote();
    body.append(
      field("Account name", username, "Letters, digits and . @ + - _"),
      field("First name", first),
      field("Last name", last),
      field("Email", email, null),
      emailNote,
      field("Add them to", pick.scope),
      field("Which one", pick.target),
      field("Their role", pick.role),
    );
    const actions = el("div", "actions");
    actions.append(
      el("span", "grow"),
      button("Cancel", async () => close(), "btn ghost"),
      button("Create", async () => {
        const r = await api("POST", `${A}/users`, {
          username: username.value,
          first_name: first.value,
          last_name: last.value,
          email: email.value,
          scope: pick.scope.value,
          scope_id: pick.target.value,
          role: pick.role.value,
        });
        close();
        if (r.invited) toast(`Invitation sent to ${r.email}`);
        else
          revealPassword(
            "Account created",
            r.username,
            r.temporary_password,
            r.invite_error,
          );
        done();
      }),
    );
    body.append(actions);
  });
}

function manageUser(u, orgs, projects, done) {
  dialog(u.name, (body, close) => {
    const first = text(u.first_name);
    const last = text(u.last_name);
    const email = text(u.email, { type: "email" });
    body.append(
      el(
        "p",
        "note",
        `${u.username} · joined ${shortDate(u.date_joined)} · last sign-in ${shortDate(u.last_login)}`,
      ),
      field("First name", first),
      field("Last name", last),
      field("Email", email),
      button(
        "Save details",
        async () => {
          await api("PATCH", `${A}/users/${u.id}`, {
            first_name: first.value,
            last_name: last.value,
            email: email.value,
          });
          toast("Saved");
          done();
        },
        "btn sm",
      ),
    );
    body.append(el("h2", "", "Access", { style: "margin-top:20px" }));
    if (!u.memberships.length)
      body.append(
        el(
          "p",
          "note",
          u.is_superuser
            ? "App Admin: access to everything."
            : "No access yet.",
        ),
      );
    u.memberships.forEach((m) => {
      const row = el("div", "access-row");
      row.append(
        el("span", "kind", m.kind),
        el("span", "", m.scope_name),
        badge(m.label),
      );
      row.append(
        button(
          "Remove",
          async () => {
            await api("DELETE", `${A}/memberships/${m.kind}/${m.id}`);
            toast("Removed");
            close();
            done();
          },
          "btn ghost sm",
        ),
      );
      body.append(row);
    });
    if (!u.is_superuser) {
      const pick = scopePicker(orgs, projects);
      pick.sync();
      const add = el("div", "add-access");
      add.append(
        pick.scope,
        pick.target,
        pick.role,
        button(
          "Add access",
          async () => {
            await api("POST", `${A}/memberships`, {
              user_id: u.id,
              scope: pick.scope.value,
              scope_id: pick.target.value,
              role: pick.role.value,
            });
            toast("Access updated");
            close();
            done();
          },
          "btn sm",
        ),
      );
      body.append(add);
    }
    if (me.is_superuser) {
      body.append(el("h2", "", "Bug bounty", { style: "margin-top:20px" }));
      if (u.is_superuser) {
        body.append(el("p", "note", "App Admins always have bug bounty access."));
      } else {
        body.append(
          el(
            "p",
            "note",
            u.bugbounty_enabled
              ? `${u.username} is authorized. They can browse programs, work them and send reports from their own HackerOne account.`
              : `${u.username} is not authorized. Only an App Admin can authorize bug bounty, because reports and scope data go to outside platforms.`,
          ),
          button(
            u.bugbounty_enabled ? "Withdraw bug bounty access" : "Authorize bug bounty",
            async () => {
              if (
                !u.bugbounty_enabled &&
                !(await ask(
                  `${u.username} will get the Bug bounty page: program scope, importing it as targets, and sending reports to platforms under their own account. This is written to the audit log.`,
                  { title: `Authorize bug bounty for ${u.username}?`, ok: "Authorize", danger: false },
                ))
              )
                return;
              await api("PUT", `${A}/users/${u.id}/bug-bounty`, {
                enabled: !u.bugbounty_enabled,
              });
              toast(u.bugbounty_enabled ? "Bug bounty access withdrawn" : "Bug bounty authorized");
              close();
              done();
            },
            "btn ghost sm",
          ),
        );
      }
    }
    body.append(el("h2", "", "Account", { style: "margin-top:20px" }));
    const row = el("div", "actions", null, { style: "flex-wrap:wrap" });
    if (emailReady && u.email && u.must_change_password)
      row.append(
        button(
          "Send the link again",
          async () => {
            const r = await api("POST", `${A}/users/${u.id}/resend-invite`);
            close();
            if (r.invited) toast(`Invitation sent to ${u.email}`);
            else
              revealPassword(
                "Invitation not sent",
                u.username,
                r.temporary_password,
                r.invite_error,
              );
            done();
          },
          "btn ghost sm",
        ),
      );
    row.append(
      button(
        "Reset password",
        async () => {
          const byEmail = emailReady && u.email;
          if (
            !(await ask(
              byEmail
                ? `${u.username} will be signed out everywhere and locked out of the old password. They are emailed a link at ${u.email} to choose a new one.`
                : `${u.username} will be signed out everywhere and given a temporary password.`,
              { title: `Reset the password for ${u.username}?`, ok: "Reset password" },
            ))
          )
            return;
          const r = await api("POST", `${A}/users/${u.id}/reset-password`);
          close();
          if (r.invited) toast(`Reset link sent to ${r.email}`);
          else
            revealPassword(
              "Password reset",
              r.username,
              r.temporary_password,
              r.invite_error,
            );
          done();
        },
        "btn ghost sm",
      ),
      button(
        u.mfa_enabled ? "Reset two-step sign-in" : "Two-step is off",
        async () => {
          if (!u.mfa_enabled) return;
          if (!(await ask("They can set it up again afterwards.", { title: `Turn off two-step sign-in for ${u.username}?`, ok: "Turn off" }))) return;
          await api("POST", `${A}/users/${u.id}/reset-mfa`);
          toast("Two-step sign-in reset");
          close();
          done();
        },
        "btn ghost sm",
      ),
      button(
        u.is_active ? "Disable account" : "Enable account",
        async () => {
          await api("PATCH", `${A}/users/${u.id}`, { is_active: !u.is_active });
          toast(u.is_active ? "Account disabled" : "Account enabled");
          close();
          done();
        },
        "btn ghost sm",
      ),
    );
    if (me.is_superuser && u.id !== me.id) {
      row.append(
        button(
          "Delete account",
          async () => {
            if (
              window.prompt(
                `Type ${u.username} to delete this account permanently.`,
              ) !== u.username
            )
              return;
            await api("DELETE", `${A}/users/${u.id}`);
            toast("Account deleted");
            close();
            done();
          },
          "btn ghost sm",
        ),
      );
    }
    body.append(row);
    const actions = el("div", "actions");
    actions.append(
      el("span", "grow"),
      button("Close", async () => close(), "btn ghost"),
    );
    body.append(actions);
  });
}

// ---------------------------------------------------------------------------- organizations
function openOrgApiKeys(o) {
  dialog(`${o.name}: API keys`, (body, close) => {
    body.append(
      el(
        "p",
        "note",
        "Shared across every project in this organization. A project may set its own key instead, which overrides this one for that project only.",
      ),
    );
    const list = el("div");
    body.append(list);
    async function draw() {
      list.textContent = "";
      const data = await api("GET", `${A}/orgs/${o.id}/api-keys`);
      data.results.filter((svc) => !(svc.retired && !svc.configured)).forEach((svc) => {
        const row = el("div", "access-row");
        row.append(el("span", "", svc.label));
        if (svc.configured) row.append(badge("configured", "success"));
        if (svc.retired) row.append(badge("retired", "queued"), el("span", "note", svc.retired));
        else if (svc.used_by_sync) row.append(el("span", "note", "read by the scheduled sync"));
        else if (!svc.used_in_scans) row.append(el("span", "note", "not used by scans yet"));
        row.append(
          button(
            svc.retired ? "Remove" : svc.configured ? "Edit" : "Configure",
            () => openOrgApiKeyEditor(o, svc, draw),
            "btn ghost sm",
          ),
        );
        list.append(row);
      });
    }
    draw();
    const actions = el("div", "actions");
    actions.append(
      el("span", "grow"),
      button("Close", async () => close(), "btn ghost"),
    );
    body.append(actions);
  });
}

function openOrgApiKeyEditor(o, svc, onSaved) {
  dialog(`${o.name}: ${svc.label}`, (body, close) => {
    if (svc.retired) body.append(el("p", "note", svc.retired));
    const inputs = (svc.retired ? [] : svc.fields).map((f) => {
      const input = text("", {
        type: f.secret ? "password" : "text",
        autocomplete: "off",
        spellcheck: "false",
        placeholder:
          f.secret && svc.set[f.name] ? "saved (leave blank to keep)" : "",
      });
      body.append(field(f.label, input));
      return { name: f.name, input };
    });
    const actions = el("div", "actions");
    const remove = button(
      "Remove",
      async () => {
        await api("DELETE", `${A}/orgs/${o.id}/api-keys/${svc.service}`);
        toast(`${svc.label} key removed`);
        close();
        onSaved();
      },
      "btn ghost",
    );
    remove.style.display = svc.configured ? "" : "none";
    const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
    cancel.onclick = close;
    actions.append(
      remove,
      el("span", "grow"),
      cancel,
      ...(svc.retired ? [] : [button("Save", async () => {
        const values = Object.fromEntries(
          inputs.map((i) => [i.name, i.input.value]).filter(([, v]) => v),
        );
        await api("PUT", `${A}/orgs/${o.id}/api-keys/${svc.service}`, values);
        toast(`${svc.label} key saved`);
        close();
        onSaved();
      })]),
    );
    body.append(actions);
  });
}

async function orgsTab(panel) {
  const orgs = (await api("GET", `${A}/orgs`)).results;
  const tools = el("div", "tools");
  if (me.is_superuser) {
    tools.append(
      button(
        "+ New organization",
        async () => {
          const name = window.prompt("Organization name");
          if (!name) return;
          await api("POST", `${A}/orgs`, { name });
          toast("Organization created");
          orgsTab(reset(panel));
        },
        "btn sm",
      ),
    );
  }
  panel.append(tools);
  if (!orgs.length) panel.append(el("p", "empty", "No organizations."));
  orgs.forEach((o) => {
    const card = el("section", "card org-card");
    card.append(el("h2", "", o.name));
    card.append(
      el(
        "p",
        "note",
        `${o.members} member${o.members === 1 ? "" : "s"}, ${o.admins} admin${o.admins === 1 ? "" : "s"}, ${o.projects.length} project${o.projects.length === 1 ? "" : "s"}`,
      ),
    );
    const projects = el("div", "chips");
    o.projects.forEach((p) => projects.append(el("span", "chip", p.name)));
    card.append(projects);
    const row = el("div", "actions", null, {
      style: "flex-wrap:wrap;margin-top:12px",
    });
    row.append(
      button(
        o.require_mfa
          ? "Two-step required: turn off"
          : "Require two-step sign-in",
        async () => {
          await api("PATCH", `${A}/orgs/${o.id}`, {
            require_mfa: !o.require_mfa,
          });
          toast("Updated");
          orgsTab(reset(panel));
        },
        "btn ghost sm",
      ),
      button(
        "Rename",
        async () => {
          const name = window.prompt("New name", o.name);
          if (!name || name === o.name) return;
          await api("PATCH", `${A}/orgs/${o.id}`, { name });
          toast("Renamed");
          orgsTab(reset(panel));
        },
        "btn ghost sm",
      ),
      button("API keys", () => openOrgApiKeys(o), "btn ghost sm"),
    );
    if (me.is_superuser) {
      row.append(
        button(
          "Delete organization",
          async () => {
            if (
              window.prompt(
                `Type ${o.name} to delete this organization${o.projects.length ? " AND its projects, targets, scans and findings" : ""}.`,
              ) !== o.name
            )
              return;
            const r = await api("DELETE", `${A}/orgs/${o.id}`, {
              confirm: o.name,
              delete_projects: true,
            });
            toast(`Deleted (${r.projects_deleted} projects)`);
            orgsTab(reset(panel));
          },
          "btn ghost sm",
        ),
      );
    }
    card.append(row);
    panel.append(card);
  });
}

// ---------------------------------------------------------------------------- projects
async function projectsTab(panel) {
  const [projects, orgs] = await Promise.all([
    api("GET", `${A}/projects`),
    api("GET", `${A}/orgs`),
  ]);
  const tools = el("div", "tools");
  tools.append(
    button(
      "+ New project",
      () => {
        if (!orgs.results.length) {
          toast("You do not administer an organization.", true);
          return;
        }
        dialog("New project", (body, close) => {
          const name = text("");
          const org = selectOf(orgs.results.map((o) => [o.id, o.name]));
          body.append(field("Project name", name), field("Organization", org));
          const actions = el("div", "actions");
          actions.append(
            el("span", "grow"),
            button("Cancel", async () => close(), "btn ghost"),
            button("Create", async () => {
              await api("POST", `${A}/projects`, {
                name: name.value,
                org_id: org.value,
              });
              toast("Project created");
              close();
              projectsTab(reset(panel));
            }),
          );
          body.append(actions);
        });
      },
      "btn sm",
    ),
  );
  panel.append(tools);
  if (!projects.results.length) {
    panel.append(el("p", "empty", "No projects yet."));
    return;
  }
  panel.append(
    table(
      [
        { label: "Project", render: (p) => p.name },
        { label: "Organization", render: (p) => p.org_name },
        {
          label: "",
          render: (p) => {
            const box = el("div", "row-actions");
            box.append(
              Object.assign(el("a", "btn ghost sm", "Open"), {
                href: `/cve/${p.slug}/targets/`,
                style:
                  "display:inline-flex;align-items:center;text-decoration:none",
              }),
              button(
                "Delete",
                async () => {
                  if (
                    window.prompt(
                      `Type ${p.name} to delete this project with all its targets, scans and findings. This cannot be undone.`,
                    ) !== p.name
                  )
                    return;
                  await api("DELETE", `${A}/projects/${p.id}`, {
                    confirm: p.name,
                  });
                  toast("Project deleted");
                  projectsTab(reset(panel));
                },
                "btn ghost sm",
              ),
            );
            return box;
          },
        },
      ],
      projects.results,
    ),
  );
}

// ---------------------------------------------------------------------------- timings (App Admin)
async function timingsTab(panel) {
  const t = await api("GET", `${A}/timings`);
  const fields = [
    ["cve_sync_minutes", "Read the CVE feed every (minutes)"],
    ["hygiene_hour_utc", "Daily certificate and email check at (hour, UTC)"],
    ["ct_watch_minutes", "Re-check certificate transparency every (minutes)"],
    ["discovery_timeout_hours", "Longest a discovery may run (hours)"],
    ["nuclei_timeout_hours", "Longest a nuclei scan may run (hours)"],
  ];
  const inputs = {};
  const card = el("section", "card");
  card.style.maxWidth = "560px";
  card.append(
    el("h2", "", "Timings"),
    el(
      "p",
      "note",
      "Schedules apply immediately. Run limits apply to the next scan.",
    ),
  );
  fields.forEach(([k, label]) => {
    inputs[k] = text(t[k], {
      type: "number",
      min: t.limits[k][0],
      max: t.limits[k][1],
    });
    card.append(
      field(
        label,
        inputs[k],
        `Between ${t.limits[k][0]} and ${t.limits[k][1]}.`,
      ),
    );
  });
  card.append(
    button("Save timings", async () => {
      await api(
        "PUT",
        `${A}/timings`,
        Object.fromEntries(fields.map(([k]) => [k, inputs[k].value])),
      );
      toast("Timings saved");
    }),
  );
  panel.append(card);
}

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

async function agentsTab(panel) {
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
    output.append(el("h3", "", "Agents"));
    const waiting = agents.results.filter((a) => a.status === "pending").length;
    if (waiting) output.append(el("p", "msg", `${waiting} agent${waiting === 1 ? " is" : "s are"} waiting for approval and get no work until you approve them (Manage, Approve).`));
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

// ---------------------------------------------------------------------------- audit
async function auditTab(panel) {
  const rows = (await api("GET", `${A}/audit`)).results;
  if (!rows.length) {
    panel.append(el("p", "empty", "Nothing has been changed yet."));
    return;
  }
  panel.append(
    table(
      [
        { label: "When", render: (r) => shortDate(r.at) },
        { label: "Who", render: (r) => r.actor },
        { label: "What", render: (r) => r.action },
        { label: "On", render: (r) => r.target || "-" },
      ],
      rows,
    ),
  );
}

async function activityTab(panel) {
  const controls = el("div", "tools");
  const search = el("input", "", null, { type: "search", placeholder: "Search message or CVE", "aria-label": "Search activity" });
  const project = el("input", "", null, { type: "search", placeholder: "Project slug", "aria-label": "Project slug" });
  const stage = el("input", "", null, { type: "search", placeholder: "Stage", "aria-label": "Activity stage" });
  const job = el("input", "", null, { type: "number", min: "1", placeholder: "Job ID", "aria-label": "Job ID" });
  const finding = el("input", "", null, { type: "number", min: "1", placeholder: "Finding ID", "aria-label": "Finding ID" });
  const errors = el("input", "", null, { type: "checkbox", "aria-label": "Errors only" });
  const errorsLabel = el("label", "note", "Errors only ");
  errorsLabel.prepend(errors);
  const output = el("div");
  let page = 1;
  let requestNumber = 0;
  async function load(reset = true) {
    if (reset) { page = 1; output.textContent = ""; }
    const current = ++requestNumber;
    const params = new URLSearchParams({ page: String(page), page_size: "100" });
    for (const [key, input] of [["q", search], ["project", project], ["stage", stage],
                               ["job_id", job], ["finding_id", finding]]) {
      if (input.value.trim()) params.set(key, input.value.trim());
    }
    if (errors.checked) params.set("errors", "1");
    const data = await api("GET", `${A}/activity?${params}`);
    if (current !== requestNumber || !panel.isConnected) return;
    output.querySelector(".activity-more")?.remove();
    if (!data.results.length && page === 1) output.append(el("p", "empty", "No matching retained activity."));
    if (data.results.length) output.append(table([
      { label: "When", render: (r) => shortDate(r.at) },
      { label: "Project", render: (r) => r.project || "System" },
      { label: "Stage", render: (r) => r.kind },
      { label: "Status", render: (r) => badge(r.status, r.status === "failed" ? "failed" : "") },
      { label: "Activity", render: (r) => r.message },
      { label: "Diagnostic", render: (r) => {
        if (!r.diagnostic) return r.status === "failed" ? "Not captured by this worker version" : "-";
        const details = el("details");
        const safe = JSON.stringify(r.diagnostic, null, 2);
        details.append(el("summary", "", "View safe worker trace"), el("pre", "", safe),
          button("Copy diagnostic", async () => {
            await navigator.clipboard.writeText(safe);
            toast("Diagnostic copied");
          }, "btn ghost sm"));
        return details;
      } },
    ], data.results));
    if (page * data.page_size < data.count) {
      const more = button("Load older", () => { page += 1; load(false); }, "btn ghost sm activity-more");
      output.append(more);
    }
  }
  controls.append(search, project, stage, job, finding, errorsLabel,
    button("Apply filters", () => load(), "btn sm"), button("Refresh latest", () => load(), "btn ghost sm"));
  panel.append(controls, el("p", "note", "Shows retained activity. Older entries trimmed by previous versions cannot be recovered."), output);
  await load();
}

async function healthTab(panel) {
  const output = el("div");
  const refresh = button("Refresh health", load, "btn sm");
  panel.append(el("p", "note", "Worker counts are a short live inspection. Beat dispatch times come from the schedule database; this page cannot prove that the Beat process is alive."), refresh, output);
  async function load() {
    const data = await api("GET", `${A}/health`);
    if (!panel.isConnected) return;
    output.textContent = "";
    output.append(el("h3", "", "Workers"), el("p", "note", `Inspection: ${data.workers_state}. ${data.worker_note || ""}`));
    if (data.workers.length) output.append(table([
      { label: "Worker", render: (r) => r.worker },
      { label: "Required queue", render: (r) => r.queue },
      { label: "Consuming", render: (r) => r.consuming === null ? "unknown" : r.consuming ? "yes" : "no" },
      { label: "Active", render: (r) => r.active === null ? "unknown" : String(r.active) },
    ], data.workers));
    output.append(el("h3", "", "Pending work"), table([
      { label: "Kind", render: (r) => r[0].replaceAll("_", " ") },
      { label: "Pending", render: (r) => String(r[1].pending) },
      { label: "Oldest", render: (r) => shortDate(r[1].oldest) },
    ], Object.entries(data.jobs).filter(([kind]) => kind !== "scans")));
    output.append(el("p", "note", `${data.jobs.scans.pending} scans queued; ${data.jobs.scans.running} running.`));
    output.append(el("h3", "", "Three-hour assessment review"));
    const review = data.assessment_review;
    output.append(el("p", "note", data.scanning_paused ? "Scanning is paused; review dispatch waits for resume." :
      review ? `Review #${review.id} · ${review.status} · ${review.reviewed}/${review.total} project summaries processed · ${review.model_calls} AI attempts · ${review.actions} actions queued · ${review.errors} deferred or failed. Started ${shortDate(review.started_at)}.${review.note ? ` ${review.note}` : ""}` :
        "No assessment review has run yet. The three-hour Beat schedule appears below."));
    if (review) {
      const performance = review.performance || {};
      output.append(el("p", "note", `Capacity review: ${performance.status || "pending"}. ${performance.reason || "No measurement yet."}`));
      if (performance.status === "changed") output.append(el("p", "note", `${performance.kind}: admission cap ${performance.before} → ${performance.after}${performance.rollback ? " (rollback)" : ""}.`));
      if (review.recent_decisions.length) output.append(table([
        { label: "Project", render: (r) => r.project },
        { label: "Decision", render: (r) => r.action },
        { label: "Status", render: (r) => r.status },
        { label: "Why / job", render: (r) => `${r.reason}${r.job_id ? ` · job #${r.job_id}` : ""}` },
      ], review.recent_decisions));
    }
    const archived = data.archive_rediscovery;
    if (archived) {
      output.append(el("h3", "", "Archived asset rediscovery"));
      output.append(el("p", "note", `${archived.archived_hosts} hosts currently archived. ${archived.run_id ?
        `Daily run #${archived.run_id}: ${archived.status}; ${archived.checked} visited (started with ${archived.total_at_start}), ${archived.reactivated} reactivated, ${archived.deferred} deferred, ${archived.errors} errors. ${archived.finished_at ? `Finished ${shortDate(archived.finished_at)}.` : "More work may remain."}` :
        "No daily check has run yet."}`));
    }
    const inactive = data.inactive_archive_review;
    if (inactive) {
      output.append(el("h3", "", "Inactive host review"));
      output.append(el("p", "note", `${inactive.retired_unarchived} retired hosts remain active in inventory. ${inactive.run_id ?
        `Daily run #${inactive.run_id}: ${inactive.status}; ${inactive.checked} checked, ${inactive.archived} archived, ${inactive.reactivated} reappeared, ${inactive.deferred} deferred, ${inactive.errors} errors. Cursor ${inactive.cursor}.` :
        "No daily inactive-host review has run yet."} Archival needs repeated negative observations at least 30 days apart; pinning prevents it.`));
    }
    output.append(el("h3", "", "Scheduled dispatch"), table([
      { label: "Task", render: (r) => r.name },
      { label: "Queue", render: (r) => r.queue },
      { label: "Last dispatch", render: (r) => shortDate(r.last_dispatch) },
      { label: "Next due", render: (r) => r.next_due ? `${shortDate(r.next_due)}${r.next_due_state === "past_due_unconfirmed" ? " · past due; dispatch unconfirmed" : ""}` : "unknown" },
      { label: "Count", render: (r) => String(r.dispatch_count) },
    ], data.schedules));
    for (const status of ["running", "done", "failed"]) {
      const row = data.last_activity[status];
      output.append(el("p", "note", `Last ${status} activity: ${row ? `${row.stage} at ${shortDate(row.at)}` : "none retained"}`));
    }
  }
  await load();
}

(async () => {
  try {
    me = (await api("GET", `${A}/users`)).actor;
  } catch (err) {
    root.append(el("p", "msg err", err.message));
    return;
  }
  const defs = {
    users: { label: "People", open: usersTab },
    orgs: { label: "Organizations", open: orgsTab },
    projects: { label: "Projects", open: projectsTab },
  };
  if (me.is_superuser) defs.timings = { label: "Timings", open: timingsTab };
  if (me.is_superuser) defs.health = { label: "Scheduler health", open: healthTab };
  defs.openvas = { label: "OpenVAS", open: openvasPanel };
  defs.agents = { label: "Agents", open: agentsTab };
  defs.audit = { label: "Audit log", open: auditTab };
  defs.activity = { label: "Activity and errors", open: activityTab };
  document.getElementById("admin-sub").textContent = me.is_superuser
    ? "You are an App Admin: everything is yours."
    : "You administer the organizations shown here.";
  tabs(root, defs, "users");
})();
