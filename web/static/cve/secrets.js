// Exposed secrets: the project's secrets inventory (docs/SECRETS-PLAN.md section 11). One row per secret, however many hosts and URLs served it.
// No value ever reaches this page: the API sends the mask (AIza…x7Qz), the kind and where it was seen. DOM is built with textContent only.
import { api, badge, button, dialog, el, field, selectOf, shortDate, table, toast } from "/staticfiles/cve/ui.js";

const SEV_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const CLASS_WORDS = { P: "Browser key", S: "Server secret", I: "Identifier" };
const STATUS_WORDS = {
  unverified: "Unverified",
  live: "Live (validated)",
  inactive: "Inactive",
  inconclusive: "Inconclusive",
  public_by_design: "Public by design",
  accepted: "Accepted",
  revoked: "Revoked",
  false_positive: "False positive",
};
const PERSON_STATUSES = ["unverified", "public_by_design", "accepted", "revoked", "false_positive"];
const STATUS_HELP = {
  public_by_design: "A browser key meant to be in the page, restricted at the provider. It stops counting in the host scores.",
  accepted: "Known and accepted. It stops counting in the host scores.",
  revoked: "Rotated at the provider. It closes once no scan sees it any more.",
  false_positive: "Not a secret (a placeholder, a test value). It stops counting.",
  unverified: "Back to the default: rated by its kind until a person or a validation says more.",
};

function filterBar(onChange) {
  const tools = el("div", "tools");
  const status = selectOf([["open", "Open"], ["quiet", "Quiet (public, accepted, revoked, false positive)"], ["all", "All"], ["live", "Live (validated)"]], "open");
  const klass = selectOf([["", "Every class"], ["S", "Server secrets"], ["P", "Browser keys"], ["I", "Identifiers"]], "");
  const q = el("input", "", null, { type: "search", placeholder: "Provider, kind, host or mask", "aria-label": "Filter secrets" });
  [status, klass].forEach((s) => (s.onchange = onChange));
  q.oninput = () => {
    clearTimeout(q.timer);
    q.timer = setTimeout(onChange, 250);
  };
  tools.append(status, klass, q);
  return { tools, params: () => ({ status: status.value, class: klass.value, q: q.value.trim() }) };
}

function validationPanel(slug, state, refresh) {
  const v = state.validation;
  const box = el("div", "card secrets-validation");
  box.append(el("h3", "", "Secret validation"));
  const words = v.enabled
    ? `On${v.by ? `, switched on by ${v.by.name}` : ""}${v.at ? ` on ${shortDate(v.at)}` : ""}. The built-in scanner checks found credentials once a week per host with read-only identity calls (${v.rules.length} reviewed rules).`
    : "Off. Found secrets are detected and rated by their kind only; nothing is sent to any provider.";
  box.append(el("p", "note", words));
  if (v.blocked_reason && v.enabled) box.append(el("p", "msg err", v.blocked_reason));
  if (v.bounty_project) box.append(el("p", "note", "This project has a bug bounty engagement: found credentials are never used, so validation cannot be switched on."));
  if (!v.can_switch) return box;
  if (v.enabled) {
    box.append(button("Switch validation off", async () => {
      await api("PUT", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/settings`, { validation: { enabled: false } });
      toast("Secret validation is off");
      refresh();
    }, "btn ghost sm"));
  } else if (!v.bounty_project) {
    const open = el("button", "btn sm", "Switch validation on…", { type: "button" });
    open.onclick = () => dialog("Switch secret validation on", (body, close) => {
      body.append(
        el("p", "note", "The built-in scanner would authenticate to the provider with each credential it finds, read-only (for example AWS GetCallerIdentity, GitHub GET /user). A key on your site can belong to a vendor: checking it is using their credential. Only switch this on for targets and accounts that are yours."),
        el("blockquote", "", v.attestation),
      );
      const check = el("input", "", null, { type: "checkbox" });
      const label = el("label", "check");
      label.append(check, document.createTextNode(" I accept this statement on behalf of the organization"));
      body.append(label);
      const go = button("Switch on", async () => {
        if (!check.checked) throw new Error("Accept the statement first");
        await api("PUT", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/settings`, { validation: { enabled: true, attestation: v.attestation } });
        close();
        toast("Secret validation is on");
        refresh();
      });
      body.append(go);
    });
    box.append(open);
  }
  return box;
}

function detail(slug, id, canWrite, refresh) {
  dialog("Secret", async (body, close) => {
    let s;
    try {
      s = await api("GET", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}`);
    } catch (err) {
      body.append(el("p", "msg err", err.message));
      return;
    }
    const head = el("div", "card-head");
    head.append(badge(s.severity, SEV_BADGE[s.severity] || "info"), el("b", "", `${s.label}`), el("code", "", s.masked), el("span", "note", CLASS_WORDS[s.class] || ""));
    body.append(head, el("p", "note", `Why ${s.severity}: ${s.severity_basis}`));
    if (!s.catalogued) body.append(el("p", "note", "Uncatalogued rule: rated as a server secret of medium severity until a person reviews it."));
    body.append(el("h3", "", "How to fix"), el("p", "", s.remediation));
    if (s.docs) body.append(el("a", "", "Provider documentation", { href: s.docs, target: "_blank", rel: "noopener noreferrer" }));
    const facts = [
      ["Status", STATUS_WORDS[s.status] || s.status],
      ["Rules", s.rule_ids.join(", ")],
      ["Seen", `${s.occurrences} place${s.occurrences === 1 ? "" : "s"} on ${s.hosts} host${s.hosts === 1 ? "" : "s"}, first ${shortDate(s.first_seen)}, last ${shortDate(s.last_seen)}`],
      ["Validation", s.validation.outcome ? `${s.validation.outcome} on ${shortDate(s.validation.at)}` : "not validated"],
    ];
    if (s.facts && s.facts.exp) facts.push(["Expires (JWT exp, unverified)", new Date(s.facts.exp * 1000).toISOString().slice(0, 10)]);
    if (s.status_note) facts.push(["Note", `${s.status_note}${s.status_by ? ` (${s.status_by.name})` : ""}`]);
    const dl = el("dl", "supplier-kv");
    facts.forEach(([k, v]) => dl.append(el("dt", "", k), el("dd", "", v)));
    body.append(dl);
    body.append(el("h3", "", "Where it was seen"));
    body.append(table([
      { label: "Host", render: (o) => o.host },
      { label: "URL", render: (o) => o.url },
      { label: "Found by", render: (o) => `${o.source} (${o.rule_id})${o.line != null ? ` line ${o.line}` : ""}` },
      { label: "Last seen", render: (o) => (o.retired_at ? `gone since ${shortDate(o.retired_at)}` : shortDate(o.last_seen)) },
    ], s.occurrence_list));
    if (s.resources.length) {
      body.append(el("h3", "", "Resources it points at"));
      body.append(el("p", "note", s.resources.map((r) => `${r.kind}: ${r.identifier}`).join(", ")));
    }
    if (!canWrite) return;
    body.append(el("h3", "", "Decision"));
    const status = selectOf(PERSON_STATUSES.map((k) => [k, STATUS_WORDS[k]]), PERSON_STATUSES.includes(s.status) ? s.status : "unverified");
    const help = el("p", "note", STATUS_HELP[status.value] || "");
    status.onchange = () => (help.textContent = STATUS_HELP[status.value] || "");
    const note = el("textarea", "", null, { rows: "2", maxlength: "2000", placeholder: "Why (optional)" });
    body.append(field("Status", status), help, field("Note", note));
    body.append(button("Save", async () => {
      await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/status`, { status: status.value, note: note.value });
      close();
      toast("Saved");
      refresh();
    }));
    const v = s.validation_available;
    if (v && v.enabled && v.can_switch && !v.blocked_reason) {
      body.append(button("Validate now", async () => {
        const out = await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/${id}/validate`);
        toast(`Queued: the built-in scanner reads ${out.hosts.length} host${out.hosts.length === 1 ? "" : "s"} again`);
      }, "btn ghost"));
    }
  });
}

export async function secretsPage(mount, { slug, all, canWrite }) {
  mount.append(el("p", "note page-intro", "API keys, tokens and private keys the project's pages and scripts serve, one row per secret however many places serve it. Values are never stored or shown: only the format prefix and the last four characters. A browser key (Google, Stripe pk_, Mapbox pk.) is meant to be public and is rated info until a person or a validation says otherwise."));
  const top = el("div");
  const summary = el("p", "note", "", { role: "status" });
  const list = el("div");
  const bar = filterBar(() => load());
  mount.append(top, bar.tools, summary, list);

  async function settings() {
    if (all) return;
    top.textContent = "";
    try {
      top.append(validationPanel(slug, await api("GET", `/api/v1/projects/${encodeURIComponent(slug)}/secrets/settings`), settings));
    } catch (_) {
      /* the switch is a convenience on this page */
    }
  }

  async function load() {
    const p = bar.params();
    const qs = new URLSearchParams({ page_size: "200", status: p.status });
    if (p.class) qs.set("class", p.class);
    if (p.q) qs.set("q", p.q);
    try {
      const data = await api("GET", `/api/v1/projects/${encodeURIComponent(slug)}/secrets?${qs}`);
      list.textContent = "";
      summary.textContent = `${data.count} secret${data.count === 1 ? "" : "s"}${data.count > data.results.length ? `, the worst ${data.results.length} shown` : ""}.`;
      if (!data.results.length) {
        list.append(el("p", "note", p.status === "open" ? "No open secrets. The secrets scan reads the web hosts' pages and scripts once a week." : "Nothing matches."));
        return;
      }
      const cols = [
        { label: "Severity", render: (s) => badge(s.severity, SEV_BADGE[s.severity] || "info") },
        { label: "Provider", render: (s) => s.provider || "(none)" },
        { label: "Kind", render: (s) => `${s.kind}${s.catalogued ? "" : " (uncatalogued)"}` },
        { label: "Secret", render: (s) => el("code", "", s.masked) },
        { label: "Class", render: (s) => CLASS_WORDS[s.class] || s.class },
        { label: "Status", render: (s) => STATUS_WORDS[s.status] || s.status },
        { label: "Hosts", render: (s) => String(s.hosts) },
        { label: "Places", render: (s) => String(s.occurrences) },
        { label: "Last seen", render: (s) => shortDate(s.last_seen) },
      ];
      if (all) cols.unshift({ label: "Project", render: (s) => s.project_name || s.project });
      cols.push({
        label: "",
        render: (s) => {
          const b = el("button", "btn ghost sm", "Open", { type: "button" });
          b.onclick = () => detail(s.project || slug, s.id, canWrite && !all, load);
          return b;
        },
      });
      list.append(table(cols, data.results));
    } catch (err) {
      list.textContent = "";
      list.append(el("p", "msg err", `Could not load secrets: ${err.message}`));
    }
  }
  settings();
  load();
}
