// Exposed secrets: the project's secrets inventory (docs/SECRETS-PLAN.md section 11). One row per secret, however many hosts and URLs served it.
// No value ever reaches this page: the API sends the mask (AIza…x7Qz), the kind and where it was seen. DOM is built with textContent only.
import { api, badge, button, dialog, el, selectOf, shortDate, table, toast } from "/staticfiles/cve/ui.js";
import { openSecret } from "/staticfiles/cve/secret-panel.js";
import { STATUS_WORDS } from "/staticfiles/cve/secret-detail-logic.js";

const SEV_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const CLASS_WORDS = { P: "Browser key", S: "Server secret", I: "Identifier" };
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
        { label: "Found at", render: (s) => (s.where ? `${s.where.url}${s.where.line != null ? ` (line ${s.where.line})` : ""}` : "not served now") },
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
          const b = el("button", "btn ghost sm", "Open", { type: "button", "aria-label": `Open the secret ${s.masked}` });
          b.onclick = () => openSecret(s.project || slug, s.id, { refresh: load });
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
  // /secrets/?open=ID (a link from a host's score line) opens that secret
  const wanted = new URLSearchParams(location.search).get("open");
  if (wanted && /^\d+$/.test(wanted)) openSecret(slug, Number(wanted), { refresh: load });
}
