// Third-party suppliers: a Shodan-style host card per supplier domain, and a technology search across all of them ("who runs PHP?").
// A supplier is not an owned host: nothing here scans, and the checks behind it are passive (a TLS handshake, normal page requests, DNS).
// DOM is built with textContent only; everything shown that came from a supplier's own responses is text, never markup.
import { api, ask, badge, copyText, dialog, el, field, selectOf, shortDate, text, toast } from "/staticfiles/cve/ui.js";

const TIER_BADGE = { critical: "critical", high: "high", normal: "info" };
const STATE_WORDS = {
  ok: ["answered", "success"],
  unreachable: ["not answering", "queued"],
  no_address: ["no address", "queued"],
  blocked: ["not public: not contacted", "queued"],
  challenged: ["edge challenged it", "medium"],
  excluded: ["excluded: not contacted", "queued"],
};
const SEV_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const CATEGORY_WORDS = { tls: "Certificate", email: "Email", web: "Headers", exposed: "Exposed page", cve: "Known CVEs (informational)" };

const kv = (rows) => {
  const box = el("dl", "supplier-kv");
  rows.filter(([, v]) => v !== "" && v != null && !(Array.isArray(v) && !v.length)).forEach(([k, v]) => {
    box.append(el("dt", "", k), el("dd", "", Array.isArray(v) ? v.join(", ") : String(v)));
  });
  return box;
};

function techChips(card, terms) {
  const box = el("div", "chips supplier-tech");
  const hit = new Set((card.matched || []).map((t) => `${t.name}\u0000${t.version}`));
  (card.technologies || []).forEach((t) => {
    const chip = el("span", `chip${hit.has(`${t.name}\u0000${t.version}`) ? " hit" : ""}`, `${t.name}${t.version ? ` ${t.version}` : ""}`, { title: t.category ? `${t.category} (from ${t.source})` : `from ${t.source}` });
    box.append(chip);
  });
  if (!box.childNodes.length) box.append(el("span", "note", terms.length ? "Matched on the server banner only." : "No technology stated by the responses."));
  return box;
}

function detailsOf(card) {
  const http = card.http || {};
  const tls = card.tls || {};
  const box = el("details", "supplier-more");
  box.append(el("summary", "", "Headers, certificate and evidence"));
  box.append(el("h4", "", "Certificate"));
  box.append(
    kv([
      ["Subject", tls.subject], ["Issuer", tls.issuer], ["Names", tls.sans], ["Valid from", tls.not_before && shortDate(tls.not_before)],
      ["Valid until", tls.not_after && `${shortDate(tls.not_after)}${tls.days_left != null ? ` (${tls.days_left} days)` : ""}`],
      ["Key", tls.key], ["Signature", tls.signature], ["Protocol", tls.protocol], ["Cipher", tls.cipher],
      ["Trust problem", tls.chain_error], ["Accepts TLS 1.0 or 1.1", tls.legacy_tls ? "yes" : ""],
    ]),
  );
  if (!tls.subject) box.lastChild.replaceWith(el("p", "note", "No certificate read yet."));
  box.append(el("h4", "", "Response headers"));
  const headers = Object.entries(http.headers || {});
  if (headers.length) box.append(kv(headers.map(([k, v]) => [k, v])));
  else box.append(el("p", "note", "No response read yet."));
  box.append(el("h4", "", "Other"));
  box.append(
    kv([
      ["Addresses", card.addresses], ["Front page", http.url], ["Title", http.title], ["Status", http.status],
      ["Plain HTTP answered", http.http_status], ["Cookies set (names)", http.cookies], ["Handles mail", card.mail && card.mail.handles_mail ? "yes" : ""],
      ["Edge in front", (card.evidence || {}).edge], ["Note", (card.evidence || {}).note], ["Challenged by", (card.evidence || {}).challenged],
      ["Last answered", card.last_ok && shortDate(card.last_ok)],
    ]),
  );
  return box;
}

function hostCard(card, terms) {
  const box = el("div", "card supplier-card");
  const head = el("div", "card-head");
  head.append(el("b", "mono", card.domain));
  const [word, cls] = STATE_WORDS[card.state] || [card.state, "queued"];
  head.append(badge(word, cls));
  box.append(head);
  box.append(techChips(card, terms));
  const http = card.http || {};
  const tls = card.tls || {};
  const banner = [http.server && `Server: ${http.server}`, http.powered_by && `X-Powered-By: ${http.powered_by}`].filter(Boolean);
  if (banner.length) box.append(el("p", "note mono", banner.join("   ")));
  if (tls.issuer || tls.not_after) {
    box.append(
      el("p", "note", [tls.issuer && `Certificate by ${tls.issuer}`, tls.not_after && `expires ${shortDate(tls.not_after).slice(0, 10)}${tls.days_left != null ? ` (${tls.days_left} days)` : ""}`,
        tls.protocol, tls.cipher].filter(Boolean).join(" · ")),
    );
  }
  box.append(el("p", "note", card.checked ? `Checked ${shortDate(card.checked)}` : "Not checked yet"));
  box.append(detailsOf(card));
  return box;
}

async function findingsPanel(supplier, canEdit, refresh) {
  const box = el("div", "supplier-findings");
  const data = await api("GET", `/api/v1/projects/${encodeURIComponent(supplier.slug)}/suppliers/findings?supplier=${supplier.id}&page_size=100`);
  if (!data.results.length) {
    box.append(el("p", "note", "No open findings."));
    return box;
  }
  data.results.forEach((f) => {
    const row = el("div", "supplier-finding");
    const top = el("div", "card-head");
    top.append(badge(f.severity, SEV_BADGE[f.severity] || "info"), el("b", "", f.title), el("span", "note", CATEGORY_WORDS[f.category] || f.category));
    row.append(top);
    if (f.ask) row.append(el("p", "note", f.ask));
    if (canEdit) {
      const accept = el("button", "btn ghost sm", "Accept", { type: "button", title: "Keep checking, but take it off the open list" });
      accept.onclick = async () => {
        try {
          await api("PATCH", `/api/v1/projects/${encodeURIComponent(supplier.slug)}/suppliers/findings/${f.id}`, { status: "accepted" });
          refresh();
        } catch (err) {
          toast(err.message, true);
        }
      };
      row.append(accept);
    }
    box.append(row);
  });
  return box;
}

function addDialog(slug, limits, done) {
  dialog("Add a supplier", (body, close) => {
    body.append(
      el("p", "note", "List the exact names of the supplier's public services. They are checked weekly with passive checks only (certificate, normal page requests, DNS). A name that is one of this project's own targets belongs in Targets, not here."),
    );
    const name = text("", { placeholder: "Acme Hosting" });
    const tier = selectOf([["critical", "Critical"], ["high", "High"], ["normal", "Normal"]], "critical");
    const domains = el("textarea", "", null, { rows: "3", placeholder: "portal.supplier.example\napi.supplier.example" });
    const contact = text("", { placeholder: "Who to write to" });
    const notes = el("textarea", "", null, { rows: "2" });
    const error = el("p", "msg err");
    error.hidden = true;
    body.append(field("Name", name), field("Tier", tier), field("Domains", domains, `One per line, at most ${limits.max_domains}. No wildcards, addresses or private names.`), field("Contact", contact), field("Notes", notes), error);
    const actions = el("div", "actions");
    const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
    cancel.onclick = close;
    const save = el("button", "btn", "Add supplier", { type: "button" });
    save.onclick = async () => {
      save.disabled = true;
      error.hidden = true;
      try {
        await api("POST", `/api/v1/projects/${encodeURIComponent(slug)}/suppliers`, {
          name: name.value, tier: tier.value, domains: domains.value.split(/[\s,]+/).filter(Boolean), contact: contact.value, notes: notes.value,
        });
        close();
        toast("Supplier added. It is checked at the next daily sweep.");
        done();
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
        save.disabled = false;
      }
    };
    actions.append(cancel, save);
    body.append(actions);
    setTimeout(() => name.focus(), 0);
  });
}

export async function suppliersPage(mount, { slug, all }) {
  if (all) {
    mount.append(el("p", "note ro-note", "Suppliers belong to one project. Pick a project to see and manage its suppliers."));
    return;
  }
  const base = `/api/v1/projects/${encodeURIComponent(slug)}/suppliers`;
  mount.append(
    el("p", "note page-intro", "Vendors this project depends on and cannot fix for itself. Each name gets a host card from passive checks only: what its public services announce about themselves (headers, certificate, technology and versions). Search by technology to ask the vendors that run it whether they are patched. Nothing here is scanned, enumerated or assigned to your team."),
  );
  const tools = el("div", "tools");
  const search = el("input", "", null, { type: "search", placeholder: "Search technology: php, node, nginx 1.1", "aria-label": "Search suppliers by technology" });
  const clear = el("button", "btn ghost sm", "Clear", { type: "button" });
  const addButton = el("button", "btn sm", "Add supplier", { type: "button" });
  addButton.hidden = true;
  tools.append(search, clear, addButton);
  const facets = el("div", "chips supplier-facets");
  const summary = el("p", "note", "", { role: "status" });
  const list = el("div", "supplier-list");
  mount.append(tools, facets, summary, list);

  let state = { suppliers: [], canEdit: false, limits: { max_domains: 10 } };
  let version = 0;

  const terms = () => search.value.split(",").map((t) => t.trim()).filter(Boolean);

  async function paintFacets() {
    try {
      const { results } = await api("GET", `${base}/technologies`);
      facets.textContent = "";
      results.slice(0, 16).forEach((t) => {
        const chip = el("button", "chip facet", `${t.name} · ${t.suppliers}`, { type: "button", title: `${t.suppliers} supplier${t.suppliers === 1 ? "" : "s"}, ${t.hosts} host${t.hosts === 1 ? "" : "s"}${t.versions.length ? `; versions seen: ${t.versions.join(", ")}` : ""}` });
        chip.onclick = () => {
          search.value = t.name;
          run();
        };
        facets.append(chip);
      });
    } catch (_) {
      /* facets are a convenience */
    }
  }

  async function run() {
    const mine = ++version;
    const q = search.value.trim();
    try {
      const [sup, hosts] = await Promise.all([api("GET", `${base}?page_size=200`), api("GET", `${base}/hosts?page_size=200${q ? `&tech=${encodeURIComponent(q)}` : ""}`)]);
      if (mine !== version) return;
      state = { suppliers: sup.results.map((s) => ({ ...s, slug })), canEdit: sup.can_edit, limits: sup.limits };
      addButton.hidden = !state.canEdit;
      draw(hosts, q);
    } catch (err) {
      list.textContent = "";
      list.append(el("p", "msg err", `Could not load suppliers: ${err.message}`));
    }
  }

  function draw(hosts, q) {
    list.textContent = "";
    const t = terms();
    const bySupplier = new Map();
    hosts.results.forEach((c) => bySupplier.set(c.supplier.id, [...(bySupplier.get(c.supplier.id) || []), c]));
    summary.textContent = q
      ? `${hosts.count} host${hosts.count === 1 ? "" : "s"} across ${bySupplier.size} supplier${bySupplier.size === 1 ? "" : "s"} match "${q}".`
      : `${state.suppliers.length} supplier${state.suppliers.length === 1 ? "" : "s"}, ${hosts.count} host card${hosts.count === 1 ? "" : "s"}.`;
    if (!state.suppliers.length) {
      list.append(el("p", "note", state.canEdit ? 'No suppliers yet. Use "Add supplier" to list the vendors you depend on.' : "No suppliers listed for this project."));
      return;
    }
    state.suppliers.filter((s) => !q || bySupplier.has(s.id)).forEach((s) => list.append(supplierBlock(s, bySupplier.get(s.id) || [], t)));
    if (q && !bySupplier.size) list.append(el("p", "note", "No supplier host shows that technology (yet: hosts are checked weekly)."));
  }

  function supplierBlock(s, cards, t) {
    const block = el("section", "supplier");
    const head = el("div", "supplier-head");
    const title = el("h3", "", s.name);
    head.append(title, badge(s.tier, TIER_BADGE[s.tier] || "info"));
    head.append(el("span", "note", s.last_checked ? `last checked ${shortDate(s.last_checked)}` : "not checked yet"));
    const f = s.findings;
    if (f.open) head.append(badge(`${f.open} open finding${f.open === 1 ? "" : "s"}`, f.critical ? "critical" : f.high ? "high" : f.medium ? "medium" : "low"));
    const actions = el("div", "supplier-actions");
    const copy = el("button", "btn ghost sm", t.length ? "Copy message about this tech" : "Copy message to supplier", { type: "button", title: "A plain-text note with the technology they announce and what to ask. Nothing is sent." });
    copy.onclick = async () => {
      try {
        const r = await api("GET", `${base}/${s.id}/summary${t.length ? `?tech=${encodeURIComponent(search.value.trim())}` : ""}`);
        await copyText(r.text);
        toast("Message copied");
      } catch (err) {
        toast(err.message, true);
      }
    };
    actions.append(copy);
    const findingsHost = el("div");
    const toggle = el("button", "btn ghost sm", "Findings", { type: "button" });
    toggle.onclick = async () => {
      if (findingsHost.childNodes.length) {
        findingsHost.textContent = "";
        return;
      }
      findingsHost.append(await findingsPanel(s, state.canEdit, run).catch((err) => el("p", "msg err", err.message)));
    };
    actions.append(toggle);
    if (state.canEdit) {
      const remove = el("button", "btn danger-ghost sm", "Remove", { type: "button" });
      remove.onclick = async () => {
        if (!(await ask(`Remove ${s.name} with its host cards and findings?`, { title: "Remove supplier", ok: "Remove" }))) return;
        try {
          await api("DELETE", `${base}/${s.id}`);
          run();
        } catch (err) {
          toast(err.message, true);
        }
      };
      actions.append(remove);
    }
    head.append(actions);
    block.append(head);
    if (s.contact || s.notes) block.append(el("p", "note", [s.contact && `Contact: ${s.contact}`, s.notes].filter(Boolean).join(" · ")));
    if (!cards.length) block.append(el("p", "note", `Names to check: ${s.domains.join(", ")}. No host card yet: the daily sweep makes one.`));
    const grid = el("div", "supplier-grid");
    cards.forEach((c) => grid.append(hostCard(c, t)));
    block.append(grid, findingsHost);
    return block;
  }

  let timer;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(run, 250);
  });
  clear.onclick = () => {
    search.value = "";
    run();
  };
  addButton.onclick = () => addDialog(slug, state.limits, () => { run(); paintFacets(); });
  await run();
  paintFacets();
  search.focus();
}
