// Situations: what needs a person, one host at a time, ranked. The server does the work (cveFeed.situations: the rank rule and the narrative are
// documented there); this page draws its answer. Every string that came from a scan is drawn with textContent, never as markup, and a finding's link
// is used only when it points at one of the existing panes (situations-logic.js safeLink).
import { api, badge, el, emptyState, selectOf, whatIs } from "/staticfiles/cve/ui.js";
import { chipsOf, countLine, heatOf, moreFindings, safeLink, stateView } from "/staticfiles/cve/situations-logic.js";

const TIER_BADGE = { proven: "fire", likely: "smoke", exposure: "high", minor: "info" };
const TIER_LABEL = { proven: "Proven", likely: "Likely", exposure: "Exposed", minor: "Minor" };
const SEV_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

// one finding of a situation: its tier, a link to the pane that already shows it, its severity, the check that proved it
function findingNode(f) {
  const li = el("li", "sit-finding");
  li.append(badge(TIER_LABEL[f.tier] || f.tier, TIER_BADGE[f.tier] || "info"));
  const href = safeLink(f.link);
  li.append(href ? el("a", "sit-link", f.title, { href }) : el("span", "", f.title));
  if (f.severity) li.append(badge(f.severity, SEV_BADGE[f.severity] || "info"));
  if (f.known_exploited) li.append(badge("known exploited", "high"));
  if (f.proof) li.append(el("span", "note", `reproduced by ${f.proof.check}`));
  return li;
}

// the opened row: the narrative, why it is where it is, and its findings
export function detailNode(r, { onMore } = {}) {
  const box = el("div", "sit-detail");
  box.append(el("p", "sit-narrative", r.narrative));
  box.append(el("p", "note", `Why it is here: ${r.rank_reason}.`));
  const list = el("ul", "sit-findings");
  (r.findings || []).forEach((f) => list.append(findingNode(f)));
  box.append(list);
  const foot = el("p", "note sit-foot");
  const more = moreFindings(r);
  if (more) {
    foot.append(`${more} `);
    if (onMore) {
      const b = el("button", "btn ghost sm", "Show all", { type: "button" });
      b.onclick = () => onMore(b);
      foot.append(b, " ");
    }
  }
  const host = safeLink(r.host_link);
  if (host) foot.append(el("a", "sit-link", "Open the host", { href: host }));
  box.append(foot);
  return box;
}

// one row: the rank and the host, why it ranks there, the counts; then the headline and the first action
export function rowNode(r, { all, selectableRow }) {
  const row = selectableRow(`${r.project}:${r.host}`, heatOf(r.counts), "key");
  row.setAttribute("aria-expanded", "false");
  const top = el("span", "hr-top");
  const name = el("span", "cve-id");
  name.append(el("span", "sit-rank", String(r.rank)), ` ${r.host}`);
  top.append(name);
  if (all && r.project_name) top.append(el("span", "proj-chip", r.project_name));
  const chips = el("span", "sit-chips");
  chipsOf(r.counts).forEach((c) => chips.append(badge(c.label, TIER_BADGE[c.key])));
  if (r.internal) chips.append(badge("internal", "internal"));
  top.append(chips);
  const meta = el("span", "host-meta");
  meta.append(el("span", "note sit-headline", r.headline), el("span", "note sit-action", `Next: ${r.first_action}`));
  row.append(top, meta);
  row.title = [`${r.rank}. ${r.host}`, r.headline, r.rank_reason, `Next: ${r.first_action}`].join("\n");
  return row;
}

export function situationsPage(mount, { slug, all, listHead, createList, selectableRow, addTargets = () => [] }) {
  const root = el("div", "table-page");
  mount.append(root);
  const search = el("input", "", null, { type: "search", placeholder: "Search hosts", "aria-label": "Search situations" });
  const tier = selectOf([["all", "Everything that needs you"], ["exposure", "Exposed or worse"], ["likely", "Likely or proven"], ["proven", "Proven only"]], "all", "Show");
  const count = el("span", "list-count note", "", { role: "status" });
  const tools = el("span", "meta-tools");
  tools.append(whatIs("One host at a time, with everything open on it that needs a person: what a check proved first, then what is likely real, what is exposed, then the small things. Closed, accepted and ruled-out findings are not here. The order is the same everywhere: proof first, then known exploited, then internet-facing, then how bad, then how old."));
  const metaRow = el("div", "list-meta");
  metaRow.append(count, tools);
  const lh = listHead({ page: "situations", lead: [search], panelNodes: [tier], meta: metaRow });
  const rows = el("div", "host-rows sit-rows");
  root.append(lh.head, rows);
  let timer = 0;
  const filtered = () => Boolean(search.value.trim()) || tier.value !== "all";
  const list = createList({
    mount: root,
    skeleton: "rows",
    onReset: () => (rows.textContent = ""),
    path: `/api/v1/projects/${encodeURIComponent(slug)}/situations`,
    params: () => ({ q: search.value.trim(), tier: tier.value === "all" ? "" : tier.value }),
    noun: "situation",
    plural: "situations",
    pageSize: 30,
    // the three empty states come from the server's `state`: clear (nothing needs you) is never drawn for a list that is still loading,
    // and never for hosts that were not scanned (unscanned)
    empty: (data) => {
      const v = stateView(data, { slug, filtered: filtered() });
      if (v.kind === "nomatch") return v.body;
      return { icon: v.icon, tone: v.tone, title: v.title, body: v.body, actions: v.kind === "unscanned" ? addTargets() : [{ label: "See all findings", href: `/cve/${encodeURIComponent(slug)}/vulns/` }] };
    },
    onLoaded: (data) => {
      count.textContent = countLine(data);
      lh.refresh();
    },
    render: (body, items, reset) => {
      if (reset) rows.textContent = "";
      items.forEach((r) => {
        const row = rowNode(r, { all, selectableRow });
        let open = null;
        const toggle = () => {
          if (open) {
            open.remove();
            open = null;
          } else {
            open = detailNode(r, {
              onMore: async (btn) => {
                btn.disabled = true;
                try {
                  const full = await api("GET", `/api/v1/projects/${encodeURIComponent(r.project)}/situations/${encodeURIComponent(r.host)}`);
                  const next = detailNode(full);
                  open.replaceWith(next);
                  open = next;
                } catch (err) {
                  btn.disabled = false;
                  btn.textContent = `Could not load: ${err.message}`;
                }
              },
            });
            row.after(open);
          }
          row.classList.toggle("sel", Boolean(open));
          row.setAttribute("aria-expanded", String(Boolean(open)));
        };
        row.addEventListener("click", (e) => {
          if (e.target.closest("a, button")) return;
          toggle();
        });
        rows.append(row);
      });
      if (!rows.isConnected) body.append(rows);
    },
  });
  const again = () => {
    clearTimeout(timer);
    timer = setTimeout(() => list.reload(), 250);
  };
  search.addEventListener("input", again);
  tier.addEventListener("change", () => list.reload());
  list.start();
  return list;
}
