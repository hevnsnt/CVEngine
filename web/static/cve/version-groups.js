// The host page's "CVE matches by product and version" card: the host's open CVE matches as one collapsed row per product version reading
// (GET findings?type=cve&group=product&host=...), each opening to its CVEs, every one a link to its own finding. Built with textContent only
// (the el() helper). The words live in version-groups-logic.js. Members are drawn when a row is first opened, so a host with hundreds of
// matches draws a few rows.
import { api, badge, el } from "/staticfiles/cve/ui.js";
import { countLine, forHost, groupTitle, memberHref, sortedMembers, triageText } from "/staticfiles/cve/version-groups-logic.js";

const PAGE = 200; // the list's cap: groups and single matches of one host fit in it

function memberList(row, project) {
  const g = row.group;
  const list = el("ul", "vg-members", null, { "aria-label": `The ${g.findings} findings of ${g.product} ${g.version}` });
  sortedMembers(g).forEach((m) => {
    const li = el("li", "vg-member");
    li.append(
      el("a", "", m.cve, { href: memberHref(project, m.id), "data-finding-key": `match-${m.id}`, title: `Open ${m.cve} on ${m.host}` }),
      el("span", "note", ` on ${m.host}${m.fixed ? ` · fixed in ${m.fixed}` : ""}`),
      ...[m.heat ? badge(m.heat, m.heat) : null, m.severity ? badge(m.severity, m.severity) : null, badge(String(m.status).replace(/_/g, " ")),
        m.classification ? badge(m.classification.replace(/_/g, " ")) : null].filter(Boolean),
    );
    list.append(li);
  });
  if (g.members_truncated) list.append(el("li", "note", `and ${g.findings - g.members.length} more: the Findings list shows them all`));
  return list;
}

function groupRow(row, project) {
  const g = row.group;
  const box = el("details", "vg-group", null, { "data-keep-key": `vg:${g.id}` });
  const summary = el("summary", "vg-summary");
  summary.append(...[g.heat ? badge(g.heat, g.heat) : null, g.severity ? badge(g.severity, g.severity) : null].filter(Boolean), el("span", "vg-title", groupTitle(g)));
  box.append(summary);
  let drawn = false;
  const draw = () => {
    if (drawn || !box.open) return;
    drawn = true;
    const triage = triageText(g);
    box.append(el("p", "note vg-note", g.note || "These rest on the version read, not on a check of each flaw."));
    if (triage) box.append(el("p", "note vg-triage", `Triage: ${triage}`));
    box.append(memberList(row, project));
  };
  box.addEventListener("toggle", draw);
  return box;
}

function singleRow(row, project) {
  const li = el("li", "vg-single");
  li.append(
    el("a", "", row.title, { href: memberHref(project, row.id), "data-finding-key": `match-${row.id}`, title: `Open ${row.title} on ${row.host}` }),
    el("span", "note", ` on ${row.host}${row.note ? ` · ${row.note}` : ""}`),
    ...[row.heat ? badge(row.heat, row.heat) : null, row.severity ? badge(row.severity, row.severity) : null].filter(Boolean),
  );
  return li;
}

// ``base`` the project's API path, ``project`` its slug, ``host`` the host's name, ``names`` every name of the host (itself and its aliases),
// ``isCurrent()`` false once another host is shown, ``onCount(n)`` told how many rows were drawn.
export function versionGroupsCard({ base, project, host, names, isCurrent = () => true, onCount = () => {} }) {
  const box = el("div", "why version-groups");
  box.append(el("h3", "sec", "CVE matches by product and version"));
  const body = el("div", "vg-body");
  body.append(el("p", "note", "Loading the CVE matches…"));
  box.append(body);
  const url = `${base}/findings?type=cve&group=product&host=${encodeURIComponent(host)}&page_size=${PAGE}`;
  api("GET", url)
    .then((data) => {
      if (!isCurrent()) return;
      body.textContent = "";
      const { groups, singles } = forHost(data.results, names);
      if (!groups.length && !singles.length) {
        body.append(el("p", "note", "No open CVE matches on this host."));
        onCount(0);
        return;
      }
      body.append(el("p", "note vg-count", countLine(groups, singles)));
      groups.forEach((r) => body.append(groupRow(r, project)));
      if (singles.length) {
        const list = el("ul", "vg-singles", null, { "aria-label": "CVE matches on their own" });
        singles.forEach((r) => list.append(singleRow(r, project)));
        body.append(list);
      }
      onCount(groups.length + singles.length);
    })
    .catch((e) => {
      if (!isCurrent()) return;
      body.textContent = "";
      body.append(el("p", "note", `The CVE matches could not be loaded: ${e.message}`));
    });
  return box;
}
