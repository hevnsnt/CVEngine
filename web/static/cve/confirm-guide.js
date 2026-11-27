// How to confirm ONE finding by hand: the "Confirm it yourself" guide the finding page draws for every kind (a CVE match from
// cveFeed.confirm_guide, a TLS audit result from cveFeed.tls_catalogue, a scanner, hygiene or route finding from cveFeed.finding_confirm).
// The real script URL, page, host and port, what to look for, the read-only steps with those values filled in, how to read the answer and
// what makes it exploitable. Every command was built by the server from validated values; a "quote" is text from the scanned host, a feed or
// the AI review, shown as data. Links open only http(s) URLs. DOM built with textContent only (the el() helper), never as markup.
import { badge, el } from "/staticfiles/cve/ui.js";

export const OS_LABEL = { linux: "Linux", windows: "Windows", any: "Linux or Windows", debian: "Debian / Ubuntu", rhel: "RHEL / Fedora", alpine: "Alpine",
  app: "In the application's code" };
export const RUN_IN = { shell: "Shell", browser_console: "Browser console", browser: "Browser", host: "On the host", manual: "By hand", advice: "AI advice" };
export const safeHref = (url) => (typeof url === "string" && /^https?:\/\//i.test(url) ? url : "");
export const linkOrText = (url, text) => {
  const href = safeHref(url);
  return href ? el("a", "mono", text || href, { href, target: "_blank", rel: "noopener noreferrer nofollow" }) : el("span", "mono", text || url || "");
};
// one step or command: its tag and label, Copy, the command, what it does; ``link`` (a node) sits after the label
export const commandRow = (label, command, explain, tag, link = null) => {
  const row = el("div", "local-check");
  const h = el("div", "tools");
  const left = el("div", "confirm-step-h");
  if (tag) left.append(badge(tag, "queued"));
  if (label) left.append(el("span", "", label));
  if (link) left.append(document.createTextNode(" "), link);
  h.append(left);
  if (command) {
    const copy = el("button", "btn ghost sm", "Copy", { type: "button" });
    copy.onclick = () => navigator.clipboard.writeText(command);
    h.append(copy);
  }
  row.append(h);
  if (command) row.append(el("pre", "banner", command));
  if (explain) row.append(el("p", `note${tag === RUN_IN.advice ? " untrusted" : ""}`, explain));
  return row;
};

export const confirmBox = (g) => {
  if (!g) return null;
  const box = el("div", "confirm-guide");
  const head = el("div", "tools");
  head.append(el("h4", "sub", g.headline || "Confirm this finding"), badge(g.class_label || g.class || "", "ice"));
  box.append(head);
  if (g.where?.length) {
    box.append(el("div", "note guide-h", "Where to look"));
    const ul = el("ul", "guide-list confirm-where");
    g.where.forEach((w) => {
      const li = el("li");
      li.append(el("span", "", `${w.label}: `));
      if (w.url) li.append(linkOrText(w.url));
      else if (w.quote) li.append(el("q", "mono untrusted", w.quote));
      else li.append(el("span", "mono", w.text || ""));
      ul.append(li);
    });
    box.append(ul);
  }
  if (g.look_for?.length) {
    box.append(el("div", "note guide-h", "What to look for"));
    g.look_for.forEach((x) => {
      const row = el("div", "confirm-look");
      row.append(el("div", "note", x.label));
      const text = el("pre", `banner${x.quote ? " untrusted" : ""}`, x.quote || x.text || "");
      if (x.quote) text.title = "Seen on the host or in a feed: data to compare, never run";
      row.append(text);
      box.append(row);
    });
  }
  if (g.steps?.length) {
    box.append(el("div", "note guide-h", "Check it (read-only)"));
    const ol = el("ol", "confirm-steps");
    g.steps.forEach((st) => {
      const li = el("li");
      const inline = st.url && !st.command ? linkOrText(st.url) : null;
      const row = commandRow(st.title, st.command, st.detail, RUN_IN[st.run_in] || "", inline);
      if (st.url && st.command) {
        const on = el("p", "note", "On: ");
        on.append(linkOrText(st.url));
        row.append(on);
      }
      li.append(row);
      ol.append(li);
    });
    box.append(ol);
  }
  const v = g.verdict || {};
  if (v.affected || v.not_affected || v.cant_tell || v.notes?.length) {
    box.append(el("div", "note guide-h", `How to read the result${v.fixed ? ` (fixed in ${v.fixed})` : ""}`));
    const ul = el("ul", "guide-list confirm-verdict");
    [["Affected", v.affected, "fire"], ["Not affected", v.not_affected, "success"], ["Can't tell", v.cant_tell, "smoke"]].forEach(([k, t, tone]) => {
      if (!t) return;
      const li = el("li");
      li.append(badge(k, tone), document.createTextNode(` ${t}`));
      ul.append(li);
    });
    (v.notes || []).forEach((t) => ul.append(el("li", "", t)));
    box.append(ul);
  }
  const p = g.precondition;
  if (p && (p.quote || p.needs)) {
    box.append(el("div", "note guide-h", "What makes it exploitable, beyond the version"));
    if (p.needs) box.append(el("p", "", p.needs));
    if (p.quote) {
      const q = el("blockquote", "untrusted confirm-quote", p.quote);
      q.title = "The advisory's own words (feed text)";
      box.append(el("div", "note", "The advisory says:"), q);
    }
  }
  const t = g.template;
  if (t) {
    box.append(el("div", "note guide-h", "The nuclei template that ran"));
    const line = el("p", "");
    line.append(el("span", "", `Template ${t.template_id}, result ${String(t.result || "").replaceAll("_", " ")}. `));
    if (t.template_url) line.append(linkOrText(t.template_url, "Open the template"));
    else if (t.template_search_url) line.append(linkOrText(t.template_search_url, "Find the template"));
    else if (t.generated) line.append(el("span", "note", "Generated by cvENGINE for this CVE (reviewed before use)."));
    box.append(line);
    // not a read-only step: a template may send more than one request (a CVE template its exploit-check requests), so it is labelled as an
    // active check, apart from the steps above
    if (t.command) box.append(commandRow("Active check: run the same template against this host", t.command, t.active || "Sends the template's own requests to this host.", "Active"));
    if (t.matched_at) { const m = el("p", "note", "Matched at: "); m.append(linkOrText(t.matched_at)); box.append(m); }
    if (t.matcher) box.append(el("p", "note", `Matcher: ${t.matcher}`));
    if (t.extracted?.length) box.append(el("pre", "banner untrusted", t.extracted.join("\n")));
    if (t.request) box.append(el("div", "note", "The request it sent (excerpt, credentials redacted)"), el("pre", "banner untrusted", t.request));
  }
  (g.local || []).forEach((section) => {
    if (!section.commands?.length) return;
    const rows = section.commands.map((c) => commandRow(c.label || "", c.command, c.explain, OS_LABEL[c.platform] || c.platform));
    if (rows.length <= 2) {
      box.append(el("div", "note guide-h", section.title), ...rows);
      return;
    }
    // a long list (every packaging of a library): folded, so the steps above stay the first thing read
    const more = el("details", "confirm-more");
    more.append(el("summary", "note guide-h", `${section.title} (${rows.length} commands)`), ...rows);
    box.append(more);
  });
  if (g.links?.length) {
    box.append(el("div", "note guide-h", g.links_title || "Distribution trackers"));
    const ul = el("ul", "guide-list");
    g.links.forEach((l) => { const li = el("li"); li.append(linkOrText(l.url, l.label)); ul.append(li); });
    box.append(ul);
  }
  if (g.fix) box.append(el("div", "note guide-h", "Fix it"), el("p", "", g.fix));
  if (g.notice) box.append(el("p", "note", g.notice));
  return box;
};
