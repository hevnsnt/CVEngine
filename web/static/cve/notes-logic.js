// Operator notes on a finding or a host (docs/AGENT-API.md "Notes on findings and hosts"): the words and badge of each note. Rendering sets every
// field with textContent (the el() helper), never as markup: a note is text a person or an agent wrote.

export const OBSERVATIONS = {
  confirmed: ["Confirmed", "fire"],
  not_reproduced: ["Not reproduced", "queued"],
  false_positive: ["False positive", "ice"],
  fixed_verified: ["Fixed, verified", "ice"],
  needs_more_info: ["Needs more info", "smoke"],
  info: ["Info", "queued"],
};

const SOURCES = { ui: "web", mcp: "MCP", rest: "REST API" };

export function noteView(n, date = (iso) => (iso ? new Date(iso).toLocaleDateString() : "")) {
  const [label, tone] = OBSERVATIONS[n.observation] || ["Comment", ""];
  const who = n.author ? n.author.name || n.author.username || "someone" : "someone";
  const via = `${SOURCES[n.source] || n.source || "web"}${n.via ? ` (${n.via})` : ""}`;
  return { label, tone, text: n.text || "", evidence: n.evidence || "", meta: `${who} · ${via} · ${date(n.created)}` };
}

export const notesSummary = (list) =>
  `${list.length} note${list.length === 1 ? "" : "s"}, newest first. The AI reviewer reads them as claims to weigh; a note never changes a status by itself.`;

// The notes as DOM: a badge with the observation, the text, the evidence (as preformatted text) and who wrote it, through what and when.
export function notesList(list, el, badge, date) {
  const box = el("div", "notes-list");
  list.forEach((n) => {
    const v = noteView(n, date);
    const line = el("div", "find note-line");
    line.append(badge(v.label, v.tone), el("span", "", ` ${v.text}`));
    box.append(line);
    if (v.evidence) box.append(el("pre", "banner", v.evidence));
    box.append(el("div", "note", v.meta));
  });
  return box;
}
