// A host's score as a list a person can read and follow: every contributor with its points, one plain sentence (what, where, why it scores)
// and a link to the evidence behind it. Built with textContent only. Used by the dashboard's score dialog and the host page.
import { el } from "/staticfiles/cve/ui.js";
import { evidenceWord, scoreLines, totalNote } from "/staticfiles/cve/score-detail-logic.js";

function line(l, onOpen) {
  const li = el("li", `score-line${l.points ? "" : " zero"}`);
  li.append(el("b", "score-pts mono", `+${l.points}`));
  const body = el("div", "score-body");
  const title = l.href
    ? el("a", "score-label", l.label, { href: l.href, title: evidenceWord(l.ref) })
    : el("span", "score-label", l.label);
  if (l.href && onOpen) {
    title.addEventListener("click", (e) => {
      if (e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey) return;
      if (onOpen(l)) e.preventDefault();
    });
  }
  body.append(title);
  if (l.text) body.append(el("p", "score-text", l.text));
  li.append(body);
  return li;
}

// ``ctx`` {slug, host}; ``score`` the number the page shows; ``onOpen(line)`` may open the evidence in place and return true (else the link is followed).
export function scoreList(parts, ctx, { score = null, onOpen = null, limit = Infinity, label = "What the score is made of" } = {}) {
  const view = scoreLines(parts, ctx, { limit });
  const box = el("div", "score-detail");
  if (!view.lines.length) {
    box.append(el("p", "note", "No score detail is stored for this host yet. It appears after the next rescore."));
    return box;
  }
  const list = el("ol", "score-lines", null, { "aria-label": label });
  view.lines.forEach((l) => list.append(line(l, onOpen)));
  box.append(list);
  if (view.hidden) {
    const more = el("details", "score-more");
    more.append(el("summary", "", `${view.hidden.count} more line${view.hidden.count === 1 ? "" : "s"}, +${view.hidden.points}`));
    const rest = el("ol", "score-lines");
    view.hidden.lines.forEach((l) => rest.append(line(l, onOpen)));
    more.append(rest);
    box.append(more);
  }
  box.append(el("p", "score-total", null));
  const total = box.lastChild;
  total.append(el("b", "mono", `Total ${view.total}`), document.createTextNode(` · ${totalNote(view, score)}`));
  return box;
}
