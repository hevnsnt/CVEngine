// App Admins only: one notice per open admin alert, in the status strip (cveFeed.reviewer: the operations checks raise and resolve them, and the AI reviewer adds its
// diagnosis; docs/AI-REVIEWER.md). Every word is set with textContent: an alert can quote a Sentinel's error or what a scanned host said,
// and none of it is ever HTML.
import { setNotices } from "/staticfiles/cve/statusstrip.js";
import { localTimes } from "/staticfiles/cve/watchdog-text.js";

const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const SHOWN = 3;
const POLL_MS = 120000;

// Each open alert is one notice in the status strip (statusstrip.js), drawn there as its own row with the Dismiss button; the strip's first line
// is the most severe notice and its count includes these. No other page lists the alerts, so when there are more than SHOWN the last row is a
// button that opens the whole list right here (and "Show fewer" folds it back); nothing sends the person to another page.
let current = [];
let showAll = false;

function render(alerts) {
  current = alerts;
  const shown = showAll ? alerts : alerts.slice(0, SHOWN);
  const items = shown.map((a) => {
    const row = el("div", `ab-row ab-${["info", "warning", "critical"].includes(a.severity) ? a.severity : "warning"}`);
    const text = el("div", "ab-text");
    text.append(el("strong", "", localTimes(a.title)));
    if (a.detail) text.append(el("p", "ab-detail", localTimes(a.detail)));
    if (a.ai_detail) {
      const ai = el("p", "ab-ai");
      ai.append(el("span", "ab-label", `AI reviewer${a.ai_model ? ` (${a.ai_model})` : ""}: `), document.createTextNode(a.ai_detail));
      text.append(ai);
    }
    const dismiss = el("button", "btn sm ab-dismiss", "Dismiss");
    dismiss.type = "button";
    dismiss.addEventListener("click", async () => {
      dismiss.disabled = true;
      try {
        await fetch(`/cve/api/settings/alerts/${encodeURIComponent(a.id)}/dismiss`, {
          method: "POST", credentials: "same-origin", headers: csrf ? { "X-CSRFToken": csrf.value } : {},
        });
      } finally {
        render(current.filter((x) => x.id !== a.id));
      }
    });
    row.append(text, dismiss);
    return { kind: "alert", text: localTimes(a.title), node: row, rank: a.severity === "critical" ? 0 : 2 };
  });
  if (alerts.length > SHOWN) {
    const n = alerts.length - SHOWN;
    const label = showAll ? "Show fewer alerts" : `${n} more ${n === 1 ? "alert" : "alerts"}. Show all.`;
    const row = el("p", "ab-more");
    const toggle = el("button", "btn sm ghost", label);
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", String(showAll));
    toggle.addEventListener("click", () => {
      showAll = !showAll;
      render(current);
    });
    row.append(toggle);
    items.push({ kind: "more", text: label, node: row, rank: 3 });
  }
  setNotices("alerts", items);
}

async function poll() {
  try {
    const r = await fetch("/cve/api/settings/alerts", { credentials: "same-origin", cache: "no-store" });
    if (r.ok) render(((await r.json()).alerts) || []);
  } catch (_) {
    // the server is restarting or unreachable: keep what is shown
  }
}

poll();
setInterval(() => { if (!document.hidden) poll(); }, POLL_MS);
