// App Admins only: one notice per open admin alert, in the status strip (cveFeed.reviewer: the operations checks raise and resolve them, and the AI reviewer adds its
// diagnosis; docs/AI-REVIEWER.md). Every word is set with textContent: an alert can quote a Sentinel's error or what a scanned host said,
// and none of it is ever HTML.
import { setNotices } from "/staticfiles/cve/statusstrip.js";
import { localTimes } from "/staticfiles/cve/watchdog-text.js";
import { afterPoll } from "/staticfiles/cve/statusstrip-logic.js";

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
const dismissedAt = new Map(); // alert id -> when its dismissal was stored (Infinity while the request is on its way): a poll that began earlier does not bring it back
let reminder = null; // the line about questions an update left open (cveFeed/setup_questions.py): it stays until they are answered, so it has no Dismiss

// force: drawn because a person pressed a button here (Dismiss, Show all), so the strip redraws at once (statusstrip.js setNotices)
function render(alerts, force = false) {
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
    if (a.decision_id != null) {  // auto-tune answered this alert: the link opens its line in Settings, configMaxxing, Auto-tuning
      const link = el("a", "ab-decision", "See what auto-tune did about this");
      link.setAttribute("href", `/cve/settings/#configmaxxing/autotune/${encodeURIComponent(a.decision_id)}`);
      text.append(link);
    }
    const dismiss = el("button", "btn sm ab-dismiss", "Dismiss");
    dismiss.type = "button";
    dismiss.addEventListener("click", async () => {
      dismiss.disabled = true;
      dismissedAt.set(a.id, Infinity);
      render(current.filter((x) => x.id !== a.id), true); // gone from the list and from the count at once
      let stored = false;
      try {
        const r = await fetch(`/cve/api/settings/alerts/${encodeURIComponent(a.id)}/dismiss`, {
          method: "POST", credentials: "same-origin", headers: csrf ? { "X-CSRFToken": csrf.value } : {},
        });
        stored = !!(r && r.ok);
      } catch (_) {
        stored = false;
      }
      if (stored) dismissedAt.set(a.id, Date.now());
      else dismissedAt.delete(a.id); // not stored: the next poll shows it again, as the server still has it open
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
      render(current, true);
    });
    row.append(toggle);
    items.push({ kind: "more", text: label, node: row, rank: 3 });
  }
  if (reminder && !location.pathname.startsWith("/cve/update-questions")) {
    const row = el("div", "ab-row ab-info");
    const text = el("div", "ab-text");
    text.append(el("p", "ab-detail", reminder.text));
    const open = el("a", "btn sm", "Answer them");
    open.href = "/cve/update-questions/";
    row.append(text, open);
    items.unshift({ kind: "questions", text: reminder.text, node: row, rank: 2 });
  }
  // the count is every open alert (also those folded behind the button) and the reminder; the "more" row is a button, not a notice
  setNotices("alerts", items, { count: alerts.length + (items.some((i) => i.kind === "questions") ? 1 : 0), force });
}

async function poll() {
  const started = Date.now();
  try {
    const r = await fetch("/cve/api/settings/alerts", { credentials: "same-origin", cache: "no-store" });
    if (r.ok) {
      const body = await r.json();
      reminder = body.questions && body.questions.text ? body.questions : null;
      render(afterPoll(body.alerts || [], dismissedAt, started));
      for (const [id, at] of dismissedAt) if (at < started) dismissedAt.delete(id); // this answer was made after the dismissal: the server's word holds from now on
    }
  } catch (_) {
    // the server is restarting or unreachable: keep what is shown
  }
}

poll();
setInterval(() => { if (!document.hidden) poll(); }, POLL_MS);
