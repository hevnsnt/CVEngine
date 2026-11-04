// App Admins only: one bar per open admin alert (cveFeed.reviewer: the operations checks raise and resolve them, and the AI reviewer adds its
// diagnosis; docs/AI-REVIEWER.md). Every word is set with textContent: an alert can quote a Sentinel's error or what a scanned host said,
// and none of it is ever HTML.
const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const SHOWN = 3;
const POLL_MS = 120000;
let box = null;

function render(alerts) {
  if (box) box.remove();
  box = null;
  if (!alerts.length) return;
  box = el("div", "alertbar");
  box.setAttribute("role", "status");
  for (const a of alerts.slice(0, SHOWN)) {
    const row = el("div", `ab-row ab-${["info", "warning", "critical"].includes(a.severity) ? a.severity : "warning"}`);
    const text = el("div", "ab-text");
    text.append(el("strong", "", a.title));
    if (a.detail) text.append(el("p", "ab-detail", a.detail));
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
        row.remove();
      }
    });
    row.append(text, dismiss);
    box.append(row);
  }
  if (alerts.length > SHOWN) box.append(el("p", "ab-more", `${alerts.length - SHOWN} more alert(s): see Settings, AI model.`));
  const layout = document.querySelector(".layout") || document.getElementById("main");
  if (layout && layout.parentNode) layout.parentNode.insertBefore(box, layout);
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
