// Superusers only: a slim bar when the twice-daily check found a newer CVEngine version. Approval happens in Settings.
const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

async function run() {
  let s;
  try {
    const r = await fetch("/cve/api/settings/updates", { credentials: "same-origin" });
    if (!r.ok) return;
    s = await r.json();
  } catch (_) {
    return;
  }
  if (s.status !== "available" && s.status !== "approved") return;
  const bar = el("div", "updatebar");
  bar.setAttribute("role", "status");
  const msg =
    s.status === "approved"
      ? `Update to ${s.latest} approved by ${s.approved_by}. The host will apply it shortly.`
      : `A new version of CVEngine is available${s.behind_by ? ` (${s.behind_by} commit${s.behind_by === 1 ? "" : "s"})` : ""}: ${s.latest_message}`;
  bar.append(el("span", "", msg));
  const review = el("a", "btn sm", s.status === "approved" ? "Details" : "Review and update");
  review.href = "/cve/settings/#updates";
  bar.append(review);
  if (s.status === "available" && csrf) {
    const dismiss = el("button", "btn ghost sm", "Dismiss");
    dismiss.type = "button";
    dismiss.onclick = async () => {
      await fetch("/cve/api/settings/updates/dismiss", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrf.value },
      });
      bar.remove();
    };
    bar.append(dismiss);
  }
  const layout = document.querySelector(".layout") || document.getElementById("main");
  layout.parentNode.insertBefore(bar, layout);
}
run();
