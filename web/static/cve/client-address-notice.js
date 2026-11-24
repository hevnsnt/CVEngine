// The client address notice's tools (cveFeed/client_address.py): the lines a host nginx needs so cvENGINE believes the visitor's address it passes
// on, a Copy button, and Check again. The lines hold this install's upstream secret, so they are fetched only when a person presses a button, from
// an App Admin only endpoint that answers no-store, and never kept here. Used by the status strip (alertbar.js) and Settings, Updates (settings.js).
// Every word is set with textContent.
const el = (tag, cls, text, attrs) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  if (attrs) for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};
export const SNIPPET_URL = "/cve/api/settings/client_address/snippet";
export const RECHECK_URL = "/cve/api/settings/client_address/recheck";

async function copy(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = el("textarea", "", null, { "aria-hidden": "true", tabindex: "-1" });
  area.style.cssText = "position:fixed;top:-1000px;opacity:0";
  area.value = text;
  document.body.append(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("copy blocked");
  return undefined;
}

async function lines() {
  const r = await fetch(SNIPPET_URL, { credentials: "same-origin", cache: "no-store" });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `the server answered ${r.status}`);
  return String(body.snippet || "");
}

// onChecked(body): called after Check again with the server's answer ({kind, result, notice}); notice null means the check passed.
export function snippetBlock({ onChecked } = {}) {
  const box = el("div", "ca-snippet");
  const pre = el("pre", "ca-lines");
  pre.hidden = true;
  const status = el("p", "note ca-status", "", { role: "status" });
  const say = (text) => { status.textContent = text; };
  const btn = (label, handler) => {
    const b = el("button", "btn sm ghost", label, { type: "button" });
    b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        await handler();
      } catch (e) {
        say(`That did not work: ${e && e.message ? e.message : "no answer"}.`);
      } finally {
        b.disabled = false;
      }
    });
    return b;
  };
  const show = btn("Show the lines", async () => {
    pre.textContent = await lines();
    pre.hidden = false;
  });
  const copyIt = btn("Copy", async () => {
    await copy(pre.hidden ? await lines() : pre.textContent);
    say("Copied. Paste them into the host nginx, then reload it. They hold this install's secret: keep that file readable by root only.");
  });
  const again = btn("Check again", async () => {
    const csrf = document.querySelector("[name=csrfmiddlewaretoken]");
    const r = await fetch(RECHECK_URL, { method: "POST", credentials: "same-origin", headers: csrf ? { "X-CSRFToken": csrf.value } : {} });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `the server answered ${r.status}`);
    say(body.notice ? "Not yet: the visitor's address still does not arrive. It is checked again within the hour and at every update." : "The check passed. This notice is gone.");
    if (onChecked) onChecked(body);
  });
  const row = el("div", "ca-buttons");
  row.append(show, copyIt, again);
  box.append(row, pre, status);
  return box;
}
