// The API keys page: create a token, connect an agent with it, list and revoke tokens, the agents on them.
import { api, button, copyText, el, toast } from "/staticfiles/cve/ui.js";
import { TABS, createCard } from "/staticfiles/cve/connect-card-logic.js";
import { renderTokenList } from "/staticfiles/cve/api-keys-list.js";

const card = createCard(window.location.origin);
const $ = (id) => document.getElementById(id);

function block(text) {
  const pre = el("pre", "code", text);
  pre.append(button("Copy", async () => { await copyText(text); toast("Copied"); }, "copy"));
  return pre;
}

function renderConnect() {
  const v = card.view();
  const root = $("connect-body");
  root.textContent = "";
  const bar = el("div", "seg", null, { role: "tablist", "aria-label": "How to connect" });
  TABS.forEach(([key, label]) => {
    const b = el("button", "seg-btn", label, { type: "button", role: "tab", id: `tab-${key}`, "aria-selected": String(v.tab === key), "aria-controls": "connect-panel", tabindex: v.tab === key ? "0" : "-1" });
    b.onclick = () => { card.select(key); renderConnect(); $(`tab-${key}`).focus(); };
    b.onkeydown = (e) => {
      const i = TABS.findIndex(([k]) => k === key);
      const next = { ArrowRight: i + 1, ArrowLeft: i - 1 }[e.key];
      if (next === undefined) return;
      e.preventDefault();
      card.select(TABS[(next + TABS.length) % TABS.length][0]);
      renderConnect();
      $(`tab-${TABS[(next + TABS.length) % TABS.length][0]}`).focus();
    };
    bar.append(b);
  });
  const panel = el("div", "", null, { role: "tabpanel", id: "connect-panel", "aria-labelledby": `tab-${v.tab}` });
  const intro = {
    tell: "Paste this into any AI agent. It tells the agent how to add cvENGINE itself.",
    claude: "Run this once in a terminal.",
    mcp: "Add this to the MCP settings of Cursor or another client (the file is usually named mcp.json).",
    rest: "For scripts. The same token works on the REST API.",
  }[v.tab];
  panel.append(el("p", "note", intro), block(v.commands[v.tab]));
  root.append(bar, panel, el("p", v.filled ? "msg" : "note", v.hint),
    el("p", "note", "A registered agent then appears under Your agents below; it takes assigned work with get_next_task. The tool list is in the "), );
  const guide = el("a", "", "agent API guide", { href: "https://github.com/hevnsnt/CVEngine/blob/HEAD/docs/AGENT-API.md", target: "_blank", rel: "noopener" });
  root.lastChild.append(guide, document.createTextNode("."));
  $("connect-live").textContent = v.announce;
}

function renderReveal(token) {
  const slot = $("secret");
  slot.textContent = "";
  if (token === null) { slot.hidden = true; return; }
  slot.hidden = false;
  slot.className = "msg ok secret-box";
  const label = el("span", "", "This is the only time the token is shown. Copy it now.", { id: "secret-label" });
  const pre = block(token);
  pre.setAttribute("tabindex", "-1");
  pre.setAttribute("aria-labelledby", "secret-label");
  const done = button("I have copied it", async () => dismiss(), "btn ghost sm");
  slot.append(label, pre, done);
  pre.focus();
}

function dismiss() {
  card.dismiss();
  renderReveal(null);
  renderConnect();
}

function renderTokens(items) {
  const count = renderTokenList($("list"), items, async (t) => { await api("DELETE", `/api/v1/tokens/${t.id}`); await loadTokens(); });
  $("none").style.display = count ? "none" : "";
}

async function loadTokens() { renderTokens((await api("GET", "/api/v1/tokens")).results || []); }

function renderAgents(items) {
  const box = $("agents");
  box.textContent = "";
  const mine = items.filter((a) => a.kind !== "scanner"); // Sentinels are on the Scanners page
  $("no-agents").style.display = mine.length ? "none" : "";
  mine.forEach((a) => {
    const li = el("li"), scope = a.scope || {};
    li.append(el("span", "cve-id", a.name));
    const where = ["orgs", "projects", "hosts"].map((k) => ((scope[k] || []).length ? `${k}: ${scope[k].slice(0, 3).join(", ")}` : "")).filter(Boolean).join(" · ") || "no scope declared";
    li.append(el("div", "meta", `${a.kind} · ${a.status !== "active" ? a.status : a.live ? "live" : "offline"} · ${a.last_seen ? `seen ${a.last_seen.slice(0, 16).replace("T", " ")}` : "never seen"}`));
    li.append(el("div", "meta", `${where} · ${a.capabilities.join(", ") || "no capabilities"}`));
    box.append(li);
  });
}

$("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("secret-err");
  out.textContent = "";
  try {
    const d = await api("POST", "/api/v1/tokens", { name: $("name").value, read_only: $("ro").checked });
    $("name").value = "";
    card.reveal(d.token);
    renderReveal(d.token);
    renderConnect();
    await loadTokens();
  } catch (err) { out.className = "msg err"; out.textContent = err.message || "Could not create the token."; }
});
window.addEventListener("pagehide", dismiss); // a page restored from the back button never shows the token again

renderConnect();
loadTokens();
api("GET", "/api/v1/agents?page_size=50").then((x) => renderAgents(x.results || [])).catch(() => {});
