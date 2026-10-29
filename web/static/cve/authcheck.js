// Authenticated checks: the headers and cookie an owner supplies for a target they may test, so Nuclei and the web route check see the
// signed-in application. A dialog on the Targets page, for App Admins and the organization's admins (everyone else gets a 403 from the
// list call and sees no button). Values are write-only: the page only ever receives header and cookie NAMES, and the form fields that hold
// a value are cleared as soon as it is saved. DOM is built with textContent only.
import { api, badge, button, dialog, el, field, selectOf, shortDate, text, toast } from "/staticfiles/cve/ui.js";

const EXPIRY_CHOICES = [["30", "30 days"], ["90", "90 days"], ["120", "120 days"], ["never", "Never (I chose this on purpose)"]];
const UNTRUSTED_WARNING =
  "Warning: with this on, the sign-in is also sent to a server whose certificate does not verify (self-signed, expired or for another name), so the sign-in can be read by anyone in the network path. Leave it off unless you know the server and the network.";
const ORIGIN_HELP = "Where the values may be sent, as scheme:port, comma separated. Default https:443. Plain http only if you name it.";

// The stored sign-ins of the project, or null when the viewer may not see them (not an App Admin or the organization's admin).
export async function loadSignIns(base) {
  try {
    const data = await api("GET", `${base}/auth-credentials`);
    return { base, rows: data.results, warning: data.warning };
  } catch (_) {
    return null;
  }
}

// "Expires 2030-01-31 (29 days left)", "Expired 2030-01-31" or "Never expires (chosen on purpose)".
const expiryText = (r) => {
  if (r.never_expires) return "Never expires (chosen on purpose)";
  if (r.expired) return `Expired ${shortDate(r.expires_at)}`;
  return `Expires ${shortDate(r.expires_at)} (${r.days_left} ${r.days_left === 1 ? "day" : "days"} left)`;
};

const forTarget = (state, target) => state.rows.filter((r) => r.target_id === target.id);

// The label of a target's Sign-in button: it says so when a stored sign-in has expired (the count is in the tooltip).
export function signInLabel(state, target) {
  return forTarget(state, target).some((r) => r.expired) ? "Sign-in expired" : "Sign-in";
}

export function signInButton(state, target) {
  const b = el("button", "btn ghost sm", signInLabel(state, target), { type: "button" });
  const describe = () => {
    const n = forTarget(state, target).length;
    b.title = `${n ? `${n} stored. ` : ""}Headers or a cookie the scanners send for this target, so they see the signed-in application`;
  };
  describe();
  b.onclick = () =>
    openSignIn(state, target, () => {
      b.textContent = signInLabel(state, target);
      describe();
    });
  return b;
}

function openSignIn(state, target, changed) {
  dialog(`Sign-in for ${target.name}`, (body, close) => {
    const render = () => {
      body.textContent = "";
      body.append(el("h2", "", `Sign-in for ${target.name}`));
      body.append(
        el("p", "note", state.warning, { style: "font-size:13px" }),
        el(
          "p",
          "note",
          "The values are encrypted when stored and can never be read back, here or through the API; only the header names are shown. " +
            "They go only to the host and origins named below, on requests the scanners send themselves, and never follow a redirect.",
          { style: "font-size:13px" },
        ),
      );
      const rows = forTarget(state, target);
      rows.forEach((r) => body.append(card(r)));
      body.append(el("h3", "", rows.length ? "Add or replace a sign-in" : "Add a sign-in"), form());
      const actions = el("div", "actions");
      const done = el("button", "btn ghost", "Close", { type: "button" });
      done.onclick = close;
      actions.append(done);
      body.append(actions);
      const dlg = body.closest("dialog");
      if (dlg) dlg.scrollTop = 0;
    };
    const refresh = async () => {
      const fresh = await loadSignIns(state.base);
      if (fresh) state.rows = fresh.rows;
      changed();
      render();
    };
    const card = (r) => {
      const box = el("div", "scope-cell", null, { style: "border:1px solid var(--line, #ccc);border-radius:8px;padding:10px;margin:10px 0" });
      const head = el("div", "");
      head.append(el("strong", "", r.label), document.createTextNode(" "), badge(r.expired ? "expired" : "active", r.expired ? "err" : ""));
      box.append(
        head,
        el("p", "note", `${r.host ? `Host ${r.host}` : `All hosts of ${r.target}`}, sent to ${r.origins.join(", ")}`, { style: "margin:4px 0" }),
        el("p", "note", `Headers: ${r.header_names.join(", ") || "none"}. Cookie: ${r.cookie_names.length ? r.cookie_names.join(", ") : "none"}.`, { style: "margin:4px 0" }),
        el("p", "note", `${expiryText(r)}. Last sent: ${r.last_used_at ? shortDate(r.last_used_at) : "never"}.`, { style: "margin:4px 0" }),
      );
      if (r.allow_untrusted_certificate) {
        box.append(el("p", "note", "Trusts an unverified certificate: the sign-in is sent even when the server's certificate does not verify, so it can be read by anyone in the network path.", { style: "margin:4px 0;color:var(--warn, #b45309)" }));
      }
      if (r.expired) box.append(el("p", "note", "Expired: the scanners no longer send it. Replace it with a fresh session.", { style: "margin:4px 0" }));
      const actions = el("div", "actions", null, { style: "justify-content:flex-start" });
      const replace = el("button", "btn ghost sm", "Replace", { type: "button" });
      replace.onclick = () => {
        render();
        fillForm(r);
        body.querySelector("[data-auth-form]").scrollIntoView({ block: "nearest" });
      };
      actions.append(
        replace,
        button(
          "Remove",
          async () => {
            await api("DELETE", `${state.base}/auth-credentials/${r.id}`);
            toast("Sign-in removed");
            await refresh();
          },
          "btn danger sm",
        ),
      );
      box.append(actions);
      return box;
    };
    let current = null; // the form's inputs
    const form = () => {
      const box = el("div", "", null, { "data-auth-form": "1" });
      const label = text("", { placeholder: "staging test account", maxlength: "80", autocomplete: "off" });
      const host = text("", { placeholder: `one host of ${target.name}, for example www.${target.name}`, autocomplete: "off" });
      const radio = (value, labelText) => {
        const wrap = el("label", "", null, { style: "display:block;margin:4px 0" });
        const input = el("input", "", null, { type: "radio", name: "auth-scope", value });
        wrap.append(input, document.createTextNode(` ${labelText}`));
        return { wrap, input };
      };
      const scopeHost = radio("host", "One host of the target");
      const scopeTarget = radio("target", `All hosts of ${target.name}`);
      const scopeWarn = el(
        "p",
        "note",
        "Warning: this credential will be sent to every host of the target that is in scope and on the allowed origins.",
        { style: "font-size:13px;margin:4px 0;color:var(--warn, #b45309)" },
      );
      const sync = () => {
        host.disabled = !scopeHost.input.checked;
        scopeWarn.hidden = !scopeTarget.input.checked;
      };
      scopeHost.input.onchange = scopeTarget.input.onchange = sync;
      scopeHost.input.checked = true;
      sync();
      const origins = text("https:443", { autocomplete: "off" });
      const expires = selectOf(EXPIRY_CHOICES, "30");
      const headerRows = el("div", "");
      const cookie = text("", { type: "password", autocomplete: "new-password", placeholder: "name=value; name2=value2" });
      const clearCookie = el("input", "", null, { type: "checkbox" });
      const untrusted = el("input", "", null, { type: "checkbox" });
      const untrustedWrap = el("label", "", null, { style: "display:block;margin:4px 0" });
      untrustedWrap.append(untrusted, document.createTextNode(" Trust this certificate anyway"));
      const untrustedWarn = el("p", "note", UNTRUSTED_WARNING, { style: "font-size:13px;margin:4px 0;color:var(--warn, #b45309)" });
      const syncUntrusted = () => (untrustedWarn.hidden = !untrusted.checked);
      untrusted.onchange = syncUntrusted;
      syncUntrusted();
      const names = [];
      const addHeader = (name = "", stored = false) => {
        const row = el("div", "scope-cell", null, { style: "display:flex;gap:8px;margin:6px 0" });
        const n = text(name, { placeholder: "Authorization", autocomplete: "off", "aria-label": "Header name" });
        const v = text("", { type: "password", autocomplete: "new-password", placeholder: stored ? "unchanged" : "value", "aria-label": "Header value" });
        const drop = el("button", "btn ghost sm", "Remove", { type: "button" });
        const entry = { n, v };
        drop.onclick = () => {
          names.splice(names.indexOf(entry), 1);
          row.remove();
        };
        row.append(n, v, drop);
        names.push(entry);
        headerRows.append(row);
      };
      addHeader();
      const more = el("button", "btn ghost sm", "Add a header", { type: "button" });
      more.onclick = () => addHeader();
      const clearWrap = el("label", "", null, { style: "display:block;margin:4px 0" });
      clearWrap.append(clearCookie, document.createTextNode(" Remove the stored cookie"));
      box.append(
        field("Label", label, "A name for you, such as which account this is."),
        el("p", "note", "Where it is sent (choose one):", { style: "margin:10px 0 0" }),
        scopeHost.wrap,
        field("Host", host, `The one host of ${target.name} it is for. Prefer this.`),
        scopeTarget.wrap,
        scopeWarn,
        field("Origins", origins, ORIGIN_HELP),
        el("p", "note", "By default the sign-in is sent only to a server whose TLS certificate verifies. If this target uses a self-signed, expired or mismatched certificate (a typical staging host), the sign-in is not sent and the activity feed says why.", { style: "margin:10px 0 0;font-size:13px" }),
        untrustedWrap,
        untrustedWarn,
        el("p", "note", "Headers (for example Authorization or X-Api-Key). A blank value for a stored name keeps it.", { style: "margin:10px 0 0" }),
        headerRows,
        more,
        field("Cookie", cookie, "Optional: the cookie string of a session, as name=value; name2=value2. Blank keeps the stored one."),
        clearWrap,
        field("Expires", expires, "How long the scanners may keep sending it: 30, 90 or 120 days from saving, or never. After that it is not sent. Replacing it starts the count again."),
      );
      const save = button("Save sign-in", async () => {
        const wide = scopeTarget.input.checked;
        const body = { label: label.value, scope: wide ? "target" : "host", host: wide ? "" : host.value, origins: origins.value.split(",").map((s) => s.trim()).filter(Boolean) };
        body.headers = names.filter((e) => e.n.value.trim()).map((e) => ({ name: e.n.value.trim(), secret: e.v.value }));
        if (cookie.value) body.cookie_secret = cookie.value;
        if (clearCookie.checked) body.clear_cookie = true;
        body.allow_untrusted_certificate = untrusted.checked;
        body.expires = expires.value === "never" ? "never" : Number(expires.value);
        await api("PUT", `${state.base}/targets/${target.id}/auth-credential`, body);
        cookie.value = ""; // a saved value is never kept on the page
        names.forEach((e) => (e.v.value = ""));
        toast("Sign-in saved");
        await refresh();
      });
      box.append(el("div", "actions", null, { style: "justify-content:flex-start" }));
      box.lastChild.append(save);
      current = { label, host, origins, expires, untrusted, syncUntrusted, scopeHost, scopeTarget, sync, addHeader, headerRows, names };
      return box;
    };
    const fillForm = (r) => {
      current.label.value = r.label;
      current.host.value = r.host || "";
      current.origins.value = r.origins.join(", ");
      current.scopeHost.input.checked = Boolean(r.host);
      current.scopeTarget.input.checked = !r.host;
      current.sync();
      current.untrusted.checked = Boolean(r.allow_untrusted_certificate); // shown, so a replace never flips it unseen
      current.syncUntrusted();
      current.expires.value = "30"; // a replacement starts a new term; the choice is shown, never inherited
      current.headerRows.textContent = "";
      current.names.length = 0;
      (r.header_names.length ? r.header_names : [""]).forEach((n) => current.addHeader(n, Boolean(n)));
    };
    render();
  });
}
