// The two-step sign-in reminder for administrators (tenancy.mfa_nag), drawn as a notice in the one status strip (statusstrip.js) so it takes no room
// of its own: the strip is the 40px line every page already reserves. It never blocks anything; "Remind me later" hides it for this session only.
import { setNotices } from "/staticfiles/cve/statusstrip.js";

const data = document.getElementById("mfa-nag-data");
const marker = document.querySelector("[data-mfa-nag]");
if (data && marker) {
  const nag = JSON.parse(data.textContent);
  const el = (tag, cls, text, attrs) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    if (attrs) for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  };
  const row = el("div", "sb-row sb-row-mfa");
  row.append(el("p", "sb-mfa", "Your administrator account has no two-step sign-in. Anyone who learns your password can sign in as you. It takes about a minute to turn on."));
  row.append(el("a", "btn sm", "Turn on two-step sign-in", { href: nag.setup_url }));
  const form = el("form", null, null, { method: "post", action: nag.snooze_url });
  form.append(el("input", null, null, { type: "hidden", name: "csrfmiddlewaretoken", value: marker.dataset.csrf || "" }));
  form.append(el("input", null, null, { type: "hidden", name: "next", value: nag.next }));
  form.append(el("button", "btn sm ghost", "Remind me later", { type: "submit" }));
  row.append(form);
  setNotices("mfa", [{ kind: "mfa", text: "Your administrator account has no two-step sign-in. Open Details to turn it on.", rank: 0, node: row }]);
}
