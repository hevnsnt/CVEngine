// Settings, configMaxxing: the section for advanced tunables. It is a small registry of cards: a card is {id, title, build(host, ctx)} and is
// added with registerCard() (see scan-concurrency-card.js), so another tunable never needs a redesign of the section. Administrators only (the
// whole Settings page is, and so is the API behind every card). DOM is built with textContent / value only.
import { api, ask, button, el, toast } from "/staticfiles/cve/ui.js";
import { SECTION_ID, SECTION_LABEL, WARNING_TEXT } from "/staticfiles/cve/config-maxxing-logic.js";

export const API = "/cve/api/settings";
const registry = [];

export function registerCard(card) {
  if (!registry.some((c) => c.id === card.id)) registry.push(card);
}
export const cards = () => registry.slice();
export const cardAnchor = (id) => `${SECTION_ID}-${id}`;

export async function buildSection(host, { card = "" } = {}) {
  host.textContent = "";
  const head = el("div", "card", null, { style: "max-width:720px;margin-bottom:16px" });
  head.append(el("h2", "", SECTION_LABEL, { style: "margin-bottom:8px" }), el("p", "note", WARNING_TEXT, { style: "margin:0 0 12px" }));
  head.append(
    button(
      "Reset all configMaxxing settings to defaults",
      async () => {
        const sure = await ask("Every setting in configMaxxing goes back to its default (or to the environment variable, where one is set). Scans keep running; the new limits apply within seconds.", {
          title: "Reset everything in configMaxxing?",
          ok: "Reset all",
        });
        if (!sure) return;
        await api("POST", `${API}/config_maxxing/reset`, {});
        toast("configMaxxing is back to its defaults");
        await buildSection(host);
      },
      "btn ghost sm",
    ),
  );
  host.append(head);
  for (const entry of registry) {
    const wrap = el("div", "", null, { id: cardAnchor(entry.id), style: "margin-bottom:16px" });
    host.append(wrap);
    try {
      await entry.build(wrap, { reload: () => buildSection(host) });
    } catch (err) {
      wrap.append(el("p", "msg err", err.message));
    }
  }
  const target = card && document.getElementById(cardAnchor(card));
  if (target) target.scrollIntoView({ block: "start" });
}
