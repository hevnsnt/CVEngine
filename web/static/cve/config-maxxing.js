// Settings, configMaxxing: the section for advanced tunables. It is a small registry of cards: a card is {id, title, build(host, ctx)} and is
// added with registerCard() (see scan-concurrency-card.js), so another tunable never needs a redesign of the section. Administrators only (the
// whole Settings page is, and so is the API behind every card). DOM is built with textContent / value only.
import { api, ask, badge, button, el, shortDate, toast } from "/staticfiles/cve/ui.js";
import { SECTION_ID, SECTION_LABEL, WARNING_TEXT, autoTuneLine } from "/staticfiles/cve/config-maxxing-logic.js";

export const API = "/cve/api/settings";
const registry = [];

export function registerCard(card) {
  if (!registry.some((c) => c.id === card.id)) registry.push(card);
}
export const cards = () => registry.slice();

const BADGE = { pinned: ["Pinned", ""], tuned: ["Auto-tuned", "success"], suggested: ["Suggested", "queued"], managed: ["Auto-tuning", ""] };

// The auto-tuning line under a row of any card (cveFeed/autotune.py): a badge and a sentence, with "Let auto-tune manage this" for a pinned row
// (mode Auto) and "Apply" for a recommendation. Null when there is nothing to say (the setting is never tuned, or auto-tuning is off).
export function autoTuneRow(field, mode, reload) {
  const line = autoTuneLine(field, mode, shortDate);
  if (!line.text) return null;
  const row = el("p", "note", null, { style: "margin:4px 0 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap" });
  const [label, tone] = BADGE[line.kind];
  row.append(badge(label, tone), el("span", "", line.text));
  if (line.release) {
    const release = button("Let auto-tune manage this", async () => {
      await api("POST", `${API}/autotune/release`, { setting: field.key });
      toast(`Auto-tuning manages ${field.label} now, from ${field.value}`);
      await reload();
    }, "btn ghost sm");
    release.setAttribute("aria-label", `Let auto-tune manage ${field.label}`);
    row.append(release);
  }
  if (line.suggestion) {
    const apply = button("Apply", async () => {
      await api("POST", `${API}/autotune/decisions/${line.suggestion.id}/apply`, {});
      toast(`${field.label} is now ${line.suggestion.value}`);
      await reload();
    }, "btn ghost sm");
    apply.setAttribute("aria-label", `Apply ${line.suggestion.value} to ${field.label}`);
    row.append(apply);
  }
  return row;
}
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
