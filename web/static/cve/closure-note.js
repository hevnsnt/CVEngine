// The note box shown whenever a finding is closed (fixed, accepted risk, false positive; a supplier finding accepted or a false positive):
// one dialog for a single finding, a bulk change and a supplier finding alike. The words and the rules are closure-logic.js's.
import { dialog, el, field } from "/staticfiles/cve/ui.js";
import { NOTE_MAX, cleanNote, noteProblem, notePrompt } from "/staticfiles/cve/closure-logic.js";

// Ask why `count` findings are being closed as `status`. Resolves {note} (an empty note where one is optional), or null when cancelled.
export function askClosureNote(status, count = 1, initial = "") {
  const words = notePrompt(status, count);
  return new Promise((resolve) => {
    let answer = null;
    const d = dialog(words.title, (body, close) => {
      const input = el("textarea", "", null, { rows: "4", maxlength: String(NOTE_MAX), "aria-required": String(words.required) });
      input.value = initial || "";
      const error = el("p", "msg err", "", { role: "alert" });
      error.hidden = true;
      const form = el("form");
      form.append(field(words.label, input, words.help), error);
      const row = el("div", "dlg-tools");
      const cancel = el("button", "btn ghost", "Cancel", { type: "button" });
      cancel.onclick = close;
      row.append(el("span", "grow"), cancel, el("button", "btn", words.ok, { type: "submit" }));
      form.append(row);
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const problem = noteProblem(status, input.value);
        if (problem) {
          error.textContent = problem;
          error.hidden = false;
          input.focus();
          return;
        }
        answer = { note: cleanNote(input.value) };
        close();
      });
      body.append(form);
      setTimeout(() => input.focus(), 0);
    });
    d.addEventListener("close", () => resolve(answer));
  });
}
