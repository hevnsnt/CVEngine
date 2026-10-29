// Bulk actions for a list of rows: a Select toggle, a checkbox on each selectable row, and a black action bar (the same bar the
// Targets page uses). An action runs the single-item request for each row, four at a time (the server also has `hosts/bulk`, which
// no screen calls yet), with progress, and reports exactly which rows failed and why, with a one-click retry of just those.
import {
  ask,
  button,
  dialog,
  el,
  field,
  text,
  toast,
} from "/staticfiles/cve/ui.js";

const LANES = 4;

// A notice with an Undo button that stays for UNDO_MS. Used after a bulk change and after a row-menu action.
export const UNDO_MS = 10000;
export function undoNotice(message, onUndo) {
  const box = el("div", "toast notice undo", null, { role: "status" });
  const text = el("span", "", message);
  const undo = el("button", "notice-link notice-undo", "Undo", { type: "button" });
  const close = el("button", "notice-close", "\u00d7", { type: "button", "aria-label": "Dismiss" });
  let done = false;
  const end = () => {
    done = true;
    box.remove();
  };
  undo.onclick = async () => {
    if (done) return;
    undo.disabled = true;
    end();
    await onUndo();
  };
  close.onclick = end;
  box.append(text, undo, close);
  document.body.append(box);
  setTimeout(() => {
    if (!done) end();
  }, UNDO_MS);
  return box;
}

export async function runBulk(items, worker, onProgress) {
  const ok = [];
  const failed = [];
  let next = 0;
  let done = 0;
  async function lane() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      try {
        await worker(items[i]);
        ok.push(items[i]);
      } catch (err) {
        failed.push({
          item: items[i],
          error: (err && err.message) || String(err),
        });
      }
      done += 1;
      if (onProgress) onProgress(done, items.length);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(LANES, items.length) }, lane),
  );
  return { ok, failed };
}

/**
 * @param {object} cfg
 * @param {HTMLElement} cfg.side        the list card: gets the "selecting" class while selection is on
 * @param {HTMLElement} cfg.rows        the element that holds the rows
 * @param {string} cfg.noun             "host", "match" ...
 * @param {(item) => string} cfg.labelOf
 * @param {(item) => boolean} [cfg.selectable]
 * @param {string} [cfg.hint]           shown while selecting (what can and cannot be selected)
 * @param {Array} cfg.actions           {label, verb, done, run(item, value), confirm?(n), danger?, select?: {label, options}, prompt?: {...}}
 * @param {() => void} cfg.afterRun     refresh the list
 */
export function createBulk({
  side,
  rows,
  noun,
  labelOf,
  selectable = () => true,
  hint = "",
  actions,
  afterRun,
}) {
  const selected = new Map(); // key -> item
  const keyOf = (item) => String(item.__bulkKey);
  let selecting = false;
  let anchor = null;

  const toggle = el("button", "bulk-toggle", "Select", {
    type: "button",
    "aria-pressed": "false",
    title: `Select ${noun}s to act on several at once`,
  });
  const bar = el("div", "selbar bulk-bar", null, {
    role: "region",
    "aria-label": `Actions for selected ${noun}s`,
  });
  bar.hidden = true;
  const note = el("p", "bulk-hint note", hint);
  note.hidden = true;
  const count = el("span", "bulk-count", "");
  const status = el("span", "bulk-status", "", { role: "status" });
  const controls = el("span", "bulk-actions");
  const all = el("button", "btn ghost sm", `Select all shown`, {
    type: "button",
  });
  const clear = el("button", "btn ghost sm", "Clear", { type: "button" });
  bar.append(count, all, controls, status, el("span", "grow"), clear);

  const boxes = () => [...rows.querySelectorAll(".row-check")];
  const visibleBoxes = () =>
    boxes().filter((b) => !b.closest(".host-row").hidden && !b.disabled);

  function paint() {
    const n = selected.size;
    bar.hidden = !selecting || n === 0;
    count.textContent = `${n} selected`;
    boxes().forEach((b) => (b.checked = selected.has(b.dataset.key)));
    side.classList.toggle("selecting", selecting);
    toggle.setAttribute("aria-pressed", String(selecting));
    toggle.textContent = selecting ? "Done" : "Select";
    note.hidden = !(selecting && hint);
  }

  function set(item, on) {
    if (on) selected.set(keyOf(item), item);
    else selected.delete(keyOf(item));
  }

  function setSelecting(on) {
    selecting = on;
    if (!on) selected.clear();
    anchor = null;
    paint();
  }

  toggle.onclick = () => setSelecting(!selecting);
  clear.onclick = () => {
    selected.clear();
    paint();
  };
  all.onclick = () => {
    visibleBoxes().forEach((b) => set(b.__item, true));
    paint();
  };

  async function perform(action, value) {
    const items = [...selected.values()];
    if (!items.length) return;
    if (action.confirm) {
      const sure = await ask(action.confirm(items.length), {
        title: `${action.label} ${items.length} ${noun}${items.length === 1 ? "" : "s"}?`,
        ok: action.label,
        danger: Boolean(action.danger),
      });
      if (!sure) return;
    }
    bar.classList.add("busy");
    [...controls.querySelectorAll("button,select"), all, clear].forEach(
      (c) => (c.disabled = true),
    );
    status.textContent = `${action.verb} ${items.length}`;
    const priors = new Map(items.map((i) => [keyOf(i), action.prior ? action.prior(i) : undefined]));
    const result = action.runBatch
      ? await action.runBatch(items, value)
      : await runBulk(
          items,
          (item) => action.run(item, value),
          (done, total) => {
            status.textContent = `${action.verb} ${done} of ${total}`;
          },
        );
    status.textContent = "";
    bar.classList.remove("busy");
    [...controls.querySelectorAll("button,select"), all, clear].forEach(
      (c) => (c.disabled = false),
    );
    selected.clear();
    result.failed.forEach((f) => selected.set(keyOf(f.item), f.item));
    const undoable = result.ok.filter((i) => priors.get(keyOf(i)) !== undefined);
    const doneText = `${action.done}: ${result.ok.length} ${noun}${result.ok.length === 1 ? "" : "s"}`;
    if (!result.failed.length) {
      if (undoable.length && (action.restore || action.restoreBatch)) {
        undoNotice(doneText, async () => {
          const back = action.restoreBatch
            ? await action.restoreBatch(undoable, (i) => priors.get(keyOf(i)))
            : await runBulk(undoable, (i) => action.restore(i, priors.get(keyOf(i))));
          toast(back.failed.length ? `Undone for ${back.ok.length}, ${back.failed.length} could not be undone` : `Undone: ${back.ok.length} ${noun}${back.ok.length === 1 ? "" : "s"}`, back.failed.length > 0);
          afterRun();
        });
      } else {
        toast(doneText);
      }
    } else {
      reportFailures(action, value, result);
    }
    afterRun();
    paint();
  }

  function reportFailures(action, value, result) {
    dialog(
      `${result.failed.length} of ${result.ok.length + result.failed.length} could not be updated`,
      (body, close) => {
        body.append(
          el(
            "p",
            "note",
            `${result.ok.length} succeeded. These are still selected, so you can try them again.`,
          ),
        );
        const list = el("ul", "bulk-fails");
        result.failed.slice(0, 12).forEach((f) => {
          const li = el("li");
          li.append(
            el("b", "mono", labelOf(f.item)),
            el("span", "note", f.error),
          );
          list.append(li);
        });
        if (result.failed.length > 12)
          list.append(
            el("li", "note", `and ${result.failed.length - 12} more`),
          );
        body.append(list);
        const actionsRow = el("div", "dlg-tools");
        actionsRow.append(
          el("span", "grow"),
          button("Close", close, "btn ghost"),
          button("Try the failed again", () => {
            close();
            perform({ ...action, confirm: null }, value);
          }),
        );
        body.append(actionsRow);
      },
    );
  }

  actions.forEach((action) => {
    if (action.select) {
      const s = el("select", "bulk-select", null, {
        "aria-label": action.select.label,
      });
      s.append(
        Object.assign(el("option", "", `${action.select.label}…`), {
          value: "",
        }),
      );
      action.select.options.forEach(([value, label]) =>
        s.append(Object.assign(el("option", "", label), { value })),
      );
      s.onchange = () => {
        const v = s.value;
        s.value = "";
        if (v) perform(action, v);
      };
      controls.append(s);
    } else if (action.prompt) {
      const b = el("button", "btn ghost sm", action.label, { type: "button" });
      b.onclick = () =>
        dialog(action.prompt.title, (body, close) => {
          const input = text("", {
            maxlength: "200",
            placeholder: action.prompt.placeholder || "",
            autocomplete: "off",
          });
          const f = el("form");
          f.append(field(action.prompt.label, input, action.prompt.help));
          const row = el("div", "dlg-tools");
          row.append(
            el("span", "grow"),
            button("Cancel", close, "btn ghost"),
            el("button", "btn", "Apply", { type: "submit" }),
          );
          f.append(row);
          f.addEventListener("submit", (e) => {
            e.preventDefault();
            close();
            perform(action, input.value.trim());
          });
          body.append(f);
          input.focus();
        });
      controls.append(b);
    } else {
      const b = el(
        "button",
        `btn ghost sm${action.danger ? " danger" : ""}`,
        action.label,
        { type: "button" },
      );
      b.onclick = () => perform(action, undefined);
      controls.append(b);
    }
  });

  // Called for each row as it is drawn. A row that cannot be selected gets no checkbox.
  function decorate(row, item, key) {
    item.__bulkKey = key;
    if (!selectable(item)) return;
    const box = el("input", "row-check", null, {
      type: "checkbox",
      "aria-label": `Select ${labelOf(item)}`,
      tabindex: selecting ? "0" : "-1",
    });
    box.dataset.key = String(key);
    box.__item = item;
    box.checked = selected.has(String(key));
    box.addEventListener("click", (e) => {
      e.stopPropagation();
      const list = visibleBoxes();
      if (e.shiftKey && anchor && list.includes(anchor)) {
        const [from, to] = [list.indexOf(anchor), list.indexOf(box)].sort(
          (x, y) => x - y,
        );
        list.slice(from, to + 1).forEach((b) => set(b.__item, box.checked));
      } else {
        set(item, box.checked);
      }
      anchor = box;
      paint();
    });
    row.prepend(box);
    // while selecting, a click on the row (not on a link) toggles it instead of opening the detail pane
    row.addEventListener(
      "click",
      (e) => {
        if (!selecting || e.target.closest("a") || e.target === box) return;
        e.stopImmediatePropagation();
        box.click();
      },
      true,
    );
  }

  // Keep only selected items that are still drawn and visible, so an action never touches something the reader cannot see.
  // Called after a list is drawn and after a filter hides rows (not while the list is empty and loading).
  function prune() {
    const live = new Set(boxes().filter((x) => !x.closest(".host-row").hidden).map((x) => x.dataset.key));
    [...selected.keys()].forEach((k) => {
      if (!live.has(k)) selected.delete(k);
    });
    paint();
  }

  return {
    toggle,
    bar,
    note,
    decorate,
    prune,
    paint,
    clear: () => setSelecting(false),
    isSelecting: () => selecting,
    toggleRow: (row) => row.querySelector(".row-check")?.click(),
  };
}
