// URL state and per-browser saved views for the filter bars on Hosts and Findings.
//
// URL state: every filter that narrows a list lives in the query string, so any view can be bookmarked or sent to a colleague.
// Values equal to their default are left out, which keeps links short and readable.
//
// Saved views: a named set of those same values, kept in this browser's localStorage (per project and per page). They are a
// convenience, not shared state: clearing site data removes them, and nothing is sent to the server.
import {
  button,
  dialog,
  el,
  field,
  text,
  toast,
  ask,
} from "/staticfiles/cve/ui.js";

const MAX_VIEWS = 12;
const MAX_NAME = 40;

// Merge `values` into the address bar. A value equal to its default (or empty) is removed; other parameters are kept.
export function writeParams(values, defaults, drop = []) {
  const next = new URLSearchParams(location.search);
  drop.forEach((k) => next.delete(k));
  Object.entries(values).forEach(([key, value]) => {
    const v = value == null ? "" : String(value);
    if (v === "" || v === String(defaults[key] ?? "")) next.delete(key);
    else next.set(key, v);
  });
  const qs = next.toString();
  history.replaceState(
    null,
    "",
    location.pathname + (qs ? `?${qs}` : "") + location.hash,
  );
}

// One parameter, accepted only when it is one of the allowed values (or any non-empty string when `allowed` is omitted).
export function readParam(key, fallback, allowed) {
  const raw = new URLSearchParams(location.search).get(key);
  if (raw == null || raw === "") return fallback;
  return !allowed || allowed.includes(raw) ? raw : fallback;
}

const storageKey = (page, slug) => `cve.views.v1.${slug}.${page}`;

function loadViews(page, slug) {
  try {
    const list = JSON.parse(
      localStorage.getItem(storageKey(page, slug)) || "[]",
    );
    return Array.isArray(list)
      ? list.filter(
          (v) =>
            v &&
            typeof v.name === "string" &&
            v.params &&
            typeof v.params === "object",
        )
      : [];
  } catch (_) {
    return []; // private windows and blocked storage: the page works, views just do not persist
  }
}

function storeViews(page, slug, views) {
  try {
    localStorage.setItem(storageKey(page, slug), JSON.stringify(views));
    return true;
  } catch (_) {
    return false;
  }
}

const normalize = (params, defaults) => {
  const out = {};
  Object.keys(defaults).forEach((k) => {
    const v = params[k] == null ? "" : String(params[k]).trim();
    out[k] = v === "" ? String(defaults[k]) : v;
  });
  return JSON.stringify(out);
};

/**
 * @param {{page: string, slug: string, defaults: Record<string,string>, read: () => Record<string,string>,
 *          apply: (params: Record<string,string>) => void}} cfg
 *   read(): the filters as they are now. apply(params): set the controls to a saved view and reload.
 * @returns {{node: HTMLElement, refresh: () => void}}
 */
export function savedViews({ page, slug, defaults, read, apply }) {
  const node = el("div", "views", null, {
    role: "group",
    "aria-label": "Saved views",
  });
  let views = loadViews(page, slug);

  const isDefault = () =>
    normalize(read(), defaults) === normalize({}, defaults);
  const matching = () =>
    views.find(
      (v) => normalize(v.params, defaults) === normalize(read(), defaults),
    );

  function save() {
    dialog("Save this view", (body, close) => {
      const name = text("", {
        maxlength: String(MAX_NAME),
        placeholder: "Exposed databases",
        autocomplete: "off",
        required: "",
      });
      const f = el("form");
      f.append(
        field(
          "Name",
          name,
          "Kept in this browser only. Saving the same name again replaces that view.",
        ),
      );
      const actions = el("div", "dlg-tools");
      actions.append(
        el("span", "grow"),
        button("Cancel", close, "btn ghost"),
        el("button", "btn", "Save view", { type: "submit" }),
      );
      f.append(actions);
      f.addEventListener("submit", (e) => {
        e.preventDefault();
        const label = name.value.trim().slice(0, MAX_NAME);
        if (!label) return;
        const params = JSON.parse(normalize(read(), defaults));
        const others = views.filter(
          (v) => v.name.toLowerCase() !== label.toLowerCase(),
        );
        if (others.length >= MAX_VIEWS) {
          toast(
            `A page keeps at most ${MAX_VIEWS} views. Delete one first.`,
            true,
          );
          return;
        }
        views = [...others, { name: label, params }];
        if (!storeViews(page, slug, views))
          toast(
            "This browser would not store the view; it lasts until you leave the page.",
            true,
          );
        close();
        draw();
        toast(`Saved view "${label}"`);
      });
      body.append(f);
      name.focus();
    });
  }

  async function remove(view) {
    const sure = await ask(
      `The view "${view.name}" will be deleted from this browser.`,
      { title: "Delete this view?", ok: "Delete" },
    );
    if (!sure) return;
    views = views.filter((v) => v !== view);
    storeViews(page, slug, views);
    draw();
  }

  function draw() {
    node.textContent = "";
    const current = matching();
    views.forEach((view) => {
      const chip = el("span", "view");
      const open = el("button", "view-open", view.name, {
        type: "button",
        "aria-pressed": String(view === current),
        title: "Apply this view",
      });
      open.onclick = () => {
        apply(JSON.parse(normalize(view.params, defaults)));
        draw();
      };
      const del = el("button", "view-del", "×", {
        type: "button",
        "aria-label": `Delete view ${view.name}`,
        title: "Delete this view",
      });
      del.onclick = () => remove(view);
      chip.append(open, del);
      node.append(chip);
    });
    if (!isDefault() && !current) {
      const add = el("button", "view-save", "Save view", { type: "button" });
      add.onclick = save;
      node.append(add);
    }
    node.hidden = !node.children.length;
    // saved views are also palette commands: Ctrl+K, then "view"
    const owner = `views:${page}`;
    window.cveCommands = (window.cveCommands || []).filter((c) => c.owner !== owner);
    views.forEach((view) =>
      window.cveCommands.push({
        owner,
        label: `Apply view: ${view.name}`,
        hint: "View",
        run: () => {
          apply(JSON.parse(normalize(view.params, defaults)));
          draw();
        },
      }),
    );
  }

  draw();
  return { node, refresh: draw };
}
