// About page: a filter over the software inventory, and the long Python library lists folded away. Without this script every group is open and every row is
// visible; the filter box is hidden until it can work. DOM is read and toggled only; nothing is built from text.
const input = document.getElementById("about-filter-input");
const box = document.getElementById("about-filter");
const status = document.getElementById("about-filter-status");
const empty = document.getElementById("about-filter-empty");
const groups = [...document.querySelectorAll("[data-group]")];
const rows = groups.map((g) => [...g.querySelectorAll("[data-row]")].map((r) => [r, r.textContent.toLowerCase().replace(/\s+/g, " ")]));
const total = rows.reduce((n, g) => n + g.length, 0);

// the library groups are long and only a reference: start them folded (the page text still holds them when this script does not run)
for (const g of groups) if (g.id.startsWith("software-libraries")) g.open = false;
const folded = new Map(groups.map((g) => [g, g.open]));

function apply() {
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;
  groups.forEach((g, i) => {
    let n = 0;
    for (const [row, text] of rows[i]) {
      const hit = words.every((w) => text.includes(w));
      row.hidden = !hit;
      if (hit) n += 1;
    }
    g.hidden = words.length > 0 && n === 0;
    g.querySelector("[data-count]").textContent = words.length ? `${n} of ${rows[i].length}` : String(rows[i].length);
    if (words.length) g.open = n > 0;
    else g.open = folded.get(g);
    shown += n;
  });
  status.textContent = words.length ? `${shown} of ${total} shown` : "";
  empty.hidden = !(words.length && shown === 0);
}

for (const g of groups) g.addEventListener("toggle", () => { if (!input.value) folded.set(g, g.open); });
input.addEventListener("input", apply);
box.hidden = false;
