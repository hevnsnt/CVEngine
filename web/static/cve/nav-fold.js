// The Ctrl+K palette lists each page once. The rail, a page's tab and the hidden index can name the same page under the same name; this folds
// them into one row (the first one keeps its place). The same name on another page, or the same page under another name, stays a row of its own.
export function foldNav(links) {
  const seen = new Set();
  const rows = [];
  for (const { label, href } of links) {
    const key = `${href}|${label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({ label, hint: "Go to", href, section: "Go to" });
  }
  return rows;
}
