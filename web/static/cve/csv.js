// CSV export of a list's current filter. The browser pages through the API (200 rows at a time), builds the file locally and
// downloads it; nothing is sent anywhere else. Cells that a spreadsheet would run as a formula are neutralized.
import { toast } from "/staticfiles/cve/ui.js";

const PAGE = 200;
const MAX_ROWS = 20000;

// A cell starting with = + - @ (or a tab or carriage return) is executed by Excel and Sheets; a leading apostrophe makes it text.
export function csvCell(value) {
  let s =
    value == null
      ? ""
      : Array.isArray(value)
        ? value.join("; ")
        : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(columns, rows) {
  const head = columns.map((c) => csvCell(c.label)).join(",");
  const body = rows.map((row) =>
    columns.map((c) => csvCell(c.value(row))).join(","),
  );
  return `﻿${[head, ...body].join("\r\n")}\r\n`; // the BOM makes Excel read the file as UTF-8
}

export function download(filename, text) {
  const url = URL.createObjectURL(
    new Blob([text], { type: "text/csv;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export const stamp = () => new Date().toISOString().slice(0, 10);

/**
 * Walk every page of a list endpoint.
 * @param {(page:number, size:number) => Promise<{results:any[], count?:number}>} fetchPage
 * @param {(n:number) => void} [onProgress]
 */
export async function collectAll(fetchPage, onProgress) {
  const rows = [];
  let truncated = false;
  for (let page = 1; ; page += 1) {
    const data = await fetchPage(page, PAGE);
    const got = data.results || [];
    rows.push(...got);
    if (onProgress) onProgress(rows.length);
    if (
      !got.length ||
      got.length < PAGE ||
      (data.count != null && rows.length >= data.count)
    )
      break;
    if (rows.length >= MAX_ROWS) {
      truncated = true;
      break;
    }
  }
  return { rows, truncated };
}

// A button that exports: shows the row count while it works, then downloads.
export function exportButton({ label = "CSV", title, run }) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "csv-btn";
  b.textContent = label;
  b.title = title || "Export the current filter as a CSV file";
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      const { filename, columns, rows, truncated } = await run(
        (n) => (b.textContent = `${n}…`),
      );
      if (!rows.length) {
        toast("Nothing to export with this filter.", true);
      } else {
        download(filename, toCsv(columns, rows));
        toast(
          `Exported ${rows.length.toLocaleString()} row${rows.length === 1 ? "" : "s"}${truncated ? ` (stopped at ${MAX_ROWS.toLocaleString()}; narrow the filter for the rest)` : ""}`,
        );
      }
    } catch (err) {
      toast(`Export failed: ${err.message}`, true);
    }
    b.textContent = label;
    b.disabled = false;
  });
  return b;
}
