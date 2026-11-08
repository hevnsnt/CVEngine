// Settings > AI model > CVE catalog seed: create a seed file, download it, import one. App Admin only (the API enforces it).
import { expiry, jobLine, stats, withheld } from "/staticfiles/cve/seed-card-logic.js";

const POLL_MS = 2000;

export function seedCard({ el, api, toast, card, csrf, apiBase, initial }) {
  let status = initial;
  const line = el("p", "note seed-status", "", { role: "status", "aria-live": "polite" });
  const result = el("div", "seed-result");
  const importLine = el("p", "note seed-status", "", { role: "status", "aria-live": "polite" });
  let timer = null;

  const draw = () => {
    const job = status.job;
    const running = !!status.building;
    line.textContent = job && job.kind === "export" && (running || job.state === "failed") ? jobLine(job) : "";
    importLine.textContent = job && job.kind === "import" ? jobLine(job) : "";
    createBtn.disabled = importBtn.disabled = running;
    result.replaceChildren();
    const m = status.built;
    if (m) {
      const dl = el("dl", "seed-stats");
      stats(m).forEach(([k, v]) => {
        dl.append(el("dt", "", k), el("dd", k === "SHA-256" ? "mono" : "", v));
      });
      const made = new Date(m.generated_at).toLocaleString();
      const out = el("ul", "seed-withheld");
      withheld(m).forEach((t) => out.append(el("li", "", t)));
      const links = el("div", "tools");
      links.append(
        el("a", "btn", "Download seed file (.jsonl.gz)", { href: `${apiBase}/cve_seed/download/seed` }),
        el("a", "btn ghost", "Download manifest (.json)", { href: `${apiBase}/cve_seed/download/manifest` }),
      );
      result.append(el("h3", "", `Created ${made}`), dl, el("h3", "", "What the privacy check kept out"), out, links, el("p", "note", expiry(status.expires_at)));
    }
    if (running && !timer) timer = setInterval(poll, POLL_MS);
    if (!running && timer) {
      clearInterval(timer);
      timer = null;
    }
  };
  const poll = async () => {
    if (!result.isConnected) {
      clearInterval(timer);
      timer = null;
      return;
    }
    try {
      const was = status.building;
      status = await api("GET", "cve_seed");
      draw();
      if (was && !status.building) toast(status.job && status.job.state === "failed" ? "The job failed" : "Done", !!(status.job && status.job.state === "failed"));
    } catch (_) {
      /* the next poll tries again */
    }
  };

  // not the page's generic button(): that one re-enables itself when the click handler returns, and these stay off while a job runs
  const action = (label, onClick) => {
    const b = el("button", "btn", label, { type: "button" });
    b.onclick = async () => {
      b.disabled = true;
      try {
        await onClick();
      } catch (err) {
        toast(err.message, true);
      }
      draw();
    };
    return b;
  };
  const createBtn = action("Create seed file", async () => {
    status = await api("POST", "cve_seed/build");
  });
  const seedInput = el("input", "", null, { type: "file", accept: ".gz,application/gzip", "aria-label": "Seed file (cve-seed.jsonl.gz)" });
  const manifestInput = el("input", "", null, { type: "file", accept: ".json,application/json", "aria-label": "Manifest (optional, cve-seed.jsonl.gz.manifest.json)" });
  const importBtn = action("Import seed file", async () => {
    if (!seedInput.files.length) throw new Error("Choose a seed file first.");
    const headers = { "X-CSRFToken": csrf, "Content-Type": "application/octet-stream", "X-Seed-Name": seedInput.files[0].name };
    if (manifestInput.files.length) {
      let m = null;
      try {
        m = JSON.parse(await manifestInput.files[0].text());
      } catch (_) {
        /* the message below */
      }
      if (!m || typeof m !== "object") throw new Error("The manifest file is not understood.");
      headers["X-Seed-Manifest"] = JSON.stringify({ format: m.format, count: m.count, bytes: m.bytes, sha256: m.sha256 });
    }
    importLine.textContent = "Uploading and checking the file...";
    // the file itself is the request body: it is streamed from disk, not read into the page
    const res = await fetch(`${apiBase}/cve_seed/import`, { method: "POST", credentials: "same-origin", headers, body: seedInput.files[0] });
    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      /* empty */
    }
    if (!res.ok) {
      importLine.textContent = data.error || `The upload failed (${res.status}).`;
      throw new Error(data.error || `The upload failed (${res.status})`);
    }
    status = data;
    seedInput.value = manifestInput.value = "";
  });

  const label = (text, input) => {
    const w = el("div", "field");
    w.append(el("label", "", text), input);
    return w;
  };
  const node = card(
    "CVE catalog seed",
    el("p", "", "A seed file is the CVE catalog as one file, to share with another cvENGINE install. A new install loads it on first start, so it begins with every CVE instead of rebuilding them one at a time."),
    el("p", "note", "What is in it: public CVE data (scores, exploitation signals, affected versions, references) and, for each CVE, the shared detection record (the checks and steps). It never holds your hosts, findings, projects or organizations. Before the file is written, every record is checked for names, hosts and addresses of this install and for anything that looks like a password or key; a record that fails is left out and counted below."),
    el("h3", "", "Create"),
    createBtn,
    line,
    result,
    el("h3", "", "Import a seed file"),
    el("p", "note", "Load a seed file made by another install. It adds the CVEs this install lacks and detection records where a CVE has none; nothing already here is changed. Add its manifest file to check the size, SHA-256 and count first."),
    label("Seed file (.jsonl.gz)", seedInput),
    label("Manifest (.json, optional)", manifestInput),
    importBtn,
    importLine,
  );
  node.classList.add("seed-card");
  draw();
  return node;
}
