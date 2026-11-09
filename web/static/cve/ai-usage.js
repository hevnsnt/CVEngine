import { api, button, el, shortDate, table, toast } from "/staticfiles/cve/ui.js";
import { renderKeepingState } from "/staticfiles/cve/keep-state.js";

const mount = document.getElementById("ai-usage");
if (mount) {
  const tools = el("div", "tools");
  const days = el("select", "", null, { "aria-label": "Usage period" });
  for (const [value, label] of [["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"]]) {
    const option = el("option", "", label);
    option.value = value;
    days.append(option);
  }
  days.value = "7";
  const output = el("div");
  const status = el("p", "note", "Loading recorded AI attempts…", { role: "status" });
  tools.append(days, button("Refresh", load, "btn ghost sm"));
  mount.append(tools, status, output);
  days.onchange = load;
  let requestNumber = 0;

  const count = (n) => n == null ? "Unknown" : Number(n).toLocaleString();
  const money = (n) => n == null ? "Unknown" : `$${Number(n).toFixed(4)}`;
  const latency = (ms) => ms == null ? "Unknown" : ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`;
  const wrap = (columns, rows) => {
    const box = el("div", "ai-usage-scroll");
    box.append(table(columns, rows));
    return box;
  };
  const metric = (label, value, detail = "") => {
    const card = el("div", "card ai-usage-metric");
    card.append(el("p", "note", label), el("strong", "", value));
    if (detail) card.append(el("p", "note", detail));
    return card;
  };
  const section = (title, content) => {
    const box = el("section", "ai-usage-section", null, { "data-keep-key": `section:${title}` });
    box.append(el("h2", "", title), content);
    return box;
  };
  // key: the stable name of the disclosure (its summary has no number today, but the key must not depend on the words)
  const expandable = (key, title, content) => {
    const box = el("details", "card ai-usage-details", null, { "data-keep-key": key });
    box.append(el("summary", "", title), content);
    return box;
  };

  function priceEditor(data) {
    const details = el("details", "card ai-usage-rate", null, { "data-keep-key": "price-editor" });
    details.append(el("summary", "", "Set operator supplied pricing for an exact model"),
      el("p", "note", "Rates are operator supplied, in USD per million tokens. CVEngine never fetches pricing or treats estimates as invoices."));
    const form = el("form", "ai-usage-rate-form");
    const defaultModel = data.configured_model || data.verified_model || data.models[0]?.billed_model || "";
    const inputs = {};
    for (const [name, label, value, type] of [
      ["provider", "Provider", data.provider || "", "text"],
      ["model", "Exact model ID", defaultModel, "text"],
      ["input_per_million_usd", "Input USD / million", "", "number"],
      ["output_per_million_usd", "Output USD / million", "", "number"],
      ["cache_read_per_million_usd", "Cache read USD / million (optional)", "", "number"],
      ["cache_write_per_million_usd", "Cache write USD / million (optional)", "", "number"],
      ["source_url", "Pricing source HTTPS URL", "", "url"],
      ["as_of", "Price checked on", new Date().toISOString().slice(0, 10), "date"],
    ]) {
      const field = el("label", "field");
      field.append(el("span", "", label));
      const input = el("input", "", null, { name, type, "data-keep-key": `price:${name}` });
      input.value = value;
      if (type === "number") { input.min = "0"; input.step = "0.000001"; }
      if (["provider", "model", "input_per_million_usd", "output_per_million_usd", "source_url", "as_of"].includes(name)) input.required = true;
      inputs[name] = input;
      field.append(input);
      form.append(field);
    }
    const existing = data.rates.find((r) => r.provider === inputs.provider.value && r.model === inputs.model.value);
    if (existing) for (const name of ["input_per_million_usd", "output_per_million_usd", "cache_read_per_million_usd",
      "cache_write_per_million_usd", "source_url", "as_of"]) inputs[name].value = existing[name] || "";
    form.append(el("button", "btn", "Save price source", { type: "submit" }));
    form.onsubmit = async (event) => {
      event.preventDefault();
      const body = Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value.trim()]));
      try {
        await api("PUT", "/cve/api/settings/ai/usage/rate", body);
        toast("Price rate saved");
        await load();
      } catch (error) { toast(error.message, true); }
    };
    details.append(form);
    return details;
  }

  async function load() {
    const current = ++requestNumber;
    try {
      const data = await api("GET", `/cve/api/settings/ai/usage?days=${days.value}`);
      if (current !== requestNumber || !mount.isConnected) return;
      // the blocks are built aside and handed to renderKeepingState: what the person opened, scrolled or typed in the last draw stays, and a block whose
      // markup did not change is not touched (static/cve/keep-state.js)
      const built = el("div");
      status.textContent = `Live · updated ${shortDate(new Date().toISOString())} · refreshes every 15 seconds while this tab is open`;
      const model = data.observed_model || data.configured_model || data.verified_model;
      const hero = el("section", "card ai-usage-hero", null, { "data-keep-key": "hero" });
      const identity = el("div", "ai-usage-identity");
      identity.append(el("p", "ai-usage-eyebrow", "CONNECTED MODEL"),
        el("h2", "", model || "Model not observed yet"),
        el("p", "note", `${data.provider || "Unknown provider"}${data.configured_model && data.configured_model !== model ? ` · configured ${data.configured_model}` : ""}${!data.configured_model ? " · provider default" : ""}`));
      const healthText = {
        responding: "Responding", recent_error: "Recent error", disabled: "Disabled",
        no_recent_activity: "No recent calls", verified_at_setup: "Verified at setup",
        last_verified_over_24h_ago: "No recent calls",
      }[data.health] || "Status unknown";
      const signal = el("div", `ai-usage-signal ${data.health === "responding" ? "ok" : data.health === "recent_error" ? "bad" : "idle"}`);
      signal.append(el("strong", "", healthText),
        el("span", "", data.last_success ? `Last successful call ${shortDate(data.last_success)}` :
          data.verified_at ? `Connection tested ${shortDate(data.verified_at)}` : "No successful call recorded"));
      hero.append(identity, signal);
      built.append(hero);
      const cards = el("div", "ai-usage-grid", null, { "data-keep-key": "metrics" });
      const successRate = data.attempts ? `${Math.round(data.successes / data.attempts * 100)}%` : "-";
      const inputTokens = data.models.reduce((sum, row) => sum + (row.input_sum || 0), 0);
      const outputTokens = data.models.reduce((sum, row) => sum + (row.output_sum || 0), 0);
      const costLabel = !data.priced_attempts ? "Not priced" : money(data.known_estimated_usd);
      const costDetail = !data.priced_attempts ? `${count(data.unknown_cost_attempts)} attempts need an exact model price` :
        data.unknown_cost_attempts ? `Partial · ${count(data.priced_attempts)} of ${count(data.attempts)} attempts priced` : "All recorded attempts priced";
      cards.append(metric("Provider calls", count(data.attempts), `${count(data.errors)} errors · ${count(data.successes)} succeeded`),
        metric("Success rate", successRate, "Recorded provider calls"),
        metric("Tokens returned", count(inputTokens + outputTokens), `${count(inputTokens)} input · ${count(outputTokens)} output`),
        metric("Average response", latency(data.avg_latency_ms), "Per provider call"),
        metric("Estimated cost", costLabel, costDetail));
      built.append(cards);
      if (!data.attempts) built.append(el("p", "empty", "No provider attempts recorded for this period. Earlier usage cannot be reconstructed."));
      if (!data.priced_attempts && data.attempts) built.append(el("p", "ai-usage-price-hint", "Cost is unavailable until an exact model price is saved below. Token counts and provider billing may differ."));
      if (data.templates) {
        const t = data.templates;
        const rows = el("div", "ai-usage-templates");
        rows.append(el("p", "note", `${count(t.valid)} passed and may run on hosts · ${count(t.pending)} being checked by the system · ${count(t.rejected + t.expired)} rejected (${count(t.expired)} of them expired without being validated). The system tests and reviews every AI-written check itself; nothing here needs your review.`));
        if ((t.reasons || []).length) {
          const list = el("ul", "ai-usage-reasons");
          t.reasons.forEach((r) => list.append(el("li", "", `${r.reason} (${count(r.count)})`)));
          rows.append(el("p", "note", "Why checks were rejected, last 30 days:"), list);
        }
        built.append(section("AI-written checks", rows));
      }
      built.append(section("Model breakdown", wrap([
        { label: "Provider / model", render: (r) => `${r.provider} · ${r.billed_model || "unknown model"}` },
        { label: "Attempts", render: (r) => `${count(r.attempts)} (${count(r.errors)} errors)` },
        { label: "Input / output", render: (r) => `${count(r.input_sum)} / ${count(r.output_sum)}` },
        { label: "Cache read / write", render: (r) => `${count(r.cache_read_sum)} / ${count(r.cache_write_sum)}` },
        { label: "Estimate", render: (r) => money(r.estimated_usd) },
        { label: "Rate source", render: (r) => r.rate_source ? `${r.rate_source} (${r.rate_as_of})` : "not configured" },
      ], data.models)));
      built.append(expandable("daily", "Daily usage", wrap([
        { label: "Day (UTC)", render: (r) => r.day },
        { label: "Attempts", render: (r) => count(r.attempts) },
        { label: "Errors", render: (r) => count(r.errors) },
      ], data.daily)));
      built.append(expandable("stages", "Call stages", wrap([
        { label: "Stage", render: (r) => r.stage },
        { label: "Attempts", render: (r) => count(r.attempts) },
        { label: "Errors", render: (r) => count(r.errors) },
        { label: "Answered by", render: (r) => ((r.models || []).length ? r.models.map((m) => `${m.model} (${count(m.successes)} of ${count(m.attempts)})`).join(", ") : "no recorded model")
          + ((r.failed_reasons || []).length ? ` | Not answered: ${r.failed_reasons.map((f) => `${count(f.count)} ${f.recovered ? "cut off, answered by the automatic retry" : f.category}${f.stop_reason && !f.recovered ? ` [${f.stop_reason}]` : ""}`).join(", ")}` : "") },
      ], data.stages)));
      built.append(expandable("recent", "Recent attempts and errors", wrap([
        { label: "When (UTC)", render: (r) => shortDate(r.at) },
        { label: "Provider / model", render: (r) => `${r.provider} · ${r.actual_model || r.model || "unknown"}` },
        { label: "Stage", render: (r) => r.stage },
        { label: "Result", render: (r) => (r.status === "failed" ? (r.reason || r.error_category || "failed") : r.status) + (r.stop_reason ? ` [${r.stop_reason}]` : "") },
        { label: "Input / output", render: (r) => `${count(r.input_tokens)} / ${count(r.output_tokens)}` },
        { label: "Latency", render: (r) => latency(r.duration_ms) },
      ], data.recent)));
      const about = el("details", "ai-usage-about", null, { "data-keep-key": "about" });
      about.append(el("summary", "", "About this data"), el("p", "note", data.coverage_note),
        el("p", "note", `Explicit connection test: ${data.verified_at ? shortDate(data.verified_at) : "not recorded"}. Successful provider calls above show observed transport activity, not a new connection test.`));
      built.append(about);
      built.append(priceEditor(data));
      renderKeepingState(output, () => Array.from(built.childNodes));
    } catch (error) {
      if (current === requestNumber) status.textContent = `Usage unavailable: ${error.message}`;
    }
  }
  load();
  setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
}
