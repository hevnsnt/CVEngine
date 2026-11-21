// What a Sentinel read about the features of the service on one port (cveFeed.service_features, the host row's `service_features`), in words:
// "HTTP/2: yes, supports CVEs that need it (ALPN h2, read 2026-11-19)". The value is printed as read (a feature may hold several tokens, such as
// SSH algorithms), and `meaning` is what the reading does for a CVE that needs the feature (exposed, ruled_out, or "" when no rule reads it).
// Kept free of the DOM and of imports so that `node --test` can run it (tests/test_service_features_logic.mjs).

export const MEANING_WORDS = {
  exposed: "supports CVEs that need it",
  ruled_out: "rules out CVEs that need it",
  unknown: "neither rules out nor supports a CVE",
};

export function featureText(f) {
  const meaning = MEANING_WORDS[f.meaning] || "";
  const when = f.observed_at ? `read ${String(f.observed_at).slice(0, 10)}` : "";
  const notes = [f.detail, when].filter(Boolean).join(", ") + (f.fresh === false ? ", stale: no longer used" : "");
  return `${f.label || f.feature}: ${f.value}` + (meaning && f.fresh !== false ? `, ${meaning}` : "") + (notes ? ` (${notes})` : "");
}

export function featureLine(features, port) {
  return (features || [])
    .filter((f) => f.port === port)
    .map(featureText)
    .join("; ");
}
