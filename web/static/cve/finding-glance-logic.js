// Pure helpers for the finding glance cards (no DOM): the evidence strings the server sends ("vulnerable (testssl:secure_client_renego),
// tested 2026-11-07T00:31:37.378808+00:00") become short segments the card can draw as a sentence: plain words, the check name as a
// code chip, and a time shown for people with the full ISO value kept for the tooltip. Tested in tests/test_glance_logic.mjs.

const ISO = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?/;
const ISO_ALL = new RegExp(ISO.source, "g");
const TEMPLATE = new RegExp(
  `^(.*?)(?:\\s*\\(([^()\\s]+)\\))?(?:,\\s*tested\\s+(${ISO.source}))?\\s*$`,
);

const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);
const text = (v) => ({ k: "text", v });
// ``lead`` travels with the code or the time so the card keeps "Check: name" and "Tested Nov 7, 2026 12:31 AM" in one piece. The chip ends its own phrase: no full stop after it (one at a line start looks broken).
const code = (v, lead = "") => ({ k: "code", v, lead });
const when = (iso, lead = "") => ({ k: "when", iso, lead });

// "vulnerable (id), tested ISO" -> "Vulnerable. Check: [id] Tested <time>". Anything that does not look like that stays as it was.
export function templateSegments(value) {
  const v = String(value == null ? "" : value);
  const m = TEMPLATE.exec(v);
  if (!m || !m[1] || (!m[2] && !m[3])) return textSegments(v);
  const out = [text(`${cap(m[1].trim())}.`)];
  if (m[2]) out.push(text(" "), code(m[2], "Check: "));
  if (m[3]) out.push(text(" "), when(m[3], "Tested "));
  return out;
}

// Any other value: the words as they are, with every ISO time swapped for a time marker so it can be shown in the viewer's zone.
export function textSegments(value) {
  const v = String(value == null ? "" : value);
  const out = [];
  let last = 0;
  for (const m of v.matchAll(ISO_ALL)) {
    if (m.index > last) out.push(text(v.slice(last, m.index)));
    out.push(when(m[0]));
    last = m.index + m[0].length;
  }
  if (last < v.length || !out.length) out.push(text(v.slice(last)));
  return out;
}

// The segments as one plain string, with times formatted by ``fmt``: what a screen reader or a test reads.
export function segmentsText(segs, fmt) {
  return segs
    .map((s) => (s.k === "when" ? `${s.lead || ""}${fmt(s.iso) || s.iso}` : s.k === "code" ? `${s.lead}${s.v}` : s.v))
    .join("");
}

// The proof of a finding: what the checks cvENGINE ran against the host reproduced, as one object the card can draw, or null when no check reproduced it
// (a check that failed, found nothing, or only read metadata is not proof). ``validation`` is the detail's own: {status, steps: [{kind, label, display,
// ran_at, result, summary}], evidence: {<check kind>: {request, response, reply}}}. Nothing is invented: every field is the server's, and a hit with no
// recorded exchange still says which check reproduced it.
export function proofOf(validation) {
  const v = validation || {};
  if (v.status !== "hit") return null;
  const hits = (v.steps || []).filter((st) => st && st.result === "hit");
  if (!hits.length) return null;
  const latest = hits.reduce((a, b) => (String(b.ran_at || "") > String(a.ran_at || "") ? b : a));
  const exchanges = Object.entries(v.evidence || {})
    .filter(([, e]) => e && (e.request || e.response || e.reply))
    .map(([kind, e]) => ({ kind, request: e.request || "", response: e.response || "", reply: e.reply || "" }));
  return {
    label: latest.label || latest.kind || "a check",
    at: latest.ran_at || "",
    summary: latest.summary || "",
    display: latest.display || "",
    checks: hits.length,
    exchanges,
  };
}


// Two notes say the same thing when, ignoring case, punctuation and filler, the shorter is mostly contained in the longer: the AI reviewer's note
// restates the triage's reasoning in other words, and the same sentence is stored in two fields. Tested in tests/test_glance_notes.mjs.
const words = (t) =>
  String(t == null ? "" : t)
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2);

export function sameNote(a, b) {
  const x = words(a);
  const y = words(b);
  if (!x.length || !y.length) return false;
  const [short, long] = x.length <= y.length ? [x, y] : [y, x];
  const pool = new Set(long);
  const shared = short.filter((w) => pool.has(w)).length;
  return shared / short.length >= 0.8 && short.length / long.length >= 0.5;
}

// ``notes``: [{key, label, text}] in the order they should read. Returns {shown, repeats}: the notes to draw (a note that repeats an earlier one is
// dropped, and the clearer of the two, the longer, is kept in the earlier one's place) and the repeats, each with the label of what it repeats, for
// a collapsed "also recorded as" line. Nothing is lost: a repeat is kept in full under a fold.
export function dedupeNotes(notes) {
  const shown = [];
  const repeats = [];
  for (const note of notes) {
    if (!note || !String(note.text || "").trim()) continue;
    const at = shown.findIndex((s) => sameNote(s.text, note.text));
    if (at < 0) {
      shown.push(note);
    } else if (String(note.text).length > String(shown[at].text).length) {
      repeats.push({ ...shown[at], repeatOf: note.label });
      shown[at] = note;
    } else {
      repeats.push({ ...note, repeatOf: shown[at].label });
    }
  }
  return { shown, repeats };
}
