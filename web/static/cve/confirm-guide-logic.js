// The words of the "Confirm it yourself" panel when no check has run: what is really true of this finding, never a promise that a check will
// run when none exists. Pure: the finding detail in (validation.status and validation.automatic from agentapi.services._automatic_plan,
// automatic_validation, ai.status), one sentence out. ``when`` formats a date (the page passes its own).

const LANE = { fire: "Fire", smoke: "Smoke", ice: "Ice" };
const BY_HAND = "confirm it by hand with the steps above";

export function checkStateText(d, when = (iso) => iso || "") {
  const v = (d && d.validation) || {};
  const plan = v.automatic || {};
  const job = d && d.automatic_validation;
  const ai = (d && d.ai) || {};
  const isMatch = d && d.kind === "match";
  if (v.status === "skipped_blocked") return "The checks were not run: the host is outside this project or resolves to an address that must not be scanned.";
  if (job && (job.status === "queued" || job.status === "running")) {
    const what = plan.check === false
      ? "An automatic AI review of this finding (no check is sent to the host for this kind of finding)"
      : `${job.source === "manual" ? "A requested" : "An automatic"} validation`;
    if (job.status === "running") return `${what} is running now${job.started ? `, since ${when(job.started)}` : ""}.`;
    return `${what} is queued${job.created ? ` since ${when(job.created)}` : ""}; a validation worker takes it next, Fire first.`;
  }
  if (plan.check === false) return `No automatic check exists for this finding; ${BY_HAND}.`;
  if (v.status === "no_check") return `No automatic check fits this finding's evidence; ${BY_HAND}.`;
  if (v.status === "pending") return `Checks are queued and run automatically; ${BY_HAND} meanwhile.`;
  if (v.status === "failed") return "The last check failed.";
  if (v.status && v.status !== "none") return "No check output is recorded for this finding.";
  if (ai.status === "untracked") return `Triage has not started for this finding yet, so no check is planned. Meanwhile, ${BY_HAND}.`;
  if (ai.status === "pending" && !plan.lane) {
    return `Triage has not finished for this finding yet${plan.why ? `; no automatic check will run after it: ${plan.why}` : ""}. Meanwhile, ${BY_HAND}.`;
  }
  if (plan.lane) {
    return `No check has run yet. This finding is in the ${LANE[plan.lane] || plan.lane} validation lane: the validation sweep, every 5 minutes, ` +
      "queues it (hottest first, within the per-project and daily limits).";
  }
  return `No automatic check will run for this finding${plan.why ? `: ${plan.why}` : ""}. ${isMatch ? "Press Validate now, or c" : "C"}onfirm it by hand with the steps above.`;
}
