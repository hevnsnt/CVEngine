# State machines

Many things in cvENGINE move through states: a scan is queued, running, then finished; a Sentinel task is claimed, run, reported; a finding is
open, then fixed or a false positive. Each of these is a **state machine**. This page lists all of them, which are explicit (one table, one
way to change them) and which are still implicit (writes spread over the code), and what is wrong with the implicit ones.

## Why explicit

An implicit machine is changed by `.update(status=...)` calls in many places, each deciding on its own which states it may leave. When a
write is based on something read a moment earlier, it can move a row backwards: a person stops a scan, and the pipeline, finishing a second
later, marks it a success. Making a machine explicit fixes that class of bug for good:

- **People** see a state named the same way everywhere, and a decision they make (Stop, Revoke, False positive) is not undone by a job that was
  already running.
- **Developers** read one table instead of grepping for writes, and change a row in one way that cannot pick a forbidden move.
- **Agents** get the stable name of every state next to its stored value, can ask what a state means and what may follow it
  (`GET /api/v1/states`, MCP `describe_states`), and get a 409 that names the allowed next states instead of a silent no-op.

## How it works

`web/reNgine/lifecycle.py` holds the `Machine` class; `web/reNgine/state_machines.py` holds every table. A table names each state (stored
value, stable key, label, one-sentence meaning), the states a row may be created in, and the allowed moves. A state with no moves is final.

```python
from reNgine.state_machines import SCAN, SUCCESS

# Moves the row only if it is in a state allowed to become SUCCESS; returns 0 if it had moved on (a person stopped it).
if not SCAN.move(ScanHistory.objects.filter(pk=scan_id), SUCCESS, stop_scan_date=now):
    return {'status': 'aborted'}
```

- `move(queryset, target, *, only_from=None, field=None, **also)` is one conditional `UPDATE ... WHERE status IN (allowed sources)`. It is
  race-free without a lock and returns how many rows moved.
- `check(current, target)` raises `Refused` with a sentence naming the allowed next states; an API handler answers 409 with it.
- `legend()` is the table as data; `lifecycle.legends()` lists them all for the API.

Rules for new code: add the table before code moves rows through it; never write a lifecycle field with a plain `.update()` or `save()`;
stored values and API field names never change (add a `state` name next to an old numeric `status` instead).

## Explicit machines

| Machine | Field | States (final in bold) | Notes |
| --- | --- | --- | --- |
| `scan` | `startScan.ScanHistory.scan_status`, and `ScanActivity.status` for each stage | queued -1, running 1, success 2, failed 0, **aborted 3** | A Stop is final. Failed may still become success (the reaper can close a scan that was still running; its own finish is the truth). REST and MCP scan rows carry `state` (the name) next to `status` (the code). |
| `remediation` | `remediation_status` of `cveFeed.CVEMatch`, `startScan.Vulnerability` and `cveFeed.HygieneFinding` | open, in_progress, fixed, accepted_risk, false_positive (labels from `cveFeed.closure.LABELS`) | A person may move a finding between any statuses. An automatic actor (retest, agent report, AI reviewer, scanner engine, sweeps) writes only with `REMEDIATION.move(..., only_from=(<the status it read>,))`, so a decision a person made in between stands. An agent's "fixed" applies only from open or in progress (`AGENT_MAY_FIX`). |

## Implicit machines, and what is wrong with them

Found by a survey of the server and the Sentinel client. Each is moved to an explicit table in its own change; the bugs listed are fixed as it moves.

### Scanning

- **Scan status** (`ScanHistory.scan_status`): explicit (above). Fixed while moving it: a Stop during an internal scan or near the end of a
  discovery was overwritten with success or failed; a stage a person stopped was overwritten with its own result; a duplicate delivery of a running
  scan's message replaced its Celery task ids, so the reaper closed the live scan and a Stop revoked the wrong task.
- **Global pause** (`ScanControl.paused`, `paused_by_update`, update window): one flag shared by a person, the updater and the watchdog's
  pressure pause. A watchdog pause opens the update window, which freezes Sentinel task expiry for up to 6 hours; the updater's release lifts a
  watchdog pause while the pressure lasts.
- **Stage runs** (`agentapi.StageRun.state`): `cancelled` is listed but never written; the close is a blind write a second worker can be overwritten by.
- **Host assessments** (`HostAssessment.status`), archive review runs (`queued/running/partial/completed`, where partial means two things).
- `SubScan.status` is dead (never written).

### Sentinels and agents

- **Agent status** (`Agent.status`: pending, active, suspended, revoked): registration does a full `save()`, so a revoke made while a Sentinel
  re-registers is reverted to active; a claim checks a status read before its lock.
- **Sentinel task** (`SentinelTask.status`: queued, claimed, running, done, failed, expired): a late result moves an expired task (cancelled by a
  person, or its Sentinel suspended) back to done without checking why it expired; the report write is blind after its check.
- **Agent task** (`AgentTask.status`): consistent (conditional writes throughout).
- **Sentinel self-update status** (`info.update.status`, `info.auto_update.status`): "Update now" is disabled exactly when Manual mode waits for
  an admin; "updating" can stay forever; a lingering "failed" clears a fresh Update now request.
- **Client side** (the Sentinel repository): an active Sentinel whose user or token has a problem gets a 403 the client reads as a revoked token
  and crash-loops; the spool, task flags and enrollment are consistent.

### Findings

- **Remediation status**: explicit (above). Fixed while moving it: a retest that started before a person closed a finding reopened it over their
  decision (it now leaves the person's status and notes in the audit trail that its result was not applied); an agent's "fixed" report overwrote a
  false positive set meanwhile; an AI verdict already queued reopened a match a rule closed while the question waited (and replaced the rule's
  not-applicable classification); the AI reviewer's close and the WordPress fixed-version close write only from the status they read; the bulk
  status change overwrote findings changed after it read them (they are now reported as failed). Still open: "fixed" sticks differently per finding kind.
- **Supplier findings** (`SupplierFinding.status`): fixed here: a person's "accepted" is no longer resolved, so it is not lost when the issue goes
  away and comes back, and the sweep writes only the fields it changes, conditionally, instead of saving a row read earlier.
- **SSH findings**: fixed here: an in-progress one is now marked gone (`open_status`) when a complete inspection reads a clean key; its status is kept.
- **Saved searches**: fixed here: an edit saves only the fields it changes, so an evaluation finishing meanwhile does not re-alert the same hosts.
- **Secrets** (`status`, `remediation_status`), triage status, validation status, retest state, generated templates.

### Operations

- **Update approval** (database row and `web/.update-approved`): the host clears the file but not the row, so the UI says approved while nothing
  is pending; a check after a failed restart deletes the approval and the retries stop; after a web-side removal the page keeps saying "The approval
  is kept and retries by itself".
- **Update phase** (`.update-phase.json`): `failed` is written for refusals that retry; `restarting`/`resuming` are read but never written; a
  phase stays `applying` after a crash.
- **Scanner plan** (`.update-sentinels`): read once and deleted before the deploy steps that need it, so the choice made in the Approve dialog is dropped.
- **AI jobs** (`AIJob.status`): a job lost while applying never tells its stage.
- **Auto-tuning phase**, **watchdog status**, **OpenVAS add-on switch** (the app never writes the request the host script waits for),
  certificate status (consistent).
