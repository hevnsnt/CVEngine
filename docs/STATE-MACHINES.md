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

`web/cvengine/lifecycle.py` holds the `Machine` class; `web/cvengine/state_machines.py` holds every table. A table names each state (stored
value, stable key, label, one-sentence meaning), the states a row may be created in, and the allowed moves. A state with no moves is final.

```python
from cvengine.state_machines import SCAN, SUCCESS

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
| `agent` | `agentapi.Agent.status` | pending, active, suspended, revoked | Created pending, active or suspended (`_initial_status`); after that only a person's `update_agent` moves it, in one conditional UPDATE from the status the decision was made on (409 when another decision landed first). A registration or heartbeat never writes it, and a claim re-reads it under its lock. Revoked is final for the agent, with one exception kept because the web interface offers it: a person's Reinstate (revoked -> active); a token cannot, and revoked -> suspended is refused (409). |
| `sentinel_task` | `agentapi.SentinelTask.status` | queued, claimed, running, **done**, **failed**, expired | A report is filed only from claimed or running. Expired -> done/failed only through the late-result path (`_adopt_late`), for a task lost or timed out across an update (`LATE_SERVABLE_ERRORS`) whose Sentinel still covers the work; never one a person cancelled or one taken back from a suspended or narrowed Sentinel. Claimed or running goes back to queued only when a Sentinel inside a private network held work that is not internal (`take_back_external`), so an external Sentinel takes it. |
| `stage_run` | `agentapi.StageRun.state` | running, waiting, ready, **done**, **failed** | A pass writes (wait, close) only while the run is still in its round (`rounds`): one that outlived its lease and was taken over by another worker writes nothing. `cancelled` is listed by the model but never written, so it is not in the table. |
| `ai_job` | `cveFeed.AIJob.status` | queued, leased, answered, applying, **applied**, **failed**, **expired** | queued to leased or expired; leased back to queued (lease ran out) or to answered; answered to applying; applying to queued (the stage's one retry), applied or failed. A continuation that ends after the housekeeping pass gave its job up as lost (`apply_lost`) changes nothing, and the lost job's stage is told through its `job_failure` hook. Leasing and taking an answer are made under a row lock that checks the state first. |

## Implicit machines, and what is wrong with them

Found by a survey of the server and the Sentinel client. Each is moved to an explicit table in its own change; the bugs listed are fixed as it moves.

### Scanning

- **Scan status** (`ScanHistory.scan_status`): explicit (above). Fixed while moving it: a Stop during an internal scan or near the end of a
  discovery was overwritten with success or failed; a stage a person stopped was overwritten with its own result; a duplicate delivery of a running
  scan's message replaced its Celery task ids, so the reaper closed the live scan and a Stop revoked the wrong task.
- **Global pause** (`ScanControl.paused`, `paused_by_update`, update window): one flag shared by a person, the updater and the watchdog's
  pressure pause. Fixed: each has its own owner (`scan_control.pause_owner`: person, update, watchdog; the watchdog's is told apart by the reason
  it always starts with, so no schema change). The watchdog's pause (`request_pressure_pause`) opens no update window and holds no Sentinel
  lease, so Sentinel task expiry no longer freezes during a memory or disk pause; each release (`release_update_pause`, `release_pressure_pause`)
  lifts only its own owner's pause; `scans_paused_by_update` and `get_system_status` (`paused_by_update`, and `paused_by`) no longer call a
  watchdog pause an update pause.
- **Stage runs** (`agentapi.StageRun.state`): explicit (above). Fixed while moving it: the close and the wait of a pass that outlived its lease
  overwrote the run another worker had resumed.
- **Queued scans nothing will start.** A host pipeline still queued after 30 minutes, or any scan still queued after 48 hours
  (`CVENGINE_SCAN_QUEUED_HOURS`), is moved to failed with the reason by the stuck job cleanup, only when the broker holds no message for it and no
  open stage run carries it. The row is never deleted ([PIPELINE.md](PIPELINE.md#restarts-and-stuck-jobs)).
- **Host assessments** (`HostAssessment.status`), archive review runs (`queued/running/partial/completed`, where partial means two things).
- `SubScan.status` is dead (never written).

### Sentinels and agents

- **Agent status** (`Agent.status`): explicit (above). Fixed while moving it: registration did a full `save()`, so a suspend or revoke made while
  a Sentinel re-registered was reverted; an administrator's change did a full `save()` over the info and Update now request a heartbeat wrote
  meanwhile; a claim checked a status read before its lock; a token could turn a revoked agent into a suspended one.
- **Sentinel task** (`SentinelTask.status`): explicit (above). Fixed while moving it: a late result moved an expired task (cancelled by a person,
  or its Sentinel suspended or narrowed) back to done without checking why it expired; the report write was blind after its check; every expired
  task was labelled "lost (the Sentinel stopped answering)", suspensions and queue-wait expiries included.
- **Agent task** (`AgentTask.status`): consistent (conditional writes throughout).
- **Sentinel self-update status** (`info.update.status`, `info.auto_update.status`): "updating" can stay forever. (Fixed: "Update now" was
  disabled exactly when Manual mode waits for an admin; a lingering "failed" cleared a fresh Update now request.)
- **Client side** (the Sentinel repository): the spool, task flags and enrollment are consistent. (Server side fixed: a 403 now carries `code`,
  `agent_blocked` or `token_revoked`, so an active Sentinel whose user or token has a problem can be told from a revoked one; the client has to read it.)

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
  is pending (still open). Fixed: the check forgets an approval only when the host reports the deploy finished (phase `done` since the approval;
  `web/.commit` is written when a deploy starts, so it alone made a check after a failed restart delete the approval and stop the retries), and
  audits it (`update.applied`); after a web-side removal (the check, Cancel, a factory reset) a failed phase is shown as the last attempt with its
  time and a drain as idle (`updater.shown_phase`, used by Settings > Updates, the update bar and `get_system_status`), never "The approval is kept
  and retries by itself"; the host removes the approval file only while it still names the commit it applied, so an approval of a newer commit made
  during a deploy is kept.
- **Update phase** (`.update-phase.json`): `failed` is written for refusals that retry; `restarting`/`resuming` are read but never written; a
  phase stays `applying` after a crash.
- **Scanner plan** (`.update-sentinels`): fixed. `apply-update.sh` reads it once per run without removing it and hands it to the deploy steps
  (`CV_UPDATE_SENTINELS`); it is removed with the approval, so a run that waits for work to settle (exit 3) or retries keeps it.
- **AI jobs** (`AIJob.status`): explicit (`ai_job`, above). Fixed: a job lost while applying tells its stage (`job_failure`), and a late
  continuation no longer overwrites the loss.
- **Auto-tuning phase**, **watchdog status**, **OpenVAS add-on switch** (the app never writes the request the host script waits for),
  certificate status (consistent).
