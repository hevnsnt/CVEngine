"""Every explicit lifecycle in cvENGINE, one table each (see :mod:`reNgine.lifecycle` for how they are used).

Add a lifecycle here before code moves rows through it, and change a row only with ``MACHINE.move(queryset, target, ...)``: the move happens
only from a state the table allows, so a late or stale write cannot undo a newer decision. docs/STATE-MACHINES.md lists these and the
lifecycles not yet moved here.
"""
from reNgine.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.lifecycle import Machine, register

QUEUED, FAILED, RUNNING, SUCCESS, ABORTED = INITIATED_TASK, FAILED_TASK, RUNNING_TASK, SUCCESS_TASK, ABORTED_TASK

# A scan (startScan.ScanHistory.scan_status) and each of its stages (startScan.ScanActivity.status, the same codes).
#
# Stopped is final: a person's Stop (agentapi.services._abort_scan) and the global pause (cveFeed.scan_control) end a scan, and nothing
# that finishes afterwards may turn it into a success or a failure. Failed may still become a success: the reaper can mark a scan failed
# that was in fact still running (its Celery task id was lost), and the scan's own finish is the truth; refusing it would leave the hosts
# it found out of the current inventory. A finished scan does not fail later. A finished or failed scan that reports the same again
# refreshes its fields (a pipeline resumed by a StageRun finishes in its last pass).
SCAN = register(Machine(
    'scan', 'scan_status', label='The scan',
    doc='A discovery, host or internal scan of one target, and each of its stages.',
    states={
        QUEUED: ('queued', 'Queued', 'Waiting for a worker or a scanner.'),
        RUNNING: ('running', 'Running', 'A worker is running it (it counts as stalled when it runs longer than any scan can).'),
        SUCCESS: ('success', 'Finished', 'It ran to the end; its hosts are the target\'s current inventory. A stage that failed is named in its error.'),
        FAILED: ('failed', 'Failed', 'It ended without a result; the error says why.'),
        ABORTED: ('aborted', 'Stopped', 'A person or the global pause stopped it. Final: nothing that finishes later changes it.'),
    },
    moves={
        QUEUED: (RUNNING, SUCCESS, FAILED, ABORTED),
        RUNNING: (SUCCESS, FAILED, ABORTED),
        FAILED: (FAILED, SUCCESS),
        SUCCESS: (SUCCESS,),
        ABORTED: (),
    },
    initial=(QUEUED,),
))


# An agent or Sentinel (agentapi.models.Agent.status). A registration creates it pending, active or suspended (agent_broker._initial_status: the
# hold-back rule suspends a user's new agent while another of theirs is suspended or revoked). After that only a person changes it, through
# agent_broker.update_agent (status one of ADMIN_STATUSES; an API token or MCP call may suspend or revoke but never approve or reinstate). The agent
# itself never does: a registration or heartbeat never writes the field. A suspended agent may be suspended again: the decision is then the
# administrator's own instead of the hold-back rule's (status_inherited is cleared).
#
# Revoked is meant to be the end: the agent cannot register, heartbeat, claim or unregister, and only a revoked agent can be deleted. One move out
# of it stays because the web interface offers it today: a person's Reinstate (agents-admin.js, "Agents in your organizations") makes a revoked
# agent active again. A token cannot (update_agent refuses it), and nothing turns a revoked agent into a suspended one.
AGENT_PENDING, AGENT_ACTIVE, AGENT_SUSPENDED, AGENT_REVOKED = 'pending', 'active', 'suspended', 'revoked'
AGENT = register(Machine(
    'agent', 'status', label='The agent',
    doc='An agent or Sentinel registered with this server: whether it may be handed work.',
    states={
        AGENT_PENDING: ('pending', 'Waiting for approval', 'Registered by someone who is not an administrator; no work until an administrator approves it.'),
        AGENT_ACTIVE: ('active', 'Active', 'May take work within its scope, capabilities and limits.'),
        AGENT_SUSPENDED: ('suspended', 'Suspended', 'Takes no new work and holds none; it may still register and heartbeat. A person reinstates it.'),
        AGENT_REVOKED: ('revoked', 'Revoked', 'Refused on every call and can be deleted. Only a person, in the web interface, can reinstate it.'),
    },
    moves={
        AGENT_PENDING: (AGENT_ACTIVE, AGENT_SUSPENDED, AGENT_REVOKED),
        AGENT_ACTIVE: (AGENT_SUSPENDED, AGENT_REVOKED),
        AGENT_SUSPENDED: (AGENT_ACTIVE, AGENT_SUSPENDED, AGENT_REVOKED),
        AGENT_REVOKED: (AGENT_ACTIVE,),  # a person's Reinstate only (see above)
    },
    initial=(AGENT_PENDING, AGENT_ACTIVE, AGENT_SUSPENDED),
))


# A Sentinel's unit of scan-stage work (agentapi.models.SentinelTask.status). Queued until a Sentinel claims it (sentinel_broker._claim), running
# once it accepts, then done or failed by its report. Expired is how every task ends that nobody finished: the dispatcher's wait ran out, the reaper
# found its lease lapsed, a person cancelled it, its Sentinel was suspended or no longer covers it (sentinel_broker.expire, cancel_task). A report is
# filed only from claimed or running, so a task that expired between the report's check and its write stays expired. Expired becomes done or failed
# only through the late-result path (sentinel_broker._adopt_late): a result the Sentinel held across an update, for a task that expired because it
# was lost or timed out (LATE_SERVABLE_ERRORS), never one a person cancelled or one taken back from a Sentinel suspended or narrowed since.
TASK_QUEUED, TASK_CLAIMED, TASK_RUNNING, TASK_DONE, TASK_FAILED, TASK_EXPIRED = 'queued', 'claimed', 'running', 'done', 'failed', 'expired'
SENTINEL_TASK = register(Machine(
    'sentinel_task', 'status', label='The Sentinel task',
    doc='One unit of scan-stage work handed to a Sentinel.',
    states={
        TASK_QUEUED: ('queued', 'Queued', 'Waiting for a Sentinel to claim it.'),
        TASK_CLAIMED: ('claimed', 'Claimed', 'Leased to a Sentinel that has not accepted it yet.'),
        TASK_RUNNING: ('running', 'Running', 'The Sentinel accepted it and keeps its lease with heartbeats.'),
        TASK_DONE: ('done', 'Done', 'The Sentinel reported a result and it was filed.'),
        TASK_FAILED: ('failed', 'Failed', 'The Sentinel reported an error, or its result was rejected or dropped; the error says why.'),
        TASK_EXPIRED: ('expired', 'Expired', 'Nobody finished it: not taken in time, lost, cancelled or taken back (the error says which). '
                                             'Only a late result for a lost task can still be filed.'),
    },
    moves={
        TASK_QUEUED: (TASK_CLAIMED, TASK_EXPIRED),
        TASK_CLAIMED: (TASK_RUNNING, TASK_DONE, TASK_FAILED, TASK_EXPIRED),
        TASK_RUNNING: (TASK_DONE, TASK_FAILED, TASK_EXPIRED),
        TASK_EXPIRED: (TASK_DONE, TASK_FAILED),  # the late-result adoption path only (see above)
        TASK_DONE: (),
        TASK_FAILED: (),
    },
    initial=(TASK_QUEUED,),
))


# A scan stage that handed its work to Sentinels and gave its worker back (agentapi.models.StageRun.state, agentapi.stage_runs). A pass runs it
# (running, its lease renewed while it works), then it waits for its tasks (waiting), is woken when they end (ready) and resumed by the next pass
# (running again, ``rounds`` + 1), until a pass ends it done or failed. A pass that outlives its lease is taken back by the tick (running -> ready)
# and resumed by another worker; the old pass then writes nothing: its close and its wait are conditional on the run still being in the round it
# started in, so it cannot overwrite the newer pass. The pass that still owns its round may end or park the run from ready (the tick took its
# lease back but nobody resumed it yet).
#
# The model also lists ``cancelled`` (StageRun.STATES, and prune deletes such rows), but nothing writes it, so it is not in this table.
RUN_RUNNING, RUN_WAITING, RUN_READY, RUN_DONE, RUN_FAILED = 'running', 'waiting', 'ready', 'done', 'failed'
STAGE_RUN = register(Machine(
    'stage_run', 'state', label='The stage run',
    doc='A scan stage that waits on Sentinels without holding a worker.',
    states={
        RUN_RUNNING: ('running', 'Running', 'A worker runs a pass of the stage and keeps its lease.'),
        RUN_WAITING: ('waiting', 'Waiting', 'No worker: Sentinels hold its tasks.'),
        RUN_READY: ('ready', 'Ready', 'Every task it waited on ended; its callback is queued.'),
        RUN_DONE: ('done', 'Done', 'The stage finished.'),
        RUN_FAILED: ('failed', 'Failed', 'The stage ended with an error; the error says why.'),
    },
    moves={
        RUN_RUNNING: (RUN_WAITING, RUN_READY, RUN_DONE, RUN_FAILED),
        RUN_WAITING: (RUN_READY,),
        RUN_READY: (RUN_RUNNING, RUN_WAITING, RUN_DONE, RUN_FAILED),
        RUN_DONE: (),
        RUN_FAILED: (),
    },
    initial=(RUN_RUNNING, RUN_WAITING),
))
