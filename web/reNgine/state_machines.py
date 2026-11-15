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


# An AI job (cveFeed.AIJob.status): one model call the AI reviewer container makes for a pipeline stage (cveFeed.ai_jobs).
#
# The container leases a queued job and answers it; a Celery task applies the answer (or queues the stage's one retry). Applied, failed and
# expired are final: a continuation that finishes after the housekeeping pass gave its job up as lost (``apply_lost``) does not turn it back
# into applied, and the stage is told of the loss through its ``job_failure`` hook. Leasing a job and taking its answer are made under a row
# lock (``select_for_update``) that checks the state first; every other move goes through this table.
AI_QUEUED, AI_LEASED, AI_ANSWERED, AI_APPLYING = 'queued', 'leased', 'answered', 'applying'
AI_APPLIED, AI_FAILED, AI_EXPIRED = 'applied', 'failed', 'expired'
AI_JOB = register(Machine(
    'ai_job', 'status', label='The AI job',
    doc='One model call the AI reviewer container makes for a pipeline stage (triage, template writing, host reviews...).',
    states={
        AI_QUEUED: ('queued', 'Queued', 'Waiting for the AI reviewer container to take it.'),
        AI_LEASED: ('leased', 'Taken', 'The container holds it for a while and is asking the model; a lease that runs out puts it back.'),
        AI_ANSWERED: ('answered', 'Answered', 'The answer (or the failure) is in; its stage has not used it yet.'),
        AI_APPLYING: ('applying', 'Applying', 'Its stage is using the answer now.'),
        AI_APPLIED: ('applied', 'Applied', 'Its stage used the answer. Final.'),
        AI_FAILED: ('failed', 'Failed', 'The model call failed, the answer could not be used, or its continuation was lost; the stage was told. Final.'),
        AI_EXPIRED: ('expired', 'Expired', 'Never answered in time, or dropped before it was asked; the stage was told. Final.'),
    },
    moves={
        AI_QUEUED: (AI_LEASED, AI_EXPIRED),
        AI_LEASED: (AI_QUEUED, AI_ANSWERED),
        AI_ANSWERED: (AI_APPLYING,),
        AI_APPLYING: (AI_QUEUED, AI_APPLIED, AI_FAILED),
        AI_APPLIED: (),
        AI_FAILED: (),
        AI_EXPIRED: (),
    },
    initial=(AI_QUEUED,),
))
