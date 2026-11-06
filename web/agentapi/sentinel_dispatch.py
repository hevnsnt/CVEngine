"""Dispatch-or-local: the one branch the scan pipeline takes before it runs nmap, naabu, nuclei or testssl.sh itself.

For each of the stages this phase covers, the pipeline asks here first: is there a live, eligible Sentinel for this
project with free capacity and the right capability? If not (the common case today: a project with no Sentinels
registered), every function below is a no-op and returns at once, so the pipeline runs exactly as it did before this
module existed - that is the single most important property here, and it is what the regression test in
``tests.test_sentinel_dispatch`` proves. If there is one, a ``SentinelTask`` is created and this module waits for it to
finish, under two different budgets: a short claim timeout (``_claim_timeout``, default 8s) for any Sentinel to even pick
the task up, and only once one has, the much longer completion timeout (``_dispatch_timeout``, default 90s) for it to
finish the work. A Sentinel with a free slot almost always claims it within its own poll interval, so one that is quiet or
offline costs a scan stage single-digit seconds, not the full completion budget, before falling back locally - while a
Sentinel that did pick the work up keeps the full budget (counted from when it claimed the task, not from when it was
created) to actually run it. **A Sentinel at its concurrency limit is not a missing one**: when every live, eligible Sentinel
is busy the task waits in the queue for a slot, under its own wait budget (``_queue_timeout``) separate from both, and the stage
falls back only when that runs out or the last live Sentinel goes away. On success its typed, clipped result is parsed into the *same shape* the local tool's own output already
takes and handed to the *same persistence function* local execution uses (``cveFeed.nmap_scan.persist_inventory``,
``cveFeed.naabu_scan.persist_open_ports``, or - for nuclei - a reconstructed result line fed through the untouched
``cveFeed.nuclei_scan._run_nuclei`` loop via its own ``stream`` seam). On timeout, failure or no Sentinel, the caller falls
back to running the tool locally, exactly as today; the subprocess-running code itself (``nmap_scan.run_nmap_xml``,
``naabu_scan.run_naabu``, ``nuclei_scan.stream_nuclei``) is never touched by this module.

A stage that splits into several chunk tasks (nmap and naabu: 64 addresses each, nuclei: 64 targets each) sends them side by side
through ``dispatch_many``: a bounded window of chunk tasks, created up front and waited for in one poll loop, refilled as chunks finish
(``CVENGINE_STAGE_PARALLEL``, default 4; ``1`` is the serial loop of before). Each chunk is still one task for one Sentinel, with the
single-task wait above and its own fallback to local execution.
"""
import contextlib
import ipaddress
import logging
import os
import tempfile
import time

MAX_ADDRESSES = 64  # kept equal to sentinel_broker.MAX_ADDRESSES: the most addresses one dispatched task names (a longer list goes in several)
DISPATCH_POLL_INTERVAL = 0.5  # seconds between checks while waiting for a dispatched task to finish
RESOLVE_WORKERS = 16  # matches targetApp.target_types.blocked_names: one bounded parallel pass, never one lookup per target serially
RESOLVE_TIMEOUT = 5  # seconds one target's lookup may take


# The longest a stage waits for a Sentinel that has claimed its task, by kind: a Sentinel that keeps heartbeating a running task is
# doing the work, and a slow tool (nuclei over ten hosts, a full TLS audit) must not be run a second time locally because a short fixed
# wall clock ran out. A Sentinel that stops heartbeating loses its lease on its own (``sentinel_broker.reap_expired``, five minutes) and
# the wait ends then, so the ceiling only bounds a Sentinel that is alive but never finishes. Every kind is here except those in
# ``scanner_state.NO_STAGE`` (no stage waits for them yet), which ``tests.test_sentinel_contract`` holds to.
COMPLETION_CEILING = {'nmap': 900, 'naabu': 600, 'nuclei_light': 900, 'nuclei_targeted': 1800, 'nuclei_deep': 3600, 'testssl': 600,
                      'nmap_udp': 900, 'wpscan': 1800, 'openvas': 3600, 'discover': 1200, 'waf': 300, 'http_probe': 1500, 'dns_resolve': 300,
                      'secrets_scan': 1800, 'nmap_full': 1800, 'nmap_verify': 300, 'node2shell': 600, 'rdp_shot': 180, 'db_probe': 120, 'path_probe': 300,
                      'nuclei_validate': 600, 'alive_check': 900, 'bucket_check': 1800, 'vhost_probe': 1800, 'subdir_probe': 1800, 'supplier_check': 1800, 'hygiene_check': 1800, 'dangling_dns_check': 900, 'route_probe': 1800, 'identity_check': 300,
                      'bbot_discovery': 6 * 3600 + 600}  # a streamed run: its own time limit (the target's timeout_seconds) decides, see sentinel_stream
DEFAULT_CEILING = 900
# Added to a kind's ceiling for each target beyond the first (an address of a chunk, a nuclei target): a chunk of 64 addresses takes longer than one.
# Only the kinds that take a chunk of targets are listed; any other adds nothing.
PER_TARGET_SECONDS = {'nmap': 15, 'naabu': 10, 'nuclei_light': 20, 'nuclei_targeted': 30, 'nuclei_deep': 60, 'nuclei_validate': 15}
DEFAULT_QUEUE_SECONDS = 300  # how long a stage waits for a free Sentinel slot when every live, eligible Sentinel is at its limit
REAP_EVERY = 10  # seconds between checks for a Sentinel whose lease ran out while a stage waits


logger = logging.getLogger(__name__)

LOCAL_FALLBACK_ENV = 'CVENGINE_LOCAL_FALLBACK'
NEVER_LOCAL = (  # kinds with no local path at all: whatever CVENGINE_LOCAL_FALLBACK says, they wait for a scanner (docs/SECRETS-PLAN.md 6.1)
    'secrets_scan',
    'bbot_discovery',
    'rdp_shot',
    'db_probe',  # the credential-less database attempts: a Sentinel's, this server carries no database client
    'bucket_check',  # the storage requests: a Sentinel's, the server carries only the readers of what comes back
    'node2shell',  # the Brotli decoder check: the detector is vendored on the scanner only, this server carries no copy of it
    'dns_resolve',  # the discovery and retire-check name lookups (agentapi.probe_dispatch.try_dns_resolve): a Sentinel's resolver, never this server's
    'alive_check',  # the retire check's web and connect checks of a vanished name's last address (cveFeed.changes._remote_alive)
    'identity_check',  # name and certificate reads (cveFeed.hosting, domain_ownership, discovery.identity_names): a Sentinel's resolver, never this server's
)
_WARNED_FALLBACK = set()  # the distinct values of CVENGINE_LOCAL_FALLBACK already warned about in this process
# The kinds the built-in scanner runs, and so the kinds that never run on this server by default (``CVENGINE_LOCAL_FALLBACK`` unset). A kind is added
# here in the change that teaches the built-in scanner to run it (its client declares it and a stage dispatches it), never before: a kind listed here
# that no scanner runs would only wait. ``openvas`` (the server's own sidecar runs it, and the built-in scanner has none), ``discover`` (internal
# ranges, Sentinel-only already) and ``waf`` (no stage dispatches it yet) are not.
BUILTIN_SCANNER_KINDS = ('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan')


def builtin_scanner_enrolled():
    """Whether the built-in scanner is switched on and has enrolled at least once (one indexed query). Until it has, nothing waits for it: a host whose
    scanner image could not be pulled, or that has no App Admin yet, goes on scanning here as it always did."""
    from agentapi import builtin_scanner
    if not builtin_scanner.enabled():
        return False
    try:
        from agentapi.models import SentinelEnrollment
        return SentinelEnrollment.objects.filter(builtin=True, used_by_agent__isnull=False).exists()
    except Exception:  # noqa: BLE001 - a database that cannot be read: the scan that asks fails on its own, and nothing is held back here
        return False


def default_fallback_kinds():
    """The kinds that may run here when ``CVENGINE_LOCAL_FALLBACK`` is unset: every kind but the built-in scanner's (``BUILTIN_SCANNER_KINDS``) once the
    built-in scanner is on and has enrolled, so every scan of those goes through a scanner and a scanner restart only makes the work wait; every kind
    while it is off or has never enrolled."""
    from agentapi.models import SentinelTask
    if builtin_scanner_enrolled():
        return {k for k in SentinelTask.KINDS if k not in BUILTIN_SCANNER_KINDS}
    return set(SentinelTask.KINDS)


def _parse_local_fallback():
    """``(allowed, unknown)``: the kinds ``CVENGINE_LOCAL_FALLBACK`` lets run here, and the names in it that are no kind. An unknown name is ignored (a
    typo reads as ``none`` for that kind), but never silently: it is warned about once per process and shown in the scanner status. Unset, it is
    ``default_fallback_kinds()``; ``all`` is the escape hatch that lets every kind run here again."""
    from agentapi.models import SentinelTask
    raw = os.environ.get(LOCAL_FALLBACK_ENV, '').strip().lower()
    if raw == '':
        return default_fallback_kinds() - set(NEVER_LOCAL), []
    if raw in ('all', '*'):
        return set(SentinelTask.KINDS) - set(NEVER_LOCAL), []
    if raw == 'none':
        return set(), []
    names = [k.strip() for k in raw.split(',') if k.strip()]
    unknown = [k for k in dict.fromkeys(names) if k not in SentinelTask.KINDS]
    if unknown and raw not in _WARNED_FALLBACK:
        _WARNED_FALLBACK.add(raw)
        logger.warning('%s names kinds that do not exist and are ignored: %s (valid: %s)', LOCAL_FALLBACK_ENV, ', '.join(unknown),
                       ', '.join(SentinelTask.KINDS))
    return {k for k in names if k in SentinelTask.KINDS and k not in NEVER_LOCAL}, unknown


def local_fallback_kinds():
    """The task kinds that may still run on this server when no Sentinel can take them: ``CVENGINE_LOCAL_FALLBACK`` is unset (every kind but the built-in
    scanner's once it has enrolled, ``default_fallback_kinds``), ``all`` (every kind, how 1.3 worked), ``none``, or a comma list of kinds. This is the switch of the move to one scanner (docs/SCANNER-ARCHITECTURE.md): a kind
    taken off the list is never run here again, and a stage that needs it waits for a scanner (``resources.ScannerUnavailable``) instead. A name in
    the list that is no kind is ignored (see ``unknown_fallback_kinds``)."""
    return _parse_local_fallback()[0]


def unknown_fallback_kinds():
    """The names in ``CVENGINE_LOCAL_FALLBACK`` that are not task kinds (in the order written, each once): empty when it is unset, ``all`` or ``none``."""
    return _parse_local_fallback()[1]


def fallback_allowed(kind):
    return kind in local_fallback_kinds()


STAY_DUE = 'the targets stay due until a scanner can take the work'


def outcome_text(kind):
    """How a task that nobody finished ends, in words that are true for the kind's policy: the stage ran it here when ``kind`` may fall back,
    or (it never ran here) the targets stay due until a scanner can take the work."""
    return 'the stage fell back to local execution' if fallback_allowed(kind) else STAY_DUE


def _no_local(kind, why, reason='no_scanner', project=None, recorded=None):
    """Where a stage would run ``kind`` here because no Sentinel took it: ``ScannerUnavailable`` when it may not; when it may, nothing happens to the
    work except one row of fallback telemetry (``scanner_fallback.record``: kind, project, ``reason``; it cannot raise) and the caller runs it here.
    This is the one place the decision "no Sentinel took it, the local run is allowed" is made.

    Inside a ``StageRun`` the stage code runs again on every pass (``agentapi.stage_runs``), so a decision is recorded once: ``recorded`` is True for
    one an earlier pass already recorded (a task's own, ``_Dispatch.no_local``), and a decision with no task is matched to the earlier passes by its
    place in the pass (``Pass.fallback_seen``)."""
    if not fallback_allowed(kind):
        from cveFeed import scanner_wait
        from reNgine.resources import ScannerUnavailable
        scanner_wait.noted(kind)  # the scan running in this context waited for ``kind``: its hosts are queued again for when a scanner is back
        raise ScannerUnavailable(kind, why)
    if recorded:
        return
    if recorded is None:
        from agentapi import stage_runs
        run = stage_runs.current()
        if run is not None and run.fallback_seen((kind, reason)):
            return
    from agentapi import scanner_fallback
    scanner_fallback.record(kind, project, reason)


def _no_scanner(kind, project, capacity=None):
    """``_no_local`` for a stage that found no live, eligible Sentinel for ``kind`` in ``project``, saying why: ``OpenVAS is not enabled on any live Sentinel
    (off on CVEngine Scanner; Remote-1 has it but is offline)`` rather than a bare "no Sentinel is live". ``capacity`` is the ``capacity_state(..., why=True)``
    the caller already has. The telemetry reason is ``disabled_everywhere`` when a live Sentinel has the kind and an administrator's (or its machine's)
    policy keeps it off every one, and ``no_scanner`` for every other reason (nothing live, nothing ever declared it)."""
    from agentapi import sentinel_broker
    if capacity is None or 'reason' not in capacity:
        capacity = sentinel_broker.capacity_state(project, kind, why=True)
    reason = 'disabled_everywhere' if capacity.get('reason') == 'disabled' else 'no_scanner'
    _no_local(kind, capacity.get('message') or 'no Sentinel is live for this project', reason, project)


def _dispatch_timeout(kind=None, targets=0):
    """Seconds a stage waits for a dispatched Sentinel task to *finish* once a Sentinel has claimed it, before falling back to running
    the tool locally: ``COMPLETION_CEILING`` for the kind, plus ``PER_TARGET_SECONDS`` for each target beyond the first (so a chunk of many
    addresses is not held to the budget of one), and for OpenVAS the instance's own ``CVENGINE_OPENVAS_MAX_HOURS``.
    ``CVENGINE_SENTINEL_DISPATCH_TIMEOUT``, when set, replaces every ceiling with that one number (an operator who wants scans never to wait
    long, and the tests)."""
    raw = os.environ.get('CVENGINE_SENTINEL_DISPATCH_TIMEOUT')
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    if kind == 'openvas':
        from cveFeed import openvas_scan
        return openvas_scan.max_hours() * 3600 + 600  # the task's own deadline, plus time to report
    base = COMPLETION_CEILING.get(kind, DEFAULT_CEILING)
    return base + PER_TARGET_SECONDS.get(kind, 0) * max(0, int(targets or 0) - 1)


def _queue_timeout(kind=None):
    """CVENGINE_SENTINEL_QUEUE_TIMEOUT: seconds a stage waits for a free slot when every live, eligible Sentinel is at its concurrency limit (default
    300), before the work runs locally instead. It starts when the task is created and is separate from the claim budget (a Sentinel with a free
    slot) and the completion budget (counted from the claim)."""
    try:
        return max(1, int(os.environ.get('CVENGINE_SENTINEL_QUEUE_TIMEOUT', str(DEFAULT_QUEUE_SECONDS))))
    except ValueError:
        return DEFAULT_QUEUE_SECONDS


def budgets():
    """The dispatch budgets as one object, for the Sentinels page: what each wait is, in seconds."""
    return {'claim_seconds': _claim_timeout(), 'queue_seconds': _queue_timeout(),
            'completion_seconds': {kind: _dispatch_timeout(kind) for kind in COMPLETION_CEILING},
            'per_target_seconds': dict(PER_TARGET_SECONDS), 'lease_seconds': int(_run_lease_seconds())}


def _run_lease_seconds():
    from agentapi import sentinel_broker
    return sentinel_broker.RUN_LEASE.total_seconds()


def _claim_timeout():
    """CVENGINE_SENTINEL_CLAIM_TIMEOUT: seconds a stage waits for *any* Sentinel to even claim a dispatched task before
    giving up on it and falling back to local execution, separate from (and much shorter than) the full completion
    timeout above. A Sentinel that polls ``next_task`` at all almost always claims new work within its own poll
    interval, so a task that is still ``queued`` after this short window is one no eligible Sentinel is going to pick
    up right now (it went offline, hit its concurrency cap, or was never really eligible) - there is no reason to make
    every scan stage eat the full completion timeout just to find that out. Once a Sentinel has claimed the task, this
    no longer applies: the work has already left this process, so the stage keeps waiting up to the completion timeout
    regardless of how long the Sentinel takes to run it. Default 8s."""
    try:
        return max(1, int(os.environ.get('CVENGINE_SENTINEL_CLAIM_TIMEOUT', '8')))
    except ValueError:
        return 8


def any_scanner_for(project, kind, internal=False):
    from agentapi import sentinel_broker
    return sentinel_broker.any_scanner_for(project, kind, internal)


def offline_fallback(project, kind, internal=False):
    """Whether a stage of ``kind`` runs here although ``project`` has a Sentinel for it, because every such Sentinel is offline (called once
    no live one was found). Such a run is a local fallback like a task nobody claimed: it is counted for the warning
    (``cveFeed.local_egress.note_fallback``), and the nmap and naabu stages put it under their hourly cap. A project that never had a Sentinel
    for ``kind`` runs here as its normal mode: never counted, never capped. Never raises."""
    from agentapi import sentinel_broker
    try:
        configured = bool(sentinel_broker.eligible_sentinels(project, kind, internal=internal))
    except Exception:  # noqa: BLE001 - bookkeeping never changes where a stage runs
        return False
    if configured:
        from cveFeed.local_egress import note_fallback
        note_fallback(kind, getattr(project, 'pk', project))
    return configured


def _label(host, ips):
    host = (host or '').strip()
    if host:
        return host
    n = len(ips or [])
    return f'{n} address{"es" if n != 1 else ""}' if n else 'its target'


TERMINAL = ('done', 'failed', 'expired')
STAGE_KINDS = ('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep')  # the kinds a stage splits into chunk tasks (and so fans out)
DEFAULT_STAGE_PARALLEL = 4  # CVENGINE_STAGE_PARALLEL: the most chunk tasks one stage keeps in flight at once
REFILL_EVERY = 5  # seconds between looks for a Sentinel slot that freed up while a stage still has chunks to send
STOP_CHECK_EVERY = 2  # seconds between checks, while a fanned-out stage waits, for a stop or a global pause


_REAL_SLEEP = time.sleep


def _woken_by_redis():
    """Whether a wait here blocks on the Redis wake-up (``sentinel_notify``) rather than sleeping. Only with the real clock: a test, or the fake
    scanner (``tests.fake_scanner``), that drives the loop through its own ``time`` keeps its sleeps."""
    if time.sleep is not _REAL_SLEEP:
        return False
    from agentapi import sentinel_notify
    return sentinel_notify.client() is not None


def _poll_interval():
    """How long a wait sleeps before it looks again by itself: half a second when it polls, the safety interval
    (``CVENGINE_SENTINEL_WAKE_POLL_SECONDS``) when a Redis wake-up ends it as soon as a task changes."""
    if _woken_by_redis():
        from agentapi import sentinel_notify
        return float(sentinel_notify.safety_seconds())
    return DISPATCH_POLL_INTERVAL


def _wait(task_ids, seconds):
    """Wait up to ``seconds`` for one of ``task_ids`` to be claimed or to end: a ``BLPOP`` on their wake keys (``sentinel_notify``) with the real
    clock and Redis, else a plain sleep, as before."""
    if _woken_by_redis():
        if seconds > 0:
            from agentapi import sentinel_notify
            sentinel_notify.wait_tasks(task_ids, seconds, sleep=time.sleep)
        return
    time.sleep(max(0.0, seconds))


def stage_parallel():
    """CVENGINE_STAGE_PARALLEL: the hard ceiling on how many chunk tasks one scan stage keeps in flight across Sentinel slots (default 4).
    ``1`` is the serial behaviour of before this existed: one chunk task at a time, each waited for before the next is created. What an App Admin
    saved on Settings, configMaxxing wins over the environment and is read on every call (``cveFeed.tunables``)."""
    from cveFeed import tunables
    return max(1, int(tunables.value('stage_parallel', DEFAULT_STAGE_PARALLEL)))


class _Dispatch:
    """One dispatched SentinelTask and its wait: the state ``dispatch_or_none`` keeps for a single task, as an object, so a stage that sends
    several chunks at once (``dispatch_many``) can wait for all of them in one loop. ``step`` is one look at a freshly read task row."""

    def __init__(self, project, kind, target, host, ips, scan, timeout, created_by, priority, internal, capacity, label=None, siblings=None,
                 secret_ref=None):
        from agentapi.models import SentinelTask
        from cveFeed import activity
        self.project, self.kind, self.scan, self.internal = project, kind, scan, internal
        self.builtin_only = bool(secret_ref)  # signed-in work: only the built-in scanner's slots count, and only it may take the task
        self.siblings = siblings  # a callable for a fanned-out chunk: the other chunk tasks of the same stage, which a slot of this one's waits on
        targets = len(ips or []) or len((target or {}).get('targets') or (target or {}).get('hosts') or []) if isinstance(target, dict) else len(ips or [])
        self.timeout = _dispatch_timeout(kind, targets) if timeout is None else timeout
        self.task = SentinelTask.objects.create(project=project, scan=scan, kind=kind, target=target, host=(host or '')[:500],
                                                ips=list(ips or [])[:MAX_ADDRESSES], priority=priority, created_by=created_by,
                                                secret_ref=secret_ref)  # set at creation: a task that names a secret is never offered to another Sentinel
        self.label = label or _label(host, ips)
        self.busy = capacity['state'] == 'busy'
        self.entry = activity.log('run_check', (f'Queued {kind} work for {self.label}: all {capacity["slots"]} Sentinel slot(s) are in use, waiting for one'
                                                if self.busy else f'Handed {kind} work for {self.label} to a Sentinel'),
                                  project=project, status='running', scan_id=getattr(scan, 'id', None), sentinel_task_id=self.task.pk,
                                  trace_id=self.task.trace_id)
        self.started = time.monotonic()
        self.queue_budget = _queue_timeout(kind)
        self.claim_deadline = self.started + (self.queue_budget if self.busy else min(_claim_timeout(), self.timeout))
        self.run_deadline = None  # set once a Sentinel holds the task: the completion budget counts from the claim, not from the queueing
        self.never_claimed = False
        self.vanished = False  # the last live Sentinel went away while the task waited
        self.stop_check = False  # a fanned-out chunk: a stop of its scan (or a pause) cancels it while it waits

    @property
    def finished(self):
        return self.task.status in TERMINAL

    # --- a wait written down (agentapi.stage_runs): the budgets as wall-clock times, so another worker can keep them --------------------

    def state(self, key=None):
        """This wait as JSON, for a ``StageRun`` (``stage_runs``): what ``restore`` needs to go on keeping its budgets in another worker."""
        mono, wall = time.monotonic(), time.time()

        def at(value):
            return None if value is None else round(wall + (value - mono), 3)
        return {'key': key, 'id': self.task.pk, 'kind': self.kind, 'project_id': getattr(self.project, 'pk', self.project),
                'scan_id': getattr(self.scan, 'pk', None), 'internal': bool(self.internal), 'busy': self.busy, 'timeout': self.timeout,
                'label': self.label, 'entry': getattr(self.entry, 'pk', None), 'started': at(self.started), 'queue_budget': self.queue_budget,
                'claim_deadline': at(self.claim_deadline), 'run_deadline': at(self.run_deadline), 'never_claimed': self.never_claimed,
                'vanished': self.vanished, 'stop_check': bool(getattr(self, 'stop_check', False))}

    @classmethod
    def restore(cls, state, siblings=None):
        """The wait ``state`` describes, with its task read afresh (``None`` when the row is gone). A task a Sentinel claimed whose completion
        clock had not started yet gets it from the time of the claim."""
        from agentapi.models import SentinelTask
        from cveFeed.models import AgentActivity
        task = SentinelTask._base_manager.filter(pk=state.get('id')).select_related('project', 'agent', 'scan').first()
        if task is None:
            return None
        mono, wall = time.monotonic(), time.time()

        def back(value):
            return None if value is None else mono + (float(value) - wall)
        self = cls.__new__(cls)
        self.task, self.kind, self.project, self.scan = task, state.get('kind') or task.kind, task.project, task.scan
        self.internal, self.busy, self.timeout = bool(state.get('internal')), bool(state.get('busy')), state.get('timeout') or _dispatch_timeout(task.kind)
        self.builtin_only = bool(task.secret_ref)  # signed-in work, read from the row it was created with: a restored wait counts the same slots
        self.label = state.get('label') or _label(task.host, task.ips)
        self.entry = AgentActivity.objects.filter(pk=state['entry']).first() if state.get('entry') else None
        self.started = back(state.get('started')) or mono
        self.queue_budget = state.get('queue_budget') or _queue_timeout(task.kind)
        self.claim_deadline = back(state.get('claim_deadline')) or mono
        self.run_deadline = back(state.get('run_deadline'))
        if self.run_deadline is None and task.status in ('claimed', 'running') and task.claimed_at is not None:
            self.run_deadline = back(task.claimed_at.timestamp()) + self.timeout
        self.never_claimed, self.vanished = bool(state.get('never_claimed')), bool(state.get('vanished'))
        self.siblings, self.stop_check = siblings, bool(state.get('stop_check'))
        return self

    def _fell_back(self):
        """Count one task that falls back to local execution (``cveFeed.local_egress.note_fallback``: the warning when it keeps happening). Nothing
        is counted for internal work (it never had a local run) or for a kind ``CVENGINE_LOCAL_FALLBACK`` keeps off this server (it stays due)."""
        if self.internal or not fallback_allowed(self.kind):
            return
        try:
            from cveFeed.local_egress import note_fallback
            note_fallback(self.kind, getattr(self.project, 'pk', self.project))
        except Exception:  # noqa: BLE001 - bookkeeping never changes the dispatch
            pass

    def step(self, now, no_sentinel_left=False):
        """Act on the task as it was just read: start the completion clock once it is claimed, and give it up (expire it, so the stage falls back)
        when the wait for a Sentinel or for its report ran out. Returns True once the task is over. ``no_sentinel_left`` is set by the loop
        after a reap that found no live, eligible Sentinel any more."""
        from agentapi import sentinel_broker
        task = self.task
        if task.status in TERMINAL:
            return True
        if no_sentinel_left and task.status == 'queued':
            self.never_claimed = self.vanished = True  # the last live Sentinel went away while the task waited: nothing will take it
            sentinel_broker.expire(task, f'no live Sentinel is left to take the task; {outcome_text(self.kind)}')
            self._fell_back()
            return True
        if task.status in ('claimed', 'running') and self.run_deadline is None:
            self.run_deadline = now + self.timeout
        if task.status == 'queued' and now >= self.claim_deadline:
            others = [t.pk for t in self.siblings()] if self.siblings else []
            if (not self.busy and now < self.started + self.queue_budget
                    and sentinel_broker.capacity_state(self.project, self.kind, self.internal, exclude=[task.pk, *others],
                                                       builtin_only=self.builtin_only, secret=self.builtin_only)['state'] == 'busy'):
                self.busy, self.claim_deadline = True, self.started + self.queue_budget  # another stage took the free slot first: wait for the next one
                return False
            hold = self._sibling_hold()
            if hold:
                self.claim_deadline = now + hold  # waiting behind its own stage's chunks, which are being worked: not a reason to run it here
                return False
            self.never_claimed = True
            sentinel_broker.expire(task, (f'no Sentinel slot freed up in time; {outcome_text(self.kind)}' if self.busy
                                          else f'no Sentinel claimed the task in time; {outcome_text(self.kind)}'))
            self._fell_back()
            return True
        if self.run_deadline is not None and now >= self.run_deadline:
            sentinel_broker.expire(task, f'the dispatch wait timed out; {outcome_text(self.kind)}')
            self._fell_back()
            return True
        return False

    def _sibling_hold(self):
        """Seconds this queued chunk task may keep waiting because the slots are held by other chunk tasks of its own stage that a Sentinel has
        claimed (they finish and free a slot), or 0 to give it up. A safety net, since the window is sized to the free slots and a stage normally
        has no chunk queued behind its own: never beyond the age at which the reaper would expire a queued task (``queued_ttl``, less two reap
        intervals), so this loop expires it, and says why, before the reaper does."""
        if not self.siblings or not any(t.status in ('claimed', 'running') for t in self.siblings()):
            return 0
        from agentapi import sentinel_broker
        from django.utils import timezone
        age = (timezone.now() - self.task.created_at).total_seconds()
        return max(0, min(self.queue_budget, sentinel_broker.queued_ttl(self.kind).total_seconds() - 2 * REAP_EVERY - age))

    def pause(self, now, interval=DISPATCH_POLL_INTERVAL):
        """Seconds to wait before the next look: ``interval`` (a plain sleep polls every half second; a wait woken through Redis passes
        ``_poll_interval()``), or less when a budget ends sooner."""
        horizon = self.run_deadline if self.run_deadline is not None else self.claim_deadline
        return min(interval, max(0.0, horizon - now))

    def settle(self):
        """Close the activity line of the task that is over, saying what became of it."""
        from cveFeed import activity
        task, kind, label, busy = self.task, self.kind, self.label, self.busy
        sentinel = task.agent.name if task.agent_id else None
        if task.status == 'done':
            activity.settle(self.entry, 'done', message=f'Sentinel {sentinel} checked in {kind} work for {label}' if sentinel
                            else f'A Sentinel checked in {kind} work for {label}', trace_id=task.trace_id)
        elif task.status == 'failed':
            reason = (task.error or (task.result or {}).get('error') or 'no reason given')[:180]
            activity.settle(self.entry, 'failed', message=(f'Sentinel {sentinel} reported {kind} failed for {label}: {reason}' if sentinel
                            else f'A Sentinel reported {kind} failed for {label}: {reason}'), trace_id=task.trace_id)
        else:  # no Sentinel took it, or one did and never reported back: the ending is true for the kind's policy (it ran here, or the targets stay due)
            ending = 'it ran locally instead' if fallback_allowed(kind) else STAY_DUE
            if self.never_claimed:
                activity.settle(self.entry, 'expired', message=(f'No Sentinel slot freed up for {kind} work for {label} in time; {ending}' if busy
                                                                else f'No Sentinel picked up {kind} work for {label} in time; {ending}'),
                                trace_id=task.trace_id)
            else:  # claimed, but not reported back before the completion timeout
                activity.settle(self.entry, 'expired', message=f'No Sentinel checked in {kind} work for {label} in time; {ending}',
                                trace_id=task.trace_id)

    def fallback_reason(self):
        """The fallback telemetry reason (``scanner_fallback.REASONS``) for a task that is over and did not come back done."""
        if self.task.status == 'failed':
            return 'failed_then_local'
        if self.vanished:
            return 'no_scanner'
        if self.never_claimed:
            return 'slot_busy' if self.busy else 'not_claimed_in_time'
        return 'completion_timeout'

    def no_local(self):
        """``_no_local`` for this task once it is over and did not come back done (nothing for one that did, or for internal work, which never had a
        local run to fall back to): ``ScannerUnavailable`` when the kind may not run here, one row of fallback telemetry when it may."""
        task = self.task
        if task.status == 'done' or self.internal:
            return
        from agentapi import stage_runs
        run = stage_runs.current()
        recorded = run.counted(self) if run is not None else None
        _no_local(self.kind, f'the {"queue" if self.never_claimed else "Sentinel"} did not return a result in time' if task.status != 'failed'
                  else f'the Sentinel reported it failed: {(task.error or "no reason given")[:120]}', self.fallback_reason(), self.project,
                  recorded=recorded)
        if run is not None:
            run.mark_counted(self)

    def cancel(self, reason):
        """Hand the task back unfinished (the stage was stopped, or its consumer went away): expired, so it is neither claimed nor left queued."""
        from agentapi import sentinel_broker
        from cveFeed import activity
        if self.task.status in TERMINAL:
            return
        sentinel_broker.expire(self.task, reason)
        activity.settle(self.entry, 'expired', message=f'{self.kind} work for {self.label} was cancelled: {reason}', trace_id=self.task.trace_id)

    @property
    def result(self):
        return Result(self.task.result, agent_id=self.task.agent_id) if self.task.status == 'done' else None


class Result(dict):
    """A dispatched task's typed result, as the plain dict every caller reads, plus ``agent_id``: which Sentinel ran it. The built-in scanner scans from
    this server's own network (it shares celery's network namespace), so a stage treats what it measured as measured here (``ran_here``)."""

    def __init__(self, data, agent_id=None):
        super().__init__(data or {})
        self.agent_id = agent_id

    @property
    def ran_here(self):
        from agentapi import sentinel_broker
        return self.agent_id is not None and self.agent_id == sentinel_broker.builtin_pk()


def dispatch_or_none(project, kind, target, host='', ips=None, scan=None, timeout=None, created_by=None, priority=1, redact_target=None,
                     internal=False, outcome=None, secret_ref=None):
    """Create one SentinelTask for ``kind`` and wait for it, or return ``None`` at once with no side effect when no live,
    eligible Sentinel exists for ``project`` right now. Returns the task's typed ``result`` dict on success; ``None`` on
    timeout, failure, or no Sentinel - in every one of those cases the caller runs the tool locally instead. The hand-off
    and the check-in each get one ``run_check`` activity line (same kind every other scan-stage line already uses, so
    both the Live page and the Activity page show them with no changes of their own), so it is visible, in one place,
    whenever work actually left this server for a Sentinel and whether it came back.

    ``redact_target``, when given, is called with ``target`` once the task reaches a terminal state (done, failed or
    expired) and its return value replaces the stored ``target`` in the database - for a kind whose target carries a
    secret the Sentinel needed only for this one run (today, only WPScan's API token), so the secret does not sit in
    the database for the rest of the task's retention window once nothing needs it there any more.

    ``outcome``, when given, is a dict that is told why a ``None`` came back: ``outcome['no_scanner']`` is True when no live, eligible Sentinel
    was there, or the last one went away while the task queued (the serial loop of ``dispatch_many`` records the chunks it then never sends
    by it).

    ``secret_ref`` makes it signed-in work (``sentinel_broker.secret_ref_for``: a reference to a stored credential, never its value): only the built-in
    scanner, and only one whose image reads stored sign-ins, can take it; it reads the credential once (``sentinel_broker.read_secret``)."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from agentapi import stage_runs
    run = stage_runs.current()
    if run is not None:  # inside a StageRun: the task is created and the worker given back, or the task made on an earlier pass is read
        return _dispatch_async(run, project, kind, target, host, ips, scan, timeout, created_by, priority, redact_target, internal, outcome,
                               secret_ref=secret_ref)
    builtin_only = bool(secret_ref)
    capacity = sentinel_broker.capacity_state(project, kind, internal, why=True, builtin_only=builtin_only, secret=builtin_only)  # why: a ``none`` carries the reason, for the message below
    if capacity['state'] == 'none':
        if outcome is not None:
            outcome['no_scanner'] = True
        if not internal:  # an internal task never had a local run to fall back to: its caller already fails it
            _no_scanner(kind, project, capacity=capacity)
        return None
    work = _Dispatch(project, kind, target, host, ips, scan, timeout, created_by, priority, internal, capacity, secret_ref=secret_ref)
    last_reap = work.started
    while True:
        work.task.refresh_from_db()
        if work.finished:
            break
        now = time.monotonic()
        none_left = False
        if now - last_reap >= REAP_EVERY:  # a Sentinel that stopped heartbeating loses its lease here, not only when something else asks
            sentinel_broker.reap_expired()
            last_reap = now
            none_left = work.task.status == 'queued' and sentinel_broker.capacity_state(project, kind, internal,
                                                                                        builtin_only=builtin_only, secret=builtin_only)['state'] == 'none'
        if work.step(now, none_left):
            break
        _wait([work.task.pk], min(work.pause(now, _poll_interval()), max(0.0, last_reap + REAP_EVERY - now) or REAP_EVERY))
    work.settle()
    if outcome is not None:
        outcome['no_scanner'] = work.vanished
    if redact_target is not None:
        SentinelTask.objects.filter(pk=work.task.pk).update(target=redact_target(target))
    work.no_local()
    return work.result


# --- fan-out: the chunks of one stage across several Sentinel slots, in one wait loop -----------------------------------

def _stage_share(scan, kind, total_slots):
    """The most chunk tasks this stage may keep in flight so that one scan never takes every slot: twice the instance's Sentinel slots, shared among
    the scans with a stage dispatching right now (this one included)."""
    from agentapi.models import SentinelTask, SENTINEL_ACTIVE_STATUSES
    others = (SentinelTask.objects.filter(status__in=SENTINEL_ACTIVE_STATUSES, kind__in=STAGE_KINDS, scan__isnull=False)
              .exclude(scan=scan).values('scan').distinct().count()) if scan is not None else 0
    return max(1, (2 * total_slots) // (others + 1))


def _stopped(scan):
    """Whether the scan was stopped or scanning is paused: what a stage that waits on Sentinels must notice, since no local process is there to."""
    if scan is None:
        return False
    from cveFeed.discovery import stopped
    from reNgine import resources
    return stopped(scan.id) or resources.global_pause_requested(fail_closed=False)


def dispatch_many(project, kind, chunks, prepare=None, scan=None, timeout=None, created_by=None, priority=1, internal=False,
                  stop_on_none=False, labeler=None):
    """Send the chunks of one stage to Sentinels in parallel and yield ``(index, result)`` for each chunk as it finishes (``result`` is the task's
    typed result dict, or ``None`` when no Sentinel did that chunk: the caller runs it here, as for ``dispatch_or_none``). Chunks come back in
    the order they finish, not the order they were given, and a chunk's own result is never split: a caller applies each as a whole.

    A window of chunk tasks is created up front and waited for in ONE poll loop (one read of all of them per tick); each finished chunk refills the
    window. Its width is the smallest of: the chunks left, the slots this stage holds plus the project's free Sentinel slots (never more chunk
    tasks than slots, so none queues behind its own stage's chunks), twice the instance's slots divided among the scans dispatching now (one scan
    does not take every slot), and ``CVENGINE_STAGE_PARALLEL`` (default 4, saved on Settings, configMaxxing: read ONCE when the stage starts, so a change applies from the next stage and a stage in flight keeps the ceiling it began with). The free slots and the other scans are read again on every refill, so
    a slot another stage took is not counted on; the instance's slot total is read once, when the stage starts. When no live Sentinel is left, or one never claims a
    task, no more chunks are sent: that chunk and every chunk not yet sent are yielded as ``None`` after the in-flight ones finish. A chunk
    that failed or expired after a Sentinel took it falls back alone, and the rest carry on.

    Every chunk yielded as ``None`` for work that is not internal has been through ``_no_local`` once, as a single ``dispatch_or_none`` does: one row
    of fallback telemetry when the kind may run here (a chunk a Sentinel did not finish gives its own reason, a chunk never sent because the stage
    stopped sending gives ``over_chunk``, or ``no_scanner`` when no live Sentinel was left), and ``ScannerUnavailable`` when it may not. That
    exception is raised once the chunks in flight are in (their results are yielded first), and no more chunks are sent after it. A chunk
    ``prepare`` turned down was never offered to a Sentinel: the caller decides what becomes of it.

    With ``CVENGINE_STAGE_PARALLEL=1`` (and for a single chunk) this is the serial loop of before: one ``dispatch_or_none`` per chunk, in order;
    ``stop_on_none`` ends it at the first chunk nobody did, the way nmap and naabu always have.

    ``prepare(chunk)`` returns ``(target, ips)`` for the task, or ``None`` for a chunk that must not be dispatched (yielded as ``None``);
    by default the target is ``{'addresses': chunk}``. A stop or global pause while waiting cancels every outstanding chunk task (expired, none
    left queued or claimed) and raises ``resources.ScanAborted``; so does closing the generator early."""
    chunks = [list(c) for c in chunks]
    if not chunks:
        return
    prepare = prepare or (lambda chunk: ({'addresses': chunk}, chunk))
    from agentapi import stage_runs
    run = stage_runs.current()
    if run is not None:  # inside a StageRun: no wait loop here, the chunks are sent and the worker given back until they are over
        yield from _many_async(run, project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none, labeler)
        return
    ceiling = stage_parallel()  # read once per stage: a stage already in flight keeps the ceiling it started with
    if ceiling <= 1 or len(chunks) == 1:
        yield from _dispatch_serially(project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none)
        return
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from reNgine import resources
    total = sentinel_broker.total_slots()
    pending = list(range(len(chunks)))  # chunk indexes not sent yet, in order
    flying = {}  # index -> _Dispatch
    unserved = []  # indexes nobody took (not dispatched, or fan-out stopped before them)
    halted, last_reap, last_refill, last_stop = False, time.monotonic(), None, time.monotonic()
    none_halt = False  # the fan-out stopped because no live, eligible Sentinel was left (not because one chunk went unclaimed)
    blocked = None  # the ScannerUnavailable of a chunk that may not run here: raised once the chunks in flight are in

    def mine_queued():
        return [d.task.pk for d in flying.values() if d.task.status == 'queued']

    def refill(now):
        """Create the chunk tasks the window has room for. Returns what it could not send as nobody's (``halted``)."""
        nonlocal halted, none_halt, last_refill
        last_refill = now
        capacity = sentinel_broker.capacity_state(project, kind, internal, exclude=mine_queued())
        if capacity['state'] == 'none':
            halted = none_halt = True
            return
        holding = sum(d.task.status in ('claimed', 'running') for d in flying.values())
        width = min(ceiling, _stage_share(scan, kind, total), max(1, holding + capacity['free']))
        free_left = max(0, capacity['free'])
        while pending and len(flying) < width:
            index = pending.pop(0)
            prepared = prepare(chunks[index])
            if prepared is None:
                unserved.append(index)
                continue
            target, ips = prepared
            label = labeler(chunks[index]) if labeler else _label('', ips)
            state = {**capacity, 'state': 'free' if free_left else 'busy'}
            flying[index] = _Dispatch(project, kind, target, '', ips, scan, timeout, created_by, priority, internal, state,
                                      label=f'{label} (part {index + 1} of {len(chunks)})',
                                      siblings=lambda me=index: [d.task for i, d in flying.items() if i != me])
            free_left = max(0, free_left - 1)

    try:
        refill(time.monotonic())
        while flying:
            now = time.monotonic()
            if scan is not None and now - last_stop >= STOP_CHECK_EVERY:
                last_stop = now
                if _stopped(scan):
                    raise resources.ScanAborted(f'{kind} dispatch was stopped with its scan')
            rows = SentinelTask._base_manager.in_bulk([d.task.pk for d in flying.values()])  # one read for every chunk in flight
            for d in flying.values():
                if d.task.pk in rows:
                    d.task = rows[d.task.pk]
                else:
                    d.task.status = 'expired'  # the row is gone: nothing will report it
            none_left = False
            if now - last_reap >= REAP_EVERY:
                sentinel_broker.reap_expired()
                last_reap = now
                none_left = any(d.task.status == 'queued' for d in flying.values()) and sentinel_broker.capacity_state(
                    project, kind, internal)['state'] == 'none'
            over = []
            for index in list(flying):
                if flying[index].step(now, none_left):
                    d = flying.pop(index)
                    d.settle()
                    if d.never_claimed:
                        halted = True  # no Sentinel takes work right now: the chunks not sent yet are not tried one by one
                        none_halt = none_halt or d.vanished  # the last live Sentinel went away while it queued: the unsent ones are no_scanner too
                    try:
                        d.no_local()
                    except resources.ScannerUnavailable as exc:
                        blocked, halted = blocked or exc, True  # the kind may not run here: send nothing more, raise once the rest are in
                        continue
                    over.append((index, d.result))
            if pending and not halted and (over or now - last_refill >= REFILL_EVERY):
                refill(now)  # before the results are handed over, so the slots do not wait on the caller's own work
            for index, result in sorted(over, key=lambda pair: pair[0]):
                yield index, result
            if flying:
                bound = min(REFILL_EVERY if pending and not halted else REAP_EVERY, STOP_CHECK_EVERY if scan is not None else REAP_EVERY)
                _wait([d.task.pk for d in flying.values()], min([d.pause(now, _poll_interval()) for d in flying.values()] + [bound]))
    finally:
        for d in flying.values():
            d.cancel('the stage stopped before the task finished')
    if blocked is not None:
        raise blocked
    for index in sorted(unserved + pending):
        if index in pending and not internal:
            _unsent(project, kind, none_halt)
        yield index, None


# --- inside a StageRun (agentapi.stage_runs): the same decisions, with the worker given back while the Sentinels work -----------------

def _dispatch_async(run, project, kind, target, host, ips, scan, timeout, created_by, priority, redact_target, internal, outcome, secret_ref=None):
    """``dispatch_or_none`` inside a StageRun. The first pass that asks creates the task and stops the pass (``Suspend``); the worker is free while
    the Sentinel works and ``stage_runs.drive`` keeps the claim, queue and completion budgets. The pass that runs once the task is over gets here
    again and ends it exactly as the blocking wait did: the activity line closed, the target redacted, ``no_local`` (``ScannerUnavailable`` or one
    fallback row) and the result."""
    from agentapi import sentinel_broker, stage_runs
    from agentapi.models import SentinelTask
    key = stage_runs.task_key(kind, target, host, ips, internal, secret_ref=secret_ref)
    work = run.work(key)
    if work is None:
        builtin_only = bool(secret_ref)  # signed-in work: only the built-in scanner's slots count, as in the blocking path
        capacity = sentinel_broker.capacity_state(project, kind, internal, why=True, builtin_only=builtin_only, secret=builtin_only)
        if capacity['state'] == 'none':
            if outcome is not None:
                outcome['no_scanner'] = True
            if not internal:
                _no_scanner(kind, project, capacity=capacity)
            return None
        work = _Dispatch(project, kind, target, host, ips, scan, timeout, created_by, priority, internal, capacity, secret_ref=secret_ref)
        run.add(key, work)
        run.suspend()
    if not work.finished:
        run.suspend()  # a pass that started before this task was over (a stage with another wait that ended first)
    run.settled(work)
    if outcome is not None:
        outcome['no_scanner'] = work.vanished
    if redact_target is not None:
        stored = work.task.target if isinstance(work.task.target, dict) else {}
        if stored.get('token') not in (None, '', '***'):
            SentinelTask.objects.filter(pk=work.task.pk).update(target=redact_target(stored))
    work.no_local()
    return work.result


def _group_id(kind, chunks):
    import hashlib
    import json
    return hashlib.sha256(json.dumps([kind, chunks], sort_keys=True, default=str).encode()).hexdigest()[:24]


def _many_async(run, project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none, labeler):
    """``dispatch_many`` inside a StageRun: the same window (the free slots, the stage's share, ``CVENGINE_STAGE_PARALLEL``), the same stop when a
    chunk goes unclaimed or the last Sentinel leaves, and the same fallback decisions, but nothing is yielded until every chunk is over: each pass
    sends what the window has room for and stops, and the pass after the last chunk ended yields them all, in order. So a stage never handles a
    chunk's result twice, however many passes its chunks took. ``CVENGINE_STAGE_PARALLEL=1`` keeps one chunk in flight and, with ``stop_on_none``,
    stops at the first chunk nobody did, as the serial loop does."""
    from agentapi import sentinel_broker
    from reNgine import resources
    gid = _group_id(kind, chunks)
    group = run.group(gid)
    group.setdefault('ceiling', stage_parallel())
    group.setdefault('prepared', {})
    group.setdefault('unserved', [])
    serial = group['ceiling'] <= 1 or len(chunks) == 1
    works = {}
    for i in range(len(chunks)):
        prepared = group['prepared'].get(str(i))
        if prepared:
            found = run.work(prepared['key'])
            if found is not None:
                found.stop_check = True
                works[i] = found
    if scan is not None and (group.get('aborted') or _stopped(scan)):
        for d in works.values():
            d.cancel('the stage stopped before the task finished')
        group['aborted'] = True
        raise resources.ScanAborted(f'{kind} dispatch was stopped with its scan')
    halted, none_halt = bool(group.get('halted')), bool(group.get('none_halt'))
    for i, d in works.items():
        if not d.finished:
            continue
        if run.tasks.get(str(d.task.pk), {}).get('settled') is not True:
            run.settled(d)
        if d.never_claimed:
            halted, none_halt = True, none_halt or d.vanished
        if d.task.status != 'done' and not internal and not fallback_allowed(kind):
            halted = True  # its no_local raises: nothing more is sent
        if serial and stop_on_none and d.task.status != 'done':
            halted, none_halt = True, none_halt or d.vanished
    sent = {int(i) for i in group['prepared']}
    pending = [i for i in range(len(chunks)) if i not in sent and i not in group['unserved']]
    flying = [i for i, d in works.items() if not d.finished]
    if pending and not halted:
        queued_mine = [d.task.pk for d in works.values() if d.task.status == 'queued']
        capacity = sentinel_broker.capacity_state(project, kind, internal, exclude=queued_mine)
        if capacity['state'] == 'none':
            halted = none_halt = True
        else:
            holding = sum(d.task.status in ('claimed', 'running') for d in works.values())
            width = 1 if serial else min(group['ceiling'], _stage_share(scan, kind, sentinel_broker.total_slots()), max(1, holding + capacity['free']))
            free_left = max(0, capacity['free'])
            while pending and len(flying) < width:
                index = pending.pop(0)
                prepared = prepare(chunks[index])
                if prepared is None:
                    group['unserved'].append(index)
                    continue
                target, ips = prepared
                label = labeler(chunks[index]) if labeler else _label('', ips)
                state = {**capacity, 'state': 'free' if free_left else 'busy'}
                d = _Dispatch(project, kind, target, '', ips, scan, timeout, created_by, priority, internal, state,
                              label=f'{label} (part {index + 1} of {len(chunks)})')
                d.stop_check = True
                key = stage_runs_key(kind, target, ips, internal)
                run.add(key, d, group=gid, index=index)
                group['prepared'][str(index)] = {'key': key}
                works[index] = d
                flying.append(index)
                free_left = max(0, free_left - 1)
    group['halted'], group['none_halt'] = halted, none_halt
    if flying:
        run.suspend(refill=bool(pending and not halted))
    blocked = None
    out = []
    for index in sorted(works):
        d = works[index]
        try:
            d.no_local()
        except resources.ScannerUnavailable as exc:
            blocked = blocked or exc
            continue
        out.append((index, d.result))
    for pair in out:
        yield pair
    if blocked is not None:
        raise blocked
    for index in sorted(group['unserved'] + pending):
        if index in pending and not internal:
            _unsent(project, kind, none_halt)
        yield index, None


def stage_runs_key(kind, target, ips, internal):
    from agentapi import stage_runs
    return stage_runs.task_key(kind, target, '', ips, internal)


def prefetch(project, kind, items, scan=None, timeout=None, internal=False):
    """Inside a StageRun, send the tasks a loop of ``dispatch_or_none`` calls is about to make (``items``: ``(target, host, ips)`` of each, the same
    arguments) side by side, before the loop runs, and wait (the worker given back) until every one is over; the loop then finds each result at
    once and handles all of them in one pass, so its own summary covers every item. The window is the free slots, as for ``dispatch_many``; with no
    live Sentinel left nothing more is sent and the loop's own calls decide, as they would have. Outside a StageRun it does nothing."""
    from agentapi import sentinel_broker, stage_runs
    run = stage_runs.current()
    if run is None or not items:
        return
    keys = [stage_runs.task_key(kind, target, host, ips, internal) for target, host, ips in items]
    gid = 'prefetch:' + _group_id(kind, keys)
    group = run.group(gid)
    works = {i: run.work(k) for i, k in enumerate(keys)}
    works = {i: d for i, d in works.items() if d is not None}
    flying = [i for i, d in works.items() if not d.finished]
    pending = [i for i in range(len(items)) if i not in works]
    if pending and not group.get('halted'):
        capacity = sentinel_broker.capacity_state(project, kind, internal,
                                                  exclude=[d.task.pk for d in works.values() if d.task.status == 'queued'])
        if capacity['state'] == 'none':
            group['halted'] = True
        else:
            holding = sum(d.task.status in ('claimed', 'running') for d in works.values())
            width = max(1, holding + capacity['free'])
            free_left = max(0, capacity['free'])
            while pending and len(flying) < width:
                index = pending.pop(0)
                target, host, ips = items[index]
                d = _Dispatch(project, kind, target, host, ips, scan, timeout, None, 1, internal, {**capacity, 'state': 'free' if free_left else 'busy'})
                run.add(keys[index], d, group=gid, index=index)
                flying.append(index)
                free_left = max(0, free_left - 1)
    if flying:
        run.suspend(refill=bool(pending and not group.get('halted')))


def _unsent(project, kind, none_left):
    """``_no_local`` for a chunk of a stage that was never sent to a Sentinel because the stage stopped sending: ``no_scanner`` (with its reason)
    when no live, eligible Sentinel was left, ``over_chunk`` when an earlier chunk of the same stage went unclaimed."""
    if none_left:
        _no_scanner(kind, project)
    else:
        _no_local(kind, 'an earlier part of the stage found no Sentinel to take it, so this part was not sent', 'over_chunk', project)


def _dispatch_serially(project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none):
    """``dispatch_many`` with a window of one: the chunks one after another through ``dispatch_or_none``, as a stage always did. The chunks
    never sent once one went undone are recorded as the parallel loop records them: ``no_scanner`` when that one found no live, eligible
    Sentinel (none at all, or the last one went away while it queued), ``over_chunk`` when it went undone with a Sentinel live."""
    ended = none_left = False
    for index, chunk in enumerate(chunks):
        if ended:
            if not internal:
                _unsent(project, kind, none_left)
            yield index, None
            continue
        prepared = prepare(chunk)
        if prepared is None:
            yield index, None
            continue
        target, ips = prepared
        kwargs = {'internal': True} if internal else {}
        outcome = {}
        if stop_on_none and not internal:
            kwargs['outcome'] = outcome
        if created_by is not None:
            kwargs['created_by'] = created_by
        if priority != 1:
            kwargs['priority'] = priority
        result = dispatch_or_none(project, kind, target, ips=ips, scan=scan, timeout=timeout, **kwargs)
        if result is None and stop_on_none:
            ended = True  # the first chunk no Sentinel took ends the dispatching: it and the rest run here
            none_left = bool(outcome.get('no_scanner'))
        yield index, result


# --- nmap: dispatch a chunk of addresses, persist a hit through the exact same function local nmap uses ---------------

def try_nmap(project, scan, targets, org_id=None, timeout=None, ports_by_ip=None):
    """Return local targets, Sentinel totals, and the local port plan.

    An address is covered only when the Sentinel reports a host row. When naabu found ports that the Sentinel did not
    report scanning, the local pass fingerprints just those ports. An absent host row keeps the whole local fallback.

    Those addresses (a Sentinel finished their chunk and left part of the work undone) go through ``_no_local`` once, like every other local
    fallback: one ``partial_result`` row of fallback telemetry when nmap may run here, and ``ScannerUnavailable`` when it may not, so they stay
    due instead of running here. A chunk no Sentinel did has been through ``_no_local`` already (``dispatch_many``). Whenever this raises
    ``ScannerUnavailable`` after a Sentinel finished part of the work, the exception's ``done`` lists the addresses a Sentinel fully covered
    (persisted already), so the caller marks only those done and the rest stay due.
    """
    from reNgine.resources import ScannerUnavailable
    targets = list(targets)
    zero = {'ports': 0, 'hosts_with_os': 0}
    local_ports = dict(ports_by_ip) if ports_by_ip is not None else None
    if not any_scanner_for(project, 'nmap'):
        _no_scanner('nmap', project)
        return targets, zero, local_ports
    from cveFeed.nmap_scan import persist_inventory
    # every chunk of MAX_ADDRESSES goes to a Sentinel (a batch of hosts has more addresses than one task takes), several at once when there are
    # free slots; a chunk no Sentinel did is simply not reported, and what the caller fingerprints here is every address without a report
    totals, reported, finished = None, {}, set()

    def missing_ports(ip):  # the ports naabu found on an address the Sentinel reported that the Sentinel did not report scanning
        if local_ports is None or ip not in local_ports:
            return []
        return sorted(set(local_ports[ip]) - reported[ip])

    chunks = _chunks(targets)
    try:
        with contextlib.closing(dispatch_many(project, 'nmap', chunks, scan=scan, timeout=timeout, stop_on_none=True)) as results:
            for index, result in results:
                if result is None:
                    continue
                chunk = chunks[index]
                finished.update(chunk)
                inventory = [{'ip': host['ip'], 'os_guess': host.get('os_guess', ''), 'os_accuracy': None, 'ports': host.get('ports', [])}
                             for host in result.get('hosts', []) if host.get('ip') in chunk]
                # the Sentinel's own network, unless it says it sits behind Docker Desktop's; the built-in scanner's is this server's own (os_reliable None:
                # judged and marked as a local scan, cveFeed.os_detection)
                reliable = None if getattr(result, 'ran_here', False) else result.get('os_reliable') is not False
                done = persist_inventory(inventory, org_id=org_id, os_reliable=reliable)
                totals = done if totals is None else {key: totals.get(key, 0) + done.get(key, 0) for key in set(totals) | set(done)}
                for host in inventory:
                    reported.setdefault(host['ip'], set()).update(p.get('number') for p in host['ports'])
    except ScannerUnavailable as exc:  # a chunk nobody did may not run here: what a Sentinel fully covered is done, the rest stays due
        exc.done = [ip for ip in targets if ip in reported and not missing_ports(ip)]
        raise
    if totals is None:
        return targets, zero, local_ports
    remaining = []
    for ip in targets:
        if ip not in reported:
            remaining.append(ip)
        else:
            missing = missing_ports(ip)
            if missing:
                local_ports[ip] = missing
                remaining.append(ip)
    partial = [ip for ip in remaining if ip in finished]  # a Sentinel finished the chunk but did not report the host, or every port naabu found
    if partial:
        try:
            _no_local('nmap', f'a Sentinel finished {len(partial)} address(es) without reporting the host or every port naabu found',
                      'partial_result', project)
        except ScannerUnavailable as exc:
            exc.done = [ip for ip in targets if ip not in remaining]
            raise
    return remaining, totals, local_ports


# --- testssl: one host:port at a time, the Sentinel's raw report items run through the same local evaluate() -----------

def try_testssl(project, host, ip, port, starttls=None, scan=None, timeout=None):
    """A Sentinel's testssl.sh report items for ``host:port`` (raw, in the exact shape ``cveFeed.testssl_scan.evaluate``
    already reads from a local run), or ``None`` when no Sentinel is eligible, on timeout, or on failure - in which case
    the caller runs ``run_testssl`` locally exactly as before. Unlike nmap/naabu/nuclei this is never chunked: a testssl
    run is already one host:port per call, locally or dispatched."""
    if not any_scanner_for(project, 'testssl'):
        _no_scanner('testssl', project)
        offline_fallback(project, 'testssl')
        return None
    target = {'host': host, 'ip': ip, 'port': port, 'starttls': starttls or ''}
    result = dispatch_or_none(project, 'testssl', target, host=host, ips=[ip], scan=scan, timeout=timeout)
    return (result or {}).get('items') if result is not None else None


# --- nmap -sU: raw XML through the Sentinel, parsed by the exact function a local run's own XML already goes through --

def try_nmap_udp(project, ip_address, scan=None, timeout=None):
    """The parsed ``nmap -sU`` host record for ``ip_address`` from a Sentinel's raw XML report, or ``None`` when no
    Sentinel is eligible, on timeout, or on failure - in which case the caller runs the local ``-sU`` scan exactly as
    before. Unlike every other dispatched kind here, the Sentinel's result is raw XML text, not pre-parsed JSON: UDP's
    own state vocabulary (``open|filtered``, extraports summarisation) and the NSE script output
    ``cveFeed.udp_scan.identify`` reads are read correctly only by ``cveFeed.nmap_scan.parse_xml`` (hardened against a
    custom ENTITY declaration precisely because it now also reads a Sentinel's report, not only this process's own
    nmap output), so that is the one function - local or dispatched - that ever turns the XML into a record. Never
    chunked: one address per task, like testssl."""
    if not any_scanner_for(project, 'nmap_udp'):
        _no_scanner('nmap_udp', project)
        offline_fallback(project, 'nmap_udp')
        return None
    result = dispatch_or_none(project, 'nmap_udp', {'address': ip_address}, ips=[ip_address], scan=scan, timeout=timeout)
    if result is None:
        return None
    from cveFeed.nmap_scan import parse_xml
    host = next((h for h in parse_xml(result.get('xml') or '') if h.get('ip') == ip_address), None)
    if host is None:
        # the Sentinel finished but its report names no host for the address: a local -sU only when the kind may run here (recorded as a
        # partial result, like the nmap stage's leftover), otherwise the address stays due (ScannerUnavailable)
        _no_local('nmap_udp', 'a Sentinel scanned the address but its report named no host for it', 'partial_result', project)
    return host


# --- naabu: an injectable runner wrapping cveFeed.naabu_scan.discover's own seam, untouched otherwise ------------------

def wrap_naabu_runner(project, scan, timeout=None):
    """A ``runner(ips) -> {ip: [open ports]}`` for ``naabu_scan.discover``'s own ``runner`` parameter, or ``None`` when no
    Sentinel is eligible (so ``discover`` uses its unmodified default, ``run_naabu``, exactly as today). The addresses a
    Sentinel actually attempted (its whole chunk, whether or not each had an open port: no entry means none, exactly as
    naabu's own JSON output already means) are never scanned locally too; a chunk no Sentinel did (left over on a timeout, or
    never sent once an earlier one went unclaimed) falls back to the real, unmodified ``naabu_scan.run_naabu``, when the kind
    may run here (``_no_local``)."""
    if not any_scanner_for(project, 'naabu'):
        _no_scanner('naabu', project)  # raises ScannerUnavailable when naabu may not run here
        if not offline_fallback(project, 'naabu'):
            return None  # no Sentinel configured for naabu: local is this project's normal mode, discover uses run_naabu as before

        def offline_runner(ips):  # every Sentinel that could take it is offline: a local fallback, under the hourly cap
            from cveFeed.local_egress import admit_fallback
            from cveFeed.naabu_scan import PortMap, run_naabu
            ips = list(ips)
            if admit_fallback('naabu', getattr(project, 'pk', project)):
                return run_naabu(ips)
            return PortMap({}, deferred=ips)
        return offline_runner

    def runner(ips):
        from cveFeed.naabu_scan import run_naabu
        ips = list(ips)
        found, unserved = {}, []
        chunks = _chunks(ips)  # a batch of hosts has more addresses than one task takes: every chunk is dispatched, several at once when slots are free
        with contextlib.closing(dispatch_many(project, 'naabu', chunks, scan=scan, timeout=timeout, stop_on_none=True)) as results:
            for index, result in results:
                if result is None:  # no Sentinel did this chunk: it, and with the serial limit everything after it, is scanned here, as before
                    unserved.append(index)
                else:
                    found.update(dict(result.get('ports') or {}))
        from cveFeed.local_egress import admit_fallback
        from cveFeed.naabu_scan import PortMap
        deferred = []
        if unserved:
            left = [ip for index in sorted(unserved) for ip in chunks[index]]
            if admit_fallback('naabu', getattr(project, 'pk', project)):
                found.update(run_naabu(left))
            else:  # over the local fallback cap: not scanned here now; discover leaves them due for the next run
                deferred = left
        return PortMap(found, deferred=deferred)
    return runner


# --- nuclei (light and targeted): an injectable stream matching cveFeed.nuclei_scan.stream_nuclei's own seam -----------

def _bare_host(target):
    """The hostname or address inside a nuclei target string built by ``nuclei_scan.build_targets`` (a bare host, a bare
    IP, or ``host:port`` for a non-default port)."""
    return target.rsplit(':', 1)[0].strip() if target.count(':') == 1 else target.strip()


def _resolves(host, timeout):
    import socket
    try:
        ipaddress.ip_address(host)
        return True  # a literal address needs no lookup
    except ValueError:
        pass
    try:
        return bool(socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP))
    except (socket.gaierror, UnicodeError, OSError):
        return False


def resolvable_targets(targets, workers=RESOLVE_WORKERS, timeout=RESOLVE_TIMEOUT):
    """The entries of ``targets`` whose host currently resolves, in order: a Sentinel is never handed a target this
    process cannot even look up, which would otherwise dispatch work for nothing and - because the stage that sent it
    marks its whole chunk scanned once the dispatched call returns, not target by target - leave a host that was never
    actually reached looking checked. A stale or deleted DNS record is the common case here (a host that resolved when
    it was first discovered may not resolve months later), not a name a tenant never controlled, so this is a plain
    resolvability check, not ``targetApp.target_types``'s prohibited-range gate: a target already passed that when it
    was added. One bounded parallel pass, like ``target_types.blocked_names``; never one lookup per target serially."""
    from concurrent.futures import ThreadPoolExecutor, wait
    targets = list(targets)
    if not targets:
        return []
    hosts = {t: _bare_host(t) for t in targets}
    unique = sorted(set(hosts.values()))
    n_workers = max(1, min(workers, len(unique)))
    pool = ThreadPoolExecutor(max_workers=n_workers, thread_name_prefix='sentinel-resolve')
    try:
        futures = {h: pool.submit(_resolves, h, timeout) for h in unique}
        # ``getaddrinfo`` cannot be interrupted, so the bound is on the wait: every lookup gets ``timeout`` per round of ``workers`` hosts, and a
        # name still unanswered then counts as not resolving (its thread ends when the resolver gives up), instead of one slow resolver holding
        # the whole stage.
        wait(futures.values(), timeout=timeout * -(-len(unique) // n_workers))
        live = {h: f.done() and not f.cancelled() and f.exception() is None and f.result() for h, f in futures.items()}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return [t for t in targets if live.get(hosts[t])]

def _finding_to_nuclei_line(finding):
    """One Sentinel-reported nuclei finding, reshaped into the same dict ``reNgine.tasks.parse_nuclei_result`` and
    ``cveFeed.nuclei_scan.host_of`` already read from nuclei's own ``-jsonl`` output. Fields nuclei's full output carries
    that a Sentinel's typed, clipped result does not carry (a curl command; the request/response transcript, ``type`` from a client that
    does not send these optional fields) are left out, not guessed: the untyped nuclei line already tolerates them being absent, and a
    finding without ``type`` reads as ``http`` as before. ``matcher-name`` is carried through from
    the Sentinel's own ``matcher_name`` field so a tech-detect template hit names a technology the same way
    ``cveFeed.nuclei_scan.tech_name_from`` already reads it from a locally-run nuclei line."""
    return {'host': finding.get('host') or finding.get('matched_at') or '', 'matched-at': finding.get('matched_at') or '',
            'type': finding.get('type') or 'http', 'template': finding.get('template_id') or '', 'template-id': finding.get('template_id') or '',
            'template-url': [], 'matcher-name': finding.get('matcher_name') or '', 'curl-command': None, 'request': finding.get('request'),
            'response': finding.get('response'), 'extracted-results': finding.get('extracted_results') or [],
            'info': {'name': finding.get('name') or '', 'severity': finding.get('severity') or 'unknown',
                     'description': finding.get('description') or '', 'classification': {'cve-id': list(finding.get('cve_ids') or [])}, 'reference': [],
                     'tags': finding.get('tags') or []}}


def _nuclei_target(kind, targets, kwargs):
    """The target of a dispatched nuclei task: the targets, the tags and severities this pass would run with locally, and the template policy the
    local run applies. The light pass is nuclei's technology fingerprint (``-tags tech -severity info``): ``run_light_nuclei`` asks for it with a
    ``tech`` flag only the unwrapped local stream takes, so the Sentinel is told the same here, or it would run the whole template library at
    every severity and the stage would time out. ``etags`` are the tags every run leaves out (``cvengine_scanner.flags.NUCLEI_EXCLUDED_TAGS``, ``dos``) and
    ``template_policy`` names the template policy in force (the read-only set, or everything when an administrator allowed it), so the client runs
    nothing this server would not; its ``bundle_sha256`` is the sha256 of the approved template archive the client fetches from
    ``GET /api/v1/sentinel/template-policy/bundle`` (``None`` until that archive exists: it is packed here when the approved snapshot is already
    cached, else on the first policy request)."""
    from cvengine_scanner import flags as scan_flags

    from agentapi import template_bundle
    from cveFeed import nuclei_scan
    # no severities given: the local run's own default (``cvengine_scanner.flags.NUCLEI_SEVERITIES``, info to critical), sent as a list, since a client given none
    # would run every severity, ``unknown`` included, and the two runs of one pass would not agree
    tags, severities = sorted(kwargs.get('tags') or []), list(kwargs.get('severities') or scan_flags.NUCLEI_SEVERITIES.split(','))
    if kind == 'nuclei_light' or kwargs.get('tech'):
        tags, severities = ['tech'], ['info']
    etags = list(scan_flags.NUCLEI_EXCLUDED_TAGS)
    rev = nuclei_scan.policy_rev()
    return {'targets': targets, 'tags': tags, 'severities': severities, 'etags': etags,
            'template_policy': {'rev': rev, 'read_only': rev == nuclei_scan.TEMPLATE_POLICY_REV, 'bundle_sha256': template_bundle.sha256_if_ready()}}


def _local_kwargs(kind, kwargs):
    """The keyword arguments the local stream gets when a dispatched stage falls back to it: the light pass keeps its ``tech`` flag, which the
    wrapper in place of ``stream_nuclei`` hid from the caller, so the fallback is the quick fingerprint and not the whole template library."""
    return {**kwargs, 'tech': True} if kind == 'nuclei_light' else kwargs


def _targets_label(chunk):
    return f'{len(chunk)} target{"s" if len(chunk) != 1 else ""}'


def _chunks(targets):
    return [targets[i:i + MAX_ADDRESSES] for i in range(0, len(targets), MAX_ADDRESSES)]


@contextlib.contextmanager
def _targets_file(targets):
    """A temporary file with one target per line, for a local nuclei run over one chunk."""
    handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
    try:
        with handle:
            handle.write('\n'.join(targets) + '\n')
        yield handle.name
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def wrap_nuclei_stream(scan, kind, timeout=None, internal=False):
    """A ``stream(targets_file, **kwargs) -> iterable of result-line dicts`` matching ``nuclei_scan.stream_nuclei``'s own
    signature, for ``run_light_nuclei``/``run_targeted_nuclei``'s ``stream`` parameter. Returns the literal, unwrapped
    ``stream_nuclei`` function (not a wrapper around it) when no Sentinel is eligible, so ``_run_nuclei``'s own
    ``stream is stream_nuclei`` identity check, and every other local behaviour, is unaffected."""
    from cveFeed.nuclei_scan import stream_nuclei
    project = scan.domain.project
    if internal:  # the target is inside a private network: only a Sentinel there can run it, and there is never a local fallback
        def internal_stream(targets_file, **kwargs):
            if kwargs.get('secret_file'):  # a signed-in pass: a Sentinel is never sent a stored credential, and it must not run signed out and be reported as signed in
                raise RuntimeError('a signed-in nuclei pass cannot run on a Sentinel: the stored sign-in stays on this server')
            try:
                with open(targets_file, encoding='utf-8') as handle:
                    targets = [line.strip() for line in handle if line.strip()]
            except OSError:
                targets = []
            chunks = _chunks(targets)  # every target is sent: a stage that marks its whole list scanned must not have dropped the tail
            with contextlib.closing(dispatch_many(project, kind, chunks, prepare=lambda chunk: (_nuclei_target(kind, chunk, kwargs), []), scan=scan,
                                                  internal=True, timeout=timeout, labeler=_targets_label)) as results:
                for _index, result in results:
                    if result is None:
                        raise RuntimeError('no Sentinel inside the network answered (one must declare network:internal and cover this project)')
                    for finding in result.get('findings', []):
                        yield _finding_to_nuclei_line(finding)
        internal_stream.chunks_itself = True  # the caller hands over the whole list: this splits it and runs the chunks side by side
        return internal_stream
    if not any_scanner_for(project, kind):
        _no_scanner(kind, project)
        offline_fallback(project, kind)
        return stream_nuclei

    def stream(targets_file, **kwargs):
        if kwargs.get('secret_file'):
            # a caller that wrote its own secrets file: it never goes to a Sentinel (a dispatched run would be signed out while its findings were
            # labelled as seen while signed in), so it runs here, when the kind may. cveFeed.auth_nuclei uses ``stream.signed_in`` instead.
            if not fallback_allowed(kind):
                _no_local(kind, 'a signed-in run that names its own secrets file runs only on this server', project=project)
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        try:
            with open(targets_file, encoding='utf-8') as handle:
                targets = [line.strip() for line in handle if line.strip()]
        except OSError:
            targets = []
        if not targets:  # nothing readable to send: the local run decides what an empty or missing list means
            if fallback_allowed(kind):
                yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        chunks = _chunks(targets)  # one task per chunk of MAX_ADDRESSES, several at once: the caller marks the whole list scanned, so none may be dropped

        unresolved = set()  # the chunks (as tuples) nothing of which resolves: never offered to a Sentinel

        def prepare(chunk):
            live = resolvable_targets(chunk)
            if not live:
                # nothing in the chunk resolves (a Sentinel would be asked to do nothing, and nuclei cannot reach what cannot be looked up either: run
                # it anyway, when the kind may run here, so the existing "ran, found nothing" accounting is unchanged): this chunk runs here
                unresolved.add(tuple(chunk))
                return None
            return _nuclei_target(kind, live, kwargs), []
        unserved = []
        with contextlib.closing(dispatch_many(project, kind, chunks, prepare=prepare, scan=scan, timeout=timeout, labeler=_targets_label)) as results:
            for index, result in results:
                if result is None:
                    unserved.append(index)  # no Sentinel took it: it runs here once the Sentinels' chunks are in, so they never wait on it
                    continue
                for finding in result.get('findings', []):
                    yield _finding_to_nuclei_line(finding)
        for index in sorted(unserved):
            if tuple(chunks[index]) in unresolved and not fallback_allowed(kind):
                continue  # nothing in the chunk resolves: there is nothing for a scanner to run, and nothing may run here
            if len(targets) <= MAX_ADDRESSES:  # the whole list is this chunk: the caller's own file
                yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
                continue
            with _targets_file(chunks[index]) as path:
                yield from stream_nuclei(path, **_local_kwargs(kind, kwargs))
    stream.chunks_itself = True  # the caller hands over the whole list: this splits it and runs the chunks side by side
    stream.signed_in = signed_in_stream(scan, kind, timeout)
    return stream


def signed_in_stream(scan, kind, timeout=None):
    """``run(items, **kwargs) -> iterable of result-line dicts``: a signed-in nuclei pass (``cveFeed.auth_nuclei``) over ``items`` (``auth_checks.PlanItem``:
    an origin URL and the stored credential that covers it) through the built-in scanner. One task per credential and chunk of origins, carrying
    ``secret_ref`` (a reference to the credential, never its value): only the built-in scanner takes it, and reads the credential once through
    ``POST sentinel/tasks/<id>/secret``. An external Sentinel is never offered it (``sentinel_broker.SentinelEff.refusal``). When no built-in
    scanner that reads stored sign-ins is live, the pass runs here with a private secrets file as before if nuclei may run here, and waits
    (``ScannerUnavailable``) when it may not. The lines are redacted by the caller like a local run's."""
    project = scan.domain.project

    def run(items, **kwargs):
        from agentapi import sentinel_broker
        from cveFeed import auth_checks
        from cveFeed.nuclei_scan import stream_nuclei
        kwargs = {k: v for k, v in kwargs.items() if k != 'secret_file'}
        for credential, _domains in auth_checks.entries_for(items):
            urls = [item.url for item in items if item.credential.pk == credential.pk]
            for chunk in _chunks(urls):
                result = dispatch_or_none(project, kind, _nuclei_target(kind, chunk, kwargs), scan=scan, timeout=timeout,
                                          secret_ref=sentinel_broker.secret_ref_for(credential.pk))
                if result is not None:
                    for finding in result.get('findings', []):
                        yield _finding_to_nuclei_line(finding)
                    continue
                # no built-in scanner took it and nuclei may run here (dispatch_or_none raised otherwise): the pass of before, for this chunk
                chunk_items = [item for item in items if item.url in set(chunk)]
                with auth_checks.secrets_file(auth_checks.entries_for(chunk_items)) as secret_path, _targets_file(chunk) as path:
                    yield from stream_nuclei(path, secret_file=secret_path, **_local_kwargs(kind, kwargs))
    return run


# --- wpscan: a wrapping runner(url, token) -> report, like cveFeed.wpscan_scan's own seam ------------------------------

def prefetch_wpscan(project, scan, urls, token, internal=False, timeout=None):
    """Inside a StageRun, send the WPScan task of every site in ``urls`` before the stage's loop over them (``prefetch``), with the target and host
    the runner of ``wrap_wpscan_runner`` gives each, so the loop finds every report in one pass. Outside a StageRun it does nothing."""
    from urllib.parse import urlsplit
    items = []
    for url in urls:
        if internal:
            host = urlsplit(url).hostname or ''
            items.append(({'url': url, 'token': token}, host, [host]))
        else:
            items.append(({'url': url, 'token': token}, '', None))
    prefetch(project, 'wpscan', items, scan=scan, timeout=timeout, internal=internal)


def wrap_wpscan_runner(project, scan=None, timeout=None, internal=False):
    """A ``runner(url, token) -> report`` for ``wpscan_scan.run_wpscan``'s own ``runner`` parameter, or the literal,
    unwrapped ``run_wpscan_process`` when no Sentinel is eligible (so ``runner is run_wpscan_process`` identity checks,
    and every other local behaviour, are unaffected). The project's WPScan API token travels with the dispatched task -
    the same blast radius it already has today, since it already leaves this process into a subprocess's environment -
    for this one run only: ``dispatch_or_none``'s ``redact_target`` scrubs it from the stored task once the task is
    done, failed or expired, so it never sits in the database beyond that. A Sentinel's reported outcome is classified
    by the exact same ``cveFeed.wpscan_scan._classify`` a local run's own exit code and report go through, so a
    dispatched site ends up ``NotWordPress``/``Blocked``/a normal report exactly as a local one would."""
    from cveFeed.wpscan_scan import run_wpscan_process
    if internal:  # a site inside a declared internal network: only a Sentinel inside it may run WPScan, and there is no local fallback
        from urllib.parse import urlsplit

        def internal_runner(url, token):
            from cveFeed.wpscan_scan import _classify
            host = urlsplit(url).hostname or ''
            result = dispatch_or_none(project, 'wpscan', {'url': url, 'token': token}, host=host, ips=[host], scan=scan, timeout=timeout,
                                      internal=True, redact_target=lambda t: {**t, 'token': '***'} if t.get('token') else t)
            if result is None:
                raise RuntimeError('no Sentinel inside the network ran WPScan (one must declare network:internal and wpscan and cover this project)')
            return _classify(result.get('report'), result.get('returncode', 1), result.get('stderr_tail', ''), token)
        return internal_runner
    if not any_scanner_for(project, 'wpscan'):
        _no_scanner('wpscan', project)
        offline_fallback(project, 'wpscan')
        return run_wpscan_process

    def runner(url, token):
        from cveFeed.wpscan_scan import _classify
        result = dispatch_or_none(project, 'wpscan', {'url': url, 'token': token}, scan=scan, timeout=timeout,
                                  redact_target=lambda t: {**t, 'token': '***'} if t.get('token') else t)
        if result is None:
            return run_wpscan_process(url, token)
        return _classify(result.get('report'), result.get('returncode', 1), result.get('stderr_tail', ''), token)
    return runner


# --- the kinds of contract version 3: one task per item, several at once, through dispatch_many -----------------------------------------------
#
# waf, nmap_full, nmap_verify, node2shell, rdp_shot, db_probe, path_probe and nuclei_validate (docs/SCANNER-ARCHITECTURE.md, section B). Each stage
# asks ``scanner_or_local`` first: True sends its items with ``dispatch_each``; False is the local run of before (no Sentinel was ever set up for the
# kind, or every one is offline and the kind may run here, counted as a fallback); ``ScannerUnavailable`` when the kind may not run here, which the
# stage turns into "waiting" with its targets left due. An item a Sentinel did not finish comes back as ``None``: the stage runs it here when the kind
# may, and ``dispatch_each`` raises ``ScannerUnavailable`` once the others are in when it may not.

def scanner_or_local(project, kind):
    """Whether ``kind`` work of ``project`` goes to a Sentinel (True) or runs here (False). Raises ``ScannerUnavailable`` when no live Sentinel can take
    it and the kind may not run here (``CVENGINE_LOCAL_FALLBACK``)."""
    if any_scanner_for(project, kind):
        return True
    _no_scanner(kind, project)
    offline_fallback(project, kind)
    return False


def dispatch_each(project, kind, items, target_of, scan=None, label_of=None, ips_of=None):
    """Send one ``kind`` task per entry of ``items`` (``target_of(item)`` is its target, ``None`` to keep it here) and yield ``(index, result)`` as each
    finishes: the task's typed result, or ``None`` when no Sentinel did it (the caller runs it here: it has been through ``_no_local`` once, as for any
    chunk). Raises ``ScannerUnavailable`` after the finished ones are yielded when one may not run here."""
    items = list(items)
    if not items:
        return

    def prepare(chunk):
        item = items[chunk[0]]
        target = target_of(item)
        if target is None:
            return None
        return target, list(ips_of(item)) if ips_of else []
    labeler = (lambda chunk: label_of(items[chunk[0]])) if label_of else None
    with contextlib.closing(dispatch_many(project, kind, [[i] for i in range(len(items))], prepare=prepare, scan=scan, labeler=labeler)) as results:
        yield from results


def _project_of(project_id):
    from dashboard.models import Project
    return Project.objects.select_related('org').filter(pk=project_id).first() if project_id else None


def _netloc(host, port):
    return f'[{host}]:{port}' if ':' in str(host) else f'{host}:{port}'


# waf: one site, at the address the server vetted -------------------------------------------------------------------------------------------

def waf_target(url, ip):
    """The ``waf`` target for a site root ``url`` reached at ``ip``, or ``None`` when the URL has no host."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if not parts.hostname or not ip:
        return None
    scheme = parts.scheme if parts.scheme in ('http', 'https') else 'https'
    return {'host': parts.hostname, 'ip': ip, 'port': parts.port or (443 if scheme == 'https' else 80), 'scheme': scheme}


def waf_outcome(result):
    """A Sentinel's ``waf`` result in the shape ``cveFeed.waf_scan.run_wafw00f`` returns, through the same product rule (``waf_scan._named``)."""
    from cveFeed import waf_scan
    products = waf_scan._named((p.get('name'), p.get('manufacturer')) for p in (result.get('products') or [])[:waf_scan.MAX_PRODUCTS])
    return {'products': products, 'generic': result.get('generic') is True and not products, 'error': ''}


# nmap_full and nmap_verify: one address, the raw report read by cveFeed.nmap_scan.parse_xml --------------------------------------------------

def nmap_hosts(xml, address):
    """The host records of a Sentinel's raw nmap report, read by ``cveFeed.nmap_scan.parse_xml`` (strict, hardened against a custom ENTITY
    declaration) and cut to ``address``: a report that names any other host never puts it in the inventory."""
    from cveFeed.nmap_scan import parse_xml
    return [h for h in parse_xml(xml or '', strict=True) if h.get('ip') == address]


def _scanner_first(project, kind):
    """``scanner_or_local`` for work that has a project only when its address is attached to one: no project means here when the kind may run here,
    else ``ScannerUnavailable``."""
    if project is not None:
        return scanner_or_local(project, kind)
    if not fallback_allowed(kind):
        from reNgine.resources import ScannerUnavailable
        raise ScannerUnavailable(kind, 'the address is attached to no project a scanner could take it for')
    return False


def try_nmap_full(project, address, scan=None):
    """The host records (``nmap_hosts``) of a full TCP sweep of ``address`` on a Sentinel, or ``None`` to sweep it here (no Sentinel took it and
    nmap_full may run here). Raises ``ScannerUnavailable`` when it may not."""
    if not _scanner_first(project, 'nmap_full'):
        return None
    result = dispatch_or_none(project, 'nmap_full', {'address': address}, ips=[address], scan=scan)
    return None if result is None else nmap_hosts(result.get('xml'), address)


def nmap_verify_target(address, ports, version_all=False, intensity=None, scripts=(), host_timeout=None):
    """The ``nmap_verify`` target: service detection on ``ports`` of ``address``, at full intensity (``version_all``) or ``intensity``, with the named safe
    NSE scripts (a Sentinel runs only the ones on its own reviewed list) and a per-host timeout in seconds."""
    target = {'address': str(address), 'ports': sorted({int(p) for p in ports})[:MAX_ADDRESSES]}
    if version_all:
        target['version_all'] = True
    elif intensity is not None:
        target['version_intensity'] = int(intensity)
    names = [n for n in (scripts or []) if n]
    if names:
        target['scripts'] = names[:12]
    if host_timeout:
        target['host_timeout'] = max(10, min(600, int(host_timeout)))
    return target


def try_nmap_verify(project, target, scan=None):
    """The host records (``nmap_hosts``) of an ``nmap_verify`` task on a Sentinel, or ``None`` to run it here. Raises ``ScannerUnavailable`` when it
    may not run here."""
    if not _scanner_first(project, 'nmap_verify'):
        return None
    result = dispatch_or_none(project, 'nmap_verify', target, ips=[target['address']], scan=scan)
    return None if result is None else nmap_hosts(result.get('xml'), target['address'])


# node2shell: the vendored detector on the scanner, the detector's own result shape ---------------------------------------------------------

def node2shell_outcome(result):
    """A Sentinel's ``node2shell`` result in the detector's own result shape (the detector's own dict)."""
    return {'vulnerable': result.get('vulnerable'), 'verdict': result.get('verdict') or '', 'reason': result.get('reason') or '',
            'status_code': result.get('status_code'), 'response': result.get('evidence') or ''}


# rdp_shot: the PNG comes back, the reading of it stays here -----------------------------------------------------------------------------------

def rdp_image(result):
    """The PNG bytes of a Sentinel's ``rdp_shot`` result (``clean_result`` checked them), or ``None`` when nothing was painted."""
    import base64
    if not result.get('painted') or not result.get('image'):
        return None
    return base64.b64decode(result['image'])


# path_probe: the built-in scanner's own path -------------------------------------------------------------------------------------------------

def try_path_probe(groups):
    """The path survey rows (``cveFeed.path_probe.survey``'s shape) from the built-in scanner, one task per project of ``groups`` (``{project_id: [(ip,
    port)]}``, so no task names another tenant's address), or ``None`` to survey from here. Raises ``ScannerUnavailable`` when the built-in scanner
    cannot take it and the survey may not run here."""
    from reNgine.resources import ScannerUnavailable
    projects = [(p, targets) for p, targets in ((_project_of(pid), t) for pid, t in groups.items()) if p is not None]
    if not projects:
        return None
    if not any(any_scanner_for(p, 'path_probe') for p, _t in projects):
        _no_scanner('path_probe', projects[0][0])
        return None
    rows = []
    for project, targets in projects:
        if not any_scanner_for(project, 'path_probe'):
            continue
        result = dispatch_or_none(project, 'path_probe', {'targets': [{'ip': ip, 'port': port} for ip, port in targets]},
                                  ips=[ip for ip, _port in targets])
        if result is not None:
            rows.extend(result.get('results') or [])
    if not rows and not fallback_allowed('path_probe'):
        raise ScannerUnavailable('path_probe', 'the built-in scanner returned no path survey')
    return rows


# nuclei_validate: an AI-written or approved template, on the built-in scanner --------------------------------------------------------------

def _carrier_project(project):
    """The project a ``nuclei_validate`` task in mode ``validate`` is filed under: the one the work is for, else the oldest. The task carries only a
    template written from public CVE data, never a host, and only the built-in scanner, whose scope is the whole instance, takes the kind."""
    if project is not None and not isinstance(project, int):
        return project
    from dashboard.models import Project
    return _project_of(project) if project else Project.objects.select_related('org').order_by('id').first()


def nuclei_validate_ready(project=None):
    """Raise ``ScannerUnavailable`` when a new template could not be checked now (no live built-in scanner, and nuclei may not run here), so the
    AI is not asked for one first. Records nothing."""
    if fallback_allowed('nuclei_validate'):
        return
    carrier = _carrier_project(project)
    if carrier is None or not any_scanner_for(carrier, 'nuclei_validate'):
        from reNgine.resources import ScannerUnavailable
        raise ScannerUnavailable('nuclei_validate', 'no live built-in scanner can check a new template')


def try_nuclei_validate(text, project=None):
    """``(valid, output, fixture_ok, fixture_note)`` for a template's syntax check and benign-fixture run on the built-in scanner, or ``None`` to run
    them here. Raises ``ScannerUnavailable`` when the scanner cannot take it and nuclei may not run here."""
    carrier = _carrier_project(project)
    if not _scanner_first(carrier, 'nuclei_validate'):
        return None
    result = dispatch_or_none(carrier, 'nuclei_validate', {'mode': 'validate', 'template': text})
    if result is None:
        return None
    return result.get('valid') is True, result.get('output') or '', result.get('fixture_ok'), result.get('fixture_note') or ''


NOT_REPORTED = 'not tested: the scanner reported no result for this host'


def try_template_test(text, hosts, project):
    """The outcomes (``cveFeed.templategen._run_template``'s shape, one per host in order) of the approved template ``text`` run on the built-in
    scanner against ``hosts`` of ``project`` (the project the hosts belong to), in tasks of at most ``MAX_ADDRESSES``; ``None`` to run them all
    here. An entry is ``None`` for a host whose chunk no Sentinel finished and that may run here. A host a finished chunk left out, or one that
    may not run here while no scanner can take it, is reported as not tested (an error outcome), so it stays due."""
    from reNgine.resources import ScannerUnavailable
    project = _project_of(project) if isinstance(project, int) else project
    if not _scanner_first(project, 'nuclei_validate'):
        return None
    hosts = list(hosts)
    chunks = _chunks(hosts)
    by_host, local, waiting = {}, set(), None
    try:
        with contextlib.closing(dispatch_many(project, 'nuclei_validate', chunks, labeler=_targets_label,
                                              prepare=lambda chunk: ({'mode': 'test', 'template': text, 'targets': list(chunk)}, []))) as results:
            for index, result in results:
                if result is None:
                    local.update(chunks[index])  # through _no_local already: it may run here
                    continue
                for outcome in result.get('outcomes') or []:
                    by_host.setdefault(outcome['host'], outcome)
    except ScannerUnavailable as exc:
        waiting = exc
    out = []
    for host in hosts:
        if host in by_host:
            out.append(by_host[host])
        elif host in local and waiting is None:
            out.append(None)
        else:
            error = f'not tested: no scanner could take this work ({waiting.kind})' if waiting else NOT_REPORTED
            out.append({'host': host, 'vulnerable': False, 'output': '', 'error': error})
    return out
