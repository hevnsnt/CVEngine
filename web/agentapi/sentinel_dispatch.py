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
# the wait ends then, so the ceiling only bounds a Sentinel that is alive but never finishes.
COMPLETION_CEILING = {'nmap': 900, 'naabu': 600, 'nuclei_light': 900, 'nuclei_targeted': 1800, 'nuclei_deep': 3600, 'testssl': 600,
                      'nmap_udp': 900, 'wpscan': 1800, 'openvas': 3600, 'discover': 1200}
DEFAULT_CEILING = 900
# Added to a kind's ceiling for each target beyond the first (an address of a chunk, a nuclei target): a chunk of 64 addresses takes longer than one.
PER_TARGET_SECONDS = {'nmap': 15, 'naabu': 10, 'nuclei_light': 20, 'nuclei_targeted': 30, 'nuclei_deep': 60}
DEFAULT_QUEUE_SECONDS = 300  # how long a stage waits for a free Sentinel slot when every live, eligible Sentinel is at its limit
REAP_EVERY = 10  # seconds between checks for a Sentinel whose lease ran out while a stage waits


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


def stage_parallel():
    """CVENGINE_STAGE_PARALLEL: the hard ceiling on how many chunk tasks one scan stage keeps in flight across Sentinel slots (default 4).
    ``1`` is the serial behaviour of before this existed: one chunk task at a time, each waited for before the next is created."""
    try:
        return max(1, int(os.environ.get('CVENGINE_STAGE_PARALLEL', str(DEFAULT_STAGE_PARALLEL))))
    except ValueError:
        return DEFAULT_STAGE_PARALLEL


class _Dispatch:
    """One dispatched SentinelTask and its wait: the state ``dispatch_or_none`` keeps for a single task, as an object, so a stage that sends
    several chunks at once (``dispatch_many``) can wait for all of them in one loop. ``step`` is one look at a freshly read task row."""

    def __init__(self, project, kind, target, host, ips, scan, timeout, created_by, priority, internal, capacity, label=None, siblings=None):
        from agentapi.models import SentinelTask
        from cveFeed import activity
        self.project, self.kind, self.scan, self.internal = project, kind, scan, internal
        self.siblings = siblings  # a callable for a fanned-out chunk: the other chunk tasks of the same stage, which a slot of this one's waits on
        targets = len(ips or []) or len((target or {}).get('targets') or (target or {}).get('hosts') or []) if isinstance(target, dict) else len(ips or [])
        self.timeout = _dispatch_timeout(kind, targets) if timeout is None else timeout
        self.task = SentinelTask.objects.create(project=project, scan=scan, kind=kind, target=target, host=(host or '')[:500],
                                                ips=list(ips or [])[:MAX_ADDRESSES], priority=priority, created_by=created_by)
        self.label = label or _label(host, ips)
        self.busy = capacity['state'] == 'busy'
        self.entry = activity.log('run_check', (f'Queued {kind} work for {self.label}: all {capacity["slots"]} Sentinel slot(s) are in use, waiting for one'
                                                if self.busy else f'Handed {kind} work for {self.label} to a Sentinel'),
                                  project=project, status='running', scan_id=getattr(scan, 'id', None), sentinel_task_id=self.task.pk)
        self.started = time.monotonic()
        self.queue_budget = _queue_timeout(kind)
        self.claim_deadline = self.started + (self.queue_budget if self.busy else min(_claim_timeout(), self.timeout))
        self.run_deadline = None  # set once a Sentinel holds the task: the completion budget counts from the claim, not from the queueing
        self.never_claimed = False

    @property
    def finished(self):
        return self.task.status in TERMINAL

    def step(self, now, no_sentinel_left=False):
        """Act on the task as it was just read: start the completion clock once it is claimed, and give it up (expire it, so the stage falls back)
        when the wait for a Sentinel or for its report ran out. Returns True once the task is over. ``no_sentinel_left`` is set by the loop
        after a reap that found no live, eligible Sentinel any more."""
        from agentapi import sentinel_broker
        task = self.task
        if task.status in TERMINAL:
            return True
        if no_sentinel_left and task.status == 'queued':
            self.never_claimed = True  # the last live Sentinel went away while the task waited: nothing will take it
            sentinel_broker.expire(task, 'no live Sentinel is left to take the task; the stage fell back to local execution')
            return True
        if task.status in ('claimed', 'running') and self.run_deadline is None:
            self.run_deadline = now + self.timeout
        if task.status == 'queued' and now >= self.claim_deadline:
            others = [t.pk for t in self.siblings()] if self.siblings else []
            if (not self.busy and now < self.started + self.queue_budget
                    and sentinel_broker.capacity_state(self.project, self.kind, self.internal, exclude=[task.pk, *others])['state'] == 'busy'):
                self.busy, self.claim_deadline = True, self.started + self.queue_budget  # another stage took the free slot first: wait for the next one
                return False
            hold = self._sibling_hold()
            if hold:
                self.claim_deadline = now + hold  # waiting behind its own stage's chunks, which are being worked: not a reason to run it here
                return False
            self.never_claimed = True
            sentinel_broker.expire(task, ('no Sentinel slot freed up in time; the stage fell back to local execution' if self.busy
                                          else 'no Sentinel claimed the task in time; the stage fell back to local execution'))
            return True
        if self.run_deadline is not None and now >= self.run_deadline:
            sentinel_broker.expire(task, 'the dispatch wait timed out; the stage fell back to local execution')
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

    def pause(self, now):
        """Seconds to sleep before the next look."""
        horizon = self.run_deadline if self.run_deadline is not None else self.claim_deadline
        return min(DISPATCH_POLL_INTERVAL, max(0.0, horizon - now))

    def settle(self):
        """Close the activity line of the task that is over, saying what became of it."""
        from cveFeed import activity
        task, kind, label, busy = self.task, self.kind, self.label, self.busy
        sentinel = task.agent.name if task.agent_id else None
        if task.status == 'done':
            activity.settle(self.entry, 'done', message=f'Sentinel {sentinel} checked in {kind} work for {label}' if sentinel
                            else f'A Sentinel checked in {kind} work for {label}')
        elif task.status == 'failed':
            reason = (task.error or (task.result or {}).get('error') or 'no reason given')[:180]
            activity.settle(self.entry, 'failed', message=(f'Sentinel {sentinel} reported {kind} failed for {label}: {reason}' if sentinel
                            else f'A Sentinel reported {kind} failed for {label}: {reason}'))
        elif self.never_claimed:
            activity.settle(self.entry, 'expired', message=(f'No Sentinel slot freed up for {kind} work for {label} in time; it ran locally instead' if busy
                                                            else f'No Sentinel picked up {kind} work for {label} in time; it ran locally instead'))
        else:  # claimed, but not reported back before the completion timeout
            activity.settle(self.entry, 'expired', message=f'No Sentinel checked in {kind} work for {label} in time; it ran locally instead')

    def cancel(self, reason):
        """Hand the task back unfinished (the stage was stopped, or its consumer went away): expired, so it is neither claimed nor left queued."""
        from agentapi import sentinel_broker
        from cveFeed import activity
        if self.task.status in TERMINAL:
            return
        sentinel_broker.expire(self.task, reason)
        activity.settle(self.entry, 'expired', message=f'{self.kind} work for {self.label} was cancelled: {reason}')

    @property
    def result(self):
        return self.task.result if self.task.status == 'done' else None


def dispatch_or_none(project, kind, target, host='', ips=None, scan=None, timeout=None, created_by=None, priority=1, redact_target=None,
                     internal=False):
    """Create one SentinelTask for ``kind`` and wait for it, or return ``None`` at once with no side effect when no live,
    eligible Sentinel exists for ``project`` right now. Returns the task's typed ``result`` dict on success; ``None`` on
    timeout, failure, or no Sentinel - in every one of those cases the caller runs the tool locally instead. The hand-off
    and the check-in each get one ``run_check`` activity line (same kind every other scan-stage line already uses, so
    both the Live page and the Activity page show them with no changes of their own), so it is visible, in one place,
    whenever work actually left this server for a Sentinel and whether it came back.

    ``redact_target``, when given, is called with ``target`` once the task reaches a terminal state (done, failed or
    expired) and its return value replaces the stored ``target`` in the database - for a kind whose target carries a
    secret the Sentinel needed only for this one run (today, only WPScan's API token), so the secret does not sit in
    the database for the rest of the task's retention window once nothing needs it there any more."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    capacity = sentinel_broker.capacity_state(project, kind, internal)
    if capacity['state'] == 'none':
        return None
    work = _Dispatch(project, kind, target, host, ips, scan, timeout, created_by, priority, internal, capacity)
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
            none_left = work.task.status == 'queued' and sentinel_broker.capacity_state(project, kind, internal)['state'] == 'none'
        if work.step(now, none_left):
            break
        time.sleep(work.pause(now))
    work.settle()
    if redact_target is not None:
        SentinelTask.objects.filter(pk=work.task.pk).update(target=redact_target(target))
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
    does not take every slot), and ``CVENGINE_STAGE_PARALLEL`` (default 4). The free slots and the other scans are read again on every refill, so
    a slot another stage took is not counted on; the instance's slot total is read once, when the stage starts. When no live Sentinel is left, or one never claims a
    task, no more chunks are sent: that chunk and every chunk not yet sent are yielded as ``None`` after the in-flight ones finish. A chunk
    that failed or expired after a Sentinel took it falls back alone, and the rest carry on.

    With ``CVENGINE_STAGE_PARALLEL=1`` (and for a single chunk) this is the serial loop of before: one ``dispatch_or_none`` per chunk, in order;
    ``stop_on_none`` ends it at the first chunk nobody did, the way nmap and naabu always have.

    ``prepare(chunk)`` returns ``(target, ips)`` for the task, or ``None`` for a chunk that must not be dispatched (yielded as ``None``);
    by default the target is ``{'addresses': chunk}``. A stop or global pause while waiting cancels every outstanding chunk task (expired, none
    left queued or claimed) and raises ``resources.ScanAborted``; so does closing the generator early."""
    chunks = [list(c) for c in chunks]
    if not chunks:
        return
    prepare = prepare or (lambda chunk: ({'addresses': chunk}, chunk))
    if stage_parallel() <= 1 or len(chunks) == 1:
        yield from _dispatch_serially(project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none)
        return
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from reNgine import resources
    ceiling = stage_parallel()
    total = sentinel_broker.total_slots()
    pending = list(range(len(chunks)))  # chunk indexes not sent yet, in order
    flying = {}  # index -> _Dispatch
    unserved = []  # indexes nobody took (not dispatched, or fan-out stopped before them)
    halted, last_reap, last_refill, last_stop = False, time.monotonic(), None, time.monotonic()

    def mine_queued():
        return [d.task.pk for d in flying.values() if d.task.status == 'queued']

    def refill(now):
        """Create the chunk tasks the window has room for. Returns what it could not send as nobody's (``halted``)."""
        nonlocal halted, last_refill
        last_refill = now
        capacity = sentinel_broker.capacity_state(project, kind, internal, exclude=mine_queued())
        if capacity['state'] == 'none':
            halted = True
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
                    over.append((index, d.result))
            if pending and not halted and (over or now - last_refill >= REFILL_EVERY):
                refill(now)  # before the results are handed over, so the slots do not wait on the caller's own work
            for index, result in sorted(over, key=lambda pair: pair[0]):
                yield index, result
            if flying:
                time.sleep(min([d.pause(now) for d in flying.values()] + [DISPATCH_POLL_INTERVAL]))
    finally:
        for d in flying.values():
            d.cancel('the stage stopped before the task finished')
    for index in sorted(unserved + pending):
        yield index, None


def _dispatch_serially(project, kind, chunks, prepare, scan, timeout, created_by, priority, internal, stop_on_none):
    """``dispatch_many`` with a window of one: the chunks one after another through ``dispatch_or_none``, as a stage always did."""
    ended = False
    for index, chunk in enumerate(chunks):
        prepared = None if ended else prepare(chunk)
        if prepared is None:
            yield index, None
            continue
        target, ips = prepared
        kwargs = {'internal': True} if internal else {}
        if created_by is not None:
            kwargs['created_by'] = created_by
        if priority != 1:
            kwargs['priority'] = priority
        result = dispatch_or_none(project, kind, target, ips=ips, scan=scan, timeout=timeout, **kwargs)
        if result is None and stop_on_none:
            ended = True  # the first chunk no Sentinel took ends the dispatching: it and the rest run here
        yield index, result


# --- nmap: dispatch a chunk of addresses, persist a hit through the exact same function local nmap uses ---------------

def try_nmap(project, scan, targets, org_id=None, timeout=None, ports_by_ip=None):
    """Return local targets, Sentinel totals, and the local port plan.

    An address is covered only when the Sentinel reports a host row. When naabu found ports that the Sentinel did not
    report scanning, the local pass fingerprints just those ports. An absent host row keeps the whole local fallback.
    """
    targets = list(targets)
    zero = {'ports': 0, 'hosts_with_os': 0}
    local_ports = dict(ports_by_ip) if ports_by_ip is not None else None
    if not any_scanner_for(project, 'nmap'):
        return targets, zero, local_ports
    from cveFeed.nmap_scan import persist_inventory
    # every chunk of MAX_ADDRESSES goes to a Sentinel (a batch of hosts has more addresses than one task takes), several at once when there are
    # free slots; a chunk no Sentinel did is simply not reported, and what the caller fingerprints here is every address without a report
    totals, reported = None, {}
    chunks = _chunks(targets)
    with contextlib.closing(dispatch_many(project, 'nmap', chunks, scan=scan, timeout=timeout, stop_on_none=True)) as results:
        for index, result in results:
            if result is None:
                continue
            chunk = chunks[index]
            inventory = [{'ip': host['ip'], 'os_guess': host.get('os_guess', ''), 'os_accuracy': None, 'ports': host.get('ports', [])}
                         for host in result.get('hosts', []) if host.get('ip') in chunk]
            done = persist_inventory(inventory, org_id=org_id, os_reliable=result.get('os_reliable') is not False)  # the Sentinel's own network, unless it says it sits behind Docker Desktop's
            totals = done if totals is None else {key: totals.get(key, 0) + done.get(key, 0) for key in set(totals) | set(done)}
            for host in inventory:
                reported.setdefault(host['ip'], set()).update(p.get('number') for p in host['ports'])
    if totals is None:
        return targets, zero, local_ports
    remaining = []
    for ip in targets:
        if ip not in reported:
            remaining.append(ip)
        elif local_ports is not None and ip in local_ports:
            missing = sorted(set(local_ports[ip]) - reported[ip])
            if missing:
                local_ports[ip] = missing
                remaining.append(ip)
    return remaining, totals, local_ports


# --- testssl: one host:port at a time, the Sentinel's raw report items run through the same local evaluate() -----------

def try_testssl(project, host, ip, port, starttls=None, scan=None, timeout=None):
    """A Sentinel's testssl.sh report items for ``host:port`` (raw, in the exact shape ``cveFeed.testssl_scan.evaluate``
    already reads from a local run), or ``None`` when no Sentinel is eligible, on timeout, or on failure - in which case
    the caller runs ``run_testssl`` locally exactly as before. Unlike nmap/naabu/nuclei this is never chunked: a testssl
    run is already one host:port per call, locally or dispatched."""
    if not any_scanner_for(project, 'testssl'):
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
        return None
    result = dispatch_or_none(project, 'nmap_udp', {'address': ip_address}, ips=[ip_address], scan=scan, timeout=timeout)
    if result is None:
        return None
    from cveFeed.nmap_scan import parse_xml
    return next((h for h in parse_xml(result.get('xml') or '') if h.get('ip') == ip_address), None)


# --- naabu: an injectable runner wrapping cveFeed.naabu_scan.discover's own seam, untouched otherwise ------------------

def wrap_naabu_runner(project, scan, timeout=None):
    """A ``runner(ips) -> {ip: [open ports]}`` for ``naabu_scan.discover``'s own ``runner`` parameter, or ``None`` when no
    Sentinel is eligible (so ``discover`` uses its unmodified default, ``run_naabu``, exactly as today). The addresses a
    Sentinel actually attempted (its whole chunk, whether or not each had an open port: no entry means none, exactly as
    naabu's own JSON output already means) are never scanned locally too; anything beyond one chunk, or left over on a
    timeout, falls back to the real, unmodified ``naabu_scan.run_naabu``."""
    if not any_scanner_for(project, 'naabu'):
        return None

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
        if unserved:
            found.update(run_naabu([ip for index in sorted(unserved) for ip in chunks[index]]))
        return found
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
    that a Sentinel's typed, clipped result never does (the raw request/response transcript, a curl command) are left
    out, not guessed: the untyped nuclei line already tolerates them being absent. ``matcher-name`` is carried through from
    the Sentinel's own ``matcher_name`` field so a tech-detect template hit names a technology the same way
    ``cveFeed.nuclei_scan.tech_name_from`` already reads it from a locally-run nuclei line."""
    return {'host': finding.get('host') or finding.get('matched_at') or '', 'matched-at': finding.get('matched_at') or '',
            'type': 'http', 'template': finding.get('template_id') or '', 'template-id': finding.get('template_id') or '',
            'template-url': [], 'matcher-name': finding.get('matcher_name') or '', 'curl-command': None, 'request': None,
            'response': None, 'extracted-results': finding.get('extracted_results') or [],
            'info': {'name': finding.get('name') or '', 'severity': finding.get('severity') or 'unknown',
                     'description': finding.get('description') or '', 'classification': {}, 'reference': [],
                     'tags': finding.get('tags') or []}}


def _nuclei_target(kind, targets, kwargs):
    """The target of a dispatched nuclei task: the targets, the tags and severities this pass would run with locally, and the template policy the
    local run applies. The light pass is nuclei's technology fingerprint (``-tags tech -severity info``): ``run_light_nuclei`` asks for it with a
    ``tech`` flag only the unwrapped local stream takes, so the Sentinel is told the same here, or it would run the whole template library at
    every severity and the stage would time out. ``etags`` are the tags the local run always leaves out (``nuclei_scan.BASE_FLAGS``, ``dos``) and
    ``template_policy`` names the template policy in force (the read-only set, or everything when an administrator allowed it), so the client runs
    nothing this server would not; its ``bundle_sha256`` is the sha256 of the approved template archive the client fetches from
    ``GET /api/v1/sentinel/template-policy/bundle`` (``None`` until that archive exists: it is packed here when the approved snapshot is already
    cached, else on the first policy request)."""
    from agentapi import template_bundle
    from cveFeed import nuclei_scan
    tags, severities = sorted(kwargs.get('tags') or []), list(kwargs.get('severities') or [])
    if kind == 'nuclei_light' or kwargs.get('tech'):
        tags, severities = ['tech'], ['info']
    flags = nuclei_scan.BASE_FLAGS
    etags = flags[flags.index('-etags') + 1].split(',') if '-etags' in flags else []
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
        return stream_nuclei

    def stream(targets_file, **kwargs):
        if kwargs.get('secret_file'):
            # a signed-in pass (cveFeed.auth_nuclei) runs here: the stored credential never goes to a Sentinel, and a dispatched run would be
            # signed out while its findings were labelled as seen while signed in
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        try:
            with open(targets_file, encoding='utf-8') as handle:
                targets = [line.strip() for line in handle if line.strip()]
        except OSError:
            targets = []
        if not targets:  # nothing readable to send: the local run decides what an empty or missing list means
            yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
            return
        chunks = _chunks(targets)  # one task per chunk of MAX_ADDRESSES, several at once: the caller marks the whole list scanned, so none may be dropped

        def prepare(chunk):
            live = resolvable_targets(chunk)
            # nothing in the chunk resolves (a Sentinel would be asked to do nothing, and nuclei cannot reach what cannot be looked up either: run it
            # anyway so the existing "ran, found nothing" accounting is unchanged): this chunk runs here
            return (_nuclei_target(kind, live, kwargs), []) if live else None
        unserved = []
        with contextlib.closing(dispatch_many(project, kind, chunks, prepare=prepare, scan=scan, timeout=timeout, labeler=_targets_label)) as results:
            for index, result in results:
                if result is None:
                    unserved.append(index)  # no Sentinel took it: it runs here once the Sentinels' chunks are in, so they never wait on it
                    continue
                for finding in result.get('findings', []):
                    yield _finding_to_nuclei_line(finding)
        for index in sorted(unserved):
            if len(targets) <= MAX_ADDRESSES:  # the whole list is this chunk: the caller's own file
                yield from stream_nuclei(targets_file, **_local_kwargs(kind, kwargs))
                continue
            with _targets_file(chunks[index]) as path:
                yield from stream_nuclei(path, **_local_kwargs(kind, kwargs))
    stream.chunks_itself = True  # the caller hands over the whole list: this splits it and runs the chunks side by side
    return stream


# --- wpscan: a wrapping runner(url, token) -> report, like cveFeed.wpscan_scan's own seam ------------------------------

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
        return run_wpscan_process

    def runner(url, token):
        from cveFeed.wpscan_scan import _classify
        result = dispatch_or_none(project, 'wpscan', {'url': url, 'token': token}, scan=scan, timeout=timeout,
                                  redact_target=lambda t: {**t, 'token': '***'} if t.get('token') else t)
        if result is None:
            return run_wpscan_process(url, token)
        return _classify(result.get('report'), result.get('returncode', 1), result.get('stderr_tail', ''), token)
    return runner
