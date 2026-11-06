"""Asynchronous stages (queue Q4, docs/SCANNER-ARCHITECTURE.md, "Asynchronous stages").

A stage that hands work to a Sentinel used to hold its Celery worker for the whole wait, polling the task row, so the number of scans in
flight was capped by the number of workers. Here a stage that has to wait for a Sentinel gives its worker back instead: its waits are written
to a ``StageRun`` row, the worker returns, and when the last task it waits on ends (a report, a failure, an expiry, a cancel) a completion
callback (``resume``, a Celery task) continues the stage from where it stopped, then the rest of the pipeline.

How a stage is continued (replay). A stage is ordinary code that calls ``sentinel_dispatch.dispatch_or_none`` or ``dispatch_many``. Inside a
StageRun those calls are keyed (``task_key``: the kind and the target): the first time a key is asked for, the task is created and the pass
stops (``Suspend``, a ``BaseException``, so no ``except Exception`` of the stage swallows it); the callback runs the same stage code again, and
this time the call finds the task it made, over, and returns its result exactly as the blocking wait would have (the same activity lines, the
same ``_no_local`` decision and ``ScannerFallback`` row, the same ``ScannerUnavailable``). A stage with two waits in a row (the port sweep, then the fingerprint)
simply stops twice. Everything the stage does before its waits is done again on every pass, so it must be safe to repeat: the ledger makes the
scan stages so (a port sweep that was recorded is not run again), ``once`` keeps a step that is not (a pipeline stage that finished, a row
that was written), activity lines said in an earlier pass are not said again (``activity.log`` asks ``repeated_activity``), a fallback row is
written once per decision, and a ledger claim taken in a pass is held, not released, while the run waits (``hold_claim``).

The waits a blocking stage did itself are done by ``drive``: the claim budget (a task nobody claimed in time is expired), the queue budget,
the completion budget counted from the claim, the reap of a Sentinel that stopped heartbeating, the last Sentinel leaving, and a stop of the scan.
``drive`` runs at the moment the next budget ends (a Celery countdown), at least once a minute, and from the minute tick (``tick``), which also
re-drives a run that was orphaned (a worker restarted mid-pass, a callback message lost): nothing is lost to a restart.

The adapter. A stage needs three things to run this way (see the architecture doc for an example):

1. ``@stage_runs.adapter('<name>', queue='<celery queue>')`` on a function ``body(context) -> result`` that continues the work from a JSON
   ``context`` (ids and flags; never a credential, never an object);
2. at its entry point, ``stage_runs.run('<name>', context, first=<callable>, project=..., scan=..., then=...)`` instead of calling the work
   directly. ``first`` is the work itself for this first pass (it may hold objects the context does not); ``run`` returns its result, or the
   ``waiting`` marker (``is_waiting``) when it handed the work to Sentinels; ``then`` (``('<continuation>', {args})``) names a
   ``@stage_runs.continuation`` that receives the result when a later pass finishes it, for a caller that does something with the result;
3. code before its waits that is safe to repeat, or wrapped in ``once``.

A context that cannot be stored as JSON (a test that injects a runner) or ``CVENGINE_ASYNC_STAGES=0`` runs the stage blocking, as before.
"""
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.db import transaction
from django.db.models import F
from django.utils import timezone

logger = logging.getLogger(__name__)

ENV = 'CVENGINE_ASYNC_STAGES'
LEASE = timedelta(minutes=5)  # a pass in progress keeps this lease alive; a run whose lease ran out lost its worker
LEASE_REFRESH_SECONDS = 60
DRIVE_EVERY_SECONDS = 60  # a waiting run is looked at at least this often (a stop of its scan, a held claim to keep alive)
READY_GRACE = timedelta(minutes=2)  # a run whose callback was queued this long ago and never started is queued again
WAIT_GRACE = timedelta(minutes=2)  # a waiting run whose deadline passed this long ago without a drive is driven by the tick
HOLD_SECONDS = 300  # a claim held for a waiting run lives this long unless the drive renews it
HISTORY_KEEP = 50
DRIVE_QUEUE = 'cve_feed_queue'
WAITING = 'waiting'


class Suspend(BaseException):
    """Raised inside a pass when the stage has to wait for a Sentinel: the pass ends, the worker is given back. A ``BaseException`` so that a
    stage's own ``except Exception`` never mistakes it for a failure."""


ADAPTERS = {}
CONTINUATIONS = {}
_local = threading.local()
# The modules that register adapters and continuations when they are imported: a callback imports them all first, since the worker that runs
# it may not have imported the one that made the run. A track that adds an adapter adds its module here.
ADAPTER_MODULES = ('cveFeed.discovery', 'cveFeed.internal_scan', 'cveFeed.internal_discovery', 'cveFeed.tls_audit', 'cveFeed.udp_scan',
                   'cveFeed.wpscan_scan', 'cveFeed.openvas_scan', 'cveFeed.host_assessment', 'cveFeed.tasks')


def load_adapters():
    import importlib
    for name in ADAPTER_MODULES:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - one module that cannot load must not stop the others' callbacks
            logger.exception('could not load the stage adapters of %s', name)


def enabled():
    """``CVENGINE_ASYNC_STAGES``: on unless it is ``0``. Off, every stage waits for its Sentinel in its worker, as before Q4."""
    return os.environ.get(ENV, '1').strip().lower() not in ('0', 'false', 'no', 'off')


class _Adapter:
    def __init__(self, name, body, queue):
        self.name, self.body, self.queue = name, body, queue


def adapter(name, queue='discovery_queue'):
    """Register ``body(context) -> result`` as the way a StageRun of ``name`` is continued, on Celery queue ``queue``."""
    def register(body):
        ADAPTERS[name] = _Adapter(name, body, queue)
        return body
    return register


def continuation(name):
    """Register ``fn(result, **args)``: what a caller does with the result of a run that finished in a later pass (``run(..., then=...)``)."""
    def register(fn):
        CONTINUATIONS[name] = fn
        return fn
    return register


def is_waiting(result):
    return isinstance(result, dict) and result.get('status') == WAITING and 'stage_run' in result


def current():
    """The pass in progress in this thread (greenlet), or ``None`` outside a StageRun."""
    return getattr(_local, 'active', None)


def _storable(value):
    try:
        json.dumps(value)
        return True
    except (TypeError, ValueError):
        return False


def _jsonable(value):
    """``value`` as it reads back from the JSON column (sets as sorted lists, dates as text), so a remembered result is the same on every pass."""
    def default(obj):
        if isinstance(obj, (set, frozenset)):
            return sorted(obj, key=str)
        return str(obj)
    return json.loads(json.dumps(value, default=default))


def task_key(kind, target, host='', ips=None, internal=False, secret_ref=None):
    """The identity of one ``dispatch`` call inside a run: the kind and what it is pointed at. What may differ from pass to pass without making
    it other work is left out (a token, which the row loses once it is over; the template policy's revision and bundle)."""
    target = dict(target) if isinstance(target, dict) else {'value': target}
    target.pop('token', None)
    target.pop('template_policy', None)
    parts = [kind, target, host or '', sorted(str(i) for i in ips or []), bool(internal)]
    if secret_ref:  # signed-in work is other work than the same scan without the sign-in; absent, the key is what it always was
        parts.append(secret_ref)
    raw = json.dumps(parts, sort_keys=True, default=str)
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class Pass:
    """One pass of a StageRun's work in this worker: the run's row (unsaved until the first wait), the waits it already has, and what the
    engine remembers from earlier passes (the results of ``once``, the fallback decisions and activity lines already recorded)."""

    def __init__(self, row, adapter_name):
        self.row = row
        self.adapter = adapter_name
        self.tasks = dict(row.tasks or {})  # str(task id) -> wait state (``sentinel_dispatch._Dispatch.state``)
        engine = (row.context or {}).get('_engine') or {}
        self.memo = dict(engine.get('once') or {})
        self.fallbacks = list(engine.get('fallbacks') or [])
        self.fallback_cursor = 0
        self.activity_prev = list(engine.get('activity') or [])
        self.activity_new = []
        self.groups = dict(engine.get('groups') or {})
        self.claims = [tuple(c) for c in engine.get('claims') or []]
        self.token = engine.get('token') or uuid.uuid4().hex[:16]
        self.refill = False
        self.works = {}  # key -> restored _Dispatch, for this pass
        self.stage = row.stage or ''
        self.keys = {state['key']: tid for tid, state in self.tasks.items() if state.get('key')}

    # --- the waits ----------------------------------------------------------------------------------------------------------------------

    def work(self, key):
        """The ``_Dispatch`` this run made for ``key`` (its task read afresh), or ``None`` when the run has none yet."""
        if key in self.works:
            return self.works[key]
        tid = self.keys.get(key)
        if tid is None:
            return None
        from agentapi import sentinel_dispatch
        found = sentinel_dispatch._Dispatch.restore(self.tasks[tid], siblings=self._siblings_of(tid))
        if found is None:
            return None
        self.works[key] = found
        return found

    def _siblings_of(self, tid):
        group = self.tasks.get(tid, {}).get('group')
        if not group:
            return None

        def siblings():
            from agentapi.models import SentinelTask
            ids = [int(t) for t, s in self.tasks.items() if s.get('group') == group and t != tid]
            return list(SentinelTask._base_manager.filter(pk__in=ids))
        return siblings

    def add(self, key, work, group=None, index=None):
        """Remember a task this pass just created for ``key``."""
        tid = str(work.task.pk)
        state = work.state(key)
        if group is not None:
            state['group'], state['index'] = group, index
        self.tasks[tid] = state
        self.keys[key] = tid
        self.works[key] = work
        ids = list(self.row.task_ids or [])
        if work.task.pk not in ids:
            ids.append(work.task.pk)
        self.row.task_ids = ids

    def settled(self, work):
        """Close the activity line of a task that is over, once for the whole run (``_Dispatch.settle``)."""
        state = self.tasks.get(str(work.task.pk))
        if state is None or state.get('settled'):
            return
        work.settle()
        state['settled'] = True

    def counted(self, work):
        """Whether the fallback decision of this task was recorded already (``_Dispatch.no_local`` records it once per run)."""
        state = self.tasks.get(str(work.task.pk)) or {}
        return bool(state.get('counted'))

    def mark_counted(self, work):
        state = self.tasks.get(str(work.task.pk))
        if state is not None:
            state['counted'] = True

    def group(self, gid):
        return self.groups.setdefault(gid, {})

    def suspend(self, refill=False):
        """Stop this pass here: the stage waits for its Sentinels. ``refill``: wake the run as soon as any of its tasks ends (a fanned-out stage
        has chunks it could send then), not only when all of them did."""
        self.refill = self.refill or refill
        raise Suspend()

    # --- what earlier passes did ------------------------------------------------------------------------------------------------------

    def once(self, name, fn):
        if name in self.memo:
            return self.memo[name]
        value = fn()
        self.memo[name] = _jsonable(value)
        return value

    def fallback_seen(self, signature):
        """Whether a fallback decision with this ``signature`` (kind, reason) at this point of the pass was recorded by an earlier pass. The passes
        replay the same stage code, so the n-th decision of this pass is the n-th of the last one when the code took the same way."""
        signature = list(signature)
        if self.fallback_cursor < len(self.fallbacks) and self.fallbacks[self.fallback_cursor] == signature:
            self.fallback_cursor += 1
            return True
        self.fallbacks = self.fallbacks[:self.fallback_cursor] + [signature]
        self.fallback_cursor = len(self.fallbacks)
        return False

    def repeated_activity(self, kind, message, project_id, scan_id, status):
        """An activity line an earlier pass of this run already wrote with these words (still running, for a running one): it is not written again."""
        if not self.activity_prev:
            return None
        from cveFeed.models import AgentActivity
        rows = AgentActivity.objects.filter(pk__in=self.activity_prev, kind=kind, message=message[:500], project_id=project_id)
        if status == 'running':
            rows = rows.filter(status='running')
        for row in rows.order_by('-id'):
            if (row.detail or {}).get('scan_id') == scan_id:
                return row
        return None

    def note_activity(self, entry):
        if entry is not None and entry.pk:
            self.activity_new.append(entry.pk)

    def hold_claim(self, key, owner):
        """A Redis claim (key, owner) this pass holds that must outlive it: kept by the drive while the run waits, released when the run ends."""
        if (key, owner) not in self.claims:
            self.claims.append((key, owner))

    def claim_owner(self, service):
        return f'stagerun:{self.token}:{service}'[:120]

    # --- saving ------------------------------------------------------------------------------------------------------------------------

    def engine(self):
        return {'once': self.memo, 'fallbacks': self.fallbacks, 'activity': (self.activity_prev + self.activity_new)[-500:],
                'groups': self.groups, 'claims': [list(c) for c in self.claims], 'token': self.token, 'refill': self.refill}

    def save_waiting(self):
        """Write the run as waiting (its first save when this was the first pass) and return the wall-clock time it must next be looked at."""
        now = timezone.now()
        row = self.row
        row.tasks = self.tasks
        row.context = {**(row.context or {}), '_engine': self.engine()}
        row.state = 'waiting'
        row.stage = self.stage[:64]
        row.lease_until = None
        row.waiting_since = now
        row.deadline = next_deadline(self.tasks, now)
        history = list(row.history or [])
        history.append({'waiting_since': now.isoformat()})
        row.history = history[-HISTORY_KEEP:]
        row.save()
        return row.deadline


def next_deadline(tasks, now):
    """When a waiting run must next be looked at: the earliest budget of its open waits, and at least every ``DRIVE_EVERY_SECONDS``."""
    soon = now + timedelta(seconds=DRIVE_EVERY_SECONDS)
    for state in tasks.values():
        if state.get('over'):
            continue
        for field in ('run_deadline', 'claim_deadline'):
            value = state.get(field)
            if value:
                at = datetime.fromtimestamp(float(value), tz=dt_timezone.utc)
                if at < soon:
                    soon = at
                break  # the completion budget replaces the claim budget once the task is claimed
    return max(soon, now + timedelta(seconds=1))


# --- running a stage ---------------------------------------------------------------------------------------------------------------------

def run(name, context, first=None, project=None, scan=None, stage='', then=None):
    """Run the stage ``name`` (a registered adapter) under a StageRun: ``first()`` (or the adapter with ``context``) is this pass. Returns its
    result, or ``{'status': 'waiting', 'stage_run': id, 'stage': ...}`` when the stage handed its work to Sentinels and gave the worker back; the
    rest is done by the completion callback, which ends with the continuation ``then`` (``(name, {args})``) when one is given. Runs blocking,
    exactly as before, when asynchronous stages are off, inside a pass already (one boundary per worker), or when the context cannot be stored."""
    from agentapi.models import StageRun
    body = first or (lambda: ADAPTERS[name].body(context))
    if name not in ADAPTERS:
        raise KeyError(f'no stage adapter is registered as {name!r}')
    full = {**(context or {}), '_then': list(then) if then else None}
    if not enabled() or current() is not None or not _storable(full):
        return body()
    row = StageRun(kind=name, context=full, project=project if getattr(project, 'pk', None) else None,
                   scan=scan if getattr(scan, 'pk', None) else None, state='running', queue=ADAPTERS[name].queue, stage=stage[:64])
    if project is not None and not getattr(project, 'pk', None):
        row.project_id = project
    if scan is not None and not getattr(scan, 'pk', None):
        row.scan_id = scan
    return _execute(row, body, first_pass=True)


def add_claim(pk, key, owner):
    """A claim kept for the waiting run ``pk`` by its caller (``redis_claim(..., keep=...)``, the pipeline's domain lock): renewed by its drive,
    released when it ends."""
    from agentapi.models import StageRun
    with transaction.atomic():
        row = StageRun.objects.select_for_update().filter(pk=pk).first()
        if row is None:
            return
        engine = dict((row.context or {}).get('_engine') or {})
        claims = [list(c) for c in engine.get('claims') or []]
        if [key, owner] not in claims:
            claims.append([key, owner])
        engine['claims'] = claims
        StageRun.objects.filter(pk=pk).update(context={**(row.context or {}), '_engine': engine})


def claim_kwargs(service, owner):
    """The ``redis_claim`` arguments of a claim a stage takes: inside a run it belongs to the run (an owner of its own, taken back by a later pass
    and held while the run waits), outside one it is ``owner``'s, as before."""
    p = current()
    if p is None:
        return {'owner': owner}
    return {'owner': p.claim_owner(service), 'adopt': True, 'hold': True}


def remember(name, value):
    """Keep ``value`` (JSON) for the later passes of the run in progress (a sweep's place in its list); nothing outside a run."""
    p = current()
    if p is not None:
        p.memo[name] = _jsonable(value)


def recall(name, default=None):
    """What ``remember`` kept under ``name`` in an earlier pass of the run in progress, else ``default``."""
    p = current()
    return p.memo.get(name, default) if p is not None else default


def watch(name, task_ids, context=None, project=None, scan=None, stage=''):
    """A StageRun that waits on tasks its caller made itself (the OpenVAS sweep's, a streamed job's) rather than through ``dispatch``: when the
    last of ``task_ids`` ends, the adapter ``name`` is called back with ``context`` at once, instead of at the caller's next scheduled look. Its
    budgets are the caller's own (the broker's reaper still ends a task whose lease ran out). Returns the run's id, or ``None`` when asynchronous
    stages are off or it could not be written (the caller's schedule then finds the result, as before). Never raises."""
    from agentapi.models import StageRun
    if not enabled() or name not in ADAPTERS:
        return None
    try:
        now = timezone.now()
        row = StageRun.objects.create(kind=name, stage=(stage or name)[:64], context={**(context or {}), '_then': None},
                                      task_ids=[int(t) for t in task_ids], state='waiting', queue=ADAPTERS[name].queue,
                                      project_id=getattr(project, 'pk', project), scan_id=getattr(scan, 'pk', scan), waiting_since=now,
                                      deadline=now + timedelta(seconds=DRIVE_EVERY_SECONDS),
                                      history=[{'waiting_since': now.isoformat()}])
        _schedule_drive(row.pk, row.deadline)
        _on_commit(lambda: _try_ready(row.pk))
        return row.pk
    except Exception:  # noqa: BLE001 - the caller's own schedule still finds the result
        logger.warning('could not watch tasks %s for %s', task_ids, name, exc_info=True)
        return None


def stage(name):
    """Name the stage a pass is in (shown with a waiting run): the pipeline sets it as each stage starts."""
    p = current()
    if p is not None:
        p.stage = name or ''


def once(name, fn):
    """``fn()`` once per run: on a later pass its remembered result (as JSON) is returned and ``fn`` is not called. Outside a run, just ``fn()``."""
    p = current()
    if p is None:
        return fn()
    return p.once(name, fn)


class _LeaseKeeper:
    """Keeps a running pass's lease alive while the pass works (a long local fallback, a slow persistence), so the tick never mistakes it for
    an orphan; a pass whose worker died stops renewing it, and the tick re-drives the run once it ran out."""

    def __init__(self, pk):
        self.pk, self.stop = pk, threading.Event()

    def __enter__(self):
        if self.pk:
            threading.Thread(target=self._loop, name='stagerun-lease', daemon=True).start()
        return self

    def _loop(self):
        from agentapi.models import StageRun
        while not self.stop.wait(LEASE_REFRESH_SECONDS):
            try:
                StageRun.objects.filter(pk=self.pk, state='running').update(lease_until=timezone.now() + LEASE)
            except Exception:  # noqa: BLE001 - the next renewal tries again
                pass

    def __exit__(self, *exc):
        self.stop.set()
        return False


def _execute(row, body, first_pass):
    p = Pass(row, row.kind)
    previous = current()
    _local.active = p
    try:
        with _LeaseKeeper(row.pk):
            try:
                result = body()
            except Suspend:
                _local.active = previous
                return _waiting(p)
            except BaseException as exc:
                _local.active = previous
                _close(p, 'failed', f'{type(exc).__name__}: {exc}')
                raise
    finally:
        _local.active = previous
    _close(p, 'done')
    return result


def _waiting(p):
    deadline = p.save_waiting()
    pk = p.row.pk
    _schedule_drive(pk, deadline)
    _try_ready(pk)  # a task that ended before the run was saved has no run to wake: look now
    return {'status': WAITING, 'stage_run': pk, 'stage': p.stage, 'tasks': len(p.row.task_ids or []), 'scan_id': p.row.scan_id}


def _close(p, state, error=''):
    """End a run: its leftover running activity lines are closed, its held claims released, and its row (when it was ever saved) says how it ended."""
    from agentapi.models import StageRun
    if not p.row.pk:
        return  # it never waited: nothing differs from a stage that ran in one go
    _settle_leftovers(p)
    _release_claims(p.claims)
    if p.row.pk:
        StageRun.objects.filter(pk=p.row.pk).update(state=state, finished_at=timezone.now(), lease_until=None, error=(error or '')[:300],
                                                    tasks=p.tasks, context={**(p.row.context or {}), '_engine': p.engine()})


def _settle_leftovers(p):
    """A running line an earlier pass wrote and no later pass closed (its words changed when the stage ran again) is closed with the run."""
    ids = p.activity_prev
    if not ids:
        return
    try:
        from cveFeed.models import AgentActivity
        AgentActivity.objects.filter(pk__in=ids, status='running').update(status='done', finished_at=timezone.now())
    except Exception:  # noqa: BLE001 - the feed never fails a stage
        logger.debug('could not close the activity lines of a stage run', exc_info=True)


def _redis():
    from reNgine import resources
    return getattr(resources.get_store(), 'r', None)


def _release_claims(claims):
    client = _redis()
    if client is None:
        return
    from reNgine import resources
    for key, owner in claims:
        try:
            resources.claim_release(client, key, owner)
        except Exception:  # noqa: BLE001 - a claim left behind expires on its own
            pass


def _renew_claims(claims):
    client = _redis()
    if client is None:
        return
    from reNgine import resources
    for key, owner in claims:
        try:
            resources.claim_refresh(client, key, owner, HOLD_SECONDS)
        except Exception:  # noqa: BLE001
            pass


# --- waking ------------------------------------------------------------------------------------------------------------------------------

def _on_commit(fn):
    try:
        transaction.on_commit(fn)
    except Exception:  # noqa: BLE001
        fn()


def _schedule_drive(pk, at):
    def send():
        try:
            from cveFeed.tasks import stage_run_drive
            countdown = max(1, min(DRIVE_EVERY_SECONDS, (at - timezone.now()).total_seconds() + 0.5)) if at else DRIVE_EVERY_SECONDS
            stage_run_drive.apply_async((pk,), countdown=countdown, queue=DRIVE_QUEUE, expires=countdown + 600)
        except Exception:  # noqa: BLE001 - the minute tick drives it anyway
            logger.warning('could not queue the drive of stage run %s; the tick will', pk, exc_info=True)
    _on_commit(send)


def _send_resume(pk, queue):
    def send():
        try:
            from cveFeed.tasks import stage_run_resume
            stage_run_resume.apply_async((pk,), queue=queue or 'discovery_queue')
        except Exception:  # noqa: BLE001 - the tick queues it again
            logger.warning('could not queue the callback of stage run %s; the tick will', pk, exc_info=True)
    _on_commit(send)


def _active_ids(ids):
    from agentapi.models import SENTINEL_ACTIVE_STATUSES, SentinelTask
    return set(SentinelTask._base_manager.filter(pk__in=list(ids or []), status__in=SENTINEL_ACTIVE_STATUSES).values_list('pk', flat=True))


def _try_ready(pk, ended=None):
    """Make the waiting run ``pk`` ready and queue its callback when every task it waits on is over (or, for a run that has chunks to send,
    when ``ended``, one of its tasks, is). One caller wins (``waiting`` -> ``ready`` is one conditional update)."""
    from agentapi.models import StageRun
    row = StageRun.objects.filter(pk=pk, state='waiting').only('pk', 'task_ids', 'context', 'queue').first()
    if row is None:
        return False
    active = _active_ids(row.task_ids)
    refill = bool(((row.context or {}).get('_engine') or {}).get('refill'))
    if active and not (refill and ended is not None and ended in (row.task_ids or []) and ended not in active):
        return False
    if not StageRun.objects.filter(pk=pk, state='waiting').update(state='ready', woke_at=timezone.now()):
        return False
    _send_resume(pk, row.queue)
    return True


def task_ended(task):
    """A SentinelTask ended (reported, failed, expired, cancelled, released): wake the StageRun waiting on it at once. Never raises."""
    try:
        from agentapi.models import StageRun
        for pk in StageRun.objects.filter(state='waiting', task_ids__contains=[task.pk]).values_list('pk', flat=True)[:10]:
            if pk == getattr(_local, 'driving', None):
                continue  # the drive that expired it saves the run's waits first, then wakes it itself
            _try_ready(pk, ended=task.pk)
    except Exception:  # noqa: BLE001 - the drive and the tick wake it anyway
        logger.warning('could not wake the stage run waiting on sentinel task %s', getattr(task, 'pk', None), exc_info=True)


def wake_scan(scan_id):
    """A scan was stopped: drive its waiting runs now, so their tasks are cancelled and their stage ends, instead of at their next deadline."""
    try:
        from agentapi.models import StageRun
        for pk in StageRun.objects.filter(scan_id=scan_id, state='waiting').values_list('pk', flat=True):
            _schedule_drive(pk, timezone.now())
    except Exception:  # noqa: BLE001
        logger.debug('could not wake the stage runs of scan %s', scan_id, exc_info=True)


# --- the callback ------------------------------------------------------------------------------------------------------------------------

def resume(pk):
    """The completion callback: continue the ready run ``pk`` in this worker, from where its stage stopped. Returns the result (or the
    waiting marker when the stage stops again). A run another worker already took, or that is no longer ready, is left alone."""
    from agentapi.models import StageRun
    now = timezone.now()
    if not StageRun.objects.filter(pk=pk, state='ready').update(state='running', lease_until=now + LEASE, resumed_at=now,
                                                                rounds=F('rounds') + 1):
        return {'stage_run': pk, 'skipped': 'not ready (another worker has it, or it ended)'}
    row = StageRun.objects.get(pk=pk)
    load_adapters()
    history = list(row.history or [])
    if history:
        entry = history[-1]
        entry['woke_at'] = row.woke_at.isoformat() if row.woke_at else None
        entry['resumed_at'] = now.isoformat()
        row.history = history
        StageRun.objects.filter(pk=pk).update(history=history)
    adapter = ADAPTERS.get(row.kind)
    if adapter is None:
        StageRun.objects.filter(pk=pk).update(state='failed', finished_at=now, error=f'no adapter {row.kind!r} in this version'[:300])
        logger.error('stage run %s: no adapter %r is registered; it cannot be continued', pk, row.kind)
        return {'stage_run': pk, 'error': 'no adapter'}
    context = {k: v for k, v in (row.context or {}).items() if not k.startswith('_')}
    try:
        result = _execute(row, lambda: adapter.body(context), first_pass=False)
    except Exception as exc:  # noqa: BLE001 - recorded on the run; the adapter's own handling already ran
        logger.exception('stage run %s (%s) failed in its callback', pk, row.kind)
        result = {'status': 'failed', 'error': str(exc)[:290]}
        _then(row, result)
        return result
    if not is_waiting(result):
        _then(row, result)
    return result


def _then(row, result):
    then = (row.context or {}).get('_then')
    if not then:
        return
    name, args = then[0], (then[1] if len(then) > 1 else None) or {}
    fn = CONTINUATIONS.get(name)
    if fn is None:
        logger.error('stage run %s: no continuation %r is registered', row.pk, name)
        return
    try:
        fn(result, **args)
    except Exception:  # noqa: BLE001
        logger.exception('stage run %s: its continuation %s failed', row.pk, name)


# --- the drive: the budgets a blocking wait used to keep ---------------------------------------------------------------------------------

def drive(pk):
    """Look at the waiting run ``pk`` as the blocking wait did at each poll: reap Sentinels that stopped heartbeating, expire a task whose claim,
    queue or completion budget ran out (or whose last Sentinel left, or whose scan was stopped), keep its held claims alive, and wake it when it
    may continue. Schedules the next look. Returns what it did."""
    from agentapi import sentinel_broker, sentinel_dispatch
    from agentapi.models import StageRun
    row = StageRun.objects.filter(pk=pk, state='waiting').first()
    if row is None:
        return {'stage_run': pk, 'skipped': 'not waiting'}
    _local.driving = pk
    try:
        return _drive(row, sentinel_broker, sentinel_dispatch)
    finally:
        _local.driving = None


def _drive(row, sentinel_broker, sentinel_dispatch):
    from agentapi.models import StageRun
    pk = row.pk
    sentinel_broker.reap_expired()
    tasks = dict(row.tasks or {})
    engine = (row.context or {}).get('_engine') or {}
    groups = engine.get('groups') or {}
    expired = 0
    stopped = None
    capacity = {}
    restored = {}
    for tid, state in tasks.items():
        if state.get('over'):
            continue
        siblings_group = state.get('group')

        def siblings(tid=tid, group=siblings_group):
            from agentapi.models import SentinelTask
            ids = [int(t) for t, s in tasks.items() if s.get('group') == group and t != tid]
            return list(SentinelTask._base_manager.filter(pk__in=ids))
        work = sentinel_dispatch._Dispatch.restore(state, siblings=siblings if siblings_group else None)
        if work is None:
            state['over'] = True
            continue
        restored[tid] = work
    for tid, work in restored.items():
        state = tasks[tid]
        if work.finished:
            state['over'] = True
            continue
        if state.get('stop_check') and work.scan is not None:
            if stopped is None:
                stopped = sentinel_dispatch._stopped(work.scan)
            if stopped:
                work.cancel('the stage stopped before the task finished')
                group = groups.setdefault(state.get('group') or '', {})
                group['aborted'] = True
                state.update(work.state(state['key']), over=True, settled=True)
                expired += 1
                continue
        now = sentinel_dispatch.time.monotonic()  # the clock the waits were written in
        none_left = False
        if work.task.status == 'queued':
            ck = (work.project.pk, work.kind, work.internal)
            if ck not in capacity:
                capacity[ck] = sentinel_broker.capacity_state(work.project, work.kind, work.internal)['state'] == 'none'
            none_left = capacity[ck]
        over = work.step(now, none_left)
        keep = {k: state[k] for k in ('key', 'group', 'index', 'settled', 'counted', 'stop_check') if k in state}
        state.clear()
        state.update(work.state(keep.get('key')), **{k: v for k, v in keep.items() if k != 'key'})
        if over:
            state['over'] = True
            expired += 1
    claims = [tuple(c) for c in engine.get('claims') or []]
    _renew_claims(claims)
    deadline = next_deadline(tasks, timezone.now())
    StageRun.objects.filter(pk=pk, state='waiting').update(
        tasks=tasks, deadline=deadline, context={**(row.context or {}), '_engine': {**engine, 'groups': groups}})
    _local.driving = None
    if not _try_ready(pk):
        if StageRun.objects.filter(pk=pk, state='waiting').exists():
            _schedule_drive(pk, deadline)
    return {'stage_run': pk, 'expired': expired, 'stopped': bool(stopped)}


# --- the safety net ----------------------------------------------------------------------------------------------------------------------

def tick(now=None):
    """Every minute (and from the 15-minute reaper): re-drive what a restart or a lost message left behind. A waiting run whose deadline passed
    without a drive is driven; a ready run whose callback never started is queued again; a running run whose lease ran out (its worker died
    mid-pass) is made ready again, so its callback replays the stage. Returns the counts."""
    from agentapi.models import StageRun
    now = now or timezone.now()
    counts = {'driven': 0, 'requeued': 0, 'recovered': 0}
    for pk in StageRun.objects.filter(state='waiting', deadline__lt=now - WAIT_GRACE).values_list('pk', flat=True)[:200]:
        try:
            drive(pk)
            counts['driven'] += 1
        except Exception:  # noqa: BLE001 - one bad run never stops the others
            logger.exception('could not drive stage run %s', pk)
    for row in StageRun.objects.filter(state='ready', woke_at__lt=now - READY_GRACE).only('pk', 'queue')[:200]:
        StageRun.objects.filter(pk=row.pk, state='ready').update(woke_at=now)
        _send_resume(row.pk, row.queue)
        counts['requeued'] += 1
    for row in StageRun.objects.filter(state='running', lease_until__lt=now).only('pk', 'queue')[:200]:
        if StageRun.objects.filter(pk=row.pk, state='running', lease_until__lt=now).update(state='ready', woke_at=now, lease_until=None):
            _send_resume(row.pk, row.queue)
            counts['recovered'] += 1
    return {k: v for k, v in counts.items() if v}


def busy(name):
    """Whether a run of the adapter ``name`` is open (waiting, ready or running): a sweep that runs one at a time does not start a second."""
    from agentapi.models import StageRun
    return StageRun.objects.filter(kind=name, state__in=StageRun.OPEN_STATES).exists()


def open_scan_ids(scan_ids=None):
    """The scans with an open run: running, though no Celery task holds them while they wait (the orphan reaper leaves them alone)."""
    from agentapi.models import StageRun
    rows = StageRun.objects.filter(state__in=StageRun.OPEN_STATES, scan__isnull=False)
    if scan_ids is not None:
        rows = rows.filter(scan_id__in=list(scan_ids))
    return set(rows.values_list('scan_id', flat=True))


def prune(now=None, days=7):
    """Delete ended runs older than ``days`` (the weekly maintenance)."""
    from agentapi.models import StageRun
    now = now or timezone.now()
    return StageRun.objects.filter(state__in=('done', 'failed', 'cancelled'), finished_at__lt=now - timedelta(days=days)).delete()[0]


# --- metrics -----------------------------------------------------------------------------------------------------------------------------

def _percentile(values, q):
    from agentapi.sentinel_broker import _percentile as pct
    return pct(values, q)


def metrics(now=None, project_ids=None):
    """What Q4 adds to the utilisation numbers (``GET sentinels/live``, the system status ``sentinels.stage_runs``): ``waiting`` (the runs that wait
    for Sentinels now) and ``waiting_by_kind`` (by the stage a pipeline waits in, else by the adapter of a sweep), ``oldest_wait_seconds``,
    ``ready`` (callbacks queued, not started), ``callback_latency_p50_seconds`` and ``_p95_seconds`` (from the last task ending to the callback
    starting, over the last hour), ``slots_freed`` (the Celery worker slots the waiting runs would hold if they blocked, which is one each) and
    ``freed_seconds_1h`` (the worker time given back in the last hour), plus ``resumed_1h``. ``project_ids`` limits it to those projects (a
    viewer's); ``None`` counts every run."""
    from agentapi.models import StageRun
    now = now or timezone.now()
    rows = StageRun._base_manager.all()
    if project_ids is not None:
        rows = rows.filter(project_id__in=list(project_ids))
    waiting = list(rows.filter(state='waiting').values_list('kind', 'stage', 'waiting_since')[:5000])
    by_kind = {}
    oldest = None
    for kind, stage_name, since in waiting:
        label = stage_name if kind.startswith('pipeline') and stage_name else kind
        by_kind[label] = by_kind.get(label, 0) + 1
        if since is not None:
            age = (now - since).total_seconds()
            oldest = age if oldest is None else max(oldest, age)
    hour = now - timedelta(hours=1)
    latencies, freed, resumed = [], 0.0, 0
    for history in rows.filter(updated_at__gte=hour).values_list('history', flat=True)[:5000]:
        for entry in history or []:
            try:
                since = datetime.fromisoformat(entry['waiting_since'])
                woke = datetime.fromisoformat(entry['woke_at']) if entry.get('woke_at') else None
                back = datetime.fromisoformat(entry['resumed_at']) if entry.get('resumed_at') else None
            except (KeyError, TypeError, ValueError):
                continue
            end = woke or back or now
            start = max(since, hour)
            if end > start:
                freed += (end - start).total_seconds()
            if back is not None and back >= hour:
                resumed += 1
                if woke is not None:
                    latencies.append(max(0.0, (back - woke).total_seconds()))
    return {'enabled': enabled(), 'waiting': len(waiting), 'waiting_by_kind': dict(sorted(by_kind.items())),
            'oldest_wait_seconds': int(oldest) if oldest is not None else None,
            'ready': rows.filter(state='ready').count(),
            'callback_latency_p50_seconds': _percentile(latencies, 0.5), 'callback_latency_p95_seconds': _percentile(latencies, 0.95),
            'slots_freed': len(waiting), 'freed_seconds_1h': int(freed), 'resumed_1h': resumed}
