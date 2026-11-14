"""Runs the system status's probes so that none of them can hold the answer back.

The status used to call every probe one after the other in the request: one slow table, one peer that did not answer, and the whole call waited
(a gunicorn worker timeout at the end, or the proxy's reset). Now every probe has a deadline of its own, the whole answer has a budget, and a probe
that runs out is named in ``problems`` while the rest of the answer is still returned.

How it is bounded, and why nothing is left stuck:

* A probe runs in a short-lived daemon thread (at most ``CONCURRENCY`` at a time) and the request waits for it only until its deadline
  (``CVENGINE_STATUS_PROBE_SECONDS``, 5) or the budget of the whole answer (``CVENGINE_STATUS_BUDGET_SECONDS``, 8), whichever is first. Python cannot
  kill a thread, so what keeps an abandoned one from living on is that every wait inside a probe is bounded by itself: the thread sets a statement
  timeout and a lock timeout on its own database connection (the probe's deadline), the Redis client has socket timeouts, Celery's inspect has a
  timeout, the one version lookup of an installed tool has a timeout. A thread that was left behind therefore ends by itself, drops what it found (the answer was sent without
  it) and closes its database connection in ``finally``.
* A probe is never started twice at once: while the thread of an earlier call is still alive the probe is reported as still running instead of
  starting another (so a poller cannot pile up threads or connections behind a slow probe).
* The probes share one interpreter lock, and the inventory's counting is Python work that holds it for seconds on a small host. A thread that waits on the
  database or Redis needs the lock back after every reply and, with CPython's 5 ms switch interval, waited up to that long for each of them: a probe of one
  statement took 1 to 2 s, the queues probe (69 reads) 1.2 s next to a counting thread that took 6, and the thread of a probe that does nothing took 0.2 s to
  start. While the probes run, the switch interval is 0.5 ms (``responsive_switching``; restored when the last status call ends).
* The threads have connections of their own and so cannot see the uncommitted rows of a caller that is inside a transaction (a Django ``TestCase``,
  ``ATOMIC_REQUESTS``). Inside a transaction the probes run one after another in the calling thread instead, with their timings but without
  deadlines (nothing can interrupt them there). The server never calls it that way: it is for the tests.
"""
import contextlib
import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)

BUDGET_SECONDS = 8.0
PROBE_SECONDS = 5.0
CONCURRENCY = 4  # database connections a status call may hold at once

_inflight = {}  # probe name -> the thread of a run that has not ended yet
_inflight_lock = threading.Lock()
SWITCH_INTERVAL = 0.0005  # seconds a thread may hold the interpreter lock while another waits for it, during a status call (CPython's default is 0.005)
_switching = {'calls': 0, 'saved': None}
_switching_lock = threading.Lock()


@contextlib.contextmanager
def responsive_switching():
    """A short thread switch interval for as long as any status call runs its probes: the probes that wait on the database or Redis get the interpreter
    lock back within ``SWITCH_INTERVAL`` instead of the default 5 ms, whatever a counting thread of the same call is doing. Nested and overlapping
    calls count; the interval in force before the first is restored after the last."""
    with _switching_lock:
        if _switching['calls'] == 0:
            _switching['saved'] = sys.getswitchinterval()
            sys.setswitchinterval(min(_switching['saved'], SWITCH_INTERVAL))
        _switching['calls'] += 1
    try:
        yield
    finally:
        with _switching_lock:
            _switching['calls'] -= 1
            if _switching['calls'] == 0:
                sys.setswitchinterval(_switching['saved'])


def _env_seconds(name, default):
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        return default
    return min(60.0, max(0.5, value))


def budget_seconds():
    """CVENGINE_STATUS_BUDGET_SECONDS: how long the whole status may take (default 8, between 0.5 and 60)."""
    return _env_seconds('CVENGINE_STATUS_BUDGET_SECONDS', BUDGET_SECONDS)


def probe_seconds():
    """CVENGINE_STATUS_PROBE_SECONDS: how long one probe may take unless it has its own limit (default 5)."""
    return _env_seconds('CVENGINE_STATUS_PROBE_SECONDS', PROBE_SECONDS)


class Probe:
    """``fn(problems, notes, done)`` returns the probe's value. ``problems`` and ``notes`` are the probe's own lists (merged into the answer only when
    it finished in time); ``done`` maps the name of every probe that ended so far to its value (``{'error': ...}`` when it failed), for a probe that
    ``after`` another. ``limit`` is its own deadline in seconds (default ``probe_seconds()``); ``db`` False for a probe that never reads the database."""

    def __init__(self, name, fn, limit=None, after=None, db=True):
        self.name, self.fn, self.limit, self.after, self.db = name, fn, limit, after, db


class Result:
    """What one probe came to: ``state`` is ``ok``, ``error``, ``timeout``, ``skipped`` (the budget was gone before it started) or ``busy`` (an earlier
    call's run of it has not ended). ``seconds`` is how long it took (until its deadline for a timeout), ``line`` the sentence for ``problems``."""

    def __init__(self, name, limit):
        self.name, self.limit = name, limit
        self.state, self.value, self.error = 'pending', None, None
        self.started = self.ended = None
        self.problems, self.notes = [], []
        self.abandoned = False
        self.seconds = 0.0

    @property
    def line(self):
        if self.state == 'timeout':
            return f'{self.name}: timed out after {_s(self.seconds)} s'
        if self.state == 'skipped':
            return f'{self.name}: not run, the status budget was used up before it started'
        if self.state == 'busy':
            return f'{self.name}: not run, its previous run has not ended ({_s(self.seconds)} s so far)'
        return f'{self.name}: could not be read ({self.error})'


def _s(seconds):
    return f'{round(seconds, 1):g}'


class Run:
    def __init__(self, results, seconds, budget, threaded):
        self.results, self.seconds, self.budget, self.threaded = results, seconds, budget, threaded

    def timings(self):
        """``{'budget_seconds', 'total_seconds', 'probes': {name: seconds}, 'slow': [names that did not finish]}`` for an App Admin."""
        return {'budget_seconds': self.budget, 'total_seconds': round(self.seconds, 3),
                'probes': {name: round(r.seconds, 3) for name, r in self.results.items()},
                'not_finished': [name for name, r in self.results.items() if r.state in ('timeout', 'skipped', 'busy')]}


def _bound_database(limit):
    """The thread's own connection: no statement or lock wait longer than the probe's deadline, so a thread left behind ends by itself."""
    from django.db import connection
    if connection.vendor != 'postgresql':
        return
    ms = max(200, int(limit * 1000))
    with connection.cursor() as cursor:
        cursor.execute('SET statement_timeout = %s', [ms])
        cursor.execute('SET lock_timeout = %s', [ms])


def _body(result, probe, done, lock, wake, clock):
    from django.db import connections
    value, error = None, None
    try:
        if probe.db:
            _bound_database(result.limit)
        value = probe.fn(result.problems, result.notes, dict(done))
    except Exception as exc:  # noqa: BLE001 - a probe must never fail the whole snapshot, and never leak its message
        error = type(exc).__name__
        logger.debug('status probe %s failed', probe.name, exc_info=True)
    finally:
        try:
            connections.close_all()  # this thread's connections: nothing is left open behind a thread that ends
        except Exception:  # noqa: BLE001
            pass
        with _inflight_lock:
            if _inflight.get(probe.name) is threading.current_thread():
                del _inflight[probe.name]
        with lock:
            if not result.abandoned:
                result.state, result.value, result.error, result.ended = ('error' if error else 'ok'), value, error, clock()
        wake.set()


def _finish(result, clock):
    started = result.started if result.started is not None else clock()
    result.seconds = (result.ended if result.ended is not None else clock()) - started


def run(probes, budget=None, concurrency=CONCURRENCY, clock=time.monotonic):
    """Run ``probes`` (a list of ``Probe``, in the order the answer reads them) and return a ``Run``. Every probe ends in one of the states of
    ``Result``; nothing here raises, and the call returns within about ``budget`` seconds (a thread in the middle of a probe is left to end by itself)."""
    from django.db import connection
    budget = budget_seconds() if budget is None else budget
    started = clock()
    deadline = started + budget
    results = {p.name: Result(p.name, min(p.limit or probe_seconds(), budget)) for p in probes}
    done = {}
    threaded = not connection.in_atomic_block
    if not threaded:
        for probe in probes:
            result = results[probe.name]
            result.started = clock()
            try:
                result.value, result.state = probe.fn(result.problems, result.notes, dict(done)), 'ok'
            except Exception as exc:  # noqa: BLE001
                result.state, result.error = 'error', type(exc).__name__
            result.ended = clock()
            _finish(result, clock)
            done[probe.name] = result.value if result.state == 'ok' else {'error': result.error}
        return Run(results, clock() - started, budget, False)
    with responsive_switching():
        return _run_threaded(probes, results, done, started, deadline, budget, concurrency, clock)


def _run_threaded(probes, results, done, started, deadline, budget, concurrency, clock):
    lock, wake = threading.Lock(), threading.Event()
    pending, running = list(probes), []
    finished = set()
    while pending or running:
        wake.clear()
        now = clock()
        with lock:
            for result in list(running):
                if result.state != 'running':
                    pass
                elif now - result.started >= result.limit or now >= deadline:
                    result.abandoned, result.state, result.ended = True, 'timeout', now
                else:
                    continue
                running.remove(result)
                _finish(result, clock)
                finished.add(result.name)
                done[result.name] = result.value if result.state == 'ok' else {'error': result.error or result.state}
        while pending and len(running) < concurrency and now < deadline:
            probe = next((p for p in pending if p.after is None or p.after in finished), None)
            if probe is None:
                break
            pending.remove(probe)
            result = results[probe.name]
            with _inflight_lock:
                old = _inflight.get(probe.name)
                if old is not None and old.is_alive():
                    result.state, result.started = 'busy', getattr(old, 'status_started', now)
                    result.seconds = max(0.0, now - result.started)
                    finished.add(probe.name)
                    done[probe.name] = {'error': 'busy'}
                    continue
                thread = threading.Thread(target=_body, args=(result, probe, done, lock, wake, clock), name=f'status-probe-{probe.name}', daemon=True)
                thread.status_started = now
                _inflight[probe.name] = thread
            result.state, result.started = 'running', now
            running.append(result)
            thread.start()
        if now >= deadline:
            for probe in pending:
                results[probe.name].state = 'skipped'
            pending = []
            continue
        if not pending and not running:
            break
        soonest = min([r.started + r.limit for r in running] + [deadline])
        wake.wait(timeout=min(0.1, max(0.005, soonest - clock())))
    return Run(results, clock() - started, budget, True)


def reset():
    """Forget every probe thread (tests)."""
    with _inflight_lock:
        _inflight.clear()
