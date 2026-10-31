"""A fake built-in Sentinel for server tests (docs/SCANNER-ARCHITECTURE.md, phase 5, risk 7).

Every phase 5 PR deletes one local scan path (nmap, naabu, nuclei, testssl, nmap -sU, WPScan) from the server. That is only safe to claim if a test
can show the stage still does its job when a scanner does the work and the server runs nothing itself. This module is that scanner, plus the two
guards that make the claim checkable. It is a helper, not a test module: ``tests/test_fake_scanner.py`` holds its own tests and one end-to-end test
per dispatchable kind, and a delete PR copies that pattern for the kind it removes.

What is real. ``FakeScanner`` registers an actual ``Agent(kind='scanner')`` through the real built-in enrollment (``builtin_scanner.ensure`` writes the
blob, ``sentinel_broker.bootstrap`` redeems it), so ``sentinel_broker.is_builtin`` is true for it, its scope is the whole instance and it declares the
capabilities and contract version it was given. It heartbeats through ``sentinel_broker.heartbeat``. It serves a task by calling the same three
functions the REST layer calls for a Sentinel, in the same order, with a ``Ctx`` for its token: ``next_task`` (claim), ``accept_task``, then
``report_result`` (which runs ``clean_result``, so a result that breaks the contract fails the way it would for a real Sentinel). Nothing about
dispatch, eligibility, capacity, leases or result cleaning is mocked.

How it is driven (the one invasive choice, and why it is the least invasive one). ``sentinel_dispatch.dispatch_or_none`` creates the task and then
polls the database, sleeping ``DISPATCH_POLL_INTERVAL`` between looks, and it runs in the test's own thread inside the test's own transaction.
A server loop in a second thread would not see that transaction's rows (it would need ``TransactionTestCase`` and truncation after every test), and
patching ``time.sleep`` globally, as older tests do, also changes every other sleeper. So while the fake is started, the name ``time`` *inside
``agentapi.sentinel_dispatch`` only* is replaced by a small virtual clock: ``monotonic()`` is a counter and ``sleep(s)`` advances it by ``s`` WITHOUT
sleeping and then lets the fake serve whatever is queued. The dispatcher's wait loop therefore runs its real code (claim budget, completion
budget, queue budget, ``expire``), serves the task at its first poll, and costs no wall time, however long the budget it is waiting under: a task
the fake never reports expires after the virtual budget, instantly. (The fake also sets ``CVENGINE_SENTINEL_CLAIM_TIMEOUT`` and
``CVENGINE_SENTINEL_DISPATCH_TIMEOUT`` to 1 second unless the test set them, so even that takes two polls.) Because the wait runs on one thread, the
fake can only serve while a dispatch waits: call ``fake.serve_once()`` yourself to serve tasks created some other way.

Behaviour, per kind or for all of them (``mode=`` / ``modes={kind: mode}`` / ``set_mode``):

``ok``       claim, accept and report the responder's result (default).
``fail``     claim, accept and report ``{'outcome': 'error', 'error': ...}``: the task ends ``failed``.
``timeout``  claim and accept and never report: the stage's completion budget runs out and the task ends ``expired``.
``idle``     live (heartbeating) but never claims: the stage's claim budget runs out and the task ends ``expired``.
``offline``  not heard from for longer than ``LIVE_WINDOW``: no dispatch is attempted at all (the stage sees "no Sentinel is live").

The responder of a kind is a callable ``responder(task) -> result dict`` (``task`` is the payload the Sentinel was handed: ``kind``, ``target``,
``ips``...) or a plain dict. The default is the contract fixture ``tests/fixtures/sentinel_results/<kind>.json`` (the ``v<N>/`` copy when the fake
declares an older contract version and a frozen set exists); ``nuclei_targeted`` and ``nuclei_deep`` share ``nuclei_light.json``, the same result
shape. The fixtures are one good result per kind, not a scenario: a test that checks what was stored passes a responder whose result names the hosts
of its own scenario (``fixture(kind, **changes)``, ``for_host``).

Limits. A serve costs two ``claim`` calls of the broker's rate limit (60 a minute per token), so one fake serves about 30 tasks per test. A kind
that fails ``FAIL_STREAK`` times running is withheld from the Sentinel for a while (``sentinel_broker.failing_kinds``), as for a real one.

``assert_ran_nowhere_locally(testcase, kind)`` makes any local run of the kind a test failure, and ``LocalFallback('none')`` is the environment
switch (``CVENGINE_LOCAL_FALLBACK``) that stops the server from running a kind itself. A delete PR for kind K is proven by: ``LocalFallback('none')``,
``assert_ran_nowhere_locally(self, K)``, ``FakeScanner(kinds=[K])`` serving the K fixture, the real stage entry point, and an assertion on what the
stage stored; plus the same with ``mode='offline'``, where the stage must wait and leave its target due.
"""
import contextlib
import copy
import json
import os
import tempfile
import time as _real_time
from pathlib import Path
from unittest import mock

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'sentinel_results'
SHARED_FIXTURE = {'nuclei_targeted': 'nuclei_light', 'nuclei_deep': 'nuclei_light'}  # the same result shape, no file of their own
MODES = ('ok', 'fail', 'timeout', 'idle', 'offline')
DEFAULT_ERROR = 'the fake scanner was told to fail'


# --- fixtures --------------------------------------------------------------------------------------------------------------------------------

def fixture(kind, version=None, **changes):
    """The contract fixture result of ``kind`` as a new dict, with top-level ``changes`` applied (``fixture('nmap', os_reliable=False)``).
    ``version``: the contract version being spoken; an older one than the current reads the frozen ``v<N>/`` copy when it exists."""
    from agentapi import sentinel_contract
    name = SHARED_FIXTURE.get(kind, kind)
    paths = []
    if version is not None and version < sentinel_contract.version():
        paths.append(FIXTURES / f'v{version}' / f'{name}.json')
    paths.append(FIXTURES / f'{name}.json')
    for path in paths:
        if path.exists():
            return {**json.loads(path.read_text()), **changes}
    raise KeyError(f'there is no result fixture for kind {kind!r} in {FIXTURES}: pass a responder for it')


def for_host(result, host):
    """A nuclei result with every finding moved to ``host`` (and its URL), so a stage that matches findings to its own hosts stores them."""
    out = copy.deepcopy(result)
    for finding in out.get('findings', []):
        finding['host'] = host
        finding['matched_at'] = f'https://{host}/'
    return out


# --- the virtual clock inside sentinel_dispatch ----------------------------------------------------------------------------------------------

class _Clock:
    """What ``time`` is inside ``agentapi.sentinel_dispatch`` while a fake scanner is started: ``sleep`` advances a counter, serves, and returns."""

    def __init__(self, fake):
        self.fake, self.offset = fake, 0.0

    def monotonic(self):
        return _real_time.monotonic() + self.offset

    def sleep(self, seconds):
        self.offset += max(0.0, float(seconds))  # the budgets see the time pass; the test does not wait for it
        self.fake.serve_once()

    def __getattr__(self, name):
        return getattr(_real_time, name)


# --- the fake scanner ------------------------------------------------------------------------------------------------------------------------

class FakeScanner:
    """A registered, live, built-in Sentinel that serves tasks synchronously through the real broker. Use it as a context manager
    (``with FakeScanner(kinds=['nmap']) as fake:``) or ``FakeScanner(...).start_for(self)`` in ``setUp`` (stopped by the test's cleanup).

    ``kinds``: the capabilities it declares and the kinds it asks for (default: every kind that has a result fixture to serve).
    ``contract_version``: the one it reports (default: the server's current). ``mode`` / ``modes``: how it behaves (see the module docstring).
    ``responders``: ``{kind: callable(task) -> dict | dict}``. ``max_concurrent``: its slots. ``error``: the text a ``fail`` task reports."""

    def __init__(self, kinds=None, contract_version=None, mode='ok', modes=None, responders=None, max_concurrent=4, error=DEFAULT_ERROR):
        from agentapi import sentinel_contract
        self.kinds = list(kinds) if kinds is not None else [k for k in sentinel_contract.KINDS if _has_fixture(k)]
        self.contract_version = sentinel_contract.version() if contract_version is None else contract_version
        self.mode, self.modes = self._checked(mode), {k: self._checked(m) for k, m in (modes or {}).items()}
        self.responders = dict(responders or {})
        self.max_concurrent, self.error = max_concurrent, error
        self.served = []  # one dict per task it picked up: id, kind, mode, target, ips, result
        self.errors = []  # what went wrong inside a serve (re-raised by stop(): a stage's own ``except Exception`` must not hide it)
        self.agent = None
        self._stack = None

    # -- lifecycle

    @staticmethod
    def _checked(mode):
        if mode not in MODES:
            raise ValueError(f'unknown fake scanner mode {mode!r}; one of {", ".join(MODES)}')
        return mode

    def start(self):
        from agentapi import builtin_scanner, sentinel_broker
        stack = contextlib.ExitStack()
        try:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='fake-scanner-'))
            stack.enter_context(mock.patch.dict(os.environ, {'CVENGINE_BUILTIN_SCANNER': '1', 'CVENGINE_SCANNER_BOOTSTRAP_DIR': directory}))
            env = {name: '1' for name in ('CVENGINE_SENTINEL_CLAIM_TIMEOUT', 'CVENGINE_SENTINEL_DISPATCH_TIMEOUT') if name not in os.environ}
            stack.enter_context(mock.patch.dict(os.environ, env))
            admin = self._admin()
            state = builtin_scanner.ensure()['state']
            if state != 'blob_written':
                raise RuntimeError(f'the built-in enrollment did not write its blob: {state}')
            with open(builtin_scanner.blob_path(), encoding='utf-8') as handle:
                blob = sentinel_broker.decode_enrollment_blob(handle.read())
            out = sentinel_broker.bootstrap({'enrollment_token': blob['enrollment_token'], 'name': 'fake-scanner', 'capabilities': self.kinds,
                                             'max_concurrent': self.max_concurrent})
            from agentapi.models import Agent
            self.agent = Agent.objects.select_related('token__user').get(pk=out['id'])
            assert self.agent.token.user_id == admin.pk
            stack.enter_context(mock.patch('agentapi.sentinel_dispatch.time', _Clock(self)))
        except BaseException:
            stack.close()
            raise
        self._stack = stack
        self._forget_scanner_state()
        self.heartbeat()
        if self.mode == 'offline':
            self.go_offline()
        return self

    def start_for(self, testcase):
        """``start()`` and stop at the end of ``testcase`` (before its other cleanups run last-in-first-out)."""
        self.start()
        testcase.addCleanup(self.stop)
        return self

    def stop(self):
        stack, self._stack = self._stack, None
        if stack is None:
            return
        stack.close()
        self._forget_scanner_state()
        errors, self.errors = self.errors, []
        if errors:
            raise AssertionError('the fake scanner could not serve a task: ' + '; '.join(errors))

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        stack, self._stack = self._stack, None
        if stack is not None:
            stack.close()
            self._forget_scanner_state()
        if exc_type is None and self.errors:
            errors, self.errors = self.errors, []
            raise AssertionError('the fake scanner could not serve a task: ' + '; '.join(errors))
        return False

    @staticmethod
    def _admin():
        from django.contrib.auth.models import User
        admin = User.objects.filter(is_superuser=True, is_active=True).order_by('id').first()
        return admin or User.objects.create_superuser('fake-scanner-admin', 'fake-scanner@example.test', 'x')

    @staticmethod
    def _forget_scanner_state():
        """``scanner_state`` keeps its answer in the cache for 15 seconds, per value of ``CVENGINE_LOCAL_FALLBACK``: an answer from the test before this
        one, or from before the fake changed, would decide what a sweep does."""
        from django.core.cache import cache

        from agentapi import scanner_state, sentinel_dispatch
        raw = os.environ.get(sentinel_dispatch.LOCAL_FALLBACK_ENV, '').strip().lower()
        for key in {scanner_state.CACHE_KEY + raw, scanner_state.CACHE_KEY + 'none'}:
            with contextlib.suppress(Exception):
                cache.delete(key)

    # -- presence

    def _ctx(self):
        from agentapi.services import Ctx
        return Ctx(user=self.agent.token.user, token=self.agent.token)

    def heartbeat(self):
        """One real heartbeat: the fake is live (and has declared its contract version) from here until ``go_offline``."""
        from agentapi import sentinel_broker
        out = sentinel_broker.heartbeat(self._ctx(), {'info': {'contract_version': self.contract_version}})
        self.agent.refresh_from_db()
        self._forget_scanner_state()
        return out

    def go_offline(self):
        """Not heard from for longer than the live window: no stage dispatches to it, and ``scanner_state`` says its kinds are waiting."""
        from django.utils import timezone

        from agentapi import sentinel_broker
        from agentapi.models import Agent
        Agent.objects.filter(pk=self.agent.pk).update(last_seen=timezone.now() - sentinel_broker.LIVE_WINDOW - sentinel_broker.LIVE_WINDOW)
        self.agent.refresh_from_db()
        self.mode = 'offline'
        self._forget_scanner_state()

    def go_online(self, mode='ok'):
        self.mode = self._checked(mode)
        self.heartbeat()

    def set_mode(self, mode, kind=None):
        """Change how it behaves, for ``kind`` or for all kinds (clearing the per-kind modes). ``offline`` applies to the whole scanner."""
        self._checked(mode)
        if mode == 'offline':
            self.go_offline()
        elif kind is not None:
            self.modes[kind] = mode
        else:
            self.mode, self.modes = mode, {}
            self.heartbeat()

    def mode_of(self, kind):
        return self.mode if self.mode == 'offline' else self.modes.get(kind, self.mode)

    # -- serving

    def result_for(self, task):
        responder = self.responders.get(task['kind'])
        if responder is None:
            return fixture(task['kind'], version=self.contract_version)
        return copy.deepcopy(responder(task) if callable(responder) else responder)

    def serve_once(self):
        """Claim one queued task the way a Sentinel's poll does and, unless told otherwise, report it. Returns the ``served`` entry, or ``None`` when
        nothing was served (offline, nothing queued, or every queued kind is ``idle``)."""
        if self.agent is None or self.mode == 'offline':
            return None
        from agentapi import sentinel_broker
        kinds = [k for k in self.kinds if self.mode_of(k) != 'idle']
        if not kinds:
            return None
        try:
            ctx = self._ctx()
            task = sentinel_broker.next_task(ctx, {'kinds': kinds, 'wait': 0})['task']
            if task is None:
                return None
            mode = self.mode_of(task['kind'])
            entry = {'id': task['id'], 'kind': task['kind'], 'mode': mode, 'target': task['target'], 'ips': task.get('ips') or [],
                     'trace_id': task.get('trace_id'), 'result': None}
            self.served.append(entry)
            sentinel_broker.accept_task(ctx, task['id'])
            if mode == 'timeout':
                return entry
            body = {'outcome': 'error', 'error': self.error} if mode == 'fail' else self.result_for(task)
            entry['result'] = body
            sentinel_broker.report_result(ctx, task['id'], body)
            return entry
        except Exception as exc:  # noqa: BLE001 - recorded, and raised again at stop(): the stage that is waiting may catch anything
            self.errors.append(f'{type(exc).__name__}: {exc}')
            raise

    def tasks(self, kind=None):
        """The ``SentinelTask`` rows of this fake, oldest first (``kind`` narrows them)."""
        from agentapi.models import SentinelTask
        rows = SentinelTask.objects.filter(agent=self.agent).order_by('id')
        return rows.filter(kind=kind) if kind else rows

    def served_kinds(self):
        return [entry['kind'] for entry in self.served]


def _has_fixture(kind):
    try:
        fixture(kind)
    except KeyError:
        return False
    return True


# --- the guards ------------------------------------------------------------------------------------------------------------------------------

class LocalFallback(contextlib.ContextDecorator):
    """``with LocalFallback('none'):`` sets ``CVENGINE_LOCAL_FALLBACK`` (``'none'``, ``'all'``, a comma list of kinds, or ``None`` to unset it) for the
    block, or for a whole test with ``LocalFallback('none').apply(self)`` in ``setUp``. Usable as a decorator too. It also drops
    ``scanner_state``'s cached answer on the way in and out, which is keyed by the value."""

    def __init__(self, value='none'):
        self.value, self._patch = value, None

    def __enter__(self):
        from agentapi.sentinel_dispatch import LOCAL_FALLBACK_ENV
        self._patch = mock.patch.dict(os.environ, {} if self.value is None else {LOCAL_FALLBACK_ENV: self.value})
        self._patch.start()
        if self.value is None:
            os.environ.pop(LOCAL_FALLBACK_ENV, None)
        FakeScanner._forget_scanner_state()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        FakeScanner._forget_scanner_state()
        return False

    def apply(self, testcase):
        self.__enter__()
        testcase.addCleanup(self.__exit__, None, None, None)
        return self


class LocalRunDetected(AssertionError):
    """A scan tool was about to run on this server in a test that says it must not."""


# what each task kind's local path goes through: the module functions that run the tool, and the resource-gate job kinds (``heavy_job``) they use
LOCAL_RUNNERS = {
    'nmap': ('cveFeed.nmap_scan.run_nmap_xml', 'cveFeed.nmap_scan.run_nmap_args'),
    'naabu': ('cveFeed.naabu_scan.run_naabu',),
    'nuclei_light': ('cveFeed.nuclei_scan.stream_nuclei',),
    'nuclei_targeted': ('cveFeed.nuclei_scan.stream_nuclei',),
    'nuclei_deep': ('cveFeed.nuclei_scan.stream_nuclei',),
    'nmap_udp': ('cveFeed.udp_scan._runner', 'cveFeed.nmap_scan.run_nmap_xml', 'cveFeed.nmap_scan.run_nmap_args'),
    'testssl': ('cveFeed.testssl_scan.run_testssl',),
    'wpscan': ('cveFeed.wpscan_scan.run_wpscan_process',),
}
HEAVY_KINDS = {
    'nmap': ('nmap', 'nmap-full-bg'),
    'naabu': ('naabu',),
    'nuclei_light': ('nuclei', 'nuclei-light'),
    'nuclei_targeted': ('nuclei', 'nuclei-light'),
    'nuclei_deep': ('nuclei', 'nuclei-light'),
    'nmap_udp': ('nmap-udp-bg',),
    'testssl': ('testssl',),
    'wpscan': ('wpscan',),
}


class LocalGuard:
    """What ``assert_ran_nowhere_locally`` returns: ``calls`` (every local run attempted, as ``(where, args)``) and ``runner``, a callable that records
    and raises, for the stage parameters that take an injected runner (``nmap_scan.run_nmap_for_scan(runner=guard.runner)``, ``udp_scan.run(runner=...)``,
    ``testssl_scan.sweep(runner=...)``). A stage's own ``except Exception`` can swallow the ``LocalRunDetected`` it raises, so ``calls`` is checked again
    when the test ends: a swallowed local run still fails the test."""

    def __init__(self, kind):
        self.kind, self.calls = kind, []

    def hit(self, where, args=()):
        self.calls.append((where, args))
        raise LocalRunDetected(f'{self.kind} ran on this server ({where}) in a test that says the scanner must do it: the stage must hand '
                               f'{self.kind} work to a Sentinel and never run the tool itself')

    def runner(self, *args, **kwargs):
        self.hit('an injected local runner', args)

    def assert_clean(self):
        if self.calls:
            raise LocalRunDetected(f'{self.kind} ran on this server {len(self.calls)} time(s): {[where for where, _ in self.calls]}')


def assert_ran_nowhere_locally(testcase, kind):
    """From now until the end of ``testcase``, any local run of ``kind`` fails the test with ``LocalRunDetected`` (an ``AssertionError``): the module
    functions in ``LOCAL_RUNNERS`` that run the tool, the resource gate (``resources.heavy_job``) for the job kinds the tool uses, and
    ``heavy_process.run`` (testssl.sh, WPScan, wafw00f) for the same. The gates catch a stage that reached the tool through a default argument
    bound before the patch (``runner=run_nmap_xml``). Returns the ``LocalGuard``; the test also fails at the end when anything was attempted, even if
    the stage swallowed the error."""
    from cveFeed import heavy_process
    from reNgine import resources
    if kind not in LOCAL_RUNNERS:
        raise ValueError(f'no local path is known for {kind!r}: one of {", ".join(LOCAL_RUNNERS)}')
    guard = LocalGuard(kind)
    heavy = set(HEAVY_KINDS[kind])
    real_heavy_job, real_run = resources.heavy_job, heavy_process.run

    def refuse(where):
        def raiser(*args, **kwargs):
            guard.hit(where, args)
        return raiser

    @contextlib.contextmanager
    def gated_job(job_kind, *args, **kwargs):
        if job_kind in heavy:
            guard.hit(f'resources.heavy_job({job_kind!r})', args)
        with real_heavy_job(job_kind, *args, **kwargs) as job:
            yield job

    def gated_run(job_kind, argv, *args, **kwargs):
        if job_kind in heavy:
            guard.hit(f'heavy_process.run({job_kind!r}, {list(argv)[:1]})', argv)
        return real_run(job_kind, argv, *args, **kwargs)

    for target in LOCAL_RUNNERS[kind]:
        patcher = mock.patch(target, side_effect=refuse(target))
        patcher.start()
        testcase.addCleanup(patcher.stop)
    for target, replacement in (('reNgine.resources.heavy_job', gated_job), ('cveFeed.heavy_process.run', gated_run)):
        patcher = mock.patch(target, replacement)
        patcher.start()
        testcase.addCleanup(patcher.stop)
    testcase.addCleanup(guard.assert_clean)  # added last: runs first, before the patches come off
    return guard
