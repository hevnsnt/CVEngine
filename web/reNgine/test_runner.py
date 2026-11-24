"""Test runner that lets ``manage.py test --parallel`` run safely against one Redis server.

Django clones the PostgreSQL test database for every worker, but the tests also use Redis (the Django cache, claims, locks
and the published settings), and ``cache.clear()`` or a held lock in one worker would break a test running in another. Each worker therefore
gets two Redis databases of its own (broker and cache: 2n and 2n+1), flushed when it starts, so Redis has room for 7 workers.
Everything else about a normal (one process) run is unchanged.

Two more guards keep a test from depending on the machine it runs on or on the tests before it:
- every test starts with the environment variables the run started with (a test that sets ``os.environ[...]`` without ``patch.dict`` cannot leak);
- with ``CVENGINE_TEST_BLOCK_NETWORK=1`` a test that resolves a name or connects to a host other than loopback, Postgres and Redis fails with
  ``NetworkBlocked`` (mock the call; a test class that really needs the resolver sets ``allow_network = True``). A DNS answer or a reachable
  host must not decide whether a test passes. A lookup of a name that cannot exist (``.test``, ``.invalid``, ``.example``, the names the
  fixtures use) is not a network call: it gets the "no such name" a resolver gives, on every machine."""
import ipaddress
import os
import socket
import unittest
from contextlib import ExitStack
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.test.runner import DiscoverRunner, ParallelTestSuite, _init_worker

BLOCK_NETWORK_ENV = 'CVENGINE_TEST_BLOCK_NETWORK'
LOCAL_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})
NONEXISTENT_TLDS = frozenset({'test', 'invalid', 'example'})  # RFC 6761 / 2606: never in the DNS
MAX_WORKERS = 7  # a default Redis has 16 databases: worker n uses 2n and 2n + 1 (0 and 1 stay with the parent)


def _with_database(url, number):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f'/{number}', '', ''))


def isolate_redis(worker_id):
    """Point this process at Redis databases that no other worker uses. A URL that is not Redis is left alone."""
    from django.test.utils import override_settings

    base = os.environ.get('CELERY_BROKER') or getattr(settings, 'CELERY_BROKER_URL', '')
    if not base.startswith(('redis://', 'rediss://')):
        return
    if not 1 <= worker_id <= MAX_WORKERS:
        raise RuntimeError(f'worker {worker_id}: --parallel is limited to {MAX_WORKERS} workers by the Redis databases available')
    broker, cache = _with_database(base, 2 * worker_id), _with_database(base, 2 * worker_id + 1)
    os.environ['CELERY_BROKER'] = os.environ['CELERY_BROKER_URL'] = broker
    caches = {**settings.CACHES, 'default': {**settings.CACHES['default'], 'LOCATION': cache}}
    # enable() without a matching disable(): this process keeps these settings until it exits, and the setting_changed signal
    # makes Django drop the cache connections it already made
    override_settings(CELERY_BROKER_URL=broker, CACHES=caches).enable()
    from reNgine import resources
    resources.reset_store()
    import redis
    for url in (broker, cache):
        redis.Redis.from_url(url).flushdb()


# cveFeed.tunables.VALUES_KEY, reNgine.resources.SAVED_VALUES_KEY and AUTO_VALUES_KEY (tests.test_hermetic_runner pins that they still match)
SAVED_SETTINGS_KEYS = ('cvengine:tunables:values', 'cvengine:scanconc:values', 'cvengine:autotune:values')


def clear_egress_state():
    try:
        from reNgine import resources
        client = resources.redis_client()
        if client is None:
            return
        # the egress ledger, and the hourly hash of the rate limiter's refusals (agentapi.claim_refusals): a test that drives a 429 (the secret reads, the claim
        # flood) leaves a refusal in Redis that is a real number in another module's system status, so it is cleared before every test, not by one module's setUp
        for pattern in ('cvengine:egress:*', 'cvengine:claim_refused:*'):
            keys = list(client.scan_iter(pattern, count=1000))
            if keys:
                client.delete(*keys)
        # the published copies of saved settings (cveFeed.tunables, reNgine.resources' scan concurrency and auto-tune values): a test that saves
        # one (a triage cap of 10, say) publishes it to Redis, its database rows roll back but the copy stays, and every later test in this worker read it
        # (tests.test_triage.CapTests ran 10 triages instead of 100). With no copy, a read falls back to the test's own database and publishes again.
        client.delete(*SAVED_SETTINGS_KEYS)
    except Exception:  # noqa: BLE001 - a test without Redis has no egress state to clear
        pass
    try:
        # the cached exclusion lists (cveFeed.exclusions): a test's rows roll back without a signal, so the copies a test cached must not reach the next one
        from cveFeed import exclusions
        exclusions._bump()
    except Exception:  # noqa: BLE001
        pass


def hermetic_egress():
    """Pin the egress settings off for the test run and clear the egress Redis keys before each test (Django's SimpleTestCase and its subclasses).

    Stages also run blocking in tests (``CVENGINE_ASYNC_STAGES=0`` unless the run sets it): a test's transaction never commits, so a StageRun's
    callback is never queued, and a test that calls a pipeline expects its result. The tests of asynchronous stages switch it on themselves
    (``tests.fake_scanner.FakeScanner(async_stages=True)`` and ``drain``)."""
    os.environ.setdefault('CVENGINE_ASYNC_STAGES', '0')
    from django.test import SimpleTestCase
    if getattr(SimpleTestCase, '_egress_hermetic', False):
        return
    original = SimpleTestCase._setup_and_call

    def setup_and_call(self, result, debug=False):
        clear_egress_state()
        return original(self, result, debug)
    SimpleTestCase._setup_and_call = setup_and_call
    SimpleTestCase._egress_hermetic = True


def _init_isolated_worker(counter, *args, **kwargs):
    from django.test import runner
    _init_worker(counter, *args, **kwargs)
    isolate_redis(runner._worker_id)
    install_hermetic()  # a forked worker has the parent's guards already; a spawned one has none
    hermetic_egress()
    time_classes()


class NetworkBlocked(RuntimeError):
    """A test reached for the network. Not an OSError on purpose: code that catches ``socket.gaierror`` or ``OSError`` must not swallow it."""


# What the test running now allows, read by the patched network calls: the test id (for the message on stderr) and its ``allow_network``.
_current = {'test': None, 'allow': False}
_installed = None  # the undo of the hooks this process already has (a forked worker inherits the parent's)


def _add_host(hosts, value):
    value = (value or '').strip().lower()
    if value and not value.startswith('/'):  # a unix socket path never reaches the resolver
        hosts.add(value)


def configured_hosts():
    """The hosts the tests may reach besides loopback: the Postgres and Redis servers named by the settings and the environment."""
    hosts = set()
    for database in settings.DATABASES.values():
        _add_host(hosts, database.get('HOST'))
    _add_host(hosts, os.environ.get('POSTGRES_HOST'))
    urls = [os.environ.get(name) for name in ('CELERY_BROKER', 'CELERY_BROKER_URL', 'CELERY_BACKEND')]
    urls += [getattr(settings, name, None) for name in ('CELERY_BROKER_URL', 'CELERY_RESULT_BACKEND')]
    for cache in settings.CACHES.values():
        location = cache.get('LOCATION') or ()
        urls += [location] if isinstance(location, str) else list(location)
    for url in urls:
        try:
            _add_host(hosts, urlsplit(url or '').hostname)  # unix:// and redis+socket:// URLs have none
        except ValueError:
            pass
    return hosts


def _literal(host):
    """``host`` as an address when it is one, in any form the resolver reads without a lookup (``2852039166`` and ``127.1`` included)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))
    except (OSError, ValueError, UnicodeError):
        return None


def report(name):
    """Straight to stderr: code that catches the exception (a broad ``except Exception`` around a lookup) would otherwise hide that a test got here."""
    os.write(2, f'NetworkBlocked: {name} ({_current["test"] or "outside a test"})\n'.encode())


def check_host(host, allowed, resolving=False, lookup=False):
    """Raise NetworkBlocked unless ``host`` is loopback, in ``allowed`` or the running test sets ``allow_network``. ``resolving`` is for calls
    that only turn a name into addresses: an IP literal needs no resolver there, so it passes (connecting to it is still checked). ``lookup``
    is for calls that look a name up: one under a reserved top-level domain (``www.example.test``, the names the fixtures use) is answered
    with the "no such name" a resolver gives for it (RFC 6761), without asking one (a "name" with a port in it, like the DOMAIN_NAME default,
    is no name either): code that treats an unresolvable name as a normal case then gets the same answer on every machine."""
    if _current['allow'] or host is None or host == '':
        return
    if isinstance(host, bytes):
        host = host.decode('ascii', 'replace')
    name = str(host).strip('[]').lower().rstrip('.')
    address = _literal(name)
    if name in LOCAL_HOSTS or name in allowed or (address and (address.is_loopback or resolving)):
        return
    if lookup and not address and (name.rsplit('.', 1)[-1] in NONEXISTENT_TLDS or ':' in name):
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known (a reserved name: no lookup was made)')
    report(name)
    raise NetworkBlocked(f'network access to {name!r} blocked: tests must not touch the network; mock it '
                         f'(a test class that deliberately needs it sets allow_network = True)')


def block_network(allowed=None):
    """Make the resolver and the connection calls raise NetworkBlocked for any host that is not loopback or in ``allowed`` (default: the
    configured Postgres and Redis hosts). Returns the function that puts the real ones back."""
    import requests.adapters
    allowed = {h.lower() for h in (configured_hosts() if allowed is None else allowed)}
    stack = ExitStack()

    def guard(owner, name, host_of, resolving=False, lookup=False):
        real = getattr(owner, name)

        def blocked(*args, **kwargs):
            check_host(host_of(*args, **kwargs), allowed, resolving, lookup)
            return real(*args, **kwargs)
        blocked.__wrapped__ = real
        setattr(owner, name, blocked)
        stack.callback(setattr, owner, name, real)

    guard(socket, 'getaddrinfo', lambda host, *a, **k: host, resolving=True, lookup=True)
    guard(socket, 'gethostbyname', lambda host, *a, **k: host, resolving=True, lookup=True)
    guard(socket, 'gethostbyname_ex', lambda host, *a, **k: host, resolving=True, lookup=True)
    guard(socket, 'create_connection', lambda address, *a, **k: address[0], lookup=True)
    guard(requests.adapters.HTTPAdapter, 'send', lambda self, request, *a, **k: urlsplit(request.url).hostname)
    return stack.close

# Per-process memos that expire on the real clock and are read by ordinary requests: whichever request lands after an expiry pays a reload (one to
# three queries), so a count that two requests are compared on, or that a test pins, depended on the machine's speed and on the tests that ran before
# (17 != 15, 4 != 6, which turned CI red three times). Every test therefore starts with them unloaded (the first read loads them) and they cannot expire
# while it runs: the two 10 second ones by a frozen clock, the others by an infinite window. A test that is ABOUT one of them (its expiry, its reload,
# its refresh) opts out with ``tests.steady.expiring_caches`` on the test or its class; ``steady_caches()`` remains for a test that wants none of them to read at all.
EXPIRING_CACHES_ATTR = 'expiring_caches'


class _FrozenTime:
    """The ``time`` module with ``time()`` stopped: a memo that compares against it never expires."""
    def __init__(self, at):
        self._at = at

    def time(self):
        return self._at

    def __getattr__(self, name):
        import time
        return getattr(time, name)


def pin_process_caches():
    """Unload and pin the memos listed above. Returns the function that unpins and unloads them again."""
    import time
    from unittest import mock

    from cveFeed import egress_proxy, internal_view, scan_concurrency, tailscale_scope, tunables
    from reNgine import input_guard, ip_allowlist, resources
    forever = float('inf')
    stack = ExitStack()

    def unload():
        input_guard._ban_cache.update(at=0.0, ips=frozenset())
        ip_allowlist._cache.update(at=0.0)
        internal_view.invalidate()
        tunables.invalidate()
        tunables._cache.update(values={})  # not even the last copy of an outage carries over
        scan_concurrency.invalidate()
        tailscale_scope.invalidate()
        egress_proxy.reset_cache()
        resources._saved.update(at=None, values={})
        resources._auto.update(at=None, values={})
    unload()
    frozen = _FrozenTime(time.time())
    for owner, name, value in ((input_guard, 'time', frozen), (ip_allowlist, 'time', frozen), (internal_view, 'CACHE_SECONDS', forever), (tunables, 'CACHE_SECONDS', forever),
                               (scan_concurrency, 'CACHE_SECONDS', forever), (tailscale_scope, 'CACHE_SECONDS', forever), (egress_proxy, 'CACHE_SECONDS', forever),
                               (resources, 'SAVED_CACHE_SECONDS', forever)):
        patch = mock.patch.object(owner, name, value)
        patch.start()
        stack.callback(patch.stop)
    stack.callback(unload)
    return stack.close


def _pin_quietly():
    try:
        return pin_process_caches()
    except Exception:  # noqa: BLE001 - a run without the app loaded (the runner's own tests) has nothing to pin
        return None


def _opts_out(test):
    method = getattr(test, getattr(test, '_testMethodName', ''), None)
    return bool(getattr(type(test), EXPIRING_CACHES_ATTR, False) or getattr(method, EXPIRING_CACHES_ATTR, False))


def isolate_tests(restore_environment=True):
    """Run every test with its ``allow_network`` visible to the network guards, and put ``os.environ`` back as it was when the test began.
    Class fixtures (setUpClass, setUpTestData) get the class's ``allow_network`` too. Returns the function that removes the hooks."""
    stack = ExitStack()
    real_run = unittest.TestCase.run
    real_class_setup = unittest.suite.TestSuite._handleClassSetUp

    def run(self, result=None):
        before, environment = dict(_current), dict(os.environ)
        _current.update(test=self.id(), allow=bool(getattr(self, 'allow_network', False)))
        unpin = None if _opts_out(self) else _pin_quietly()
        try:
            return real_run(self, result)
        finally:
            if unpin:
                unpin()
            _current.update(before)
            if restore_environment and dict(os.environ) != environment:
                os.environ.clear()
                os.environ.update(environment)

    def class_setup(self, test, result):
        before = dict(_current)
        _current.update(test=f'{type(test).__name__} fixtures', allow=bool(getattr(type(test), 'allow_network', False)))
        try:
            return real_class_setup(self, test, result)
        finally:
            _current.update(before)

    run.__wrapped__ = real_run
    unittest.TestCase.run, unittest.suite.TestSuite._handleClassSetUp = run, class_setup
    stack.callback(setattr, unittest.TestCase, 'run', real_run)
    stack.callback(setattr, unittest.suite.TestSuite, '_handleClassSetUp', real_class_setup)
    return stack.close


def install_hermetic(block=None, restore_environment=True):
    """Install the guards once per process: the network block when ``block`` (default: CVENGINE_TEST_BLOCK_NETWORK=1), the per-test
    environment restore. Returns the function that removes them and restores ``os.environ`` as it is now."""
    global _installed
    if _installed:
        return _installed
    if block is None:
        block = os.environ.get(BLOCK_NETWORK_ENV) == '1'
    stack = ExitStack()
    environment = dict(os.environ)

    def put_environment_back():
        os.environ.clear()
        os.environ.update(environment)
    stack.callback(put_environment_back)
    stack.callback(globals().__setitem__, '_installed', None)
    stack.callback(_current.update, test=None, allow=False)
    stack.callback(isolate_tests(restore_environment))
    if block:
        stack.callback(block_network())
    _installed = stack.close
    return _installed


# ``--module-times``: the wall time of every test class (its fixtures included) is written by the process that ran it, a parallel worker or the
# runner itself, to a file in this directory, and the runner prints one line per module at the end: its seconds, the group Django runs it in and
# its longest class. scripts/ci_shard.py --refresh reads those lines from the CI logs to weigh the modules when it splits the suite into shards.
# The group is Django's run order (DiscoverRunner.reorder_by): 0 for TestCase classes, 1 for the other SimpleTestCase ones (TransactionTestCase
# among them), 2 for plain unittest classes, which run last. A long class in group 2 starts only when the rest of its shard is done.
MODULE_TIMES_ENV = 'CVENGINE_TEST_MODULE_TIMES'
MODULE_TIME_LINE = 'MODULE-TIME'
_times = {'installed': False, 'started': {}}


def time_classes(force=False):
    """Record the wall time of each test class run in this process, from the first test's class setup to the class teardown, to the
    ``MODULE_TIMES_ENV`` directory. Installed once per process, when the variable is set (or ``force``); writes nothing while it is unset."""
    import time
    if _times['installed'] or not (force or os.environ.get(MODULE_TIMES_ENV)):
        return
    real = unittest.suite.TestSuite._tearDownPreviousClass

    def tear_down_previous_class(self, test, result):
        previous = getattr(result, '_previousTestClass', None)
        current = type(test)
        try:
            return real(self, test, result)
        finally:
            if previous is not current:
                now = time.perf_counter()
                began = _times['started'].pop(previous, None)
                folder = os.environ.get(MODULE_TIMES_ENV)
                if began is not None and folder:
                    with open(os.path.join(folder, f'times-{os.getpid()}.tsv'), 'a', encoding='utf-8') as handle:  # one file per process
                        handle.write(f'{previous.__module__}\t{previous.__qualname__}\t{now - began:.3f}\t{run_group(previous)}\n')
                if test is not None:
                    _times['started'][current] = now
    unittest.suite.TestSuite._tearDownPreviousClass = tear_down_previous_class
    _times['installed'] = True


def run_group(case):
    """The group Django runs a test class in: 0 TestCase, 1 another SimpleTestCase, 2 anything else (DiscoverRunner.reorder_by)."""
    from django.test import SimpleTestCase, TestCase
    return 0 if issubclass(case, TestCase) else 1 if issubclass(case, SimpleTestCase) else 2


def module_times(folder):
    """Per test module recorded in ``folder`` by every process of the run: its seconds summed over its classes, the group that holds most of
    them, and its longest class."""
    totals, groups = {}, {}
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), encoding='utf-8') as handle:
            for line in handle:
                module, _, seconds, group = line.rstrip('\n').split('\t')
                entry = totals.setdefault(module, {'seconds': 0.0, 'longest': 0.0})
                entry['seconds'] += float(seconds)
                entry['longest'] = max(entry['longest'], float(seconds))
                groups.setdefault(module, {}).setdefault(int(group), 0.0)
                groups[module][int(group)] += float(seconds)
    for module, entry in totals.items():
        entry['group'] = max(sorted(groups[module]), key=lambda g: groups[module][g])
    return totals


class IsolatedRedisParallelSuite(ParallelTestSuite):
    init_worker = _init_isolated_worker


class IsolatedRedisRunner(DiscoverRunner):
    parallel_test_suite = IsolatedRedisParallelSuite

    def __init__(self, *args, module_times=False, **kwargs):
        super().__init__(*args, **kwargs)
        if self.parallel > MAX_WORKERS:
            print(f'--parallel {self.parallel} lowered to {MAX_WORKERS}: each worker needs two of Redis\'s 16 databases.')
            self.parallel = MAX_WORKERS
        self.module_times_dir = None
        if module_times:
            import tempfile
            # in the environment before any worker starts, so a forked or spawned worker writes to the same place
            self.module_times_dir = os.environ[MODULE_TIMES_ENV] = tempfile.mkdtemp(prefix='cvengine-module-times-')

    @classmethod
    def add_arguments(cls, parser):
        super().add_arguments(parser)
        parser.add_argument('--module-times', action='store_true',
                            help='Print the wall time of every test module at the end (scripts/ci_shard.py --refresh reads it from the CI logs).')

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._remove_hermetic = install_hermetic()
        hermetic_egress()  # after install_hermetic: the egress settings are part of every test's starting environment
        time_classes()

    def run_suite(self, suite, **kwargs):
        try:
            return super().run_suite(suite, **kwargs)
        finally:
            if self.module_times_dir:
                self.print_module_times()

    def print_module_times(self):
        import shutil
        totals = module_times(self.module_times_dir)
        shutil.rmtree(self.module_times_dir, ignore_errors=True)
        print(f'\nModule times ({len(totals)} modules, seconds of one process, class fixtures included; the group Django runs it in; its longest class):')
        for module, entry in sorted(totals.items(), key=lambda item: (-item[1]['seconds'], item[0])):
            print(f'{MODULE_TIME_LINE} {entry["seconds"]:9.2f} {module} group={entry["group"]} longest={entry["longest"]:.2f}')
        print(f'{MODULE_TIME_LINE} total {sum(entry["seconds"] for entry in totals.values()):.2f}', flush=True)

    def teardown_test_environment(self, **kwargs):
        self._remove_hermetic()
        super().teardown_test_environment(**kwargs)
