"""Test runner that lets ``manage.py test --parallel`` run safely against one Redis server.

Django clones the PostgreSQL test database for every worker, but the tests also use Redis (the Django cache, the scan memory gate,
claims and locks), and ``cache.clear()`` or a held lock in one worker would break a test running in another. Each worker therefore
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


def _init_isolated_worker(counter, *args, **kwargs):
    from django.test import runner
    _init_worker(counter, *args, **kwargs)
    isolate_redis(runner._worker_id)
    install_hermetic()  # a forked worker has the parent's guards already; a spawned one has none


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


def isolate_tests(restore_environment=True):
    """Run every test with its ``allow_network`` visible to the network guards, and put ``os.environ`` back as it was when the test began.
    Class fixtures (setUpClass, setUpTestData) get the class's ``allow_network`` too. Returns the function that removes the hooks."""
    stack = ExitStack()
    real_run = unittest.TestCase.run
    real_class_setup = unittest.suite.TestSuite._handleClassSetUp

    def run(self, result=None):
        before, environment = dict(_current), dict(os.environ)
        _current.update(test=self.id(), allow=bool(getattr(self, 'allow_network', False)))
        try:
            return real_run(self, result)
        finally:
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


class IsolatedRedisParallelSuite(ParallelTestSuite):
    init_worker = _init_isolated_worker


class IsolatedRedisRunner(DiscoverRunner):
    parallel_test_suite = IsolatedRedisParallelSuite

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.parallel > MAX_WORKERS:
            print(f'--parallel {self.parallel} lowered to {MAX_WORKERS}: each worker needs two of Redis\'s 16 databases.')
            self.parallel = MAX_WORKERS

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._remove_hermetic = install_hermetic()

    def teardown_test_environment(self, **kwargs):
        self._remove_hermetic()
        super().teardown_test_environment(**kwargs)
