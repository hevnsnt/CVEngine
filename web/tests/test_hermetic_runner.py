"""The hermetic guards of reNgine/test_runner.py (CVENGINE_TEST_BLOCK_NETWORK, the per-test environment restore), tested through their functions so
the cases do not depend on the runner that is running them being hermetic."""
import os
import socket
import unittest
from unittest import mock

import requests
from django.conf import settings
from django.test import SimpleTestCase, override_settings

from reNgine import test_runner as runner


class Guarded(SimpleTestCase):
    """Base: the network block in place for the test, with the stderr report silenced."""

    def block(self, allowed=()):
        """Block the network with ``allowed`` hosts let through. What is let through reaches a stand-in for ``gethostbyname`` (the names used
        here do not exist, and the run that holds these tests may itself be blocking), recorded in ``self.looked_up``."""
        self.looked_up = []
        for patch in (mock.patch.object(runner, 'report'),
                      mock.patch.object(socket, 'gethostbyname', lambda host: self.looked_up.append(host) or '192.0.2.1')):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(runner.block_network(allowed))

    def run_inner(self, case):
        """Run ``case`` (a TestCase class defined by the caller) under the per-test hooks and return its result."""
        result = unittest.TestResult()
        undo = runner.isolate_tests()
        try:
            unittest.defaultTestLoader.loadTestsFromTestCase(case).run(result)
        finally:
            undo()
        return result


class BlockNetworkTests(Guarded):
    def test_resolving_a_real_hostname_raises_naming_the_host(self):
        self.block()
        for call in (lambda: socket.getaddrinfo('example.com', 80), lambda: socket.gethostbyname('example.com'),
                     lambda: socket.gethostbyname_ex('example.com')):
            with self.assertRaises(runner.NetworkBlocked) as caught:
                call()
            self.assertIn("'example.com'", str(caught.exception))
            self.assertIn('tests must not touch the network; mock it', str(caught.exception))

    def test_the_error_is_not_an_oserror_so_a_resolver_fallback_does_not_swallow_it(self):
        self.block()
        self.assertTrue(issubclass(runner.NetworkBlocked, RuntimeError))
        self.assertFalse(issubclass(runner.NetworkBlocked, OSError))
        with self.assertRaises(runner.NetworkBlocked):
            try:
                socket.getaddrinfo('example.com', 80)
            except (OSError, socket.gaierror):
                self.fail('NetworkBlocked was caught as an OSError')

    def test_a_connection_to_a_remote_host_raises_before_any_socket_is_made(self):
        self.block()
        with mock.patch.object(socket.socket, 'connect') as connect, self.assertRaises(runner.NetworkBlocked) as caught:
            socket.create_connection(('example.com', 443), timeout=1)
        self.assertIn("'example.com'", str(caught.exception))
        connect.assert_not_called()
        with self.assertRaises(runner.NetworkBlocked):
            socket.create_connection(address=('203.0.113.7', 443), timeout=1)

    def test_a_requests_call_to_a_remote_host_raises_even_when_the_call_is_not_mocked_at_the_top(self):
        self.block()
        with self.assertRaises(runner.NetworkBlocked) as caught:
            requests.get('https://api.example.com/v1/feed', timeout=1)
        self.assertIn("'api.example.com'", str(caught.exception))
        with self.assertRaises(runner.NetworkBlocked):
            requests.Session().post('http://203.0.113.7:8080/', data='x', timeout=1)

    def test_loopback_is_allowed(self):
        self.block()
        self.assertTrue(socket.getaddrinfo('localhost', 80))
        self.assertTrue(socket.getaddrinfo('127.0.0.1', 80))
        self.assertEqual(self.looked_up, [])
        socket.gethostbyname('localhost')  # let through: it reaches the stand-in
        self.assertEqual(self.looked_up, ['localhost'])
        self.assertTrue(socket.getaddrinfo('::1', 80))
        self.assertTrue(socket.getaddrinfo(None, 80))
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        socket.create_connection(('127.0.0.1', listener.getsockname()[1]), timeout=2).close()
        socket.create_connection(('localhost', listener.getsockname()[1]), timeout=2).close()

    def test_the_http_client_reaches_a_loopback_server(self):
        self.block()
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        # nothing answers, so the request fails the way a real one does (a timeout or a reset), not with NetworkBlocked
        with self.assertRaises(requests.RequestException):
            requests.get(f'http://localhost:{listener.getsockname()[1]}/', timeout=0.2)

    def test_an_ip_literal_needs_no_resolver_but_connecting_to_it_is_still_blocked(self):
        self.block()
        self.assertTrue(socket.getaddrinfo('203.0.113.7', 80))
        socket.gethostbyname('203.0.113.7')
        self.assertEqual(self.looked_up, ['203.0.113.7'])
        with self.assertRaises(runner.NetworkBlocked):
            socket.create_connection(('203.0.113.7', 80), timeout=1)

    def test_a_name_under_a_reserved_domain_is_answered_as_unknown_without_a_lookup(self):
        self.block()
        for call in (lambda: socket.getaddrinfo('www.example.test', 80), lambda: socket.gethostbyname('h1.fs.test'),
                     lambda: socket.gethostbyname_ex('a.b.invalid'), lambda: socket.getaddrinfo('app.example', 443),
                     lambda: socket.create_connection(('www.example.test', 80), timeout=1)):
            with self.assertRaises(socket.gaierror):  # what a resolver answers: the code under test sees an ordinary failed lookup
                call()
        self.assertEqual(self.looked_up, [])
        with self.assertRaises(runner.NetworkBlocked):  # a request is not a lookup: it is still a call to mock
            requests.get('http://www.example.test/', timeout=1)
        with self.assertRaises(runner.NetworkBlocked):
            socket.gethostbyname('www.example.test.example.com')

    def test_a_name_with_a_port_in_it_is_no_name(self):
        self.block()
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo('localhost:8000', None)
        with self.assertRaises(runner.NetworkBlocked):
            socket.create_connection(('2001:db8::1', 80), timeout=1)  # an IPv6 address has colons too, and is a connection to block

    def test_an_address_written_as_one_number_needs_no_resolver_but_is_not_a_name_to_connect_to(self):
        self.block()
        self.assertTrue(socket.getaddrinfo('2852039166', 80))  # 169.254.169.254
        with self.assertRaises(runner.NetworkBlocked):
            socket.create_connection(('2852039166', 80), timeout=1)

    def test_the_hosts_given_as_allowed_pass_and_nothing_else_does(self):
        self.block(allowed=['Db.internal'])
        with self.assertRaises(runner.NetworkBlocked):
            socket.gethostbyname('other.internal')
        with self.assertRaises(runner.NetworkBlocked):
            socket.gethostbyname('db.internal.example.com')
        self.assertEqual(self.looked_up, [])
        self.assertEqual(socket.gethostbyname('db.internal'), '192.0.2.1')
        self.assertEqual(socket.gethostbyname('DB.internal.'), '192.0.2.1')
        self.assertEqual(self.looked_up, ['db.internal', 'DB.internal.'])

    def test_the_undo_puts_the_real_calls_back(self):
        real = (socket.getaddrinfo, socket.gethostbyname, socket.gethostbyname_ex, socket.create_connection, requests.adapters.HTTPAdapter.send)
        undo = runner.block_network(())
        self.assertIsNot(socket.getaddrinfo, real[0])
        undo()
        self.assertEqual((socket.getaddrinfo, socket.gethostbyname, socket.gethostbyname_ex, socket.create_connection,
                          requests.adapters.HTTPAdapter.send), real)


class ConfiguredHostsTests(SimpleTestCase):
    @mock.patch.dict(os.environ, {'POSTGRES_HOST': 'DB', 'CELERY_BROKER': 'redis://:secret@broker.internal:6379/3'}, clear=True)
    @mock.patch.object(settings, 'DATABASES', {'default': {'ENGINE': 'django.db.backends.postgresql', 'HOST': 'postgres.internal'}})
    @override_settings(
        CELERY_BROKER_URL='redis://redis.internal:6379/0', CELERY_RESULT_BACKEND='rediss://results.internal:6380/1',
        CACHES={'default': {'BACKEND': 'x', 'LOCATION': 'redis://cache.internal:6379/1'}, 'second': {'BACKEND': 'x', 'LOCATION': ['redis://a.internal/1']}})
    def test_postgres_and_redis_hosts_come_from_the_settings_and_the_environment(self):
        self.assertEqual(runner.configured_hosts(),
                         {'db', 'postgres.internal', 'broker.internal', 'redis.internal', 'results.internal', 'cache.internal', 'a.internal'})

    @mock.patch.dict(os.environ, {'POSTGRES_HOST': '/var/run/postgresql', 'CELERY_BROKER': 'unix:///var/run/redis/redis.sock?db=3'}, clear=True)
    @mock.patch.object(settings, 'DATABASES', {'default': {'ENGINE': 'django.db.backends.postgresql', 'HOST': '/var/run/postgresql'}})
    @override_settings(
        CELERY_BROKER_URL='redis+socket:///var/run/redis.sock', CELERY_RESULT_BACKEND='unix:///var/run/redis.sock',
        CACHES={'default': {'BACKEND': 'x', 'LOCATION': 'unix:///var/run/redis.sock'}})
    def test_a_unix_socket_adds_no_host(self):
        self.assertEqual(runner.configured_hosts(), set())

    @mock.patch.object(settings, 'DATABASES', {'default': {'ENGINE': 'django.db.backends.postgresql', 'HOST': 'postgres.internal'}})
    def test_block_network_defaults_to_the_configured_hosts(self):
        looked_up = []
        for patch in (mock.patch.object(runner, 'report'), mock.patch.object(socket, 'gethostbyname', lambda host: looked_up.append(host))):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(runner.block_network())
        with self.assertRaises(runner.NetworkBlocked):
            socket.gethostbyname('example.com')
        socket.gethostbyname('postgres.internal')
        self.assertEqual(looked_up, ['postgres.internal'])


class AllowNetworkTests(Guarded):
    def test_a_class_with_allow_network_passes_the_guard_and_one_without_does_not(self):
        self.block()

        class Open(unittest.TestCase):
            allow_network = True

            def test_lookup(self):
                socket.gethostbyname('example.com')

        class Closed(unittest.TestCase):
            def test_lookup(self):
                socket.gethostbyname('example.org')

        self.assertTrue(self.run_inner(Open).wasSuccessful())
        self.assertEqual(self.looked_up, ['example.com'])
        result = self.run_inner(Closed)
        self.assertEqual((len(result.errors), len(result.failures)), (1, 0))
        self.assertIn('NetworkBlocked', result.errors[0][1])
        self.assertEqual(self.looked_up, ['example.com'])

    def test_allow_network_ends_with_the_test_that_set_it(self):
        self.block()

        class Open(unittest.TestCase):
            allow_network = True

            def test_nothing(self):
                pass

        self.assertTrue(self.run_inner(Open).wasSuccessful())
        with self.assertRaises(runner.NetworkBlocked):
            socket.gethostbyname('example.com')

    def test_the_class_fixtures_see_the_class_setting(self):
        self.block()

        class Open(unittest.TestCase):
            allow_network = True

            @classmethod
            def setUpClass(cls):
                socket.gethostbyname('example.com')

            def test_nothing(self):
                pass

        class Closed(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                socket.gethostbyname('example.org')

            def test_nothing(self):
                pass

        self.assertTrue(self.run_inner(Open).wasSuccessful())
        self.assertEqual(self.looked_up, ['example.com'])
        result = self.run_inner(Closed)
        self.assertEqual(len(result.errors), 1)
        self.assertIn('NetworkBlocked', result.errors[0][1])


class EnvironmentTests(Guarded):
    def test_a_test_that_sets_a_variable_without_patch_dict_does_not_leak_it(self):
        name = 'CVENGINE_HERMETIC_TEST_LEAK'
        self.addCleanup(os.environ.pop, name, None)

        class Leaky(unittest.TestCase):
            def test_sets(self):
                os.environ[name] = 'leaked'
                os.environ['PATH'] += os.pathsep + '/nowhere'
                os.environ.pop('HOME', None)

        before = dict(os.environ)
        self.assertTrue(self.run_inner(Leaky).wasSuccessful())
        self.assertEqual(dict(os.environ), before)
        self.assertNotIn(name, os.environ)

    def test_a_test_sees_the_variables_an_earlier_test_set_in_a_class_fixture(self):
        name = 'CVENGINE_HERMETIC_TEST_FIXTURE'
        self.addCleanup(os.environ.pop, name, None)
        seen = []

        class Fixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                os.environ[name] = 'class'

            def test_a(self):
                seen.append(os.environ.get(name))
                os.environ[name] = 'changed'

            def test_b(self):
                seen.append(os.environ.get(name))

        self.run_inner(Fixture)
        self.assertEqual(seen, ['class', 'class'])

    def test_restoring_can_be_turned_off(self):
        name = 'CVENGINE_HERMETIC_TEST_KEEP'
        self.addCleanup(os.environ.pop, name, None)

        class Leaky(unittest.TestCase):
            def test_sets(self):
                os.environ[name] = 'kept'

        # the run that holds this test may have the restoring hook in place already: start from the run it wraps
        current = unittest.TestCase.run
        unwrapped = mock.patch.object(unittest.TestCase, 'run', getattr(current, '__wrapped__', current))
        unwrapped.start()
        undo = runner.isolate_tests(restore_environment=False)
        try:
            unittest.defaultTestLoader.loadTestsFromTestCase(Leaky).run(unittest.TestResult())
        finally:
            undo()
            unwrapped.stop()
        self.assertEqual(os.environ.get(name), 'kept')

    def test_install_puts_the_environment_back_on_undo_and_removes_every_hook(self):
        name = 'CVENGINE_HERMETIC_TEST_TEARDOWN'
        self.addCleanup(os.environ.pop, name, None)
        real_run = unittest.TestCase.run
        real_lookup = socket.gethostbyname
        with mock.patch.object(runner, '_installed', None):
            undo = runner.install_hermetic(block=True)
            self.assertIs(runner.install_hermetic(), undo)  # once per process
            self.assertIsNot(unittest.TestCase.run, real_run)
            self.assertIsNot(socket.gethostbyname, real_lookup)
            os.environ[name] = 'set after setup'
            undo()
        self.assertNotIn(name, os.environ)
        self.assertIs(unittest.TestCase.run, real_run)
        self.assertIs(socket.gethostbyname, real_lookup)

    def test_install_leaves_the_network_alone_unless_asked(self):
        real_lookup = socket.gethostbyname
        with mock.patch.object(runner, '_installed', None):
            undo = runner.install_hermetic(block=False)
            try:
                self.assertIs(socket.gethostbyname, real_lookup)
            finally:
                undo()

    @mock.patch.dict(os.environ, {runner.BLOCK_NETWORK_ENV: '1'})
    def test_the_environment_variable_turns_the_block_on(self):
        real_lookup = socket.gethostbyname
        with mock.patch.object(runner, '_installed', None):
            undo = runner.install_hermetic()
            try:
                self.assertIsNot(socket.gethostbyname, real_lookup)
            finally:
                undo()

    @mock.patch.dict(os.environ, {runner.BLOCK_NETWORK_ENV: '0'})
    def test_anything_but_one_leaves_it_off(self):
        real_lookup = socket.gethostbyname
        with mock.patch.object(runner, '_installed', None):
            undo = runner.install_hermetic()
            try:
                self.assertIs(socket.gethostbyname, real_lookup)
            finally:
                undo()
