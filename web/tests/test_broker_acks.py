"""``reNgine.broker_acks``: an ack whose broker connection drops must still free its delivery, or the channel's prefetch keeps counting it and
an acks_late worker runs one task fewer at once until it restarts (``tests/test_gevent_worker_e2e.py`` shows it end to end). These drive kombu's
real Redis ``QoS`` with the broker side (``_remove_from_indices``) stood in for."""
import unittest
from unittest import mock

import redis
import reNgine.celery  # noqa: F401  (the app installs the guard; read before any test here installs it itself)
from kombu.transport import redis as kombu_redis
from reNgine import broker_acks

INSTALLED_BY_THE_APP = getattr(kombu_redis.QoS, broker_acks._MARK, False)


class Pipeline:
    """What ``_remove_from_indices`` returns: ``execute`` fails as many times as asked, then succeeds."""

    def __init__(self, failures):
        self.failures = failures
        self.executed = 0

    def execute(self):
        if self.failures:
            self.failures -= 1
            raise redis.exceptions.ConnectionError('Connection closed by server.')
        self.executed += 1
        return [1, 1]


def qos_with(delivered, prefetch=2):
    channel = mock.Mock(connection_errors=(redis.exceptions.ConnectionError,), do_restore=False)
    qos = kombu_redis.QoS(channel, prefetch_count=prefetch)
    for tag in delivered:
        qos._delivered[tag] = mock.Mock()
    return qos


class AckFreesTheSlotTests(unittest.TestCase):

    def setUp(self):
        self.assertTrue(broker_acks.install())

    def test_the_app_installs_it(self):
        self.assertTrue(INSTALLED_BY_THE_APP)
        self.assertTrue(broker_acks.install())  # idempotent
        self.assertEqual(kombu_redis.QoS.ack.__module__, 'reNgine.broker_acks')

    def test_an_ack_is_removed_from_the_broker_and_frees_its_slot(self):
        qos = qos_with(['a', 'b'])
        self.assertFalse(qos.can_consume())
        pipe = Pipeline(0)
        with mock.patch.object(qos, '_remove_from_indices', return_value=pipe) as remove:
            qos.ack('a')
        remove.assert_called_once_with('a')
        self.assertEqual(pipe.executed, 1)
        self.assertTrue(qos.can_consume())

    def test_a_dropped_connection_is_tried_once_more_and_the_slot_is_freed(self):
        qos = qos_with(['a', 'b'])
        pipe = Pipeline(1)
        with mock.patch.object(qos, '_remove_from_indices', return_value=pipe) as remove:
            qos.ack('a')
        self.assertEqual(remove.call_count, 2)
        self.assertEqual(pipe.executed, 1)
        self.assertTrue(qos.can_consume())

    def test_when_the_broker_cannot_be_told_the_error_is_raised_and_the_slot_is_still_freed(self):
        # kombu's ack_log_error logs it; the message stays in the broker's unacked index and comes back after the visibility timeout
        qos = qos_with(['a', 'b'])
        with mock.patch.object(qos, '_remove_from_indices', return_value=Pipeline(2)), self.assertRaises(redis.exceptions.ConnectionError):
            qos.ack('a')
        self.assertTrue(qos.can_consume())
        qos._flush()
        self.assertEqual(list(qos._delivered), ['b'])

    def test_a_reject_without_requeue_frees_its_slot_too(self):
        qos = qos_with(['a', 'b'])
        with mock.patch.object(qos, '_remove_from_indices', return_value=Pipeline(1)):
            qos.reject('a', requeue=False)
        self.assertTrue(qos.can_consume())

    def test_a_reject_with_requeue_is_left_to_kombu(self):
        qos = qos_with(['a', 'b'])
        with mock.patch.object(qos, 'restore_by_tag') as restore:
            qos.reject('a', requeue=True)
        restore.assert_called_once_with('a', leftmost=True)
        self.assertTrue(qos.can_consume())


class InstallIsFailSafeTests(unittest.TestCase):

    def test_a_kombu_that_does_not_look_as_expected_is_left_alone_with_a_warning_and_nothing_raises(self):
        import kombu
        before = kombu_redis.QoS.ack
        with mock.patch.object(kombu_redis, 'QoS', None), self.assertLogs('reNgine.broker_acks', 'WARNING') as logs:
            self.assertFalse(broker_acks.install())  # the transport has no QoS
        self.assertIn(f'kombu {kombu.__version__} lacks kombu.transport.redis.QoS', logs.output[0])
        with mock.patch.object(broker_acks, '_install', side_effect=RuntimeError('odd kombu')), \
                self.assertLogs('reNgine.broker_acks', 'WARNING') as logs:
            self.assertFalse(broker_acks.install())  # anything unexpected
        self.assertIn('Could not guard kombu', logs.output[0])
        self.assertIs(kombu_redis.QoS.ack, before)
