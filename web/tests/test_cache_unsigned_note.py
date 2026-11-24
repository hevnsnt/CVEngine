"""The cache's note about a value it cannot read is written at most once a minute per process, with the number of reads it left out.

On production a key written before a secret rotation, with no expiry, was read about 250 times a second, and every read wrote one warning line to the
worker log (about 13 MB of log every half hour on a disk that already stalls). The value is still ignored on every read; only the note is limited.
"""
import pickle
from unittest import mock

from django.test import SimpleTestCase

from cvengine import cache_serializer


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def foreign_value():
    blob = pickle.dumps({'a': 1})
    return cache_serializer.MAGIC + b'\0' * cache_serializer.MAC_BYTES + blob  # signed with some other key


class UnsignedValueNoteTests(SimpleTestCase):
    def setUp(self):
        self.clock = Clock()
        patcher = mock.patch.object(cache_serializer, '_clock', self.clock, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        warned = getattr(cache_serializer, '_warned', {})
        warned.update(at=None, left_out=0)
        self.addCleanup(warned.update, at=None, left_out=0)
        self.serializer = cache_serializer.SignedRedisSerializer()

    def test_a_thousand_unreadable_reads_write_one_note(self):
        with self.assertLogs('cvengine.cache_serializer', 'WARNING') as logs:
            for _ in range(1000):
                self.assertIsNone(self.serializer.loads(foreign_value()))
        self.assertEqual(len(logs.output), 1)

    def test_the_next_note_after_the_window_counts_what_was_left_out(self):
        with self.assertLogs('cvengine.cache_serializer', 'WARNING') as logs:
            for _ in range(5):
                self.serializer.loads(foreign_value())
            self.clock.now += getattr(cache_serializer, 'WARN_EVERY_SECONDS', 60)
            self.serializer.loads(b'not a cache value at all')
        self.assertEqual(len(logs.output), 2)
        self.assertIn('4 more were ignored since the last note', logs.output[1])

    def test_values_this_installation_wrote_still_read_back(self):
        for value in ({'k': [1, 2]}, 'text', 7, True, None):
            self.assertEqual(self.serializer.loads(self.serializer.dumps(value)), value)
