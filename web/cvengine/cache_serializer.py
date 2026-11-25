"""A signed serializer for the Django cache.

Django's Redis cache pickles every value that is not a plain int, and every read unpickles what it finds in Redis, so anyone who can write to
Redis (its password, or a foothold on the data network) could run code in web, celery and celery-beat. Here each pickled value carries an
HMAC (SHA-256, keyed with the Django secret) and a value whose signature does not check out is never unpickled: it reads as ``None``, a miss.
Plain ints stay unpickled exactly as Django stores them, so ``incr``, ``decr`` and the raw Redis TTL reads keep working; an int cannot run code.

Changing the Django secret makes every cached value a miss once, like a Redis restart.

A value written under an earlier secret stays in Redis until it expires, and one written with no expiry stays for good, so a process can read the same
unreadable value hundreds of times a second. The note about it is written at most once per ``WARN_EVERY_SECONDS`` per process, with the number of
reads it left out: on production a key kept from before a secret rotation wrote 250 such lines a second into the worker log.
"""
import hmac
import logging
import pickle
import threading
import time

from django.core.cache.backends.redis import RedisSerializer
from django.utils.crypto import salted_hmac

logger = logging.getLogger(__name__)

MAGIC = b'cvs1'  # format marker, so a later format can be told apart
SALT = 'cvengine.cache_serializer.SignedRedisSerializer'
MAC_BYTES = 32  # SHA-256
WARN_EVERY_SECONDS = 60
_warned = {'at': None, 'left_out': 0}
_warn_lock = threading.Lock()
_clock = time.monotonic


def _warn_unsigned():
    """Log the ignored value, at most once per ``WARN_EVERY_SECONDS``, saying how many more were ignored since the last note."""
    with _warn_lock:
        now = _clock()
        if _warned['at'] is not None and now - _warned['at'] < WARN_EVERY_SECONDS:
            _warned['left_out'] += 1
            return
        left_out = _warned['left_out']
        _warned.update(at=now, left_out=0)
    logger.warning('cache: a value without a valid signature was ignored (written by something other than this installation, or before '
                   'its secret key changed)%s', f'; {left_out} more were ignored since the last note' if left_out else '')


def _mac(blob):
    return salted_hmac(SALT, blob, algorithm='sha256').digest()


class SignedRedisSerializer(RedisSerializer):
    def dumps(self, obj):
        if type(obj) is int:  # as Django: only true ints, not bool, stay raw for incr() and decr()
            return obj
        blob = pickle.dumps(obj, self.protocol)
        return MAGIC + _mac(blob) + blob

    def loads(self, data):
        try:
            return int(data)
        except ValueError:
            pass
        data = bytes(data)
        head = len(MAGIC) + MAC_BYTES
        if len(data) > head and data.startswith(MAGIC):
            mac, blob = data[len(MAGIC):head], data[head:]
            if hmac.compare_digest(mac, _mac(blob)):
                return pickle.loads(blob)
        _warn_unsigned()
        return None
