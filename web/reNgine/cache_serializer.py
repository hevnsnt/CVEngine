"""A signed serializer for the Django cache.

Django's Redis cache pickles every value that is not a plain int, and every read unpickles what it finds in Redis, so anyone who can write to
Redis (its password, or a foothold on the data network) could run code in web, celery and celery-beat. Here each pickled value carries an
HMAC (SHA-256, keyed with the Django secret) and a value whose signature does not check out is never unpickled: it reads as ``None``, a miss.
Plain ints stay unpickled exactly as Django stores them, so ``incr``, ``decr`` and the raw Redis TTL reads keep working; an int cannot run code.

Changing the Django secret makes every cached value a miss once, like a Redis restart."""
import hmac
import logging
import pickle

from django.core.cache.backends.redis import RedisSerializer
from django.utils.crypto import salted_hmac

logger = logging.getLogger(__name__)

MAGIC = b'cvs1'  # format marker, so a later format can be told apart
SALT = 'reNgine.cache_serializer.SignedRedisSerializer'
MAC_BYTES = 32  # SHA-256


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
        logger.warning('cache: a value without a valid signature was ignored (written by something other than this installation)')
        return None
