"""Model fields that keep a secret encrypted in the database.

API keys, webhook URLs and tokens used to sit in plaintext columns: a database dump, a backup or a read-only SQL injection
would hand them over. These fields encrypt with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived from Django's
``SECRET_KEY`` (HKDF-SHA256, a fixed context string), so the database alone is not enough to read them.

Reads are backward compatible: a stored value without the ``enc:v1:`` marker is a plaintext value from before the migration and
is returned as it is, and the next save writes it encrypted (the ``encrypt_existing_*`` data migrations do that for every row).
A value that cannot be decrypted (the ``SECRET_KEY`` changed) reads as empty and is logged: the key has to be entered again, which
is better than handing ciphertext to a scanner as if it were a key. Empty values stay empty so ``blank`` checks keep working.

Not for anything that is looked up by value: the ciphertext differs on every write.
"""
import base64
import functools
import json
import logging

from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)

PREFIX = 'enc:v1:'
JSON_MARKER = '__enc'
ENCRYPTED_COLUMN_LENGTH = 1200  # room for a plaintext of about 800 characters once encrypted and base64 encoded


@functools.lru_cache(maxsize=4)
def _fernet(secret_key):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'cvengine/field-encryption/v1').derive(secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_text(plain):
    """``enc:v1:<token>`` for a plaintext string; a value that is already encrypted is returned unchanged."""
    if plain is None or plain == '' or str(plain).startswith(PREFIX):
        return plain
    return PREFIX + _fernet(settings.SECRET_KEY).encrypt(str(plain).encode()).decode()


def decrypt_text(value):
    """The plaintext of an ``enc:v1:`` value; anything else is legacy plaintext and comes back as it is. Undecryptable reads as ''."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    from cryptography.fernet import InvalidToken
    try:
        return _fernet(settings.SECRET_KEY).decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        logger.warning('a stored secret could not be decrypted: SECRET_KEY changed? enter it again')
        return ''


class EncryptedCharField(models.CharField):
    """A CharField whose database value is encrypted; the Python value is always the plaintext."""

    def from_db_value(self, value, expression, connection):
        return decrypt_text(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encrypt_text(value) if isinstance(value, str) else value


class EncryptedJSONField(models.JSONField):
    """A JSONField whose non-empty dict is stored as ``{"__enc": "enc:v1:<token>"}`` (the column stays jsonb)."""

    def from_db_value(self, value, expression, connection):
        value = super().from_db_value(value, expression, connection)
        if isinstance(value, dict) and set(value) == {JSON_MARKER}:
            plain = decrypt_text(value[JSON_MARKER])
            try:
                return json.loads(plain) if plain else {}
            except ValueError:
                return {}
        return value

    def get_db_prep_value(self, value, connection, prepared=False):
        if isinstance(value, dict) and value and JSON_MARKER not in value:
            value = {JSON_MARKER: encrypt_text(json.dumps(value, sort_keys=True))}
        return super().get_db_prep_value(value, connection, prepared)
