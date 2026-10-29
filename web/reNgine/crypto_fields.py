"""Model fields that keep a secret encrypted in the database.

API keys, webhook URLs and tokens used to sit in plaintext columns: a database dump, a backup or a read-only SQL injection
would hand them over. These fields encrypt with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived from Django's
``SECRET_KEY`` (HKDF-SHA256, a fixed context string), so the database alone is not enough to read them.

Reads are backward compatible: a stored value without the ``enc:v1:`` marker is a plaintext value from before the migration and
is returned as it is, and the next save writes it encrypted (the ``encrypt_existing_*`` data migrations do that for every row).
A value that cannot be decrypted (the ``SECRET_KEY`` changed) reads as empty and is logged: the key has to be entered again, which
is better than handing ciphertext to a scanner as if it were a key. Empty values stay empty so ``blank`` checks keep working.

A dedicated key can be set apart from ``SECRET_KEY`` (``CVENGINE_FIELD_KEY``, see ``dedicated_keys``): then the secret that signs
sessions and the key that protects the stored API keys are different, the key does not have to live in the ``web/secret`` file every
container reads, and it can be rotated (``manage.py rotate_field_key``) without logging everyone out.

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


def _derive(secret, info):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return base64.urlsafe_b64encode(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret.encode()))


@functools.lru_cache(maxsize=4)
def _fernet(secret_key):
    from cryptography.fernet import Fernet
    return Fernet(_derive(secret_key, b'cvengine/field-encryption/v1'))


def _read_key_file(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return handle.read().strip()
    except OSError:
        logger.warning('the field key file %s cannot be read', path)
        return ''


def dedicated_keys():
    """The encryption keys set for these fields apart from Django's SECRET_KEY, newest first: ``CVENGINE_FIELD_KEY`` (or the file named by
    ``CVENGINE_FIELD_KEY_FILE``, for a Docker secret) followed by every key in ``CVENGINE_FIELD_KEY_PREVIOUS`` (comma separated), which
    only decrypt. Empty when none is set: the fields then use the key derived from SECRET_KEY, as before."""
    import os
    primary = os.environ.get('CVENGINE_FIELD_KEY', '').strip()
    if not primary and os.environ.get('CVENGINE_FIELD_KEY_FILE'):
        primary = _read_key_file(os.environ['CVENGINE_FIELD_KEY_FILE'])
    previous = [k.strip() for k in os.environ.get('CVENGINE_FIELD_KEY_PREVIOUS', '').split(',') if k.strip()]
    return tuple(k for k in (primary, *previous) if k)


@functools.lru_cache(maxsize=8)
def _cipher(secret_key, dedicated):
    """Encrypts with the first key; decrypts with any. With a dedicated key set, the SECRET_KEY-derived key stays last, so values
    written before it was set still read (and are re-encrypted under the new key by the next save or ``rotate_field_key``)."""
    from cryptography.fernet import Fernet, MultiFernet
    keys = [Fernet(_derive(k, b'cvengine/field-encryption/v2')) for k in dedicated] + [_fernet(secret_key)]
    return MultiFernet(keys)


def encrypt_text(plain):
    """``enc:v1:<token>`` for a plaintext string; a value that is already encrypted is returned unchanged."""
    if plain is None or plain == '' or str(plain).startswith(PREFIX):
        return plain
    return PREFIX + _cipher(settings.SECRET_KEY, dedicated_keys()).encrypt(str(plain).encode()).decode()


def decrypt_text(value):
    """The plaintext of an ``enc:v1:`` value; anything else is legacy plaintext and comes back as it is. Undecryptable reads as ''."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    from cryptography.fernet import InvalidToken
    try:
        return _cipher(settings.SECRET_KEY, dedicated_keys()).decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        logger.warning('a stored secret could not be decrypted: the key changed? enter it again')
        return ''


def encrypted_fields():
    """Every ``(model, [encrypted field names])`` in the project, for rotation."""
    from django.apps import apps
    found = []
    for model in apps.get_models():
        names = [f.name for f in model._meta.concrete_fields if isinstance(f, (EncryptedCharField, EncryptedTextField, EncryptedJSONField))]
        if names:
            found.append((model, names))
    return found


class EncryptedCharField(models.CharField):
    """A CharField whose database value is encrypted; the Python value is always the plaintext."""

    def from_db_value(self, value, expression, connection):
        return decrypt_text(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encrypt_text(value) if isinstance(value, str) else value


class EncryptedTextField(models.TextField):
    """A TextField (no length limit, several lines) whose database value is encrypted; the Python value is always the plaintext."""

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
