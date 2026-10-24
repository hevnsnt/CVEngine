"""TOTP (RFC 6238) and recovery codes. Pure stdlib, so it is unit-testable and dependency free."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1  # accept one step either side for clock drift
RECOVERY_CODE_COUNT = 8
ISSUER = 'CVEngine'


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _counter(for_time=None):
    return int((time.time() if for_time is None else for_time) // STEP)


def hotp(secret, counter, digits=DIGITS):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def totp(secret, for_time=None):
    return hotp(secret, _counter(for_time))


def verify(secret, code, for_time=None, last_used_step=0):
    """Return the matched time step (to store, blocking replay) or None."""
    code = (code or '').strip().replace(' ', '')
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    now = _counter(for_time)
    for step in range(now - WINDOW, now + WINDOW + 1):
        if step > last_used_step and hmac.compare_digest(hotp(secret, step), code):
            return step
    return None


def otpauth_uri(secret, username):
    label = quote(f'{ISSUER}:{username}')
    return f'otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&digits={DIGITS}&period={STEP}'


def _hash(code):
    return hashlib.sha256(code.strip().lower().replace('-', '').encode()).hexdigest()


def new_recovery_codes():
    """Return (plain codes to show once, hashes to store)."""
    plain = [f'{secrets.token_hex(3)}-{secrets.token_hex(3)}' for _ in range(RECOVERY_CODE_COUNT)]
    return plain, [_hash(c) for c in plain]


def consume_recovery_code(hashes, code):
    """Return the remaining hashes if ``code`` matched one (single use), else None."""
    digest = _hash(code)
    for stored in hashes:
        if hmac.compare_digest(stored, digest):
            return [h for h in hashes if h != stored]
    return None
