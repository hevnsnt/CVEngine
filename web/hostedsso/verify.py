"""Strict verification of the single sign-on assertion and the back-channel logout token.

Compact JWS, Ed25519 only. The header is compared exactly (alg, typ, kid and nothing else), the key comes only from the local JWKS file by its
``kid``, and every failure is the same ``SsoError`` to the caller: the reason code is logged, never the token and never the answer given to the
client. Nothing here talks to the network."""
import base64
import json
import logging
import os
import re
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings

logger = logging.getLogger(__name__)

LEEWAY = 30  # seconds of clock difference tolerated in either direction
MAX_LIFETIME = 120  # exp - iat
MAX_TOKEN_BYTES = 4096
ASSERTION, LOGOUT = 'assertion', 'logout'
TYP = {ASSERTION: 'cvl-sso+jwt', LOGOUT: 'cvl-logout+jwt'}
ACCEPTED_STATUSES = ('current', 'next', 'retiring')
HEADER_MEMBERS = frozenset({'alg', 'typ', 'kid'})
COMPACT = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
HEX32 = re.compile(r'^[0-9a-f]{32}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
KID = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
SUBJECT = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
AMR_MFA = ('otp', 'hwk')


class SsoError(Exception):
    """Any reason a token is refused. ``code`` is for the server log only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ---- encoding helpers --------------------------------------------------------------------------------------------------------------------------

def _b64d(segment):
    try:
        raw = base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
    except (ValueError, TypeError):
        raise SsoError('bad_base64')
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != segment:  # not the canonical encoding (stray bits): refuse rather than guess
        raise SsoError('bad_base64')
    return raw


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate member')
        out[key] = value
    return out


def _json_object(raw, code):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise SsoError(code)
    if not isinstance(value, dict):
        raise SsoError(code)
    return value


# ---- the local key file ------------------------------------------------------------------------------------------------------------------------

_lock = threading.Lock()
_cache = {'sig': None, 'keys': {}}


def _load_keys(path):
    with open(path, 'rb') as handle:
        document = json.loads(handle.read().decode('utf-8'))
    keys = {}
    for entry in document.get('keys', []) if isinstance(document, dict) else []:
        try:
            if (entry.get('kty') != 'OKP' or entry.get('crv') != 'Ed25519' or entry.get('status') not in ACCEPTED_STATUSES
                    or not isinstance(entry.get('kid'), str) or not KID.match(entry['kid']) or entry['kid'] in keys):
                continue
            raw = _b64d(entry['x'])
            if len(raw) != 32:
                continue
            keys[entry['kid']] = Ed25519PublicKey.from_public_bytes(raw)
        except (AttributeError, KeyError, TypeError, ValueError, SsoError):
            continue
    return keys


def public_keys():
    """The accepted public keys of the local JWKS file by kid, re-read when the file changes. A missing or unreadable file means no keys at all
    (every token is refused), which is also how an emergency revoke works: the file is replaced without the kid."""
    path = settings.CVENGINE_SSO_KEYS_FILE
    try:
        stat = os.stat(path)
        signature = (path, stat.st_mtime_ns, stat.st_size, stat.st_ino)
    except OSError:
        signature = None
    with _lock:
        if signature != _cache['sig'] or signature is None:
            if signature is None:
                keys = {}
            else:
                try:
                    keys = _load_keys(path)
                except (OSError, ValueError):
                    logger.warning('sso: the key file could not be read')
                    keys = {}
            _cache.update(sig=signature, keys=keys)
        return _cache['keys']


# ---- claims ------------------------------------------------------------------------------------------------------------------------------------

def audience():
    configured = (settings.CVENGINE_SSO_AUDIENCE or '').strip().rstrip('/')
    return configured or 'https://' + settings.DOMAIN_NAME.strip().rstrip('/')


def _int(value):
    return type(value) is int


def _id_text(value):
    """A site id may travel as a number or as text; it is compared as text everywhere."""
    if type(value) is int and value >= 0:
        return str(value)
    return value if isinstance(value, str) else None


def _check_claims(claims, purpose, now):
    required = (('iss', 'aud', 'iat', 'exp', 'jti') if purpose == LOGOUT else
                ('iss', 'aud', 'srv', 'cus', 'slug', 'sub', 'email', 'cvl_role', 'mfa', 'amr', 'auth_time', 'iat', 'nbf', 'exp', 'jti', 'nonce',
                 'sid', 'sexp'))
    for name in required:
        if name not in claims:
            raise SsoError('claim_missing')
    if claims['iss'] != settings.CVENGINE_SSO_ISSUER or not isinstance(claims['iss'], str):
        raise SsoError('bad_iss')
    if claims['aud'] != audience() or not isinstance(claims['aud'], str):
        raise SsoError('bad_aud')
    for name in ('iat', 'exp') + (('nbf', 'auth_time', 'sexp') if purpose == ASSERTION else ()):
        if not _int(claims[name]):
            raise SsoError('claim_type')
    if not isinstance(claims['jti'], str) or not HEX32.match(claims['jti']):
        raise SsoError('bad_jti')
    if claims['iat'] > now + LEEWAY:
        raise SsoError('iat_future')
    if claims['exp'] <= now - LEEWAY:
        raise SsoError('expired')
    if claims['exp'] < claims['iat'] or claims['exp'] - claims['iat'] > MAX_LIFETIME:
        raise SsoError('lifetime')
    if purpose == LOGOUT:
        sid, sub = claims.get('sid'), _id_text(claims.get('sub')) if 'sub' in claims else None
        if 'sid' not in claims and 'sub' not in claims:
            raise SsoError('claim_missing')
        if 'sid' in claims and not (isinstance(sid, str) and HEX32.match(sid)):
            raise SsoError('bad_sid')
        if 'sub' in claims and not (sub and SUBJECT.match(sub)):
            raise SsoError('bad_sub')
        return
    if claims['nbf'] > now + LEEWAY:
        raise SsoError('nbf_future')
    if claims['mfa'] is not True:
        raise SsoError('no_mfa')
    amr = claims['amr']
    if not (isinstance(amr, list) and all(isinstance(a, str) for a in amr)) or not any(a in AMR_MFA for a in amr):
        raise SsoError('amr')
    if claims['auth_time'] > now + LEEWAY or now - claims['auth_time'] > settings.CVENGINE_SSO_MAX_AUTH_AGE:
        raise SsoError('auth_time')
    if claims['sexp'] <= now:
        raise SsoError('family_expired')
    sub = _id_text(claims['sub'])
    if not (sub and SUBJECT.match(sub)):
        raise SsoError('bad_sub')
    if _id_text(claims['srv']) is None or _id_text(claims['cus']) is None:
        raise SsoError('claim_type')
    if not isinstance(claims['slug'], str) or not isinstance(claims['email'], str) or not 3 <= len(claims['email']) <= 254 or '@' not in claims['email']:
        raise SsoError('claim_type')
    if claims['cvl_role'] != 'owner':
        raise SsoError('bad_role')
    if not (isinstance(claims['nonce'], str) and HEX64.match(claims['nonce'])) or not (isinstance(claims['sid'], str) and HEX32.match(claims['sid'])):
        raise SsoError('bad_binding_claim')


def verify(token, purpose=ASSERTION, now=None):
    """Return the verified claims, or raise SsoError. ``purpose`` is ``assertion`` or ``logout`` and fixes the expected header ``typ``."""
    try:
        claims = _verify(token, purpose, int(time.time()) if now is None else now)
    except SsoError as exc:
        logger.warning('sso: %s refused (%s)', purpose, exc.code)
        raise
    except Exception:  # noqa: BLE001  a bug or a hostile shape must still be a plain refusal
        logger.exception('sso: %s refused (internal)', purpose)
        raise SsoError('internal')
    return claims


def _verify(token, purpose, now):
    if purpose not in TYP:
        raise SsoError('purpose')
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or not COMPACT.match(token):
        raise SsoError('format')
    head_b64, payload_b64, sig_b64 = token.split('.')
    header = _json_object(_b64d(head_b64), 'bad_header')
    if set(header) != HEADER_MEMBERS:  # jwk, jku, x5u, x5c, crit and anything else are refused outright
        raise SsoError('header_members')
    if header['alg'] != 'EdDSA' or not isinstance(header['alg'], str):
        raise SsoError('bad_alg')
    if header['typ'] != TYP[purpose] or not isinstance(header['typ'], str):
        raise SsoError('bad_typ')
    kid = header['kid']
    if not isinstance(kid, str) or not KID.match(kid):
        raise SsoError('bad_kid')
    key = public_keys().get(kid)
    if key is None:
        raise SsoError('unknown_kid')
    signature = _b64d(sig_b64)
    if len(signature) != 64:
        raise SsoError('bad_signature')
    try:
        key.verify(signature, (head_b64 + '.' + payload_b64).encode('ascii'))
    except InvalidSignature:
        raise SsoError('bad_signature')
    claims = _json_object(_b64d(payload_b64), 'bad_payload')
    _check_claims(claims, purpose, now)
    return claims
