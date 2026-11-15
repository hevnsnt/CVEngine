"""Hosted single sign-on (web/hostedsso/README.md): the strict assertion verifier, the exchange and back-channel endpoints, the per-request binding,
the step-up rule, login gating and break-glass, and the proof that all of it is off by default.

No network and no fixed secrets: every key pair is generated here with ``cryptography``. A fixed vector from the site repository is verified as well
when it is on disk (see FixedVectorTests)."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from io import StringIO
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponse
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import AuditLog, Org, OrgMembership, Project, UserProfile
from hostedsso import gating, middleware as sso_middleware
from hostedsso.common import sso_url, stepup_url
from hostedsso.models import SsoIdentity, SsoJti
from hostedsso.verify import ASSERTION, LOGOUT, SsoError, verify
from tenancy import mfa
from tenancy.middleware import TenancyMiddleware

AUD = 'https://s-ab12cd34.cvengine.live'
ISS = 'https://cvengine.live'
SUB = '4711'
EDGE = {'HTTP_X_CVL_EDGE_VERIFIED': '1'}
EXCH = {**EDGE, 'HTTP_X_CVL_SSO_EXCHANGE': '1'}  # what nginx forwards on an exchange call behind a valid secret
WEB = Path(__file__).resolve().parents[1]


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def jws(header, claims, key, tamper=None):
    head = b64u(json.dumps(header, separators=(',', ':')).encode())
    body = b64u(json.dumps(claims, separators=(',', ':')).encode())
    signature = key.sign((head + '.' + body).encode()) if key is not None else b''
    return head + '.' + body + '.' + b64u(signature)


def good_claims(now=None, **override):
    now = int(time.time()) if now is None else now
    claims = {
        'iss': ISS, 'aud': AUD, 'srv': 'srv_1', 'cus': 'cus_1', 'slug': 'acme', 'sub': SUB, 'email': 'owner@example.com', 'cvl_role': 'owner',
        'mfa': True, 'amr': ['pwd', 'otp'], 'auth_time': now - 60, 'iat': now, 'nbf': now, 'exp': now + 60,
        'jti': os.urandom(16).hex(), 'nonce': os.urandom(32).hex(), 'sid': os.urandom(16).hex(), 'sexp': now + 86400}
    claims.update(override)
    return {k: v for k, v in claims.items() if v is not None}


def logout_claims(now=None, **override):
    now = int(time.time()) if now is None else now
    claims = {'iss': ISS, 'aud': AUD, 'iat': now, 'exp': now + 60, 'jti': os.urandom(16).hex(), 'sid': os.urandom(16).hex()}
    claims.update(override)
    return {k: v for k, v in claims.items() if v is not None}


def jwk(kid, key, status='current'):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {'kid': kid, 'kty': 'OKP', 'crv': 'Ed25519', 'x': b64u(raw), 'status': status}


class KeyedCase:
    """A temporary JWKS file with one current key, the matching settings, and signing helpers."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.keys_file = Path(self._dir.name) / 'sso-keys.json'
        self.key = Ed25519PrivateKey.generate()
        self.write_keys([jwk('k1', self.key)])
        override = override_settings(CVENGINE_HOSTED=True, CVENGINE_SSO=True, CVENGINE_SSO_ENFORCE=False, CVENGINE_SSO_KEYS_FILE=str(self.keys_file),
                                     CVENGINE_SSO_ISSUER=ISS, CVENGINE_SSO_AUDIENCE=AUD, CVENGINE_SSO_MAX_AUTH_AGE=43200,
                                     CVENGINE_SSO_STEPUP_AGE=900, CVENGINE_SSO_BREAKGLASS_UNTIL=0, ALLOWED_HOSTS=['*'])
        override.enable()
        self.addCleanup(override.disable)

    def write_keys(self, entries):
        self.keys_file.write_text(json.dumps({'keys': entries}))
        stat = self.keys_file.stat()
        os.utime(self.keys_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000 * len(entries) + time.time_ns() % 1000))  # a distinct mtime for the cache

    def token(self, claims=None, header=None, key=None, purpose=ASSERTION):
        typ = 'cvl-sso+jwt' if purpose == ASSERTION else 'cvl-logout+jwt'
        header = {'alg': 'EdDSA', 'typ': typ, 'kid': 'k1'} if header is None else header
        claims = (good_claims() if purpose == ASSERTION else logout_claims()) if claims is None else claims
        return jws(header, claims, key or self.key)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# the verifier
# ---------------------------------------------------------------------------------------------------------------------------------------------

class VerifyTests(KeyedCase, SimpleTestCase):
    def refused(self, token, code=None, purpose=ASSERTION, now=None):
        with self.assertLogs('hostedsso.verify', 'WARNING') as logs:
            with self.assertRaises(SsoError) as caught:
                verify(token, purpose, now=now)
        if code:
            self.assertEqual(caught.exception.code, code)
        if token.split('.')[2]:
            self.assertNotIn(token.split('.')[2], '\n'.join(logs.output))  # the log names a reason, never token content
        return caught.exception

    def test_a_valid_assertion_is_accepted(self):
        claims = good_claims()
        self.assertEqual(verify(self.token(claims), ASSERTION)['sub'], SUB)

    def test_a_valid_logout_token_is_accepted(self):
        self.assertIn('sid', verify(self.token(purpose=LOGOUT), LOGOUT))

    def test_wrong_audience(self):
        self.refused(self.token(good_claims(aud='https://s-other.cvengine.live')), 'bad_aud')

    def test_wrong_issuer(self):
        self.refused(self.token(good_claims(iss='https://evil.example')), 'bad_iss')

    def test_audience_is_derived_from_the_domain_name_when_not_set(self):
        with override_settings(CVENGINE_SSO_AUDIENCE='', DOMAIN_NAME='s-ab12cd34.cvengine.live'):
            self.assertEqual(verify(self.token(good_claims()), ASSERTION)['aud'], AUD)

    def test_expired(self):
        now = int(time.time())
        self.refused(self.token(good_claims(now - 300)), 'expired')

    def test_expired_within_the_leeway_is_accepted(self):
        now = int(time.time())
        claims = good_claims(now - 80)  # exp = now - 20
        self.assertTrue(verify(self.token(claims), ASSERTION))

    def test_not_before_in_the_future(self):
        now = int(time.time())
        self.refused(self.token(good_claims(nbf=now + 120)), 'nbf_future')

    def test_issued_more_than_30_seconds_in_the_future(self):
        now = int(time.time())
        self.refused(self.token(good_claims(iat=now + 90, nbf=now, exp=now + 150)), 'iat_future')

    def test_skew_inside_30_seconds_is_tolerated(self):
        now = int(time.time())
        self.assertTrue(verify(self.token(good_claims(iat=now + 20, nbf=now + 20, exp=now + 80)), ASSERTION))

    def test_lifetime_over_120_seconds(self):
        now = int(time.time())
        self.refused(self.token(good_claims(exp=now + 400)), 'lifetime')

    def test_alg_none(self):
        head = b64u(json.dumps({'alg': 'none', 'typ': 'cvl-sso+jwt', 'kid': 'k1'}).encode())
        token = head + '.' + b64u(json.dumps(good_claims()).encode()) + '.'
        self.refused(token, 'format')
        self.refused(head + '.' + b64u(json.dumps(good_claims()).encode()) + '.' + b64u(b'x' * 64), 'bad_alg')

    def test_alg_hs256_signed_with_the_public_key_material(self):
        import hashlib
        import hmac
        public = jwk('k1', self.key)['x'].encode()
        head = b64u(json.dumps({'alg': 'HS256', 'typ': 'cvl-sso+jwt', 'kid': 'k1'}).encode())
        body = b64u(json.dumps(good_claims()).encode())
        sig = b64u(hmac.new(public, (head + '.' + body).encode(), hashlib.sha256).digest())
        self.refused(head + '.' + body + '.' + sig, 'bad_alg')

    def test_alg_es256(self):
        ec = generate_private_key(SECP256R1())
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
        head = b64u(json.dumps({'alg': 'ES256', 'typ': 'cvl-sso+jwt', 'kid': 'k1'}).encode())
        body = b64u(json.dumps(good_claims()).encode())
        sig = b64u(ec.sign((head + '.' + body).encode(), ec_mod.ECDSA(hashes.SHA256())))
        self.refused(head + '.' + body + '.' + sig, 'bad_alg')

    def test_wrong_typ_for_the_purpose(self):
        self.refused(self.token(header={'alg': 'EdDSA', 'typ': 'cvl-logout+jwt', 'kid': 'k1'}), 'bad_typ')
        self.refused(self.token(purpose=LOGOUT), 'bad_typ', purpose=ASSERTION)
        self.refused(self.token(), 'bad_typ', purpose=LOGOUT)
        self.refused(self.token(header={'alg': 'EdDSA', 'typ': 'JWT', 'kid': 'k1'}), 'bad_typ')

    def test_unknown_kid(self):
        self.refused(self.token(header={'alg': 'EdDSA', 'typ': 'cvl-sso+jwt', 'kid': 'nope'}), 'unknown_kid')

    def test_revoked_kid_is_one_that_is_absent_from_the_file(self):
        token = self.token()
        self.assertTrue(verify(token, ASSERTION))
        self.write_keys([jwk('k2', Ed25519PrivateKey.generate())])  # emergency revoke: a file without k1
        self.refused(token, 'unknown_kid')

    def test_a_key_with_an_unlisted_status_is_not_used(self):
        self.write_keys([jwk('k1', self.key, status='revoked')])
        self.refused(self.token(), 'unknown_kid')

    def test_current_next_and_retiring_are_all_accepted(self):
        other, third = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.write_keys([jwk('k1', self.key, 'retiring'), jwk('k2', other, 'current'), jwk('k3', third, 'next')])
        for kid, key in (('k1', self.key), ('k2', other), ('k3', third)):
            self.assertTrue(verify(jws({'alg': 'EdDSA', 'typ': 'cvl-sso+jwt', 'kid': kid}, good_claims(), key), ASSERTION))

    def test_the_key_file_is_reloaded_when_it_changes(self):
        token = self.token(key=Ed25519PrivateKey.generate())
        self.refused(token, 'bad_signature')
        self.write_keys([jwk('k1', Ed25519PrivateKey.generate())])
        self.refused(token, 'bad_signature')

    def test_a_missing_key_file_fails_closed(self):
        self.keys_file.unlink()
        self.refused(self.token(), 'unknown_kid')

    def test_a_garbled_key_file_fails_closed(self):
        self.keys_file.write_text('{not json')
        os.utime(self.keys_file, ns=(1, time.time_ns() + 9_000_000_000))
        self.refused(self.token(), 'unknown_kid')

    def test_an_empty_key_file_fails_closed_and_is_read_again_once_it_is_filled(self):
        """The file is rewritten in place, so a read can land on the truncated, still empty file: nothing verifies, and the failure is not remembered."""
        good = json.dumps({'keys': [jwk('k1', self.key)]})
        self.keys_file.write_text('')
        os.utime(self.keys_file, ns=(1, 4_000_000_000_000_000_000))
        self.refused(self.token(), 'unknown_kid')
        self.keys_file.write_text(good)
        os.utime(self.keys_file, ns=(1, 4_000_000_000_000_000_000))  # the very same mtime as the truncated read
        self.assertTrue(verify(self.token(), ASSERTION))

    def test_a_half_written_key_file_fails_closed_and_the_failure_is_not_cached(self):
        good = json.dumps({'keys': [jwk('k1', self.key)]})
        broken_forms = (good[:len(good) // 2], '{"keys": [', '\x00' * len(good), ' ' * len(good), good[:-1], good.replace('{"keys": [', '{"keys": ', 1)[:-1])
        for index, broken in enumerate(broken_forms):
            mtime = 4_100_000_000_000_000_000 + index * 1_000_000_000  # each rewrite has its own mtime; the repair below keeps the broken one's
            self.keys_file.write_text(broken)
            os.utime(self.keys_file, ns=(1, mtime))
            self.refused(self.token(), 'unknown_kid')
            self.keys_file.write_text(good)
            os.utime(self.keys_file, ns=(1, mtime))
            self.assertTrue(verify(self.token(), ASSERTION), broken[:12])

    def test_an_unreadable_key_file_fails_closed(self):
        with mock.patch('hostedsso.verify.open', side_effect=PermissionError('no'), create=True):
            self.write_keys([jwk('k1', self.key)])
            self.refused(self.token(), 'unknown_kid')

    def test_a_key_file_that_is_not_an_object_or_has_no_usable_key_fails_closed(self):
        for text in ('[]', 'null', '{}', '{"keys": "x"}', '{"keys": [1, "a", null]}', '{"keys": [{"kid": "k1"}]}'):
            self.keys_file.write_text(text)
            os.utime(self.keys_file, ns=(1, time.time_ns() + 20_000_000_000 + len(text)))
            self.refused(self.token(), 'unknown_kid')

    def test_jwk_and_other_key_carrying_header_members(self):
        for extra in ({'jwk': {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'AAAA'}}, {'jku': 'https://evil.example/k'}, {'x5u': 'https://evil.example/c'},
                      {'x5c': ['AAAA']}, {'crit': ['exp']}, {'cty': 'JWT'}):
            header = {'alg': 'EdDSA', 'typ': 'cvl-sso+jwt', 'kid': 'k1', **extra}
            self.refused(self.token(header=header), 'header_members')

    def test_missing_header_members(self):
        self.refused(self.token(header={'alg': 'EdDSA', 'typ': 'cvl-sso+jwt'}), 'header_members')

    def test_duplicate_header_members(self):
        head = b64u(b'{"alg":"EdDSA","alg":"EdDSA","typ":"cvl-sso+jwt","kid":"k1"}')
        body = b64u(json.dumps(good_claims()).encode())
        self.refused(head + '.' + body + '.' + b64u(self.key.sign((head + '.' + body).encode())), 'bad_header')

    def test_bad_signature(self):
        token = self.token()
        head, body, sig = token.split('.')
        flipped = ('A' if sig[0] != 'A' else 'B') + sig[1:]
        self.refused(f'{head}.{body}.{flipped}', None)

    def test_truncated_signature(self):
        head, body, sig = self.token().split('.')
        self.refused(f'{head}.{body}.{sig[:-8]}')  # not even a whole encoding
        raw = base64.urlsafe_b64decode(sig + '==')
        self.refused(f'{head}.{body}.{b64u(raw[:32])}', 'bad_signature')  # a well-formed but short signature
        self.refused(f'{head}.{body}.', 'format')
        with self.assertRaises(SsoError), self.assertLogs('hostedsso.verify', 'WARNING'):
            verify(f'{head}.{body}', ASSERTION)

    def test_signature_over_other_claims(self):
        head, body, sig = self.token().split('.')
        other = b64u(json.dumps(good_claims(email='attacker@example.com')).encode())
        self.refused(f'{head}.{other}.{sig}', 'bad_signature')

    def test_missing_mfa(self):
        self.refused(self.token(good_claims(mfa=None)), 'claim_missing')

    def test_mfa_false_or_not_boolean_true(self):
        self.refused(self.token(good_claims(mfa=False)), 'no_mfa')
        self.refused(self.token(good_claims(mfa='true')), 'no_mfa')
        self.refused(self.token(good_claims(mfa=1)), 'no_mfa')

    def test_amr_with_only_a_password(self):
        self.refused(self.token(good_claims(amr=['pwd'])), 'amr')
        self.refused(self.token(good_claims(amr=['pwd', 'rec'])), 'amr')
        self.refused(self.token(good_claims(amr='otp')), 'amr')
        self.refused(self.token(good_claims(amr=[])), 'amr')

    def test_hardware_key_amr_is_enough(self):
        self.assertTrue(verify(self.token(good_claims(amr=['pwd', 'hwk'])), ASSERTION))

    def test_stale_auth_time(self):
        now = int(time.time())
        self.refused(self.token(good_claims(auth_time=now - 43200 - 60)), 'auth_time')

    def test_auth_time_follows_the_setting(self):
        now = int(time.time())
        with override_settings(CVENGINE_SSO_MAX_AUTH_AGE=100):
            self.refused(self.token(good_claims(auth_time=now - 500)), 'auth_time')

    def test_auth_time_in_the_future(self):
        self.refused(self.token(good_claims(auth_time=int(time.time()) + 600)), 'auth_time')

    def test_every_required_claim_is_required(self):
        for name in good_claims():
            self.refused(self.token(good_claims(**{name: None})), 'claim_missing') if name not in () else None

    def test_claim_types(self):
        now = int(time.time())
        for bad in ({'exp': str(now + 60)}, {'iat': float(now)}, {'iat': True}, {'auth_time': '1'}, {'sexp': None}, {'sub': ['1']},
                    {'sub': 'bad sub!'}, {'jti': 'x' * 32}, {'jti': 'A' * 32}, {'nonce': 'zz'}, {'sid': 'abc'}, {'email': 'no-at-sign'}, {'email': 7},
                    {'cvl_role': 'admin'}, {'slug': 5}, {'srv': None, 'cus': {}}):
            claims = good_claims(**bad)
            if any(v is None for v in bad.values()):
                continue
            self.refused(self.token(claims))

    def test_a_numeric_subject_is_accepted_and_text_too(self):
        self.assertTrue(verify(self.token(good_claims(sub=4711)), ASSERTION))
        self.assertTrue(verify(self.token(good_claims(sub='u_4711')), ASSERTION))

    def test_family_expiry_in_the_past(self):
        self.refused(self.token(good_claims(sexp=int(time.time()) - 5)), 'family_expired')

    def test_logout_token_needs_sid_or_sub(self):
        self.refused(self.token(logout_claims(sid=None), purpose=LOGOUT), 'claim_missing', purpose=LOGOUT)
        self.assertTrue(verify(self.token(logout_claims(sid=None, sub=SUB), purpose=LOGOUT), LOGOUT))

    def test_logout_token_with_wrong_audience(self):
        self.refused(self.token(logout_claims(aud='https://x.cvengine.live'), purpose=LOGOUT), 'bad_aud', purpose=LOGOUT)

    def test_oversized_and_malformed_input(self):
        for token in ('', 'a', 'a.b', 'a.b.c.d', 'a.b.c', '.' * 5, 'é.é.é', 'x' * 5000 + '.b.c', None, 5, b'a.b.c'):
            with self.assertRaises(SsoError):
                verify(token, ASSERTION)

    def test_base64_with_padding_or_stray_bits_is_refused(self):
        head, body, sig = self.token().split('.')
        self.refused(f'{head}=.{body}.{sig}', 'format')
        self.refused(f'{head}.{body}.{sig[:-1]}{"A" if sig[-1] != "A" else "B"}', None)

    def test_a_payload_that_is_not_an_object(self):
        head = b64u(json.dumps({'alg': 'EdDSA', 'typ': 'cvl-sso+jwt', 'kid': 'k1'}).encode())
        body = b64u(b'[1,2]')
        self.refused(head + '.' + body + '.' + b64u(self.key.sign((head + '.' + body).encode())), 'bad_payload')


class FixedVectorTests(KeyedCase, SimpleTestCase):
    """The site repository publishes a deterministic vector (``test/fixtures/sso/vector.json``: a JWKS, an assertion and a logout token with the
    time each is valid at). A copy lives in ``web/tests/fixtures/sso/`` (test data only: its key is the documented test seed, never a real one) and
    the verifier is checked against exactly what the signer produces. CVENGINE_SSO_VECTOR may name another copy."""

    VECTOR = WEB / 'tests' / 'fixtures' / 'sso' / 'vector.json'

    def load(self):
        path = Path(os.environ.get('CVENGINE_SSO_VECTOR') or self.VECTOR)
        self.assertTrue(path.is_file(), f'the fixed SSO vector is missing: {path}')  # a failure, not a skip: the vector is part of this repository
        data = json.loads(path.read_text())
        self.keys_file.write_text(json.dumps(data['jwks']))
        os.utime(self.keys_file, ns=(1, time.time_ns() + 7_000_000_000))
        return data

    def test_the_assertion_and_the_logout_token_verify_at_their_time(self):
        data = self.load()
        aud = data['assertion']['claims']['aud']
        with override_settings(CVENGINE_SSO_AUDIENCE=aud):
            self.assertEqual(verify(data['assertion']['jws'], ASSERTION, now=data['assertion']['now'])['sub'], data['assertion']['claims']['sub'])
            self.assertEqual(verify(data['logout']['jws'], LOGOUT, now=data['logout']['now'])['aud'], aud)

    def test_the_vector_is_rejected_for_another_audience_and_outside_its_window(self):
        data = self.load()
        claims = data['assertion']['claims']
        token = data['assertion']['jws']
        with override_settings(CVENGINE_SSO_AUDIENCE=claims['aud']):
            for now, ok in ((claims['iat'] - 30, True), (claims['iat'] - 31, False), (claims['exp'] + 29, True), (claims['exp'] + 30, False)):
                if ok:
                    self.assertTrue(verify(token, ASSERTION, now=now), now - claims['iat'])
                else:
                    with self.assertRaises(SsoError), self.assertLogs('hostedsso.verify', 'WARNING'):
                        verify(token, ASSERTION, now=now)
        with override_settings(CVENGINE_SSO_AUDIENCE='https://s-other.cvengine.live'), self.assertRaises(SsoError), self.assertLogs('hostedsso.verify', 'WARNING'):
            verify(token, ASSERTION, now=data['assertion']['now'])

    def test_tokens_do_not_cross_purposes_and_any_bit_flip_fails(self):
        data = self.load()
        with override_settings(CVENGINE_SSO_AUDIENCE=data['assertion']['claims']['aud']), self.assertLogs('hostedsso.verify', 'WARNING'):
            with self.assertRaises(SsoError):
                verify(data['logout']['jws'], ASSERTION, now=data['logout']['now'])
            with self.assertRaises(SsoError):
                verify(data['assertion']['jws'], LOGOUT, now=data['assertion']['now'])
            token = data['assertion']['jws']
            head, body, sig = token.split('.')
            for index in range(0, len(sig), 7):  # a sample of positions in each part
                for part, text in (('h', head), ('b', body), ('s', sig)):
                    pos = index % len(text)
                    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
                    changed = text[:pos] + alphabet[(alphabet.index(text[pos]) + 1) % 64] + text[pos + 1:]
                    parts = {'h': (changed, body, sig), 's': (head, body, changed), 'b': (head, changed, sig)}[part]
                    with self.assertRaises(SsoError):
                        verify('.'.join(parts), ASSERTION, now=data['assertion']['now'])


# ---------------------------------------------------------------------------------------------------------------------------------------------
# exchange, back-channel logout
# ---------------------------------------------------------------------------------------------------------------------------------------------

class SsoCase(KeyedCase, TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('owner', 'owner@example.com', 'pw-correct-horse-1')
        self.identity = SsoIdentity.objects.create(user=self.user, issuer=ISS, subject=SUB, email_seen='owner@example.com')

    def exchange(self, assertion=None, client=None, headers=EXCH, method='post', body=None, **claims):
        client = client or Client()
        if assertion is None:
            assertion = self.token(good_claims(**claims))
        payload = body if body is not None else json.dumps({'assertion': assertion})
        if method == 'post':
            return client.post('/sso/exchange', data=payload, content_type='application/json', **headers)
        return getattr(client, method)('/sso/exchange', **headers)

    def signed_in(self, **claims):
        """A client signed in through the exchange, plus the claims it used."""
        client = Client()
        claims.setdefault('sid', os.urandom(16).hex())
        response = self.exchange(client=client, **claims)
        self.assertEqual(response.status_code, 204, getattr(response, 'content', b''))
        return client

    def headers_for(self, sub=SUB, sid=None, **extra):
        return {'HTTP_X_CVL_EDGE_VERIFIED': '1', 'HTTP_X_CVL_SSO_SUB': sub, 'HTTP_X_CVL_SSO_SID': sid, **extra}


class ExchangeTests(SsoCase):
    def test_positive_flow(self):
        sid = os.urandom(16).hex()
        client = Client()
        response = self.exchange(client=client, sid=sid, auth_time=int(time.time()) - 30)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.content, b'')
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)
        session = client.session
        self.assertEqual(session[SESSION_KEY], str(self.user.pk))
        self.assertEqual((session['sso_sub'], session['sso_sid'], session['sso_amr']), (SUB, sid, ['pwd', 'otp']))
        self.assertIsInstance(session['sso_auth_time'], int)
        self.identity.refresh_from_db()
        self.assertIsNotNone(self.identity.last_login_at)
        self.assertTrue(AuditLog.objects.filter(action='sso.login', actor=self.user).exists())
        self.assertTrue(SsoJti.objects.exists())

    def test_the_session_key_is_rotated_and_old_session_data_is_dropped(self):
        client = Client()
        fixated = client.session
        fixated['planted'] = 'x'
        fixated.save()
        client.cookies[settings.SESSION_COOKIE_NAME] = fixated.session_key
        old_key = fixated.session_key
        self.assertEqual(self.exchange(client=client).status_code, 204)
        self.assertNotEqual(client.session.session_key, old_key)
        self.assertNotIn('planted', client.session)

    def test_the_session_lifetime_is_the_shorter_of_family_expiry_and_max_auth_age(self):
        now = int(time.time())
        client = Client()
        self.exchange(client=client, sexp=now + 600)
        self.assertLessEqual(client.session.get_expiry_age(), 600)
        self.assertGreater(client.session.get_expiry_age(), 500)
        client = Client()
        self.exchange(client=client, sexp=now + 10 * 86400)
        self.assertLessEqual(client.session.get_expiry_age(), 43200)
        with override_settings(CVENGINE_SSO_MAX_AUTH_AGE=7200):
            client = Client()
            self.exchange(client=client, sexp=now + 10 * 86400)
            self.assertLessEqual(client.session.get_expiry_age(), 7200)

    def test_a_replayed_jti_is_refused(self):
        token = self.token(good_claims())
        self.assertEqual(self.exchange(token).status_code, 204)
        response = self.exchange(token)
        self.assertEqual((response.status_code, response.json()), (401, {'error': 'invalid_assertion'}))

    def test_jti_rows_older_than_ten_minutes_are_removed_on_each_exchange(self):
        SsoJti.objects.create(jti='a' * 32, expires_at=timezone.now() - timezone.timedelta(seconds=1))
        SsoJti.objects.create(jti='b' * 32, expires_at=timezone.now() + timezone.timedelta(minutes=5))
        self.assertEqual(self.exchange().status_code, 204)
        self.assertIn('b' * 32, set(SsoJti.objects.values_list('jti', flat=True)))
        self.assertFalse(SsoJti.objects.filter(jti='a' * 32).exists())

    def test_every_verification_failure_is_the_same_401(self):
        now = int(time.time())
        cases = [self.token(good_claims(aud='https://x.example')), self.token(good_claims(now - 400)), self.token(good_claims(mfa=False)),
                 self.token(good_claims(amr=['pwd'])), self.token(good_claims(auth_time=now - 99999)), 'garbage', 'a.b.c',
                 self.token(good_claims(), key=Ed25519PrivateKey.generate())]
        for token in cases:
            response = self.exchange(token)
            self.assertEqual((response.status_code, response.json()), (401, {'error': 'invalid_assertion'}))
            self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)

    def test_an_unknown_subject_is_refused_audited_and_gets_no_session(self):
        client = Client()
        response = self.exchange(client=client, sub='99999')
        self.assertEqual((response.status_code, response.json()), (403, {'error': 'not_linked'}))
        self.assertNotIn(SESSION_KEY, client.session)
        row = AuditLog.objects.get(action='sso.not_linked')
        self.assertEqual(row.target, 'sub:99999')

    def test_the_email_is_never_the_key(self):
        other = User.objects.create_user('someone', 'new@example.com', 'pw-correct-horse-1')
        response = self.exchange(sub='55555', email='new@example.com')  # same email as an existing user, unknown subject
        self.assertEqual(response.status_code, 403)
        self.assertFalse(SsoIdentity.objects.filter(user=other).exists())

    def test_the_same_subject_under_another_issuer_is_not_linked(self):
        SsoIdentity.objects.filter(pk=self.identity.pk).update(issuer='https://other.example')
        self.assertEqual(self.exchange().status_code, 403)

    def test_an_inactive_user_is_refused(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        client = Client()
        response = self.exchange(client=client)
        self.assertEqual((response.status_code, response.json()), (403, {'error': 'not_linked'}))
        self.assertNotIn(SESSION_KEY, client.session)
        self.assertTrue(AuditLog.objects.filter(action='sso.refused_inactive').exists())

    def test_missing_edge_verified_is_404(self):
        for headers in ({}, {'HTTP_X_CVL_EDGE_VERIFIED': '0'}, {'HTTP_X_CVL_EDGE_VERIFIED': ''}, {'HTTP_X_CVL_EDGE_VERIFIED': 'true'}):
            response = self.exchange(headers=headers)
            self.assertEqual(response.status_code, 404)
        self.assertFalse(SsoJti.objects.exists())

    def test_only_post_is_served(self):
        for method in ('get', 'put', 'delete', 'head', 'patch'):
            response = self.exchange(method=method)
            self.assertEqual(response.status_code, 405, method)
        self.assertEqual(self.exchange(method='get')['Allow'], 'POST')

    def test_get_without_the_edge_header_is_404_not_405(self):
        self.assertEqual(self.exchange(method='get', headers={}).status_code, 404)

    def test_bad_bodies_are_400(self):
        for body in ('', 'not json', '[]', '{}', '{"assertion": 5}', '{"assertion": ""}', json.dumps({'assertion': 'x' * 9000})):
            self.assertEqual(self.exchange(body=body).status_code, 400, body[:20])

    def test_csrf_is_not_required(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(self.exchange(client=client).status_code, 204)

    def test_failures_are_throttled_per_address(self):
        for _ in range(20):
            self.assertEqual(self.exchange('garbage.garbage.garbage').status_code, 401)
        response = self.exchange()  # a valid assertion, but this address has used up its refusals
        self.assertEqual(response.status_code, 429)
        self.assertFalse(SsoJti.objects.exists())

    def test_throttling_is_per_address(self):
        for _ in range(20):
            self.exchange('garbage.garbage.garbage')
        elsewhere = Client(REMOTE_ADDR='198.51.100.9')
        self.assertEqual(self.exchange(client=elsewhere).status_code, 204)

    def test_successes_are_not_counted_against_the_limit(self):
        for _ in range(25):
            self.assertEqual(self.exchange().status_code, 204)

    def test_email_change_updates_the_account_and_is_audited(self):
        self.assertEqual(self.exchange(email='renamed@example.com').status_code, 204)
        self.user.refresh_from_db()
        self.identity.refresh_from_db()
        self.assertEqual((self.user.email, self.identity.email_seen), ('renamed@example.com', 'renamed@example.com'))
        row = AuditLog.objects.get(action='sso.email_changed')
        self.assertEqual((row.detail['old'], row.detail['new']), ('owner@example.com', 'renamed@example.com'))

    def test_an_unchanged_email_writes_no_email_audit_row(self):
        self.exchange(email='OWNER@example.com')
        self.assertFalse(AuditLog.objects.filter(action='sso.email_changed').exists())

    def test_no_secret_or_assertion_reaches_the_log_or_audit(self):
        token = self.token(good_claims())
        with self.assertLogs(level='DEBUG') as logs:
            self.assertEqual(self.exchange(token).status_code, 204)
            self.exchange(token)
        self.assertNotIn(token, '\n'.join(logs.output))
        self.assertNotIn(token.split('.')[1], json.dumps(list(AuditLog.objects.values_list('detail', flat=True))))


class BackchannelTests(SsoCase):
    def logout(self, token=None, headers=EXCH, body=None, method='post', **claims):
        token = token or self.token(logout_claims(**claims), purpose=LOGOUT)
        payload = body if body is not None else json.dumps({'logout_token': token})
        client = Client()
        if method == 'post':
            return client.post('/sso/backchannel-logout', data=payload, content_type='application/json', **headers)
        return getattr(client, method)('/sso/backchannel-logout', **headers)

    def signed_out(self, client):
        response = client.get('/cve/api/account/me', **self.headers_for(sid=client.session.get('sso_sid', 'x')))
        return response.status_code in (302, 401)

    def test_logout_by_sid_ends_only_that_family(self):
        sid_a, sid_b = os.urandom(16).hex(), os.urandom(16).hex()
        a, b = self.signed_in(sid=sid_a), self.signed_in(sid=sid_b)
        local = Client()
        local.force_login(self.user)
        self.assertEqual(self.logout(sid=sid_a).status_code, 204)
        self.assertEqual(Session.objects.count(), 2)
        self.assertEqual(a.get('/cve/api/account/me').status_code, 302)
        self.assertEqual(b.get('/cve/api/account/me', **self.headers_for(sid=sid_b)).status_code, 200)
        self.assertEqual(local.get('/cve/api/account/me').status_code, 200)  # a local session is not an SSO session

    def test_logout_by_sub_ends_every_sso_session_of_that_subject(self):
        a, b = self.signed_in(), self.signed_in()
        other = User.objects.create_user('other', 'o@example.com', 'pw-correct-horse-1')
        SsoIdentity.objects.create(user=other, issuer=ISS, subject='777')
        c = self.signed_in(sub='777')
        local = Client()
        local.force_login(self.user)
        self.assertEqual(self.logout(sid=None, sub=SUB).status_code, 204)
        self.assertEqual(a.get('/cve/api/account/me').status_code, 302)
        self.assertEqual(b.get('/cve/api/account/me').status_code, 302)
        self.assertEqual(c.get('/cve/api/account/me', **self.headers_for(sub='777', sid=c.session['sso_sid'])).status_code, 200)
        self.assertEqual(local.get('/cve/api/account/me').status_code, 200)

    def test_it_is_idempotent(self):
        sid = os.urandom(16).hex()
        self.signed_in(sid=sid)
        token = self.token(logout_claims(sid=sid), purpose=LOGOUT)
        self.assertEqual([self.logout(token).status_code for _ in range(3)], [204, 204, 204])
        self.assertEqual(self.logout(sid='f' * 32).status_code, 204)  # nothing matches: still 204

    def test_a_forged_or_assertion_typed_token_is_refused_and_ends_nothing(self):
        client = self.signed_in(sid=os.urandom(16).hex())
        sid = client.session['sso_sid']
        wrong_key = self.token(logout_claims(sid=sid), purpose=LOGOUT, key=Ed25519PrivateKey.generate())
        assertion_typed = jws({'alg': 'EdDSA', 'typ': 'cvl-sso+jwt', 'kid': 'k1'}, logout_claims(sid=sid), self.key)
        for token in (wrong_key, assertion_typed, 'garbage.garbage.garbage'):
            self.assertEqual(self.logout(token).status_code, 401)
        self.assertEqual(client.get('/cve/api/account/me', **self.headers_for(sid=sid)).status_code, 200)

    def test_an_assertion_is_not_a_logout_token_and_the_reverse(self):
        self.assertEqual(self.exchange(self.token(logout_claims(), purpose=LOGOUT)).status_code, 401)

    def test_gates(self):
        self.assertEqual(self.logout(headers={}).status_code, 404)
        self.assertEqual(self.logout(method='get').status_code, 405)
        self.assertEqual(self.logout(body='{}').status_code, 400)
        with override_settings(CVENGINE_SSO=False):
            self.assertEqual(self.logout().status_code, 404)

    def test_the_event_is_audited_without_the_token(self):
        token = self.token(logout_claims(), purpose=LOGOUT)
        self.logout(token)
        row = AuditLog.objects.get(action='sso.backchannel_logout')
        self.assertNotIn(token, json.dumps([row.target, row.detail]))


# ---------------------------------------------------------------------------------------------------------------------------------------------
# per-request binding and step-up
# ---------------------------------------------------------------------------------------------------------------------------------------------

class BindingTests(SsoCase):
    URL = '/cve/api/account/me'

    def test_matching_headers_keep_the_session(self):
        client = self.signed_in()
        response = client.get(self.URL, **self.headers_for(sid=client.session['sso_sid']))
        self.assertEqual(response.status_code, 200)

    def test_sub_mismatch_flushes_the_session(self):
        client = self.signed_in()
        sid = client.session['sso_sid']
        response = client.get(self.URL, **self.headers_for(sub='999', sid=sid))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(client.get(self.URL, **self.headers_for(sid=sid)).status_code, 302)  # the session is gone, even with correct headers now
        self.assertFalse(Session.objects.exists())

    def test_sid_mismatch_flushes_the_session(self):
        client = self.signed_in()
        response = client.get(self.URL, **self.headers_for(sid='0' * 32))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(client.get(self.URL, **self.headers_for(sid=client.session.get('sso_sid', '0' * 32))).status_code, 302)

    def test_missing_sso_headers_flush_the_session(self):
        client = self.signed_in()
        self.assertEqual(client.get(self.URL, HTTP_X_CVL_EDGE_VERIFIED='1').status_code, 401)
        self.assertFalse(Session.objects.exists())

    def test_headers_without_the_edge_verified_flag_are_not_believed(self):
        client = self.signed_in()
        sid = client.session['sso_sid']
        headers = self.headers_for(sid=sid)
        headers['HTTP_X_CVL_EDGE_VERIFIED'] = '0'
        self.assertEqual(client.get(self.URL, **headers).status_code, 401)

    def test_a_browser_page_is_redirected_to_the_edge_instead_of_a_401(self):
        client = self.signed_in()
        response = client.get('/cve/account/?tab=x', HTTP_X_CVL_EDGE_VERIFIED='1')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/_cvl/sso?next=%2Fcve%2Faccount%2F%3Ftab%3Dx')

    def test_the_flush_clears_the_session_cookie(self):
        client = self.signed_in()
        response = client.get(self.URL)
        self.assertEqual(response.cookies[settings.SESSION_COOKIE_NAME].value, '')

    def test_a_local_session_is_not_bound(self):
        client = Client()
        client.force_login(self.user)
        self.assertEqual(client.get(self.URL).status_code, 200)

    def test_api_tokens_are_untouched(self):
        from agentapi.auth import create_token
        _, raw = create_token(self.user, 't')
        self.assertEqual(Client().get('/api/v1/me', HTTP_AUTHORIZATION='Bearer ' + raw).status_code, 200)

    def test_an_sso_session_satisfies_the_organisation_mfa_rule_and_local_enrolment_stays_open(self):
        org = Org.objects.create(name='Strict', slug='strict', require_mfa=True)
        OrgMembership.objects.create(user=self.user, org=org, role='user')
        Project.objects.create(name='P', slug='p', org=org, insert_date=timezone.now())
        client = self.signed_in()
        response = client.get('/cve/p/hosts/', **self.headers_for(sid=client.session['sso_sid']))
        self.assertNotEqual(response.status_code, 302, response.get('Location'))
        local = Client()
        local.force_login(self.user)
        self.assertEqual(local.get('/cve/p/hosts/')['Location'], '/cve/account/#security')  # a local session still has to enrol
        self.assertTrue(TenancyMiddleware.must_enrol_mfa(self.user))  # and with no request there is no SSO to count
        enrol = client.post('/cve/api/account/mfa/start', content_type='application/json', **self.headers_for(sid=client.session['sso_sid']))
        self.assertEqual(enrol.status_code, 200)  # enrolment of a local factor is possible

    def test_an_sso_session_without_a_second_factor_amr_does_not_count(self):
        request = RequestFactory().get('/')
        request.session = {'sso_sub': SUB, 'sso_amr': ['pwd']}
        org = Org.objects.create(name='Strict', slug='strict', require_mfa=True)
        OrgMembership.objects.create(user=self.user, org=org, role='user')
        self.assertTrue(TenancyMiddleware.must_enrol_mfa(self.user, request))
        request.session['sso_amr'] = ['pwd', 'hwk']
        self.assertFalse(TenancyMiddleware.must_enrol_mfa(self.user, request))
        with override_settings(CVENGINE_SSO=False):
            self.assertTrue(TenancyMiddleware.must_enrol_mfa(self.user, request))


class StepUpTests(SsoCase):
    def setUp(self):
        super().setUp()
        User.objects.filter(pk=self.user.pk).update(is_superuser=True, is_staff=True)

    def client_with_age(self, seconds):
        client = self.signed_in(auth_time=int(time.time()) - seconds)
        return client, self.headers_for(sid=client.session['sso_sid'])

    def test_helper_and_decorator(self):
        old, headers = self.client_with_age(3000)
        fresh, fresh_headers = self.client_with_age(30)
        factory = RequestFactory()

        def make(client):
            request = factory.post('/x')
            request.session = client.session
            return request
        self.assertFalse(sso_middleware.has_recent_auth(make(old)))
        self.assertTrue(sso_middleware.has_recent_auth(make(fresh)))
        self.assertTrue(sso_middleware.has_recent_auth(make(old), max_age=4000))
        view = sso_middleware.recent_auth_required(lambda request: HttpResponse('ok'))
        self.assertEqual(view(make(fresh)).content, b'ok')
        self.assertEqual(view(make(old)).status_code, 403)
        wrapped = sso_middleware.recent_auth_required(max_age=5000)(lambda request: HttpResponse('ok'))
        self.assertEqual(wrapped(make(old)).content, b'ok')

    def test_the_helper_never_blocks_a_session_that_is_not_from_sso_or_when_sso_is_off(self):
        request = RequestFactory().post('/x')
        request.session = {'_auth_user_id': '1'}
        self.assertTrue(sso_middleware.has_recent_auth(request))
        request.session = {'sso_sub': SUB, 'sso_auth_time': 1}
        with override_settings(CVENGINE_SSO=False):
            self.assertTrue(sso_middleware.has_recent_auth(request))

    def sensitive(self):
        return [('post', '/cve/api/admin/users'), ('patch', '/cve/api/admin/users/1'), ('delete', '/cve/api/admin/projects/1'),
                ('post', '/cve/api/admin/memberships'), ('put', '/cve/api/settings/ai'), ('put', '/cve/api/settings/keys'),
                ('post', '/api/v1/tokens'), ('delete', '/api/v1/tokens/3'), ('get', '/api/v1/sentinels/enroll'),
                ('post', '/api/v1/projects/p/sentinels/enroll'), ('put', '/cve/api/admin/orgs/1/api-keys/shodan'), ('get', '/scan/export/subdomains/1')]

    def test_an_old_sign_in_is_refused_on_the_sensitive_actions_and_a_fresh_one_is_not(self):
        old, headers = self.client_with_age(3000)
        for method, url in self.sensitive():
            response = getattr(old, method)(url, content_type='application/json', **headers)
            self.assertEqual(response.status_code, 403, (method, url))
            if url.startswith(('/cve/api/', '/api/')):
                self.assertEqual(response.json()['error'], 'recent_auth_required')
        fresh, fresh_headers = self.client_with_age(30)
        for method, url in self.sensitive():
            response = getattr(fresh, method)(url, content_type='application/json', **fresh_headers)
            self.assertNotEqual(response.json().get('error') if response['Content-Type'].startswith('application/json') else '', 'recent_auth_required')

    def test_the_refusal_names_the_step_up_route_with_the_validated_path(self):
        old, headers = self.client_with_age(3000)
        response = old.post('/api/v1/tokens', content_type='application/json', **headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'error': 'recent_auth_required', 'message': 'confirm your sign-in again to do this',
                                           'reauth_url': '/_cvl/sso?prompt=stepup&next=%2Fcve%2F'})  # a POST: the landing page, never the POST target
        response = old.get('/api/v1/sentinels/enroll?x=1&y=a b', **headers)
        self.assertEqual(response.json()['reauth_url'], '/_cvl/sso?prompt=stepup&next=%2Fapi%2Fv1%2Fsentinels%2Fenroll%3Fx%3D1%26y%3Da%2520b')
        self.assertTrue(all(url.startswith('/_cvl/sso?prompt=stepup&next=%2F') for url in
                            [old.delete(u, content_type='application/json', **headers).json()['reauth_url'] for u in ('/api/v1/tokens/3', '/cve/api/admin/projects/1')]))

    def test_the_reauth_url_never_carries_an_unvalidated_next(self):
        request = RequestFactory().get('//evil.example/x', HTTP_HOST='testserver')
        request.session = {'sso_sub': SUB, 'sso_auth_time': 1}
        self.assertEqual(stepup_url(request, '//evil.example'), '/_cvl/sso?prompt=stepup&next=%2Fcve%2F')
        self.assertEqual(stepup_url(request, '/\\evil.example'), '/_cvl/sso?prompt=stepup&next=%2Fcve%2F')
        self.assertEqual(stepup_url(request, 'https://evil.example/'), '/_cvl/sso?prompt=stepup&next=%2Fcve%2F')
        self.assertEqual(stepup_url(request, '/ok\r\nSet-Cookie: a=b'), '/_cvl/sso?prompt=stepup&next=%2Fcve%2F')
        self.assertEqual(stepup_url(request, '/cve/p/'), '/_cvl/sso?prompt=stepup&next=%2Fcve%2Fp%2F')

    def test_only_the_step_up_refusal_uses_the_sso_route(self):
        self.assertTrue(sso_url(RequestFactory().get('/'), '/cve/p/').startswith('/_cvl/start?next='))

    def test_reads_and_ordinary_writes_are_not_step_up(self):
        old, headers = self.client_with_age(3000)
        for method, url in (('get', '/cve/api/admin/users'), ('get', '/api/v1/tokens'), ('get', '/cve/api/account/me'), ('patch', '/cve/api/account/profile')):
            response = getattr(old, method)(url, content_type='application/json', **headers)
            self.assertNotIn(b'recent_auth_required', response.content, (method, url))

    def test_the_html_refusal_is_a_page_not_a_redirect_loop(self):
        old, headers = self.client_with_age(3000)
        response = old.get('/scan/export/subdomains/1', **headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response['Content-Type'].split(';')[0], 'text/html')

    def test_the_age_follows_the_setting(self):
        client, headers = self.client_with_age(3000)
        with override_settings(CVENGINE_SSO_STEPUP_AGE=7200):
            self.assertNotIn(b'recent_auth_required', client.post('/api/v1/tokens', content_type='application/json', **headers).content)

    def test_a_local_session_is_never_stepped_up(self):
        client = Client()
        client.force_login(self.user)
        self.assertNotIn(b'recent_auth_required', client.post('/api/v1/tokens', content_type='application/json').content)


class EdgeContractTests(SsoCase):
    """What nginx forwards (config/nginx/rengine.conf) is exactly what the application accepts, and nothing looser."""

    def post(self, url, body, headers):
        return Client().post(url, data=json.dumps(body), content_type='application/json', **headers)

    def test_the_exchange_header_must_be_exactly_one_on_both_endpoints(self):
        token, logout = self.token(), self.token(purpose=LOGOUT)
        for url, body in (('/sso/exchange', {'assertion': token}), ('/sso/backchannel-logout', {'logout_token': logout})):
            for value in (None, '', '0', 'true', '11', ' 1', '1 ', 'yes', '01'):
                headers = dict(EDGE) if value is None else {**EDGE, 'HTTP_X_CVL_SSO_EXCHANGE': value}
                response = self.post(url, body, headers)
                self.assertEqual(response.status_code, 404, (url, value))
                self.assertEqual(response.content, b'', (url, value))
            self.assertEqual(Client().get(url, **EXCH).status_code, 405)  # with all three in place the method is what is refused
        self.assertFalse(SsoJti.objects.exists())
        self.assertFalse(Session.objects.exists())

    def test_the_verified_flag_must_be_exactly_one_even_with_the_exchange_header(self):
        for value in (None, '0', 'true', '11', ''):
            headers = {'HTTP_X_CVL_SSO_EXCHANGE': '1'} if value is None else {'HTTP_X_CVL_EDGE_VERIFIED': value, 'HTTP_X_CVL_SSO_EXCHANGE': '1'}
            self.assertEqual(self.post('/sso/exchange', {'assertion': self.token()}, headers).status_code, 404, value)
        self.assertFalse(Session.objects.exists())

    def test_both_headers_together_are_accepted(self):
        self.assertEqual(self.post('/sso/exchange', {'assertion': self.token()}, EXCH).status_code, 204)
        self.assertEqual(self.post('/sso/backchannel-logout', {'logout_token': self.token(purpose=LOGOUT)}, EXCH).status_code, 204)

    def test_the_exchange_header_alone_does_not_bind_a_session_or_vouch_for_the_edge(self):
        client = self.signed_in()
        sid = client.session['sso_sid']
        headers = {'HTTP_X_CVL_SSO_EXCHANGE': '1', 'HTTP_X_CVL_SSO_SUB': SUB, 'HTTP_X_CVL_SSO_SID': sid}
        self.assertEqual(client.get('/cve/api/account/me', **headers).status_code, 401)

    def test_uuid_subjects_and_32_hex_sids_travel_end_to_end(self):
        uuid_sub = '3f2b8c1e-5d4a-4e7b-9a10-6c2d8e4f1a77'  # a site users.id as text: 36 characters, within what nginx forwards
        self.assertRegex(uuid_sub, r'^[A-Za-z0-9_-]{1,64}$')
        self.identity.subject = uuid_sub
        self.identity.save()
        sid = os.urandom(16).hex()
        client = Client()
        self.assertEqual(self.exchange(client=client, sub=uuid_sub, sid=sid).status_code, 204)
        self.assertEqual((client.session['sso_sub'], client.session['sso_sid']), (uuid_sub, sid))
        self.assertEqual(client.get('/cve/api/account/me', **self.headers_for(sub=uuid_sub, sid=sid)).status_code, 200)
        self.assertEqual(client.get('/cve/api/account/me', **self.headers_for(sub=uuid_sub, sid=sid.upper())).status_code, 401)

    def test_a_subject_or_sid_nginx_would_not_forward_is_refused_at_the_exchange(self):
        for sub in ('a.b', 'a:b', 'a b', 'x' * 65, '', 'a/b'):
            self.refused_exchange(sub=sub)
        for sid in ('A' * 32, 'a' * 31, 'a' * 33, 'g' * 32, 'a' * 31 + ' '):
            self.refused_exchange(sid=sid)

    def refused_exchange(self, **claims):
        with self.assertLogs('hostedsso.verify', 'WARNING'):
            response = self.exchange(**claims)
        self.assertEqual(response.status_code, 401, claims)


class SessionCookieTests(SsoCase):
    """The exchange answer's Set-Cookie header, with the cookie settings a hosted server with SSO really computes (a clean interpreter)."""

    def test_the_set_cookie_header_of_the_exchange(self):
        got = settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO='1')
        self.assertEqual(got['SESSION_COOKIE_NAME'], '__Host-cve_s')
        with override_settings(SESSION_COOKIE_NAME=got['SESSION_COOKIE_NAME'], SESSION_COOKIE_SECURE=got['SESSION_COOKIE_SECURE'],
                               SESSION_COOKIE_HTTPONLY=got['SESSION_COOKIE_HTTPONLY'], SESSION_COOKIE_SAMESITE=got['SESSION_COOKIE_SAMESITE'],
                               SESSION_COOKIE_PATH=got['SESSION_COOKIE_PATH'], SESSION_COOKIE_DOMAIN=got['SESSION_COOKIE_DOMAIN']):
            response = self.exchange()
        self.assertEqual(response.status_code, 204)
        self.assertIn('__Host-cve_s', response.cookies)
        self.assertNotIn('sessionid', response.cookies)  # the stock name is not used
        header = response.cookies.output(header='Set-Cookie:').strip()
        self.assertRegex(header, r'^Set-Cookie: __Host-cve_s=[A-Za-z0-9]{20,}; ')
        attributes = [part.strip() for part in header.split(';')[1:]]
        lowered = [a.lower() for a in attributes]
        self.assertIn('secure', lowered)
        self.assertIn('httponly', lowered)
        self.assertIn('samesite=lax', lowered)
        self.assertIn('path=/', lowered)
        self.assertFalse([a for a in lowered if a.startswith('domain')], header)  # a __Host- cookie must not carry Domain
        morsel = response.cookies['__Host-cve_s']
        self.assertEqual((morsel['domain'], morsel['path'], bool(morsel['secure']), bool(morsel['httponly']), morsel['samesite']), ('', '/', True, True, 'Lax'))
        self.assertTrue(morsel['max-age'] and 0 < int(morsel['max-age']) <= 43200)

    def test_the_cookie_value_is_a_session_the_next_request_can_use(self):
        got = settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO='1')
        with override_settings(SESSION_COOKIE_NAME=got['SESSION_COOKIE_NAME'], SESSION_COOKIE_SECURE=True):
            client = Client()
            sid = os.urandom(16).hex()
            self.assertEqual(self.exchange(client=client, sid=sid).status_code, 204)
            self.assertEqual(client.get('/cve/api/account/me', **self.headers_for(sid=sid)).status_code, 200)
            self.assertIn('__Host-cve_s', client.cookies)
            self.assertNotIn('sessionid', client.cookies)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# login gating and break-glass
# ---------------------------------------------------------------------------------------------------------------------------------------------

class GatingTests(SsoCase):
    def setUp(self):
        super().setUp()
        self.password = 'pw-correct-horse-1'
        self.profile = UserProfile.objects.create(user=self.user, mfa_enabled=True, mfa_secret=mfa.new_secret())
        self.enforce = override_settings(CVENGINE_SSO_ENFORCE=True)

    def login(self, client=None, headers=None, **extra):
        client = client or Client()
        return client, client.post('/login/', {'username': 'owner', 'password': self.password, **extra}, **(headers or {}))

    def breakglass(self, seconds):
        return override_settings(CVENGINE_SSO_ENFORCE=True, CVENGINE_SSO_BREAKGLASS_UNTIL=int(time.time()) + seconds)

    def test_phase_a_local_login_still_works_and_the_page_offers_the_sso_link(self):
        client, response = self.login()
        self.assertEqual((response.status_code, response['Location']), (302, '/mfa/verify/'))
        page = Client().get('/login/?next=/cve/p/')
        self.assertContains(page, 'Sign in with cvengine.live')
        self.assertContains(page, '/_cvl/start?next=%2Fcve%2Fp%2F')

    def test_enforce_refuses_the_local_post_and_sends_the_visitor_to_the_edge(self):
        with self.enforce:
            client, response = self.login(next='/cve/p/hosts/?x=1')
            self.assertEqual((response.status_code, response['Location']), (302, '/_cvl/start?next=%2Fcve%2Fp%2Fhosts%2F%3Fx%3D1'))
            self.assertNotIn(SESSION_KEY, client.session)
            self.assertNotIn('mfa_pending', client.session)
            for headers in (EDGE, {}):
                _, response = self.login(headers=headers)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response['Location'].startswith('/_cvl/start?next='))

    def test_enforce_also_redirects_the_login_page(self):
        with self.enforce:
            self.assertEqual(Client().get('/login/?next=/cve/p/')['Location'], '/_cvl/start?next=%2Fcve%2Fp%2F')

    def test_enforce_refuses_the_django_admin_login(self):
        admin = User.objects.create_superuser('root', 'r@example.com', self.password)
        with self.enforce:
            client = Client()
            for method in (client.get, client.post):
                response = method('/admin/login/?next=/admin/', **({'data': {'username': 'root', 'password': self.password}} if method == client.post else {}))
                self.assertEqual((response.status_code, response['Location']), (302, '/_cvl/start?next=%2Fadmin%2F'))
            self.assertNotIn(SESSION_KEY, client.session)
        self.assertTrue(admin.pk)

    def test_the_next_value_is_validated(self):
        with self.enforce:
            default = '/_cvl/start?next=%2Fcve%2F'
            for bad in ('//evil.example', '/\\evil.example', 'https://evil.example/x', 'javascript:alert(1)', '/ok\r\nSet-Cookie: a=b', '/with space', 'evil',
                        '/' + 'a' * 2100):
                response = Client().get('/login/', {'next': bad})
                self.assertEqual(response['Location'], default, bad[:30])
            self.assertEqual(Client().get('/login/', {'next': '/cve/p/'})['Location'], '/_cvl/start?next=%2Fcve%2Fp%2F')

    def test_break_glass_needs_the_edge_header(self):
        with self.breakglass(1800):
            _, response = self.login()
            self.assertTrue(response['Location'].startswith('/_cvl/start'))
            _, response = self.login(headers=EDGE)
            self.assertEqual(response['Location'], '/mfa/verify/')

    def test_break_glass_still_needs_the_password_and_the_local_mfa(self):
        with self.breakglass(1800):
            client, response = self.login(headers=EDGE, password='wrong') if False else (Client(), Client().post('/login/', {'username': 'owner', 'password': 'wrong'}, **EDGE))
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(SESSION_KEY, client.session)
            client, response = self.login(headers=EDGE)
            self.assertNotIn(SESSION_KEY, client.session)  # the password alone opens nothing
            self.assertEqual(response['Location'], '/mfa/verify/')
            bad = client.post('/mfa/verify/', {'code': '000000'}, **EDGE)
            self.assertNotIn(SESSION_KEY, client.session)
            self.assertEqual(bad.status_code, 200)
            ok = client.post('/mfa/verify/', {'code': mfa.totp(self.profile.mfa_secret)}, **EDGE)
            self.assertEqual(ok.status_code, 302)
            self.assertEqual(client.session[SESSION_KEY], str(self.user.pk))

    def test_break_glass_refuses_an_account_without_local_mfa(self):
        UserProfile.objects.filter(pk=self.profile.pk).update(mfa_enabled=False, mfa_secret='')
        with self.breakglass(1800):
            client, response = self.login(headers=EDGE)
            self.assertTrue(response['Location'].startswith('/_cvl/start'))
            self.assertNotIn(SESSION_KEY, client.session)
        self.assertTrue(AuditLog.objects.filter(action='sso.breakglass_refused').exists())

    def test_break_glass_is_audited_and_logged(self):
        with self.breakglass(1800), self.assertLogs('hostedsso.gating', 'WARNING') as logs:
            client, _ = self.login(headers=EDGE)
            client.post('/mfa/verify/', {'code': mfa.totp(self.profile.mfa_secret)}, **EDGE)
        self.assertTrue(AuditLog.objects.filter(action='sso.breakglass_attempt').exists())
        self.assertTrue(AuditLog.objects.filter(action='sso.breakglass_login', actor=self.user).exists())
        self.assertTrue(any('break-glass' in line for line in logs.output))

    def test_break_glass_window_rules(self):
        now = time.time()
        for until, expected in ((now + 1800, True), (now + 3599, True), (now + 3601, False), (now + 7200, False), (now - 1, False), (0, False), (now + 86400 * 30, False)):
            with override_settings(CVENGINE_SSO_BREAKGLASS_UNTIL=int(until)):
                self.assertEqual(gating.breakglass_active(), expected, until - now)
        with override_settings(CVENGINE_SSO_BREAKGLASS_UNTIL='soon'):
            self.assertFalse(gating.breakglass_active())

    def test_a_window_longer_than_an_hour_does_not_open_local_login(self):
        with override_settings(CVENGINE_SSO_ENFORCE=True, CVENGINE_SSO_BREAKGLASS_UNTIL=int(time.time()) + 7200):
            _, response = self.login(headers=EDGE)
            self.assertTrue(response['Location'].startswith('/_cvl/start'))

    def test_an_expired_window_closes_a_started_login(self):
        with self.breakglass(1800):
            client, _ = self.login(headers=EDGE)
        with self.enforce:
            response = client.post('/mfa/verify/', {'code': mfa.totp(self.profile.mfa_secret)}, **EDGE)
            self.assertTrue(response['Location'].startswith('/_cvl/start'))
            self.assertNotIn(SESSION_KEY, client.session)

    def test_the_window_is_ignored_when_not_enforcing(self):
        with override_settings(CVENGINE_SSO_ENFORCE=False, CVENGINE_SSO_BREAKGLASS_UNTIL=int(time.time()) + 1800):
            _, response = self.login()  # no edge header needed: the window only matters under enforcement
            self.assertEqual(response['Location'], '/mfa/verify/')
            self.assertFalse(AuditLog.objects.filter(action='sso.breakglass_attempt').exists())

    def test_the_invite_link_does_not_open_a_local_session_when_enforcing(self):
        from tenancy import invite
        user = User.objects.create_user('invitee', 'i@example.com', 'x')
        token = invite.make_token(user) if hasattr(invite, 'make_token') else None
        if token is None:
            self.skipTest('no token helper')
        with self.enforce:
            client = Client()
            response = client.post(f'/invite/{token}/', {'password': 'A-long-unusual-pw-9187', 'confirm': 'A-long-unusual-pw-9187'})
            self.assertTrue(response['Location'].startswith('/_cvl/start'))
            self.assertNotIn(SESSION_KEY, client.session)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# off by default
# ---------------------------------------------------------------------------------------------------------------------------------------------

def settings_probe(**env):
    """Import the project settings in a clean interpreter with the given environment and report the SSO-related values."""
    code = ("import json; from django.conf import settings as s; "
            "print(json.dumps({k: getattr(s, k) for k in ('CVENGINE_HOSTED','CVENGINE_SSO','CVENGINE_SSO_ENFORCE','SESSION_COOKIE_NAME','CSRF_COOKIE_NAME',"
            "'SESSION_COOKIE_SECURE','CSRF_COOKIE_SECURE','CVENGINE_SSO_KEYS_FILE','CVENGINE_SSO_ISSUER','CVENGINE_SSO_MAX_AUTH_AGE',"
            "'CVENGINE_SSO_STEPUP_AGE','CVENGINE_SSO_BREAKGLASS_UNTIL','LOGIN_REQUIRED_IGNORE_PATHS','SESSION_COOKIE_HTTPONLY','SESSION_COOKIE_SAMESITE','SESSION_COOKIE_PATH','SESSION_COOKIE_DOMAIN')}))")
    base = {k: v for k, v in os.environ.items() if not k.startswith(('CVENGINE_HOSTED', 'CVENGINE_SSO'))}
    base.update(DJANGO_SETTINGS_MODULE='reNgine.settings', DEBUG='0', **env)
    done = subprocess.run([sys.executable, '-I', '-c', 'import sys; sys.path.insert(0, %r); import django; ' % str(WEB) + code], env=base, capture_output=True,
                          text=True, cwd=str(WEB), timeout=120)
    if done.returncode:
        raise AssertionError(done.stderr[-2000:])
    return json.loads(done.stdout.strip().splitlines()[-1])


class DefaultOffSettingsTests(SimpleTestCase):
    def test_a_stock_install_has_stock_cookie_names_and_everything_off(self):
        got = settings_probe()
        self.assertEqual((got['CVENGINE_HOSTED'], got['CVENGINE_SSO'], got['CVENGINE_SSO_ENFORCE']), (False, False, False))
        self.assertEqual((got['SESSION_COOKIE_NAME'], got['CSRF_COOKIE_NAME']), ('sessionid', 'csrftoken'))
        self.assertEqual((got['CVENGINE_SSO_KEYS_FILE'], got['CVENGINE_SSO_ISSUER'], got['CVENGINE_SSO_MAX_AUTH_AGE'], got['CVENGINE_SSO_STEPUP_AGE'],
                          got['CVENGINE_SSO_BREAKGLASS_UNTIL']), ('/etc/cvl/sso-keys.json', 'https://cvengine.live', 43200, 900, 0))
        self.assertEqual(got['LOGIN_REQUIRED_IGNORE_PATHS'], [r'^/api/v1/sentinels/bootstrap/?$'])

    def test_a_plain_hosted_install_keeps_the_stock_cookie_names(self):
        got = settings_probe(CVENGINE_HOSTED='1')
        self.assertEqual((got['CVENGINE_HOSTED'], got['CVENGINE_SSO']), (True, False))
        self.assertEqual((got['SESSION_COOKIE_NAME'], got['CSRF_COOKIE_NAME']), ('sessionid', 'csrftoken'))

    def test_sso_variables_alone_do_nothing_without_hosted_mode(self):
        for hosted in ('', '0', 'false', 'off', 'no'):
            got = settings_probe(CVENGINE_HOSTED=hosted, CVENGINE_SSO='1', CVENGINE_SSO_ENFORCE='1', CVENGINE_SSO_BREAKGLASS_UNTIL='99999999999')
            self.assertEqual((got['CVENGINE_SSO'], got['CVENGINE_SSO_ENFORCE']), (False, False), hosted)
            self.assertEqual((got['SESSION_COOKIE_NAME'], got['CSRF_COOKIE_NAME']), ('sessionid', 'csrftoken'))

    def test_enforce_without_sso_is_not_enforcing(self):
        got = settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO_ENFORCE='1')
        self.assertEqual((got['CVENGINE_SSO'], got['CVENGINE_SSO_ENFORCE']), (False, False))

    def test_hosted_with_sso_uses_host_prefixed_secure_cookies(self):
        got = settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO='1')
        self.assertEqual((got['SESSION_COOKIE_NAME'], got['CSRF_COOKIE_NAME']), ('__Host-cve_s', '__Host-cve_csrf'))
        self.assertEqual((got['SESSION_COOKIE_SECURE'], got['CSRF_COOKIE_SECURE']), (True, True))
        self.assertEqual(settings_probe(CVENGINE_HOSTED='1', CVENGINE_SSO='1', CVENGINE_SSO_ENFORCE='1')['CVENGINE_SSO_ENFORCE'], True)


class DefaultOffBehaviourTests(TestCase):
    """The test process itself runs with the stock environment: the whole feature must be invisible."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('plain', 'plain@example.com', 'pw-correct-horse-1')

    def test_the_process_settings_are_stock(self):
        self.assertFalse(settings.CVENGINE_HOSTED or settings.CVENGINE_SSO or settings.CVENGINE_SSO_ENFORCE)
        self.assertEqual((settings.SESSION_COOKIE_NAME, settings.CSRF_COOKIE_NAME), ('sessionid', 'csrftoken'))

    def test_the_endpoints_do_not_exist_in_effect(self):
        for url in ('/sso/exchange', '/sso/backchannel-logout'):
            for headers in ({}, EDGE):
                self.assertEqual(Client().post(url, data='{}', content_type='application/json', **headers).status_code, 404)
                self.assertEqual(Client().get(url, **headers).status_code, 404)

    def test_local_login_is_stock(self):
        client = Client()
        self.assertEqual(client.get('/login/').status_code, 200)
        self.assertNotContains(client.get('/login/'), 'cvengine.live')
        response = client.post('/login/', {'username': 'plain', 'password': 'pw-correct-horse-1'})
        self.assertEqual((response.status_code, response['Location']), (302, '/cve/'))
        self.assertEqual(client.session[SESSION_KEY], str(self.user.pk))

    def test_admin_login_redirect_is_stock(self):
        self.assertEqual(Client().get('/admin/login/?next=/admin/')['Location'], '/login/?next=%2Fadmin%2F')

    def test_the_binding_and_step_up_ignore_everything_when_off(self):
        client = Client()
        client.force_login(self.user)
        session = client.session
        session.update({'sso_sub': '1', 'sso_sid': 'x', 'sso_auth_time': 1, 'sso_amr': ['pwd', 'otp']})
        session.save()
        self.assertEqual(client.get('/cve/api/account/me').status_code, 200)  # no headers at all, nothing flushed
        self.assertNotIn(b'recent_auth_required', client.post('/api/v1/tokens', content_type='application/json').content)

    def test_an_sso_session_flag_does_not_satisfy_mfa_when_off(self):
        org = Org.objects.create(name='Strict', slug='strict', require_mfa=True)
        OrgMembership.objects.create(user=self.user, org=org, role='user')
        request = RequestFactory().get('/')
        request.session = {'sso_sub': '1', 'sso_amr': ['pwd', 'otp']}
        self.assertTrue(TenancyMiddleware.must_enrol_mfa(self.user, request))

    @override_settings(CVENGINE_HOSTED=True, CVENGINE_SSO=False, CVENGINE_SSO_ENFORCE=True)
    def test_a_plain_hosted_install_is_unchanged(self):
        self.assertEqual(Client().post('/sso/exchange', data='{}', content_type='application/json', **EDGE).status_code, 404)
        client = Client()
        self.assertEqual(client.post('/login/', {'username': 'plain', 'password': 'pw-correct-horse-1'}, **EDGE)['Location'], '/cve/')
        self.assertNotContains(Client().get('/login/'), 'cvengine.live')

    @override_settings(CVENGINE_HOSTED=False, CVENGINE_SSO=True, CVENGINE_SSO_ENFORCE=True)
    def test_sso_flags_without_hosted_mode_are_inert(self):
        self.assertEqual(Client().post('/sso/exchange', data='{}', content_type='application/json', **EDGE).status_code, 404)
        self.assertEqual(Client().post('/login/', {'username': 'plain', 'password': 'pw-correct-horse-1'})['Location'], '/cve/')


# ---------------------------------------------------------------------------------------------------------------------------------------------
# link_sso_identity
# ---------------------------------------------------------------------------------------------------------------------------------------------

class LinkCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('alice', 'Alice@Example.com', 'x')

    def run_cmd(self, *args):
        out = StringIO()
        call_command('link_sso_identity', *args, stdout=out)
        return out.getvalue().strip()

    def test_links_by_email_with_the_default_issuer_and_is_idempotent(self):
        self.assertEqual(self.run_cmd('--email', 'alice@example.com', '--subject', '42'), 'linked')
        identity = SsoIdentity.objects.get(user=self.user)
        self.assertEqual((identity.subject, identity.issuer), ('42', 'https://cvengine.live'))
        self.assertEqual(self.run_cmd('--email', 'ALICE@example.com', '--subject', '42'), 'already linked')
        self.assertEqual(SsoIdentity.objects.count(), 1)
        self.assertTrue(AuditLog.objects.filter(action='sso.link').exists())

    def test_explicit_issuer(self):
        self.run_cmd('--email', 'alice@example.com', '--subject', '42', '--issuer', 'https://idp.example')
        self.assertEqual(SsoIdentity.objects.get().issuer, 'https://idp.example')

    def test_refuses_an_inactive_user(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        with self.assertRaisesMessage(CommandError, 'inactive'):
            self.run_cmd('--email', 'alice@example.com', '--subject', '42')
        self.assertFalse(SsoIdentity.objects.exists())

    def test_refuses_a_different_subject_for_a_linked_user_unless_forced(self):
        self.run_cmd('--email', 'alice@example.com', '--subject', '42')
        with self.assertRaisesMessage(CommandError, 'already linked'):
            self.run_cmd('--email', 'alice@example.com', '--subject', '43')
        self.assertEqual(SsoIdentity.objects.get().subject, '42')
        self.assertEqual(self.run_cmd('--email', 'alice@example.com', '--subject', '43', '--force'), 'linked')
        self.assertEqual(SsoIdentity.objects.get().subject, '43')

    def test_refuses_a_subject_that_belongs_to_another_user_unless_forced(self):
        bob = User.objects.create_user('bob', 'bob@example.com', 'x')
        self.run_cmd('--email', 'alice@example.com', '--subject', '42')
        with self.assertRaisesMessage(CommandError, 'already linked'):
            self.run_cmd('--email', 'bob@example.com', '--subject', '42')
        self.run_cmd('--email', 'bob@example.com', '--subject', '42', '--force')
        self.assertEqual(SsoIdentity.objects.get().user, bob)

    def test_unknown_or_ambiguous_email_and_bad_subject(self):
        with self.assertRaises(CommandError):
            self.run_cmd('--email', 'nobody@example.com', '--subject', '42')
        User.objects.create_user('alice2', 'alice@example.com', 'x')
        with self.assertRaisesMessage(CommandError, 'more than one'):
            self.run_cmd('--email', 'alice@example.com', '--subject', '42')
        with self.assertRaises(CommandError):
            self.run_cmd('--email', 'alice@example.com', '--subject', 'bad subject!')
