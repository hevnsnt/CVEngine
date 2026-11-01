"""Mask secrets in text before it reaches an AI provider, and in what the model answers.

Scanners find real credentials on a target (a nuclei token template extracts the key itself, bbot's badsecrets prints the secret it
decoded). The AI provider is a third party, so no raw secret may leave in a prompt. Two layers, both pure (no Django, no I/O):

  * ``mask_secret(value, hint)``: the whole value of a finding known to be a secret becomes
    ``AIza…[redacted 39 chars, google_api_key, fp:1a2b3c4d]``: the public prefix of the format (when it has one), the length, the class of
    secret and a short keyed fingerprint. The model can still reason "a Google API key is exposed", and the same secret always gets the
    same mask, so two findings of one key still read as one.
  * ``redact_text(text)``: a pass over free text for the shapes of well-known secrets. It is the last line of defence: it runs on the final
    prompt and on the model's reply, so a secret that no finding kind announced, or that the reply echoed, is masked as well.

Every pattern has bounded repeats and a token boundary or a literal anchor in front, so the work on a long adversarial string stays linear
(see the tests). Masks do not match any pattern, so ``redact_text`` is idempotent. The fingerprint is an HMAC (server field key), not a plain
hash, so a weak password cannot be confirmed by hashing guesses.
"""
import hashlib
import hmac
import os
import re
import time

FINGERPRINT_CHARS = 8
_FALLBACK_KEY = b'cvengine/secret-redaction/v1'
MAX_TEXT = 2_000_000  # a longer text is masked in pieces: the work stays bounded whatever a caller passes


_KEY_CACHE = []
_NO_KEY_UNTIL = [0.0]


def _fingerprint_key():
    """The server field key (``CVENGINE_FIELD_KEY``, else Django's SECRET_KEY), read once; the fixed fallback is never cached, so a key
    that appears later (Django set up after the first call) is still used."""
    if _KEY_CACHE:
        return _KEY_CACHE[0]
    if time.monotonic() < _NO_KEY_UNTIL[0]:
        return _FALLBACK_KEY
    key = (os.environ.get('CVENGINE_FIELD_KEY') or '').strip()
    if not key:
        try:
            from reNgine.crypto_fields import dedicated_keys
            key = (dedicated_keys() or ('',))[0]
        except Exception:  # noqa: BLE001 - no Django here (a unit test, a script): the fallback below
            key = ''
    if not key:
        try:
            from django.conf import settings
            key = str(settings.SECRET_KEY or '')
        except Exception:  # noqa: BLE001
            key = ''
    if not key:
        _NO_KEY_UNTIL[0] = time.monotonic() + 30  # looking is slow (an import that fails): not once per match
        return _FALLBACK_KEY
    _KEY_CACHE.append(key.encode())
    return _KEY_CACHE[0]


def fingerprint(value):
    """A short stable keyed digest of a secret: identical secrets share it, and it reveals nothing of the value."""
    return hmac.new(_fingerprint_key(), str(value).encode('utf-8', 'replace'), hashlib.sha256).hexdigest()[:FINGERPRINT_CHARS]


def _mask(value, kind, prefix=''):
    value = str(value)
    return f'{prefix}\u2026[redacted {len(value)} chars, {kind}, fp:{fingerprint(value)}]'


# A token must not start in the middle of a longer token.
_B = r'(?<![A-Za-z0-9_-])'
_PEM_KIND = r'(?:[A-Z]{2,10} ){0,3}PRIVATE KEY(?: BLOCK)?'

# (kind, regex of the public prefix kept in the mask, compiled pattern). Order matters: the first pattern to claim a stretch of text wins, so the
# specific shapes come before the generic ones (sk-ant- before sk-).
_BASE64_RUN = r'[A-Za-z0-9+/=]{20,8192}'
SHAPES = (
    # a PEM block, END marker present; or, when it is cut short (a prompt is capped), the header and the base64 lines that follow it
    ('private_key', '', re.compile(
        r'-----BEGIN ' + _PEM_KIND + r'-----(?:(?:[A-Za-z0-9+/=\s\\:,.]{0,8192}?-----END ' + _PEM_KIND + r'-----)'
        r'|(?:(?:\s|\\n){0,4}' + _BASE64_RUN + r'(?:(?:\s|\\n){1,4}' + _BASE64_RUN + r'){0,200}))?')),
    ('jwt', 'eyJ', re.compile(_B + r'eyJ[A-Za-z0-9_-]{5,4096}\.eyJ[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{0,4096}')),
    ('google_api_key', 'AIza', re.compile(_B + r'AIza[0-9A-Za-z_-]{35,64}')),
    ('google_oauth_secret', 'GOCSPX-', re.compile(_B + r'GOCSPX-[0-9A-Za-z_-]{20,64}')),
    ('aws_access_key_id', 'AKIA|ASIA', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])')),
    ('github_token', r'gh[pousr]_|github_pat_', re.compile(_B + r'(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})')),
    ('gitlab_token', 'glpat-', re.compile(_B + r'glpat-[A-Za-z0-9_-]{20,64}')),
    ('slack_token', r'xox[abprs]-', re.compile(_B + r'xox[abprs]-[A-Za-z0-9-]{10,250}')),
    ('slack_webhook', 'https://hooks[.]slack[.]com/', re.compile(r'https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,200}')),
    ('discord_webhook', '', re.compile(r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{5,30}/[A-Za-z0-9_-]{20,200}')),
    ('stripe_key', r'[spr]k_(?:live|test)_', re.compile(_B + r'[spr]k_(?:live|test)_[0-9A-Za-z]{10,99}')),
    ('anthropic_key', 'sk-ant-', re.compile(_B + r'sk-ant-[A-Za-z0-9_-]{20,200}')),
    ('openai_key', 'sk-', re.compile(_B + r'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}')),
    ('sendgrid_key', 'SG[.]', re.compile(_B + r'SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}')),
    ('mailgun_key', 'key-', re.compile(_B + r'key-[0-9a-f]{32}(?![0-9A-Za-z])')),
    ('twilio_sid_or_key', 'AC|SK', re.compile(r'(?<![A-Za-z0-9])(?:AC|SK)[0-9a-f]{32}(?![0-9A-Za-z])')),
    ('npm_token', 'npm_', re.compile(_B + r'npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])')),
    ('pypi_token', 'pypi-', re.compile(_B + r'pypi-[A-Za-z0-9_-]{50,200}')),
    ('azure_storage_key', '', re.compile(r'(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{30,100}={0,2}')),
    ('aws_secret_access_key', '', re.compile(r'(?i:aws_secret_access_key|secret_access_key)["\']?\s{0,3}[:=]\s{0,3}["\']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')),
)
# The credential of a URL (scheme://user:password@host): the password alone is masked, the rest stays readable.
_URL_CREDENTIAL = re.compile(r'(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@]{1,128}:)([^\s/@]{1,256})(@)')
# A bearer token anywhere in text (not a lowercase word: "Bearer token-based authentication" is prose), and an Authorization header.
_BEARER = re.compile(r'(\bBearer\s+)(?!(?-i:[a-z-]+)(?![A-Za-z0-9._~+/=-]))([A-Za-z0-9._~+/=-]{16,2048})', re.I)
_AUTH_HEADER = re.compile(r'(\bAuthorization["\']?\s{0,3}[:=]\s{0,3}["\']?(?:Basic|Token|Digest)\s+)([A-Za-z0-9._~+/=-]{8,2048})', re.I)
# A bbot finding that prints the secret in brackets: "Secret: [value]" (badsecrets), "Raw result: [value]" and "RawV2 result: [...]" (trufflehog).
_BBOT_BRACKET = re.compile(r'(\b(?:Secret|Raw ?(?:V2)? result)\s{0,3}:\s{0,3}\[)([^\[\]\n]{1,1024})(\])')
# ... and the signed cookie, ViewState or token a badsecrets finding cracked ("Product: [<value>]"): a long value with no space is one.
_BBOT_PRODUCT = re.compile(r'(\bProduct\s{0,3}:\s{0,3}\[)([^\[\]\s]{40,2048})(\])')


_MASKED = '\u2026[redacted '  # what every mask contains


def _prefix_of(text, prefix):
    found = re.match(prefix, text) if prefix else None
    return found.group(0) if found else ''


def _sub_shape(kind, prefix):
    return lambda match: _mask(match.group(0), kind, _prefix_of(match.group(0), prefix))


def _redact_piece(text):
    for kind, prefix, pattern in SHAPES:
        text = pattern.sub(_sub_shape(kind, prefix), text)
    text = _URL_CREDENTIAL.sub(lambda m: m.group(1) + _mask(m.group(2), 'url_password') + m.group(3), text)
    text = _BEARER.sub(lambda m: m.group(1) + _mask(m.group(2), 'bearer_token'), text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + _mask(m.group(2), 'auth_header'), text)
    text = _BBOT_BRACKET.sub(lambda m: m.group(0) if _MASKED in m.group(2) else m.group(1) + _mask(m.group(2), 'secret') + m.group(3), text)
    return _BBOT_PRODUCT.sub(lambda m: m.group(1) + _mask(m.group(2), 'secret_product') + m.group(3), text)


def redact_text(text):
    """``text`` with every well-known secret shape masked (see ``SHAPES``). Not a str (None, a number) is returned unchanged. Idempotent."""
    if not isinstance(text, str) or len(text) < 8:
        return text
    if len(text) <= MAX_TEXT:
        return _redact_piece(text)
    return ''.join(_redact_piece(text[i:i + MAX_TEXT]) for i in range(0, len(text), MAX_TEXT))


def classify(value):
    """``(kind, public prefix)`` of a value that is, whole or in part, of a well-known secret shape; ``('secret', '')`` when it is not."""
    text = str(value)
    for kind, prefix, pattern in SHAPES:
        found = pattern.search(text)
        if found:
            return kind, _prefix_of(found.group(0), prefix)
    return 'secret', ''


def mask_secret(value, hint=''):
    """The mask of ``value``, a value known to be a secret (the extracted result of a token template, a bbot secret): the public prefix of
    its format when it has one, its length, its kind and a keyed fingerprint. Empty stays empty."""
    text = str(value if value is not None else '').strip()
    if not text:
        return ''
    kind, prefix = classify(text)
    if kind == 'secret' and hint:
        kind = re.sub(r'[^a-z0-9_]', '_', str(hint).lower())[:30] or 'secret'
    return _mask(text, kind, prefix)


# Nuclei templates that extract a secret. Strong signals mask every extracted value, a weak one (the generic "exposure" tag) only a value
# that looks like a secret: one token with no whitespace, long enough to be a key.
STRONG_TAGS = frozenset({'token', 'tokens', 'secret', 'secrets', 'key', 'keys', 'apikey', 'api-key', 'credential', 'credentials',
                         'password', 'passwords', 'private-key', 'privatekey', 'access-key'})
WEAK_TAGS = frozenset({'exposure', 'exposures', 'leak', 'disclosure'})
_STRONG_ID = re.compile(r'token|secret|api[-_]?key|access[-_]?key|credential|private[-_]?key|passw(?:or)?d|-key(?:-|$)|^key-', re.I)
WEAK_MIN_LENGTH = 12


def secret_template(template_id='', tags=()):
    """``'strong'``, ``'weak'`` or ``''``: whether a nuclei template (by id and tags) extracts secrets."""
    names = {str(t).strip().lower() for t in tags or ()}
    if names & STRONG_TAGS or _STRONG_ID.search(str(template_id or '')):
        return 'strong'
    return 'weak' if names & WEAK_TAGS else ''


def mask_extracted(values, template_id='', tags=()):
    """``values`` (a finding's ``extracted_results``) ready for a prompt: every value masked for a template that extracts secrets, then
    the generic pass over each (so a secret in a template nobody tagged is still caught)."""
    level = secret_template(template_id, tags)
    out = []
    for value in values or ():
        text = '' if value is None else str(value)
        if level == 'strong' or (level == 'weak' and len(text.strip()) >= WEAK_MIN_LENGTH and not re.search(r'\s', text.strip())):
            out.append(mask_secret(text, template_id or 'secret'))
        else:
            out.append(redact_text(text))
    return out
