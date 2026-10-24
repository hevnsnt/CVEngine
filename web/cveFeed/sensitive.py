"""Sensitive data in a web response: which kinds of secrets and personal data a route serves, never the values.

``scan_text`` reads the body already sampled by the route auth probe (at most 64 KB) and returns, per type, how many
distinct values it saw and ONE sample: a credential shows only its type, length and public prefix, personal data a partial mask. Raw matches never leave this module: nothing here logs, stores or returns a
value, only counts and masked samples. All functions are pure.
"""
import ipaddress
import re

MAX_PER_TYPE = 50  # distinct values counted per type per body
CREDENTIAL_TYPES = ('aws_key', 'google_key', 'slack_token', 'github_token', 'stripe_key', 'jwt', 'private_key')
PII_TYPES = ('email', 'phone', 'card')
INTERNAL_TYPES = ('internal_ip', 'internal_host')
TYPE_GROUPS = {'credentials': CREDENTIAL_TYPES, 'pii': PII_TYPES, 'internal': INTERNAL_TYPES}
PATTERNS = {
    'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
    'phone': r'(?<!\d)(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]?\d{3,4}(?!\d)',
    'card': r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)',  # then Luhn + IIN check
    'aws_key': r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
    'google_key': r'\bAIza[0-9A-Za-z_-]{35}\b',
    'slack_token': r'\bxox[abposr]-[0-9A-Za-z-]{10,}\b',
    'github_token': r'\bgh[pousr]_[A-Za-z0-9]{36}\b',
    'stripe_key': r'\b[sr]k_live_[0-9a-zA-Z]{24,}\b',
    'jwt': r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
    'private_key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----',
    'internal_ip': r'\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b',
    'internal_host': r'\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|internal|corp|lan|intranet)\b',
}
COMPILED = {name: re.compile(pattern, re.I if name == 'internal_host' else 0) for name, pattern in PATTERNS.items()}
EMAIL_NOISE = ('example.com', 'example.org', 'sentry.io', 'w3.org', 'schema.org', 'yoursite', 'email.com', 'domain.com')
ASSET_TLDS = ('png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'css', 'js', 'map')
TEXT_TYPES = ('application/json', 'application/javascript', 'application/xml', 'application/x-javascript', 'application/ecmascript')


def luhn_ok(digits):
    total, flip = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if flip:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        flip = not flip
    return total % 10 == 0


def card_ok(raw):
    """A payment card number: 13 to 19 digits, Luhn, and a first digit of 3, 4, 5 or 6 (Amex, Visa, Mastercard, Discover
    IINs), which cuts timestamps and order ids."""
    digits = re.sub(r'[ -]', '', raw)
    return digits.isdigit() and 13 <= len(digits) <= 19 and digits[0] in '3456' and luhn_ok(digits)


def _phone_ok(raw):
    digits = re.sub(r'\D', '', raw)
    return len(digits) >= 10 and len(set(digits)) > 1 and not card_ok(raw)


def _email_ok(value):
    lowered = value.lower()
    domain = lowered.rsplit('@', 1)[1]
    if any(noise in domain for noise in EMAIL_NOISE):
        return False
    return domain.rsplit('.', 1)[-1] not in ASSET_TLDS


def _internal_ip_ok(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def mask(value):
    """A masked sample: the first 2 and last 2 characters around up to 8 stars (``jo********om``); a value of 4 or fewer
    characters is all stars. An email keeps the first 2 characters of the name and the TLD: ``jo**@****.com``. Never returns
    more than 4 characters of a non-email value, and nothing of a short one."""
    value = str(value)
    if '@' in value and not value.startswith('@') and '.' in value.rsplit('@', 1)[1]:
        local, domain = value.rsplit('@', 1)
        shown = local[:2] if len(local) > 2 else local[:1]
        return f'{shown}**@****.{domain.rsplit(".", 1)[1]}'
    if len(value) <= 4:
        return '*' * len(value)
    return value[:2] + '*' * min(len(value) - 4, 8) + value[-2:]


# what a sample of a credential may show: a label, the length and the public format prefix. The prefix (AKIA, ghp_, sk_live_, eyJ)
# is a format marker every key of that kind carries, not secret material; no character of the secret itself is ever kept.
CREDENTIAL_LABELS = {'aws_key': 'AWS access key', 'google_key': 'Google API key', 'slack_token': 'Slack token',
                     'github_token': 'GitHub token', 'stripe_key': 'Stripe live key', 'jwt': 'JWT'}
CREDENTIAL_PREFIX = {'aws_key': re.compile(r'^(?:AKIA|ASIA)'), 'google_key': re.compile(r'^AIza'), 'slack_token': re.compile(r'^xox[abposr]-'),
                     'github_token': re.compile(r'^gh[pousr]_'), 'stripe_key': re.compile(r'^[sr]k_live_'), 'jwt': re.compile(r'^eyJ')}


def sample(value, name):
    """The sample stored and shown for one value of type ``name``. A credential shows only its type, its length and its public
    format prefix (``AWS access key, 20 chars (AKIA...)``); a private key shows its PEM header, which is the same text in every
    key. Email, phone, card and the internal identifiers keep ``mask``'s partial view: they say whose data it is, not how to log in."""
    value = str(value)
    if name == 'private_key':
        return f'private key, PEM header {value[:60]}'
    if name in CREDENTIAL_LABELS:
        prefix = CREDENTIAL_PREFIX[name].match(value)
        return f'{CREDENTIAL_LABELS[name]}, {len(value)} chars' + (f' ({prefix.group(0)}...)' if prefix else '')
    return mask(value)


def is_text(content_type):
    """Only text, JSON, JavaScript and XML bodies are scanned; images, fonts, PDFs and octet streams never are."""
    ct = (content_type or '').split(';')[0].strip().lower()
    if not ct:
        return False
    return ct.startswith('text/') or ct in TEXT_TYPES or ct.endswith('+json') or ct.endswith('+xml')


def _card_spans(text):
    return [m.span() for m in COMPILED['card'].finditer(text) if card_ok(m.group(0))]


def _distinct(name, text, skip=()):
    """Distinct valid matches of one type, in order of appearance, at most MAX_PER_TYPE. Matches that overlap a ``skip`` span
    are ignored (a card number is not also a phone number)."""
    seen, out = set(), []
    for match in COMPILED[name].finditer(text):
        if any(match.start() < end and start < match.end() for start, end in skip):
            continue
        value = match.group(0)
        key = value.lower() if name in ('email', 'internal_host') else re.sub(r'[ -]', '', value) if name == 'card' else value
        if key in seen:
            continue
        valid = {'email': _email_ok, 'phone': _phone_ok, 'card': card_ok, 'internal_ip': _internal_ip_ok}.get(name, lambda v: True)
        if not valid(value):
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= MAX_PER_TYPE:
            break
    return out


def scan_text(text):
    """``{type: {'count': n, 'sample': masked}}`` for the sensitive data in ``text`` (already capped by the caller). Distinct
    values per type, at most MAX_PER_TYPE; emails with a placeholder domain or an image or font extension are dropped; a value
    that is a credential is not also counted as a JWT or an email. Raw matches never leave this function."""
    text = text or ''
    cards = _card_spans(text)
    found = {name: _distinct(name, text, cards if name == 'phone' else ()) for name in PATTERNS}
    credentials = [v for name in CREDENTIAL_TYPES if name != 'jwt' for v in found[name]]
    found['jwt'] = [v for v in found['jwt'] if not any(v in c or c in v for c in credentials)]
    found['email'] = [v for v in found['email'] if not any(v in c for c in credentials + found['jwt'])]
    return {name: {'count': len(values), 'sample': sample(values[0], name)} for name, values in found.items() if values}


def sensitive_score(found):
    """0 to 25: any credential 25; PII (5 or more emails, 3 or more phone numbers, any card) 15; a few emails or phone numbers
    (a contact page) or internal identifiers 5; the highest that applies."""
    if not found:
        return 0
    if any(t in found for t in CREDENTIAL_TYPES):
        return 25
    count = lambda t: (found.get(t) or {}).get('count', 0)  # noqa: E731
    if count('email') >= 5 or count('phone') >= 3 or count('card') >= 1:
        return 15
    if count('email') or count('phone') or any(t in found for t in INTERNAL_TYPES):
        return 5
    return 0
