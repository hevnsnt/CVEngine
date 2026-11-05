"""What an exposed secret is, from the rule that found it and the shape of its value: the provider, the kind, the class, the severity and why,
and how it is shown (docs/SECRETS-PLAN.md, sections 7 and 8). Pure: no Django, no I/O, no network.

A rule ID comes from one of the detectors that feed the secrets inventory (``cveFeed.secrets_inventory``): a Kingfisher rule
(``betterleaks.gcp-api-key``, ``kingfisher.connection-string.password.unquoted``, ``veles.secrets/sendgrid``), a nuclei token template
(``nuclei:google-api-key``), the route check's own patterns (``route:google_key``) or a bbot module (``bbot:badsecrets``). ``classify`` maps it,
with the value's format, to a ``Kind``: who issued it, what it is and its class:

* ``P``: publishable. A browser key that is meant to sit in a page (a Google API key, a Firebase web config, a Stripe ``pk_`` key, a Mapbox ``pk.``
  token, a Sentry DSN). It is protected by restrictions on the provider's side, not by being secret.
* ``S``: a server secret. Anyone who reads it can act as its owner (an AWS key pair, a GitHub token, a Stripe ``sk_`` key, a private key).
* ``I``: an identifier, or a credential that is half of something (an AWS key ID alone, an OAuth client ID, a webhook URL, a JWT).

``severity`` is the table of section 8.2, deterministic and with no AI: it gives the level and a sentence that says why. A rule this catalog does not
know falls back to the provider named in its ID, class S, medium, and is flagged as uncatalogued (never a crash, never a guess at "safe").

``mask`` is the only form of a value anything shows: the format prefix every key of that kind carries, an ellipsis and the last four characters
(``AIza…x7Qz``), or the PEM header alone for a private key. ``normalise`` is what the inventory fingerprints.
"""
import base64
import json
import re
import time
from dataclasses import dataclass

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
LEVELS = ('info', 'low', 'medium', 'high', 'critical')
CLASSES = ('P', 'S', 'I')
CLASS_WORDS = {'P': 'browser key', 'S': 'server secret', 'I': 'identifier'}
STATUSES = ('unverified', 'live', 'inactive', 'inconclusive', 'public_by_design', 'accepted', 'revoked', 'false_positive')
PERSON_STATUSES = ('unverified', 'public_by_design', 'accepted', 'revoked', 'false_positive')  # what a person may set; the rest come from validation
QUIET_STATUSES = ('public_by_design', 'accepted', 'false_positive', 'revoked')  # count for nothing in a host's score
# Kingfisher's machine-readable validation outcomes (its docs/USAGE.md "Finding Validation Statuses") and what each makes of the status.
OUTCOMES = ('verified_active', 'assumed', 'locally_derived', 'invalid_material', 'verified_inactive', 'unavailable', 'skipped', 'not_attempted')
OUTCOME_STATUS = {'verified_active': 'live', 'verified_inactive': 'inactive', 'invalid_material': 'inactive', 'unavailable': 'inconclusive',
                  'skipped': 'inconclusive'}
MASK_LEN = 80
TAIL = 4
MIN_TAIL_LENGTH = 16  # a value shorter than this shows no character of its own, only its prefix
RULE_ID = re.compile(r'^[a-z0-9][a-z0-9._:/-]{0,119}$')


@dataclass(frozen=True)
class Kind:
    provider: str
    kind: str
    klass: str
    remediation: str
    docs: str = ''
    level: int = None  # the unverified severity when it is not the class's own (a webhook URL is medium)
    catalogued: bool = True

    @property
    def label(self):
        return f'{self.provider} {self.kind.replace("-", " ")}'.strip() if self.provider else self.kind.replace('-', ' ')


_ROTATE = 'Rotate the credential at the provider, remove it from what the site serves, and check the provider\'s logs for use you do not recognise.'
_GOOGLE = ('A browser key is meant to be embedded. Confirm in the Google Cloud console that it has an HTTP referrer (or app) restriction and is '
           'limited to the APIs the site uses; an unrestricted key can be used by anyone, at your cost.')

# (rule ID pattern, value pattern or None, Kind). The first entry whose rule pattern matches the rule ID (and whose value pattern matches the value,
# when it has one) wins, so the specific entries come before the generic ones.
CATALOG = (
    # Google: the API key served in a page is a browser key; a service-account key or ADC file is a server secret
    (r'(gcp-api-key|google-api-key|google_key|firebase-api-key)', None, Kind('Google', 'google-api-key', 'P', _GOOGLE,
                                                                            'https://cloud.google.com/docs/authentication/api-keys#securing')),
    (r'firebase-web-config', None, Kind('Google', 'firebase-web-config', 'P', 'A Firebase web config is public by design: check the Firebase security '
                                         'rules of its database and storage, which are what protect the data.', 'https://firebase.google.com/docs/rules')),
    (r'gcp-gemini-api', None, Kind('Google', 'gemini-api-key', 'S', _ROTATE)),
    (r'(gcp-service-account|gcp-application-default-credentials|google-service-account)', None,
     Kind('Google', 'gcp-service-account-key', 'S', _ROTATE, 'https://cloud.google.com/iam/docs/keys-disable-enable')),
    # AWS: a key ID alone is an identifier; with its secret (``aws-access-key-pair``, set by the inventory) it is a server secret
    (r'aws-secret-access-key', None, Kind('AWS', 'aws-access-key-pair', 'S', _ROTATE, 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html')),
    (r'(aws-session-token)', None, Kind('AWS', 'aws-session-token', 'S', _ROTATE)),
    (r'(aws-amazon-bedrock-api-key)', None, Kind('AWS', 'bedrock-api-key', 'S', _ROTATE)),
    (r'(aws-access-token|aws-access-key|aws_key)', None, Kind('AWS', 'aws-access-key-id', 'I', 'An AWS access key ID alone cannot sign a request, but '
                                                              'it names an account and a user: look for its secret key nearby and rotate the pair.')),
    # Stripe: pk_ is publishable, sk_ and rk_ are not
    (r'stripe', r'^pk_(?:live|test)_', Kind('Stripe', 'stripe-publishable-key', 'P', 'A Stripe publishable key is meant for the browser. Make sure no '
                                             'secret (sk_) or restricted (rk_) key is served beside it.')),
    (r'stripe', r'^rk_', Kind('Stripe', 'stripe-restricted-key', 'S', _ROTATE)),
    (r'stripe', None, Kind('Stripe', 'stripe-secret-key', 'S', _ROTATE, 'https://docs.stripe.com/keys#rolling-keys')),
    # Mapbox: pk. is a public token, sk. a secret one
    (r'mapbox', r'^pk\.', Kind('Mapbox', 'mapbox-public-token', 'P', 'A Mapbox public token is meant for the browser; restrict it to your URLs.')),
    (r'mapbox', None, Kind('Mapbox', 'mapbox-secret-token', 'S', _ROTATE)),
    # Slack and Discord: tokens are server secrets, webhook URLs post into a channel
    (r'slack-webhook', None, Kind('Slack', 'slack-webhook-url', 'I', 'Anyone with this URL can post into the channel. Regenerate the webhook.', level=MEDIUM)),
    (r'discord.*webhook', None, Kind('Discord', 'discord-webhook-url', 'I', 'Anyone with this URL can post into the channel. Delete and recreate the webhook.',
                                      level=MEDIUM)),
    (r'(slack|xox)', None, Kind('Slack', 'slack-token', 'S', _ROTATE, 'https://api.slack.com/authentication/token-types')),
    (r'discord-client-id', None, Kind('Discord', 'discord-client-id', 'I', 'A client ID is public; make sure its secret is not served too.')),
    (r'discord', None, Kind('Discord', 'discord-token', 'S', _ROTATE)),
    # source hosting
    (r'(github|gh[pousr]_)', None, Kind('GitHub', 'github-token', 'S', _ROTATE, 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation')),
    (r'gitlab', None, Kind('GitLab', 'gitlab-token', 'S', _ROTATE)),
    (r'bitbucket', None, Kind('Bitbucket', 'bitbucket-token', 'S', _ROTATE)),
    # mail, messaging and AI
    (r'sendgrid', None, Kind('SendGrid', 'sendgrid-api-key', 'S', _ROTATE)),
    (r'mailgun-pub-key', None, Kind('Mailgun', 'mailgun-public-key', 'P', 'A Mailgun public validation key is meant to be public.')),
    (r'mailgun', None, Kind('Mailgun', 'mailgun-api-key', 'S', _ROTATE)),
    (r'twilio', None, Kind('Twilio', 'twilio-api-key', 'S', _ROTATE)),
    (r'anthropic', None, Kind('Anthropic', 'anthropic-api-key', 'S', _ROTATE)),
    (r'openai', None, Kind('OpenAI', 'openai-api-key', 'S', _ROTATE)),
    # package registries
    (r'(npm)', None, Kind('npm', 'npm-token', 'S', _ROTATE)),
    (r'pypi', None, Kind('PyPI', 'pypi-token', 'S', _ROTATE)),
    # Azure
    (r'(azure-client-id|azure-tenant-id|azure-storage-account-name)', None, Kind('Azure', 'azure-identifier', 'I', 'An Azure tenant, client or account '
                                                                                 'name is not a secret on its own; check that its secret is not served too.')),
    (r'azure', None, Kind('Azure', 'azure-secret', 'S', _ROTATE)),
    # browser-side identifiers and keys
    (r'sentry-dsn', None, Kind('Sentry', 'sentry-dsn', 'P', 'A Sentry DSN is meant for the browser. Limit its allowed domains in Sentry.')),
    (r'sentry', None, Kind('Sentry', 'sentry-token', 'S', _ROTATE)),
    (r'recaptcha', None, Kind('Google', 'recaptcha-site-key', 'P', 'A reCAPTCHA site key is meant for the browser.')),
    (r'algolia-application-id', None, Kind('Algolia', 'algolia-application-id', 'I', 'An Algolia application ID is public.')),
    (r'algolia', None, Kind('Algolia', 'algolia-api-key', 'S', 'If this is a search-only key it is meant for the browser and can be marked public by '
                                                              'design; an admin or write key must be rotated.', level=MEDIUM)),
    (r'(paypal-client-id|client-id|oauth-client-id)', None, Kind('', 'oauth-client-id', 'P', 'An OAuth client ID is public; make sure its secret is not served.')),
    # tokens of no one provider
    (r'(jwt|json-web-token)', None, Kind('', 'jwt', 'I', 'A JSON Web Token is a signed claim. If it has not expired it may let its holder act as the '
                                                         'subject it names: find what issued it and revoke the session.')),
    (r'(private-key|private_key|pem)', None, Kind('', 'private-key', 'S', 'Replace the key pair, revoke any certificate issued for it, and remove '
                                                                        'the file from what the site serves.')),
    (r'(connection-string|database-url|mongodb-connection|postgres|mysql|redis-url)', None,
     Kind('', 'database-url', 'S', 'Change the database password, remove the connection string from what the site serves, and check that the '
                                   'database is not reachable from the internet.')),
    (r'(badsecrets)', None, Kind('', 'known-secret', 'S', 'The secret is a known default or a published key (bbot badsecrets): replace it with a '
                                                          'random one and rotate the sessions it signed.')),
    (r'(trufflehog)', None, Kind('', 'secret', 'S', _ROTATE)),
)
_COMPILED = tuple((re.compile(rule, re.I), re.compile(value) if value else None, kind) for rule, value, kind in CATALOG)

# Providers by the name a rule ID carries, for an uncatalogued rule: ``betterleaks.datadog-api-key`` is Datadog's.
_PROVIDER_WORDS = {'aws': 'AWS', 'gcp': 'Google', 'google': 'Google', 'azure': 'Azure', 'github': 'GitHub', 'gitlab': 'GitLab', 'slack': 'Slack',
                   'openai': 'OpenAI', 'npm': 'npm', 'pypi': 'PyPI', 'digitalocean': 'DigitalOcean', 'mongodb': 'MongoDB', 'heroku': 'Heroku'}


def rule_id_ok(rule_id):
    return isinstance(rule_id, str) and bool(RULE_ID.match(rule_id))


def _short(rule_id):
    """The rule's own name without its namespace or source: ``betterleaks.gcp-api-key`` and ``nuclei:google-api-key`` are ``gcp-api-key`` and
    ``google-api-key``."""
    rule_id = str(rule_id or '').lower()
    rule_id = rule_id.split(':', 1)[1] if ':' in rule_id else rule_id
    return rule_id.split('.', 1)[1] if rule_id.split('.', 1)[0] in ('betterleaks', 'kingfisher', 'veles', 'custom') and '.' in rule_id else rule_id


def _fallback_provider(rule_id):
    word = re.split(r'[^a-z0-9]+', _short(rule_id).replace('secrets/', ''))[0] if rule_id else ''
    return _PROVIDER_WORDS.get(word) or (word.capitalize() if word and word not in ('generic', 'secret', 'key', 'token', 'api') else '')


def classify(rule_id, value=''):
    """The ``Kind`` of a secret found by ``rule_id`` with value ``value`` (the value only refines a rule shared by several kinds, Stripe's ``pk_``
    against ``sk_``). Never raises: an unknown rule is uncatalogued, class S, medium."""
    value = normalise(value)
    for rule, value_re, kind in _COMPILED:
        if rule.search(str(rule_id or '')) and (value_re is None or value_re.search(value)):
            return kind
    if value.startswith('-----BEGIN') and 'PRIVATE KEY' in value[:80]:
        return classify('private-key', value)
    return Kind(_fallback_provider(rule_id), _short(rule_id)[:60] or 'secret', 'S', _ROTATE, level=MEDIUM, catalogued=False)


def normalise(value):
    """The value as it is fingerprinted: no surrounding whitespace or quotes (a key copied out of ``"AIza..."`` or ``'AIza...'`` is the same key)."""
    text = str(value if value is not None else '').strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'`':
        text = text[1:-1].strip()
    return text


# The public prefix a value of each format carries: kept in the mask, since every key of the kind starts with it.
_PREFIXES = re.compile(
    r'^(?:AIza|AKIA|ASIA|AGPA|AIDA|AROA|github_pat_|gh[pousr]_|glpat-|gldt-|glrt-|xox[abposre]-|xapp-|[spr]k_(?:live|test)_|sk-ant-(?:api\d\d-|admin\d\d-)?|'
    r'sk-(?:proj-|svcacct-|admin-)?|SG\.|key-|npm_|pypi-|eyJ|pk\.|sk\.|AC|SK|https?://hooks\.slack\.com/|https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/|'
    r'[a-z][a-z0-9+.-]{1,20}://)')
_PEM = re.compile(r'-----BEGIN ((?:[A-Z0-9]{1,12} ){0,3}PRIVATE KEY(?: BLOCK)?)-----')


def mask(value, kind=''):
    """How a secret is shown everywhere: its format prefix, an ellipsis and its last four characters (``AIza…x7Qz``); the prefix alone for a value
    shorter than ``MIN_TAIL_LENGTH``; ``PEM RSA PRIVATE KEY`` for a private key. Never more than the prefix and four characters."""
    text = normalise(value)
    if not text:
        return ''
    pem = _PEM.search(text[:200])
    if pem or kind == 'private-key':
        return (f'PEM {pem.group(1)}' if pem else 'PEM PRIVATE KEY')[:MASK_LEN]
    found = _PREFIXES.match(text)
    prefix = found.group(0) if found else ''
    if len(prefix) > 40 or len(prefix) >= len(text) - TAIL:
        prefix = prefix[:12] if len(text) - TAIL > 12 else ''
    tail = text[-TAIL:] if len(text) >= MIN_TAIL_LENGTH else ''
    return f'{prefix}…{tail}'[:MASK_LEN]


def jwt_expiry(value):
    """The ``exp`` claim of a JWT (seconds since the epoch), decoded without checking the signature, or None when there is none or it is not a JWT."""
    parts = normalise(value).split('.')
    if len(parts) < 2 or not parts[0].startswith('eyJ'):
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None
    exp = claims.get('exp') if isinstance(claims, dict) else None
    return int(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def facts(kind, value):
    """What can be read from a value that is not the value itself, kept on the inventory row: a JWT's expiry."""
    if kind.kind == 'jwt':
        exp = jwt_expiry(value)
        return {'exp': exp} if exp is not None else {}
    return {}


def _unrestricted_billable(meta):
    """Whether validation showed a browser key that anyone can use for a sensitive or billable API: for Google, Gemini access with no referrer,
    address or app restriction."""
    meta = meta or {}
    return meta.get('gemini_access') in (True, 'true') and not meta.get('restriction')


def severity(kind, status='unverified', meta=None, row_facts=None, now=None):
    """``(level, basis)`` for a secret of ``kind`` (a ``Kind``) in ``status``, from the table in docs/SECRETS-PLAN.md section 8.2. ``meta`` is the
    sanitised validation metadata, ``row_facts`` what ``facts`` kept. A person's status (``public_by_design``, ``accepted``, ``false_positive``,
    ``revoked``) does not change the level; it takes the secret out of the host's score (``counts``)."""
    klass = kind.klass
    live = status == 'live'
    inactive = status == 'inactive'
    if klass == 'P':
        if live:
            if _unrestricted_billable(meta):
                return MEDIUM, (f'a {kind.label} that validation shows is not restricted and can reach a billable API: restrict it in the provider\'s '
                                'console')
            return LOW, f'a {kind.label} that validation shows is active; browser keys are meant to be embedded, so check its restrictions'
        if inactive:
            return INFO, f'a {kind.label} that the provider no longer accepts'
        return INFO, f'likely public by design: a {kind.label} served to browsers, protected by restrictions on the provider\'s side'
    if klass == 'S':
        if live:
            return CRITICAL, f'a {kind.label} that validation shows is active: anyone who reads the page can use it'
        if inactive:
            return LOW, f'a {kind.label} the provider no longer accepts: rotate and remove it anyway'
        if kind.level is not None:
            return kind.level, (f'an uncatalogued secret ({kind.kind}): treated as a server secret of medium severity until a person reviews it'
                                if not kind.catalogued else f'a {kind.label} served to anyone who asks')
        return HIGH, f'a {kind.label} served to anyone who asks: a server secret, not meant to leave the server'
    if kind.kind == 'jwt':
        exp = (row_facts or {}).get('exp')
        now = time.time() if now is None else now
        if exp is not None and exp < now:
            return LOW, 'a JSON Web Token that has expired (by its exp claim, read without checking the signature)'
        return MEDIUM, ('a JSON Web Token that has not expired (by its exp claim, read without checking the signature)' if exp is not None
                        else 'a JSON Web Token with no expiry claim')
    if kind.level is not None:
        return kind.level, f'a {kind.label}: it lets anyone who reads it act through it'
    return LOW, f'a {kind.label}: an identifier, not a credential on its own'


def counts(status):
    """Whether a secret in ``status`` counts towards a host's score and the open lists."""
    return status not in QUIET_STATUSES


def status_after_validation(current, outcome):
    """The status a validation outcome leads to. A person's decision (public by design, accepted, revoked, false positive) is never overwritten."""
    if current in ('public_by_design', 'accepted', 'revoked', 'false_positive'):
        return current
    return OUTCOME_STATUS.get(outcome, current)
