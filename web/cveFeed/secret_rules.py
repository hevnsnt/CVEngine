"""The instance's custom rules and placeholder lists for the secrets scan (docs/SECRETS-PLAN.md section 10).

* **Custom rules.** Kingfisher YAML, at most ``MAX_BYTES``, checked here against a strict subset of Kingfisher's rule schema (``name``, ``id`` under
  ``custom.``, ``pattern``, ``min_entropy``, ``confidence``, ``keywords``, ``examples``) and refused with the reason otherwise. **No ``validation``
  block**: a custom rule only detects. The Sentinel fetches them from ``GET /api/v1/sentinel/secret-rules/bundle`` (its token only) when a task's
  ``rules_bundle_sha256`` names a set it does not have, and runs them with ``--rules-path``.
* **Skip words and patterns.** Passed as ``--skip-word`` and ``--skip-regex``: a match that contains one is a placeholder, not a secret. The list
  starts with ``DEFAULT_SKIP_WORDS``.
* **Known-public keys** are not listed here: they are the inventory's ``public_by_design`` and ``accepted`` statuses, keyed by fingerprint.

App Admins only; every change is audited (``secrets.rules.updated``).
"""
import hashlib
import re

MAX_BYTES = 64 * 1024
MAX_RULES = 100
MAX_PATTERN = 2000
MAX_SKIP_WORDS, SKIP_WORD_LEN = 100, 100
MAX_SKIP_REGEX, SKIP_REGEX_LEN = 50, 200
RULE_KEYS = ('name', 'id', 'pattern', 'min_entropy', 'confidence', 'keywords', 'examples')
CUSTOM_ID = re.compile(r'^custom\.[a-z0-9][a-z0-9._-]{0,100}$')
DEFAULT_SKIP_WORDS = ('EXAMPLE', 'PLACEHOLDER', 'your-api-key', 'xxxxxxxx', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')


class RulesError(ValueError):
    pass


def check_rules(text):
    """The ids of the rules in ``text`` (Kingfisher YAML: ``rules: [...]``) when every rule keeps to the subset, else ``RulesError`` with the
    first reason. Empty text is no rules."""
    import yaml
    text = text or ''
    if len(text.encode()) > MAX_BYTES:
        raise RulesError(f'the rules are larger than {MAX_BYTES // 1024} KB')
    if not text.strip():
        return []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RulesError(f'not valid YAML: {str(exc).splitlines()[0][:200]}') from None
    if not isinstance(doc, dict) or set(doc) != {'rules'} or not isinstance(doc['rules'], list):
        raise RulesError('the file must hold one key, rules, with a list of rules')
    if len(doc['rules']) > MAX_RULES:
        raise RulesError(f'at most {MAX_RULES} rules')
    ids = []
    for n, rule in enumerate(doc['rules'], 1):
        where = f'rule {n}'
        if not isinstance(rule, dict):
            raise RulesError(f'{where} is not a mapping')
        extra = sorted(set(rule) - set(RULE_KEYS))
        if extra:
            raise RulesError(f'{where}: {", ".join(extra)} is not allowed (a custom rule may have only {", ".join(RULE_KEYS)}; never a validation)')
        for key in ('name', 'id', 'pattern'):
            if not isinstance(rule.get(key), str) or not rule[key].strip():
                raise RulesError(f'{where}: {key} is required')
        if not CUSTOM_ID.match(rule['id']):
            raise RulesError(f'{where}: the id must start with custom. and use lowercase letters, digits, dots, dashes or underscores')
        if rule['id'] in ids:
            raise RulesError(f'{where}: the id {rule["id"]} is used twice')
        if len(rule['pattern']) > MAX_PATTERN:
            raise RulesError(f'{where}: the pattern is longer than {MAX_PATTERN} characters')
        try:
            re.compile(rule['pattern'])
        except re.error as exc:
            raise RulesError(f'{where}: the pattern does not compile ({exc})') from None
        if 'confidence' in rule and rule['confidence'] not in ('low', 'medium', 'high'):
            raise RulesError(f'{where}: confidence must be low, medium or high')
        if 'min_entropy' in rule and (isinstance(rule['min_entropy'], bool) or not isinstance(rule['min_entropy'], (int, float))
                                      or not 0 <= rule['min_entropy'] <= 8):
            raise RulesError(f'{where}: min_entropy must be a number from 0 to 8')
        for key, most, length in (('keywords', 20, 100), ('examples', 10, 500)):
            values = rule.get(key, [])
            if not isinstance(values, list) or len(values) > most or not all(isinstance(v, str) and 0 < len(v) <= length for v in values):
                raise RulesError(f'{where}: {key} must be a list of at most {most} strings of at most {length} characters')
        ids.append(rule['id'])
    return ids


def check_skip(words, patterns):
    """``(words, patterns)`` cleaned (stripped, each once, in order), or ``RulesError``."""
    def clean(values, most, length, what):
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise RulesError(f'{what} must be a list of strings')
        out = list(dict.fromkeys(v.strip() for v in values if v.strip()))
        if len(out) > most or any(len(v) > length for v in out):
            raise RulesError(f'{what}: at most {most}, each at most {length} characters')
        return out
    words = clean(words, MAX_SKIP_WORDS, SKIP_WORD_LEN, 'skip words')
    patterns = clean(patterns, MAX_SKIP_REGEX, SKIP_REGEX_LEN, 'skip patterns')
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise RulesError(f'skip pattern {pattern!r} does not compile ({exc})') from None
    return words, patterns


def current():
    """The stored row, made with the defaults the first time it is read."""
    from cveFeed.models import SecretScanRules
    return SecretScanRules.objects.order_by('id').first() or SecretScanRules.objects.create(skip_words=list(DEFAULT_SKIP_WORDS), skip_regex=[])


def bundle():
    """``(text, sha256)`` of the custom rules, or ``(None, None)`` when there are none."""
    text = current().rules_yaml or ''
    if not text.strip():
        return None, None
    data = text.encode()
    return data, hashlib.sha256(data).hexdigest()


def target_fields():
    """The rules half of a ``secrets_scan`` target."""
    row = current()
    return {'rules_bundle_sha256': bundle()[1], 'skip_words': list(row.skip_words or [])[:MAX_SKIP_WORDS],
            'skip_regex': list(row.skip_regex or [])[:MAX_SKIP_REGEX]}


def describe():
    row = current()
    return {'rules_yaml': row.rules_yaml or '', 'rule_ids': _ids_quietly(row.rules_yaml), 'skip_words': list(row.skip_words or []),
            'skip_regex': list(row.skip_regex or []), 'bundle_sha256': bundle()[1],
            'updated_at': row.updated_at.isoformat() if row.pk and row.updated_at else None, 'max_bytes': MAX_BYTES,
            'default_skip_words': list(DEFAULT_SKIP_WORDS)}


def _ids_quietly(text):
    try:
        return check_rules(text)
    except RulesError:
        return []


def save(user, rules_yaml=None, skip_words=None, skip_regex=None):
    """Store what is given (what is left out stays as it is) after checking it; App Admins only. Returns ``describe()``."""
    from tenancy import audit
    if not (user and user.is_superuser):
        raise PermissionError('only an App Admin can change the secrets scan rules')
    row = current()
    rules_yaml = row.rules_yaml if rules_yaml is None else str(rules_yaml)
    ids = check_rules(rules_yaml)
    words, patterns = check_skip(list(row.skip_words or []) if skip_words is None else skip_words,
                                 list(row.skip_regex or []) if skip_regex is None else skip_regex)
    row.rules_yaml, row.skip_words, row.skip_regex, row.updated_by = rules_yaml, words, patterns, user
    row.save()
    audit.record(user, 'secrets.rules.updated', 'secrets scan rules', rules=ids, skip_words=len(words), skip_regex=len(patterns))
    return describe()
