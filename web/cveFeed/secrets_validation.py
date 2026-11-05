"""Opt-in validation of exposed secrets: read-only identity checks of the credentials a scan found (docs/SECRETS-PLAN.md 5.2 and 5.3).

Off by default, with three locks, all of which must open for a secret to be checked:

1. **The project opted in.** Only an Org Admin or an App Admin may switch it on, and only by accepting ``ATTESTATION`` word for word; who did, when,
   and the text are stored on ``ProjectSettings`` and written to the audit log (``secrets.validation.enabled`` and ``.disabled``).
2. **The gates.** A project with any bug bounty engagement never validates, whatever its confirmation (program rules forbid using found credentials,
   and cvENGINE cannot read a program's exceptions reliably). Each host must also pass ``bounty_gate.Gate.refusal``.
3. **The allow-list.** Only the Kingfisher rules in ``data/secrets_validation_allowlist.json`` are run with their validator, and only while the
   sha256 of each one's validation block in the pinned rule bundle is the one a person reviewed (``tests.test_secrets_validation`` recomputes them
   in CI from the attested bundle).

Validation happens in the built-in scanner only, at detection time, while it holds the value: a ``secrets_scan`` task that carries
``validate: true`` is never offered to another Sentinel (``agentapi.sentinel_broker``), and the scanner runs a second Kingfisher pass over the same
files with the allow-listed rules only. The value never comes back to be stored. Each host is validated at most once per ``ttl('secrets-validate')``
(7 days); the scanner cannot fingerprint a value the way the inventory does (it has no install key), so the limit is per host, not per secret.

Audit lines: ``secrets.validation.requested`` (project, hosts, rules) for each validating task and ``secrets.validation.result`` (project, inventory
ID, rule ID, outcome) for each answer. Never the value, never the provider's response.
"""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

ALLOWLIST_PATH = Path(__file__).resolve().parent / 'data' / 'secrets_validation_allowlist.json'
LEDGER = 'secrets-validate'
ATTESTATION = ('The targets of this project and the cloud and SaaS accounts behind them are ours, and we authorise read-only credential checks '
               'against them.')


@lru_cache(maxsize=1)
def allowlist():
    """The reviewed allow-list: ``{'kingfisher_version', 'rule_bundle_sha256', 'rules': {rule_id: sha256}, 'helpers': [rule_id]}``."""
    return json.loads(ALLOWLIST_PATH.read_text())


def rule_ids():
    """The rules a validating pass loads: the allow-listed ones and the helpers whose captures they read."""
    data = allowlist()
    return sorted(data['rules']) + sorted(data.get('helpers') or ())


def validator_block(yaml_text, rule_id):
    """The text of ``rule_id``'s ``validation:`` block in a Kingfisher rules file, exactly as written (indentation included), ``''`` when the rule has
    none, ``None`` when the rule is not in the file. Line based on purpose: the hash is of what a reviewer read, not of a parsed form."""
    lines = yaml_text.split('\n')
    start = next((i for i, line in enumerate(lines) if line == f'  id: {rule_id}'), None)
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line.startswith('- ') or (line and not line.startswith(' ')):
            return ''  # the next rule, or the end of the list: no validator
        if line.startswith('  validation:'):
            k = j + 1
            while k < len(lines) and (lines[k].startswith('   ') or lines[k] == ''):
                k += 1
            return '\n'.join(lines[j:k]).rstrip('\n') + '\n'
    return ''


def validator_hash(yaml_text, rule_id):
    block = validator_block(yaml_text, rule_id)
    return hashlib.sha256(block.encode()).hexdigest() if block else block


# ----------------------------------------------------------------------------- the project switch

def settings_row(project_id):
    from cveFeed.models import ProjectSettings
    return ProjectSettings.objects.filter(project_id=project_id).first()


def bounty_project(project_id):
    """Whether ``project_id`` has a bug bounty engagement of any status: such a project never validates."""
    from cveFeed.models import BountyEngagement
    return BountyEngagement.objects.filter(project_id=project_id).exists()


def enabled_for(project_id):
    """Whether locks 1 and 2 (the project half) are open: the project opted in and has no bug bounty engagement."""
    row = settings_row(project_id)
    return bool(row and row.secrets_validation) and not bounty_project(project_id)


def blocked_reason(project_id):
    """Why the project cannot validate now, in words for the page (``''`` when it can)."""
    if bounty_project(project_id):
        return 'this project has a bug bounty engagement: found credentials are never used in a bounty project'
    row = settings_row(project_id)
    if not (row and row.secrets_validation):
        return 'secret validation is off for this project'
    return ''


def can_switch(user, project):
    """Only an Org Admin of the project's organization or an App Admin may switch validation on or off."""
    from tenancy import roles
    return bool(user and user.is_authenticated) and (user.is_superuser or (project.org_id is not None and roles.can_manage_org(user, project.org_id)))


class SwitchError(ValueError):
    pass


def switch(project, user, on, attestation=''):
    """Turn validation on (``attestation`` must be ``ATTESTATION`` exactly) or off, record who and when, and write the audit line. Raises
    ``SwitchError`` with the reason when it may not."""
    from django.utils import timezone

    from cveFeed.models import ProjectSettings
    from tenancy import audit
    if not can_switch(user, project):
        raise SwitchError('only an Org Admin of this organization or an App Admin can change secret validation')
    if on and bounty_project(project.pk):
        raise SwitchError('this project has a bug bounty engagement: secret validation cannot be switched on')
    if on and (attestation or '').strip() != ATTESTATION:
        raise SwitchError('switching secret validation on needs the attestation, accepted word for word')
    row, _ = ProjectSettings.objects.get_or_create(project=project)
    row.secrets_validation = bool(on)
    row.secrets_validation_by, row.secrets_validation_at = user, timezone.now()
    row.secrets_validation_attestation = ATTESTATION if on else ''
    row.updated_by = user
    row.save()
    audit.record(user, 'secrets.validation.enabled' if on else 'secrets.validation.disabled', project.slug, org=project.org_id,
                 project=project.slug, **({'attestation': ATTESTATION} if on else {}))
    return row


# ----------------------------------------------------------------------------- the scan side

def plan(project_id, hosts, builtin_available, force=False, gate=None):
    """``(validate, hosts)``: whether a ``secrets_scan`` batch of ``hosts`` may carry ``validate: true``, and the hosts it validates (the gate's and
    the per-host ledger's survivors). False when the project is not opted in, the built-in scanner cannot take it, or no host is left."""
    if not hosts or not builtin_available or not enabled_for(project_id):
        return False, []
    from cveFeed import ledger
    from cveFeed.bounty_gate import Gate
    gate = gate or Gate()
    allowed = [h for h in hosts if not gate.refusal(project_id, h)]
    if not force:
        fresh = ledger.fresh(LEDGER, allowed, project_id)
        allowed = [h for h in allowed if ledger._norm(h) not in fresh]
    return bool(allowed), allowed


def target_fields(validate):
    """The validation half of a ``secrets_scan`` target."""
    if not validate:
        return {'validate': False, 'validate_rules': [], 'validate_kingfisher': None}
    return {'validate': True, 'validate_rules': rule_ids(), 'validate_kingfisher': allowlist()['kingfisher_version']}


def audit_requested(project, hosts, user=None):
    from tenancy import audit
    audit.record(user, 'secrets.validation.requested', project.slug, org=project.org_id, project=project.slug, hosts=len(hosts),
                 rules=sorted(allowlist()['rules']))


def audit_result(project, row, rule_id, outcome):
    from tenancy import audit
    audit.record(None, 'secrets.validation.result', f'secret #{row.pk}', org=project.org_id, project=project.slug, secret_id=row.pk,
                 rule_id=rule_id, outcome=outcome)


def allowed_outcome(rule_id, outcome, validating):
    """The validation outcome the server keeps for a finding: Kingfisher's outcome only for an allow-listed rule of a task that was told to validate;
    anything else (a Sentinel that validated on its own, a rule not on the list) is ``not_attempted``."""
    from cveFeed.secrets_catalog import OUTCOMES
    if not validating or rule_id not in allowlist()['rules'] or outcome not in OUTCOMES:
        return 'not_attempted'
    return outcome
