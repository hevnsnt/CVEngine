"""Bounded AI choice among checks that the deterministic validation policy already permits.

The model receives evidence and names of approved checks, never a shell command or an
arbitrary target. Its response can only select those checks or request a draft template.
"""
import hashlib
import json
import re
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from cveFeed import templategen
from cveFeed.models import TriageCall
from reNgine.ai_providers import clean_text, untrusted_block

SYSTEM = ("Choose only checks that can distinguish a specific missing fact about this CVE and affected product. "
          "A check being safe and available does not make it relevant. Generic HTTP banners and nmap service versions "
          "cannot verify local kernel, driver, NIC, KVM or hardware prerequisites. If none can establish a relevant "
          "fact, return an empty check_kinds list and explain the missing evidence. "
          "Reply with one JSON object only: "
          '{"check_kinds":["nuclei_template"],"generate_template":false,"reason":"..."}. '
          "check_kinds may contain only listed kinds. Choose generate_template only if no safe installed CVE "
          "template exists and a specific non-destructive detector can plausibly be written from the CVE facts. "
          "Never propose commands, URLs, hosts, credentials, or an exploit payload. An empty plan is allowed "
          "when evidence is insufficient. A version or a generic server banner alone does not prove vulnerability.")
MAX_REASON = 700


def parse_plan(reply, checks, can_generate):
    """Reject out-of-schema choices. A model cannot expand the deterministic check set."""
    match = re.search(r'\{.*\}', reply or '', re.DOTALL)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or set(obj) != {'check_kinds', 'generate_template', 'reason'}:
        return None
    kinds, generate, reason = obj['check_kinds'], obj['generate_template'], obj['reason']
    allowed = {c['kind'] for c in checks}
    if not isinstance(kinds, list) or len(kinds) > len(allowed) or len(set(map(str, kinds))) != len(kinds):
        return None
    if any(not isinstance(k, str) or k not in allowed for k in kinds):
        return None
    if not isinstance(generate, bool) or (generate and (not can_generate or 'nuclei_template' in allowed)):
        return None
    if not isinstance(reason, str) or not reason.strip():
        return None
    return {'check_kinds': kinds, 'generate_template': generate, 'reason': clean_text(reason, MAX_REASON),
            'source': 'ai'}


def _reserve(project_id, signature):
    """One in-flight plan per signature; a project has at most 20, and all projects 200, billable attempts daily."""
    with transaction.atomic():
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', [21860074])
        now = timezone.now()
        TriageCall.objects.filter(kind='validation_plan', status='running', expires_at__lte=now).update(
            status='expired', finished_at=now)
        if TriageCall.objects.filter(kind='validation_plan', signature=signature, status='running').exists():
            return None, 'another planning request is running for this evidence'
        since = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today = TriageCall.objects.filter(kind='validation_plan', started_at__gte=since)
        if today.count() >= 200 or today.filter(project_id=project_id).count() >= 20:
            return None, 'AI planning daily budget reached'
        return TriageCall.objects.create(kind='validation_plan', project_id=project_id, signature=signature,
                                         expires_at=now + timedelta(minutes=5)), ''


def plan(project_id, row, cve, subject, checks, template, provider=None, observations=None):
    """Return (decision, provider). Failure cannot authorize generic checks by default."""
    can_generate = not template[0]
    # An exact CVE template is relevant by construction; generic banners are not.
    fallback = {'check_kinds': ['nuclei_template'] if any(c['kind'] == 'nuclei_template' for c in checks) else [],
                'generate_template': False,
                'reason': 'No usable AI plan. Only a vetted CVE-specific template can run without an AI relevance decision.',
                'source': 'policy_fallback'}
    if provider is None:
        try:
            from reNgine.ai_settings import get_configured_provider
            provider = get_configured_provider()
        except Exception:
            provider = None
    if provider is None:
        return {**fallback, 'reason': 'No AI provider is configured; generic external checks have no CVE-specific relevance decision.'}, None
    observation_digest = hashlib.sha256(json.dumps(observations or [], sort_keys=True, default=str).encode()).hexdigest()[:12]
    signature = hashlib.sha256(f'validation-plan-v2:{project_id}:{row.signature}:{observation_digest}'.encode()).hexdigest()[:40]
    claim, why = _reserve(project_id, signature)
    if claim is None:
        return {**fallback, 'reason': why + '; generic external checks deferred.'}, provider
    try:
        context = {'cve': templategen.cve_info_for(cve),
                   'asset_evidence': {k: subject.get(k) for k in ('source', 'product', 'matched_version', 'range', 'port')},
                   'approved_checks': [{'kind': c['kind'], 'label': c['label']} for c in checks],
                   'completed_observations': (observations or [])[:6],
                   'safe_template': bool(template[0]), 'template_unavailable_reason': template[1] if not template[0] else ''}
        # templategen's prompt cleaner treats CVE feed text as hostile input. The hostname and IP are excluded.
        safe = templategen._clean_value(context, 500)
        from reNgine.ai_providers import usage_stage
        with usage_stage('validation_plan'):
            decision = parse_plan(provider.complete(SYSTEM, untrusted_block('VALIDATION_CONTEXT', safe)), checks, can_generate)
        TriageCall.objects.filter(pk=claim.pk, status='running').update(
            status='succeeded' if decision else 'failed', finished_at=timezone.now())
        if decision:
            return decision, provider
        return {**fallback, 'reason': 'AI returned an invalid plan; generic external checks deferred.'}, provider
    except Exception:
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='failed', finished_at=timezone.now())
        return {**fallback, 'reason': 'AI planning failed; generic external checks deferred.'}, provider


def generate_candidate(project_id, cve, provider):
    """Create at most one bounded draft attempt for a CVE; never install or run it on the requested host."""
    if provider is None:
        return {'status': 'unavailable', 'reason': 'AI provider is not configured'}
    signature = hashlib.sha256(f'validation-template-v1:{project_id}:{cve.cve_id}'.encode()).hexdigest()[:40]
    claim, why = _reserve(project_id, signature)
    if claim is None:
        return {'status': 'deferred', 'reason': why}
    try:
        candidate = templategen.generate_template(cve, provider, project=project_id, candidate_only=True)
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='succeeded', finished_at=timezone.now())
        return {'id': candidate.pk, 'status': candidate.status, 'reason': candidate.validation_output[:500],
                'provenance': 'AI-authored draft; static, syntax and benign fixture gates only'}
    except Exception:
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='failed', finished_at=timezone.now())
        return {'status': 'failed', 'reason': 'template generation or validation failed'}
