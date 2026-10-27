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

SYSTEM = ("You investigate whether a CVE really applies to one product on one host. First read host_metadata: every technology with "
          "its version and where it was seen, the ports with product, version, extra info and banners, the front page headers, any CDN, "
          "WAF or hosting edge, certificates, the operating system guess, earlier probe and check results and the host's other CVE "
          "matches. Then say which missing fact decides the question: the product's version, which look-alike product it is (nginx, "
          "ingress-nginx and nginx-ui are different software), whether an edge hides the origin, or local state that no network check "
          "can read. Choose only checks that can establish that fact. Kind fact_probe is a catalogue of read-only version and identity "
          "probes the application runs itself; prefer it whenever a version or identity is missing. A check being safe and available "
          "does not make it relevant. Generic HTTP banners and nmap service versions cannot verify local kernel, driver, NIC, KVM or "
          "hardware prerequisites: say they need the host inventory reporter. Behind a CDN or WAF the Server header, X-Powered-By and "
          "error pages describe the edge, so origin software and versions cannot be known from here; a tag such as cloudflare names "
          "the edge, not an application: say so instead of assuming. If none can establish a relevant fact, return an empty "
          "check_kinds list and explain the missing evidence. "
          "Reply with one JSON object only: "
          '{"check_kinds":["nuclei_template"],"generate_template":false,"reason":"..."}. '
          "check_kinds may contain only listed kinds. Choose generate_template only if no safe installed CVE "
          "template exists and a specific non-destructive detector can plausibly be written from the CVE facts. "
          "Never propose commands, URLs, hosts, credentials, or an exploit payload. An empty plan is allowed "
          "when evidence is insufficient. A version or a generic server banner alone does not prove vulnerability, and a banner "
          "that states no version proves nothing either way.")
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


def daily_limits():
    """(all projects, one project) planning requests a day, from the AI settings; 0 stops AI planning."""
    from dashboard.models import AIProviderSettings
    cfg = AIProviderSettings.objects.first()
    return (cfg.plan_daily_total, cfg.plan_daily_per_project) if cfg else (200, 20)


def _reserve(project_id, signature):
    """One in-flight plan per signature; billable attempts per day are capped per project and in total (Settings > AI model)."""
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
        total, per_project = daily_limits()
        if today.count() >= total or today.filter(project_id=project_id).count() >= per_project:
            return None, 'AI planning daily budget reached (raise it in Settings > AI model)'
        return TriageCall.objects.create(kind='validation_plan', project_id=project_id, signature=signature,
                                         expires_at=now + timedelta(minutes=5)), ''


def plan(project_id, row, cve, subject, checks, template, provider=None, observations=None, host=None):
    """Return (decision, provider). Failure cannot authorize generic checks by default. ``host`` is the host's metadata
    (cveFeed.host_context.host_context), given to the model as untrusted data. Version and identity probes need no relevance decision:
    they are the way to learn the missing fact, so they are always part of the plan when the planner offers them."""
    can_generate = not template[0]
    probe_kinds = ['fact_probe'] if any(c['kind'] == 'fact_probe' for c in checks) else []
    # An exact CVE template is relevant by construction; generic banners are not. A probe finds the fact itself.
    fallback = {'check_kinds': (['nuclei_template'] if any(c['kind'] == 'nuclei_template' for c in checks) else []) + probe_kinds,
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
        return {**fallback, 'reason': 'No AI provider is configured; version and identity probes and a vetted CVE template run, other generic '
                                      'checks have no CVE-specific relevance decision.'}, None
    observation_digest = hashlib.sha256(json.dumps(observations or [], sort_keys=True, default=str).encode()).hexdigest()[:12]
    signature = hashlib.sha256(f'validation-plan-v2:{project_id}:{row.signature}:{observation_digest}'.encode()).hexdigest()[:40]
    claim, why = _reserve(project_id, signature)
    if claim is None:
        return {**fallback, 'reason': why + '; generic external checks deferred.'}, provider
    try:
        from cveFeed import detection
        context = {'cve': {**templategen.cve_info_for(cve), 'guidance': detection.prompt_guidance(cve)},
                   'asset_evidence': {k: subject.get(k) for k in ('source', 'product', 'matched_version', 'range', 'port')},
                   'approved_checks': [{'kind': c['kind'], 'label': c['label']} for c in checks],
                   'host_metadata': host,
                   'completed_observations': (observations or [])[:6],
                   'safe_template': bool(template[0]), 'template_unavailable_reason': template[1] if not template[0] else ''}
        # templategen's prompt cleaner treats CVE feed text as hostile input. The hostname and IP are excluded.
        safe = templategen._clean_value(context, 500)
        from reNgine.ai_providers import usage_stage
        with usage_stage('validation_plan'):
            decision = parse_plan(provider.complete(SYSTEM, untrusted_block('VALIDATION_CONTEXT', safe)), checks, can_generate)
        if decision and probe_kinds and 'fact_probe' not in decision['check_kinds']:
            decision['check_kinds'].append('fact_probe')  # an empty or narrow plan never ends a request while a probe can still find the fact
            decision['reason'] = clean_text(decision['reason'] + ' (Version and identity probes still run to establish the missing fact.)', MAX_REASON)
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
        try:
            candidate = templategen.generate_template(cve, provider, project=project_id, candidate_only=True)
        except templategen.TemplateBudgetExceeded as exc:  # no AI call was made, so the planning budget is not charged
            TriageCall.objects.filter(pk=claim.pk).delete()
            return {'status': 'deferred', 'reason': str(exc)}
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='succeeded', finished_at=timezone.now())
        return {'id': candidate.pk, 'status': candidate.status, 'reason': candidate.validation_output[:500],
                'provenance': 'AI-authored draft; static, syntax and benign fixture gates only'}
    except Exception:
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='failed', finished_at=timezone.now())
        return {'status': 'failed', 'reason': 'template generation or validation failed'}
