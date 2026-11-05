"""The secrets inventory over the API and MCP (docs/SECRETS-PLAN.md section 11). No answer ever holds a secret's value: only its mask
(``AIza…x7Qz``), its kind and where it was seen.

* ``list_secrets`` and ``get_secret``: anyone who can read the project (``_all`` lists every project the caller may see).
* ``set_secret_status``: a write role (Member and up), audited as ``secrets.status``.
* ``secrets_settings`` and ``set_secrets_settings``: the project's validation switch (cveFeed.secrets_validation): an Org Admin or App Admin only,
  with the attestation.
* ``request_validation``: queues a validating secrets scan of the hosts that serve the secret, by the built-in scanner; Org Admin or App Admin,
  opt-in projects only, never a bug bounty project. Audited.
* ``secret_rules`` and ``set_secret_rules``: the instance's custom rules and skip lists (cveFeed.secret_rules), App Admins only.
"""
from django.db.models import Q

from agentapi.services import (ApiError, SEVERITY_NAMES, _is_all, _iso, _scoped, _tagged, _user_brief, get_one_project, get_project, paginate,
                               require_write_token)
from cveFeed import secrets_catalog as catalog

MAX_OCCURRENCES = 200
FILTER_STATUSES = ('open', 'quiet', 'all') + catalog.STATUSES


def _secret(row):
    from cveFeed import secrets_inventory
    kind = secrets_inventory.kind_of(row)
    return {'id': row.pk, 'provider': row.provider, 'kind': row.kind, 'label': kind.label, 'class': row.klass,
            'class_label': catalog.CLASS_WORDS.get(row.klass, ''), 'catalogued': row.catalogued, 'masked': row.masked, 'length': row.length,
            'severity': SEVERITY_NAMES.get(row.severity, 'unknown'), 'severity_basis': row.severity_basis, 'status': row.status,
            'counts': catalog.counts(row.status), 'confidence': row.confidence, 'rule_ids': list(row.rule_ids or []),
            'hosts': row.host_count, 'occurrences': row.occurrence_count, 'first_seen': _iso(row.first_seen), 'last_seen': _iso(row.last_seen),
            'validation': {'outcome': row.validation_outcome or None, 'at': _iso(row.validated_at), 'meta': row.validation_meta or {}},
            'remediation_status': row.remediation_status, 'facts': row.facts or {}}


def _filtered(qs, params):
    status = params.get('status') or 'open'
    if status not in FILTER_STATUSES:
        raise ApiError(400, f'status must be one of {", ".join(FILTER_STATUSES)}')
    if status == 'open':
        qs = qs.exclude(status__in=catalog.QUIET_STATUSES)
    elif status == 'quiet':
        qs = qs.filter(status__in=catalog.QUIET_STATUSES)
    elif status != 'all':
        qs = qs.filter(status=status)
    klass = (params.get('class') or '').upper()
    if klass:
        if klass not in catalog.CLASSES:
            raise ApiError(400, 'class must be P (browser key), S (server secret) or I (identifier)')
        qs = qs.filter(klass=klass)
    if params.get('provider'):
        qs = qs.filter(provider__iexact=params['provider'])
    inverse = {v: k for k, v in SEVERITY_NAMES.items()}
    if params.get('severity'):
        if params['severity'] not in inverse:
            raise ApiError(400, f'severity must be one of {", ".join(v for v in SEVERITY_NAMES.values() if v != "unknown")}')
        qs = qs.filter(severity=inverse[params['severity']])
    if params.get('host'):
        qs = qs.filter(occurrences__host=params['host'].strip().lower(), occurrences__retired_at__isnull=True).distinct()
    if params.get('q'):
        q = params['q'].strip()
        qs = qs.filter(Q(provider__icontains=q) | Q(kind__icontains=q) | Q(masked__icontains=q) | Q(occurrences__host__icontains=q)
                       | Q(occurrences__url__icontains=q)).distinct()
    return qs


def list_secrets(ctx, slug, params):
    """The project's exposed secrets, worst first. ``status``: open (default: every status that counts), quiet (public by design, accepted,
    false positive, revoked), all, or one status; ``class``: P, S or I; ``provider``; ``severity``; ``host``; ``q``. Paged."""
    from cveFeed.models import SecretFinding
    project, _ = get_project(ctx, slug)
    everywhere = _is_all(project)
    qs = _scoped(SecretFinding.objects.all(), project, 'project')
    if everywhere:
        qs = qs.select_related('project')
    qs = _filtered(qs, params).order_by('-severity', '-last_seen', 'id')
    return paginate(qs, params, _tagged(_secret, lambda s: s.project) if everywhere else _secret)


def _row(ctx, slug, secret_id, write=False):
    from cveFeed.models import SecretFinding
    project, role = get_one_project(ctx, slug, write=write)
    try:
        secret_id = int(secret_id)
    except (TypeError, ValueError):
        raise ApiError(400, 'id must be an integer')
    row = SecretFinding.objects.filter(project=project, pk=secret_id).first()
    if row is None:
        raise ApiError(404, 'secret not found')
    return project, role, row


def get_secret(ctx, slug, secret_id):
    """One secret with where it was seen (newest first, at most MAX_OCCURRENCES), why it is rated as it is, how to fix it, the findings it came from
    and the resources it points at. Never the value."""
    from cveFeed import secrets_inventory
    project, _, row = _row(ctx, slug, secret_id)
    kind = secrets_inventory.kind_of(row)
    occurrences = [{'host': o.host, 'url': o.url, 'source': o.source, 'rule_id': o.rule_id, 'line': o.line, 'first_seen': _iso(o.first_seen),
                    'last_seen': _iso(o.last_seen), 'retired_at': _iso(o.retired_at), 'finding_id': o.vulnerability_id, 'scan_id': o.scan_id}
                   for o in row.occurrences.order_by('retired_at', '-last_seen', 'id')[:MAX_OCCURRENCES]]
    return {**_secret(row), 'remediation': kind.remediation, 'docs': kind.docs,
            'status_by': _user_brief(row.status_by), 'status_at': _iso(row.status_at), 'status_note': row.status_note,
            'occurrence_list': occurrences,
            'resources': [{'kind': r.kind, 'identifier': r.identifier, 'host': r.host} for r in row.resources.all()[:50]],
            'validation_available': _validation_state(ctx, project)}


def set_secret_status(ctx, slug, secret_id, body):
    """A person's decision: ``status`` one of unverified, public_by_design, accepted, revoked, false_positive, with an optional ``note``. A quiet
    status takes the secret out of its hosts' scores; ``revoked`` closes it once it is no longer seen."""
    from cveFeed import secrets_inventory
    from tenancy import audit
    require_write_token(ctx)
    project, _, row = _row(ctx, slug, secret_id, write=True)
    body = body if isinstance(body, dict) else {}
    before = row.status
    try:
        secrets_inventory.set_status(row, body.get('status'), user=ctx.user, note=body.get('note') or '')
    except secrets_inventory.StatusError as exc:
        raise ApiError(400, str(exc))
    audit.record(ctx.user, 'secrets.status', f'secret #{row.pk}', org=project.org_id, project=project.slug, secret_id=row.pk,
                 before=before, after=row.status, masked=row.masked)
    return _secret(row)


# ----------------------------------------------------------------------------- validation

def _validation_state(ctx, project):
    from cveFeed import secrets_validation
    row = secrets_validation.settings_row(project.pk)
    return {'enabled': bool(row and row.secrets_validation), 'blocked_reason': secrets_validation.blocked_reason(project.pk),
            'bounty_project': secrets_validation.bounty_project(project.pk), 'can_switch': secrets_validation.can_switch(ctx.user, project),
            'by': _user_brief(row.secrets_validation_by) if row else None, 'at': _iso(row.secrets_validation_at) if row else None,
            'attestation': secrets_validation.ATTESTATION, 'rules': sorted(secrets_validation.allowlist()['rules'])}


def secrets_settings(ctx, slug):
    project, _ = get_one_project(ctx, slug)
    return {'validation': _validation_state(ctx, project)}


def set_secrets_settings(ctx, slug, body):
    """``{validation: {enabled: true, attestation: "<the text, word for word>"}}`` or ``{validation: {enabled: false}}``; Org Admin or App Admin."""
    from cveFeed import secrets_validation
    require_write_token(ctx)
    project, _ = get_one_project(ctx, slug, write=True)
    wanted = (body or {}).get('validation') if isinstance(body, dict) else None
    if not isinstance(wanted, dict) or not isinstance(wanted.get('enabled'), bool):
        raise ApiError(400, 'send {validation: {enabled: true|false, attestation}}')
    try:
        secrets_validation.switch(project, ctx.user, wanted['enabled'], wanted.get('attestation') or '')
    except secrets_validation.SwitchError as exc:
        raise ApiError(403 if 'only an' in str(exc) else 400, str(exc))
    return secrets_settings(ctx, slug)


def request_validation(ctx, slug, secret_id):
    """Queue a validating secrets scan of the hosts that serve this secret now (the built-in scanner reads them again and checks what it finds with
    the allow-listed validators). Org Admin or App Admin, for a project that opted in; refused for a bug bounty project, for a secret whose rules
    have no allow-listed validator, and while no built-in scanner takes the kind."""
    from agentapi import sentinel_broker
    from cveFeed import secrets_validation
    from cveFeed.tasks import secrets_validate_hosts
    require_write_token(ctx)
    project, _, row = _row(ctx, slug, secret_id, write=True)
    if not secrets_validation.can_switch(ctx.user, project):
        raise ApiError(403, 'only an Org Admin of this organization or an App Admin can ask for a validation')
    reason = secrets_validation.blocked_reason(project.pk)
    if reason:
        raise ApiError(409, reason)
    allowed = set(secrets_validation.allowlist()['rules'])
    if not any(r in allowed or r == 'betterleaks.aws-secret-access-key' for r in row.rule_ids or ()):
        raise ApiError(409, 'no rule that found this secret has a reviewed read-only validator')
    if not sentinel_broker.any_scanner_for(project, 'secrets_scan', builtin_only=True):
        raise ApiError(409, 'the built-in scanner is not running the secrets scan: validation happens there only')
    hosts = sorted(set(row.occurrences.filter(retired_at__isnull=True).values_list('host', flat=True)))[:25]
    if not hosts:
        raise ApiError(409, 'the secret is not served anywhere now')
    secrets_validate_hosts.apply_async(args=[project.pk, hosts, ctx.user.pk])
    return {'queued': True, 'hosts': hosts, 'secret_id': row.pk}


# ----------------------------------------------------------------------------- custom rules (App Admin)

def _app_admin(ctx):
    if not ctx.user.is_superuser:
        raise ApiError(403, 'App Admins only')


def secret_rules(ctx):
    from cveFeed import secret_rules as rules
    _app_admin(ctx)
    return rules.describe()


def set_secret_rules(ctx, body):
    """``{rules_yaml, skip_words, skip_regex}``, each optional (what is left out stays). Rules are checked against the allowed subset (no validator)."""
    from cveFeed import secret_rules as rules
    require_write_token(ctx)
    _app_admin(ctx)
    body = body if isinstance(body, dict) else {}
    try:
        return rules.save(ctx.user, body.get('rules_yaml'), body.get('skip_words'), body.get('skip_regex'))
    except rules.RulesError as exc:
        raise ApiError(400, str(exc))


def rules_bundle_response(ctx, if_none_match=None):
    """``GET sentinel/secret-rules/bundle``: the custom rules as YAML, for a Sentinel's own token only; 404 when there are none, 304 when
    ``If-None-Match`` names the current sha256."""
    from django.http import HttpResponse, HttpResponseNotModified

    from agentapi import sentinel_broker
    from agentapi.template_bundle import matches
    from cveFeed import secret_rules as rules
    if ctx.token is None or ctx.token.scope != sentinel_broker.SCOPE_SENTINEL:
        raise ApiError(403, 'the secret rules are for a Sentinel token only')
    sentinel_broker._sentinel_agent(ctx, write=False)
    data, sha = rules.bundle()
    if data is None:
        raise ApiError(404, 'there are no custom secret rules')
    answer = HttpResponseNotModified() if matches(if_none_match, sha) else HttpResponse(data, content_type='application/yaml')
    answer['ETag'] = f'"{sha}"'
    answer['Cache-Control'] = 'private, no-cache'
    return answer
