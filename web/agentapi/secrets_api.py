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
CONTEXT_MISSING = {'kingfisher': 'Context not stored: the Sentinel that read this page did not send the text around the match (it is older than the one that '
                                 'does, or the line could not be cut with the value hidden). Update the Sentinel, then rescan.',
                   'route': 'Context not stored: the scanner that read this route did not send the text around the key (an older Sentinel, or the line could not '
                            'be cut with the value hidden). Update the Sentinel, then rescan.'}
CONTEXT_MISSING_DEFAULT = 'Context not stored, rescan to capture.'
STATUS_ACTIONS = ('public_by_design', 'false_positive', 'accepted')  # the buttons of the detail view, each one a person's decision (set_secret_status)
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
    page = paginate(qs, params, _tagged(_secret, lambda s: s.project) if everywhere else _secret)
    _add_where(page['results'])
    return page


def _add_where(rows):
    """Each listed secret says where it is served now (its newest live occurrence: URL, line, source), one query for the page: the list says where
    to look without opening the secret."""
    from cveFeed.models import SecretOccurrence
    if not rows:
        return
    first = {}
    for o in (SecretOccurrence.objects.filter(finding_id__in=[r['id'] for r in rows], retired_at__isnull=True)
              .order_by('finding_id', '-last_seen', 'id').values('finding_id', 'url', 'line', 'source')):
        first.setdefault(o['finding_id'], {'url': o['url'], 'line': o['line'], 'source': o['source']})
    for r in rows:
        r['where'] = first.get(r['id'])


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


def _explain(row, kind):
    """The secret in plain words, for the detail view: what it is, what anyone who reads it can do, how to fix it, why it is rated as it is."""
    words = catalog.CLASS_EXPLAIN.get(row.klass) or catalog.CLASS_EXPLAIN['I']
    rules = ', '.join(row.rule_ids or []) or row.kind
    title = kind.label[:1].upper() + kind.label[1:]
    return {'title': title, 'what': f'{title}. This is {words["what"]}.',
            'abuse': words['abuse'],
            'how_to_fix': words['fix'],
            'provider_fix': '' if kind.remediation == catalog._ROTATE else kind.remediation,  # the generic text says what 'how_to_fix' already says
            'rating': (f'{row.severity_basis[:1].upper() + row.severity_basis[1:].rstrip(".")}.' if row.severity_basis else ''),
            'catalogue': ((f'The rule ({rules}) is in the secrets catalogue, so it is rated by what it is.' if row.catalogued else
                           f'The rule ({rules}) is not in the secrets catalogue. Until a person reviews it, it is treated as a server secret of medium '
                           'severity: mark it as an intended public key if it is meant to be public, or a false positive if it is not a secret.')),
            'validated': ({'done': True, 'words': f'Validated: the provider answered "{row.validation_outcome.replace("_", " ")}".'} if row.validation_outcome
                          else {'done': False, 'words': 'Not validated: nothing has checked with the provider whether the credential still works.'})}


def _where(o):
    """One occurrence for the detail view: where, how it was found, and the masked text around it, or why there is none."""
    return {'host': o.host, 'url': o.url, 'source': o.source, 'source_label': catalog.SOURCE_WORDS.get(o.source, o.source), 'rule_id': o.rule_id,
            'line': o.line, 'context': o.context or '',
            'context_note': '' if o.context else CONTEXT_MISSING.get(o.source, CONTEXT_MISSING_DEFAULT),
            'first_seen': _iso(o.first_seen), 'last_seen': _iso(o.last_seen), 'retired_at': _iso(o.retired_at), 'finding_id': o.vulnerability_id,
            'scan_id': o.scan_id}


def _can_write(ctx, slug):
    try:
        get_one_project(ctx, slug, write=True)
        return True
    except ApiError:
        return False


def get_secret(ctx, slug, secret_id):
    """One secret with where it was seen (newest first, at most MAX_OCCURRENCES), why it is rated as it is, how to fix it, the findings it came from
    and the resources it points at. Never the value."""
    from cveFeed import secrets_inventory
    project, _, row = _row(ctx, slug, secret_id)
    kind = secrets_inventory.kind_of(row)
    occurrences = [_where(o) for o in row.occurrences.order_by('retired_at', '-last_seen', 'id')[:MAX_OCCURRENCES]]
    return {**_secret(row), 'remediation': kind.remediation, 'docs': kind.docs, 'explain': _explain(row, kind), 'can_write': _can_write(ctx, slug),
            'assignee': _user_brief(row.assignee), 'status_actions': list(STATUS_ACTIONS),
            'status_by': _user_brief(row.status_by), 'status_at': _iso(row.status_at), 'status_note': row.status_note,
            'occurrence_list': occurrences,
            'resources': [{'kind': r.kind, 'identifier': r.identifier, 'host': r.host} for r in row.resources.all()[:50]],
            'validation_available': _validation_state(ctx, project)}


def set_secret_assignee(ctx, slug, secret_id, body):
    """Give a secret to a person: ``assignee`` is the id of a user who can see the project, or null to unassign (the ids ``projects/<slug>/members``
    lists). A write role; audited as ``secrets.assign``."""
    from agentapi.services import _resolve_assignee
    from tenancy import audit
    require_write_token(ctx)
    project, _, row = _row(ctx, slug, secret_id, write=True)
    body = body if isinstance(body, dict) else {}
    if 'assignee' not in body:
        raise ApiError(400, 'send {assignee: <user id>|null}')
    user = _resolve_assignee(project, body['assignee'])
    before = _user_brief(row.assignee)
    row.assignee = user
    row.save(update_fields=['assignee'])
    audit.record(ctx.user, 'secrets.assign', f'secret #{row.pk}', org=project.org_id, project=project.slug, secret_id=row.pk,
                 before=before, after=_user_brief(user), masked=row.masked)
    return {'id': row.pk, 'assignee': _user_brief(user)}


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
