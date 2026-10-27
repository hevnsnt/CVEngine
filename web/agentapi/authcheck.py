"""Authenticated checks for agents and the web UI (REST for all of it, MCP only to list and remove: a secret never passes through the model's context): the headers and cookie an owner supplies for a target they may test
(see cveFeed.auth_checks). App Admins and the project's Org Admin only; every other role, including a project member, gets 403, because
a stored sign-in lets the scanners act as a person inside the application. Values are write-only: nothing here returns one, only the
header and cookie NAMES, and the audit log records names too. Every credential has an explicit scope (one host or all hosts of the target)
and an explicit expiry (30, 90 or 120 days, or never).
"""
from agentapi.services import ApiError, get_one_project
from cveFeed import auth_checks
from tenancy import roles

MAX_PER_TARGET = 25


def _admin(ctx, slug, write=False):
    project, _role = get_one_project(ctx, slug, write=write)
    if not (ctx.user.is_superuser or (project.org_id and roles.can_manage_org(ctx.user, project.org_id))):
        raise ApiError(403, 'only an App Admin or the project\'s organization admin can manage stored sign-ins')
    return project


def _target(project, target_id):
    from targetApp.models import Domain
    try:
        number = int(target_id)
    except (TypeError, ValueError):
        raise ApiError(400, 'target_id must be an integer')
    domain = Domain.objects.filter(pk=number, project=project).first()
    if domain is None:
        raise ApiError(404, 'target not found')
    return domain


def list_credentials(ctx, slug, params=None):
    """The stored sign-ins of a project, masked: label, target, host (null with scope ``target``: every host of the target), origins, header and cookie names,
    expiry (with the days left) and state (active or expired). Never a value. ``target_id`` narrows to one target."""
    from cveFeed.models import AuthCredential
    project = _admin(ctx, slug)
    rows = AuthCredential.objects.filter(project=project).select_related('domain', 'updated_by').order_by('domain__name', 'host', 'id')
    if (params or {}).get('target_id'):
        rows = rows.filter(domain=_target(project, params['target_id']))
    return {'results': [auth_checks.summary(c) for c in rows], 'warning': auth_checks.WARNING, 'max_per_target': MAX_PER_TARGET}


def set_credential(ctx, slug, target_id, body):
    """Create or replace the sign-in of a target (or of one host of it). ``label`` is required. ``scope`` is required: ``"host"`` with ``host``
    (one host of the target) or ``"target"`` (every host of the target, chosen deliberately; ``host`` blank). ``expires`` is required: 30, 90
    or 120 (days from now) or ``"never"``. ``headers`` is a list of ``{name, secret}`` (``secret`` is the header value; blank for a name
    already stored keeps it, and names left out are removed), ``cookie_secret`` a ``name=value; ...`` string (blank keeps the stored one,
    ``clear_cookie: true`` removes it) and ``origins`` the ``scheme:port`` list it may go to (default ``["https:443"]``). REST and the web
    page only: a secret never passes through an MCP tool."""
    from cveFeed.admin_api import audit
    from cveFeed.models import AuthCredential
    project = _admin(ctx, slug, write=True)
    domain = _target(project, target_id)
    body = body if isinstance(body, dict) else {}
    try:
        host = auth_checks.clean_scope(body.get('scope'), body.get('host'), domain)
        existing = AuthCredential.objects.filter(domain=domain, host=host).first()
        stored = auth_checks.stored_headers(existing) if existing else []
        headers = auth_checks.clean_headers(body.get('headers'), stored)
        headers = [list(pair) for pair in stored] if headers is None else headers
        cookie = auth_checks.clean_cookie(body.get('cookie_secret')) or ''
        if not cookie and not body.get('clear_cookie') is True:
            cookie = auth_checks.stored_cookie(existing) if existing else ''
        if not headers and not cookie:
            raise auth_checks.CredentialError('give at least one header or a cookie')
        label = str(body.get('label') or (existing.label if existing else '')).strip()
        if not label or len(label) > auth_checks.MAX_LABEL:
            raise auth_checks.CredentialError(f'give it a label of up to {auth_checks.MAX_LABEL} characters (for example "staging test account")')
        origins = auth_checks.clean_origins(body['origins']) if 'origins' in body else (list(existing.origins) if existing else list(auth_checks.DEFAULT_ORIGINS))
        expires = auth_checks.compute_expiry(body.get('expires'))
    except auth_checks.CredentialError as exc:
        raise ApiError(400, str(exc))
    if existing is None and AuthCredential.objects.filter(domain=domain).count() >= MAX_PER_TARGET:
        raise ApiError(400, f'a target holds at most {MAX_PER_TARGET} stored sign-ins')
    cred = existing or AuthCredential(project=project, domain=domain, host=host)
    cred.label, cred.origins, cred.expires_at, cred.updated_by = label, origins, expires, ctx.user
    cred.secret = {'headers': headers, 'cookie': cookie}
    cred.save()
    audit(ctx.user, 'target.auth_credential.set', f'{project.slug}:{domain.name}:{host or "*"}', org=project.org_id, label=label,
          headers=[name for name, _ in headers], cookie=bool(cookie), origins=origins, scope='host' if host else 'target', expires=str(body.get('expires')).strip().lower(),
          expires_at=expires.isoformat() if expires else None,
          created=existing is None)
    return auth_checks.summary(cred)


def delete_credential(ctx, slug, credential_id):
    """Remove one stored sign-in. The audit log keeps its label, host and the names it held."""
    from cveFeed.admin_api import audit
    from cveFeed.models import AuthCredential
    project = _admin(ctx, slug, write=True)
    try:
        cred = AuthCredential.objects.filter(pk=int(credential_id), project=project).select_related('domain').first()
    except (TypeError, ValueError):
        raise ApiError(400, 'credential id must be an integer')
    if cred is None:
        raise ApiError(404, 'stored sign-in not found')
    names, label, where = auth_checks.header_names(cred), cred.label, f'{project.slug}:{cred.domain.name}:{cred.host or "*"}'
    cred.delete()
    audit(ctx.user, 'target.auth_credential.remove', where, org=project.org_id, label=label, headers=names)
    return {'deleted': True}
