"""The routes of the AI reviewer container (``/api/v1/reviewer/*``, docs/AI-REVIEWER.md). Only a token of scope ``reviewer`` may call them:
the middleware keeps that token on these paths (``agentapi.auth.REVIEWER_PATH``), and every route here refuses any other token and any
signed-in session, so a person's full token or browser can never read the provider key the configuration carries. All decisions are made in
``cveFeed.reviewer``; these only parse and answer."""
from agentapi.services import ApiError

MAX_BODY_ITEMS = 50


def _require_reviewer(ctx):
    token = ctx.token
    if token is None or token.scope != 'reviewer':
        raise ApiError(403, 'only the AI reviewer container may call this')
    if not (ctx.user.is_active and ctx.user.is_superuser):
        raise ApiError(403, 'the reviewer token belongs to a user who is no longer an App Admin')


def config(request, ctx):
    from cveFeed import reviewer
    _require_reviewer(ctx)
    return reviewer.config()


def next_findings(request, ctx):
    from cveFeed import reviewer
    _require_reviewer(ctx)
    try:
        limit = int(request.GET.get('limit') or reviewer.PACKET_LIMIT)
    except ValueError:
        raise ApiError(400, 'limit must be a whole number')
    return {'packets': reviewer.next_packets(limit)}


def verdict(request, ctx, ref, body):
    from cveFeed import reviewer
    _require_reviewer(ctx)
    if not reviewer.enabled():
        raise ApiError(409, 'the reviewer is turned off')
    try:
        return reviewer.apply_verdict(ref, body)
    except reviewer.VerdictError as exc:
        raise ApiError(exc.status, str(exc))


def ops_snapshot(request, ctx):
    from cveFeed import reviewer
    _require_reviewer(ctx)
    release = None
    tag, published = request.GET.get('templates_release', ''), request.GET.get('templates_published_at', '')
    if tag:
        release = {'tag': tag[:40], 'published_at': published[:40]}
    return reviewer.snapshot(templates_release=release)


def ops_report(request, ctx, body):
    from cveFeed import reviewer
    _require_reviewer(ctx)
    if not reviewer.enabled():
        raise ApiError(409, 'the reviewer is turned off')
    try:
        return reviewer.apply_ops_report(body)
    except reviewer.VerdictError as exc:
        raise ApiError(exc.status, str(exc))
