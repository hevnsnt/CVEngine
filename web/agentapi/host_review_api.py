"""The AI review of one host over REST and MCP (docs/AI-REVIEWER.md "Host review", docs/AGENT-API.md).

* ``get_host_review``: anyone who can read the project. The newest review of the host: what the AI concluded for each finding, the next step it chose and
  its state, and why a review failed or a step was held. A host that was never reviewed answers ``status: none`` with whether it can be reviewed now.
* ``request_host_review`` (Review now), ``start_host_review_step`` and ``dismiss_host_review_step``: a write role, the same one a person needs to start
  an assessment or a rescan by hand. A read-only token, the audit role and ``_all`` are refused before anything is read.
* ``host_review_mode`` is a project setting: ``get_project_settings`` and ``set_project_settings`` carry it (agentapi.services).

The review is always fetched through the route's own project and host (the host id is checked against the project first), so another project's host or
review is a 404, exactly like a missing one. ``host_note``, a finding's ``note`` and the step's ``note`` are the model's words, and the model read text
from the scanned host: they are cleaned on the server but a client still treats them as untrusted data and shows them as text, never as markup.
"""
from agentapi.services import ApiError, _int_param, _iso, _user_brief, get_one_project

REAL = ('true_open', 'true_in_progress', 'true_fixed', 'true_accepted_risk')
RUNNING = ('queued', 'answered')
NO_START = ('none', 'ask_person')  # steps with nothing for a person to start: "nothing more" and the notification


def reviewer_settings():
    from cveFeed import reviewer
    return reviewer.settings_row()


def _host_row(ctx, slug, host_id, write=False):
    """``(project, subdomain, host name)`` of an inventory row of this project; a missing field is a 400, a foreign or unknown id a 404."""
    from cveFeed import web_shot
    from startScan.models import Subdomain
    project, _ = get_one_project(ctx, slug, write=write)
    if host_id in (None, ''):
        raise ApiError(400, 'missing field(s): host_id')
    sub = Subdomain.objects.filter(pk=_int_param(host_id, 'host_id'), target_domain__project=project).select_related('target_domain').first()
    if sub is None:
        raise ApiError(404, 'host not found')
    return project, sub, web_shot.host_of(sub)


def _newest(project, host):
    from cveFeed.models import HostReview
    return HostReview.objects.filter(project=project, host=host).select_related('dismissed_by').order_by('-created_at', '-id').first()


def readiness(project, host):
    """Whether "Review now" would be accepted, and if not why: ``{can_request, reason_code, reason}``. The codes are ``unavailable`` (not a host of the
    project, archived, excluded, gone), ``off`` (switched off for the project), ``disabled`` (switched off for the install: the default until a person turns it on in Settings), ``no_provider``, ``paused``, ``daily_limit``,
    ``open`` (a review is already running) and ``nothing_open`` (no open finding to review)."""
    from cveFeed import host_review
    from cveFeed.models import HostReview
    why = host_review.unavailable(project, host)
    if why:
        return {'can_request': False, 'reason_code': 'unavailable', 'reason': why}
    if host_review.mode_of(project) == 'off':
        return {'can_request': False, 'reason_code': 'off', 'reason': 'the AI host review is switched off for this project'}
    ok, why = host_review.available()
    if not ok:
        code = 'no_provider' if 'provider' in why else 'daily_limit' if 'limit' in why else 'paused' if 'paused' in why else 'disabled'
        return {'can_request': False, 'reason_code': code, 'reason': why}
    if HostReview.objects.filter(project=project, host=host, status__in=HostReview.OPEN).exists():
        return {'can_request': False, 'reason_code': 'open', 'reason': 'a review of this host is already running'}
    if not host_review.open_rows(project, host):
        return {'can_request': False, 'reason_code': 'nothing_open', 'reason': 'nothing is open on this host to review'}
    return {'can_request': True, 'reason_code': '', 'reason': ''}


def _link(project, kind, finding_id):
    """The page that opens one finding (the same links Situations uses)."""
    if kind == 'hygiene':
        return f'/cve/{project.slug}/hygiene/#hygiene-{finding_id}'
    return f'/cve/{project.slug}/vulns/#{kind}-{finding_id}'


def _titles(project, triage_ids):
    """``{triage id: (kind, finding id, title)}`` for findings of this project a review named, whether or not they are still open."""
    from cveFeed.models import Triage
    rows = Triage.objects.filter(project=project, pk__in=triage_ids).select_related('match__cve_entry', 'vulnerability', 'route', 'hygiene')
    out = {}
    for t in rows:
        finding = t.finding
        if finding is None:
            continue
        kind = 'match' if t.match_id else 'vulnerability' if t.vulnerability_id else 'route' if t.route_id else 'hygiene'
        title = (finding.cve_entry.cve_id if kind == 'match' else finding.name if kind == 'vulnerability'
                 else finding.url if kind == 'route' else finding.title)
        out[t.pk] = (kind, finding.pk, str(title or '')[:200], finding.remediation_status)
    return out


def _findings(review, project):
    """The verdicts of one review, one per finding in the order the model saw them, each naming the finding by kind and id."""
    from cveFeed.models import FindingReview
    pairs = sorted((review.refs or {}).items(), key=lambda kv: int(kv[0][1:]))
    found = _titles(project, [int(v) for _, v in pairs])
    verdicts = {}
    for row in FindingReview.objects.filter(host_review=review, project=project).order_by('id'):
        verdicts[row.triage_id] = row  # the newest row of a finding wins
    out = []
    for _ref, pk in pairs:
        row = verdicts.get(int(pk))
        if row is None or int(pk) not in found:
            continue
        kind, finding_id, title, status = found[int(pk)]
        out.append({'finding': {'type': kind, 'id': finding_id}, 'link': _link(project, kind, finding_id), 'title': title, 'verdict': row.verdict,
                    'summary': 'real' if row.verdict in REAL else 'false_positive' if row.verdict == 'false_positive' else 'uncertain',
                    'confidence': row.confidence, 'reason_code': row.reason_code, 'note': row.note, 'outcome': row.outcome, 'held_reason': row.held_reason,
                    # a false positive the AI would have closed but the host review may not close by itself: a person with write permission closes it in one click
                    'can_close': kind != 'route' and status == 'open' and row.held_reason.startswith('the host review does not close')})
    return out


def _step(review, project):
    """The step the AI chose, or None. ``state`` is proposed (waiting for a person), started, done, refused, dismissed or expired; ``mode`` is ``auto``
    (started by the server) or ``recommend`` (a person decides); ``detail`` says what was started, or why it was not or was refused."""
    from cveFeed import host_actions
    if not review.step_action:
        return None
    spec = host_actions.ACTIONS.get(review.step_action)
    target = None
    ref = (review.refs or {}).get(review.step_target) if review.step_target else None
    if ref:
        found = _titles(project, [int(ref)]).get(int(ref))
        if found:
            target = {'type': found[0], 'id': found[1], 'title': found[2], 'link': _link(project, found[0], found[1])}
    proposed = review.status == 'applied' and review.step_state == 'proposed'
    sent = review.status == 'applied' and review.step_action == 'ask_person' and review.step_state == 'done'
    return {'action': review.step_action, 'description': spec[3] if spec else '', 'what_it_touches': spec[1] if spec else '', 'target': target,
            'reason_code': review.step_reason_code, 'note': review.step_note, 'mode': review.step_mode, 'state': review.step_state,
            'detail': review.step_detail, 'needs_person': review.step_action == 'ask_person' and review.step_state in ('proposed', 'done'),
            'can_start': proposed and review.step_action not in NO_START, 'can_dismiss': proposed or sent,
            'dismissed_by': _user_brief(review.dismissed_by) if review.step_state == 'dismissed' else None,
            'dismissed_at': _iso(review.dismissed_at) if review.step_state == 'dismissed' else None}


def describe(review, project):
    """One review as the API shows it."""
    from cveFeed import host_review
    findings = _findings(review, project) if review.status == 'applied' else []
    counts = {'real': 0, 'false_positive': 0, 'uncertain': 0, 'closed': 0, 'held': 0}
    for f in findings:
        counts[f['summary']] += 1
        counts['closed'] += f['outcome'] == 'closed'
        counts['held'] += f['outcome'] in ('held', 'disputed')
    return {'id': review.pk, 'status': review.status, 'running': review.status in RUNNING, 'created': _iso(review.created_at), 'decided': _iso(review.decided_at),
            'model': review.model, 'failure': (review.step_detail or None) if review.status in ('failed', 'stale') else None,
            'host_note': review.host_note if review.status == 'applied' else '', 'held_for_instructions': bool(host_review.hard_flags(review.injection)),
            'claims_about_findings': 'verdict_claim' in (review.injection or []),
            'injection': list(review.injection or []), 'counts': counts, 'findings': findings,
            'step': _step(review, project) if review.status == 'applied' else None}


def get_host_review(ctx, slug, host_id):
    """The newest AI review of one host with its verdicts and next step; ``review`` is null while the host has never been reviewed. ``mode`` is the
    project's host review mode, ``readiness`` whether "Review now" would be accepted and, if not, why."""
    from cveFeed import host_review
    project, sub, host = _host_row(ctx, slug, host_id)
    row = _newest(project, host)
    return {'host_id': sub.pk, 'host': host, 'mode': host_review.mode_of(project), 'readiness': readiness(project, host),
            'auto_close': reviewer_settings().host_review_auto_close,
            'status': row.status if row else 'none', 'review': describe(row, project) if row else None}


def request_host_review(ctx, slug, host_id):
    """Review now: queue the AI review of one host at a person's priority. 409 while one is open, when nothing is open on the host or when the project's
    mode is off, 429 at the daily limit, 503 with no AI provider or while scanning is paused, 404 for a host that cannot be reviewed (archived,
    excluded, gone)."""
    from cveFeed import host_review
    project, _sub, host = _host_row(ctx, slug, host_id, write=True)
    try:
        host_review.request(project, host, priority=2)
    except host_review.HostReviewRefused as exc:
        raise ApiError(exc.status, str(exc)) from exc
    return {**get_host_review(ctx, slug, host_id), 'created': True}


def _newest_for_write(ctx, slug, host_id):
    project, _sub, host = _host_row(ctx, slug, host_id, write=True)
    row = _newest(project, host)
    if row is None:
        raise ApiError(404, 'this host has no review')
    return project, row


def start_host_review_step(ctx, slug, host_id):
    """Start the step the AI proposed, as the caller: the same gates as starting that action by hand. 409 when nothing is proposed any more, or when the
    step is no longer offered (the answer says why and the step is stored as refused)."""
    from cveFeed import host_review
    project, row = _newest_for_write(ctx, slug, host_id)
    try:
        result = host_review.start_step(row, ctx.user, agent=ctx.token is not None)  # an API key or an agent: the user is kept for the record, the gates are the unattended ones
    except host_review.HostReviewRefused as exc:
        raise ApiError(exc.status, str(exc)) from exc
    row.refresh_from_db()
    shown = describe(row, project)
    if result['state'] == 'refused':
        raise ApiError(409, result['detail'] or 'the step is no longer offered', review=shown)
    return {'result': {'state': result['state'], 'detail': result['detail']}, 'review': shown}


def dismiss_host_review_step(ctx, slug, host_id, reason=''):
    """Dismiss the proposed step (or the "ask a person" flag): it is not proposed again for this state of the host. ``reason`` is optional text."""
    from cveFeed import host_review
    project, row = _newest_for_write(ctx, slug, host_id)
    if reason is not None and not isinstance(reason, str):
        raise ApiError(400, 'reason must be text')
    try:
        row = host_review.dismiss_step(row, ctx.user, reason or '')
    except host_review.HostReviewRefused as exc:
        raise ApiError(exc.status, str(exc)) from exc
    return {'review': describe(row, project)}
