"""AI-written scan templates (``GeneratedTemplate``) over REST and MCP: list, read, review, retire and revise (``cveFeed.template_review``).

Tenancy. A template is per CVE and global, like a CVE's detection record: its text, status and validation record are shown to every member
of any organization or project. What it found is not: the CVE matches it recorded are counted and listed only for hosts in projects the caller
may see, and ``test_results`` (``[{host, vulnerable, output}]``, which carries no project and so cannot be cut down reliably by host name, as
two tenants may hold the same name) only to an App Admin. A review's outcome (match ids across tenants) is likewise for an App Admin only.

Changes are for an App Admin only, because a template runs against every tenant's hosts: a verdict (keep, retire) and a revision.
"""
from django.db.models import Count, Q

from agentapi import services as svc
from agentapi.services import ApiError, _int_param, _iso

STATUSES = ('draft', 'valid', 'invalid', 'expired')
EVIDENCE = {'version': 'version', 'behavior': 'behavior', 'behaviour': 'behavior'}
VERDICTS = ('keep', 'retire')
MAX_EVIDENCE_SCAN = 5000  # rows read to filter by evidence class (it is worked out from the text, not stored)
MAX_MATCHES = 200  # matches listed on one template


def _admin(ctx):
    return bool(getattr(ctx.user, 'is_superuser', False))


def _require_admin(ctx, what):
    if not _admin(ctx):
        raise ApiError(403, f'only an App Admin can {what}: an AI-written template runs against every organization\'s hosts')
    svc.require_write_token(ctx)


def _scoped_matches(ctx, qs):
    """``qs`` (CVE matches) cut down to the hosts of the projects the caller may see; an App Admin sees every project."""
    if _admin(ctx):
        return qs
    return qs.filter(subdomain__target_domain__project_id__in=list(svc._allowed_ids(ctx.user)))


def _get(generated_id):
    from cveFeed.models import GeneratedTemplate
    pk = _int_param(generated_id, 'id')
    row = GeneratedTemplate.objects.filter(pk=pk).select_related('cve_entry', 'revised_by').first()
    if row is None:
        raise ApiError(404, 'generated template not found')
    return row


def _match_counts(ctx, rows):
    """{(cve pk, template id): {vulnerable, version_only, no_match, error}} of the caller's matches each installed row recorded."""
    from cveFeed import template_review
    from cveFeed.models import CVEMatch
    pairs = {(r.cve_entry_id, r.template_id) for r in rows if r.path and r.template_id}
    out = {pair: dict.fromkeys(template_review.RESULTS, 0) for pair in pairs}
    if not pairs:
        return out
    wanted = Q()
    for cve_pk, template_id in pairs:
        wanted |= Q(cve_entry_id=cve_pk, template_id=template_id)
    for row in (_scoped_matches(ctx, CVEMatch.objects.filter(wanted)).values('cve_entry_id', 'template_id', 'template_result')
                .annotate(n=Count('id'))):
        bucket = out.get((row['cve_entry_id'], row['template_id']))
        if bucket is not None and row['template_result'] in bucket:
            bucket[row['template_result']] = row['n']
    return out


def _superseded_by(rows):
    from cveFeed.models import GeneratedTemplate
    out = {}
    for rev in GeneratedTemplate.objects.filter(supersedes_id__in=[r.pk for r in rows]).order_by('id').only('id', 'template_id', 'status', 'supersedes_id'):
        out[rev.supersedes_id] = {'id': rev.pk, 'template_id': rev.template_id, 'status': rev.status}  # the newest wins
    return out


def _row(tmpl, counts, superseded_by, evidence=None):
    from cveFeed import template_review
    return {
        'id': tmpl.pk, 'cve_id': tmpl.cve_entry.cve_id, 'template_id': tmpl.template_id, 'status': tmpl.status,
        'validation_stage': tmpl.validation_stage, 'validation_reason': tmpl.validation_reason, 'created_at': _iso(tmpl.created_at),
        'validated_at': _iso(tmpl.validated_at), 'ai_model': tmpl.ai_model,
        'author': 'revision' if tmpl.supersedes_id else 'ai',
        'revised_by': tmpl.revised_by.username if tmpl.revised_by_id and tmpl.revised_by else None,
        'evidence': evidence if evidence is not None else template_review.evidence_of(tmpl),
        'installed': bool(tmpl.path),
        'matches': counts.get((tmpl.cve_entry_id, tmpl.template_id), dict.fromkeys(template_review.RESULTS, 0)),
        'supersedes': tmpl.supersedes_id, 'superseded_by': superseded_by.get(tmpl.pk),
    }


def list_generated_templates(ctx, params):
    """One page of AI-written templates, newest first. Filters: ``cve_id``, ``status`` (draft, valid, invalid, expired), ``evidence``
    (version or behaviour/behavior: the static class, worked out from the text)."""
    from cveFeed import templategen
    from cveFeed.models import GeneratedTemplate
    svc._require_member(ctx)
    qs = GeneratedTemplate.objects.select_related('cve_entry', 'revised_by').order_by('-created_at', '-id')
    cve_id = str(params.get('cve_id') or '').strip()
    if cve_id:
        qs = qs.filter(cve_entry__cve_id__iexact=cve_id[:64])
    status = str(params.get('status') or '').strip().lower()
    if status:
        if status not in STATUSES:
            raise ApiError(400, f'status must be one of {", ".join(STATUSES)}')
        qs = qs.filter(status=status)
    wanted = str(params.get('evidence') or '').strip().lower()
    evidence = {}
    if wanted:
        if wanted not in EVIDENCE:
            raise ApiError(400, 'evidence must be version or behaviour')
        keep = []
        for pk, text in qs.exclude(yaml='').values_list('pk', 'yaml')[:MAX_EVIDENCE_SCAN]:
            evidence[pk] = templategen.template_evidence(text)
            if evidence[pk] == EVIDENCE[wanted]:
                keep.append(pk)
        qs = qs.filter(pk__in=keep)

    def load(ids):
        rows = list(GeneratedTemplate.objects.filter(pk__in=ids).select_related('cve_entry', 'revised_by'))
        rows.sort(key=lambda r: ids.index(r.pk))
        counts, superseded = _match_counts(ctx, rows), _superseded_by(rows)
        return [_row(r, counts, superseded, evidence.get(r.pk)) for r in rows]
    return svc.paginate_by_ids(qs, params, load)


def _match_rows(ctx, tmpl):
    """The caller's matches this template recorded (at most MAX_MATCHES), each with the evidence class of its stored hit when one was kept."""
    from cveFeed import template_review
    matches = list(_scoped_matches(ctx, template_review.recorded_matches(tmpl)).select_related('subdomain__target_domain__project', 'cve_entry')
                   .order_by('id')[:MAX_MATCHES])
    groups = {}
    for m in matches:
        if m.template_result in ('vulnerable', 'version_only'):
            groups.setdefault((m.subdomain.target_domain.project_id, m.subdomain.name), []).append(m.pk)
    reading = {}
    for (project_id, host), ids in groups.items():
        stored, evidence = template_review.hit_reading(tmpl, project_id, host, ids)
        for pk in ids:
            reading[pk] = (stored, evidence)
    out = []
    for m in matches:
        project = m.subdomain.target_domain.project
        stored, evidence = reading.get(m.pk, (False, None))
        out.append({'id': m.pk, 'project': project.slug if project else None, 'host': m.subdomain.name, 'cve_id': m.cve_entry.cve_id,
                    'template_result': m.template_result, 'tested_at': _iso(m.template_tested_at), 'stored_response': stored,
                    'hit_evidence': evidence})
    return out


def _review_row(review, admin):
    out = {'id': review.pk, 'verdict': review.verdict, 'reason': review.reason, 'by': review.reviewer_name or 'system',
           'at': _iso(review.created_at)}
    if admin:  # the match ids it touched are every organization's
        out['outcome'] = review.outcome
    return out


def _chain_row(row):
    return {'id': row.pk, 'template_id': row.template_id, 'status': row.status, 'created_at': _iso(row.created_at),
            'author': 'revision' if row.supersedes_id else 'ai', 'supersedes': row.supersedes_id,
            'revised_by': row.revised_by.username if row.revised_by_id and row.revised_by else None, 'revision_reason': row.revision_reason}


def _detail(ctx, tmpl):
    from cveFeed import template_review
    counts, superseded = _match_counts(ctx, [tmpl]), _superseded_by([tmpl])
    out = _row(tmpl, counts, superseded)
    admin = _admin(ctx)
    out.update({
        'yaml': tmpl.yaml, 'validation_output': tmpl.validation_output, 'fixture': tmpl.fixture, 'submitted_fixture': tmpl.submitted_fixture,
        'revision_reason': tmpl.revision_reason,
        'positive_fixture': {'verified_at': _iso(tmpl.positive_fixture_verified_at), 'source': tmpl.positive_fixture_source},
        'static_gate': template_review.static_gate(tmpl),
        'match_list': _match_rows(ctx, tmpl),
        'revisions': [_chain_row(r) for r in template_review.chain(tmpl)],
        'reviews': [_review_row(r, admin) for r in tmpl.reviews.all()[:50]],
    })
    if admin:
        out['test_results'] = tmpl.test_results
    else:
        out['test_results'] = None
        out['test_results_note'] = ('the per-host test results name hosts of every organization and are shown to an App Admin only; '
                                    'match_list holds this template\'s results on your hosts')
    return out


def get_generated_template(ctx, generated_id):
    svc._require_member(ctx)
    return _detail(ctx, _get(generated_id))


def _refused(exc):
    return ApiError(exc.status, exc.message)


def review_generated_template(ctx, generated_id):
    """The review report of one template (reads only; a read-only token may ask): the static gate, the evidence class, the fixture check,
    each of the caller's confirmations read again and plain findings (``cveFeed.template_review.report``)."""
    from cveFeed import template_review
    svc._require_member(ctx)
    tmpl = _get(generated_id)
    out = {'id': tmpl.pk, 'cve_id': tmpl.cve_entry.cve_id, 'template_id': tmpl.template_id, 'status': tmpl.status}
    out.update(template_review.report(tmpl, _scoped_matches(ctx, template_review.recorded_matches(tmpl))))
    out['reviews'] = [_review_row(r, _admin(ctx)) for r in tmpl.reviews.all()[:50]]
    return out


def set_generated_template_verdict(ctx, generated_id, verdict=None, reason=None):
    """A verdict on one template (App Admin, write token): keep records the review; retire sets the template invalid and reads its
    confirmations again (``cveFeed.template_review.retire``)."""
    from cveFeed import template_review
    svc._require_member(ctx)
    tmpl = _get(generated_id)
    if verdict not in VERDICTS:
        raise ApiError(400, f'verdict must be one of {", ".join(VERDICTS)} (a revision is update_generated_template)')
    _require_admin(ctx, 'review an AI-written template')
    try:
        if verdict == 'keep':
            review = template_review.keep(tmpl, reason, ctx.user)
        else:
            review = template_review.retire(tmpl, reason, ctx.user)
    except template_review.ReviewRefused as exc:
        raise _refused(exc)
    tmpl.refresh_from_db()
    return {'review': _review_row(review, True), 'template': _detail(ctx, tmpl)}


def update_generated_template(ctx, generated_id, yaml=None, reason=None, fixture=None):
    """A revision (App Admin): a new draft that supersedes the template, never an edit of it. Refused at once when the static gate refuses
    the text; otherwise validated automatically like an AI draft, and run on no host before it is valid."""
    from cveFeed import template_review, templatevalidate
    svc._require_member(ctx)
    tmpl = _get(generated_id)
    _require_admin(ctx, 'revise an AI-written template')
    try:
        revision, review = template_review.revise(tmpl, yaml, reason, ctx.user, fixture=fixture)
    except template_review.ReviewRefused as exc:
        raise _refused(exc)
    enabled = templatevalidate.enabled()
    revision = _get(revision.pk)
    return {'revision': _detail(ctx, revision), 'review': _review_row(review, True),
            'validation': {'enabled': enabled, 'note': (
                'the revision is a draft: the automatic validator takes it through the static gate, the scanner\'s syntax check and benign '
                'control on a Sentinel, the AI fixture and the second-pass review; it runs on no host before it is valid, and then the template '
                'it supersedes is retired' if enabled else
                'automatic validation of AI-written checks is off: the revision waits as a draft, and runs on no host, until an administrator '
                'switches it on in Settings')}}
