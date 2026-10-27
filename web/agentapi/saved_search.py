"""Saved searches: a Hosts-page search a person keeps and, optionally, is alerted about (see cveFeed.saved_searches).

A saved search is private to its owner inside one project: every operation looks it up by (project, owner, id), so another
member, another project's member or a guessed id all get the same 404. Reading and running one needs the same access as the
search itself; creating, changing, deleting and running it (a run can notify) need write access (an audit role or a read-only
token gets 403), and ``_all`` is refused because a search belongs to one project.
"""
import re
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from agentapi.services import ApiError, check_search, get_one_project, search_hosts
from cveFeed import notify, saved_searches
from cveFeed.models import SavedSearch
from dashboard.models import Project

FIELDS = ('name', 'query', 'enabled', 'alert_new', 'alert_gone', 'threshold', 'channels', 'frequency')
RUN_THROTTLE_SECONDS = 30  # a run-now is a full search; one every half minute per search is plenty
_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')


def _iso(value):
    return value.isoformat() if value else None


def _view(s, project):
    return {'id': s.pk, 'project': project.slug, 'name': s.name, 'query': s.query, 'enabled': s.enabled,
            'alert_new': s.alert_new, 'alert_gone': s.alert_gone, 'threshold': s.threshold, 'channels': list(s.channels or []),
            'frequency': s.frequency, 'baseline': s.baseline_at is not None, 'last_run_at': _iso(s.last_run_at),
            'next_run_at': _iso(s.next_run_at) if s.enabled else None, 'last_match_count': s.last_match_count,
            'last_status': s.last_status, 'last_error': s.last_error, 'last_alert_at': _iso(s.last_alert_at),
            'created': _iso(s.created_at), 'updated': _iso(s.updated_at)}


def _bool(body, key):
    if not isinstance(body[key], bool):
        raise ApiError(400, f'{key} must be true or false')
    return body[key]


def _clean(body, creating):
    """The validated fields of ``body``: a 400 for anything unknown, mistyped or out of range. The query goes through the
    search's own parser and filters, so a query that would fail on the Hosts page cannot be saved."""
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be a JSON object')
    unknown = sorted(set(body) - set(FIELDS))
    if unknown:
        raise ApiError(400, f'unknown field(s): {", ".join(str(k) for k in unknown)}')
    out = {}
    if creating or 'name' in body:
        name = body.get('name')
        if not isinstance(name, str):
            raise ApiError(400, 'name is required')
        name = ' '.join(_CONTROL.sub(' ', name).split())[:SavedSearch.MAX_NAME]  # clipped: a long name is not worth a refusal
        if not name:
            raise ApiError(400, 'name is required')
        out['name'] = name
    if creating or 'query' in body:
        query = body.get('query')
        if not isinstance(query, str):
            raise ApiError(400, 'query is required')
        query = query.strip()
        check_search(query)  # too long, too many terms, an unusable value, or empty: 400
        out['query'] = query
    for key in ('enabled', 'alert_new', 'alert_gone'):
        if key in body:
            out[key] = _bool(body, key)
    if 'threshold' in body:
        t = body['threshold']
        if t is not None and (isinstance(t, bool) or not isinstance(t, int) or not 1 <= t <= SavedSearch.MAX_MATCHES):
            raise ApiError(400, f'threshold must be null or a whole number from 1 to {SavedSearch.MAX_MATCHES}')
        out['threshold'] = t
    if 'channels' in body:
        channels = body['channels']
        if not isinstance(channels, list) or any(c not in SavedSearch.CHANNELS for c in channels):
            raise ApiError(400, f'channels must be a list of: {", ".join(SavedSearch.CHANNELS)}')
        out['channels'] = list(dict.fromkeys(channels))
    if 'frequency' in body:
        if body['frequency'] not in SavedSearch.FREQUENCIES:
            raise ApiError(400, f'frequency must be one of: {", ".join(SavedSearch.FREQUENCIES)}')
        out['frequency'] = body['frequency']
    return out


def _mine(ctx, project, search_id):
    s = SavedSearch.objects.filter(project=project, owner=ctx.user, pk=search_id).first()
    if not s:
        raise ApiError(404, 'saved search not found')
    return s


def _name_taken(ctx, project, name, except_id=None):
    rows = SavedSearch.objects.filter(project=project, owner=ctx.user, name__iexact=name)
    return (rows.exclude(pk=except_id) if except_id else rows).exists()


def list_saved_searches(ctx, slug):
    project, _ = get_one_project(ctx, slug)
    rows = SavedSearch.objects.filter(project=project, owner=ctx.user)
    return {'results': [_view(s, project) for s in rows],
            'limits': {'per_user': SavedSearch.MAX_PER_USER, 'per_project': SavedSearch.MAX_PER_PROJECT,
                       'matches': SavedSearch.MAX_MATCHES, 'frequencies': list(SavedSearch.FREQUENCIES)},
            'channels_available': notify.enabled_channels()}


def get_saved_search(ctx, slug, search_id):
    project, _ = get_one_project(ctx, slug)
    return _view(_mine(ctx, project, search_id), project)


def create_saved_search(ctx, slug, body):
    project, _ = get_one_project(ctx, slug, write=True)
    fields = _clean(body, creating=True)
    with transaction.atomic():
        # the project row is the lock that keeps two creations from both slipping under a cap
        Project.objects.select_for_update().get(pk=project.pk)
        if SavedSearch._base_manager.filter(owner=ctx.user).count() >= SavedSearch.MAX_PER_USER:
            raise ApiError(400, f'you can keep at most {SavedSearch.MAX_PER_USER} saved searches; delete one first')
        if SavedSearch._base_manager.filter(project=project).count() >= SavedSearch.MAX_PER_PROJECT:
            raise ApiError(400, f'this project already has {SavedSearch.MAX_PER_PROJECT} saved searches; delete one first')
        if _name_taken(ctx, project, fields['name']):
            raise ApiError(400, 'you already have a saved search with that name')
        try:
            with transaction.atomic():
                s = SavedSearch.objects.create(project=project, owner=ctx.user, **fields)
        except IntegrityError:
            raise ApiError(400, 'you already have a saved search with that name')
    return _view(s, project), 201


def update_saved_search(ctx, slug, search_id, body):
    project, _ = get_one_project(ctx, slug, write=True)
    s = _mine(ctx, project, search_id)
    fields = _clean(body, creating=False)
    if not fields:
        raise ApiError(400, f'nothing to change: send one or more of {", ".join(FIELDS)}')
    if 'name' in fields and fields['name'].lower() != s.name.lower() and _name_taken(ctx, project, fields['name'], s.pk):
        raise ApiError(400, 'you already have a saved search with that name')
    restart = ('query' in fields and fields['query'] != s.query) or (fields.get('enabled') and not s.enabled)
    if 'frequency' in fields and fields['frequency'] != s.frequency and not restart:
        # the next check follows the new rhythm from the last one, not from the old slot: weekly to hourly must not wait out the week
        now = timezone.now()
        due = (s.last_run_at or now) + timedelta(minutes=SavedSearch.FREQUENCIES.get(fields['frequency'], SavedSearch.FREQUENCIES['daily']))
        fields['next_run_at'] = max(now, due) if s.last_run_at else now
    if restart:
        # a different query, or a search that was off while hosts changed, has no meaningful "new": learn the baseline again, silently
        fields.update(matched={}, baseline_at=None, last_match_count=0, last_status='', last_error='', next_run_at=timezone.now())
    try:
        with transaction.atomic():
            for key, value in fields.items():
                setattr(s, key, value)
            s.save()
    except IntegrityError:
        raise ApiError(400, 'you already have a saved search with that name')
    return _view(s, project)


def delete_saved_search(ctx, slug, search_id):
    project, _ = get_one_project(ctx, slug, write=True)
    _mine(ctx, project, search_id).delete()
    return {'deleted': True}


def run_saved_search(ctx, slug, search_id):
    """Evaluate the search now, exactly as the schedule would: compare with the last evaluation, alert if it asked to, record
    the outcome. The first run only learns the baseline. A disabled search is not run (switch it on first)."""
    from django.core.cache import cache
    project, _ = get_one_project(ctx, slug, write=True)
    s = _mine(ctx, project, search_id)
    if not s.enabled:
        raise ApiError(400, 'this saved search is switched off; enable it first')
    if not cache.add(f'cvengine:saved-search-run:{s.pk}', 1, timeout=RUN_THROTTLE_SECONDS):
        raise ApiError(429, f'this search was run a moment ago; try again in {RUN_THROTTLE_SECONDS} seconds')
    outcome = saved_searches.evaluate(s)
    if outcome['status'] == 'busy':
        raise ApiError(409, 'this search is being evaluated right now')
    s.refresh_from_db()
    return {**outcome, 'saved_search': _view(s, project)}


def saved_search_matches(ctx, slug, search_id, params):
    """The hosts the saved search matches now: the interactive search with the saved query (same results, paging, sort, heat and
    facets). Read only; it does not touch the search's baseline."""
    project, _ = get_one_project(ctx, slug)
    s = _mine(ctx, project, search_id)
    page = search_hosts(ctx, slug, {**{k: params.get(k) for k in ('page', 'page_size', 'sort', 'heat', 'facets', 'facet_size') if params.get(k) not in (None, '')}, 'q': s.query})
    return {**page, 'saved_search': _view(s, project)}
