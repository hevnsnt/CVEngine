"""Third-party suppliers of a project: the list, their host cards, the technology search and the posture findings (REST and MCP share this).

Reading needs any role on the project (the audit role included). Adding and removing a supplier, and accepting a finding, need the project's
admin role (an organization admin or an App Admin, the rule the runZero settings use) and a write token: a supplier list drives outbound checks
against third parties, so it is not for every member. A supplier is never an owned host (see ``cveFeed.supplier_scan``)."""
from agentapi import services as svc
from agentapi.services import ApiError, _iso, _user_brief, paginate
from tenancy import roles

SEVERITY_FILTER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _project(ctx, slug, write=False):
    """The project, for a supplier operation. Writes are for the project's admins only."""
    project, role = svc.get_one_project(ctx, slug, write=write)
    if write and role != roles.ADMIN:
        raise ApiError(403, 'the supplier list is managed by an organization admin or an App Admin')
    return project, role


def _can_edit(ctx, role):
    return role == roles.ADMIN and not (ctx.token and ctx.token.read_only)


def _supplier_of(project, supplier_id):
    from cveFeed.models import Supplier
    try:
        found = Supplier.objects.filter(project=project, pk=int(supplier_id)).select_related('added_by').first()
    except (TypeError, ValueError):
        found = None
    if found is None:
        raise ApiError(404, 'supplier not found')
    return found


def _counts(supplier_ids):
    """``{supplier_id: {'open', 'critical', 'high', 'medium', 'low', 'accepted'}}`` of the findings, in one query."""
    from django.db.models import Count

    from cveFeed.models import SupplierFinding
    out = {}
    for row in SupplierFinding.objects.filter(supplier_id__in=supplier_ids, status__in=('open', 'accepted')).values('supplier_id', 'status', 'severity').annotate(n=Count('id')):
        entry = out.setdefault(row['supplier_id'], {'open': 0, 'accepted': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
        if row['status'] == 'accepted':
            entry['accepted'] += row['n']
            continue
        entry['open'] += row['n']
        name = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}.get(row['severity'])
        if name:
            entry[name] += row['n']
    return out


def _supplier(s, counts=None, hosts=None):
    empty = {'open': 0, 'accepted': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    return {'id': s.id, 'name': s.name, 'tier': s.tier, 'domains': list(s.domains or []), 'contact': s.contact, 'notes': s.notes,
            'added_by': _user_brief(s.added_by), 'created': _iso(s.created_at), 'last_checked': _iso(s.last_checked_at),
            'findings': (counts or {}).get(s.id, empty), 'hosts': (hosts or {}).get(s.id, 0)}


def _card(card, matched=None):
    s = card.supplier
    return {'id': card.id, 'supplier': {'id': s.id, 'name': s.name, 'tier': s.tier}, 'domain': card.domain, 'state': card.state,
            'addresses': card.addresses, 'http': card.http, 'tls': card.tls, 'technologies': card.technologies, 'mail': card.mail,
            'evidence': card.evidence, 'checked': _iso(card.checked_at), 'last_ok': _iso(card.last_ok_at),
            'matched': [{'name': t['name'], 'version': t.get('version', ''), 'category': t.get('category', '')} for t in (matched or [])]}


def _finding(f):
    from cveFeed import supplier_checks
    s = f.supplier
    return {'id': f.id, 'supplier': {'id': s.id, 'name': s.name, 'tier': s.tier}, 'domain': f.domain, 'category': f.category, 'check': f.check_name,
            'severity': supplier_checks.level(f.severity), 'title': f.title, 'detail': f.detail, 'ask': f.ask, 'evidence': f.evidence,
            'status': f.status, 'first_seen': _iso(f.first_seen), 'last_seen': _iso(f.last_seen), 'resolved': _iso(f.resolved_at),
            'status_note': f.status_note, 'status_by': _user_brief(f.status_by)}


def _audit(ctx, project, action, target, **detail):
    from cveFeed.admin_api import audit
    audit(ctx.user, action, f'{project.slug}:{target}', org=project.org_id, **detail)


# --- the supplier list -------------------------------------------------------------

def list_suppliers(ctx, slug, params=None):
    """The project's suppliers, critical tier first, each with its domains, when it was last checked, how many findings are open (by
    severity) and how many host cards it has. ``can_edit`` says whether the caller may add or remove."""
    from django.db.models import Case, Count, IntegerField, Value, When

    from cveFeed import supplier_scan
    from cveFeed.models import Supplier, SupplierHostCard
    project, role = _project(ctx, slug)
    qs = Supplier.objects.filter(project=project).select_related('added_by').order_by(
        Case(When(tier='critical', then=Value(0)), When(tier='high', then=Value(1)), default=Value(2), output_field=IntegerField()), 'name')
    page = paginate(qs, params or {}, lambda s: s)
    ids = [s.id for s in page['results']]
    counts = _counts(ids)
    hosts = {r['supplier_id']: r['n'] for r in SupplierHostCard.objects.filter(supplier_id__in=ids).values('supplier_id').annotate(n=Count('id'))}
    page['results'] = [_supplier(s, counts, hosts) for s in page['results']]
    page['can_edit'] = _can_edit(ctx, role)
    page['limits'] = {'max_suppliers': supplier_scan.max_per_project(), 'max_domains': supplier_scan.max_domains()}
    page['checks_enabled'] = supplier_scan.enabled()
    return page


def add_supplier(ctx, slug, body):
    """Add a supplier: ``name``, ``domains`` (the exact names to check), ``tier`` (critical, high or normal) and optionally ``contact`` and
    ``notes``. A domain that is one of the project's own targets, an address, a wildcard or a private name is refused (400)."""
    from django.db import IntegrityError, transaction

    from cveFeed import supplier_scan
    from cveFeed.models import Supplier
    project, _ = _project(ctx, slug, write=True)
    if not isinstance(body, dict):
        raise ApiError(400, 'send a JSON object with name and domains')
    try:
        name = supplier_scan.clean_text(body.get('name'), supplier_scan.MAX_NAME, 'name', required=True)
        tier = supplier_scan.clean_tier(body.get('tier'))
        contact = supplier_scan.clean_text(body.get('contact'), supplier_scan.MAX_CONTACT, 'contact')
        notes = supplier_scan.clean_text(body.get('notes'), supplier_scan.MAX_NOTES, 'notes')
        domains = supplier_scan.clean_domains(project, body.get('domains'))
    except supplier_scan.SupplierError as exc:
        raise ApiError(400, str(exc))
    if Supplier.objects.filter(project=project).count() >= supplier_scan.max_per_project():
        raise ApiError(409, f'a project can list at most {supplier_scan.max_per_project()} suppliers')
    try:
        with transaction.atomic():
            supplier = Supplier.objects.create(project=project, name=name, tier=tier, domains=domains, contact=contact, notes=notes, added_by=ctx.user)
    except IntegrityError:
        raise ApiError(409, f'a supplier named {name} is already listed')
    _audit(ctx, project, 'project.supplier.add', name, tier=tier, domains=domains)
    return _supplier(supplier)


def remove_supplier(ctx, slug, supplier_id):
    """Remove a supplier with its host cards and findings."""
    project, _ = _project(ctx, slug, write=True)
    supplier = _supplier_of(project, supplier_id)
    name, domains = supplier.name, list(supplier.domains or [])
    supplier.delete()
    _audit(ctx, project, 'project.supplier.remove', name, domains=domains)
    return {'deleted': True}


# --- host cards and the technology search -------------------------------------------

def search_hosts(ctx, slug, params=None):
    """The supplier host cards of the project. ``tech`` filters them by technology: comma separated terms, any of which matches
    anywhere in ``name version`` or in the Server and X-Powered-By banners (``php``, ``node``, ``php 7``, ``nginx 1.1``). ``supplier``
    (an id) and ``tier`` narrow it further. Each card says which of its technologies matched."""
    from cveFeed import supplier_search
    project, _ = _project(ctx, slug)
    params = params or {}
    supplier_id = params.get('supplier') or None
    rows = supplier_search.cards_for(project.id, params.get('tech') or params.get('q') or '', supplier_id=supplier_id, tier=str(params.get('tier') or ''))
    by_id = {card.id: matched for card, matched in rows}
    page = paginate(_Seq([card for card, _m in rows]), params, lambda card: card)
    page['results'] = [_card(card, by_id[card.id]) for card in page['results']]
    page['terms'] = supplier_search.terms_of(params.get('tech') or params.get('q') or '')
    return page


class _Seq:
    """A list that ``paginate`` can count and slice like a queryset."""

    def __init__(self, items):
        self.items = items

    def count(self):
        return len(self.items)

    def __getitem__(self, key):
        return self.items[key]


def list_technologies(ctx, slug):
    """The technologies the project's suppliers run (from their host cards), most widespread first, each with its category, the number of
    suppliers and hosts and the versions seen: the answer to "what do my suppliers run?", and what the search offers as a click."""
    from cveFeed import supplier_search
    project, _ = _project(ctx, slug)
    rows = supplier_search.facets(project.id)
    return {'count': len(rows), 'results': rows}


# --- findings ------------------------------------------------------------------------

def list_supplier_findings(ctx, slug, params=None):
    """Posture findings of the project's suppliers (certificate, email authentication, headers, exposed pages and, secondary, known CVEs for
    announced versions): ``status`` (open by default, accepted, resolved or all), ``supplier`` (id), ``severity`` (that or worse), ``category``
    (tls, email, web, exposed, cve). Worst first."""
    from cveFeed.models import SupplierFinding
    project, _ = _project(ctx, slug)
    params = params or {}
    qs = SupplierFinding.objects.filter(supplier__project=project).select_related('supplier', 'status_by')
    status = str(params.get('status') or 'open').lower()
    if status != 'all':
        if status not in SupplierFinding.STATUSES:
            raise ApiError(400, 'status must be open, accepted, resolved or all')
        qs = qs.filter(status=status)
    if params.get('supplier'):
        qs = qs.filter(supplier_id=svc._int_param(params['supplier'], 'supplier'))
    if params.get('severity'):
        if str(params['severity']).lower() not in SEVERITY_FILTER:
            raise ApiError(400, 'severity must be one of info, low, medium, high, critical')
        qs = qs.filter(severity__gte=SEVERITY_FILTER[str(params['severity']).lower()])
    if params.get('category'):
        qs = qs.filter(category=str(params['category']).lower())
    return paginate(qs.order_by('-severity', 'supplier__name', 'domain', 'check_name'), params, _finding)


def set_finding_status(ctx, slug, finding_id, body):
    """Accept a finding (the supplier knows and the project lives with it: the sweep keeps refreshing it but it leaves the open list) or open it
    again. ``resolved`` is set by the checks alone. ``note`` is kept with it."""
    from cveFeed import supplier_scan
    from cveFeed.models import SupplierFinding
    project, _ = _project(ctx, slug, write=True)
    body = body if isinstance(body, dict) else {}
    status = body.get('status')
    if status not in ('open', 'accepted'):
        raise ApiError(400, 'status must be open or accepted (a finding is resolved by a later check that no longer finds it)')
    try:
        note = supplier_scan.clean_text(body.get('note'), 500, 'note')
    except supplier_scan.SupplierError as exc:
        raise ApiError(400, str(exc))
    try:
        row = SupplierFinding.objects.filter(supplier__project=project, pk=int(finding_id)).select_related('supplier', 'status_by').first()
    except (TypeError, ValueError):
        row = None
    if row is None:
        raise ApiError(404, 'finding not found')
    if row.status == 'resolved':
        raise ApiError(409, 'a resolved finding cannot be changed; if it comes back the next check reopens it')
    row.status, row.status_note, row.status_by = status, note, ctx.user
    row.save(update_fields=['status', 'status_note', 'status_by'])
    _audit(ctx, project, 'project.supplier.finding', f'{row.supplier.name}:{row.check_name}', status=status)
    return _finding(row)


def supplier_summary(ctx, slug, supplier_id, params=None):
    """The plain-text message about one supplier, to copy and send: the technology its services announce (``tech``, comma separated, asks about
    those first) and its open findings with what to ask. Nothing is sent from here."""
    from cveFeed import supplier_checks
    from cveFeed.models import SupplierFinding, SupplierHostCard
    project, _ = _project(ctx, slug)
    supplier = _supplier_of(project, supplier_id)
    cards = list(SupplierHostCard.objects.filter(supplier=supplier).order_by('domain'))
    findings = list(SupplierFinding.objects.filter(supplier=supplier, status='open'))
    return {'supplier': {'id': supplier.id, 'name': supplier.name}, 'text': supplier_checks.share_text(supplier, findings, cards, (params or {}).get('tech', '')),
            'open': len(findings)}
