"""Third-party supplier posture checks: how well the suppliers a project depends on secure their own public services.

A supplier is NOT an owned host. It is a row of its own (``Supplier``: a name, a tier, the exact domain names to look at, a contact) and its
results are rows of their own (``SupplierFinding``), so nothing that counts, scores, schedules or assigns owned-host work ever sees it:
no discovery, no port scan, no subdomain enumeration, no host assessment, no nuclei or bbot, no remediation assigned to the project's team
(they cannot fix a supplier's server), no SLA clock, no stats. What a project owns is a target; a name that is one of the project's own
targets is refused here.

What is checked is passive and polite, from the outside, for each listed name and nothing else (no wildcard, no neighbouring name, no other
port than 443 and 80):

* TLS and certificate health of the name on port 443 (expiry, name match, chain, weak signature or key, TLS 1.0/1.1);
* email authentication (SPF, DKIM, DMARC, MTA-STS and the MailFail checks, DNS only, plus the one MTA-STS policy file over verified HTTPS);
* HTTP security headers and a short fixed list of well-known administration and login pages: the front page over HTTPS and over HTTP, then
  one plain GET per path of ``supplier_checks.WELL_KNOWN`` through the Sentinel's slow, polite web client, never a guessed path;
* known CVEs for the products and versions the responses announce, matched with the existing correlation rules and a strict version rule
  (``supplier_checks.cve_postures``). Nothing is tried against the supplier, so nothing is ever "validated".

Safety, the same as the other slow sweeps (cloud storage, virtual hosts, UDP): every name is resolved once and every address must be public
(loopback, private, link-local and cloud metadata addresses refuse the whole name, whatever ``CVENGINE_ALLOW_PRIVATE_TARGETS`` says), and
every connection goes to those vetted numeric addresses; the sweep stops while scanning is paused; a global request
pace is shared with the other slow web sweeps; each supplier is checked at most once a week (``ledger`` kind ``supplier``) and a supplier that
answered nothing is asked again tomorrow (``supplier-failed``); one sweep runs at a time; a project whose bug bounty engagement has not
confirmed automated testing is skipped; an organization's excluded names are never contacted; an edge that challenges a request is
recorded and never worked around. Caps: suppliers per project, names per supplier and requests per sweep (see the ``CVENGINE_SUPPLIERS_*``
settings).

A finding resolves by itself when a later check no longer finds it; a check that got no answer changes nothing.

Where the checks run: a project's suppliers are checked by a Sentinel (the ``supplier_check`` kind, contract version 3): one task per supplier carries
its validated names, the pacing and the request budget still left, and the scope policy (``probe_scope.for_suppliers``); the Sentinel runs the
network part (``cvengine_scanner.probes.suppliers``) and reports a row per name. This module keeps everything else: the list, the validation, the
schedule and the budget, the ledger, the CVE match against the catalog (the Sentinel only reports what the response announces), the text of what to
ask the supplier, and what is stored (``row_result`` reads a row; nothing in it is stored as it is). This server sends nothing to a supplier: with no Sentinel able to take the kind the suppliers stay due and nothing is recorded as checked."""
import logging
import os
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from cveFeed import slow_web, supplier_checks as checks

logger = logging.getLogger(__name__)

SERVICE = 'supplier'  # ledger asset: the supplier's id, per project (CVENGINE_TTL_SUPPLIER, hours, default a week)
FAILED_SERVICE = 'supplier-failed'  # a supplier that answered nothing: asked again tomorrow (CVENGINE_TTL_SUPPLIER_FAILED)
QUEUE = 'supplier_queue'
CLAIM_KEY = 'cvengine:supplier'
DEFAULT_MAX_PER_PROJECT = 50
DEFAULT_MAX_DOMAINS = 10
DEFAULT_MAX_REQUESTS = 600
TLS_COST = 3  # a certificate read is up to three handshakes: it is counted as three requests
DOMAIN_COST = TLS_COST + 2 + len(checks.PATHS) + 1  # front page twice, the fixed paths, the MTA-STS policy file
CLAIM_TTL = 1800
TIER_RANK = {'critical': 0, 'high': 1, 'normal': 2}
FORBIDDEN_SUFFIXES = ('localhost', 'local', 'internal', 'lan', 'intranet', 'corp', 'home', 'home.arpa', 'onion', 'invalid')
MAX_NAME, MAX_CONTACT, MAX_NOTES = 120, 300, 2000


# ----------------------------------------------------------------------------- settings

def enabled():
    """CVENGINE_SUPPLIERS: on unless it is 0/false/no/off."""
    return slow_web.truthy(os.environ.get('CVENGINE_SUPPLIERS', '1'))


def max_per_project():
    return slow_web.env_int('CVENGINE_SUPPLIERS_MAX_PER_PROJECT', DEFAULT_MAX_PER_PROJECT, 1, 500)


def max_domains():
    return slow_web.env_int('CVENGINE_SUPPLIERS_MAX_DOMAINS', DEFAULT_MAX_DOMAINS, 1, 25)


def max_requests():
    return slow_web.env_int('CVENGINE_SUPPLIERS_MAX_REQUESTS', DEFAULT_MAX_REQUESTS, 50, 5000)


# ----------------------------------------------------------------------------- validation

class SupplierError(ValueError):
    """A supplier, name or domain that is refused, with a message fit to show the person who typed it."""


def clean_domain(value):
    """The exact, lowercase DNS name in ``value``, or ``SupplierError``. A supplier is looked at by name only, so an address, a range, a
    wildcard, a URL, a port or a name with anything but letters, digits, dots and hyphens is refused, and so is a name that can only be private."""
    from targetApp.target_types import DOMAIN, classify_target
    if not isinstance(value, str):
        raise SupplierError('a domain must be text')
    name = value.strip().lower().rstrip('.')
    if not name:
        raise SupplierError('a domain must not be empty')
    if '*' in name:
        raise SupplierError(f'{value.strip()}: wildcards are not accepted, list each exact name to check')
    if '://' in name or '/' in name or '@' in name or '?' in name or '#' in name:
        raise SupplierError(f'{value.strip()}: give the bare domain name, not a URL or an address with a path')
    kind = classify_target(name)
    if kind in ('ip', 'cidr', 'range'):
        raise SupplierError(f'{value.strip()}: a supplier is checked by domain name, not by address (an address you own is a target)')
    if kind != DOMAIN:
        raise SupplierError(f'{value.strip()}: not a valid domain name (letters, digits and hyphens, with a dot; punycode for non-ASCII names)')
    if any(name == suffix or name.endswith('.' + suffix) for suffix in FORBIDDEN_SUFFIXES):
        raise SupplierError(f'{value.strip()}: a private or local name is never checked')
    return name


def owned_by(project_id, name):
    """The project's own target that ``name`` is or sits under (an owned name belongs in targets, not in the supplier list), or ''."""
    from cveFeed import vhost_scan
    for target, host_scoped, _id in vhost_scan.scope_targets(project_id):
        if name == target or (not host_scoped and name.endswith('.' + target)):
            return target
    return ''


def clean_domains(project, values, ignore=None):
    """``values`` as a list of validated, distinct names, or ``SupplierError``: at most ``max_domains`` of them, none that is one of the
    project's own targets (or under one), none the organization excluded, none already listed under another supplier of the project."""
    from cveFeed import exclusions
    from cveFeed.models import Supplier
    if isinstance(values, str):
        values = [part for part in values.replace(',', ' ').split() if part]
    if not isinstance(values, (list, tuple)) or not values:
        raise SupplierError('domains must be a list with at least one exact domain name')
    names = []
    for value in values:
        name = clean_domain(value)
        if name not in names:
            names.append(name)
    if len(names) > max_domains():
        raise SupplierError(f'a supplier can list at most {max_domains()} domain names')
    banned = exclusions.excluded_names(project.pk)
    taken = {}
    for other in Supplier.objects.filter(project=project).exclude(pk=getattr(ignore, 'pk', None)):
        for domain in other.domains or []:
            taken[domain] = other.name
    for name in names:
        target = owned_by(project.pk, name)
        if target:
            raise SupplierError(f'{name} is one of this project\'s own targets ({target}); an owned domain is a target, not a supplier')
        if name in banned:
            raise SupplierError(f'{name} is excluded for this organization and is never contacted')
        if name in taken:
            raise SupplierError(f'{name} is already listed under the supplier {taken[name]}')
    return names


def clean_text(value, limit, what, required=False):
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise SupplierError(f'{what} must be text')
    text = ''.join(ch for ch in value if ch in '\n\t' or ord(ch) >= 32).strip()
    if required and not text:
        raise SupplierError(f'{what} must not be empty')
    if len(text) > limit:
        raise SupplierError(f'{what} is too long (at most {limit} characters)')
    return text


def clean_tier(value):
    tier = (value or 'normal')
    if not isinstance(tier, str) or tier.strip().lower() not in checks_tiers():
        raise SupplierError(f'tier must be one of {", ".join(checks_tiers())}')
    return tier.strip().lower()


def checks_tiers():
    from cveFeed.models import Supplier
    return Supplier.TIERS


# ----------------------------------------------------------------------------- the address gate



# ----------------------------------------------------------------------------- the network (injectable)



class Budget:
    """The requests one sweep may still make (a certificate read counts as ``TLS_COST``)."""

    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def spend(self, units=1):
        self.used += units

    def left(self):
        return self.limit - self.used


# ----------------------------------------------------------------------------- one name

@dataclass
class DomainResult:
    domain: str
    postures: list = field(default_factory=list)
    resolvable: dict = field(default_factory=dict)  # category -> check-name prefixes this run could decide (what it no longer finds resolves)
    summary: dict = field(default_factory=dict)  # what the sweep did and saw for this name (counted, logged; the card keeps the durable parts)
    card: dict = field(default_factory=dict)  # sections of the host card this run could read: state, addresses, http, tls, technologies, mail, evidence
    answered: bool = False  # something conclusive came back
    stopped: bool = False
    partial: bool = False


# ----------------------------------------------------------------------------- storing

def _dedupe(postures):
    best = {}
    for p in postures:
        key = (p.domain, p.check)
        if key not in best or p.severity > best[key].severity:
            best[key] = p
    return list(best.values())


def store_card(supplier, res, now):
    """Refresh the host card of one name from a check. A section this check could not read (no certificate, no page) keeps what the check before
    it saw; ``checked_at`` always says when the card was last tried and ``last_ok_at`` when the page last answered."""
    from cveFeed.models import SupplierHostCard
    card, _ = SupplierHostCard.objects.get_or_create(supplier=supplier, domain=res.domain)
    data = res.card or {}
    card.state = data.get('state', card.state)[:12]
    card.addresses = data.get('addresses', card.addresses)
    for section in ('tls', 'mail'):
        if data.get(section):
            setattr(card, section, data[section])
    http_part = data.get('http')
    if http_part:
        if 'headers' in http_part:
            card.http = http_part
        else:  # only the statuses over each scheme are known: the headers of the last answer stay
            card.http = {**(card.http or {}), 'https_status': http_part.get('https_status'), 'http_status': http_part.get('http_status')}
    if data.get('technologies') is not None:
        card.technologies = data['technologies']
        banners = ((card.http or {}).get('server'), (card.http or {}).get('powered_by'))
        card.tech_text = checks.tech_text(data['technologies'], *banners)
    card.evidence = {**(card.evidence or {}), **(data.get('evidence') or {})} if card.state not in ('ok',) else {**(data.get('evidence') or {})}
    card.checked_at = now
    if card.state == 'ok':
        card.last_ok_at = now
    card.save()
    return card


def store_results(supplier, results, now=None):
    """Upsert the findings of ``results`` (``DomainResult``s of one supplier), and resolve the open or accepted ones that a check which could
    decide them no longer finds. A resolved finding that is found again reopens. One a person closed as a false positive is left as it is
    (its evidence refreshed, never resolved, so never reopened). Returns ``{'new', 'reopened', 'resolved', 'open'}``."""
    from cveFeed.models import SupplierFinding
    now = now or timezone.now()
    counts = {'new': 0, 'reopened': 0, 'resolved': 0}
    with transaction.atomic():
        for res in results:
            found = set()
            for p in _dedupe(res.postures):
                found.add(p.check)
                values = {'category': p.category, 'severity': p.severity, 'title': p.title[:300], 'detail': p.detail, 'ask': p.ask,
                          'evidence': p.evidence, 'last_seen': now}
                row = SupplierFinding.objects.filter(supplier=supplier, domain=p.domain, check_name=p.check).first()
                if row is None:
                    SupplierFinding.objects.create(supplier=supplier, domain=p.domain, check_name=p.check, first_seen=now, **values)
                    counts['new'] += 1
                    continue
                for key, value in values.items():
                    setattr(row, key, value)
                if row.status == 'resolved':
                    row.status, row.resolved_at, row.status_note = 'open', None, 'Reopened: a later check found this again.'
                    counts['reopened'] += 1
                row.save()
            store_card(supplier, res, now)
            for category, prefixes in res.resolvable.items():
                stale =SupplierFinding.objects.filter(supplier=supplier, domain=res.domain, category=category, status__in=('open', 'accepted'))
                for row in stale:
                    if row.check_name not in found and any(row.check_name.startswith(prefix) for prefix in prefixes):
                        row.status, row.resolved_at = 'resolved', now
                        row.save(update_fields=['status', 'resolved_at'])
                        counts['resolved'] += 1
    counts['open'] = SupplierFinding.objects.filter(supplier=supplier, status='open').count()
    return counts


# ----------------------------------------------------------------------------- the sweep

def due_suppliers(project_id):
    """The project's suppliers whose weekly window has run out, never-checked first, then the longest waiting, critical ones first among
    those; minus the ones that answered nothing within the last day."""
    from cveFeed import ledger
    from cveFeed.models import Supplier
    by_asset = {str(s.pk): s for s in Supplier.objects.filter(project_id=project_id) if s.domains}
    rows = ledger.stale_first(SERVICE, [(0, asset, project_id) for asset in by_asset])
    failed = ledger.fresh(FAILED_SERVICE, [r[1] for r in rows], project_id)
    ordered = [by_asset[r[1]] for r in rows if r[1] not in failed]
    return sorted(ordered, key=lambda s: TIER_RANK.get(s.tier, 2))  # stable: staleness order is kept within a tier


def _skipped(domain):
    return DomainResult(domain, card={'state': 'excluded', 'evidence': {
        'note': 'Not contacted: the name is excluded for the organization or is now one of the project\'s own targets.'}})


def row_result(row, pool):
    """A ``DomainResult`` from one row a Sentinel reported (already clipped by ``probe_results.clean_supplier_check``), finished here: the text
    to ask the supplier is written from the check name, the technology list is read from the fingerprints, and the CVE catalog is matched against
    what the response announced. A category the Sentinel says it could decide counts only when the card shows it read what that category needs
    (a certificate for ``tls``, the mail records for ``email``, a front page for ``web``, ``exposed`` and ``cve``): a bare claim resolves nothing."""
    domain = row['domain']
    res = DomainResult(domain)
    card = res.card = {k: v for k, v in (row.get('card') or {}).items()}
    card['evidence'] = dict(card.get('evidence') or {})
    res.summary = dict(row.get('summary') or {})
    res.answered, res.partial = bool(row.get('answered')), bool(row.get('partial'))
    res.stopped = bool(row.get('stopped')) and not res.partial
    res.postures = [checks.Posture(p['check'], p['severity'], p['title'], p['detail'], p['category'], domain, checks.ask_for(p['check'], domain, p['title']),
                                   p.get('evidence') or {}) for p in row.get('postures') or []]
    front = card.get('state') == 'ok' and isinstance(card.get('http'), dict)
    needs = {'tls': bool(card.get('tls')), 'email': bool(card.get('mail')), 'web': isinstance(card.get('http'), dict), 'exposed': front, 'cve': front}
    res.resolvable = {category: set(prefixes) for category, prefixes in (row.get('resolvable') or {}).items() if needs.get(category)}
    if front:
        technologies = checks.technologies_of(row.get('fingerprints'))
        edges = list(row.get('edges') or [])
        card['technologies'] = technologies
        card['evidence'].update({'edge': edges, 'fingerprint_sources': sorted({t['source'] for t in technologies})})
        if any(t['version'] for t in technologies):
            distro = row.get('distro') or ''
            matched, looked_up = checks.cve_postures(domain, checks.observations_of(technologies), pool(), edge=bool(edges), distro=distro)
            res.postures += matched
            card['evidence']['announced'] = looked_up
    return res


def _remote_rows(supplier, domains, budget):
    """``{domain: row}`` from a Sentinel's ``supplier_check`` for ``domains`` of ``supplier`` (empty when no task answered). Raises
    ``ScannerUnavailable`` when no Sentinel can take it: the supplier stays due."""
    from agentapi import probe_dispatch
    from dashboard.models import Project
    return probe_dispatch.try_suppliers(Project.objects.get(pk=supplier.project_id), domains, budget.left())


def _remote_results(domains, skipped, rows, budget, pool):
    """``(results, stopped)`` in the order of ``domains``: a skipped name as such, a name the Sentinel reported as its row, a name it did not
    report not at all (it was not checked, so it answers nothing). As on the local path, nothing after a name that ran out of budget or time."""
    results = []
    for domain in domains:
        if domain in skipped:
            results.append(skipped[domain])
            continue
        row = rows.get(domain)
        if row is None:
            continue
        res = row_result(row, pool)
        budget.spend(row.get('requests') or 0)
        results.append(res)
        if res.stopped or res.partial:
            return results, True
    return results, False


def check_supplier(supplier, budget, pool, stop, banned=frozenset()):
    """All names of one supplier, checked by a Sentinel as one ``supplier_check`` task (``ScannerUnavailable`` propagates when none can take it:
    this server sends nothing, and the supplier stays due). Returns ``(results, stopped)``."""
    domains = (supplier.domains or [])[:max_domains()]
    if stop():
        return [], True
    skipped = {d: _skipped(d) for d in domains if d in banned or owned_by(supplier.project_id, d)}  # excluded since it was added, or since become one of the project's own targets
    todo = [d for d in domains if d not in skipped]
    rows = _remote_rows(supplier, todo, budget) if todo else {}
    return _remote_results(domains, skipped, rows, budget, pool)


def sweep(project_id, stop=None, pool=None, budget=None, now=None):
    """One project's due suppliers. Returns the counts (and ``skipped`` with the reason when nothing ran). ``pool`` and ``stop`` replace the CVE catalog and the pause check in tests."""
    from cveFeed import activity, exclusions, ledger
    from cveFeed.conductor import bounty_blocked_projects
    from reNgine import resources
    from reNgine.resources import ScannerUnavailable
    summary = {'suppliers': 0, 'domains': 0, 'new': 0, 'reopened': 0, 'resolved': 0, 'deferred': 0, 'requests': 0}
    if not enabled():
        return {**summary, 'skipped': 'supplier checks are turned off (CVENGINE_SUPPLIERS=0)'}
    stop = stop or (lambda: resources.global_pause_requested(fail_closed=True))
    if stop():
        return {**summary, 'skipped': 'scanning is paused: the suppliers stay due'}
    if project_id in bounty_blocked_projects():
        return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing'}
    owner = f'supplier-{os.getpid()}'
    with resources.redis_claim(f'{CLAIM_KEY}:{project_id}', owner, CLAIM_TTL) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another supplier sweep is running for this project'}
        due = due_suppliers(project_id)
        if not due:
            return summary
        budget = budget or Budget(max_requests())
        if pool is None:
            from cveFeed import correlation
            pool = correlation.cve_pool
        started = budget.used
        banned = exclusions.excluded_names(project_id)
        running = activity.log('run_check', f'Supplier posture checks: {len(due)} supplier{"s" if len(due) != 1 else ""} due', project=project_id, status='running')
        for supplier in due:
            if stop():
                summary['skipped'] = 'scanning is paused: the suppliers stay due'
                break
            if budget.left() < min(len(supplier.domains), max_domains()) * DOMAIN_COST and summary['suppliers']:
                summary['deferred'] += 1  # not enough of this sweep's request budget left: due again at the next sweep
                continue
            if budget.left() <= 0:
                summary['deferred'] += 1
                continue
            try:
                results, stopped = check_supplier(supplier, budget, pool, stop, banned=banned)
            except ScannerUnavailable as exc:
                logger.info('supplier sweep of project %s waits for a scanner: %s', project_id, exc)
                summary['skipped'] = 'waiting for a scanner: the suppliers stay due'
                break
            counts = store_results(supplier, results, now=now)
            answered = any(r.answered for r in results)
            if answered:
                supplier.last_checked_at = now or timezone.now()
                supplier.save(update_fields=['last_checked_at'])
            summary['suppliers'] += 1
            summary['domains'] += len(results)
            for key in ('new', 'reopened', 'resolved'):
                summary[key] += counts[key]
            if stopped:
                if not budget.left() > 0 or any(r.partial for r in results):
                    summary['deferred'] += 1
                else:
                    summary['skipped'] = 'scanning is paused: the suppliers stay due'
                    break
                continue
            ledger.record(SERVICE if answered else FAILED_SERVICE, [str(supplier.pk)], project_id)
        summary['requests'] = budget.used - started
        activity.settle(running, 'done', message=(
            f'Supplier posture checks: {summary["suppliers"]} supplier{"s" if summary["suppliers"] != 1 else ""} checked, {summary["new"]} new finding'
            f'{"s" if summary["new"] != 1 else ""}, {summary["resolved"]} resolved'), **summary)
    return summary


def sweep_all(**kwargs):
    """Every project's due suppliers, the project waiting longest first. One sweep at a time; the work is spread over days by the request budget."""
    from django.db.models import Min

    from cveFeed import ledger
    from cveFeed.models import Supplier
    from reNgine import resources
    if not enabled():
        return {'skipped': 'supplier checks are turned off (CVENGINE_SUPPLIERS=0)'}
    stop = kwargs.get('stop') or (lambda: resources.global_pause_requested(fail_closed=True))
    if stop():
        return {'skipped': 'scanning is paused: the suppliers stay due'}
    if not ledger.sweep_claim('suppliers', 2 * 60 * 60):
        return {'skipped': 'another sweep is running'}
    kwargs.setdefault('budget', Budget(max_requests()))
    waiting = (Supplier.objects.values('project_id').annotate(oldest=Min('last_checked_at')).order_by('oldest', 'project_id'))
    order = sorted(waiting, key=lambda row: (row['oldest'] is not None, row['oldest'] or 0, row['project_id']))
    totals = {}
    for row in order:
        part = sweep(row['project_id'], **kwargs)
        for key, value in part.items():
            if isinstance(value, int):
                totals[key] = totals.get(key, 0) + value
        if part.get('skipped', '').startswith('scanning is paused'):
            totals['skipped'] = part['skipped']
            break
    return totals
