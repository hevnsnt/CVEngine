"""Third-party supplier posture checks: how well the suppliers a project depends on secure their own public services.

A supplier is NOT an owned host. It is a row of its own (``Supplier``: a name, a tier, the exact domain names to look at, a contact) and its
results are rows of their own (``SupplierFinding``), so nothing that counts, scores, schedules or assigns owned-host work ever sees it:
no discovery, no port scan, no subdomain enumeration, no host assessment, no nuclei or bbot, no remediation assigned to the project's team
(they cannot fix a supplier's server), no SLA clock, no stats. What a project owns is a target; a name that is one of the project's own
targets is refused here.

What is checked is passive and polite, from the outside, for each listed name and nothing else (no wildcard, no neighbouring name, no other
port than 443 and 80):

* TLS and certificate health of the name on port 443 (``hygiene.probe_tls``: expiry, name match, chain, weak signature or key, TLS 1.0/1.1);
* email authentication (SPF, DKIM, DMARC, MTA-STS and the MailFail checks, DNS only, plus the one MTA-STS policy file over verified HTTPS);
* HTTP security headers and a short fixed list of well-known administration and login pages: the front page over HTTPS and over HTTP, then
  one plain GET per path of ``supplier_checks.WELL_KNOWN`` through the slow, polite web client (``slow_web``), never a guessed path;
* known CVEs for the products and versions the responses announce, matched with the existing correlation rules and a strict version rule
  (``supplier_checks.cve_postures``). Nothing is tried against the supplier, so nothing is ever "validated".

Safety, the same as the other slow sweeps (cloud storage, virtual hosts, UDP): every name is resolved once and every address must be public
(loopback, private, link-local and cloud metadata addresses refuse the whole name, whatever ``CVENGINE_ALLOW_PRIVATE_TARGETS`` says), and
every connection goes to those vetted numeric addresses (``pinned_transport``); the sweep stops while scanning is paused; a global request
pace is shared with the other slow web sweeps; each supplier is checked at most once a week (``ledger`` kind ``supplier``) and a supplier that
answered nothing is asked again tomorrow (``supplier-failed``); one sweep runs at a time; a project whose bug bounty engagement has not
confirmed automated testing is skipped; an organization's excluded names are never contacted; an edge that challenges a request is
recorded and never worked around. Caps: suppliers per project, names per supplier and requests per sweep (see the ``CVENGINE_SUPPLIERS_*``
settings).

A finding resolves by itself when a later check no longer finds it; a check that got no answer changes nothing."""
import http.client
import logging
import os
import socket
import ssl
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

def numeric_addresses(ips, port=443):
    """``pinned_transport``'s numeric ``(family, sockaddr)`` pairs for vetted address strings."""
    out = []
    for ip in ips:
        out.append((socket.AF_INET6, (ip, port, 0, 0)) if ':' in ip else (socket.AF_INET, (ip, port)))
    return tuple(out)


def public_addresses(name, net):
    """``(addresses, state)`` for a name: ``ok`` with every address it resolves to (IPv4 first) when ALL of them are public; ``blocked`` when
    any is loopback, private, link-local, metadata or otherwise one a scanner must not touch (the whole name is then refused, whatever
    ``CVENGINE_ALLOW_PRIVATE_TARGETS`` is set to); ``none`` when the name has no address; ``unknown`` when the lookup failed."""
    from targetApp.target_types import is_scannable_ip
    try:
        found = list(dict.fromkeys(net.resolve(name)))
    except socket.gaierror as exc:
        return [], ('none' if exc.errno in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', -5)) else 'unknown')
    except (OSError, ValueError):
        return [], 'unknown'
    if not found:
        return [], 'none'
    if not all(is_scannable_ip(ip, allow_private=False) for ip in found):
        return [], 'blocked'
    return sorted(found, key=lambda ip: (':' in ip, ip)), 'ok'


# ----------------------------------------------------------------------------- the network (injectable)

class Network:
    """The real network of the checks. A test injects an object with the same methods and never touches the internet. Every connection goes
    to addresses ``public_addresses`` admitted; nothing here resolves a name by itself except ``resolve``."""

    def resolve(self, name):
        return [info[4][0] for info in socket.getaddrinfo(name, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)]

    def fetch(self, url, ip):
        """One bounded, anonymous GET through the slow web client, connected to the vetted ``ip`` (the URL's name is the Host and TLS name)."""
        return slow_web.get(url, connect_ip=ip)

    def tls(self, name, addresses):
        from cveFeed import hygiene
        return hygiene.probe_tls(name, 443, addresses=numeric_addresses(addresses))

    def dns_state(self, name):
        import dns.exception
        import dns.resolver

        from cveFeed import hygiene
        try:
            hygiene._resolver().resolve(name, 'MX')
            return 'ok'
        except dns.resolver.NoAnswer:
            return 'ok'
        except dns.resolver.NXDOMAIN:
            return 'nxdomain'
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return 'unknown'

    def txt(self, name):
        from cveFeed import hygiene
        return hygiene.fetch_txt(name)

    def records(self, name, rtype):
        from cveFeed import hygiene
        return hygiene.fetch_records(name, rtype)

    def has_record(self, name, rtype):
        from cveFeed import hygiene
        return hygiene.has_record(name, rtype)

    def mta_sts_policy(self, domain, addresses):
        """The MTA-STS policy file over verified HTTPS (RFC 8461), to the vetted addresses only, no redirects, at most 64 KB. None when there is none."""
        from cveFeed import mailfail, pinned_transport
        host = f'mta-sts.{domain}'
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = pinned_transport.HTTPConnection(host, 443, numeric_addresses(addresses), mailfail.HTTP_TIMEOUT, context=context)
        try:
            conn.request('GET', '/.well-known/mta-sts.txt', headers={'Host': host, 'User-Agent': 'CVEngine supplier check'})
            response = conn.getresponse()
            if response.status != 200:
                return None
            body = response.read(mailfail.MAX_POLICY_BYTES + 1)
            return None if len(body) > mailfail.MAX_POLICY_BYTES else body.decode('utf-8', 'replace')
        except (OSError, http.client.HTTPException, ValueError):
            return None
        finally:
            conn.close()


class Budget:
    """The requests one sweep may still make (a certificate read counts as ``TLS_COST``)."""

    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def spend(self, units=1):
        self.used += units

    def left(self):
        return self.limit - self.used


class _Stopped(Exception):
    """Scanning was paused, or the sweep's request budget ran out, in the middle of a name."""


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


def _email(res, domain, net, pace, budget):
    """SPF, DKIM, DMARC, MTA-STS and the MailFail checks, DNS only, for a name that handles mail."""
    from cveFeed import hygiene, mailfail
    state = net.dns_state(domain)
    res.card.setdefault('evidence', {})['dns'] = state
    if state != 'ok':
        return
    has_mx = net.has_record(domain, 'MX')
    mail = has_mx or any('v=spf1' in t.lower() for t in net.txt(domain)) or any('v=dmarc1' in t.lower() for t in net.txt(f'_dmarc.{domain}'))
    res.card['mail'] = {'handles_mail': bool(mail), 'mx': bool(has_mx)}
    if not mail:
        return
    found, has_mx = hygiene.email_findings(domain, fetch=net.txt, mx=net.has_record, records=net.records)
    sts = net.txt(f'_mta-sts.{domain}')
    if any('v=stsv1' in t.lower() for t in sts):  # the one policy file, fetched only to the addresses vetted for mta-sts.<domain>
        addresses, sts_state = public_addresses(f'mta-sts.{domain}', net)
        if sts_state in ('ok', 'none', 'blocked'):
            policy = None
            if sts_state == 'ok':
                budget.spend(1)
                pace.wait(f'mta-sts.{domain}')
                policy = net.mta_sts_policy(domain, addresses)
            found = [f for f in found if not f.check.startswith('mta_sts_')] + mailfail.evaluate_mta_sts(domain, sts, policy, has_mx)
    if net.dns_state(domain) != 'ok':  # the resolver failed on the way: an empty answer is not "no record"
        res.card['evidence']['dns'] = 'unknown'
        return
    res.postures += checks.email_postures(domain, found)
    res.resolvable['email'] = {''}
    res.answered = True


def _http_section(https, http_page, base, scheme, domain):
    """The ``http`` section of the card: the front page's status over both schemes and the raw response headers of the one that answered."""
    section = {'https_status': (https or {}).get('status'), 'http_status': (http_page or {}).get('status')}
    if base:
        section.update({'url': f'{scheme}://{domain}/', 'status': base.get('status'), 'title': (base.get('title') or '')[:200],
                        'content_type': base.get('content_type') or '', 'server': str(base.get('server') or '')[:200],
                        'powered_by': str(base.get('powered_by') or '')[:200], 'location': str(base.get('location') or '')[:300],
                        'cookies': sorted(base.get('cookies') or [])[:20], 'bytes': base.get('bytes'),
                        'headers': dict(list((base.get('raw_headers') or {}).items())[:60])})
    return section


def _tls_section(info):
    """The ``tls`` section: the certificate and protocol as read, text clipped to what the card stores."""
    from cveFeed import hygiene
    info = hygiene.clip_certificate(info)
    not_after = info.get('not_after')
    days = (not_after - timezone.now()).days if not_after else None
    return {'subject': info['subject'], 'issuer': info['issuer'], 'sans': info['sans'][:50], 'not_before': info['not_before'].isoformat() if info.get('not_before') else None,
            'not_after': not_after.isoformat() if not_after else None, 'days_left': days, 'key': info['key_description'],
            'signature': info['signature_algorithm'], 'protocol': info['protocol'], 'cipher': info['cipher'], 'chain_error': info['chain_error'],
            'legacy_tls': bool(info.get('legacy_tls'))}


def check_domain(domain, net, pace, budget, pool, stop=lambda: False, now=None):
    """Every check of one supplier name: its host card first (certificate, response headers, technology stack), then the findings. Returns a
    ``DomainResult``; nothing is stored here. ``pool`` is a callable returning the CVE catalog's ``(cve_by_id, product_index)``, read only when
    the stack shows a version."""
    from cveFeed import route_auth, versions
    res = DomainResult(domain)
    addresses, state = public_addresses(domain, net)
    res.summary['address'] = state
    res.card = {'state': {'ok': 'unreachable', 'none': 'no_address', 'blocked': 'blocked'}.get(state, 'unreachable'), 'addresses': addresses[:6],
                'evidence': {'address': state}}
    try:
        if stop():
            raise _Stopped
        _email(res, domain, net, pace, budget)
        if state != 'ok':
            if state == 'blocked':
                res.card['evidence']['note'] = 'The name resolves to an address that is not public, so it was not contacted.'
            return res
        ip = addresses[0]

        def spend(units):
            if stop():
                raise _Stopped
            if budget.left() < units:
                res.partial = True
                raise _Stopped
            budget.spend(units)
            pace.wait(domain)

        def get(url):
            spend(1)
            try:
                return net.fetch(url, ip)
            except (OSError, ValueError, http.client.HTTPException):
                return None

        spend(TLS_COST)
        try:
            info = net.tls(domain, addresses)
        except Exception as exc:  # noqa: BLE001 - a certificate the library cannot read must not stop the rest
            logger.info('supplier: could not read the certificate of %s (%s)', domain, type(exc).__name__)
            info = None
        if info:
            res.postures += checks.tls_postures(domain, info, now=now)
            res.resolvable['tls'] = {'tls_'}
            res.answered = True
            res.card['tls'] = _tls_section(info)

        https, http_page = get(f'https://{domain}/'), get(f'http://{domain}/')
        front = https if checks.answered(https) else http_page if checks.answered(http_page) else None
        challenge = (https or {}).get('challenge') or (http_page or {}).get('challenge') or ''
        if challenge:
            res.card['evidence']['challenged'] = challenge  # an edge refused the request: recorded, never retried or worked around
            res.card['state'] = 'challenged'
        if any(slow_web.busy(r) for r in (https, http_page) if r):
            res.partial = True
        web, evaluated = checks.web_postures(domain, https, http_page)
        res.postures += web
        if evaluated:
            res.resolvable['web'] = evaluated
            res.answered = True
        res.card['http'] = _http_section(https, http_page, None, '', domain) if front is None else None
        if front is None or challenge:
            return res
        res.card['state'] = 'ok'
        scheme = 'https' if checks.answered(https) else 'http'
        base = https if scheme == 'https' else http_page
        res.card['http'] = _http_section(https, http_page, base, scheme, domain)
        # the stack: the fingerprinting owned hosts use (headers, generator tags, markers in the page, script names), read from this one page
        evidence = route_auth.classify({**base, 'url': f'{scheme}://{domain}/'})[1]
        technologies = checks.technologies_of(evidence.get('fingerprints'))
        edges = versions.edges_from_headers({**(base.get('headers') or {}), 'server': base.get('server', '')})
        res.card['technologies'] = technologies
        res.card['evidence'].update({'edge': edges, 'fingerprint_sources': sorted({t['source'] for t in technologies})})
        if any(t['version'] for t in technologies):
            matched, looked_up = checks.cve_postures(domain, checks.observations_of(technologies), pool(), edge=bool(edges),
                                                     distro=versions.parse_server_header(base.get('server', '')).get('distro', ''))
            res.postures += matched
            res.card['evidence']['announced'] = looked_up
        if not edges:
            res.resolvable['cve'] = {'cve_'}
        results = {}
        for page in checks.WELL_KNOWN:
            response = get(f'{scheme}://{domain}{page.path}')
            results[page.path] = response
            if response and response.get('challenge'):
                res.card['evidence']['challenged'] = response['challenge']
                break
            if response and slow_web.busy(response):
                res.partial = True
                break
        exposed, evaluated = checks.exposed_postures(domain, scheme, results, front=base)
        res.postures += exposed
        if evaluated:
            res.resolvable['exposed'] = evaluated
    except _Stopped:
        res.stopped = not res.partial
    return res

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
    decide them no longer finds. A resolved finding that is found again reopens. Returns ``{'new', 'reopened', 'resolved', 'open'}``."""
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


def check_supplier(supplier, net, pace, budget, pool, stop, banned=frozenset(), now=None):
    """All names of one supplier. Returns ``(results, stopped)``."""
    results = []
    for domain in (supplier.domains or [])[:max_domains()]:
        if stop():
            return results, True
        if domain in banned or owned_by(supplier.project_id, domain):  # excluded since it was added, or since become one of the project's own targets
            skipped = DomainResult(domain, card={'state': 'excluded', 'evidence': {
                'note': 'Not contacted: the name is excluded for the organization or is now one of the project\'s own targets.'}})
            results.append(skipped)
            continue
        res = check_domain(domain, net, pace, budget, pool, stop=stop, now=now)
        results.append(res)
        if res.stopped or res.partial:
            return results, True
    return results, False


def sweep(project_id, net=None, pace=None, stop=None, pool=None, budget=None, now=None):
    """One project's due suppliers. Returns the counts (and ``skipped`` with the reason when nothing ran). ``net``, ``pace``, ``pool`` and
    ``stop`` replace the network, the pacing, the CVE catalog and the pause check in tests."""
    from cveFeed import activity, exclusions, ledger
    from cveFeed.conductor import bounty_blocked_projects
    from reNgine import resources
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
        net, pace = net or Network(), pace or slow_web.Pace()
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
            results, stopped = check_supplier(supplier, net, pace, budget, pool, stop, banned=banned, now=now)
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
