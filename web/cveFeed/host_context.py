"""Everything cvENGINE holds about one host, assembled for the AI that judges a finding or plans checks for it.

One function, ``host_context``, reads the technologies and where each was seen, the ports with product, version, extra info, banner,
HTTP and TLS facts, the root page's headers and title, WAF, CDN, hosting and CNAME hints, certificates, the operating system guess and
its runners-up, what runZero and the host inventory reporter said, what version and identity probes found (or found hidden), earlier
check results and the host's other CVE matches. Every value comes from a scanned host or a third party, so it is cleaned, capped and
meant to travel inside an untrusted block; host names and addresses are left out, as in every other prompt.

The context carries the rules the model must not forget: behind a CDN or WAF the Server header, X-Powered-By and error pages describe
the edge, a tag such as "cloudflare" names the edge and not an application, and a banner that states no version proves nothing."""
import hashlib
import json
import re

from reNgine.ai_providers import clean_text

MAX_TECHS, MAX_PORTS, MAX_PROBES, MAX_MATCHES, MAX_STEPS, MAX_CERTS = 40, 25, 30, 10, 8, 6
EDGE_NOTE = ('This host is fronted by a CDN, WAF or hosting edge. The Server header, X-Powered-By, error pages and TLS answers describe '
             'the edge, so the origin software and its versions cannot be known from here: a technology tag such as "cloudflare" '
             'names the edge, not an application on the host. Say so instead of assuming an origin product or version.')
UNVERSIONED_NOTE = ('A product listed under unversioned_products was seen without a version. Its name alone is not evidence that any '
                    'advisory applies; only a stated version, or a probe result, is.')


def _s(value, limit=120, names=()):
    """Scanned-host text: the host's own names redacted, then cleaned to an identifier-like alphabet."""
    from cveFeed.triage import _s as clean
    return clean(value, limit, names)


def _names_of(sub):
    from cveFeed.triage import _names
    domain = getattr(sub, 'target_domain', None)
    return _names(getattr(sub, 'name', ''), getattr(domain, 'name', ''), getattr(sub, 'cname', ''))


def edge_of(sub, project_id=None, observations=None, route_headers=None):
    """``{'fronted', 'verified', 'providers', 'basis'}``: whether a CDN, WAF or hosting edge answers for this host and what says so (its CNAME,
    the CDN flag on the host or an address, a WAF fingerprint, edge-only response headers, a probe that saw only an edge page). ``fronted`` is
    for the model's information. ``verified`` is true only on DNS-level evidence (the CNAME, the host's own name, a CDN flag on an address):
    a response header or a page is the scanned host's own say-so, and one ``cf-ray`` header must not be able to clear its CVE matches."""
    from cveFeed import hosting, versions
    providers, basis = set(), []
    ips = list(sub.ip_addresses.all())
    pointers = [ip.reverse_pointer for ip in ips if ip.reverse_pointer]
    flagged = bool(sub.is_cdn or any(ip.is_cdn for ip in ips))
    info = hosting.classify(name=sub.name, cname=sub.cname or '', webserver=sub.webserver or '', reverse_pointers=pointers, cdn_name=sub.cdn_name or '',
                            is_cdn=flagged)
    dns_info = hosting.classify(name=sub.name, cname=sub.cname or '', webserver='', reverse_pointers=pointers, cdn_name=sub.cdn_name or '',
                                is_cdn=flagged)
    verified = bool(dns_info['shared_ip'] and dns_info['provider'])
    if info['shared_ip'] and info['provider']:
        providers.add(info['provider'])
        basis += info['evidence'][:2]
    for waf in sub.waf.all():
        providers.add(waf.name[:60])
        basis.append(f'WAF fingerprint {waf.name[:40]}')
    for provider in versions.edges_from_headers(route_headers or {}):
        providers.add(provider)
        basis.append(f'edge response headers ({provider})')
    for row in observations or ():
        if row.outcome in ('edge', 'challenged') and row.product:
            providers.add(row.product[:60])
            basis.append(f'probe {row.probe}: {row.outcome}')
    return {'fronted': bool(providers), 'verified': verified, 'providers': sorted(providers)[:6], 'basis': basis[:6]}


def edge_for(sub, project_id):
    """``edge_of`` with what the stored probe results and the front page's response headers add: the answer the probe planner and the match
    triage need without building the whole context."""
    root = _root_route(sub, project_id)
    return edge_of(sub, project_id, _probe_rows(project_id, sub.name.lower()), ((root.evidence or {}).get('headers') if root else None) or {})


def _root_route(sub, project_id):
    from cveFeed.models import RouteAuth
    rows = RouteAuth.objects.filter(project_id=project_id, host=sub.name.lower(), path='/', retired_at__isnull=True).order_by('checked_at')
    chosen = None
    for row in rows:
        if chosen is None or row.url.startswith('https'):
            chosen = row
    return chosen


def library_copies(record, names=(), limit=6):
    """The copies of one JavaScript library the front page loads (cveFeed.js_libraries), cleaned: path, version, where the version came
    from and which copy runs. Shared by the AI's host context and the host record."""
    from urllib.parse import urlsplit
    out = []
    for copy in (record or {}).get('copies') or []:
        if not isinstance(copy, dict):
            continue
        try:
            path = urlsplit(str(copy.get('url') or '')).path or '/'
        except ValueError:
            path = '/'
        out.append({'path': _s(path, 120, names), 'version': _s(copy.get('version'), 40, names), 'version_source': _s(copy.get('source'), 12),
                    'state': _s(copy.get('state'), 12), **({'loaded_after_noconflict': True} if copy.get('loaded_after_noconflict') else {})})
    return out[:limit]


def _technologies(sub, names, observed, libraries=None):
    from cveFeed import fingerprint, js_libraries
    from cveFeed.correlation import split_name_version
    by_product = {str(r.get('product', '')).lower(): r for r in (libraries or {}).values() if isinstance(r, dict)}
    out = []
    for tech in sub.technologies.all()[:200]:
        base, version = split_name_version(tech.name or '')
        row = {'name': _s(base or tech.name, 60, names), 'version': _s(version, 40, names), 'category': fingerprint.categorize(tech.name or ''),
               'source': observed.get(tech.name, 'scan')}
        record = by_product.get((base or '').lower()) if js_libraries.is_library(tech.name) else None
        if record:  # where the version came from and every copy on the page, with the one that runs
            row['version_source'] = _s(record.get('version_source'), 12)
            row['copies'] = library_copies(record, names)
            if record.get('copies_unresolved'):
                row['copies_unresolved'] = True
        out.append(row)
    return sorted(out, key=lambda t: t['name'].lower())[:MAX_TECHS]


def _ports(sub, names):
    from startScan.models import open_services
    out = []
    for ip in sub.ip_addresses.all():
        for port in open_services(ip):
            extra = port.extra or {}
            record = {'number': port.number, 'protocol': port.protocol, 'service': _s(port.service_name, 40, names),
                      'product': _s(port.product, 80, names), 'version': _s(port.version, 40, names),
                      'extra_info': _s(port.service_extra, 100, names), 'cpe': _s(port.cpe, 100, names),
                      'tls': extra.get('tunnel') == 'ssl' or bool(port.tls), 'detection': _s(extra.get('method'), 12),
                      'banner': _s(port.banner, 160, names)}
            http = port.http or {}
            if http:
                record['http'] = _s('; '.join(f'{k} {http[k]}' for k in ('status', 'title', 'webserver', 'content_type') if http.get(k)), 240, names)
            tls = port.tls or {}
            if tls.get('subject'):
                record['certificate'] = _s(f"subject {tls.get('subject')}; issuer {tls.get('issuer', '')}; expires {tls.get('not_after', '')}", 240, names)
            scripts = [f'{sid}: {text}' for sid, text in list((extra.get('scripts') or {}).items())[:6]
                       if sid in ('http-server-header', 'http-generator', 'http-title', 'banner')]
            if scripts:
                record['scripts'] = _s(' | '.join(scripts), 400, names)
            out.append(record)
    return sorted(out, key=lambda p: p['number'])[:MAX_PORTS]


def _os(sub, names):
    """The operating system evidence: nmap's guesses with their accuracy and what other tools reported. Behind Docker Desktop's network a
    guess describes that network, not the host (cveFeed.os_detection), and a model would reason about it as a fact, so no guess is
    given and the block says why. Whether to believe a guess depends on where it was made (``os_detection.guess_believed``): a Sentinel's, which
    measured on its own network, is kept on such an install."""
    from cveFeed import os_detection
    guesses = []
    facts = {}
    withheld = False
    for ip in sub.ip_addresses.all():
        fingerprint = ip.fingerprint or {}
        believe = os_detection.guess_believed(ip)
        withheld = withheld or bool(ip.os_guess and not believe)
        if ip.os_guess and believe:
            guesses.append({'guess': _s(ip.os_guess, 80, names), 'accuracy': ip.os_accuracy,
                            'alternatives': [_s(m.get('name'), 80, names) for m in (fingerprint.get('os_matches') or [])[1:3] if isinstance(m, dict)]})
        for key in ('runzero', 'facts'):
            if isinstance(fingerprint.get(key), dict):
                facts.setdefault(key, {k: _s(v, 80, names) for k, v in list(fingerprint[key].items())[:12] if isinstance(v, (str, int, float))})
    out = {'guesses': guesses[:3], 'reported_by_other_tools': facts}
    if withheld or (os_detection.unreliable() and not guesses):
        out['note'] = os_detection.reason()
    return out


TAILSCALE_FACTS = ('os', 'client_version', 'tags', 'update_available')  # never the device name, its addresses or the signed-in user


def _tailscale(project_id, host):
    """What Tailscale said about the device this host is (a tailnet device is a target named by its tailnet address), or None: only the
    operating system, client version, tags, whether an update is available and whether it is online. Its name, hostname, addresses and the
    login of its owner stay out of a prompt (no host names or addresses, and a person's login is personal data)."""
    from cveFeed.models import TailscaleDevice
    row = TailscaleDevice.objects.filter(project_id=project_id, domain__name=host, departed_at__isnull=True).first()
    if row is None:
        return None
    facts = {k: _s(json.dumps(v, default=str) if isinstance(v, (list, dict)) else v, 100) for k, v in (row.facts or {}).items()
             if k in TAILSCALE_FACTS and v not in (None, '', [])}
    return {'online': row.online, **facts}


def _certificates(project_id, host):
    from cveFeed.models import TlsCertificate
    rows = TlsCertificate.objects.filter(domain__project_id=project_id, host=host)[:MAX_CERTS]
    return [{'port': r.port, 'issuer': _s(r.issuer, 80), 'days_left': r.days_left, 'protocol': r.protocol, 'legacy_tls': r.legacy_tls,
             'san_count': len(r.sans or [])} for r in rows]


def _inventory(project_id, host):
    """The host's own report (cveFeed.host_inventory), when that feature is installed: OS, kernel and package counts, never the list."""
    try:
        from cveFeed.models import HostInventory
    except ImportError:
        return None
    row = HostInventory.objects.filter(project_id=project_id, host=host).order_by('-reported_at').first()
    if row is None:
        return None
    return {'os': _s(f'{row.os_name} {row.os_version}', 100), 'kernel': _s(row.os_kernel, 60), 'packages': row.package_count,
            'reported_at': row.reported_at.isoformat()}


def _steps(project_id, host):
    from cveFeed.models import Triage
    out = []
    for row in Triage.objects.filter(project_id=project_id, host=host).exclude(validation_steps=[]).order_by('-validated_at')[:4]:
        for step in (row.validation_steps or [])[-3:]:
            out.append({'kind': _s(step.get('kind'), 20), 'result': _s(step.get('result'), 20), 'summary': _s(step.get('summary'), 160)})
    return out[:MAX_STEPS]


def _matches(sub, names):
    from cveFeed.models import CVEMatch
    rows = CVEMatch.objects.filter(subdomain=sub).select_related('cve_entry').order_by('-confidence', 'cve_entry__cve_id', 'matched_product', 'matched_version', 'source', 'id')[:MAX_MATCHES]
    return [{'cve': r.cve_entry.cve_id, 'product': _s(r.matched_product, 60, names), 'version': _s(r.matched_version, 40, names),
             'in_range': r.version_in_range, 'verdict': r.ai_verdict} for r in rows]


def _probe_rows(project_id, host):
    from cveFeed.models import ProbeObservation
    # the virtual host sweep's rows name an address in ``product``: the model is never given an address; the OpenVAS add-on's rows are its own evidence, not version probes
    return list(ProbeObservation.objects.filter(project_id=project_id, host=host).exclude(kind='vhost').exclude(probe='openvas').order_by('-observed_at')[:MAX_PROBES])


def _probes(rows, names):
    return [{'probe': r.probe, 'kind': r.kind, 'product': _s(r.product, 60, names), 'version': _s(r.version, 40, names),
             'variant': _s(r.variant, 40, names), 'outcome': r.outcome, 'confidence': round(r.confidence, 2), 'source': _s(r.source, 40),
             'port': r.port, 'observed': r.observed_at.date().isoformat()} for r in rows]


def wordpress_summary(rows):
    """Where WordPress stands on a host, from its probe rows (the WordPress probe and WPScan write them): ``status`` (see
    ``wpscan_scan.state_of``: detected how, scanned when or why not), the core version and the plugins and themes with versions. None when
    nothing suggests WordPress."""
    from cveFeed import wpscan_scan
    state = wpscan_scan.state_of(rows)
    plugins = [{'slug': r.product, 'title': (r.evidence or {}).get('title', ''), 'version': r.version, 'latest': (r.evidence or {}).get('latest', ''),
                'outdated': bool((r.evidence or {}).get('outdated')), 'source': r.source} for r in sorted(rows, key=lambda r: r.product) if r.kind == 'wp-plugin']
    themes = [{'slug': r.product, 'version': r.version, 'source': r.source} for r in sorted(rows, key=lambda r: r.product) if r.kind == 'wp-theme']
    if state is None and not plugins and not themes:
        return None
    core = next((r.version for r in rows if r.probe == 'wpscan-core' and r.version), '') or (state or {}).get('core', '')
    return {'status': state, 'core': core, 'plugins': plugins[:40], 'themes': themes[:10]}


def host_context(sub, project_id=None, focus=None):
    """The host's context dict (see the module docstring). ``sub`` is a Subdomain with ``technologies``, ``ip_addresses__ports`` and
    ``waf`` ideally prefetched; ``focus`` (a product name) puts that product's leads and probe rows first. Pure reads, bounded."""
    from cveFeed import hosting, probes
    from cveFeed.models import HostLabel
    project_id = project_id or (sub.target_domain.project_id if sub.target_domain_id else None)
    host = sub.name.lower()
    names = _names_of(sub)
    root = _root_route(sub, project_id)
    evidence = dict((root.evidence or {}) if root else {})
    rows = _probe_rows(project_id, host)
    route_headers = evidence.get('headers') or {}
    observed = {f['name']: f['source'] for f in evidence.get('fingerprints') or []}
    observed.update({(f'{r.product}:{r.version}' if r.version else r.product): r.source for r in rows if r.kind == 'version'})
    edge = edge_of(sub, project_id, rows, route_headers)
    ips = list(sub.ip_addresses.all())
    info = hosting.classify(name=sub.name, cname=sub.cname or '', webserver=sub.webserver or '', cdn_name=sub.cdn_name or '',
                            reverse_pointers=[ip.reverse_pointer for ip in ips if ip.reverse_pointer],
                            is_cdn=bool(sub.is_cdn or any(ip.is_cdn for ip in ips)))
    web = {'status': sub.http_status or (root.http_status if root else 0), 'title': _s(sub.page_title or (root.title if root else ''), 100, names),
           'server': _s(sub.webserver or evidence.get('server'), 100, names), 'powered_by': _s(evidence.get('powered_by'), 80, names),
           'redirects': bool(root and root.redirect_to),
           'kept_response_headers': [_s(f'{k}: {v}', 140, names) for k, v in list(route_headers.items())[:30]]}
    context = {
        'technologies': _technologies(sub, names, observed, evidence.get('libraries') if isinstance(evidence.get('libraries'), dict) else None),
        'unversioned_products': [{k: _s(v, 80, names) for k, v in lead.items() if k in ('name', 'source', 'port', 'service')}
                                 for lead in probes.leads_for(sub)][:20],
        'ports': _ports(sub, names), 'web': web,
        'hosting': {k: _s(info.get(k), 60, names) for k in ('provider', 'kind', 'infrastructure')} | {'shared_ip': info['shared_ip']},
        'edge': {**edge, 'note': EDGE_NOTE if edge['fronted'] else ''},
        'labels': sorted({_s(label, 40) for label in HostLabel.objects.filter(project_id=project_id, host=host).values_list('label', flat=True)[:30]}),
        'operating_system': _os(sub, names), 'tailscale': _tailscale(project_id, host), 'certificates': _certificates(project_id, host), 'host_inventory': _inventory(project_id, host),
        'probe_results': _probes(rows, names), 'earlier_checks': _steps(project_id, host), 'other_cve_matches': _matches(sub, names),
        'wordpress': wordpress_summary(rows),
        'rules': [UNVERSIONED_NOTE] + ([EDGE_NOTE] if edge['fronted'] else []),
    }
    if focus:
        key = re.sub(r'[^a-z0-9]', '', str(focus).lower())
        context['technologies'].sort(key=lambda t: re.sub(r'[^a-z0-9]', '', t['name'].lower()) != key)
    if not context['host_inventory']:
        context['host_inventory'] = None
        context['notes'] = ['No host inventory report exists for this host: a kernel, driver or package level cannot be read from the network. '
                            'Only the host inventory reporter can place them.']
    return context


def signal_digest(context):
    """A short hash of what probes and edges said about a host, or '' when they said nothing. Folded into a finding's signature so a
    verdict is re-asked when a probe changes the picture, while a host nothing probed keeps its old signature (and its verdict)."""
    parts = {'edge': (context.get('edge') or {}).get('providers'),
             'probes': [(p['probe'], p['product'], p['version'], p['variant'], p['outcome']) for p in context.get('probe_results') or []]}
    if not parts['edge'] and not parts['probes']:
        return ''
    return hashlib.sha1(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:12]


# What a re-scan or a clock changes without the host having changed. ``stable_view`` (the host text key of a match's signature) leaves these
# out, so the same host evidence is the same key tomorrow (issue 338 follow-up: one AI review per rescan for every match without a floor).
PER_REQUEST_HEADERS = frozenset({'cf-ray', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-request-id', 'x-fastly-request-id', 'x-azure-ref', 'x-nf-request-id',
                                 'x-vercel-id', 'x-sucuri-id', 'x-served-by', 'x-envoy-upstream-service-time', 'x-iinfo'})  # a new value on every response
CACHE_STATE_HEADERS = frozenset({'x-cache', 'cf-cache-status', 'x-nextjs-cache', 'x-drupal-cache', 'x-litespeed-cache',
                                 'x-magento-cache-debug'})  # HIT or MISS, depending on who asked last
_HEADER = re.compile(r'^\s*([a-z0-9-]+)\s*:')
_NONCE = re.compile(r"nonce-[A-Za-z0-9+/_=-]+", re.I)  # a Content-Security-Policy nonce is new on every response
_CLOCK = re.compile(r'\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b')  # a time of day in a banner or a check summary
_MONTH = r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*'
# a whole timestamp in a banner (Exim, Sendmail and Microsoft SMTP greet with "Sun, 01 Nov 2026 10:15:32 +0000"; others write ISO 8601): the date
# moves daily and the time every second, so both go. A date with no time of day stays (a certificate's expiry is one).
_TIMESTAMP = re.compile(rf'(?:\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+)?\b\d{{1,2}}[ -]{_MONTH}[ -]\d{{2,4}}\s+\d{{1,2}}:\d{{2}}(?::\d{{2}})?'
                        rf'(?:\.\d+)?(?:\s*(?:Z|UTC|GMT|[+-]\d{{2}}:?\d{{2}}))?'
                        rf'|\b\d{{4}}-\d{{2}}-\d{{2}}[T ]\d{{1,2}}:\d{{2}}(?::\d{{2}})?(?:\.\d+)?(?:Z|[+-]\d{{2}}:?\d{{2}})?', re.I)
_CLOUDFRONT_EDGE = re.compile(r'\b[0-9a-f]{8,}\.cloudfront\.net\b', re.I)  # the edge node that answered, in "via: 1.1 <id>.cloudfront.net (CloudFront)"
CERT_SOON_DAYS = 30


def _stable_text(text, dates=True):
    text = _CLOUDFRONT_EDGE.sub('*.cloudfront.net', _NONCE.sub('nonce-*', text))
    return _CLOCK.sub('hh:mm:ss', _TIMESTAMP.sub('timestamp', text) if dates else text)


def _stable_header(line):
    """``name: value`` with the value of a header that changes on every response (or with the cache's state) left out; the header being present
    is what stays (it names the edge, the cache or the proxy)."""
    match = _HEADER.match(line)
    if match and match.group(1) in PER_REQUEST_HEADERS | CACHE_STATE_HEADERS:
        return f'{match.group(1)}: *'
    return line


def _certificate_state(days_left):
    return days_left if days_left is None else ('expired' if days_left < 0 else 'expiring' if days_left <= CERT_SOON_DAYS else 'valid')


def _canonical(items):
    """``items`` in an order that does not depend on the order the database returned them in (or on which row was written last)."""
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str))


def _stable(value, key=''):
    if isinstance(value, str):
        text = _stable_text(value, dates=key != 'certificate')  # a certificate's expiry date is evidence (a renewal), unlike a banner's clock
        return _stable_header(text) if key == 'kept_response_headers' else text
    if isinstance(value, dict):
        return {k: _stable(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stable(v, key) for v in value]
    return value


def stable_view(context):
    """``context`` without what changes while the host does not, or what only a host chooses to say. It is both what the model is SHOWN in a
    triage prompt (``clipped(..., stable=True)``) and what a match's host text key is made of (``triage.bind_host_text``): the verdict a
    model gives is stored under a signature shared by every host and project with the same signature, so any host-controlled text it was
    shown has to be in the key, and what is left out of the key has to be left out of the prompt. Per field:

    - certificate ``days_left``: replaced by ``expiry`` (expired, expiring within CERT_SOON_DAYS days, or valid);
    - probe ``observed``, host inventory ``reported_at`` and ``packages``, Tailscale ``online``: removed;
    - the AI's ``verdict`` on the host's other matches (this match's own among them): blanked (a rescan's new row of the match starts with
      none; the verdict of another CVE flipping does not re-ask this one);
    - per-request and cache-state response headers (and Imperva's ``x-iinfo``): the header stays, its value is ``*``;
    - Content-Security-Policy nonces, the CloudFront edge node in ``via``, whole timestamps and times of day in banners and check summaries
      (a certificate's expiry date in a port record is kept): masked;
    - probe results, certificates, and ports on one number: sorted, they have no order of their own.

    A value that is evidence (a product, a version, an outcome, a banner, a header's content, a certificate's issuer, expired or not) stays."""
    if not isinstance(context, dict):
        return context
    out = _stable(context)
    if isinstance(out.get('certificates'), list):
        certs = [{k: v for k, v in c.items() if k != 'days_left'} | {'expiry': _certificate_state(c.get('days_left'))}
                 if isinstance(c, dict) and 'days_left' in c else c for c in out['certificates']]
        out['certificates'] = _canonical(certs)
    if isinstance(out.get('probe_results'), list):
        out['probe_results'] = _canonical([{k: v for k, v in p.items() if k != 'observed'} if isinstance(p, dict) else p
                                           for p in out['probe_results']])
    if isinstance(out.get('host_inventory'), dict):
        out['host_inventory'] = {k: v for k, v in out['host_inventory'].items() if k not in ('reported_at', 'packages')}
    if isinstance(out.get('other_cve_matches'), list):
        # the AI's verdicts on this host's matches (this match's own among them) are answers, not host evidence: the review writes this match's
        # verdict, and a rescan's new row of it starts with none, so the key moved from one scan to the next. Blanked, not removed, so a host
        # whose matches had no verdict yet keeps the key it had.
        out['other_cve_matches'] = [{**m, 'verdict': ''} if isinstance(m, dict) and 'verdict' in m else m for m in out['other_cve_matches']]
    if isinstance(out.get('tailscale'), dict):
        out['tailscale'] = {k: v for k, v in out['tailscale'].items() if k != 'online'}
    if isinstance(out.get('ports'), list):
        out['ports'] = sorted(out['ports'], key=lambda p: (p.get('number', 0) if isinstance(p, dict) else 0,
                                                           json.dumps(p, sort_keys=True, default=str)))
    return out


def _deep(value, depth=0):
    """Every string cleaned to the identifier-like alphabet and every container bounded: what the AI prompts get is safe at any depth."""
    if isinstance(value, str):
        return clean_text(value, 400, strict=True)
    if isinstance(value, dict) and depth < 6:
        return {clean_text(k, 60, strict=True): _deep(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)) and depth < 6:
        return [_deep(v, depth + 1) for v in list(value)[:40]]
    return value if value is None or isinstance(value, (bool, int, float)) else clean_text(value, 100, strict=True)


def clipped(context, limit=9000, stable=False):
    """``context`` as prompt-safe data no larger than ``limit`` characters once serialised: cleaned at every depth, put through ``stable_view``
    when ``stable`` (before the long sections are halved, so what is cut is the end of a sorted list), then halved until it fits."""
    data = _deep(context)
    if stable:
        data = stable_view(data)
    for key in ('earlier_checks', 'other_cve_matches', 'probe_results', 'ports', 'technologies', 'certificates'):
        if len(json.dumps(data)) <= limit:
            break
        data[key] = (data.get(key) or [])[:max(1, len(data.get(key) or []) // 2)]
    return data
