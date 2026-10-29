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


def _technologies(sub, names, observed):
    from cveFeed import fingerprint
    from cveFeed.correlation import split_name_version
    out = []
    for tech in sub.technologies.all()[:200]:
        base, version = split_name_version(tech.name or '')
        out.append({'name': _s(base or tech.name, 60, names), 'version': _s(version, 40, names), 'category': fingerprint.categorize(tech.name or ''),
                    'source': observed.get(tech.name, 'scan')})
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
    guesses = []
    facts = {}
    for ip in sub.ip_addresses.all():
        fingerprint = ip.fingerprint or {}
        if ip.os_guess:
            guesses.append({'guess': _s(ip.os_guess, 80, names), 'accuracy': ip.os_accuracy,
                            'alternatives': [_s(m.get('name'), 80, names) for m in (fingerprint.get('os_matches') or [])[1:3] if isinstance(m, dict)]})
        for key in ('runzero', 'facts'):
            if isinstance(fingerprint.get(key), dict):
                facts.setdefault(key, {k: _s(v, 80, names) for k, v in list(fingerprint[key].items())[:12] if isinstance(v, (str, int, float))})
    return {'guesses': guesses[:3], 'reported_by_other_tools': facts}


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
    rows = CVEMatch.objects.filter(subdomain=sub).select_related('cve_entry').order_by('-confidence')[:MAX_MATCHES]
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
        'technologies': _technologies(sub, names, observed),
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


def _deep(value, depth=0):
    """Every string cleaned to the identifier-like alphabet and every container bounded: what the AI prompts get is safe at any depth."""
    if isinstance(value, str):
        return clean_text(value, 400, strict=True)
    if isinstance(value, dict) and depth < 6:
        return {clean_text(k, 60, strict=True): _deep(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)) and depth < 6:
        return [_deep(v, depth + 1) for v in list(value)[:40]]
    return value if value is None or isinstance(value, (bool, int, float)) else clean_text(value, 100, strict=True)


def clipped(context, limit=9000):
    """``context`` as prompt-safe data no larger than ``limit`` characters once serialised: cleaned at every depth, then the long sections are
    halved until it fits."""
    data = _deep(context)
    for key in ('earlier_checks', 'other_cve_matches', 'probe_results', 'ports', 'technologies', 'certificates'):
        if len(json.dumps(data)) <= limit:
            break
        data[key] = (data.get(key) or [])[:max(1, len(data.get(key) or []) // 2)]
    return data
