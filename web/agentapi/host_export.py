"""Export of every discovered host: a scope list for an external penetration test (REST and MCP).

``GET projects/{slug}/hosts/export`` and ``GET orgs/{org}/hosts/export`` answer a file (CSV or a plain list a scanner reads as its target file) of the hosts
the Hosts page lists, with what a tester needs to scope the work (names, addresses, open ports and services, web URLs, where each host was
found) and nothing about the customer's security posture: no findings, CVE matches, heat, score, notes, owners or labels.

What is left out, always: a host the organization removed and excluded (or moved out of the project), an address on the organization's
do-not-scan list. By default also: a host in a network the project declared internal, a private or reserved address (``is_public_address``), and an archived host.

Access is the Hosts page's own: ``get_one_project`` for one project; for an organization, only the projects of it the caller can see. Everything
that can refuse, and the audit line, happens before the first byte, because a stream cannot turn into a JSON error half way. The file is then read in
chunks of ``CHUNK`` hosts, so a project with a hundred thousand hosts is never held in memory as rows, and there is no row cap.
"""
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from agentapi import services as svc
from agentapi.services import ApiError
from tenancy import audit

CHUNK = 500
LOOKUP_CHUNK = 2000  # ids in one IN list
FORMATS = ('csv', 'txt')
SCOPES = ('external', 'all')
MCP_MAX_BYTES = 3 * 1024 * 1024  # an MCP answer is capped at 4 MiB in all (agentapi.mcp.MAX_RESPONSE_BYTES): a bigger file is downloaded from REST
COLUMNS = ('Host', 'IP addresses', 'Open TCP ports', 'Open UDP ports', 'Services', 'Web URLs', 'Project', 'Organization', 'Target', 'First seen', 'Last seen')
BOM = '﻿'  # makes Excel read the file as UTF-8
_FORMULA = re.compile(r'^[=+\-@\t\r]')
WEB_PORTS_TLS = (443, 8443)


def cell(value):
    """One CSV cell, as ``static/cve/csv.js`` ``csvCell`` makes it: a value a spreadsheet would run as a formula (a leading = + - @, tab or
    carriage return) gets an apostrophe in front, and a cell with a quote, comma or line break is quoted."""
    text = '' if value is None else '; '.join(str(v) for v in value) if isinstance(value, (list, tuple)) else str(value)
    text = text.replace('\x00', '')
    if _FORMULA.match(text):
        text = "'" + text
    return '"' + text.replace('"', '""') + '"' if re.search(r'[",\r\n]', text) else text


def _flag(params, name):
    value = params.get(name)
    if value in (None, ''):
        return False
    text = str(value).strip().lower()
    if text in ('1', 'true', 'yes'):
        return True
    if text in ('0', 'false', 'no'):
        return False
    raise ApiError(400, f'{name} must be 0 or 1')


def _choice(params, name, allowed, default):
    value = str(params.get(name) or default).strip().lower()
    if value not in allowed:
        raise ApiError(400, f'{name} must be one of {", ".join(allowed)}')
    return value


def _literal(name):
    """The address ``name`` is when a host is named by one (bracketed or not), else None."""
    try:
        return str(ipaddress.ip_address(str(name).strip().strip('[]')))
    except ValueError:
        return None


def _ip_key(address):
    ip = ipaddress.ip_address(address)
    return (ip.version, int(ip))


def _sorted_addresses(addresses):
    good = {a for a in addresses if _literal(a)}
    return sorted(good, key=_ip_key)


def _iso(value):
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if value else ''


def _projects(ctx, slug, org_slug):
    """``(label for the file name, [projects])``: the one project (any role may read it), or the projects of the organization that the caller may see."""
    from agentapi import report_scope
    scope = report_scope.resolve(ctx, project=slug, org=org_slug)  # both or neither is a 400; _all is a 400; a missing or foreign organization is a 404
    return scope.slug, scope.projects


def _plan(project, external, include_archived):
    """``[(subdomain id, host name, [addresses])]`` for the hosts of one project that belong in the file, by name. The host list is the Hosts page's:
    each host's current inventory, one row per host (names on the same addresses are one host)."""
    from cveFeed import exclusions, internal_view
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import HostState
    from startScan.models import Subdomain
    from targetApp.target_types import is_public_address
    excluded = exclusions.excluded_names(project.pk)  # the removed-and-excluded names, the hosts moved away, and the do-not-scan addresses
    if excluded.unreadable:
        raise ApiError(503, "the organization's do-not-scan address list could not be read, so no host list is made until it can be: try again shortly")
    archived = set() if include_archived else {h.lower() for h in HostState.objects.filter(project=project, archived_at__isnull=False).values_list('host', flat=True)}
    qs = Subdomain.objects.filter(target_domain__project=project).filter(latest_scan_q())
    rows = list(svc._one_per_host(qs).values_list('pk', 'name'))
    through = Subdomain.ip_addresses.through
    found = {}
    for start in range(0, len(rows), LOOKUP_CHUNK):
        ids = [pk for pk, _ in rows[start:start + LOOKUP_CHUNK]]
        for sub_id, address in through.objects.filter(subdomain_id__in=ids).values_list('subdomain_id', 'ipaddress__address'):
            if address:
                found.setdefault(sub_id, set()).add(address.strip())
    plan = []
    for pk, name in rows:
        name = (name or '').strip().lower().rstrip('.')
        if not name or exclusions.normalize(name) in excluded or name in archived:
            continue
        addresses = _sorted_addresses(found.get(pk, ()))
        kept = [a for a in addresses if a not in excluded]  # an address the organization said must never be scanned is not in a scope list
        if addresses and not kept:
            continue
        if external:
            literal = _literal(name)
            if internal_view.is_internal(project.pk, name) or (literal and not is_public_address(literal)):
                continue
            public = [a for a in kept if is_public_address(a)]
            if kept and not public:  # it resolves only to private or reserved addresses: an internal host
                continue
            kept = public
        plan.append((pk, name, kept))
    plan.sort(key=lambda row: (row[1], row[0]))
    return plan


def _is_web(port):
    service = (port.service_name or '').lower()
    return 'http' in service or bool(port.http)


def _web_url(name, port):
    service = (port.service_name or '').lower()
    tls = 'https' in service or 'ssl' in service or bool(port.tls) or (port.extra or {}).get('tunnel') == 'ssl' or port.number in WEB_PORTS_TLS
    scheme = 'https' if tls else 'http'
    default = 443 if tls else 80
    host = f'[{name}]' if ':' in name else name
    return f'{scheme}://{host}/' if port.number == default else f'{scheme}://{host}:{port.number}/'


def _root_of(url, external, is_public_address):
    """The ``scheme://host[:port]/`` of a stored page address, or '' for anything that is not a web page (no path, query or credentials are kept)."""
    try:
        parts = urlsplit(str(url or '').strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return ''
    if parts.scheme not in ('http', 'https') or not host:
        return ''
    literal = _literal(host)
    if external and literal and not is_public_address(literal):
        return ''
    shown = f'[{host}]' if ':' in host else host
    return f'{parts.scheme}://{shown}/' if port in (None, 80 if parts.scheme == 'http' else 443) else f'{parts.scheme}://{shown}:{port}/'


def _rows(project, plan, external):
    """The CSV rows (as lists) of one project's planned hosts, ``CHUNK`` at a time."""
    from cveFeed.models import HostState
    from startScan.models import Subdomain, open_services
    from targetApp.target_types import is_public_address
    org_name = project.org.name if project.org_id else ''
    for start in range(0, len(plan), CHUNK):
        part = plan[start:start + CHUNK]
        subs = {s.pk: s for s in Subdomain._base_manager.filter(pk__in=[p[0] for p in part]).select_related('target_domain').prefetch_related('ip_addresses__ports')}
        states = {s.host.lower(): s for s in HostState.objects.filter(project=project, host__in={p[1] for p in part})}
        for pk, name, addresses in part:
            sub = subs.get(pk)
            if sub is None:  # removed while the file was being written
                continue
            keep = set(addresses)
            services = {}
            urls = set()
            for ip in sub.ip_addresses.all():
                if ip.address and ip.address.strip() not in keep:
                    continue
                for port in open_services(ip):
                    proto = 'udp' if port.protocol == 'udp' else 'tcp'
                    label = ' '.join(x for x in (port.product or port.service_name or '', port.version or '') if x)
                    key = (port.number, proto)
                    if key not in services or (label and not services[key][1]):
                        services[key] = (port, label)
                    if proto == 'tcp' and _is_web(port):
                        urls.add(_web_url(name, port))
            root = _root_of(sub.http_url, external, is_public_address)
            if root:
                urls.add(root)
            ordered = sorted(services.items())
            state = states.get(name)
            first = state.first_seen if state else sub.discovered_date
            last = state.last_seen if state else sub.discovered_date
            yield [name, ' '.join(addresses),
                   ' '.join(str(n) for (n, proto), _ in ordered if proto == 'tcp'), ' '.join(str(n) for (n, proto), _ in ordered if proto == 'udp'),
                   '; '.join(f'{n}/{proto} {label}'.strip() for (n, proto), (_, label) in ordered), '; '.join(sorted(urls)),
                   project.name, org_name, sub.target_domain.name if sub.target_domain_id else '', _iso(first), _iso(last)]


class Export:
    """What an export is, before any of it is written: its file name, type, how many hosts and lines it holds, and the chunks of its text."""

    def __init__(self, label, projects, plans, fmt, scope, include_archived):
        self.projects, self.plans, self.format, self.scope, self.include_archived = projects, plans, fmt, scope, include_archived
        self.label = label
        self.hosts = sum(len(p) for p in plans)
        self.entries = self.hosts if fmt == 'csv' else len(self._txt_lines())
        self.filename = f'cvengine-hosts-{label}-{datetime.now(timezone.utc).strftime("%Y-%m-%d")}.{fmt}'
        self.content_type = 'text/csv; charset=utf-8' if fmt == 'csv' else 'text/plain; charset=utf-8'

    def _txt_lines(self):
        """Every host name, then every address: each once, names in alphabetical order and addresses in numeric order, ready for a scanner's target-list option."""
        if not hasattr(self, '_lines'):
            names, addresses = set(), set()
            for plan in self.plans:
                for _, name, found in plan:
                    literal = _literal(name)
                    (addresses if literal else names).add(literal or name)
                    addresses.update(found)
            self._lines = sorted(names) + _sorted_addresses(addresses)
        return self._lines

    def chunks(self):
        if self.format == 'txt':
            lines = self._txt_lines()
            for start in range(0, len(lines), 1000):
                yield ''.join(f'{line}\n' for line in lines[start:start + 1000])
            return
        yield BOM + ','.join(cell(c) for c in COLUMNS) + '\r\n'
        external = self.scope == 'external'
        for project, plan in zip(self.projects, self.plans):
            for row in _rows(project, plan, external):
                yield ','.join(cell(c) for c in row) + '\r\n'

    def text(self):
        return ''.join(self.chunks())


def prepare(ctx, params, slug=None, org=None):
    """Check access and the parameters, work out which hosts belong in the file and write the audit line: everything that can refuse, before a byte is sent."""
    fmt, scope = _choice(params, 'format', FORMATS, 'csv'), _choice(params, 'scope', SCOPES, 'external')
    include_archived = _flag(params, 'archived')
    label, projects = _projects(ctx, slug, org)
    plans = [_plan(p, scope == 'external', include_archived) for p in projects]
    export = Export(label, projects, plans, fmt, scope, include_archived)
    org_id = projects[0].org_id if slug and projects else None
    if org:
        from dashboard.models import Org
        org_id = Org.objects.filter(slug=str(org)).values_list('pk', flat=True).first()
    audit.record(ctx.user, 'host.export', f'{label}: {fmt}, {"internet-facing hosts" if scope == "external" else "all hosts incl. internal"}'
                 f'{", incl. archived" if include_archived else ""}', org=org_id, project=slug or None, organization=org or None,
                 projects=[p.slug for p in projects], format=fmt, scope=scope, archived=include_archived, hosts=export.hosts)
    return export


def response(ctx, params, slug=None, org=None):
    """The streamed download for ``GET projects/{slug}/hosts/export`` and ``GET orgs/{org}/hosts/export``."""
    from django.http import StreamingHttpResponse
    export = prepare(ctx, params, slug=slug, org=org)
    out = StreamingHttpResponse(export.chunks(), content_type=export.content_type)
    out['Content-Disposition'] = f'attachment; filename="{export.filename}"'
    out['Cache-Control'] = 'no-store'
    out['X-Export-Hosts'] = str(export.hosts)  # the count the page shows: known before the first byte, so a header can carry it
    out['X-Export-Entries'] = str(export.entries)
    return out


def tool(ctx, args):
    """The MCP tool ``export_hosts``: the same file as text, with its name and counts (a file too big for an MCP answer is a 413 that points at REST)."""
    export = prepare(ctx, args, slug=args.get('project'), org=args.get('org'))
    # the text is gathered chunk by chunk and given up as soon as it is past the cap: a file too big for an answer is refused after the chunks
    # that pass the cap, not after every chunk of the project was read (the size only grows, so the answer is the same)
    parts, size, chunks = [], 0, export.chunks()
    try:
        for part in chunks:
            parts.append(part)
            size += len(part.encode('utf-8'))
            if size > MCP_MAX_BYTES:
                break
    finally:
        chunks.close()
    text = ''.join(parts)
    if size > MCP_MAX_BYTES:
        raise ApiError(413, f'the list is too large for an MCP answer ({export.hosts} hosts): download it with GET {"orgs" if args.get("org") else "projects"}/'
                       f'{args.get("org") or args.get("project")}/hosts/export, or narrow it with scope=external and archived=0')
    return {'filename': export.filename, 'format': export.format, 'scope': export.scope, 'archived': export.include_archived, 'hosts': export.hosts,
            'entries': export.entries, 'projects': [p.slug for p in export.projects], 'content': text}
