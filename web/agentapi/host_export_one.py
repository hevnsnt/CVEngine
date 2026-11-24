"""Export of one host: everything cvENGINE knows about it, as a ZIP file (REST) or as the JSON record alone (MCP).

``GET projects/{slug}/hosts/{host_id}/export`` answers ``host-<name>-<date>.zip``, streamed. It holds:

* ``host.json``: the complete structured record, versioned by its ``schema`` field (``SCHEMA``). Identity (names, aliases, addresses, hosting,
  state, first and last seen, labels, heat, score and its reasons), services and ports, web data (routes, title, headers, technologies with
  versions and sources, certificates), findings of every kind (CVE matches with their explanation and triage, scanner findings, hygiene
  findings) with status, heat, severity, assignment, retest state and comment counts, exposed secrets (masked only), the full change history,
  the host's own inventory report, probes and check coverage, the scans that saw it, the latest host assessment and AI review, and the
  manifest of the screenshots.
* ``findings.csv``, ``services.csv``, ``history.csv``, ``certificates.csv`` and ``inventory.csv``: the tabular parts, one row each, every cell
  through ``host_export.cell`` (a value a spreadsheet would run as a formula gets an apostrophe in front).
* ``screenshots/``: the browser captures of the host's pages (and RDP login screens), as the stored image files.
* ``README.txt``: what each file holds, when it was made and by which cvENGINE version, and what was left out.

The MCP tool ``export_host`` returns ``host.json`` as text only (no images: the answer names the REST route for them), up to ``MCP_MAX_BYTES``.

Access is the host page's own: the caller must be able to read the project (``get_one_project``: any role, a read-only token too), and the host
id must be a host row of that project, else a 404 (an id from another project is a 404, never a 403). Every read, every refusal and the audit
line (``host.export``, as the Export all hosts file) happen before the first byte. The record is gathered with a fixed number of statements
whatever the number of findings (lists are read in chunks of ``CHUNK`` rows, each chunk a fixed number of statements), each list is capped at
``MAX_ROWS`` rows (the record says when one was cut), and the screenshots are capped at ``MAX_SCREENSHOT_FILES`` files and
``MAX_SCREENSHOT_BYTES`` bytes in all (the README and the manifest name the ones left out). The ZIP is written as it is sent, so the images are
never held in memory at once.

No secret value is ever written: exposed secrets appear as their mask (``AIza…x7Qz``) only, and any value stored under a key that names a
credential (an Authorization header, a cookie, a password, a token, an API key) is replaced with ``MASK`` wherever it appears in the record.
"""
import csv
import io
import json
import os
import re
import zipfile
from datetime import datetime, timezone

from agentapi import services as svc
from agentapi.host_export import BOM, cell
from agentapi.services import ApiError

SCHEMA = 'cvengine.host-export/1'
CHUNK = 500  # finding rows serialised per round: a fixed number of statements per round, whatever the round holds
MAX_ROWS = 20000  # most rows of one list (findings of one kind, history, routes, probes, packages): a host past this is cut, and the record says so
MAX_NAMES = 50  # the host's own name and at most this many other names on its addresses
MAX_SCREENSHOT_FILES = 60
MAX_SCREENSHOT_BYTES = 64 * 1024 * 1024  # all images together; a capture is at most a few MB (cveFeed.web_shot.max_bytes)
MCP_MAX_BYTES = 3 * 1024 * 1024  # an MCP answer is capped at 4 MiB in all (agentapi.mcp.MAX_RESPONSE_BYTES)
READ_CHUNK = 64 * 1024
MASK = '[masked]'
# keys whose value is a credential wherever they appear in the record (headers, evidence, facts): replaced with MASK, never written
_SECRET_KEYS = re.compile(r'^(authorization|proxy[-_]authorization|cookie|set[-_]cookie|password|passwd|pass|pwd|secret|secret[-_]value|value_raw|raw_value|'
                          r'token|access[-_]token|refresh[-_]token|id[-_]token|bearer|api[-_]?key|x[-_]api[-_]key|private[-_]key|client[-_]secret|'
                          r'credential|credentials|session[-_]?id|sessionid)$', re.IGNORECASE)


def _iso(value):
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if value else None


def scrub(value):
    """``value`` with every value stored under a credential key replaced by ``MASK`` (dicts and lists, all the way down)."""
    if isinstance(value, dict):
        return {k: (MASK if _SECRET_KEYS.match(str(k)) and v not in (None, '', [], {}) else scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    return value


def _host_row(ctx, slug, host_id):
    """``(project, sub)``: the host row of the project, or a 404 (an id of another project included). Any role that reads the project may export."""
    from startScan.models import Subdomain
    project, _ = svc.get_one_project(ctx, slug)
    sub = (Subdomain.objects.filter(pk=svc._host_id(host_id), target_domain__project=project).select_related('target_domain')
           .prefetch_related('ip_addresses__ports', 'cve_matches__cve_entry', svc.triage_prefetch('cve_matches__triage'), 'vulnerability_set',
                             svc.triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags', 'technologies')
           .first())
    if not sub:
        raise ApiError(404, 'host not found')
    return project, sub


def _name_q(names, field):
    from django.db.models import Q
    q = Q()
    for name in names:
        q |= Q(**{f'{field}__iexact': name})
    return q


def _capped(qs):
    """``(rows, cut)``: at most ``MAX_ROWS`` rows of ``qs`` and whether there were more."""
    limit = MAX_ROWS
    rows = list(qs[:limit + 1])
    return rows[:limit], len(rows) > limit


def _findings(project, names, current_ids):
    """Every finding of the host's names, of every kind and every status, hottest first: ``({kind: [rows]}, {kind: cut})``."""
    from cveFeed import match_explain
    from startScan.models import Subdomain
    sources = svc._finding_sources(project, {'status': 'all'}, current_ids=current_ids)
    sources['cve'] = sources['cve'].filter(_name_q(names, 'subdomain__name'))
    sources['scanner'] = sources['scanner'].filter(_name_q(names, 'subdomain__name')).prefetch_related('cve_ids')
    sources['hygiene'] = sources['hygiene'].filter(_name_q(names, 'host'))
    hint = None
    out, cut = {}, {}
    for kind, qs in sources.items():
        ids = list(qs.values_list('pk', flat=True)[:MAX_ROWS + 1])
        cut[kind] = len(ids) > MAX_ROWS
        ids = ids[:MAX_ROWS]
        rows = []
        for start in range(0, len(ids), CHUNK):
            part = ids[start:start + CHUNK]
            loaded = {obj.pk: obj for obj in qs.filter(pk__in=part)}
            chunk = []
            for pk in part:
                obj = loaded.get(pk)
                if obj is None:
                    continue
                row = svc._finding_row(kind, obj)
                if kind == 'cve':
                    if hint is None:
                        first = Subdomain.objects.filter(pk=obj.subdomain_id).prefetch_related('ip_addresses__ports', 'technologies').first()
                        hint = match_explain.host_hint(first) if first else ''
                    row.update({'cve_id': obj.cve_entry.cve_id, 'product': obj.matched_product, 'version': obj.matched_version,
                                'in_affected_range': obj.version_in_range, 'confidence': obj.confidence, 'source': obj.source,
                                'ai_verdict': obj.ai_verdict, 'ai_reason': obj.ai_reason, 'distro_status': obj.distro_status,
                                'distro_fixed_version': obj.distro_fixed_version, 'evidence': obj.evidence or {},
                                'template_id': obj.template_id, 'template_result': obj.template_result,
                                'template_tested': _iso(obj.template_tested_at), 'explain': svc._explain(obj, hint)})
                elif kind == 'scanner':
                    row.update({'cves': [c.name for c in obj.cve_ids.all()], 'url': obj.http_url, 'description': obj.description,
                                'remediation': obj.remediation, 'open': obj.open_status})
                else:
                    row.update({'check': obj.check_name, 'detail': obj.detail, 'evidence': obj.evidence, 'hygiene_status': obj.status,
                                'last_seen': _iso(obj.last_seen)})
                chunk.append(row)
            rows += svc._attach_reviews(chunk)
        out[kind] = rows
    return out, cut


def _current_ids(project, names):
    """The current inventory rows of the host's names (the CVE match list reads them first: see ``services._current_named_ids``)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    named = list(Subdomain.objects.filter(target_domain__project=project).filter(_name_q(names, 'name')).order_by().values_list('pk', flat=True))
    if not named:
        return []
    return list(Subdomain.objects.filter(id__in_array=svc._id_array(named)).filter(latest_scan_q()).order_by().values_list('pk', flat=True))


def _history(project, names):
    from cveFeed.models import AssetChange
    rows, cut = _capped(AssetChange.objects.filter(project=project).filter(_name_q(names, 'host')).select_related('domain').order_by('-detected_at', '-id'))
    return [svc._change(c) for c in rows], cut


def _certificates(project, names):
    from django.db.models import OuterRef, Subquery

    from cveFeed.models import ServiceFeature, TlsCertificate
    http2 = ServiceFeature.objects.filter(domain_id=OuterRef('domain_id'), host=OuterRef('host'), port=OuterRef('port'), feature='http2')
    qs = (TlsCertificate.objects.filter(domain__project=project).filter(_name_q(names, 'host'))
          .annotate(http2_value=Subquery(http2.values('value')[:1]), http2_detail=Subquery(http2.values('detail')[:1]),
                    http2_at=Subquery(http2.values('observed_at')[:1])).order_by('host', 'port', 'id'))
    rows, cut = _capped(qs)
    out = []
    for c in rows:
        row = svc._cert(c)
        row['sans'] = list(c.sans or [])  # the whole list here (the list route shows ten)
        out.append(row)
    return out, cut


def _routes(project, names):
    from cveFeed.models import RouteAuth
    rows, cut = _capped(RouteAuth.objects.filter(project=project).filter(_name_q(names, 'host')).select_related('domain', 'triage__verdict').order_by('host', 'path', 'id'))
    return [svc._route(r) for r in rows], cut


def _probes(project, names):
    from cveFeed.models import ProbeObservation
    rows, cut = _capped(ProbeObservation.objects.filter(project=project, host__in=names).order_by('host', 'probe', 'port', 'id'))
    return [{'host': r.host, 'probe': r.probe, 'kind': r.kind, 'product': r.product, 'version': r.version, 'variant': r.variant, 'port': r.port,
             'url': r.url, 'outcome': r.outcome, 'confidence': r.confidence, 'source': r.source, 'evidence': r.evidence or {},
             'first_seen': _iso(r.first_seen), 'observed_at': _iso(r.observed_at)} for r in rows], cut


def _secrets(project, names):
    """The exposed secrets the host's names serve or served, masked (``secrets_api._secret``: the mask, never the value), with where each was seen."""
    from agentapi import secrets_api
    from cveFeed.models import SecretFinding, SecretOccurrence
    ids = list(SecretOccurrence.objects.filter(project=project, host__in=names).order_by().values_list('finding_id', flat=True).distinct()[:MAX_ROWS])
    findings = list(SecretFinding.objects.filter(project=project, pk__in=ids).order_by('-severity', '-last_seen', 'id'))
    where = {}
    for o in SecretOccurrence.objects.filter(project=project, finding_id__in=ids, host__in=names).order_by('finding_id', '-last_seen', 'id')[:MAX_ROWS]:
        where.setdefault(o.finding_id, []).append(secrets_api._where(o))
    return [{**secrets_api._secret(f), 'where': where.get(f.pk, [])} for f in findings]


def _scans(project, names):
    """The scans that saw the host: one row per scan that wrote a row for one of its names."""
    from startScan.models import Subdomain
    seen = {}
    for row in (Subdomain.objects.filter(target_domain__project=project, scan_history__isnull=False).filter(_name_q(names, 'name'))
                .order_by('-scan_history_id').values('scan_history_id', 'scan_history__start_scan_date', 'scan_history__stop_scan_date',
                                                     'scan_history__scan_status', 'scan_history__scan_type__engine_name', 'name', 'discovered_date')[:MAX_ROWS]):
        scan = seen.setdefault(row['scan_history_id'], {'scan_id': row['scan_history_id'], 'started': _iso(row['scan_history__start_scan_date']),
                                                         'finished': _iso(row['scan_history__stop_scan_date']), 'status': row['scan_history__scan_status'],
                                                         'engine': row['scan_history__scan_type__engine_name'], 'names': []})
        if row['name'] not in scan['names']:
            scan['names'].append(row['name'])
    return list(seen.values())


def _state(project, names):
    from cveFeed.models import HostState
    out = []
    for s in HostState.objects.filter(project=project, host__in=names).order_by('host'):
        out.append({'host': s.host, 'state': s.state, 'first_seen': _iso(s.first_seen), 'last_seen': _iso(s.last_seen), 'retired_at': _iso(s.retired_at),
                    'score': s.score, 'zombie_since': _iso(s.zombie_since), 'last_alive_check': _iso(s.last_alive_check),
                    'archived_at': _iso(s.archived_at), 'archive_reason': s.archive_reason, 'pinned': s.pinned,
                    'archive_checked_at': _iso(s.archive_checked_at), 'archive_check_status': s.archive_check_status,
                    'unresolved_first_at': _iso(s.unresolved_first_at), 'unresolved_last_at': _iso(s.unresolved_last_at),
                    'resolution_note': s.resolution_note})
    return out


def _inventory(project, names):
    """The host's own inventory report (the newest tied to one of its names), with every package up to ``MAX_ROWS``, or None."""
    from cveFeed import host_inventory as store
    from cveFeed.models import HostInventory
    inv = HostInventory.objects.filter(project=project, host__in=names).order_by('-reported_at', '-id').first()
    if inv is None:
        return None
    return store.detail(inv, store.stale_days(project), {'page_size': MAX_ROWS}, package_limit=MAX_ROWS)


def _optional(fn, *args):
    """A part of the record another service owns (the assessment, the AI review): its answer, or None when it has nothing for this host."""
    try:
        return fn(*args)
    except ApiError:
        return None


def _safe_name(text):
    return re.sub(r'[^A-Za-z0-9.-]+', '_', str(text or 'host')).strip('._')[:80] or 'host'


def _media_file(rel):
    """The real path of a stored image under MEDIA_ROOT with its type, or ``(None, reason)``: never a path outside it, never a file that is not a picture."""
    from django.conf import settings

    from cveFeed import shots
    if not rel:
        return None, 'no file'
    root = os.path.realpath(settings.MEDIA_ROOT)
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        return None, 'the file is missing'
    kind = shots.file_image_type(path)
    if kind not in shots.IMAGE_TYPES:
        return None, 'the file is not a PNG or JPEG picture'
    return (path, kind), ''


def _screenshots(project, sub, names):
    """``(manifest, files)``: one manifest entry per capture (included or why not) and ``[(zip name, path)]`` within the caps."""
    from cveFeed import web_shot
    from cveFeed.models import HostScreenshot, RdpScreenshot
    from startScan.models import Subdomain
    candidates = []
    shots = sorted(HostScreenshot.objects.filter(project=project, host__in=[n.rstrip('.') for n in names]), key=web_shot.rank)
    for row in shots:
        info = web_shot.describe(row, row.host)
        if row.image_path:
            candidates.append((info, row.image_path, f'{row.host}-{row.scheme}-{row.port}'))
        else:
            candidates.append((info, '', ''))
        if row.previous_image_path:
            candidates.append(({**info, 'previous': True, 'captured_at': None}, row.previous_image_path, f'{row.host}-{row.scheme}-{row.port}-previous'))
    for row in RdpScreenshot.objects.filter(project=project, host__in=names).order_by('host', 'port'):
        candidates.append(({'scheme': 'rdp', 'port': row.port, 'address': row.address, 'outcome': 'captured' if row.image_path else 'none',
                            'ai_summary': row.ai_summary}, row.image_path, f'{row.host}-rdp-{row.port}'))
    if not any(c[1] for c in candidates):  # the discovery screenshot of the newest row of the name that has one, as the host page shows it
        legacy = (Subdomain.objects.filter(target_domain__project=project).filter(_name_q(names, 'name')).exclude(screenshot_path__isnull=True)
                  .exclude(screenshot_path='').order_by('-id').values_list('screenshot_path', flat=True).first()) or sub.screenshot_path
        if legacy:
            candidates.append(({'scheme': 'discovery', 'outcome': 'captured'}, legacy, f'{sub.name}-discovery'))
    manifest, files, total = [], [], 0
    for info, rel, stem in candidates:
        entry = {**info, 'file': None, 'included': False, 'left_out': ''}
        if not rel:
            entry['left_out'] = 'no picture was taken'
            manifest.append(entry)
            continue
        found, why = _media_file(rel)
        if not found:
            entry['left_out'] = why
            manifest.append(entry)
            continue
        path, kind = found
        size = os.path.getsize(path)
        entry['bytes'] = size
        if len(files) >= MAX_SCREENSHOT_FILES:
            entry['left_out'] = f'over the limit of {MAX_SCREENSHOT_FILES} images per export'
        elif total + size > MAX_SCREENSHOT_BYTES:
            entry['left_out'] = f'over the limit of {MAX_SCREENSHOT_BYTES // (1024 * 1024)} MB of images per export'
        else:
            name = f'screenshots/{_safe_name(stem)}.{"png" if kind == "image/png" else "jpg"}'
            entry.update(file=name, included=True)
            files.append((name, path))
            total += size
        manifest.append(entry)
    return manifest, files


class HostExport:
    """One host's export, gathered before a byte is sent: ``record`` (host.json), the CSV texts, the screenshot files and the file name."""

    def __init__(self, project, sub, record, screenshots):
        self.project, self.sub, self.record, self.screenshot_files = project, sub, record, screenshots
        stamp = datetime.now(timezone.utc)
        self.filename = f'host-{_safe_name(sub.name)}-{stamp.strftime("%Y-%m-%d")}.zip'

    def json_text(self):
        return json.dumps(self.record, indent=2, ensure_ascii=False, default=str)

    def csv_files(self):
        r = self.record
        return {
            'findings.csv': _csv(('Type', 'ID', 'Title', 'Host', 'Heat', 'Severity', 'Status', 'Assignee', 'Comments', 'Retest', 'Triage', 'CVSS', 'KEV',
                                  'First seen', 'Status changed', 'Note'),
                                 ([f.get('type'), f.get('id'), f.get('title'), f.get('host'), f.get('heat'), f.get('severity'), f.get('status'),
                                   (f.get('assignee') or {}).get('name') or (f.get('assignee') or {}).get('username') or '', f.get('comment_count'),
                                   (f.get('retest') or {}).get('state') if isinstance(f.get('retest'), dict) else f.get('retest'),
                                   (f.get('triage') or {}).get('classification') if isinstance(f.get('triage'), dict) else '',
                                   f.get('cvss', ''), 'yes' if f.get('kev') else '', f.get('first_seen'), f.get('status_changed_at'), f.get('note')]
                                  for kind in ('cve', 'scanner', 'hygiene') for f in r['findings'][kind])),
            'services.csv': _csv(('Address', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'CPE', 'TLS tunnel', 'Info', 'Banner'),
                                 ([ip.get('address'), p.get('number'), p.get('protocol'), p.get('service'), p.get('product'), p.get('version'), p.get('cpe'),
                                   p.get('tunnel'), p.get('info'), p.get('banner')] for ip in r['services']['addresses'] for p in ip.get('ports') or [])),
            'history.csv': _csv(('Detected', 'Kind', 'Host', 'IP', 'Port', 'Before', 'After', 'Target', 'Scan'),
                                ([c.get('detected'), c.get('kind'), c.get('host'), c.get('ip'), c.get('port'), _flat(c.get('before')), _flat(c.get('after')),
                                  c.get('target'), c.get('scan_id')] for c in r['history']['changes'])),
            'certificates.csv': _csv(('Host', 'Port', 'Subject', 'Issuer', 'Names (SAN)', 'Not before', 'Not after', 'Days left', 'Signature', 'Key',
                                      'Protocol', 'Chain error', 'Legacy TLS', 'Checked'),
                                     ([c.get('host'), c.get('port'), c.get('subject'), c.get('issuer'), c.get('sans'), c.get('not_before'), c.get('not_after'),
                                       c.get('days_left'), c.get('signature_algorithm'), c.get('key'), c.get('protocol'), c.get('chain_error'),
                                       c.get('legacy_tls'), c.get('checked')] for c in r['web']['certificates'])),
            'inventory.csv': _csv(('Section', 'Name', 'Version', 'Detail', 'Source'), _inventory_rows(r)),
        }

    def readme(self):
        r = self.record
        left = [s for s in r['screenshots'] if s.get('file') is None and s.get('left_out') and s.get('left_out') != 'no picture was taken']
        cuts = [name for name, cut in r['truncated'].items() if cut]
        lines = [
            f'cvENGINE host export: {r["host"]["name"]}',
            '',
            f'Exported at {r["exported_at"]} by cvENGINE {r["cvengine_version"]}, from project {r["project"]["name"]} ({r["project"]["slug"]}).',
            f'Record format: {SCHEMA} (the "schema" field of host.json).',
            '',
            'What each file holds',
            '',
            'host.json         The complete record of the host in one structured file: its names, aliases and addresses, hosting and',
            '                  ownership, state, first and last seen, labels, heat and score with the reasons, services and ports with',
            '                  versions, banners and service features, web data (routes, title, headers, technologies with versions and',
            '                  sources, certificates), every finding of every kind with its status, heat, severity, triage, assignment,',
            '                  retest state and comment count, exposed secrets (masked), the full change history, the host\'s own',
            '                  inventory report, probes and check coverage, the scans that saw it, the latest assessment and AI review,',
            '                  and the list of screenshots (screenshots, with the file name of each picture in this ZIP).',
            'findings.csv      One row per finding: CVE matches, scanner findings and hygiene findings, open and closed.',
            'services.csv      One row per open port and service on each address of the host.',
            'history.csv       One row per recorded change of the host, newest first, from the first scan on.',
            'certificates.csv  One row per TLS certificate seen on the host.',
            'inventory.csv     The host\'s own inventory report: packages, patches, listening services, Java runtimes and version sources.',
            'screenshots/      The pictures of the host\'s web pages (and RDP login screens), PNG or JPEG.',
            '',
            'Secrets and credentials',
            '',
            'No secret value is in this export. An exposed secret appears only as its mask (the first and last characters), its kind and',
            f'where it was seen, and any stored header, cookie, password, token or API key value is replaced with {MASK}.',
            '',
            'Limits',
            '',
            f'Each list holds at most {MAX_ROWS:,} rows. Screenshots are limited to {MAX_SCREENSHOT_FILES} files and '
            f'{MAX_SCREENSHOT_BYTES // (1024 * 1024)} MB in all.',
        ]
        lines.append(f'Lists cut at the limit: {", ".join(cuts)}.' if cuts else 'No list was cut.')
        if left:
            lines.append(f'{len(left)} screenshot(s) were left out; host.json says which and why (screenshots, left_out).')
        else:
            lines.append('Every stored screenshot is included.')
        return '\r\n'.join(lines) + '\r\n'

    def chunks(self):
        """The ZIP, a piece at a time: the texts first, then each picture read in ``READ_CHUNK`` pieces (never a whole picture set in memory)."""
        sink = _Sink()
        with zipfile.ZipFile(sink, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for name, text in [('README.txt', self.readme()), ('host.json', self.json_text()), *self.csv_files().items()]:
                zf.writestr(name, text.encode('utf-8'))
                yield sink.drain()
            for name, path in self.screenshot_files:
                info = zipfile.ZipInfo(name, date_time=datetime.now(timezone.utc).timetuple()[:6])
                info.compress_type = zipfile.ZIP_STORED  # a PNG or JPEG is compressed already
                try:
                    with open(path, 'rb') as src, zf.open(info, 'w') as dst:
                        while True:
                            piece = src.read(READ_CHUNK)
                            if not piece:
                                break
                            dst.write(piece)
                            yield sink.drain()
                except OSError:  # removed since the export was planned: the manifest named it, the ZIP simply lacks it
                    continue
                yield sink.drain()
        yield sink.drain()


class _Sink:
    """A write-only file for ``zipfile`` that hands back what was written since the last ``drain``. It cannot seek, so zipfile writes the sizes
    after each member (data descriptors) and nothing written is ever read back."""

    def __init__(self):
        self.parts, self.pos = [], 0

    def write(self, data):
        self.parts.append(bytes(data))
        self.pos += len(data)
        return len(data)

    def tell(self):
        return self.pos

    def flush(self):
        pass

    def drain(self):
        out = b''.join(self.parts)
        self.parts = []
        return out


def _flat(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    return value


def _csv(header, rows):
    out = io.StringIO()
    out.write(BOM + ','.join(cell(h) for h in header) + '\r\n')
    for row in rows:
        out.write(','.join(cell(_flat(c)) for c in row) + '\r\n')
    return out.getvalue()


def _inventory_rows(r):
    inv = r['inventory']['report'] or {}
    for p in (inv.get('packages_page') or {}).get('results') or []:
        yield ['package', p.get('name'), p.get('version'), ' '.join(x for x in (p.get('ecosystem'), p.get('arch'), p.get('purl')) if x), p.get('source')]
    for p in inv.get('patches') or []:
        yield ['patch', p.get('id') or p.get('name') if isinstance(p, dict) else p, '', _flat(p) if isinstance(p, dict) else '', '']
    for s in inv.get('services') or []:
        yield ['service', s.get('name') or s.get('process') if isinstance(s, dict) else s, '', _flat(s) if isinstance(s, dict) else '', '']
    for j in r['inventory']['java_runtimes']:
        yield ['java_runtime', j.get('vendor') or 'java', j.get('version'), j.get('line') or '', j.get('source')]
    for v in r['inventory']['version_sources']:
        yield ['version_source', v.get('product') or v.get('name'), v.get('version'), v.get('kind') or '', v.get('source')]


def build(ctx, slug, host_id):
    """Check access and gather the whole record (every read happens here): a ``HostExport``. Raises ApiError (404 for a host the caller cannot read)."""
    from django.conf import settings

    from agentapi import host_review_api
    project, sub = _host_row(ctx, slug, host_id)
    row = svc.host_group(project, sub)
    svc._mark_zombies(project, {'results': [row]})
    names = list(dict.fromkeys([sub.name.lower().rstrip('.'), *[a.lower().rstrip('.') for a in row.get('aliases') or []]]))[:MAX_NAMES + 1]
    current = _current_ids(project, names)
    findings, findings_cut = _findings(project, names, current)
    history, history_cut = _history(project, names)
    certificates, certs_cut = _certificates(project, names)
    routes, routes_cut = _routes(project, names)
    probes, probes_cut = _probes(project, names)
    inventory_report = _inventory(project, names)
    packages = (inventory_report or {}).get('packages_page') or {}
    manifest, files = _screenshots(project, sub, names)
    identity = {k: row.get(k) for k in ('id', 'host', 'alias', 'alias_from', 'note', 'note_from', 'aliases', 'names', 'target', 'target_id', 'internal',
                                        'network', 'hosting', 'labels', 'profile', 'excluded', 'zombie', 'archived', 'archive_reason', 'pinned',
                                        'archive_checked_at', 'archive_check_status', 'scan_blocked', 'unconfirmed_addresses', 'secrets')}
    identity['name'] = identity.pop('host')
    record = {
        'schema': SCHEMA,
        'exported_at': _iso(datetime.now(timezone.utc)),
        'cvengine_version': getattr(settings, 'CVENGINE_CURRENT_VERSION', ''),
        'project': {'slug': project.slug, 'name': project.name, 'organization': project.org.name if project.org_id else None},
        'host': {**identity, 'state': _state(project, names),
                 'heat': row.get('heat'), 'heat_reasons': row.get('heat_reasons'), 'score': row.get('score'), 'score_detail': row.get('score_detail'),
                 'validate_plan': row.get('validate_plan')},
        'services': {'addresses': row.get('ips') or [], 'service_features': row.get('service_features'), 'shodan_leads': row.get('shodan_leads')},
        'web': {'http': row.get('http'), 'http_status': row.get('http_status'), 'title': row.get('title'), 'technologies': row.get('technologies'),
                'technology_details': row.get('technology_details'), 'unverified_products': row.get('unverified_products'),
                'archived_technologies': row.get('archived_technologies'), 'wordpress': row.get('wordpress'), 'also_served': row.get('also_served'),
                'served_from': row.get('served_from'), 'subdirectory_apps': row.get('subdirectory_apps'), 'routes': routes, 'certificates': certificates},
        'findings': findings,
        'finding_counts': {kind: len(rows) for kind, rows in findings.items()},
        'secrets': _secrets(project, names),
        'history': {'changes': history},
        'inventory': {'report': inventory_report, 'java_runtimes': row.get('java_runtimes') or [], 'version_sources': row.get('version_sources') or [],
                      'summary': row.get('inventory')},
        'probes': probes,
        'check_coverage': row.get('check_coverage'),
        'scans': _scans(project, names),
        'assessment': _optional(svc.latest_host_assessment, ctx, slug, sub.pk),
        'ai_review': _optional(host_review_api.get_host_review, ctx, slug, sub.pk),
        'screenshots': manifest,
        'truncated': {**{f'findings.{k}': v for k, v in findings_cut.items()}, 'history': history_cut, 'certificates': certs_cut, 'routes': routes_cut,
                      'probes': probes_cut, 'inventory.packages': packages.get('count', 0) > len(packages.get('results') or []),
                      'names': len(names) > MAX_NAMES},
        'limits': {'rows_per_list': MAX_ROWS, 'screenshot_files': MAX_SCREENSHOT_FILES, 'screenshot_bytes': MAX_SCREENSHOT_BYTES},
    }
    return HostExport(project, sub, scrub(record), files)


def _audit(ctx, export, channel):
    from tenancy import audit
    r = export.record
    audit.record(ctx.user, 'host.export', f'{export.project.slug}: host {export.sub.name}', org=export.project.org_id, project=export.project.slug,
                 host=export.sub.name, host_id=export.sub.pk, kind='host', channel=channel, findings=sum(r['finding_counts'].values()),
                 screenshots=len(export.screenshot_files))


def response(ctx, slug, host_id):
    """The streamed ZIP for ``GET projects/{slug}/hosts/{host_id}/export``."""
    from django.http import StreamingHttpResponse
    export = build(ctx, slug, host_id)
    _audit(ctx, export, 'rest')
    out = StreamingHttpResponse(export.chunks(), content_type='application/zip')
    out['Content-Disposition'] = f'attachment; filename="{export.filename}"'
    out['Cache-Control'] = 'no-store'
    out['X-Export-Findings'] = str(sum(export.record['finding_counts'].values()))
    out['X-Export-Screenshots'] = str(len(export.screenshot_files))
    return out


def tool(ctx, args):
    """The MCP tool ``export_host``: host.json as text (no pictures), up to ``MCP_MAX_BYTES``; a bigger record is a 413 that points at REST."""
    slug, host_id = args.get('project'), args.get('host_id')
    export = build(ctx, slug, host_id)
    text = export.json_text()
    size = len(text.encode('utf-8'))
    download = f'GET projects/{export.project.slug}/hosts/{export.sub.pk}/export'
    if size > MCP_MAX_BYTES:
        raise ApiError(413, f'the record of {export.sub.name} is {size:,} bytes, over the {MCP_MAX_BYTES:,} bytes an MCP answer holds: download the ZIP with {download}')
    _audit(ctx, export, 'mcp')
    return {'filename': export.filename[:-4] + '.json', 'schema': SCHEMA, 'bytes': size, 'screenshots': len(export.screenshot_files),
            'screenshots_note': f'The pictures are not in this answer: {download} returns the ZIP with screenshots/ and the CSV files.',
            'content': text}
