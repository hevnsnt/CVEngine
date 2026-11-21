"""The CSV form of a report (cveFeed.report_export): one row per finding, or one row per host, written in the report worker.

It reads what the PDF reads, through the same selections (``report_data._sources`` for the findings, so "open", "ruled out" and "false positive"
mean what the Findings page and the PDF mean, and ``report_data.host_pages`` for the hosts), and filters by the scope's project ids explicitly: a
worker has no request scope. Every cell goes through ``agentapi.host_export.cell``, so a value a spreadsheet would run as a formula (a banner, a
finding title or a host name from a scanned machine) gets an apostrophe in front and stays text. Nothing here contacts a host.

A file holds at most ``CVENGINE_REPORT_CSV_MAX_ROWS`` rows (hottest first); ``write`` says how many rows it wrote and how many the cap left out.
"""
import os
from datetime import datetime, timezone as dt_timezone

from agentapi import services as svc
from agentapi.host_export import BOM, cell
from cveFeed import report_data
from cveFeed.report_data import HEAT_NAMES, clean

DEFAULT_MAX_ROWS, CEILING_ROWS = 20000, 100000
LOOKUP_CHUNK = 500  # findings loaded by id at a time
FINDING_COLUMNS = ('Kind', 'Heat', 'Severity', 'Title', 'CVE', 'CVSS', 'Known exploited', 'Host', 'Host alias', 'Project', 'Organization', 'Status',
                   'Assignee', 'Basis', 'Fixed in', 'First seen', 'Last seen', 'Link')
HOST_COLUMNS = ('Host', 'Alias', 'Also answers to', 'IP addresses', 'Open ports', 'Technologies', 'Heat', 'Score', 'Open findings', 'Owner',
                'Criticality', 'Project', 'Organization')
EPOCH = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
HASH_KIND = {'cve': 'match', 'scanner': 'vulnerability', 'hygiene': 'hygiene'}  # the finding's address on the Findings page (#match-12)


def max_rows():
    return report_data._env_int('CVENGINE_REPORT_CSV_MAX_ROWS', DEFAULT_MAX_ROWS, CEILING_ROWS)


def _line(values):
    return ','.join(cell(v) for v in values) + '\r\n'


def _keys(sources):
    """``[(heat rank, severity, when, id, source)]`` of every finding of the sources: the sort keys only, so choosing the rows that fit the cap holds no row."""
    out = []
    for source, qs in sources.items():
        out += [(heat or 0, sev or 0, when or EPOCH, pk, source) for heat, sev, when, pk in qs.order_by().values_list('heat_rank', 'sev', 'when', 'id')]
    return out


def _entry(source, obj, base):
    """The CSV row (as a dict, so the host alias can be set after) of one finding."""
    if source == 'cve':
        cve, sub = obj.cve_entry, obj.subdomain
        product = ' '.join(x for x in (obj.matched_product, obj.matched_version) if x)
        project = sub.target_domain.project
        values = {'Kind': 'CVE match', 'Title': f'{cve.cve_id} in {product}' if product else cve.cve_id, 'CVE': cve.cve_id, 'CVSS': cve.cvss if cve.cvss is not None else '',
                  'Known exploited': 'yes' if cve.kev else 'no', 'Host': sub.name if sub else '', 'Basis': report_data.match_basis(obj)[0],
                  'Fixed in': ', '.join(svc._fixed_versions(cve, obj.matched_product)[:6]),
                  'First seen': report_data._date(svc._seen(obj, 'first_seen', obj.created_at)), 'Last seen': report_data._date(svc._seen(obj, 'last_seen', obj.updated_at))}
    elif source == 'scanner':
        sub = obj.subdomain
        project = obj.target_domain.project
        confirmed = bool(svc._triage_of(obj) and svc._triage_of(obj).validation_status == 'hit')
        values = {'Kind': 'Scanner finding', 'Title': obj.name, 'CVE': ', '.join(c.name for c in obj.cve_ids.all()[:8]), 'CVSS': obj.cvss_score or '',
                  'Known exploited': '', 'Host': sub.name if sub else (obj.target_domain.name if obj.target_domain else ''),
                  'Basis': 'Confirmed: a check on the host reproduced it' if confirmed else 'Detected by the scanner template (a response matched); not independently reproduced',
                  'Fixed in': '', 'First seen': report_data._date(svc._seen(obj, 'first_seen', obj.discovered_date)),
                  'Last seen': report_data._date(svc._seen(obj, 'last_seen', obj.discovered_date))}
    else:
        project = obj.domain.project
        values = {'Kind': 'Hygiene finding', 'Title': obj.title, 'CVE': '', 'CVSS': '', 'Known exploited': '', 'Host': obj.host, 'Basis': 'Configuration check', 'Fixed in': '',
                  'First seen': report_data._date(obj.first_seen), 'Last seen': ''}
    tracking = report_data._tracking(obj)
    values.update({'Heat': HEAT_NAMES.get(obj.heat_rank, ''), 'Severity': svc.SEVERITY_NAMES.get(obj.sev, ''), 'Project': project.name,
                   'Organization': project.org.name if project.org_id else '', 'Status': tracking['status'], 'Assignee': tracking['assignee'],
                   'Link': f'{base}/cve/{project.slug}/vulns/#{HASH_KIND[source]}-{obj.pk}'})
    return {k: clean(v, 500) if isinstance(v, str) else v for k, v in values.items()} | {'project_slug': project.slug}


def _rows_findings(scope_obj, sources, cap):
    """``(rows, omitted)``: the hottest ``cap`` findings of the sources, merged across kinds in the Findings page's order, as lists of cells."""
    from cveFeed import mailer
    keys = _keys(sources)
    total = len(keys)
    keys.sort(reverse=True)
    chosen = keys[:cap]
    base = mailer.base_url()
    loaded = {}
    for source, qs in sources.items():
        ids = [k[3] for k in chosen if k[4] == source]
        if source == 'scanner':
            qs = qs.prefetch_related('cve_ids')
        for start in range(0, len(ids), LOOKUP_CHUNK):
            for obj in qs.order_by().filter(pk__in=ids[start:start + LOOKUP_CHUNK]):
                loaded[(source, obj.pk)] = _entry(source, obj, base)
    entries = [loaded[(k[4], k[3])] for k in chosen if (k[4], k[3]) in loaded]
    for start in range(0, len(entries), LOOKUP_CHUNK):
        part = [{'host': e['Host'], 'project_slug': e['project_slug']} for e in entries[start:start + LOOKUP_CHUNK]]
        report_data._label_hosts(scope_obj, [], part)
        for e, labelled in zip(entries[start:start + LOOKUP_CHUNK], part):
            e['Host alias'] = clean(labelled['host_alias'], 200)
    return [[e[c] for c in FINDING_COLUMNS] for e in entries], total - len(entries)


def _rows_hosts(scope_obj, cap, organization):
    """``(rows, omitted)``: one row per machine of the scope's current inventory, highest score first, at most ``cap``."""
    everywhere = svc._is_all(scope_obj)
    sources, _ = report_data._sources(scope_obj, False)
    per_host = report_data._per_host(sources, everywhere)
    qs = report_data._host_qs(scope_obj)
    rows = []
    for h in report_data.host_pages(scope_obj, qs, cap):
        row = report_data._host_row(h, per_host, detail=False, everywhere=everywhere)
        ports = sorted({(p['number'], p['protocol'] or '') for ip in h['ips'] for p in ip['ports']})
        rows.append([row['host'], row['alias'], clean(', '.join(h['aliases']), 500), ' '.join(clean(ip['address'], 64) for ip in h['ips']),
                     ' '.join(f'{n}/{proto}' if proto else str(n) for n, proto in ports), clean('; '.join(h['technologies']), 500), row['heat'], row['score'],
                     row['findings'], row['owner'], row['criticality'], row['project'] if everywhere else clean(scope_obj.name, 200), organization])
    return rows, max(0, qs.count() - len(rows))


def write(scope_obj, kind, include_closed, path, now=None, organization=''):
    """Write the CSV of the scope to ``path`` (a path the caller chose) and return ``{'rows': n, 'omitted': n}``. ``organization``: the organization's name."""
    if kind == 'hosts':
        columns, (rows, omitted) = HOST_COLUMNS, _rows_hosts(scope_obj, max_rows(), organization)
    else:
        sources, _ = report_data._sources(scope_obj, include_closed)
        columns, (rows, omitted) = FINDING_COLUMNS, _rows_findings(scope_obj, sources, max_rows())
    with open(path, 'w', encoding='utf-8', newline='') as fh:
        fh.write(BOM + _line(columns))
        for row in rows:
            fh.write(_line(row))
    os.chmod(path, 0o600)
    return {'rows': len(rows), 'omitted': omitted}
