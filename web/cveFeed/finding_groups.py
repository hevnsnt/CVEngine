"""One library on one site is one finding: CVE matches of the same script on sibling hosts, grouped for the Findings list.

The same jQuery file served by www., blog., info. and careers.example.com used to read as four findings per CVE. Grouping is a
presentation and counting layer only: every host keeps its own CVEMatch and Triage row, its own validation, remediation status,
assignee and audit trail, so an operator can still act on one host. A group row stands for its members and every action on it is
applied to each member through the ordinary per-finding paths (the same role gates, tenancy checks and per-member audit events).

What is grouped (the rule, chosen to be the safe one):

* only technology fingerprints of a web page (``source == 'tech'``) with a version, AND whose product is a client-side JavaScript
  library or framework the browser downloads (``CLIENT_SIDE_LIBRARIES``, an explicit allow-list: jQuery, jQuery UI and Migrate,
  Bootstrap, AngularJS and Angular, React, Vue, lodash, Underscore, Moment, DataTables, ...). The same file on sibling hosts is one
  file, so one finding. Anything else, a web server, language, CMS, proxy or CDN, database or any server-side framework (nginx 1.18.0
  on www. and on mail. is two machines, not one), and any product the list does not name, stays one row per host. Port banners,
  host inventory reports and CPE matches always stay one row per host;
* never across projects (the key starts with the project id, so never across organizations either) and never across registrable
  domains (``www.example.com`` and ``www.example.org`` are two sites). The registrable domain comes from the public suffix list
  bundled with tldextract INCLUDING its private section, so each tenant of a hosting provider (``acme.github.io``,
  ``x.blogspot.com``, ``a.trycloudflare.com``, ``b.s3.amazonaws.com``) is its own site, as is a host under
  ``targetApp.shared_domains`` and an IP address. Internationalised names are compared in their ASCII (punycode) form;
* the key is (project, CVE, product, version, registrable domain, script identity). The script identity is the evidence's
  ``script_sha256`` (the bytes of the file) when the probe recorded it; else its ``script_url``: the path when the script is served
  from the site's own registrable domain (``/js/jquery.min.js`` on www. and on blog. is one file), the host and path when it comes
  from elsewhere (a CDN); else nothing more, so a library match with neither field groups by (CVE, library, version, registrable
  domain);
* a match with hard evidence of its own is never folded into a group, it stays its own row: a template check that answered
  ``vulnerable``, a validation ``hit``, or a ``confirmed`` classification. What was proven on one host is not hidden behind its
  siblings, and an action on the group (accepting the risk, say) cannot sweep a proven host along with the version-only ones.

A group shows the worst member (it is ordered and coloured by it), the number of hosts, the split of heat, status, classification
and validation across its members, and when it was first and last seen. A single member is shown as an ordinary row.

Cost: one ``values()`` query over the filtered matches (at most ``GROUP_SCAN_MAX`` rows, hottest first) and a pass in memory; no
query per row or per member.
"""
import functools
import hashlib
import re
from datetime import datetime, timezone as dt_timezone
from urllib.parse import urlsplit

GROUP_SCAN_MAX = 20000  # matches read to build the groups; the rest of a larger list stays one row each (``scan_truncated``)
MEMBERS_SHOWN = 100  # members listed in full on a group row; ``member_ids`` always holds every one
GROUPABLE_SOURCES = ('tech',)
HARD_TEMPLATE_RESULTS = ('vulnerable',)
HARD_VALIDATION = ('hit',)
HARD_CLASSIFICATIONS = ('confirmed',)
_SHA256 = re.compile(r'^[0-9a-f]{64}$')

# Client-side JavaScript libraries and frameworks: code the browser downloads from the page, so the same version on sibling hosts is
# the same file. An explicit allow-list (names normalised by ``library_key``): an unknown product never groups. Every name of
# cveFeed.fingerprint's "javascript library" category is here; its "framework" category is NOT taken whole, it mixes React and Vue
# with Django, Laravel, Express, Rails and Next.js, which run on the server.
CLIENT_SIDE_LIBRARIES = frozenset({
    'jquery', 'jquery ui', 'jqueryui', 'jquery migrate', 'jquery mobile', 'jquery validation', 'jquery validate', 'jquery form',
    'jquery cookie', 'jquery file upload', 'jquery colorbox', 'jquery prettyphoto', 'jquery fancybox', 'fancybox', 'lightbox',
    'bootstrap', 'twitter bootstrap', 'popper', 'angularjs', 'angular', 'react', 'react dom', 'vue', 'lodash', 'underscore',
    'moment', 'moment timezone', 'datatables', 'swiper', 'handlebars', 'mustache', 'knockout', 'backbone', 'ember', 'dompurify',
    'select2', 'prototype', 'mootools', 'yui', 'dojo', 'ext', 'tinymce', 'ckeditor', 'highcharts', 'd3', 'axios',
    'plupload', 'video', 'mediaelement', 'flowplayer', 'jwplayer', 'svelte', 'alpine', 'htmx', 'zepto', 'require',
    'sweetalert', 'sweetalert2', 'slick', 'owl carousel', 'magnific popup', 'isotope', 'masonry', 'modernizr', 'polyfill',
})


def library_key(product):
    """A product name in the allow-list's form: lowercase, vendor prefix and ``.js``/``js`` suffix dropped, separators as spaces
    (``jQuery-UI`` -> ``jquery ui``, ``Moment.js`` -> ``moment``, ``jquery:jquery`` -> ``jquery``, ``vue.js`` -> ``vue``,
    ``AngularJS`` -> ``angular``, ``video.js`` -> ``video``, ``RequireJS`` -> ``require``)."""
    name = str(product or '').strip().lower()
    if ':' in name:  # a CPE-style vendor:product
        name = name.rsplit(':', 1)[-1]
    name = re.sub(r'[-_./\s]+', ' ', name).strip()
    name = re.sub(r'\s*(?:js)$', '', name).strip() if name not in ('js',) else name
    return re.sub(r'\s+', ' ', name)


def is_client_side_library(product):
    from cveFeed.fingerprint import categorize
    key = library_key(product)
    return bool(key) and (key in CLIENT_SIDE_LIBRARIES or categorize(str(product or '')) == 'javascript library')
_EPOCH = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)

# what the pass reads of each match (with the list's own annotations heat_rank, sev and when when present)
BASE_FIELDS = ('id', 'cve_entry_id', 'matched_product', 'matched_version', 'source', 'template_result', 'ai_verdict',
               'remediation_status', 'created_at', 'updated_at', 'subdomain__name', 'subdomain__target_domain__project_id',
               'triage__classification', 'triage__validation_status', 'triage__first_seen', 'triage__last_seen')
LIST_FIELDS = ('heat_rank', 'sev', 'when')


_EXTRACT = None


def _private_aware_apex(name):
    """The registrable domain with the private section of the public suffix list honoured (``acme.github.io`` stays itself), from
    tldextract's bundled list (no network); None when the suffix is unknown or tldextract is missing."""
    global _EXTRACT
    try:
        if _EXTRACT is None:
            import tldextract
            _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
        return _EXTRACT(name).top_domain_under_public_suffix or None
    except ImportError:
        from targetApp.target_types import apex_domain
        return apex_domain(name)


def ascii_host(host):
    """A host name in its ASCII form: ``bücher.example.de`` -> ``xn--bcher-kva.example.de`` (IDNA, label by label; a label that does
    not encode is kept as it is)."""
    name = (host or '').strip().lower().rstrip('.')
    if name.isascii():
        return name
    labels = []
    for label in name.split('.'):
        try:
            labels.append(label.encode('idna').decode('ascii') if label and not label.isascii() else label)
        except UnicodeError:
            labels.append(label)
    return '.'.join(labels)


@functools.lru_cache(maxsize=4096)  # thousands of rows name a few hundred hosts
def registrable_domain(host):
    """The site a host belongs to, for grouping: its registrable domain (``blog.example.co.uk`` -> ``example.co.uk``), from the public
    suffix list bundled with tldextract including its private section, so each tenant of a hosting provider is its own site
    (``acme.github.io``, ``x.blogspot.com``, ``a.ngrok.io``, ``a.trycloudflare.com``, ``b.s3.amazonaws.com``). A host under
    ``targetApp.shared_domains`` and an IP address are their own site too; a name whose suffix the list does not know
    (``a.corp.local``) uses its last two labels. Names are compared in punycode. Limit: a multi-tenant provider that is in neither
    the bundled list's private section nor SHARED_DOMAINS (a new one, or a provider that does not register its domain there) groups
    its tenants under the provider's domain."""
    from targetApp.shared_domains import shared_domain_of
    from targetApp.target_types import DOMAIN, classify_target
    name = ascii_host(host)
    if not name or classify_target(name) != DOMAIN:
        return name
    if shared_domain_of(name):
        return name
    apex = _private_aware_apex(name)
    if apex:
        return name if shared_domain_of(apex) else apex
    labels = name.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else name


def has_hard_evidence(row):
    """A template hit, a validation hit or a confirmed classification: proof about this host, never folded into a group."""
    return (row.get('template_result') in HARD_TEMPLATE_RESULTS or row.get('triage__validation_status') in HARD_VALIDATION
            or row.get('triage__classification') in HARD_CLASSIFICATIONS)


def is_groupable(row):
    return (row.get('source') in GROUPABLE_SOURCES and bool((row.get('matched_version') or '').strip())
            and is_client_side_library(row.get('matched_product'))
            and bool((row.get('subdomain__name') or '').strip()) and row.get('subdomain__target_domain__project_id') is not None
            and not has_hard_evidence(row))


def script_identity(row, domain):
    """``(kind, value)``: what says two sightings are the same file. ``sha256`` (the file's bytes), ``script_path`` (a path on the
    site's own registrable domain), ``script_url`` (host and path elsewhere, a CDN) or ``library`` (no script recorded)."""
    sha = str(row.get('script_sha256') or '').strip().lower()
    if _SHA256.match(sha):
        return 'sha256', sha
    url = str(row.get('script_url') or '').strip()
    if url:
        try:
            parts = urlsplit(url if '//' in url else f'//{url}')
            script_host = (parts.hostname or '').lower()
        except ValueError:
            script_host, parts = '', None
        if script_host and parts is not None:
            path = parts.path or '/'
            if registrable_domain(script_host) == domain:
                return 'script_path', path
            return 'script_url', f'{script_host}{path}'
    return 'library', ''


def group_key(row):
    """The grouping key of a groupable row, or None (the row stays its own)."""
    if not is_groupable(row):
        return None
    domain = registrable_domain(row['subdomain__name'])
    kind, value = script_identity(row, domain)
    return (row['subdomain__target_domain__project_id'], row['cve_entry_id'], (row.get('matched_product') or '').strip().lower(),
            (row.get('matched_version') or '').strip(), domain, kind, value)


def key_id(key):
    """A short stable id for a key, for the page to tell group rows apart (never parsed back)."""
    return 'g' + hashlib.sha1('\x1f'.join(str(part) for part in key).encode()).hexdigest()[:20]


def rows_of(qs, with_list_fields=True):
    """The values() query the pass reads: one query, the script fields pulled out of the evidence by the database."""
    from django.db.models.fields.json import KeyTextTransform
    fields = BASE_FIELDS + (LIST_FIELDS if with_list_fields else ())
    return qs.annotate(script_sha256=KeyTextTransform('script_sha256', 'evidence'),
                       script_url=KeyTextTransform('script_url', 'evidence')).values(*fields, 'script_sha256', 'script_url')


def build(rows):
    """The list rows of ``rows`` (dicts, in the list's order: hottest first), each ``{'rep', 'members', 'key'}``. The first member of
    a group is the hottest (its representative, the row a click opens), and the group sits where that member would."""
    out, groups = [], {}
    for row in rows:
        key = group_key(row)
        if key is None:
            out.append({'rep': row, 'members': [row], 'key': None})
            continue
        group = groups.get(key)
        if group is None:
            group = groups[key] = {'rep': row, 'members': [row], 'key': key}
            out.append(group)
        else:
            group['members'].append(row)
    return out


def read(qs, cap=None, with_list_fields=True):
    """``(list rows, matches read)`` over the first ``cap`` (GROUP_SCAN_MAX) matches of ``qs`` in its order."""
    cap = GROUP_SCAN_MAX if cap is None else cap
    rows = list(rows_of(qs, with_list_fields)[:cap])
    return build(rows), len(rows)


def row_count(qs, cap=None):
    """``(rows, truncated)``: how many rows the grouped list shows for these matches (groups and single matches), and whether there
    were more than ``cap`` matches to read. Past the cap each match counts as one row, so the number is then an upper bound."""
    cap = GROUP_SCAN_MAX if cap is None else cap
    built, scanned = read(qs, cap, with_list_fields=False)
    total = qs.count() if scanned >= cap else scanned
    return len(built) + max(0, total - scanned), total > scanned


def _member_status(row):
    return 'ruled out' if row.get('ai_verdict') == 'not_affected' else row.get('remediation_status') or 'open'


def _tally(values):
    out = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def summary(group, iso=None):
    """The ``group`` object of a list row with more than one member."""
    from cveFeed.threat import HEAT_RANK
    iso = iso or (lambda value: value.isoformat() if value else None)
    heat_name = {rank: name for name, rank in HEAT_RANK.items()}
    members = group['members']
    firsts = [m.get('triage__first_seen') or m.get('created_at') for m in members]
    lasts = [m.get('triage__last_seen') or m.get('updated_at') for m in members]
    firsts, lasts = [v for v in firsts if v], [v for v in lasts if v]
    _, _, _, _, domain, kind, value = group['key']
    return {
        'id': key_id(group['key']),
        'registrable_domain': domain,
        'identity': kind,  # sha256 | script_path | script_url | library
        'script': value[:300],  # a path or URL the scanned page named: data, capped
        'hosts': len({m['subdomain__name'] for m in members}),
        'findings': len(members),
        'member_ids': [m['id'] for m in members],
        # every member's own remediation status keyed by id, and the members the AI ruled out: an action on the group changes only
        # the members it applies to (open and in progress ones by default), and Undo puts each back, even past the members listed in full
        'member_status': {str(m['id']): m.get('remediation_status') or 'open' for m in members},
        'ruled_out_ids': [m['id'] for m in members if m.get('ai_verdict') == 'not_affected'],
        'members': [{'kind': 'match', 'id': m['id'], 'host': m['subdomain__name'], 'heat': heat_name.get(m.get('heat_rank'), ''),
                     'status': _member_status(m), 'remediation_status': m.get('remediation_status') or 'open',
                     'classification': m.get('triage__classification') or '',
                     'validation_status': m.get('triage__validation_status') or 'none'} for m in members[:MEMBERS_SHOWN]],
        'members_truncated': len(members) > MEMBERS_SHOWN,
        'heat_counts': _tally(heat_name.get(m.get('heat_rank'), '') for m in members),
        'status_counts': _tally(_member_status(m) for m in members),
        'classification_counts': _tally(m.get('triage__classification') or '' for m in members),
        'validation_counts': _tally(m.get('triage__validation_status') or 'none' for m in members),
        'first_seen': iso(min(firsts)) if firsts else None,
        'last_seen': iso(max(lasts)) if lasts else None,
    }


def sort_key(rep):
    """The unified list's order (heat, severity, newest, id) of a representative's values row."""
    return (rep.get('heat_rank') or 0, rep.get('sev') or 0, rep.get('when') or _EPOCH, rep['id'])
