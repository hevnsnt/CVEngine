"""Archived URLs as passive evidence of what a host has run.

One query per target to the Internet Archive's CDX index (a third party: nothing is sent to the target) lists the URLs it has
saved for the domain and its subdomains. File extensions and well-known paths in them say what a host ran at some point: a
``.php`` page means PHP, ``/wp-content/`` means WordPress. That is kept per host as ``HostArchive`` and shown in search as
*seen in the web archive*, never as a current technology, so it does not feed CVE matching.

A lookup is one bounded request per target per week (the service ledger, ``archive-urls``), and any failure leaves the host
alone: the archive being slow or down must never affect a scan.
"""
import json
import logging
import os
from urllib.parse import urlsplit

import requests
from django.utils import timezone

logger = logging.getLogger(__name__)

CDX_URL = 'https://web.archive.org/cdx/search/cdx'
MAX_URLS = 20000           # rows asked of the index (already one per distinct URL, answered 200)
MAX_BYTES = 12 * 1024 * 1024
TIMEOUT = (10, 90)         # connect, read
SAMPLE = 5                 # example URLs kept per technology
MAX_HOSTS_PER_TARGET = 5000

EXTENSIONS = {
    'php': 'PHP', 'php3': 'PHP', 'php4': 'PHP', 'php5': 'PHP', 'php7': 'PHP', 'phtml': 'PHP',
    'asp': 'ASP', 'aspx': 'ASP.NET', 'ashx': 'ASP.NET', 'asmx': 'ASP.NET', 'axd': 'ASP.NET',
    'jsp': 'Java', 'jspx': 'Java', 'do': 'Java (Struts)', 'action': 'Java (Struts)',
    'cfm': 'ColdFusion', 'cfc': 'ColdFusion', 'pl': 'Perl', 'cgi': 'CGI', 'py': 'Python', 'rb': 'Ruby',
}
# (substring of the lowercase path, technology). First reading of a path wins only once per technology.
PATH_MARKERS = (
    ('/wp-content/', 'WordPress'), ('/wp-includes/', 'WordPress'), ('/wp-login.php', 'WordPress'), ('/wp-json/', 'WordPress'),
    ('/xmlrpc.php', 'WordPress'), ('/sites/default/', 'Drupal'), ('/misc/drupal.js', 'Drupal'),
    ('/administrator/index.php', 'Joomla'), ('/components/com_', 'Joomla'), ('/phpmyadmin', 'phpMyAdmin'),
    ('/_next/', 'Next.js'), ('/skin/frontend/', 'Magento'), ('/typo3', 'TYPO3'), ('/umbraco/', 'Umbraco'),
    ('/sitecore/', 'Sitecore'), ('/jenkins/', 'Jenkins'), ('/solr/', 'Apache Solr'), ('/actuator/', 'Spring Boot'),
)


def lookup_enabled():
    return os.environ.get('CVENGINE_ARCHIVE_LOOKUP', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def fetch_urls(domain, get=None):
    """The distinct archived URLs for ``domain`` and its subdomains that answered 200, as a list of strings (at most
    ``MAX_URLS``). ``get`` replaces ``requests.get`` in tests. Raises on a network or format problem."""
    get = get or requests.get
    params = {'url': f'*.{domain}', 'output': 'json', 'fl': 'original', 'collapse': 'urlkey', 'filter': 'statuscode:200',
              'limit': str(MAX_URLS)}
    response = get(CDX_URL, params=params, timeout=TIMEOUT, stream=True, headers={'User-Agent': 'cvENGINE passive lookup'})
    try:
        response.raise_for_status()
        body, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                break
            body.append(chunk)
    finally:
        response.close()
    rows = json.loads(b''.join(body).decode('utf-8', 'replace') or '[]') if size <= MAX_BYTES else []
    return [r[0] for r in rows[1:] if r and isinstance(r[0], str)]


def classify(urls, apex, known_hosts):
    """``{host: {'url_count': n, 'technologies': {name: {'count': n, 'sample': [paths]}}}}`` for the hosts of ``known_hosts``
    (lowercase names of this target). A URL is read by its file extension and by well-known path markers."""
    out = {}
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        host = (parts.hostname or '').lower()
        if host not in known_hosts or not (host == apex or host.endswith('.' + apex)):
            continue
        entry = out.setdefault(host, {'url_count': 0, 'technologies': {}})
        entry['url_count'] += 1
        path = (parts.path or '/')[:300]
        lowered = path.lower()
        seen = set()
        name = lowered.rsplit('/', 1)[-1]
        ext = name.rsplit('.', 1)[-1] if '.' in name else ''
        if ext in EXTENSIONS:
            seen.add(EXTENSIONS[ext])
        for marker, tech in PATH_MARKERS:
            if marker in lowered:
                seen.add(tech)
        for tech in seen:
            slot = entry['technologies'].setdefault(tech, {'count': 0, 'sample': []})
            slot['count'] += 1
            if len(slot['sample']) < SAMPLE:
                slot['sample'].append(path)
    return out


def _searchable(technologies):
    """The flat text search reads, so a JSON key name never matches: the technology names, lowercase."""
    return ' '.join(sorted(technologies)).lower()


def run_for_domain(domain_id, get=None, force=False):
    """Look up one target and store the evidence for its hosts. Returns a small result dict; never raises."""
    from cveFeed import ledger
    from cveFeed.models import HostArchive
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from targetApp.target_types import IP, classify_target
    if not lookup_enabled():
        return {'skipped': 'disabled'}
    domain = Domain.objects.filter(pk=domain_id).first()
    if not domain or classify_target(domain.name) == IP:
        return {'skipped': 'not a domain name'}
    apex = domain.name.lower()
    if not force and ledger.fresh('archive-urls', [apex], project=domain.project_id):
        return {'skipped': 'checked recently'}
    try:
        urls = fetch_urls(apex, get=get)
    except Exception as exc:  # noqa: BLE001 - a passive third-party lookup must never affect anything else
        logger.warning('archive lookup for %s failed: %s', apex, exc)
        return {'error': str(exc)[:200]}
    known = set(Subdomain.objects.filter(target_domain=domain).values_list('name', flat=True).distinct()[:MAX_HOSTS_PER_TARGET])
    known = {n.lower() for n in known} | {apex}
    found = classify(urls, apex, known)
    now = timezone.now()
    stored = 0
    for host, data in found.items():
        if not data['technologies']:
            HostArchive.objects.filter(project_id=domain.project_id, host=host).update(
                url_count=data['url_count'], checked_at=now)
            continue
        HostArchive.objects.update_or_create(
            project_id=domain.project_id, host=host,
            defaults={'domain': domain, 'technologies': data['technologies'], 'tech_text': _searchable(data['technologies']),
                      'url_count': data['url_count'], 'checked_at': now})
        stored += 1
    ledger.record('archive-urls', [apex], project=domain.project_id)
    return {'urls': len(urls), 'hosts': len(found), 'stored': stored}
