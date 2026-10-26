"""Names the web application firewall or edge product in front of a host, with wafw00f (https://github.com/EnableSecurity/wafw00f).

The scanners already say that something blocks ("WAF"); they rarely say what. wafw00f fingerprints the product from how the host answers (headers,
cookies, block pages) with a handful of requests, five to seven for a host with nothing in front of it, a few dozen for one that has. Some of them
carry a harmless attack-looking string, so this is a loud check, but far lighter than any nuclei pass. The product is stored as a technology of the
host, like every other fingerprint, so it is searchable and the CVE correlation, the AI and the targeted nuclei pass see it. It gives a product and
no version: say "version unknown" and let a CVE-specific template find the version if it matters.

On by default; ``CVENGINE_WAFW00F=0`` turns it off. Bounded per scan (``CVENGINE_WAFW00F_MAX_HOSTS``) and run at most once per host per window
(``CVENGINE_TTL_WAFW00F``, the service ledger, 7 days).
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

SERVICE = 'wafw00f'
DEFAULT_MAX_HOSTS = 25
DEFAULT_TIMEOUT = 60
WORKERS = 4
GENERIC = {'generic', 'unknown', 'none', ''}


def enabled():
    return os.environ.get('CVENGINE_WAFW00F', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def installed():
    return shutil.which('wafw00f') is not None


def _int_env(name, default, floor):
    try:
        return max(floor, int(os.environ.get(name, default)))
    except ValueError:
        return default


def max_hosts():
    return _int_env('CVENGINE_WAFW00F_MAX_HOSTS', DEFAULT_MAX_HOSTS, 1)


def check_timeout():
    return _int_env('CVENGINE_WAFW00F_TIMEOUT', DEFAULT_TIMEOUT, 10)


def web_sites(scan):
    """``[(Subdomain, root URL)]`` for this scan's hosts that answered over HTTP, excluded and blocked names already removed (the same target list
    every stage uses). wafw00f is pointed at the root of the site, never at a path or a query."""
    from cveFeed.nuclei_scan import scan_targets
    from startScan.models import Subdomain
    allowed, _ips, _ports = scan_targets(scan)
    sites = []
    for sub in Subdomain.objects.filter(scan_history=scan, name__in=allowed, http_status__gt=0).order_by('name'):
        parts = urlsplit(sub.http_url or '')
        scheme = parts.scheme if parts.scheme in ('http', 'https') else 'https'
        netloc = parts.netloc if parts.scheme in ('http', 'https') and parts.netloc else sub.name
        sites.append((sub, f'{scheme}://{netloc}/'))
    return sites


def parse_output(text):
    """The products wafw00f named, ``[{'firewall', 'manufacturer'}]``, from its JSON output. A generic detection (something blocks, no product
    known) and "no WAF" name nothing. Pure; bad input gives an empty list."""
    try:
        rows = json.loads(text or '[]')
    except ValueError:
        return []
    found, seen = [], set()
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not row.get('detected'):
            continue
        product = str(row.get('firewall') or '').strip()[:100]
        if product.lower() in GENERIC or product.lower() in seen:
            continue
        seen.add(product.lower())
        found.append({'firewall': product, 'manufacturer': str(row.get('manufacturer') or '').strip()[:100]})
    return found


def run_wafw00f(url, timeout_s=None):
    """Run wafw00f for one URL. Returns ``{'products': [...], 'generic': bool, 'error': str}``; never raises."""
    timeout_s = timeout_s or check_timeout()
    with tempfile.TemporaryDirectory(prefix='cvengine-waf-') as directory:
        out = os.path.join(directory, 'out.json')
        try:
            subprocess.run(['wafw00f', '-a', '-r', '-T', str(min(timeout_s, 15)), '--no-colors', '-f', 'json', '-o', out, url],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s, check=False)
            with open(out, encoding='utf-8') as handle:
                text = handle.read(200_000)
        except subprocess.TimeoutExpired:
            return {'products': [], 'generic': False, 'error': 'timed out'}
        except (OSError, UnicodeError) as exc:
            return {'products': [], 'generic': False, 'error': str(exc)[:200]}
    try:
        generic = any(r.get('detected') for r in json.loads(text) if isinstance(r, dict))
    except ValueError:
        return {'products': [], 'generic': False, 'error': 'unreadable output'}
    products = parse_output(text)
    return {'products': products, 'generic': generic and not products, 'error': ''}


def run_for_scan(scan_id, runner=run_wafw00f, force=False):
    """Fingerprint the WAF in front of every web host this scan found, bounded and TTL-gated. Each product is stored as a technology of the host.
    Returns a summary dict; never raises."""
    from cveFeed import activity, ledger
    from startScan.models import ScanHistory, Technology
    if not enabled():
        return {'checked': 0, 'skipped': 'disabled'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project, scan.domain
    sites = web_sites(scan)
    if not sites:
        return {'checked': 0}
    covered = set() if force else ledger.fresh(SERVICE, [s.name for s, _ in sites], project.id)
    todo = [(s, u) for s, u in sites if s.name not in covered][:max_hosts()]
    if not todo:
        return {'checked': len(sites), 'tested': 0, 'reused': len(covered)}
    running = activity.log('run_check', f'Fingerprinting the web application firewall of {len(todo)} host(s) of {domain.name} with wafw00f',
                           project=project, status='running', scan_id=scan.id)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda site: runner(site[1]), todo))
    named = generic = errors = 0
    for (sub, _url), result in zip(todo, results):
        if result.get('error'):
            errors += 1
            continue  # not recorded: the host is asked again on the next scan
        ledger.record(SERVICE, [sub.name], project.id, scan)
        if result.get('generic'):
            generic += 1
        for product in result.get('products') or []:
            tech = Technology.objects.filter(name=product['firewall']).order_by('id').first() or Technology.objects.create(name=product['firewall'])
            sub.technologies.add(tech)
            named += 1
    activity.settle(running, 'done', message=(
        f'wafw00f for {domain.name}: {named} firewall(s) named on {len(todo)} host(s)'
        + (f', {generic} blocked without a known product' if generic else '') + (f', {errors} failed' if errors else '')))
    return {'checked': len(sites), 'tested': len(todo), 'named': named, 'generic': generic, 'errors': errors, 'reused': len(covered)}
