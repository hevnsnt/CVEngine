"""Who hosts a name, from what is already recorded about it: its CNAME, the Server header, the CDN flag, and reverse DNS. A CNAME that was never
stored is read by a Sentinel (``identity_check``), never by this server.

A name on a multi-tenant platform (Netlify, Vercel, GitHub Pages, Heroku, a CDN edge) shares its IP addresses with thousands of
other customers. Those addresses are the platform's, not the target's: another customer's site answers on them, and port-scanning
them is scanning a third party. ``classify`` says so (``shared_ip``) and ``shared_by_address`` finds such addresses so the port
scans can leave them alone."""
import logging
import re
import threading
import time

logger = logging.getLogger(__name__)

# (CNAME suffix, provider, kind). kind: paas, cdn, storage and saas are shared edges; cloud is one tenant's own machine.
PLATFORM_SUFFIXES = (
    ("netlify.app", "Netlify", "paas"), ("netlify.com", "Netlify", "paas"), ("netlifyglobalcdn.com", "Netlify", "paas"),
    ("vercel.app", "Vercel", "paas"), ("vercel-dns.com", "Vercel", "paas"), ("now.sh", "Vercel", "paas"),
    ("github.io", "GitHub Pages", "paas"), ("herokuapp.com", "Heroku", "paas"), ("herokudns.com", "Heroku", "paas"),
    ("azurewebsites.net", "Azure App Service", "paas"), ("azurefd.net", "Azure Front Door", "cdn"),
    ("trafficmanager.net", "Azure Traffic Manager", "cdn"), ("blob.core.windows.net", "Azure Storage", "storage"),
    ("cloudfront.net", "Amazon CloudFront", "cdn"), ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "paas"),
    ("awsglobalaccelerator.com", "AWS Global Accelerator", "cdn"), ("fastly.net", "Fastly", "cdn"),
    ("fastlylb.net", "Fastly", "cdn"), ("pages.dev", "Cloudflare Pages", "paas"), ("workers.dev", "Cloudflare Workers", "paas"),
    ("cdn.cloudflare.net", "Cloudflare", "cdn"), ("akamaiedge.net", "Akamai", "cdn"), ("edgekey.net", "Akamai", "cdn"),
    ("edgesuite.net", "Akamai", "cdn"), ("wpengine.com", "WP Engine", "paas"), ("squarespace.com", "Squarespace", "paas"),
    ("myshopify.com", "Shopify", "paas"), ("wixdns.net", "Wix", "paas"), ("ghost.io", "Ghost", "paas"),
    ("readthedocs.io", "Read the Docs", "paas"), ("surge.sh", "Surge", "paas"), ("onrender.com", "Render", "paas"),
    ("fly.dev", "Fly.io", "paas"), ("railway.app", "Railway", "paas"), ("firebaseapp.com", "Firebase Hosting", "paas"),
    ("web.app", "Firebase Hosting", "paas"), ("appspot.com", "Google App Engine", "paas"), ("run.app", "Google Cloud Run", "paas"),
    ("webflow.io", "Webflow", "paas"), ("pantheonsite.io", "Pantheon", "paas"), ("hubspot.net", "HubSpot", "paas"),
    ("statuspage.io", "Atlassian Statuspage", "paas"), ("zendesk.com", "Zendesk", "paas"),
    # SaaS fronts a customer points a name at (mail autodiscover, device enrolment, sign-in): the addresses are the vendor's
    ("outlook.com", "Microsoft 365", "saas"), ("office365.com", "Microsoft 365", "saas"), ("office.com", "Microsoft 365", "saas"),
    ("microsoftonline.com", "Microsoft 365", "saas"), ("manage.microsoft.com", "Microsoft Intune", "saas"),
    ("windows.net", "Microsoft", "saas"), ("sharepoint.com", "Microsoft SharePoint", "saas"), ("azure-api.net", "Azure API Management", "saas"),
    ("googlehosted.com", "Google Workspace", "saas"), ("ghs.google.com", "Google Workspace", "saas"),
    ("mimecast.com", "Mimecast", "saas"), ("pphosted.com", "Proofpoint", "saas"),
    ("atlassian.net", "Atlassian Cloud", "saas"), ("jira.com", "Atlassian Cloud", "saas"), ("bitbucket.io", "Bitbucket", "paas"),
    ("gitlab.io", "GitLab Pages", "paas"), ("my.salesforce.com", "Salesforce", "saas"), ("force.com", "Salesforce", "saas"),
    ("okta.com", "Okta", "saas"), ("oktapreview.com", "Okta", "saas"), ("freshdesk.com", "Freshdesk", "saas"),
    ("service-now.com", "ServiceNow", "saas"), ("slack.com", "Slack", "saas"), ("notion.site", "Notion", "paas"),
)
# Server header (lowercase, first word) -> (provider, kind)
SERVER_PLATFORMS = {
    "netlify": ("Netlify", "paas"), "vercel": ("Vercel", "paas"), "github.com": ("GitHub Pages", "paas"),
    "cloudflare": ("Cloudflare", "cdn"), "cloudfront": ("Amazon CloudFront", "cdn"), "akamaighost": ("Akamai", "cdn"),
    "amazons3": ("Amazon S3", "storage"), "heroku": ("Heroku", "paas"),
}
# reverse DNS suffix -> infrastructure (where the machine runs; not shared by itself)
REVERSE_INFRA = (
    (".compute-1.amazonaws.com", "Amazon Web Services (EC2)"), (".compute.amazonaws.com", "Amazon Web Services (EC2)"),
    (".compute.amazonaws.com.cn", "Amazon Web Services (EC2)"), (".bc.googleusercontent.com", "Google Cloud"),
    (".googleusercontent.com", "Google Cloud"), (".cloudapp.azure.com", "Microsoft Azure"), (".cloudapp.net", "Microsoft Azure"),
    (".linodeusercontent.com", "Linode"), (".vultrusercontent.com", "Vultr"), (".your-server.de", "Hetzner"),
)
SHARED_KINDS = ("paas", "cdn", "storage", "saas")
# Address ranges a provider publishes for its shared edge (Cloudflare's, https://www.cloudflare.com/ips/): a customer's name proxied through
# it answers from these addresses, whatever its recorded CNAME or Server header says, and they are never the customer's machines to test.
PROVIDER_RANGES = (
    ("Cloudflare", "cdn", ("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
                           "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
                           "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
                           "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32")),
)
_RANGES = None


def provider_range(address):
    """``(provider, kind)`` when ``address`` is inside a provider's published shared-edge range, else ``None``."""
    import ipaddress
    global _RANGES
    if _RANGES is None:
        _RANGES = [(provider, kind, [ipaddress.ip_network(n) for n in nets]) for provider, kind, nets in PROVIDER_RANGES]
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None
    for provider, kind, nets in _RANGES:
        if any(ip.version == net.version and ip in net for net in nets):
            return provider, kind
    return None
_LABEL = re.compile(r"[^a-z0-9.-]")


def _host(value):
    return _LABEL.sub("", (value or "").lower().strip().rstrip("."))


def _suffix_match(host):
    host = _host(host)
    for suffix, provider, kind in PLATFORM_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return provider, kind, suffix
    return None


def classify(name="", cname="", webserver="", reverse_pointers=(), cdn_name="", is_cdn=False):
    """``{'provider', 'kind', 'shared_ip', 'infrastructure', 'evidence'}`` for one name. Order of trust: its CNAME, its own name,
    the Server header, the recorded CDN flag. ``infrastructure`` is the cloud its addresses reverse-resolve to, when one does."""
    provider, kind, evidence = "", "", []
    hit = _suffix_match(cname)
    if hit:
        provider, kind, evidence = hit[0], hit[1], [f"CNAME {_host(cname)}"]
    if not provider:
        hit = _suffix_match(name)
        if hit:
            provider, kind, evidence = hit[0], hit[1], [f"hosted on {hit[2]}"]
    first = re.split(r"[/ (]", (webserver or "").strip().lower(), maxsplit=1)[0]
    if first in SERVER_PLATFORMS:
        server_provider, server_kind = SERVER_PLATFORMS[first]
        if not provider:
            provider, kind = server_provider, server_kind
        if server_provider == provider or not evidence:
            evidence.append(f"Server: {webserver.strip()[:60]}")
    if not provider and is_cdn:
        provider, kind, evidence = (cdn_name or "CDN").strip()[:60] or "CDN", "cdn", ["flagged as a CDN address"]
    infrastructure = ""
    for pointer in reverse_pointers or ():
        pointer = _host(pointer)
        for suffix, label in REVERSE_INFRA:
            if pointer.endswith(suffix):
                infrastructure = label
                evidence.append(f"reverse DNS {pointer}")
                break
        if infrastructure:
            break
    return {"provider": provider, "kind": kind or ("cloud" if infrastructure else ""),
            "shared_ip": kind in SHARED_KINDS, "infrastructure": infrastructure, "evidence": evidence[:4]}


# ----------------------------------------------------------------------------- DNS (cached, bounded, read by a Sentinel)

CANON_TTL = 3600
CANON_MAX = 4096
MAX_LOOKUPS = 25
_canon, _canon_lock = {}, threading.Lock()


def _cached(key, now):
    with _canon_lock:
        hit = _canon.get(key)
    return hit[0] if hit and now - hit[1] < CANON_TTL else None


def canonical_names(names, scan=None):
    """``{name: canonical}`` for hostnames (``''`` when a name is not an alias), cached for an hour. The lookup is made by a Sentinel
    (``identity_check``, ``agentapi.probe_dispatch.try_identity``): this server sends nothing. A name that is not asked (no project holds it, or
    its policy leaves it out), a lookup the Sentinel could not answer, or no Sentinel able to take the kind (it has no local path) is simply
    missing from the answer and is not cached: unknown, never \"not an alias\". Never raises."""
    now = time.monotonic()
    found, wanted = {}, []
    for name in dict.fromkeys(_host(n) for n in names):
        if not name:
            continue
        hit = _cached(name, now)
        if hit is not None:
            found[name] = hit
        else:
            wanted.append(name)
    if not wanted:
        return found
    try:
        from agentapi import probe_dispatch
        from startScan.models import Subdomain
        projects = {}
        for name, project in Subdomain.objects.filter(name__in=wanted, target_domain__isnull=False).values_list('name', 'target_domain__project_id').distinct():
            projects.setdefault(project, []).append(_host(name))
        from dashboard.models import Project
        for project_id, held in projects.items():
            from agentapi import sentinel_dispatch
            project = Project.objects.get(pk=project_id)
            if not sentinel_dispatch.any_scanner_for(project, 'identity_check'):  # a best-effort read: with no scanner for it nothing waits, the stored data classifies
                continue
            queries = [{'id': name, 'name': name, 'type': 'CNAME'} for name in dict.fromkeys(held) if name in wanted]
            answers, _certs = probe_dispatch.try_identity(project, scan, dns=queries)
            for query in queries:
                row = answers.get(query['id'])
                if not row or row.get('status') == 'unknown' or query['name'] in found:
                    continue
                canon = _host(row.get('canonical') or '')
                canon = '' if canon == query['name'] else canon
                found[query['name']] = canon
                with _canon_lock:
                    if len(_canon) >= CANON_MAX:
                        _canon.clear()
                    _canon[query['name']] = (canon, now)
    except Exception as exc:  # noqa: BLE001 - ScannerUnavailable and every other failure: no answer, the classification uses what is stored
        logger.info('live CNAME lookups were not answered (%s): the stored data classifies these names', exc)
    return found


def canonical_name(name):
    """The name a hostname's CNAME chain ends at ('' when it is not an alias or nothing answered), through ``canonical_names``."""
    key = _host(name)
    return canonical_names([key]).get(key, "") if key else ""


def shared_by_address(addresses, lookup=None):
    """``{address: classification}`` for the addresses that belong to a shared platform: some name recorded on the address has a
    platform CNAME, Server header or CDN flag. A name with no recorded CNAME is resolved once (cached, at most MAX_LOOKUPS names
    per call, all in one ``identity_check`` task) so a host whose CNAME was never stored is still recognised. ``lookup(name)`` replaces
    that read (tests)."""
    from startScan.models import Subdomain
    wanted = sorted({a for a in addresses if a})
    if not wanted:
        return {}
    found, lookups = {}, 0
    for address in wanted:  # the provider's own published range decides first, whatever the names on the address say
        known = provider_range(address)
        if known:
            found[address] = {"provider": known[0], "kind": known[1], "shared_ip": True, "infrastructure": "", "evidence": [f"in {known[0]}'s published address range"]}
    rows = list(Subdomain.objects.filter(ip_addresses__address__in=wanted).values_list(
        "ip_addresses__address", "name", "cname", "webserver", "cdn_name", "is_cdn", "ip_addresses__is_cdn").distinct())
    if lookup is None:
        asking = []
        for address, name, cname, webserver, cdn_name, sub_cdn, ip_cdn in rows:
            if address in found or (cname or "").strip() or len(asking) >= MAX_LOOKUPS:
                continue
            if not classify(name=name, cname="", webserver=webserver or "", cdn_name=cdn_name or "", is_cdn=bool(sub_cdn or ip_cdn))["shared_ip"]:
                asking.append(name)
        read = canonical_names(asking)
        lookup = lambda name: read.get(_host(name), "")  # noqa: E731
    for address, name, cname, webserver, cdn_name, sub_cdn, ip_cdn in rows:
        if address in found:
            continue
        verdict = classify(name=name, cname=cname or "", webserver=webserver or "", cdn_name=cdn_name or "", is_cdn=bool(sub_cdn or ip_cdn))
        if not verdict["shared_ip"] and not (cname or "").strip() and lookups < MAX_LOOKUPS:
            lookups += 1
            canon = lookup(name)
            if canon:
                verdict = classify(name=name, cname=canon, webserver=webserver or "")
        if verdict["shared_ip"]:
            found[address] = verdict
    return found


def mark_shared(found):
    """Record the addresses ``shared_by_address`` found as CDN/edge addresses, which the port sweep already skips for good."""
    from startScan.models import IpAddress
    if found:
        IpAddress.objects.filter(address__in=list(found)).update(is_cdn=True)
    return len(found)
