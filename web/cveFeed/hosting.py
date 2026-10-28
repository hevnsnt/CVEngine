"""Who hosts a name, from what is already recorded about it: its CNAME, the Server header, the CDN flag, and reverse DNS.

A name on a multi-tenant platform (Netlify, Vercel, GitHub Pages, Heroku, a CDN edge) shares its IP addresses with thousands of
other customers. Those addresses are the platform's, not the target's: another customer's site answers on them, and port-scanning
them is scanning a third party. ``classify`` says so (``shared_ip``) and ``shared_by_address`` finds such addresses so the port
scans can leave them alone."""
import re
import socket
import threading
import time

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


# ----------------------------------------------------------------------------- DNS (cached, bounded)

CANON_TTL = 3600
CANON_MAX = 4096
MAX_LOOKUPS = 25
_canon, _canon_lock = {}, threading.Lock()


def canonical_name(name):
    """The name a hostname's CNAME chain ends at ('' when it is not an alias or does not resolve), cached for an hour. One
    ``getaddrinfo`` call, the same lookup the target checks already make."""
    key = _host(name)
    if not key:
        return ""
    now = time.monotonic()
    with _canon_lock:
        hit = _canon.get(key)
        if hit and now - hit[1] < CANON_TTL:
            return hit[0]
    try:
        info = socket.getaddrinfo(key, None, type=socket.SOCK_STREAM, flags=socket.AI_CANONNAME)
        canon = _host(info[0][3]) if info else ""
    except (OSError, UnicodeError):
        canon = ""
    canon = "" if canon == key else canon
    with _canon_lock:
        if len(_canon) >= CANON_MAX:
            _canon.clear()
        _canon[key] = (canon, now)
    return canon


def shared_by_address(addresses, lookup=canonical_name):
    """``{address: classification}`` for the addresses that belong to a shared platform: some name recorded on the address has a
    platform CNAME, Server header or CDN flag. A name with no recorded CNAME is resolved once (cached, at most MAX_LOOKUPS names
    per call) so a host whose CNAME was never stored is still recognised."""
    from startScan.models import Subdomain
    wanted = sorted({a for a in addresses if a})
    if not wanted:
        return {}
    rows = Subdomain.objects.filter(ip_addresses__address__in=wanted).values_list(
        "ip_addresses__address", "name", "cname", "webserver", "cdn_name", "is_cdn", "ip_addresses__is_cdn").distinct()
    found, lookups = {}, 0
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
