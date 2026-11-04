"""Does a target domain belong to the same owner as the project's other domains? Read before anything is guessed from its name.

The bucket sweep (``cveFeed.bucket_scan``) guesses bucket names from each target's own label. A project can hold a domain that is not the
client's (a look-alike, a domain added by mistake, a big company's brand that shares the client's word), and the guesses then find someone
else's buckets and report them as the client's. ``foreign_owner`` says, with its reason, when a domain shows another owner; it says nothing
(None) whenever the evidence is missing or mixed, so a domain is only left out on positive evidence:

1. **Registrant** (RDAP, the successor of whois): the domain's registrant organization is published and differs from every published
   registrant organization of the project's other domains -> another owner. The same organization as one of them -> the same owner, whatever
   the DNS says. Redacted or missing registrant data says nothing.
2. **Name servers and mail servers**: both the NS and the MX hosts sit under domains that are neither the domain itself, nor one of the
   project's domains, nor what any of the project's other domains use, nor a common hosting provider (``SHARED_INFRASTRUCTURE``) -> the domain
   runs on another organization's own infrastructure. Only read when the project has another domain whose name servers are known.

Not covered (follow-up): the HTTP redirect of the domain's web site to another company's, and addresses whose PTR and certificate name
another company.
"""
import logging
import re

logger = logging.getLogger(__name__)

CACHE_SECONDS = 24 * 3600
# Registrable domains of DNS and mail hosting used by many unrelated customers: a domain on them says nothing of its owner.
SHARED_INFRASTRUCTURE = frozenset({
    # DNS hosting and registrars' name servers
    'cloudflare.com', 'googledomains.com', 'google.com', 'domaincontrol.com', 'azure-dns.com', 'azure-dns.net', 'azure-dns.org',
    'azure-dns.info', 'digitalocean.com', 'linode.com', 'he.net', 'nsone.net', 'dnsmadeeasy.com', 'ultradns.com', 'ultradns.net',
    'ultradns.org', 'ultradns.biz', 'dynect.net', 'akam.net', 'markmonitor.com', 'cscdns.net', 'cscdns.uk', 'registrar-servers.com',
    'name-services.com', 'worldnic.com', 'dnsimple.com', 'dnsimple-edge.net', 'gandi.net', 'ovh.net', 'hostgator.com', 'bluehost.com',
    'wixdns.net', 'squarespacedns.com', 'hover.com', 'easydns.com', 'easydns.net', 'easydns.org', 'cloudns.net', 'rackspace.com',
    'dreamhost.com', 'name.com', 'namebrightdns.com', 'netlify.com', 'vercel-dns.com', 'hostinger.com', 'dns-parking.com', 'siteground.net',
    'inmotionhosting.com', 'a2hosting.com', 'ionos.com', 'ui-dns.com', 'ui-dns.de', 'ui-dns.org', 'ui-dns.biz', 'register.com',
    'networksolutions.com', 'safenames.net', 'nic.ru', 'yandex.net', 'alidns.com', 'dnspod.net', 'hichina.com', 'constellix.com',
    'constellix.net', 'neustar.biz', 'verisigndns.com', 'zoneedit.com', 'pairnic.com', 'mydyndns.org', 'dyndns.org',
    # mail hosting and filtering
    'outlook.com', 'office365.com', 'googlemail.com', 'pphosted.com', 'ppe-hosted.com', 'mimecast.com', 'mimecast.co.za',
    'messagelabs.com', 'iphmx.com', 'barracudanetworks.com', 'zoho.com', 'zoho.eu', 'zoho.in', 'secureserver.net', 'emailsrvr.com',
    'mailgun.org', 'sendgrid.net', 'amazonaws.com', 'messagingengine.com', 'icloud.com', 'protonmail.ch', 'mailchannels.net',
    'trendmicro.com', 'trendmicro.eu', 'sophos.com', 'mailcontrol.com', 'antispamcloud.com', 'spamexperts.com',
    'hornetsecurity.com', 'mx.microsoft', 'mailroute.net', 'improvmx.com', 'forwardemail.net', 'mxrouting.net', 'titan.email',
    'hostedemail.com', 'qq.com', 'yandex.ru', 'mail.ru', 'fastmail.com', 'everycloudtech.com', 'mailspamprotection.com',
})
_REDACTED = re.compile(r'redact|privacy|private|protect|withheld|not disclosed|proxy|guard|data protected|statutory masking|gdpr|n/a|^none$',
                       re.I)
_ORG_SUFFIX = re.compile(r'\b(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|sas|bv|nv|plc|pty|oy|ab|as|'
                         r'srl|spa|kk|technologies|holdings|group)\b\.?', re.I)


def _clean(name):
    return (name or '').strip().lower().rstrip('.')


def registrable(host):
    from targetApp.target_types import apex_domain
    return apex_domain(_clean(host))


def normalized_org(org):
    """An organization name compared loosely: case, punctuation and legal-form words ("Inc.", "LLC", "Technologies") do not count. ''
    for a redacted or empty name."""
    text = ' '.join(str(org or '').split())
    if not text or _REDACTED.search(text):
        return ''
    text = _ORG_SUFFIX.sub(' ', text.lower())
    return ' '.join(re.sub(r'[^a-z0-9]+', ' ', text).split())


class Lookup:
    """The DNS and RDAP reads ``foreign_owner`` makes (replaced in tests). ``records`` returns None when DNS gave no answer at all, so a
    failed lookup is never read as "no name servers"."""

    def records(self, name, rtype):
        import dns.exception
        import dns.resolver

        from cveFeed.hygiene import _resolver
        try:
            return [rd.to_text() for rd in _resolver().resolve(name, rtype)]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError):
            return None

    def registrant(self, domain):
        """The registrant organization RDAP publishes for ``domain`` ('' when redacted or not published, None when RDAP gave no answer).
        Cached for a day."""
        from django.core.cache import cache
        key = f'cvengine:registrant:{domain}'
        try:
            cached = cache.get(key)
        except Exception:  # noqa: BLE001 - a cache that is down only costs a lookup
            cached = None
        if cached is not None:
            return cached
        found = _rdap_registrant(domain)
        if found is not None:
            try:
                cache.set(key, found, CACHE_SECONDS)
            except Exception:  # noqa: BLE001
                pass
        return found


def _vcard_org(entity):
    """The organization of an RDAP entity's vCard ("org"), else its formatted name ("fn"), else ''."""
    items = [i for i in ((entity.get('vcardArray') or [None, []])[1] or []) if isinstance(i, list) and len(i) >= 4 and isinstance(i[3], str)]
    for kind in ('org', 'fn'):
        value = next((i[3].strip() for i in items if i[0] == kind and i[3].strip()), '')
        if value:
            return value
    return ''


def _registrant_in(data):
    for entity in data.get('entities') or []:
        if 'registrant' in (entity.get('roles') or []):
            return _vcard_org(entity)
        nested = _registrant_in(entity)
        if nested:
            return nested
    return ''


def _rdap_registrant(domain):
    """The registry's RDAP answer, then (thin registries such as .com publish no registrant) the registrar's, linked from it."""
    import requests

    from cveFeed import mailfail
    try:
        tld = domain.rsplit('.', 1)[-1]
        with requests.Session() as session:
            session.trust_env = False
            base = next((urls[0] for tlds, urls in mailfail._rdap_services(session) if tld in [t.lower() for t in tlds] and urls), None)
            if not base or not base.lower().startswith('https://'):
                return None
            resp = session.get(base.rstrip('/') + f'/domain/{domain}', timeout=mailfail.HTTP_TIMEOUT, allow_redirects=False,
                               headers={'Accept': 'application/rdap+json'})
            if resp.status_code != 200:
                return None
            data = resp.json()
            org = _registrant_in(data)
            if org:
                return org
            related = next((link.get('href') for link in data.get('links') or [] if link.get('rel') == 'related'
                            and str(link.get('href') or '').lower().startswith('https://') and '/domain/' in str(link.get('href'))), None)
            if not related:
                return ''
            resp = session.get(related, timeout=mailfail.HTTP_TIMEOUT, allow_redirects=False, headers={'Accept': 'application/rdap+json'})
            return _registrant_in(resp.json()) if resp.status_code == 200 else None
    except Exception:  # noqa: BLE001 - no answer says nothing about the owner
        return None


def _hosts(values, rtype):
    """Host names out of NS or MX record texts ("10 mx.example.com." -> "mx.example.com"); a null MX ("0 .") gives none."""
    out = []
    for value in values or []:
        parts = str(value).split()
        host = _clean(parts[-1] if parts else '')
        if host and host not in out:
            out.append(host)
    return out


def infrastructure(domain, lookup):
    """``(ns_domains, mx_domains)``: the registrable domains of a domain's name servers and mail servers, or None when DNS gave no answer."""
    ns, mx = lookup.records(domain, 'NS'), lookup.records(domain, 'MX')
    if ns is None or mx is None:
        return None
    return ({d for d in map(registrable, _hosts(ns, 'NS')) if d}, {d for d in map(registrable, _hosts(mx, 'MX')) if d})


def _shared(domains):
    return {d for d in domains if d in SHARED_INFRASTRUCTURE}


def foreign_owner(domain, other_domains, lookup=None):
    """Why ``domain`` (a registrable domain of the project) shows another owner than the project's ``other_domains``, or None (the same
    owner, or nothing shows otherwise). Never raises."""
    lookup = lookup or Lookup()
    domain = _clean(domain)
    others = sorted({_clean(d) for d in other_domains if _clean(d) and _clean(d) != domain})
    if not domain or not others:
        return None
    try:
        return _foreign_owner(domain, others, lookup)
    except Exception:  # noqa: BLE001 - no verdict, the domain is treated as the project's as before
        logger.exception('ownership check of %s failed', domain)
        return None


def _foreign_owner(domain, others, lookup):
    mine = lookup.registrant(domain)
    theirs = {d: lookup.registrant(d) for d in others}
    known = {d: org for d, org in theirs.items() if normalized_org(org)}
    if normalized_org(mine) and known:
        if normalized_org(mine) in {normalized_org(org) for org in known.values()}:
            return None
        return (f'the registrant of {domain} is "{mine}", and the project\'s other domains are registered to '
                + ', '.join(sorted({f'"{org}"' for org in known.values()})))
    own = infrastructure(domain, lookup)
    if own is None:
        return None
    ns, mx = own
    neighbours = [x for x in (infrastructure(d, lookup) for d in others) if x is not None and x[0]]
    if not neighbours or not ns or not mx:
        return None
    familiar = {domain, *others} | {d for n, m in neighbours for d in n | m}
    if (ns & familiar) or (mx & familiar) or _shared(ns) or _shared(mx):
        return None
    return (f'{domain} uses the name servers of {", ".join(sorted(ns))} and the mail servers of {", ".join(sorted(mx))}, which none of the '
            f'project\'s other domains use and which are not a hosting provider: it runs on another organization\'s infrastructure')
