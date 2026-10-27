"""Which CVEs cvENGINE never matches to a host: the ones only usable from the host itself.

cvENGINE looks at hosts from outside. A flaw that needs the attacker already running code on the machine (a kernel or Win32k
privilege escalation, a local file-parsing bug) is decided by software and patch levels an external scan cannot see, so a "match" on it
is a guess that is almost always wrong: a technology label such as "Windows Communication Foundation" says nothing about the Win32k
driver. Such a CVE stays in the catalogue (and its record says how to check a host you can log in to) but is never turned into a
finding, a validation or an AI review.

``classify`` decides from the record alone, in this order:
  1. the CVSS vector: attack vector Local (AV:L) or Physical (AV:P) is local-only;
  2. with no vector (older CVE List records carry none): a description that says the attacker must be local, or that is an elevation of
     privilege, a kernel/driver/Win32k flaw, in an operating system, with nothing in it that says it can be reached over a network.
A record that says "remote", "unauthenticated" or names a network protocol is never classified local by the text rules, and a product that
is not an operating system or client component (Exchange, SharePoint, a web application) is never classified local by its wording alone.
"""
import re

from django.utils import timezone

VECTOR_LOCAL = re.compile(r'(?:^|/)AV:[LP](?:/|$)')
# SQL form of the same pattern, for the queryset filter in cve_pool and the vector backfill
VECTOR_LOCAL_SQL = r'(^|/)AV:[LP](/|$)'

LOCAL_STRONG = re.compile(
    r'\b(?:local(?:ly)?[ -](?:attacker|user|users|privilege|privileges|access|authenticated|account|administrator)'
    r'|locally[ -](?:authenticated|exploit|logged|access)|physical(?:ly)? (?:access|proximity)|physically[ -]proximate'
    r'|requires? (?:the )?(?:an )?(?:attacker|user) (?:to )?(?:already )?(?:have|has|obtain|with) (?:local|physical|code execution|shell)'
    r'|must (?:already )?have (?:local|physical|shell|code execution)'
    r'|win32k|kernel[- ]mode drivers?|windows kernel|common log file system|cldflt|ntfs\.sys|win32kfull|dwm core|windows gdi)\b',
    re.I)
PRIVESC = re.compile(r'\b(?:elevation of privilege|privilege escalation|escalat\w* (?:of )?privileges?|escalate privileges)\b', re.I)
REMOTE = re.compile(
    r'\b(?:remote(?:ly)?|unauthenticated|over (?:the )?(?:network|internet|http|https|lan)|network[- ]based|network attacker|'
    r'via (?:a )?(?:network|http|https|web|crafted (?:http|request|packet|url))|crafted (?:http|request|packet|url|web)|'
    r'web (?:server|application|interface|page|console)|\bhttps?\b|smb|rdp|dns|ftp|ssh|ldap|snmp|api request)\b', re.I)
# products whose flaws are decided on the machine: an operating system, a kernel, a driver
OS_PRODUCT = re.compile(
    r'^(?:microsoft )?(?:windows(?: (?:server|10|11|8\.1|8|7|vista|xp|rt|nt)\b.*)?|win32k|linux(?: kernel)?|macos|mac os x?|os x|ios|ipados|'
    r'tvos|watchos|android|freebsd|openbsd|netbsd|solaris|aix|hp-ux|kernel|xnu)$', re.I)


def _products(affected):
    names = []
    for item in affected if isinstance(affected, list) else []:
        if isinstance(item, dict):
            name = item.get('product') or item.get('package') or ''
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
    return names


def classify(cvss_vector, description, title='', affected=None):
    """``(local_only, why)`` for one CVE record. ``why`` is empty when it is not local-only."""
    vector = cvss_vector or ''
    if VECTOR_LOCAL.search(vector):
        return True, 'its CVSS attack vector is local or physical'
    if 'AV:' in vector:  # a vector that says network or adjacent settles it, whatever the wording
        return False, ''
    text = f'{title or ""} {description or ""}'
    if not text.strip() or REMOTE.search(text):
        return False, ''
    products = _products(affected)
    is_os = bool(products) and all(OS_PRODUCT.match(p) for p in products)
    if LOCAL_STRONG.search(text) and (is_os or not products or re.search(r'local|physical', text, re.I)):
        return True, 'the record says it needs local access or is a kernel or driver flaw in the operating system'
    if PRIVESC.search(text) and is_os:
        return True, 'it is an elevation of privilege in an operating system, which needs code already running on the host'
    return False, ''


def reason_text(why=''):
    return ('Closed automatically: local-only vulnerability' + (f' ({why})' if why else '') + '. An attacker needs to be on the host, and '
            'an external scan cannot see the software or patch level that decides it, so cvENGINE does not report it as a finding. '
            'The CVE record says how to check a host you can log in to.')


def refresh(limit=20000, chunk=2000):
    """Work out ``local_only`` for CVEs never classified or changed since. Returns how many were examined."""
    from django.db.models import F, Q

    from cveFeed.models import CVEDetection, CVEEntry
    done = 0
    while done < limit:
        rows = list(CVEEntry.objects.filter(Q(locality_at__isnull=True) | Q(locality_at__lt=F('synced_at')))
                    .only('id', 'cvss_vector', 'original_description', 'title', 'affected', 'local_only')[:chunk])
        if not rows:
            break
        now = timezone.now()
        scopes = dict(CVEDetection.objects.filter(cve_entry_id__in=[r.id for r in rows]).values_list('cve_entry_id', 'strategy__scope'))
        for row in rows:
            row.local_only = classify(row.cvss_vector, row.original_description, row.title, row.affected)[0]
            if 'AV:' not in (row.cvss_vector or '') and scopes.get(row.id) in ('external', 'local_only'):
                row.local_only = scopes[row.id] == 'local_only'  # the model's reading of a record with no attack vector
            row.locality_at = now
        CVEEntry.objects.bulk_update(rows, ['local_only', 'locality_at'])
        done += len(rows)
    return done


def close_local_matches():
    """Close every open match of a local-only CVE, the way a rejected CVE's matches are closed, and rescore the hosts they were on.
    Matches a person already worked keep their remediation state, and so do the ones the host reported itself (source ``host``,
    cveFeed.inventory_match): those are how a local-only CVE becomes a finding, from the one place that can decide it.
    Returns how many were closed."""
    from cveFeed import scoring
    from cveFeed.models import CVEMatch
    from startScan.models import Subdomain
    open_matches = CVEMatch.objects.filter(cve_entry__local_only=True).exclude(source='host').exclude(
        ai_verdict='not_affected', ai_reason__startswith='Closed automatically:')
    ids = list(open_matches.values_list('id', flat=True))
    if not ids:
        return 0
    hosts = list(Subdomain.objects.filter(cve_matches__in=ids).values_list('target_domain__project_id', 'name').distinct())
    closed = CVEMatch.objects.filter(id__in=ids).update(
        ai_verdict='not_affected', ai_model='deterministic-locality', confidence=0.0, updated_at=timezone.now(),
        ai_reason=reason_text('CVSS attack vector local, or a kernel or operating-system elevation of privilege'))
    by_project = {}
    for project_id, name in hosts:
        if project_id:
            by_project.setdefault(project_id, set()).add(name)
    for project_id, names in by_project.items():
        for start in range(0, len(names), scoring.CHUNK):
            scoring.rescore_quietly(project_id, sorted(names)[start:start + scoring.CHUNK])
    return closed


def apply_scope(cve, scope):
    """The model's scope decision for a CVE (``external`` or ``local_only``). A CVSS attack vector settles the matter and is never
    overridden; ``unclear`` leaves the rule-based classification as it was. Returns True when the flag was set from the model's answer."""
    from cveFeed.models import CVEEntry
    if 'AV:' in (cve.cvss_vector or '') or scope not in ('external', 'local_only'):
        return False
    CVEEntry.objects.filter(pk=cve.pk).update(local_only=(scope == 'local_only'), locality_at=timezone.now())
    return True
