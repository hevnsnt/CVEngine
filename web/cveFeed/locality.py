"""Which CVEs cvENGINE never matches to a host: the ones only usable from the host itself.

cvENGINE looks at hosts from outside. A flaw that needs the attacker already running code on the machine (a kernel or Win32k
privilege escalation, a local file-parsing bug) is decided by software and patch levels an external scan cannot see, so a "match" on it
is a guess that is almost always wrong: a technology label such as "Windows Communication Foundation" says nothing about the Win32k
driver. Such a CVE stays in the catalogue (and its record says how to check a host you can log in to) but is never turned into a
finding, a validation or an AI review.

``classify`` decides from the record alone, in this order:
  1. a Linux kernel record (the kernel CNA's "In the Linux kernel, the following vulnerability has been resolved", or an affected
     product that is only the kernel) with no vector: local-only, because the running kernel build and the distribution's backported
     fixes decide it and no external scan can read them. A kernel flaw that says it is reachable over a network (a network vector, or
     "remote" in its text: SACK Panic, TIPC) stays remote, and so does one on the CISA KEV list unless its vector is local;
  2. the CVSS vector: attack vector Local (AV:L) or Physical (AV:P) is local-only; any other vector settles it as not local;
  3. with no vector (older CVE List records carry none): a description that says the attacker must be local, or that is an elevation of
     privilege, a kernel/driver/Win32k flaw, in an operating system, with nothing in it that says it can be reached over a network.
A record that says "remote", "unauthenticated" or names a network protocol is never classified local by the text rules, and a product that
is not an operating system or client component (Exchange, SharePoint, a web application) is never classified local by its wording alone.
"""
import re
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone

# CVEs classified before this moment are classified again: bump it when ``classify`` changes, so existing records follow the rules
RULES_AT = datetime(2026, 10, 27, 2, 0, tzinfo=dt_timezone.utc)

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
KERNEL_CNA = re.compile(r'^\s*in the linux kernel,? the following vulnerability has been (?:resolved|fixed)', re.I)
LINUX_KERNEL_PRODUCT = re.compile(r'^(?:linux(?:[ _]kernel)?|kernel)$', re.I)
# products whose flaws are decided on the machine: an operating system, a kernel, a driver
OS_PRODUCT = re.compile(
    r'^(?:microsoft )?(?:windows(?:[ _](?:server|10|11|8\.1|8|7|vista|xp|rt|nt|kernel|gdi|common log file system)\b.*)?|win32k|'
    r'linux(?:[ _]kernel)?|macos|mac os x?|os x|ios|ipados|tvos|watchos|android|freebsd|openbsd|netbsd|solaris|aix|hp-ux|kernel|xnu)$', re.I)


def _products(affected):
    names = []
    for item in affected if isinstance(affected, list) else []:
        if isinstance(item, dict):
            name = item.get('product') or item.get('package') or ''
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
    return names


def is_linux_kernel_record(description, title='', affected=None):
    """A Linux kernel CVE: written by the kernel CNA, or naming nothing but the kernel as its product."""
    if KERNEL_CNA.search(description or '') or KERNEL_CNA.search(title or ''):
        return True
    products = _products(affected)
    return bool(products) and all(LINUX_KERNEL_PRODUCT.match(p) for p in products)


def classify(cvss_vector, description, title='', affected=None, kev=False):
    """``(local_only, why)`` for one CVE record. ``why`` is empty when it is not local-only."""
    vector = cvss_vector or ''
    text = f'{title or ""} {description or ""}'
    if VECTOR_LOCAL.search(vector):
        return True, 'its CVSS attack vector is local or physical'
    if 'AV:' in vector:  # a vector that says network or adjacent settles it, whatever the wording
        return False, ''
    if is_linux_kernel_record(description, title, affected):
        if kev or REMOTE.search(text):  # exploited in the wild, or a flaw the record says a remote attacker can reach: not host-only
            return False, ''
        return True, ('it is a Linux kernel flaw: the running kernel build and the distribution\'s backported fixes decide it, '
                      'and only the host can report them')
    if not text.strip() or REMOTE.search(text):
        return False, ''
    products = _products(affected)
    is_os = bool(products) and all(OS_PRODUCT.match(p) for p in products)
    if LOCAL_STRONG.search(text) and (is_os or not products or re.search(r'local|physical', text, re.I)):
        return True, 'the record says it needs local access or is a kernel or driver flaw in the operating system'
    if PRIVESC.search(text) and is_os:
        return True, 'it is an elevation of privilege in an operating system, which needs code already running on the host'
    if is_os:  # an operating-system component with no vector and nothing in its text that says a network reaches it
        return True, 'it is a flaw in an operating-system component that nothing in the record says a network can reach'
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
        rows = list(CVEEntry.objects.filter(Q(locality_at__isnull=True) | Q(locality_at__lt=F('synced_at')) | Q(locality_at__lt=RULES_AT))
                    .only('id', 'cvss_vector', 'original_description', 'title', 'affected', 'local_only', 'kev')[:chunk])
        if not rows:
            break
        now = timezone.now()
        scopes = dict(CVEDetection.objects.filter(cve_entry_id__in=[r.id for r in rows]).values_list('cve_entry_id', 'strategy__scope'))
        for row in rows:
            row.local_only = classify(row.cvss_vector, row.original_description, row.title, row.affected, row.kev)[0]
            if ('AV:' not in (row.cvss_vector or '') and scopes.get(row.id) in ('external', 'local_only')
                    and not (is_linux_kernel_record(row.original_description, row.title, row.affected) and not row.kev)):
                row.local_only = scopes[row.id] == 'local_only'  # the model's reading of a record with no attack vector
            row.locality_at = now
        CVEEntry.objects.bulk_update(rows, ['local_only', 'locality_at'])
        done += len(rows)
    return done


CLOSE_CHUNK = 2000


def close_local_matches():
    """Close every open match of a local-only CVE, the way a rejected CVE's matches are closed, and rescore the hosts they were on.
    A match somebody vouches for stays (``match_policy.unworked``: worked by a person, a template hit, a distribution verdict, a
    host's own report): the classification is a guess from the record, and that is evidence about the host. Done in chunks, each
    guarded again by its own UPDATE. Returns how many were closed."""
    from cveFeed import scoring
    from cveFeed.match_policy import settle_triage, unworked
    from cveFeed.models import CVEMatch
    from cveFeed.views import bump_stats_revision
    from startScan.models import Subdomain
    reason = reason_text('CVSS attack vector local, or a kernel or operating-system elevation of privilege')
    todo = unworked(CVEMatch.objects.filter(cve_entry__local_only=True)).exclude(
        ai_verdict='not_affected', ai_reason__startswith='Closed automatically:')
    closed = 0
    by_project = {}
    while True:
        ids = list(todo.order_by('id').values_list('id', flat=True)[:CLOSE_CHUNK])
        if not ids:
            break
        now = timezone.now()
        count = todo.filter(id__in=ids).update(
            ai_verdict='not_affected', ai_model='deterministic-locality', confidence=0.0, updated_at=now, ai_reason=reason)
        if not count:
            break
        done = CVEMatch.objects.filter(id__in=ids, ai_model='deterministic-locality', updated_at=now)
        settle_triage(done.values('id'), reason, now)
        hosts = Subdomain.objects.filter(cve_matches__in=done.values('id')).values_list('target_domain__project_id', 'name').distinct()
        for project_id, name in hosts:
            if project_id:
                by_project.setdefault(project_id, set()).add(name)
        closed += count
    for project_id, names in by_project.items():
        for start in range(0, len(names), scoring.CHUNK):
            scoring.rescore_quietly(project_id, sorted(names)[start:start + scoring.CHUNK])
    if closed:
        bump_stats_revision()
    return closed


def apply_scope(cve, scope):
    """The model's scope decision for a CVE (``external`` or ``local_only``). A CVSS attack vector settles the matter and is never
    overridden; ``unclear`` leaves the rule-based classification as it was. Returns True when the flag was set from the model's answer."""
    from cveFeed.models import CVEEntry
    if ('AV:' in (cve.cvss_vector or '') or scope not in ('external', 'local_only')
            or (is_linux_kernel_record(cve.original_description, cve.title, cve.affected) and not getattr(cve, 'kev', False))):
        return False
    CVEEntry.objects.filter(pk=cve.pk).update(local_only=(scope == 'local_only'), locality_at=timezone.now())
    return True
