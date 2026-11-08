"""OpenVAS (Greenbone Community Edition) as an optional vulnerability scanner, run by Sentinels.

The add-on is OFF by default and costs nothing while it is off: the beat entry that drives it is created disabled, and nothing in this module does
anything unless an App Admin switched it on (Settings > OpenVAS) and opted a project's hosts in. Nothing here runs inside a scan: it is a slow
background sweep on its own queue (``openvas_queue``), like ``cveFeed.tls_audit``.

How it works. This server never talks to gvmd and never runs a scan: the Sentinel's own GVM stack scans (kind ``openvas``, in
``sentinel_dispatch.NEVER_LOCAL``; the Sentinel client is ``client/openvas.py`` in the Sentinel repo, which makes and verifies the scan configuration,
the target and the task). A beat entry calls ``tick`` every 15 minutes, and a tick does one small step, so a worker restart loses nothing:

* nothing is running: pick the next opted-in project with hosts that are due (once a week each, ``ledger`` service ``openvas``), vet every host
  (``scannable_hosts``, exclusions, ``pinned_transport.resolve``: only the vetted numeric address is ever put in a task, never a name), and hand one
  batch to a Sentinel that declares ``openvas`` for the project (``dispatch_to_sentinel``). With no such Sentinel the hosts stay due;
* a task is running: ask the ``SentinelTask``'s status; when it is done import the reported results (``poll_sentinel``), when it failed, expired or was
  lost say so. At most one task runs at a time (a unique constraint on ``OpenvasRun``).

The task carries this instance's excluded NVT families (``EXCLUDED_FAMILIES``) and its preferences, never a copy a Sentinel might carry out of date.

Results. Every result that names a CVE becomes a ``ProbeObservation`` (one per host, port and NVT OID: the dedupe key and the durable record), a
``Vulnerability`` (source ``openvas``) and ``CVEMatch`` evidence (source ``openvas``). Only a result whose quality of detection (QoD) is at
least ``CONFIRMED_QOD`` (95) or of a hard type (``exploit``, ``remote_vul``, ``remote_app``, ``remote_active``, ``package``, ``registry``: the
check ran against the service or read the installed package) is hard evidence (``template_result`` ``vulnerable``). Greenbone's QoD 80 is
``remote_banner`` and ``executable_version``, a version read from a banner or a binary, which a backport defeats: it is stored with its QoD
and never confirms anything. A result that is absent from a later complete scan of the same host is resolved. The text of an NVT is
third-party text: it is clipped, stripped of control characters and stored as plain text, and nothing here marks it safe for HTML.

A run an earlier version started against this server's own gvmd (an ``OpenvasRun`` with no Sentinel task) is closed as failed at the next tick
(``tick``): no host is recorded as failed, so they stay due and go to a Sentinel."""
import ipaddress
import logging
import os
import re
import time
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

SERVICE = 'openvas'
FAILED_SERVICE = 'openvas-failed'  # a host that could not be scanned: asked again in three days, not at the next tick
PROBE = 'openvas'
OBS_KIND = 'openvas'
SOURCE = 'openvas'  # Vulnerability.source and CVEMatch.source
QUEUE = 'openvas_queue'
BEAT_NAME = 'cvengine-openvas-sweep'
CONFIRMED_QOD = 95  # the lowest QoD of a hard type when a result carries no type (remote_active is 95, package and registry 97, remote_vul 99)
HARD_QOD_TYPES = frozenset({'exploit', 'remote_vul', 'remote_app', 'remote_active', 'package', 'registry'})
FRESH_DAYS = 21  # an observation older than this is not carried onto a new scan's host row
DEFAULT_MAX_HOSTS = 1  # hosts in one task: a run is slow (hours per host), so one host per task keeps what a stop or a failure costs to one host
MAX_HOSTS_PER_TASK = 16  # the most CVENGINE_OPENVAS_MAX_HOSTS may give: the Sentinel client refuses an OpenVAS task of more hosts (client/openvas.py MAX_HOSTS)
DEFAULT_MAX_HOURS = 24  # the time budget PER HOST: a task of n hosts gets n times this; when it runs out, what was found so far is kept
DEFAULT_MAX_CHECKS = 4  # NVTs run at a time against a host (Greenbone's own default); CVENGINE_OPENVAS_MAX_CHECKS
MAX_RESULTS = 5000  # per task: more is a misconfigured scan, not a report
MAX_TEXT = 4000
RESULT_EVIDENCE = 1000  # how much of an NVT's result text a CVE match keeps (triage quotes part of it, cleaned)

# Families left out of the scan configuration, and why. "Denial of Service": NVTs that crash or hang the service they test (the reason
# ``safe_checks`` exists, enforced here a second time at the family level). "Brute force attacks": password guessing, which locks accounts out
# and is a different act from checking for a known vulnerability. Every other family is "Full and fast"'s. ``safe_checks`` stays on, which makes
# the scanner skip any remaining NVT whose category is destructive, denial, kill-host or flood.
EXCLUDED_FAMILIES = ('Denial of Service', 'Brute force attacks')

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')  # bounded: CveId.name holds 100 characters
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_TAILNET = [ipaddress.ip_network(n) for n in ('100.64.0.0/10', 'fd7a:115c:a1e0::/48')]


# ----------------------------------------------------------------------------- settings and text

def _env_int(name, default, low=1):
    try:
        return max(low, int(os.environ.get(name, default)))
    except ValueError:
        return default


_warned_max_hosts = set()  # the values of CVENGINE_OPENVAS_MAX_HOSTS already warned about, so a tick every 15 minutes does not repeat it


def max_hosts():
    """Hosts in one task (``CVENGINE_OPENVAS_MAX_HOSTS``, 1 to ``MAX_HOSTS_PER_TASK``). A Sentinel refuses a task of more than 16 hosts, so a larger
    value is held to 16 (with a warning) rather than dispatching tasks that fail."""
    value = _env_int('CVENGINE_OPENVAS_MAX_HOSTS', DEFAULT_MAX_HOSTS)
    if value > MAX_HOSTS_PER_TASK:
        if value not in _warned_max_hosts and len(_warned_max_hosts) < 100:
            _warned_max_hosts.add(value)
            logger.warning('CVENGINE_OPENVAS_MAX_HOSTS=%r is above %s, the most a Sentinel takes in one OpenVAS task: using %s',
                           value, MAX_HOSTS_PER_TASK, MAX_HOSTS_PER_TASK)
        value = MAX_HOSTS_PER_TASK
    return value


def max_hours():
    """The time budget per host, in hours."""
    return _env_int('CVENGINE_OPENVAS_MAX_HOURS', DEFAULT_MAX_HOURS)


def budget_hours(hosts):
    """The budget of a task of ``hosts`` hosts: ``max_hours()`` for each."""
    return max_hours() * max(1, int(hosts))


def task_preferences():
    """GVM task preferences: ``max_checks`` NVTs at a time (``CVENGINE_OPENVAS_MAX_CHECKS``, 1 to 10) against one host at a time. Fewer is gentler on the
    target and slower: at 2 a host took about a day, at 4 (Greenbone's default) about half that."""
    return {'max_checks': str(min(10, _env_int('CVENGINE_OPENVAS_MAX_CHECKS', DEFAULT_MAX_CHECKS))), 'max_hosts': '1'}


def clean(value, limit=MAX_TEXT):
    """Third-party text as plain, bounded text: control characters removed, whitespace kept, clipped."""
    return _CONTROL.sub('', str(value or '')).strip()[:limit]


def _enabled():
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.objects.first()
    return bool(row and row.enabled)

# ----------------------------------------------------------------------------- feed state and the safe configuration


# ----------------------------------------------------------------------------- the resource guard


# ----------------------------------------------------------------------------- choosing hosts

_DOCUMENTATION = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]
OWN_TTL = 3600
OWN_RETRY = 60  # how long a failed lookup of this server's own name is remembered
_own = {'at': 0.0, 'addresses': frozenset()}


def own_addresses():
    """The addresses this cvENGINE instance answers on: ``CVENGINE_OWN_ADDRESSES`` (comma separated; for an instance behind NAT or a load balancer)
    and what ``DOMAIN_NAME`` resolves to, cached for an hour. A scan of any of them would be this instance scanning itself."""
    import socket
    from django.conf import settings
    now = time.monotonic()
    if _own['at'] and now - _own['at'] < OWN_TTL:
        return _own['addresses']
    found, looked_up = set(), True
    for part in os.environ.get('CVENGINE_OWN_ADDRESSES', '').split(','):
        part = part.strip()
        if part:
            found.add(_compressed(part))
    name = str(getattr(settings, 'DOMAIN_NAME', '') or '').strip()
    if name:
        try:
            found.update(_compressed(item[4][0]) for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM))
        except (OSError, UnicodeError):
            looked_up = False
    # A failed lookup is asked again within a minute, not an hour: until it works this server's own address is not refused.
    _own.update(at=now if looked_up else now - OWN_TTL + OWN_RETRY, addresses=frozenset(found))
    return _own['addresses']


def _compressed(address):
    """The form ``refuse_reason`` compares (``ipaddress``'s compressed text), so an IPv6 written in full or with a zone id still matches."""
    try:
        return ipaddress.ip_address(str(address).split('%')[0].strip()).compressed
    except ValueError:
        return str(address).strip()


def refuse_reason(ip):
    """Why OpenVAS must not be given this address even though a scanner could reach it, or ``None``. The GVM stack has
    no tailscale interface, so a tailnet address would leave by the host's default route: never. A documentation range (RFC 5737,
    RFC 3849) is nobody's host, and this instance's own address is never a target of its own scanner. Everything else is
    ``is_scannable_ip``'s decision."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 'not a valid address'
    if address.compressed in own_addresses():
        return 'this cvENGINE server'
    if any(address.version == net.version and address in net for net in _TAILNET):
        return 'a tailnet address'
    if any(address.version == net.version and address in net for net in _DOCUMENTATION):
        return 'a documentation address range'
    return None


def _address(host, project_id):
    """The one vetted numeric address of ``host`` (IPv4 first); raises ``ValueError`` when it resolves somewhere prohibited."""
    from cveFeed import pinned_transport
    addresses = pinned_transport.resolve(host, 443, project=project_id)
    ordered = sorted(addresses, key=lambda item: item[0] != 2)  # AF_INET is 2
    return ordered[0][1][0]


def _latest_row(project_id, host, scoped=False):
    """The newest row of ``host``, a row of a target that is not manual only before one that is (a host two targets hold is the first one's to scan).
    ``scoped`` leaves out a row kept under a target that is now exactly one host (``targetApp.models.in_target_scope_q``): what may be scanned."""
    from cveFeed.manual_only import held_expr
    from startScan.models import Subdomain
    from targetApp.models import in_target_scope_q
    rows = Subdomain.objects.filter(target_domain__project_id=project_id, name=host)
    if scoped:
        rows = rows.filter(in_target_scope_q())
    return rows.select_related('scan_history', 'target_domain').annotate(held=held_expr()).order_by('held', '-scan_history_id').first()


def _names(items):
    return {str(h).strip().lower() for h in (items or ()) if str(h).strip()}


HOT = ('fire', 'smoke')  # the heats OpenVAS is spent on: a run is slow (hours per host), so it goes where it matters
# OpenVAS is a confirmer: it selects and orders hosts by the validation heat (threat.validation_heat, the heat once proven), as hot_validation
# does, so a known-exploited match whose version is not proven keeps its Fire priority here. Under the KEV heat policy a host whose only CVE
# matches are ice (not on the KEV, no known exploit, whatever their CVSS) does not qualify.
HOT_WINDOW = 500  # hot-looking names looked at in one step, per project
EPOCH_DAYS = 36500


def hot_names(project_id, limit=HOT_WINDOW):
    """The names of a project's hosts that may be Fire or Smoke: a CVE match rated smoke or hotter that nobody ruled out or closed, or an open
    finding rated medium or above, on any of the project's scans. A short list to look at: ``host_heat`` decides exactly, from the latest row
    of each name, by the rules the host card uses."""
    from django.db.models import Max
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    from cveFeed.threat import match_heat_rank_expr
    from startScan.models import Vulnerability
    from targetApp.models import in_target_scope_q
    from cveFeed.counts import CLOSED as closed  # fixed, accepted_risk, false_positive
    scope = in_target_scope_q('subdomain__')  # a name kept under a target that is now exactly one host is never OpenVAS's to scan through it
    # The current inventory only (not every scan's copy of a name), hottest first, so a large project's fire hosts fall inside the window.
    names = set(CVEMatch.objects.filter(latest_scan_q('subdomain__'), scope, subdomain__target_domain__project_id=project_id).exclude(ai_verdict='not_affected')
                .exclude(remediation_status__in=closed).annotate(heat_rank=match_heat_rank_expr(capped=False)).filter(heat_rank__gte=2)
                .values('subdomain__name').annotate(top=Max('heat_rank')).order_by('-top', 'subdomain__name').values_list('subdomain__name', flat=True)[:limit])
    names |= set(Vulnerability.objects.filter(latest_scan_q('subdomain__'), scope, target_domain__project_id=project_id, open_status=True, severity__gte=2)
                 .exclude(remediation_status__in=closed).values('subdomain__name').annotate(top=Max('severity')).order_by('-top', 'subdomain__name')
                 .values_list('subdomain__name', flat=True)[:limit])
    return _names(names)


def host_heat(project_id, names):
    """``{name: (heat, (fire reasons, smoke reasons))}`` for each of ``names`` that is a host of the project: the host card's rules (its CVE matches
    as they apply to it and its open findings, hottest first), read from the latest stored row of the name, with each CVE match rated by its
    validation heat (the heat once proven: OpenVAS is how such a match is confirmed, see ``HOT``)."""
    from agentapi import services
    from startScan.models import Subdomain
    wanted = sorted(_names(names))
    if not wanted:
        return {}
    rows = (Subdomain.objects.filter(target_domain__project_id=project_id, name__in=wanted).order_by('name', '-scan_history_id').distinct('name')
            .prefetch_related('cve_matches__cve_entry', services.triage_prefetch('cve_matches__triage'), 'vulnerability_set', services.triage_prefetch('vulnerability_set__triage'), 'vulnerability_set__cve_ids', 'vulnerability_set__tags'))
    out = {}
    for sub in rows:
        reasons = services._heat_reasons(sub, capped=False)
        out[sub.name.lower()] = (services._host_heat(sub, reasons),
                                 (sum(1 for r in reasons if r['temp'] == 'fire'), sum(1 for r in reasons if r['temp'] == 'smoke')))
    return out


def _days(when):
    days = (timezone.now() - when).days
    return 'today' if days < 1 else f'{days} day{"s" if days != 1 else ""} ago'


def _stored_address(sub):
    addresses = [ip.address for ip in sub.ip_addresses.all() if ip.address]
    return sorted(addresses, key=lambda a: ':' in a)[0] if addresses else ''


def assess(project_id, candidates, forced=(), gate=True, resolve=None, blocked=None, internal=False):
    """Decide, host by host, what OpenVAS may scan next. Returns ``(ready, verdicts)``: ``ready`` is ``[(host, ip, domain_id)]`` in scan order,
    ``verdicts`` is ``{host: {'heat', 'ready', 'reason', 'retry'}}`` for every candidate (``reason`` says why a host is not ready, in the words
    people read; ``retry`` marks one whose address could not be had, asked again in three days).

    A host is refused when: it is held only under a target set to exactly one host (a name under ``=example.com``); it is not a host of the
    project; it is excluded or archived; (with ``gate``) it is not Fire or Smoke, unless
    ``forced`` names it; it is on a CDN or a platform other tenants share, or at an address that is not the project's to test (documentation
    ranges, this server, the tailnet), or the same address as a host already chosen; it was scanned within a week or failed within three days.
    ``forced`` lifts only the heat gate, never the ownership refusals. Order: Fire before Smoke, then the most fire reasons, then the most smoke
    reasons, then the longest-waiting; a forced host with no heat comes last. ``resolve=None`` reads the stored address (no DNS): the explanation
    shown to people. The real selection passes ``_address``. ``internal`` selects the project's declared internal networks, whose names are their
    own address and which only a Sentinel inside can reach."""
    from cveFeed import exclusions, ledger
    from targetApp.target_types import internal_networks, scannable_hosts, sentinel_only_target
    names = sorted(_names(candidates))
    forced = _names(forced)
    nets = internal_networks(project_id)
    verdicts = {}

    def refuse(host, heat, reason, retry=False):
        verdicts[host] = {'heat': heat, 'ready': False, 'reason': reason, 'retry': retry}

    if nets:  # a declared internal network has its own batch (``internal_batch``); the external one must not mark it failed
        names = [n for n in names if bool(sentinel_only_target(n, project_id, nets)) == internal]
    elif internal:
        names = []
    kept = set(exclusions.drop_excluded(project_id, names))
    from cveFeed.bounty_gate import Gate
    bounty = Gate()  # a bug bounty project that has not confirmed automated testing is never scanned (forced hosts included), nor a host outside the program's scope
    heats = host_heat(project_id, names)
    scanned = ledger.last_run(SERVICE, names, project_id)
    failed_at = ledger.last_run(FAILED_SERVICE, names, project_id)
    fresh = ledger.fresh(SERVICE, names, project_id)
    fresh_failed = ledger.fresh(FAILED_SERVICE, names, project_id)
    empty = inconclusive_hosts(project_id, [n for n in names if n in fresh_failed])
    worn = interrupted_out_hosts(project_id, [n for n in names if n in fresh_failed])
    from targetApp.models import narrowed_names
    narrowed = narrowed_names(project_id, names)  # held only under a target that is now exactly one host: no person's naming lifts that
    passed = []
    for host in names:
        heat = heats.get(host, ('', (0, 0)))[0]
        sub = _latest_row(project_id, host, scoped=True) if host in heats else None
        if host in narrowed:
            refuse(host, heat, 'its target is set to this host only: a name under it is not scanned')
        elif sub is None:
            refuse(host, heat, 'not a host of this project')
        elif host not in kept:
            refuse(host, heat, 'excluded from scanning')
        elif (barred := bounty.refusal(project_id, host)):
            refuse(host, heat, 'bug bounty: ' + barred)
        elif sub.target_domain.discovery_mode == 'manual' and host not in forced:  # "just add them, do not scan yet": only a person who names the host reaches it
            refuse(host, heat, 'the target is set to manual only: OpenVAS scans its hosts only when a person names them')
        elif gate and host not in forced and heat not in HOT:
            refuse(host, heat, f'not Fire or Smoke ({heat or "unknown"}): OpenVAS is only spent on hosts on fire or smoke')
        elif _platform_reason(sub):
            refuse(host, heat, _platform_reason(sub))
        elif host in empty:
            refuse(host, heat, f'{INCONCLUSIVE} {_days(failed_at[host])}; asked again after three days')
        elif host in worn and host in fresh_failed:
            refuse(host, heat, interrupted_reason(worn[host]))
        elif host in fresh_failed:
            refuse(host, heat, f'could not be scanned {_days(failed_at[host])}; asked again after three days')
        elif host in fresh:
            refuse(host, heat, f'scanned {_days(scanned[host])}; due again after a week')
        else:
            passed.append((host, sub, heat))
    chosen, by_ip = [], {}
    for host, sub, heat in passed:
        if internal:
            ip = host
        elif not scannable_hosts([host], resolver=blocked, project=project_id):
            refuse(host, heat, 'a scanner may not be pointed at it (a prohibited address range, or it does not resolve to a public address)')
            continue
        else:
            try:
                ip = resolve(host, project_id) if resolve else _stored_address(sub)
            except (ValueError, OSError):
                refuse(host, heat, 'the name does not resolve to an address a scanner may use', retry=True)
                continue
            if not ip:
                refuse(host, heat, 'no address is recorded for the host yet')
                continue
        why = None if internal else (refuse_reason(ip) or ('a platform other tenants share (its address)' if _shared_address(ip) else None))
        if why:
            refuse(host, heat, f'{why}: not the project\'s to test')
        elif ip in by_ip:
            refuse(host, heat, f'the same address as {by_ip[ip]}')
        else:
            by_ip[ip] = host
            chosen.append((host, ip, sub.target_domain_id))
    rank = {'fire': 0, 'smoke': 1}
    epoch = timezone.now() - timedelta(days=EPOCH_DAYS)

    def order(item):
        host = item[0]
        heat, (fire, smoke) = heats.get(host, ('', (0, 0)))
        return (rank.get(heat, 2), -fire, -smoke, scanned.get(host) or epoch, host)
    chosen.sort(key=order)
    for host, _ip, _domain in chosen:
        verdicts[host] = {'heat': heats[host][0], 'ready': True, 'reason': None, 'retry': False}
    return chosen, verdicts


def _platform_reason(sub):
    """Why a stored host row is a platform other tenants share (a CDN edge, a SaaS or PaaS front such as Microsoft 365's autodiscover), or ``None``."""
    from cveFeed import hosting
    verdict = hosting.classify(name=sub.name, cname=sub.cname or '', webserver=sub.webserver or '', cdn_name=sub.cdn_name or '', is_cdn=bool(sub.is_cdn))
    if not verdict['shared_ip']:
        return None
    provider = verdict['provider'] or 'a provider'
    return (f'a CDN edge ({provider}): not the project\'s to test' if verdict['kind'] == 'cdn'
            else f'a third-party platform ({provider}) shared with other customers: not the project\'s to test')


def _shared_address(ip):
    from cveFeed import hosting
    return bool(hosting.shared_by_address([ip]))


def due(project_id, hosts, resolve=None, blocked=None):
    """``[(host, ip, domain_id)]`` of ``hosts`` that are due, whatever their heat: vetted (the same gate as every other scanner,
    ``scannable_hosts`` and ``pinned_transport.resolve``, plus ``assess``'s ownership refusals), not excluded or archived, not scanned within a
    week and not failed within three days, never-scanned first, one host per address. ``next_batch`` adds the heat gate."""
    return assess(project_id, hosts, gate=False, resolve=resolve or _address, blocked=blocked)[0]


def sweep_links():
    """The ``OpenvasProject`` rows the sweep works through: the projects opted in one by one, and every project of an opted-in organization that
    nobody excluded (a row is made for those, disabled, to keep the GVM target of its host set). A project's own choice wins over its
    organization's: ``excluded`` is an explicit "not this one". The project scanned longest ago goes first, so one busy project cannot keep the
    single GVM slot from the others."""
    from django.db.models import F, OuterRef, Q, Subquery
    from cveFeed.models import OpenvasOrg, OpenvasProject, OpenvasRun
    from dashboard.models import Project
    org_ids = set(OpenvasOrg.objects.filter(enabled=True).values_list('org_id', flat=True))
    if org_ids:
        have = set(OpenvasProject.objects.values_list('project_id', flat=True))
        for project in Project.objects.filter(org_id__in=org_ids).exclude(pk__in=have):
            OpenvasProject.objects.get_or_create(project=project)
    last = OpenvasRun.objects.filter(project_id=OuterRef('project_id')).order_by('-id').values('started_at')[:1]
    return (OpenvasProject.objects.filter(Q(enabled=True) | Q(project__org_id__in=org_ids, excluded=False)).select_related('project')
            .annotate(last_started=Subquery(last)).order_by(F('last_started').asc(nulls_first=True), 'project_id'))


def links_for(project_ids):
    """The ``OpenvasProject`` rows (saved or not) of the opted-in projects among ``project_ids``, without creating any: what a read-only page shows."""
    from cveFeed.models import OpenvasOrg, OpenvasProject
    from dashboard.models import Project
    org_ids = set(OpenvasOrg.objects.filter(enabled=True).values_list('org_id', flat=True))
    have = {l.project_id: l for l in OpenvasProject.objects.filter(project_id__in=project_ids).select_related('project')}
    out = [l for l in have.values() if l.enabled or (l.project.org_id in org_ids and not l.excluded)]
    out += [OpenvasProject(project=p) for p in Project.objects.filter(pk__in=project_ids, org_id__in=org_ids).exclude(pk__in=have)]
    return sorted(out, key=lambda l: l.project_id)


def overview(project_ids, limit=12):
    """The OpenVAS queue for the Sentinels page, over the projects the viewer may read: the run in progress, the hosts due next in scan order
    and the hosts that are not due, each with the reason in plain words (Fire or Smoke only; never a CDN or a shared platform; scanned three days
    ago). ``None`` while the add-on is off. The per-project explanation is cached for a minute: the page polls."""
    from django.core.cache import cache
    from cveFeed.models import OpenvasRun, OpenvasSettings
    if not OpenvasSettings.current().enabled:
        return None
    run = OpenvasRun.objects.filter(status='running', project_id__in=project_ids).select_related('project').first()
    rows = []
    for link in links_for(project_ids):
        found = cache.get_or_set(f'openvas-explain:{link.project_id}', lambda link=link: explain(link)[:100], 60)
        rows += [{**r, 'project': link.project.slug} for r in found]
    ready = [r for r in rows if r['ready']]
    refused = [r for r in rows if not r['ready']]
    return {'running': ({'run': run.pk, 'project': run.project.slug, 'hosts': sorted(run.hosts.values()), 'progress': run.progress, 'status': run.gvm_status,
                         'started_at': run.started_at.isoformat(), 'budget_hours': budget_hours(len(run.hosts)), 'via': 'sentinel' if run.sentinel_task_id else 'local'}  # a run with no Sentinel task is a closed one from an earlier version
                        if run else None),
            'hosts_per_task': max_hosts(), 'budget_hours_per_host': max_hours(), 'max_checks': int(task_preferences()['max_checks']),
            'next': ready[:limit], 'not_due': refused[:limit], 'counts': {'next': len(ready), 'not_due': len(refused)}}


def next_batch(link, resolve=None, blocked=None):
    """``[(host, ip, domain_id)]`` for the next OpenVAS task of this project: its hosts that are Fire or Smoke (Fire first), plus the hosts
    someone listed (still gated by heat unless the list marks them forced), vetted by ``assess``. Nothing else is ever scanned: a host nobody
    listed and that is not hot is not a candidate, and a host that turns Fire or Smoke becomes one by itself. A name whose address could not be
    had is marked failed so it is asked again in three days, not at every tick."""
    from cveFeed import ledger
    explicit, forced = _names(link.hosts), _names(link.forced_hosts)
    ready, verdicts = assess(link.project_id, hot_names(link.project_id) | explicit | forced, forced, resolve=resolve or _address, blocked=blocked)
    retry = [host for host, v in verdicts.items() if v['retry']]
    if retry:
        ledger.record(FAILED_SERVICE, retry, link.project_id)
    return ready[:max_hosts()]


def internal_batch(link):
    """``[(host, ip, domain_id)]`` of the project's targets inside a network it declared internal that are due for OpenVAS: only such an
    address (``target_types.sentinel_only_target``: this server may not scan it), Fire or Smoke like any other host, not excluded, not scanned within
    a week and not failed within three days. Always a batch of its own, never mixed with the vetted external one: a Sentinel inside the network is
    the only one that can reach it."""
    from targetApp.target_types import internal_networks
    if not internal_networks(link.project_id):
        return []
    forced = _names(link.forced_hosts)
    ready, _verdicts = assess(link.project_id, hot_names(link.project_id) | _names(link.hosts) | forced, forced, internal=True)
    return ready[:max_hosts()]


def explain(link):
    """What the sweep would do with each of the project's candidate hosts right now and why, without any DNS: ``[{'host', 'heat', 'ready',
    'reason'}]``, ready hosts first in scan order, then the refused ones by name. For the Settings page, the host record and the Sentinels page,
    so nobody has to guess why a host is or is not due."""
    explicit, forced = _names(link.hosts), _names(link.forced_hosts)
    candidates = hot_names(link.project_id) | explicit | forced
    out = {}
    for internal in (False, True):
        ready, verdicts = assess(link.project_id, candidates, forced, internal=internal)
        order = {host: i for i, (host, _ip, _d) in enumerate(ready)}
        out.update({host: {'host': host, **v, 'order': order.get(host)} for host, v in verdicts.items()})
    return sorted(out.values(), key=lambda r: (r['order'] is None, r['order'] if r['order'] is not None else 0, r['host']))


# ----------------------------------------------------------------------------- targets and tasks


def finish(run, status, error='', summary=None):
    run.status, run.error, run.finished_at = status, clean(error, 300), timezone.now()
    if summary is not None:
        run.summary = summary
    run.save(update_fields=['status', 'error', 'finished_at', 'summary'])
    _settle_progress(run)


# ----------------------------------------------------------------------------- what the activity feed says about a run

def task_name(run):
    """The name of the run's task in GVM (what the GVM web interface and ``gvm-cli`` show)."""
    return f'cvengine-run-{run.pk}'


def hosts_text(run, limit=4):
    """The run's host names for a line people read: ``a, b and 3 more``."""
    names = sorted(set(run.hosts.values()))
    shown = ', '.join(names[:limit])
    return shown + (f' and {len(names) - limit} more' if len(names) > limit else '') if names else 'no host'


def run_label(run):
    """``OpenVAS run 12 on www.example.com (Sentinel task 7)``: which run, which hosts and which task an activity line is about, so a queue of
    several hosts can be told apart. A run with no Sentinel task (closed by ``tick``) names the GVM task of the earlier version."""
    where = f'GVM task {task_name(run)}' if not run.sentinel_task_id else f'Sentinel task {run.sentinel_task_id}'
    return f'OpenVAS run {run.pk} on {hosts_text(run)} ({where})'


def run_detail(run, **extra):
    """The structured part of a run's activity lines (``AgentActivity.detail``)."""
    detail = {'openvas_run': run.pk, 'hosts': sorted(set(run.hosts.values())), 'addresses': sorted(run.hosts)}
    if run.sentinel_task_id:
        detail['sentinel_task'] = run.sentinel_task_id
    else:
        detail['gvm_task'] = task_name(run)
        if run.task_id:
            detail['gvm_task_id'] = run.task_id
    return {**detail, **extra}


def _progress_entry(run):
    from cveFeed.models import AgentActivity
    try:
        return AgentActivity.objects.filter(status='running', detail__openvas_run=run.pk, detail__progress_line=True).order_by('-id').first()
    except Exception:  # noqa: BLE001 - telemetry never breaks the sweep
        return None


def log_started(run, via='sentinel'):
    """The run's progress line: shown as running while a Sentinel's GVM stack works and settled when the run ends (``finish``)."""
    from cveFeed import activity
    activity.log('run_check', f'{run_label(run)}: started', project=run.project_id, status='running',
                 **run_detail(run, progress_line=True, via=via, progress=0))


def _settle_progress(run):
    from cveFeed import activity
    entry = _progress_entry(run)
    if entry is None:
        return
    took = _duration(max(0, int((timezone.now() - run.started_at).total_seconds() // 60)))
    word = {'done': 'finished', 'failed': 'failed', 'stopped': 'stopped'}.get(run.status, run.status)
    activity.settle(entry, 'failed' if run.status == 'failed' else 'done',
                    message=f'{run_label(run)}: {word} after {took}' + (f' ({clean(run.error, 160)})' if run.error and run.status != 'done' else ''),
                    gvm_status=run.gvm_status, progress=run.progress)


INCONCLUSIVE = 'OpenVAS ran but reported no scanned host'
RESTART_GVMD = 'restart its openvas-gvmd container'
SENTINEL_GVMD = "the Sentinel's gvmd"


def stale_cache_error(count, where='gvmd'):
    """What a run says when ``count`` of its results came without their CVE references because gvmd's NVT cache is out of date (the Sentinel's NVT cache)."""
    return (f'{where} sent {count} result(s) without their CVE references: its NVT cache is out of date (greenbone/gvmd#3220). Imported as partial, '
            f'so nothing earlier is resolved by it; {RESTART_GVMD}, and the next scan of these hosts reads them')


def inconclusive(summary):
    """A finished task whose report names no scanned host proved nothing about the hosts: not a scan, whatever its status word says. The hosts are not
    stamped as scanned, the run says so, and they are asked again after the usual three days."""
    summary['inconclusive'] = not summary.get('hosts_scanned')
    return summary['inconclusive']


def inconclusive_hosts(project_id, names):
    """The hosts among ``names`` whose latest OpenVAS run finished inconclusive (see ``inconclusive``): for the host record's reason text."""
    from cveFeed.models import OpenvasRun
    wanted, out = set(names), set()
    for run in OpenvasRun.objects.filter(project_id=project_id, status='done').order_by('-id')[:30]:
        for host in set(run.hosts.values()) & wanted:
            wanted.discard(host)  # only the newest run of a host counts
            if (run.summary or {}).get('inconclusive'):
                out.add(host)
    return out


def interrupted_reason(count):
    return f'OpenVAS was interrupted {count} times scanning this host; asked again after three days'


def interrupted_out_hosts(project_id, names):
    """``{host: attempts}`` for the hosts among ``names`` whose latest run that covered them gave them up after repeated interruptions (see
    ``interrupted_streak``): for the host record's reason text."""
    from cveFeed.models import OpenvasRun
    wanted, out = set(names), {}
    for run in OpenvasRun.objects.filter(project_id=project_id).exclude(status='running').order_by('-id').only('hosts', 'summary')[:30]:
        for host in set(run.hosts.values()) & wanted:
            wanted.discard(host)  # only the newest run of a host counts
            if host in (run.summary or {}).get('interrupt_limit', {}):
                out[host] = run.summary['interrupt_limit'][host]
    return out


# ----------------------------------------------------------------------------- results


_CPE_RE = re.compile(r'^cpe:(?:/|2\.3:)[aoh]:[A-Za-z0-9._~%+-]+:[A-Za-z0-9._~%+-]+(?::[A-Za-z0-9._~%+*-]*)*$')
# what a version-check NVT prints in its result ("Installed version: 9.11.3", "Fixed version:     9.11.31"): a version has a digit and no space
_VERSION_LINE = {'installed': re.compile(r'Installed\s+version\s*:\s*([A-Za-z0-9][A-Za-z0-9._:+~-]{0,99})', re.I),
                 'fixed': re.compile(r'Fixed\s+version\s*:\s*([A-Za-z0-9][A-Za-z0-9._:+~-]{0,99})', re.I)}


def _version_from(text, kind):
    found = _VERSION_LINE[kind].search(str(text or ''))
    value = found.group(1).rstrip('.') if found else ''
    return value if any(ch.isdigit() for ch in value) else ''  # "Installed version: unknown" is no version


def identified(ev):
    """What the NVT identified, from a parsed result or a stored observation's evidence: ``{'product', 'cpe', 'installed_version',
    'fixed_version'}``, each '' when the result does not say. The product is the detected CPE's product part ("openssh"); the installed
    version is the result's "Installed version:" line, else the CPE's version. A Sentinel-reported result carries no CPE; its version
    still comes from the result text."""
    cpe = ev.get('cpe') or ''
    cpe = cpe if _CPE_RE.match(cpe) else ''
    parts = cpe.replace('cpe:2.3:', 'cpe:/', 1).split(':') if cpe else []
    product = parts[3].replace('_', ' ')[:120] if len(parts) > 3 else ''
    cpe_version = parts[4] if len(parts) > 4 and parts[4] not in ('', '*', '-') else ''
    installed = _version_from(ev.get('result'), 'installed') or (cpe_version[:100] if any(ch.isdigit() for ch in cpe_version) else '')
    return {'product': product, 'cpe': cpe, 'installed_version': installed, 'fixed_version': _version_from(ev.get('result'), 'fixed')}


def severity_level(score):
    """The Vulnerability severity (0 info .. 4 critical) of a CVSS base score."""
    return 4 if score >= 9.0 else 3 if score >= 7.0 else 2 if score >= 4.0 else 1 if score > 0 else 0


def confirmed(item):
    """Whether a result is hard evidence. The type decides when gvmd gave one: QoD 80 is ``remote_banner`` / ``executable_version``, a version
    string that a backport defeats, so the number alone must not confirm anything."""
    qod_type = (item.get('qod_type') or '').strip().lower()
    if qod_type:
        return qod_type in HARD_QOD_TYPES
    return item['qod'] >= CONFIRMED_QOD


def _duration(minutes):
    return f'{minutes // 60} h {minutes % 60} min' if minutes >= 60 else f'{minutes} min'


def _same_machine(project_id, address):
    """The other names of the project whose stored addresses include ``address``: scanning the address scanned them all, so the sweep must not
    scan each of them again at the next tick (freshness is recorded per name)."""
    from startScan.models import Subdomain
    return sorted({n.lower() for n in Subdomain.objects.filter(target_domain__project_id=project_id, ip_addresses__address=address)
                   .values_list('name', flat=True)})


def _same_address(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def _product(oid, udp=False):
    return oid + ('/udp' if udp else '')


# ----------------------------------------------------------------------------- storing results

def record_observations(project_id, domain_id, host, found, scanned_now):
    """The durable record of one scanned host: an observation per (port, OID) found now, and the ones found before and not now flipped to
    ``absent``. ``found`` is the host's parsed results that name a CVE; the observation is the dedupe key and carries what is needed to
    rebuild the finding on a later scan's host row."""
    from cveFeed.models import ProbeObservation
    now = timezone.now()
    host = host.lower()
    keys = set()
    for item in found:
        port_number, udp = item['port_number'], item['port'].endswith('/udp')
        keys.add((port_number, _product(item['oid'], udp)))
        evidence = {k: item[k] for k in ('name', 'family', 'port', 'severity', 'threat', 'qod', 'qod_type', 'result', 'summary', 'insight', 'impact',
                                         'affected', 'solution', 'solution_type', 'cvss_vector', 'cves', 'urls', 'oid')}
        evidence['cpe'] = item.get('cpe') or ''  # a Sentinel-reported result has none
        ProbeObservation.objects.update_or_create(
            project_id=project_id, host=host, probe=PROBE, port=port_number, kind=OBS_KIND, product=_product(item['oid'], udp)[:120],
            defaults={'domain_id': domain_id, 'outcome': 'found', 'confidence': item['qod'] / 100, 'source': 'openvas', 'evidence': evidence, 'observed_at': now})
    if scanned_now:
        stale = ProbeObservation.objects.filter(project_id=project_id, host=host, probe=PROBE, kind=OBS_KIND, outcome='found')
        for row in stale:
            if (row.port, row.product) not in keys:
                row.outcome, row.confidence, row.observed_at = 'absent', 0.0, now
                row.save(update_fields=['outcome', 'confidence', 'observed_at'])


def _description(ev):
    head = (f'OpenVAS detection quality {ev["qod"]}% ({ev["qod_type"] or "unknown"}): '
            + ('an active check or an authenticated package check; treated as confirmed.' if ev['qod'] >= CONFIRMED_QOD
               else 'a version or banner inference; the product may not be affected (for example a backported fix). Not confirmed.'))
    return '\n\n'.join(part for part in (head, ev.get('summary'), ev.get('insight'), ('Affected: ' + ev['affected']) if ev.get('affected') else '') if part)[:6000]


def apply_observations(sub):
    """Make the Vulnerability rows and CVE matches of ``sub`` agree with the stored observations: save what was found (fresh), resolve what a
    later complete scan no longer found. Idempotent; the one code path for a fresh import and for a new scan's host row. Returns
    ``(findings, evidence, resolved)``."""
    from cveFeed import correlation
    from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation
    from reNgine.tasks import save_vulnerability
    domain = sub.target_domain
    cutoff = timezone.now() - timedelta(days=FRESH_DAYS)
    observations = list(ProbeObservation.objects.filter(project_id=domain.project_id, host=sub.name.lower(), probe=PROBE, kind=OBS_KIND))
    live = [o for o in observations if o.outcome == 'found' and o.observed_at >= cutoff]
    gone = [o for o in observations if o.outcome == 'absent']
    keep, matches, rows = set(), set(), []
    known = {c.cve_id: c for c in CVEEntry.objects.filter(cve_id__in={c for o in live for c in o.evidence.get('cves', [])})
             .exclude(status__icontains='reject').exclude(local_only=True).only('id', 'cve_id')}
    for obs in live:
        ev = obs.evidence
        where = f'{sub.name}:{ev["port"]}'
        template_id = f'openvas:{ev["oid"]}'
        keep.add((template_id, where))
        hard = confirmed(ev)
        save_vulnerability(
            target_domain=domain, scan_history=sub.scan_history, subdomain=sub, http_url=where, name=f'OpenVAS: {ev["name"]}'[:500],
            severity=severity_level(ev['severity']), description=_description(ev), impact=ev.get('impact') or None,
            remediation=ev.get('solution') or None, source=SOURCE, template_id=template_id, type='openvas', cvss_score=ev['severity'] or None,
            cvss_metrics=ev.get('cvss_vector') or None, extracted_results=[ev['result']] if ev.get('result') else None, cve_ids=list(ev['cves']),
            references=list(ev.get('urls') or []), tags=['openvas', 'qod-confirmed' if hard else 'qod-unconfirmed'])
        # The OID and port stay the match's key (``matched_product``, one row per NVT and port, as resolve_missing reads it); what the NVT
        # identified (the detected product and the installed version it printed) is recorded beside it, so the version is the row's own
        # and the product is not a guess (correlation.invalid_identity_reason never compares an OpenVAS match's name: the NVT tested it).
        product = f'OpenVAS NVT {ev["oid"]} on {ev["port"]}'[:255]
        seen = identified(ev)
        for cve_id in ev['cves']:
            cve = known.get(cve_id)
            if cve is None:
                continue
            matches.add((cve.id, product))
            rows.append({'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': SOURCE, 'matched_product': product,
                         'matched_version': seen['installed_version'][:100],
                         'version_in_range': True if hard else None, 'confidence': 0.95 if hard else min(0.5, ev['qod'] / 100),
                         'scan_history_id': sub.scan_history_id, 'distro_status': 'no_data', 'distro_fixed_version': '',
                         'evidence': {'source': 'openvas', 'oid': ev['oid'], 'nvt': ev['name'], 'port': ev['port'], 'qod': ev['qod'], 'qod_type': ev['qod_type'],
                                      'severity': ev['severity'], 'result': ev['result'][:RESULT_EVIDENCE], 'tested_at': obs.observed_at.isoformat(),
                                      **{k: v for k, v in seen.items() if v}}})
    correlation.save_matches(rows)
    now = timezone.now()
    for row in rows:
        hard = confirmed(row['evidence'])
        mine = CVEMatch.objects.filter(subdomain_id=sub.id, cve_entry_id=row['cve_entry_id'], source=SOURCE, matched_product=row['matched_product'])
        if hard:
            mine.update(template_result='vulnerable', template_id=('openvas:' + row['evidence']['oid'])[:128], template_tested_at=now)
        else:
            mine.filter(template_id__startswith='openvas:').update(template_result='', template_tested_at=now)  # a drop in quality un-confirms it
    # Only what a complete scan of the host answered "no longer there" is resolved (an observation that merely went stale is left alone).
    absent = {(f'openvas:{o.evidence["oid"]}', f'{sub.name}:{o.evidence["port"]}') for o in gone if o.evidence.get('oid')}
    products = {f'OpenVAS NVT {o.evidence["oid"]} on {o.evidence["port"]}'[:255] for o in gone if o.evidence.get('oid')} | {p for _c, p in matches}
    resolved = resolve_missing(domain, sub, absent - keep, matches, products)
    return len(keep), len(matches), resolved


def resolve_missing(domain, sub, gone, matches, products):
    """Close what a complete scan no longer found on this host: the Vulnerability rows in ``gone`` (every scan's copy) and the CVE matches of
    ``products`` that are not in ``matches`` (kept as a record, closed unless a person already works them)."""
    from cveFeed.models import CVEMatch
    from startScan.models import Vulnerability
    count = 0
    if gone:
        for vuln in Vulnerability.objects.filter(target_domain=domain, subdomain__name=sub.name, source=SOURCE, open_status=True):
            if (vuln.template_id, vuln.http_url) in gone:
                vuln.open_status = False
                vuln.save(update_fields=['open_status'])
                count += 1
    stale = [m.pk for m in CVEMatch.objects.filter(subdomain=sub, source=SOURCE, matched_product__in=products) if (m.cve_entry_id, m.matched_product) not in matches]
    if stale:
        CVEMatch.objects.filter(pk__in=stale).update(template_result='no_match', template_tested_at=timezone.now())  # the test result is a fact
        CVEMatch.objects.filter(pk__in=stale, remediation_status='open', assignee__isnull=True).update(
            ai_verdict='not_affected', confidence=0.0, updated_at=timezone.now(),
            ai_reason='Closed automatically: a later OpenVAS scan of this host no longer reports this result.')
    return count


def _apply_import(run, items, scanned, no_cve, unusable, partial=False):
    """Observations, findings, evidence and resolutions for each host of ``run``, from already-fetched, already-parsed
    results (``items``, the shape ``sentinel_broker`` cleans a Sentinel's report into) and the set of addresses gvmd actually scanned. ``partial`` is a scan stopped at its time budget: what it found is kept, but it says nothing about
    what it did not get to, so no earlier finding is resolved by it. Returns the run summary."""
    summary = {'results': len(items), 'without_cve': no_cve, 'unusable': unusable, 'hosts_scanned': 0, 'hosts_not_scanned': 0, 'findings': 0,
               'evidence': 0, 'resolved': 0, 'not_in_batch': 0, 'partial': bool(partial)}
    names = []
    for address, host in run.hosts.items():
        if not any(_same_address(address, s) for s in scanned):
            summary['hosts_not_scanned'] += 1
            continue
        sub = _latest_row(run.project_id, host)
        if sub is None:
            summary['hosts_not_scanned'] += 1
            continue
        found = [i for i in items if i['cves'] and _same_address(i['address'], address)]
        record_observations(run.project_id, sub.target_domain_id, host, found, scanned_now=not partial)
        findings, evidence, resolved = apply_observations(sub)
        summary['hosts_scanned'] += 1
        summary['findings'] += findings
        summary['evidence'] += evidence
        summary['resolved'] += resolved
        names.append(host)
        names += [n for n in _same_machine(run.project_id, address) if n not in names]  # one host, many names: they are fresh too
    summary['not_in_batch'] = sum(1 for i in items if not any(_same_address(i['address'], a) for a in run.hosts))
    return summary, names


# ----------------------------------------------------------------------------- Sentinel dispatch (see docs/AGENT-API.md)

def dispatch_to_sentinel(link, batch):
    """Hand a due batch to a Sentinel: one ``SentinelTask`` (kind ``openvas``) and one ``OpenvasRun`` that only tracks it (the unique running row
    keeps two tasks from running at once). The Sentinel runs its own GVM stack against
    this exact host set and the excluded-NVT-family list named in the task's ``target`` - this instance's own
    ``EXCLUDED_FAMILIES``, never a copy a Sentinel might carry out of date - and reports back when done; the next tick
    imports the result (``_apply_import``)."""
    from agentapi.models import SentinelTask
    from cveFeed import activity
    from cveFeed.models import OpenvasRun
    batch = batch[:MAX_HOSTS_PER_TASK]  # a Sentinel refuses more; ``max_hosts`` already holds a batch to this, and the rest would stay due for the next tick
    hosts = {ip: host for host, ip, _domain in batch}
    task = SentinelTask.objects.create(project=link.project, kind='openvas', ips=sorted(hosts), host=', '.join(sorted(set(hosts.values())))[:500],
                                       target={'hosts': hosts, 'excluded_families': list(EXCLUDED_FAMILIES), 'max_hours': budget_hours(len(hosts)),
                                    'preferences': task_preferences()})
    try:
        with transaction.atomic():  # the one-task-at-a-time lock
            run = OpenvasRun.objects.create(project=link.project, status='running', sentinel_task=task, hosts=hosts)
    except IntegrityError:
        task.delete()
        return None
    activity.log('run_check', f'Handed {run_label(run)} to a Sentinel', project=link.project_id, sentinel_task_id=task.pk,
                 trace_id=task.trace_id, **run_detail(run))
    log_started(run, via='sentinel')
    from agentapi import stage_runs
    # the sweep never waited in a worker for this (each tick polls the task); the watch makes the report import at once, not at the next tick
    stage_runs.watch('openvas.import', [task.pk], {'run_id': run.pk}, project=link.project)
    return run


def _import_reported(context):
    """The completion callback of a Sentinel's OpenVAS task (``stage_runs.watch``): one sweep step now, which imports the report (``tick`` ->
    ``poll_sentinel``) and frees the one-at-a-time slot for the next batch."""
    return tick()


# What a Sentinel says when its own stack, not the scan, failed (client/openvas.py raises these before a task exists in gvmd).
INFRASTRUCTURE_ERRORS = ('no gmp login', 'gvmd could not be reached', 'gvmd refused the gmp login', 'the default gvm login', 'gvmd would not set a password',
                         'gvmd has no user', 'gvmd answered with an error', 'the connection to gvmd failed', 'is still syncing', 'feed is not loaded',
                         'not in gvmd yet', 'does not list the openvas scanner', 'port list yet', 'scan configuration', 'is the gvm stack up',
                         'gmp login', 'did not accept the login', 'the task was stopped', 'are not loaded yet', 'selects no nvts')


def infrastructure_failure(status, reason):
    """Whether a failed Sentinel task failed for want of a working Sentinel or gvmd (no host is to blame): an ``expired`` task (the Sentinel stopped
    answering) or an error naming its own stack."""
    text = str(reason or '').lower()
    return status == 'expired' or any(marker in text for marker in INFRASTRUCTURE_ERRORS)


LOCAL_RUN_CLOSED = 'started by an earlier version against this server\'s own gvmd, which is no longer driven here; the hosts stay due and go to a Sentinel'
NO_SCANNER_GRACE = timedelta(minutes=30)  # a queued Sentinel task whose Sentinels have all been gone this long is given up on


def _claimable(run, task):
    """Whether a queued Sentinel task may still be taken: a live Sentinel that declares ``openvas`` covers its project (and, for an address of a
    declared internal network, one inside it), or the task is still young enough that a Sentinel only briefly out of contact may come back. The run
    holds the one-at-a-time OpenVAS slot for every project, so one whose Sentinels are gone must not hold it until the queue limit."""
    from agentapi import sentinel_broker
    from targetApp.target_types import in_internal_range, internal_networks
    if task.created_at > timezone.now() - NO_SCANNER_GRACE:
        return True
    nets = internal_networks(run.project_id)
    internal = bool(nets) and any(in_internal_range(address, nets) for address in run.hosts)
    return sentinel_broker.any_scanner_for(run.project, 'openvas', internal=internal)


class _SkippedProjects:
    """The projects one OpenVAS tick passed over because no live Sentinel could take OpenVAS work for them, and why (``sentinel_broker.capacity_state``'s reason:
    ``disabled``, ``offline``, ``withheld``, ``inactive``, ``never``). The tick used to ``continue`` past them without a word, so an administrator who turned
    OpenVAS off everywhere (or whose only Sentinel with it was offline) saw nothing happen and no reason. ``log`` writes one line per tick naming the state. The
    reason is worked out once, for the first project passed over (it names every Sentinel that has the kind); the others are counted."""

    def __init__(self):
        self.projects, self.first, self._checked = [], None, {}

    def eligible(self, project, internal):
        from agentapi import sentinel_broker, sentinel_dispatch
        key = (project.pk, internal)
        if key not in self._checked:
            ok = bool(sentinel_dispatch.any_scanner_for(project, 'openvas', internal=internal))
            self._checked[key] = ok
            if not ok:
                self.projects.append(project.slug)
                if self.first is None:
                    self.first = sentinel_broker.explain_none(project, 'openvas', internal=internal)
        return self._checked[key]

    def summary(self):
        return (f'OpenVAS has no live Sentinel for {len(set(self.projects))} project(s) ({self.first["reason"]}): {self.first["message"]}'
                if self.first else '')

    def log(self):
        """One line per tick. An install that has no Sentinel for the project at all (``never``, the way every install ran before Sentinels) is the ordinary
        route to this server's own OpenVAS, so it is logged at debug level; every other state is something an administrator can act on, at info level."""
        if self.first:
            level = logging.DEBUG if self.first['reason'] == 'never' and not self.first['message'].startswith('no Sentinel that covers') else logging.INFO
            logger.log(level, 'OpenVAS tick: %s; their hosts stay due', self.summary())

    def suffix(self):
        """What to add to the tick's ``skipped`` text: nothing when there is simply no Sentinel for the project (the text already says so), else the reason."""
        return f' ({self.first["message"]})' if self.first and self.first['reason'] != 'never' else ''


def poll_sentinel(run):
    """One step of a run: ask its ``SentinelTask``'s status and import what the Sentinel reported. No GMP session is opened: the Sentinel talks to
    its own gvmd, never this server to one."""
    from agentapi import sentinel_broker
    from cveFeed import activity, ledger
    task = run.sentinel_task
    task.refresh_from_db()
    if task.status == 'queued':
        sentinel_broker.reap_expired()  # a queued task has no lease: this is what expires one nobody claims within ``queued_ttl``
        task.refresh_from_db()
    if task.status == 'queued' and not _claimable(run, task):
        sentinel_broker.expire(task, 'no live Sentinel is left to take the OpenVAS task')
        task.refresh_from_db()
    if task.status in ('queued', 'claimed', 'running'):
        return {'run': run.pk, 'status': 'running', 'sentinel_status': task.status}
    if task.status == 'done':
        result = task.result or {}
        entry = activity.log('run_check', f'{run_label(run)}: importing the Sentinel-reported results', project=run.project_id, status='running',
                             **run_detail(run))
        try:
            stale = result.get('nvt_cache_stale') or 0
            summary, names = _apply_import(run, result.get('results') or [], set(result.get('scanned_addresses') or []),
                                           result.get('without_cve', 0), result.get('unusable', 0), partial=bool(result.get('partial') or stale))
        except Exception as exc:  # noqa: BLE001
            finish(run, 'failed', f'the Sentinel-reported results could not be imported ({type(exc).__name__})')
            ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
            activity.settle(entry, 'done', message=activity.diagnostic('OpenVAS Sentinel result import', exc))
            return {'run': run.pk, 'status': 'failed'}
        gone = [h for h in run.hosts.values() if h not in names]
        if stale:
            summary['nvt_cache_stale'] = stale
        ledger.record(FAILED_SERVICE if stale else SERVICE, names, run.project_id)  # asked again once the Sentinel's gvmd is restarted
        ledger.record(FAILED_SERVICE, gone, run.project_id)
        empty = inconclusive(summary)
        finish(run, 'done', error=(INCONCLUSIVE if empty else stale_cache_error(stale, SENTINEL_GVMD) if stale
                                   else 'stopped at its time budget; the results found so far were kept' if summary['partial'] else ''), summary=summary)
        if empty:
            activity.settle(entry, 'done', message=f'{run_label(run)}: {INCONCLUSIVE} ({len(run.hosts)} host(s) asked); none is marked scanned')
            return {'run': run.pk, 'status': 'done', **summary}
        activity.settle(entry, 'done', message=(f'{run_label(run)}{" stopped at its time budget" if summary["partial"] and not stale else ""}: {summary["hosts_scanned"]} host(s) scanned, {summary["findings"]} finding(s) with a CVE, '
                                                f'{summary["resolved"]} resolved' + (f', {summary["without_cve"]} result(s) without a CVE not imported' if summary['without_cve'] else '')
                                                + (f'; {stale_cache_error(stale, SENTINEL_GVMD)}' if stale else '')))
        return {'run': run.pk, 'status': 'done', **summary}
    # failed or expired: the Sentinel never finished it. A later tick retries on a Sentinel. The hosts are marked failed (asked again in
    # three days) only when the scan itself ran and failed: a Sentinel that went away, or whose gvmd was not ready, says nothing about them.
    reason = task.error or (task.result or {}).get('error') or 'the Sentinel did not report a finished scan'
    if not infrastructure_failure(task.status, reason):
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
    finish(run, 'failed', clean(reason, 300))
    return {'run': run.pk, 'status': 'failed'}


def carry_forward(scan):
    """Hosts are stored once per scan, so a fresh host row has no OpenVAS findings until this runs. A no-op while the add-on is off."""
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    try:
        if not _enabled():
            return 0
        cutoff = timezone.now() - timedelta(days=FRESH_DAYS)
        hosts = set(ProbeObservation.objects.filter(project_id=scan.domain.project_id, probe=PROBE, kind=OBS_KIND, outcome='found', observed_at__gte=cutoff)
                    .values_list('host', flat=True))
        if not hosts:
            return 0
        return sum(apply_observations(sub)[0] for sub in Subdomain.objects.filter(scan_history=scan, name__in=hosts).select_related('target_domain', 'scan_history'))
    except Exception:  # noqa: BLE001 - never fatal to the scan
        logger.exception('could not carry the OpenVAS findings onto scan %s', getattr(scan, 'pk', None))
        return 0


# ----------------------------------------------------------------------------- the tick


def tick(resolve=None, blocked=None):
    """One step of the sweep (every 15 minutes, queue ``openvas_queue``): import the running Sentinel task's report, or hand the next due batch to a
    Sentinel. Returns what it did, or ``{'skipped': reason}``.

    This server never talks to gvmd and never runs a scan: every batch is a ``SentinelTask`` of kind ``openvas`` (``sentinel_dispatch.NEVER_LOCAL``), and
    the Sentinel's own GVM stack scans. A batch with no eligible Sentinel right now is simply left due, and the next tick tries again.

    Enablement is this instance's global switch (``row.enabled``) AND the opt-in of the project, its own (``OpenvasProject.enabled``) or its
    organization's (``OpenvasOrg``) unless the project was excluded (``sweep_links``).

    Pausing. This step is exempt from the pause gate of the task layer (``scan_control.PAUSE_EXEMPT_TASKS``) because it is what reaches a task that is
    already running: while scanning is paused it never dispatches a task, and when an App Admin paused everything (not just an update's drain, which lets
    running work finish) it expires the running Sentinel task. Only one GVM task ever runs at a time (``OpenvasRun``'s own unique constraint).

    A run with no Sentinel task is one an earlier version started against this server's own gvmd. Nothing drives it any more, so it is closed as failed
    (``finish``) at once and no host is recorded as failed: they stay due and go to a Sentinel at the next step. Left open it would hold the
    one-at-a-time slot for ever."""
    from cveFeed.models import OpenvasRun, OpenvasSettings
    from cveFeed.scan_control import operator_pause_requested
    from reNgine import resources
    row = OpenvasSettings.current()
    if not row.enabled:
        return {'skipped': 'the OpenVAS add-on is switched off'}
    owner = f'openvas-{os.getpid()}'
    with resources.redis_claim('cvengine:openvas:tick', owner, 600) as holder:
        if holder is not True:
            return {'skipped': 'another OpenVAS step is running'}
        run = OpenvasRun.objects.select_related('sentinel_task').filter(status='running').first()
        if run is not None and not run.sentinel_task_id:
            finish(run, 'failed', LOCAL_RUN_CLOSED)  # no ledger entry: the hosts stay due
            logger.warning('closed OpenVAS run %s: it was started against a local gvmd, which this server no longer drives', run.pk)
            run = None
        if run is None and resources.global_pause_requested(fail_closed=True):
            return {'skipped': 'scanning is paused'}
        if run is not None:
            if operator_pause_requested():
                from agentapi import sentinel_broker
                sentinel_broker.expire(run.sentinel_task, 'scanning is paused: the hosts stay due')  # an expired task marks no host failed
            return poll_sentinel(run)
        found_due = False
        skipped = _SkippedProjects()
        for link in sweep_links():
            if not skipped.eligible(link.project, internal=False):
                continue
            batch = next_batch(link, resolve=resolve, blocked=blocked)
            if not batch:
                continue
            found_due = True
            started = dispatch_to_sentinel(link, batch)
            if started is not None:
                return {'run': started.pk, 'status': 'running', 'hosts': len(batch), 'via': 'sentinel'}
        for link in sweep_links():  # a project's declared internal networks: only a Sentinel inside them can scan, never this server
            if not skipped.eligible(link.project, internal=True):
                continue
            batch = internal_batch(link)
            if not batch:
                continue
            found_due = True
            started = dispatch_to_sentinel(link, batch)
            if started is not None:
                return {'run': started.pk, 'status': 'running', 'hosts': len(batch), 'via': 'internal sentinel'}
        skipped.log()
        if found_due:
            return {'skipped': 'a due host has no eligible Sentinel right now; it stays due' + skipped.suffix()}
        return {'skipped': 'no opted-in host with an eligible Sentinel is due' + skipped.suffix()}


def _register():
    from agentapi import stage_runs
    stage_runs.adapter('openvas.import', queue='openvas_queue')(_import_reported)


_register()
