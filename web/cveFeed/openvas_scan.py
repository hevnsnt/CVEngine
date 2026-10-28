"""OpenVAS (Greenbone Community Edition) as an optional vulnerability scanner.

The add-on is OFF by default and costs nothing while it is off: its containers belong to the compose profile ``openvas`` (docs/OPENVAS.md),
the beat entry that drives it is created disabled, and nothing in this module contacts the sidecar unless an App Admin switched it on
(Settings > OpenVAS) and opted a project's hosts in. Nothing here runs inside a scan: it is a slow background sweep on its own queue
(``openvas_queue``), like ``cveFeed.testssl_scan``.

How it works. cvENGINE talks GMP (the Greenbone Management Protocol) to gvmd with python-gvm, over the unix socket the sidecar publishes in a
volume (or TLS, ``CVENGINE_OPENVAS_HOST``). gvmd drives the OpenVAS scanner; cvENGINE never talks to the scanner itself. A beat entry calls
``tick`` every 15 minutes, and a tick does one small step, so a worker restart loses nothing:

* nothing is running: pick the next opted-in project with hosts that are due (once a week each, ``ledger`` service ``openvas``), vet every
  host (``scannable_hosts``, exclusions, ``pinned_transport.resolve``: only the vetted numeric address is ever given to GVM, never a name),
  refuse while the feed is not loaded or memory is short (``resource_guard``), make or reuse the GVM target and start one task;
* a task is running: ask its status; when it is Done import its results, when it was stopped, interrupted or lost say so. At most one task
  runs at a time (a unique constraint on ``OpenvasRun``), whichever worker asks.

The scan configuration is a copy of "Full and fast" without the families that can crash or lock out what they test (``EXCLUDED_FAMILIES``)
and with ``safe_checks`` on; it is verified after it is built and again before every use, and the sweep refuses to run with a configuration
that does not pass. Tasks are throttled (``max_checks`` 2, ``max_hosts`` 1).

Results. Every result that names a CVE becomes a ``ProbeObservation`` (one per host, port and NVT OID: the dedupe key and the durable record), a
``Vulnerability`` (source ``openvas``) and ``CVEMatch`` evidence (source ``openvas``). Only a result whose quality of detection (QoD) is at
least ``CONFIRMED_QOD`` (80, the level of the remote and authenticated active checks, ``remote_active``, ``remote_vul``, ``package``) is hard
evidence (``template_result`` ``vulnerable``); a lower one ("version possibly affected", a banner that may be a backport) is stored with its
QoD and never confirms anything. A result that is absent from a later complete scan of the same host is resolved. The text of an NVT is
third-party text: it is clipped, stripped of control characters and stored as plain text, and nothing here marks it safe for HTML.

The GMP password lives in ``OpenvasSettings`` (encrypted), is read here and nowhere else, and is never logged, never put in activity text,
evidence or error messages, and never on a command line."""
import hashlib
import ipaddress
import logging
import os
import re
import time
from contextlib import ExitStack, contextmanager
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
CONFIRMED_QOD = 80
FRESH_DAYS = 21  # an observation older than this is not carried onto a new scan's host row
DEFAULT_MAX_HOSTS = 4  # hosts in one task
DEFAULT_MAX_HOURS = 12
DEFAULT_MIN_AVAILABLE_MB = 3072
DEFAULT_COST_MB = 1500
DEFAULT_SOCKET = '/run/gvmd/gvmd.sock'
RESULT_PAGE = 100
MAX_RESULTS = 5000  # per task: more is a misconfigured scan, not a report
MAX_TEXT = 4000
MIN_NVTS = 1000  # fewer NVTs than this in "Full and fast" means the feed has not been loaded into gvmd yet

# GVM built-ins (the community feed's fixed ids; each is confirmed by name when it is looked up).
FULL_AND_FAST = ('daba56c8-73ec-11df-a475-002264764cea', 'Full and fast')
OPENVAS_SCANNER = ('08b69003-5fc2-4037-a479-93b440211c73', 'OpenVAS Default')
PORT_LIST = ('33d0cd82-57c6-11e1-8ed1-406186ea4fc5', 'All IANA assigned TCP')
CONFIG_NAME = 'cvENGINE safe scan'
# Families left out of the scan configuration, and why. "Denial of Service": NVTs that crash or hang the service they test (the reason
# ``safe_checks`` exists, enforced here a second time at the family level). "Brute force attacks": password guessing, which locks accounts out
# and is a different act from checking for a known vulnerability. Every other family is "Full and fast"'s. ``safe_checks`` stays on, which makes
# the scanner skip any remaining NVT whose category is destructive, denial, kill-host or flood.
EXCLUDED_FAMILIES = ('Denial of Service', 'Brute force attacks')
DEFAULT_LOGIN = ('admin', 'admin')  # what Greenbone's community containers create; replaced by ``bootstrap``
TASK_PREFERENCES = {'max_checks': '2', 'max_hosts': '1'}  # two NVTs at a time against one host at a time: slow on purpose

ACTIVE = ('New', 'Requested', 'Queued', 'Running', 'Processing', 'Stop Requested')
LOST = ('Delete Requested', 'Ultimate Delete Requested')
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_TAILNET = [ipaddress.ip_network(n) for n in ('100.64.0.0/10', 'fd7a:115c:a1e0::/48')]


class OpenvasError(RuntimeError):
    """The sidecar could not do what was asked. The message is safe to store and show: it never carries the login."""


# ----------------------------------------------------------------------------- settings and text

def _env_int(name, default, low=1):
    try:
        return max(low, int(os.environ.get(name, default)))
    except ValueError:
        return default


def max_hosts():
    return _env_int('CVENGINE_OPENVAS_MAX_HOSTS', DEFAULT_MAX_HOSTS)


def max_hours():
    return _env_int('CVENGINE_OPENVAS_MAX_HOURS', DEFAULT_MAX_HOURS)


def min_available_mb():
    return _env_int('CVENGINE_OPENVAS_MIN_AVAILABLE_MB', DEFAULT_MIN_AVAILABLE_MB, 256)


def cost_mb():
    return _env_int('CVENGINE_OPENVAS_COST_MB', DEFAULT_COST_MB, 100)


def socket_path():
    return os.environ.get('CVENGINE_OPENVAS_SOCKET', '').strip() or DEFAULT_SOCKET


def transport():
    """How the sidecar is reached: ``socket:<path>`` (the default) or ``tls:<host>:<port>``."""
    host = os.environ.get('CVENGINE_OPENVAS_HOST', '').strip()
    return f'tls:{host}:{_env_int("CVENGINE_OPENVAS_PORT", 9390)}' if host else f'socket:{socket_path()}'


def clean(value, limit=MAX_TEXT):
    """Third-party text as plain, bounded text: control characters removed, whitespace kept, clipped."""
    return _CONTROL.sub('', str(value or '')).strip()[:limit]


def _redact(text, secret):
    text = str(text or '')
    return text.replace(secret, '***') if secret else text


def _enabled():
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.objects.first()
    return bool(row and row.enabled)


# ----------------------------------------------------------------------------- the GMP session

@contextmanager
def session(creds=None, connection=None):
    """An authenticated python-gvm session (``gmp``) to gvmd. ``creds`` is ``(username, password)``, read from the settings when omitted;
    ``connection`` replaces the unix socket or TLS link in tests. Raises ``OpenvasError`` with a message that never holds the password."""
    from gvm.errors import GvmError
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeCheckCommandTransform
    if creds is None:
        from cveFeed.models import OpenvasSettings
        row = OpenvasSettings.current()
        creds = (row.gmp_username, row.gmp_password)
    username, password = creds
    if not (username and password):
        raise OpenvasError('no GMP login is saved: run `make openvas-user` or enter one in Settings > OpenVAS')
    stack = ExitStack()
    try:
        gmp = stack.enter_context(GMP(connection or _connection(), transform=EtreeCheckCommandTransform()))
    except GvmError as exc:
        raise OpenvasError(f'gvmd could not be reached ({clean(_redact(exc, password), 120)}): is the openvas profile running?') from None
    except (OSError, ValueError) as exc:
        raise OpenvasError(f'gvmd could not be reached ({type(exc).__name__}): is the openvas profile running?') from None
    try:
        with stack:
            try:
                gmp.authenticate(username, password)
            except GvmError as exc:
                raise OpenvasError(f'gvmd refused the GMP login ({type(exc).__name__})') from None
            yield gmp
    except OpenvasError:
        raise
    except GvmError as exc:
        raise OpenvasError(f'gvmd answered with an error: {clean(_redact(exc, password), 160)}') from None
    except OSError as exc:
        raise OpenvasError(f'the connection to gvmd failed ({type(exc).__name__})') from None


def _connection():
    from gvm.connections import TLSConnection, UnixSocketConnection
    host = os.environ.get('CVENGINE_OPENVAS_HOST', '').strip()
    if host:
        return TLSConnection(hostname=host, port=_env_int('CVENGINE_OPENVAS_PORT', 9390), timeout=120,
                             cafile=os.environ.get('CVENGINE_OPENVAS_CA') or None, certfile=os.environ.get('CVENGINE_OPENVAS_CERT') or None,
                             keyfile=os.environ.get('CVENGINE_OPENVAS_KEY') or None)
    return UnixSocketConnection(path=socket_path(), timeout=120)


def bootstrap(connection=None, token=None):
    """Replace the community containers' default login (``admin`` / ``admin``) with a generated password and save it for cvENGINE. The password is
    set over GMP, so it is never on a command line; it is checked by signing in with it before it is saved. Returns the user name. If the default
    login no longer works the password was already changed, and the operator saves the one they chose (``manage.py openvas_credentials``)."""
    import secrets
    from cveFeed.models import OpenvasSettings
    new = (token or secrets.token_urlsafe)(24)
    try:
        with session(creds=DEFAULT_LOGIN, connection=connection) as gmp:
            users = [u for u in gmp.get_users(filter_string=f'name={DEFAULT_LOGIN[0]}').findall('user') if _text(u, 'name') == DEFAULT_LOGIN[0]]
            if not users:
                raise OpenvasError('gvmd has no user "admin" to take over')
            gmp.modify_user(users[0].get('id'), password=new)
    except OpenvasError as exc:
        if 'refused the GMP login' in str(exc):
            raise OpenvasError('the default login (admin / admin) no longer works, so its password was changed already: save the one in use with '
                               '`manage.py openvas_credentials --username <user>` (the password on standard input)') from None
        raise
    with session(creds=(DEFAULT_LOGIN[0], new), connection=connection):
        pass  # the new password works
    row = OpenvasSettings.current()
    row.gmp_username, row.gmp_password = DEFAULT_LOGIN[0], new
    row.save()
    return row.gmp_username


def ensure_login():
    """The saved GMP login, made when there is none: the first time the add-on runs, the community containers' default login is replaced by a
    generated one (``bootstrap``) with nobody typing anything. Raises ``OpenvasError`` while gvmd is not up yet or when its default login was
    changed by hand; the caller records that and tries again at the next check."""
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.current()
    if row.gmp_username and row.gmp_password:
        return row
    try:
        bootstrap()
    except OpenvasError:
        row = OpenvasSettings.current()  # another worker may have made it a moment ago
        if row.gmp_username and row.gmp_password:
            return row
        raise
    return OpenvasSettings.current()


def _text(element, path, default=''):
    found = element.find(path) if element is not None else None
    return (found.text or '').strip() if found is not None and found.text else default


def _int(text):
    """A number from gvmd's text, 0 when it is not one."""
    try:
        return int(str(text or '').strip())
    except ValueError:
        return 0


def _find(items, spec, tag):
    """The entity (``<config>``, ``<scanner>``, ``<port_list>``) of ``spec`` = (id, name): by its id when the name agrees, else by name."""
    by_name = None
    for item in items.findall(tag):
        if item.get('id') == spec[0] and _text(item, 'name') == spec[1]:
            return item
        if _text(item, 'name') == spec[1] and by_name is None:
            by_name = item
    return by_name


# ----------------------------------------------------------------------------- feed state and the safe configuration

def feed_state(gmp):
    """Whether gvmd can scan yet, and if not why. The first synchronisation of the feeds takes a long time and a lot of disk, and until
    the NVTs are loaded no scan is possible: ``{ready, reason, feeds: {type: {version, syncing}}, nvts, scanner}``."""
    out = {'ready': False, 'reason': '', 'feeds': {}, 'nvts': 0, 'scanner': ''}
    for feed in gmp.get_feeds().findall('feed'):
        kind = _text(feed, 'type').upper() or _text(feed, 'name')
        syncing = feed.find('currently_syncing')
        out['feeds'][kind] = {'version': _text(feed, 'version'), 'syncing': syncing is not None}
    missing = [k for k in ('NVT', 'SCAP', 'CERT', 'GVMD_DATA') if not (out['feeds'].get(k) or {}).get('version')]
    syncing = [k for k, v in out['feeds'].items() if v['syncing']]
    base = _find(gmp.get_scan_configs(), FULL_AND_FAST, 'config')
    out['nvts'] = _int(_text(base, 'nvt_count')) if base is not None else 0
    scanner = _find(gmp.get_scanners(), OPENVAS_SCANNER, 'scanner')
    out['scanner'] = _text(scanner, 'name') if scanner is not None else ''
    if syncing:
        out['reason'] = f'the {", ".join(sorted(syncing))} feed is synchronising: no scan can start until it finishes (the first synchronisation takes a long time and needs several GB of disk)'
    elif 'NVT' in missing or base is None or out['nvts'] < MIN_NVTS:
        out['reason'] = (f'the vulnerability tests are not loaded yet ({out["nvts"]} in "Full and fast"): the feed is still being downloaded and '
                         'loaded, which takes a long time the first time')
    elif missing:
        out['reason'] = f'the {", ".join(missing)} feed data has not loaded yet'
    elif scanner is None:
        out['reason'] = 'gvmd does not list the OpenVAS scanner yet'
    else:
        out['ready'] = True
    return out


def config_problems(config):
    """Why a ``<config>`` element is not the safe configuration, or ``[]``: an excluded family selected, ``safe_checks`` not on."""
    problems = []
    for family in config.findall('./families/family'):
        name = _text(family, 'name')
        if name in EXCLUDED_FAMILIES and _int(_text(family, 'nvt_count')) > 0:
            problems.append(f'the family "{name}" still has {_text(family, "nvt_count")} NVTs selected')
    safe = [p for p in config.findall('./preferences/preference') if _text(p, 'name') == 'safe_checks']
    if not safe or _text(safe[0], 'value').lower() != 'yes':
        problems.append('the scanner preference safe_checks is not "yes"')
    return problems


def ensure_config(gmp):
    """The id of the safe scan configuration: found by name, or built as a copy of "Full and fast" without ``EXCLUDED_FAMILIES``. It is
    read back and checked every time; a configuration that does not pass is an error, never used."""
    existing = [c for c in gmp.get_scan_configs().findall('config') if _text(c, 'name') == CONFIG_NAME]
    if existing:
        config_id = existing[0].get('id')
    else:
        base = _find(gmp.get_scan_configs(), FULL_AND_FAST, 'config')
        if base is None:
            raise OpenvasError('the "Full and fast" scan configuration is not in gvmd yet (the feed is not loaded)')
        created = gmp.create_scan_config(base.get('id'), CONFIG_NAME, comment='cvENGINE: Full and fast without denial of service and brute force')
        config_id = created.get('id')
        families = [_text(f, 'name') for f in gmp.get_nvt_families().findall('./families/family')]
        wanted = [(name, False, True) for name in families if name and name not in EXCLUDED_FAMILIES]
        gmp.modify_scan_config_set_family_selection(config_id, wanted, auto_add_new_families=False)
        gmp.modify_scan_config_set_scanner_preference(config_id, 'safe_checks', value='yes')
    problems = config_problems(gmp.get_scan_config(config_id).find('config'))
    if problems:
        raise OpenvasError(f'the scan configuration "{CONFIG_NAME}" is not safe ({"; ".join(problems)}): delete it in GVM so cvENGINE can rebuild it')
    return config_id


# ----------------------------------------------------------------------------- the resource guard

def resource_guard(state_fn=None, store=None, now=None):
    """``(ok, reason)``: whether a GVM scan may START now. The scanner runs in the sidecar, outside the celery container's job budget
    (``reNgine.resources``), so this applies the same rules to the machine: free memory must cover the add-on's floor plus the platform's
    headroom, the running heavy jobs plus this one must fit the job budget, nothing may be waiting for memory, and no scanner may have been
    killed for memory in the last hour. ``state_fn`` and ``store`` replace the machine's in tests."""
    from reNgine import resources
    state = (state_fn or resources.memory_state)()
    store = store or resources.get_store()
    now = now or time.time()
    need = min_available_mb() + resources.headroom_mb(state)
    if state['available_mb'] < need:
        return False, (f'memory is short: {state["available_mb"]} MB free, a GVM scan needs {need} MB '
                       f'(the add-on floor of {min_available_mb()} MB plus {resources.headroom_mb(state)} MB headroom)')
    reserved = sum(job.get('mb', 0) for job in store.live(now))
    if reserved + cost_mb() > resources.budget_mb(state):
        return False, f'the scanners running now have {reserved} MB reserved, which leaves no room in the {resources.budget_mb(state)} MB job budget for a GVM scan'
    if store.waiting(now):
        return False, 'other scanner jobs are waiting for memory'
    if any(now - event.get('t', 0) < 3600 for event in store.events()):
        return False, 'a scanner was stopped for memory in the last hour'
    return True, ''


def memory_critical(state_fn=None):
    """Whether a task that is running should be stopped: free memory is below the platform's critical floor."""
    from reNgine import resources
    state = (state_fn or resources.memory_state)()
    return state['available_mb'] < resources.critical_mb(state)


# ----------------------------------------------------------------------------- choosing hosts

def refuse_address(ip):
    """Whether OpenVAS must not be given this address even though a scanner could reach it from the celery container. The sidecar has no
    tailscale interface, so a tailnet address would leave by the Docker host's default route: never. Everything else is
    ``is_scannable_ip``'s decision."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(address.version == net.version and address in net for net in _TAILNET)


def _address(host, project_id):
    """The one vetted numeric address of ``host`` (IPv4 first); raises ``ValueError`` when it resolves somewhere prohibited."""
    from cveFeed import pinned_transport
    addresses = pinned_transport.resolve(host, 443, project=project_id)
    ordered = sorted(addresses, key=lambda item: item[0] != 2)  # AF_INET is 2
    return ordered[0][1][0]


def _latest_row(project_id, host):
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name=host).select_related('scan_history', 'target_domain')
            .order_by('-scan_history_id').first())


def due(project_id, hosts, resolve=None, blocked=None):
    """``[(host, ip, domain_id)]`` of the opted-in ``hosts`` that are due: vetted, not excluded or archived, not scanned within a week and
    not failed within three days, never-scanned first. Vetting is the same as for every other scanner (``scannable_hosts``,
    ``pinned_transport.resolve``); a host that fails it is dropped silently, like a name that stopped resolving. One host per address."""
    from cveFeed import exclusions, ledger
    from targetApp.target_types import scannable_hosts
    resolve = resolve or _address
    names = exclusions.drop_excluded(project_id, [h.strip().lower() for h in hosts if str(h).strip()])
    allowed = scannable_hosts(names, resolver=blocked, project=project_id)
    found, by_ip = [], set()
    for host in allowed:
        sub = _latest_row(project_id, host)
        if sub is None:
            continue  # not a host of this project (any more): never scan a name the project does not own
        try:
            ip = resolve(host, project_id)
        except (ValueError, OSError):
            continue
        if refuse_address(ip) or ip in by_ip:
            continue
        by_ip.add(ip)
        found.append((host, ip, sub.target_domain_id))
    rows = ledger.stale_first(SERVICE, [(0, host, project_id) for host, _ip, _d in found])
    failed = ledger.fresh(FAILED_SERVICE, [r[1] for r in rows], project_id)
    order = [r[1] for r in rows if r[1] not in failed]
    keyed = {item[0]: item for item in found}
    return [keyed[host] for host in order if host in keyed]


AUTO_WINDOW = 40  # the hosts of an opted-in project that is not limited to a list, looked at in one step: the stalest first


def candidate_hosts(project_id, limit=AUTO_WINDOW):
    """The hosts of a project the sweep may look at next when nobody listed any: every name the project's scans found, minus the excluded
    ones, the ones scanned within a week and the ones that failed within three days, never-scanned first. ``due`` then vets this short list
    like any other (a name that fails the vetting is not dropped for good: the sweep marks it failed, so it is asked again in three days)."""
    from cveFeed import exclusions, ledger
    from startScan.models import Subdomain
    from targetApp.models import Domain
    names = set(Subdomain.objects.filter(target_domain__project_id=project_id).values_list('name', flat=True).distinct()[:5000])
    names |= set(Domain.objects.filter(project_id=project_id).values_list('name', flat=True))
    names = sorted({n.strip().lower() for n in names if n and '*' not in n})
    rows = ledger.stale_first(SERVICE, [(0, n, project_id) for n in exclusions.drop_excluded(project_id, names)])
    failed = ledger.fresh(FAILED_SERVICE, [r[1] for r in rows], project_id)
    return [r[1] for r in rows if r[1] not in failed][:limit]


def sweep_links():
    """The ``OpenvasProject`` rows the sweep works through: the projects opted in one by one, and every project of an opted-in organization
    (a row is made for those, disabled, to keep the GVM target of its host set)."""
    from django.db.models import Q
    from cveFeed.models import OpenvasOrg, OpenvasProject
    from dashboard.models import Project
    org_ids = set(OpenvasOrg.objects.filter(enabled=True).values_list('org_id', flat=True))
    if org_ids:
        have = set(OpenvasProject.objects.values_list('project_id', flat=True))
        for project in Project.objects.filter(org_id__in=org_ids).exclude(pk__in=have):
            OpenvasProject.objects.get_or_create(project=project)
    return OpenvasProject.objects.filter(Q(enabled=True) | Q(project__org_id__in=org_ids)).select_related('project').order_by('project_id')


def next_batch(link, resolve=None, blocked=None):
    """``[(host, ip, domain_id)]`` due for this project: the listed hosts when someone limited it to a list, else its own hosts."""
    if link.hosts:
        return due(link.project_id, link.hosts, resolve=resolve, blocked=blocked)[:max_hosts()]
    names = candidate_hosts(link.project_id)
    vetted = due(link.project_id, names, resolve=resolve, blocked=blocked)
    kept = {host for host, _ip, _domain in vetted}
    from cveFeed import ledger
    ledger.record(FAILED_SERVICE, [n for n in names if n not in kept], link.project_id)
    return vetted[:max_hosts()]


# ----------------------------------------------------------------------------- targets and tasks

def target_for(gmp, link, batch):
    """The GVM target id for this project's address set: reused when the set is the one the last target was made for and gvmd still has
    it, else created (and the superseded one removed when gvmd lets it go)."""
    addresses = sorted({ip for _host, ip, _domain in batch})
    key = hashlib.sha256(','.join(addresses).encode()).hexdigest()[:40]
    if link.target_id and link.target_key == key:
        found = [t for t in gmp.get_targets(filter_string=f'uuid={link.target_id}').findall('target') if t.get('id') == link.target_id]
        if found:
            return link.target_id
    port_list = _find(gmp.get_port_lists(), PORT_LIST, 'port_list')
    if port_list is None:
        raise OpenvasError(f'gvmd has no "{PORT_LIST[1]}" port list yet (the feed data is not loaded)')
    created = gmp.create_target(f'cvengine-p{link.project_id}-{key[:12]}', hosts=addresses, port_list_id=port_list.get('id'),
                                comment='cvENGINE: a vetted host set; created and removed by cvENGINE')
    old, link.target_id, link.target_key = link.target_id, created.get('id'), key
    link.save(update_fields=['target_id', 'target_key'])
    if old:
        try:
            gmp.delete_target(old, ultimate=True)
        except Exception:  # noqa: BLE001 - a target a task still uses cannot be deleted: it is harmless and the next sweep tries again
            logger.info('could not remove the superseded GVM target %s', old)
    return link.target_id


def start(gmp, link, batch):
    """Create and start the GVM task for ``batch``. Returns the ``OpenvasRun``."""
    from cveFeed.models import OpenvasRun
    config_id = ensure_config(gmp)
    scanner = _find(gmp.get_scanners(), OPENVAS_SCANNER, 'scanner')
    if scanner is None:
        raise OpenvasError('gvmd does not list the OpenVAS scanner yet')
    target_id = target_for(gmp, link, batch)
    try:
        with transaction.atomic():  # the unique constraint is the "one task at a time" lock
            run = OpenvasRun.objects.create(project=link.project, status='running', target_id=target_id,
                                            hosts={ip: host for host, ip, _domain in batch})
    except IntegrityError:
        raise OpenvasError('another OpenVAS task is already running') from None
    try:
        task = gmp.create_task(f'cvengine-run-{run.pk}', config_id, target_id, scanner.get('id'), comment='cvENGINE weekly sweep',
                               preferences=TASK_PREFERENCES)
        run.task_id = task.get('id') or ''
        run.save(update_fields=['task_id'])
        gmp.start_task(run.task_id)
    except Exception as exc:  # noqa: BLE001
        from cveFeed import ledger
        ledger.record(FAILED_SERVICE, run.hosts.values(), link.project_id)  # asked again in three days, not at the next tick
        finish(run, 'failed', f'could not create or start the task ({type(exc).__name__})')
        raise OpenvasError(f'could not create or start the GVM task ({type(exc).__name__})') from None
    return run


def finish(run, status, error='', summary=None):
    run.status, run.error, run.finished_at = status, clean(error, 300), timezone.now()
    if summary is not None:
        run.summary = summary
    run.save(update_fields=['status', 'error', 'finished_at', 'summary'])


# ----------------------------------------------------------------------------- results

def _tags(raw):
    """The ``key=value|key=value`` tag string of an NVT as a dict (a value may contain '=' but not '|')."""
    out = {}
    for part in str(raw or '').split('|'):
        key, sep, value = part.partition('=')
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _port(text):
    """``('443/tcp', 443)`` from a GVM port string; ``('general/tcp', 0)`` for a result that belongs to the host."""
    match = re.match(r'^(\d{1,5})/(tcp|udp)$', str(text or '').strip().lower())
    if match and 0 < int(match.group(1)) < 65536:
        return f'{int(match.group(1))}/{match.group(2)}', int(match.group(1))
    return 'general/tcp', 0


def parse_result(result):
    """One ``<result>`` element as a plain dict, or None when it is unusable (no host, no NVT OID). Every text is cleaned and clipped; the
    CVE ids are the ``cve`` references of the NVT, validated; a missing or malformed number reads as zero."""
    nvt = result.find('nvt')
    host_el = result.find('host')
    oid = (nvt.get('oid') or '').strip() if nvt is not None else ''
    address = ((host_el.text or '').strip() if host_el is not None else '')
    if not re.fullmatch(r'[0-9.]{3,64}', oid) or not address:
        return None

    def number(path, default=0.0):
        try:
            return float(_text(result, path) or default)
        except ValueError:
            return default
    refs = nvt.findall('./refs/ref')
    cves = sorted({r.get('id', '').strip().upper() for r in refs if r.get('type', '').lower() == 'cve' and CVE_RE.match(r.get('id', '').strip().upper())})
    cves = sorted(set(cves) | {c for c in (x.strip().upper() for x in re.split(r'[,\s]+', _text(nvt, 'cve'))) if CVE_RE.match(c)})[:50]
    urls = [clean(r.get('id'), 500) for r in refs if r.get('type', '').lower() == 'url' and re.match(r'^https?://', r.get('id', ''))][:20]
    tags = _tags(_text(nvt, 'tags'))
    port, number_port = _port(_text(result, 'port'))
    return {
        'id': result.get('id', ''), 'oid': oid, 'name': clean(_text(nvt, 'name') or _text(result, 'name'), 300), 'family': clean(_text(nvt, 'family'), 100),
        'address': address, 'hostname': clean(_text(host_el, 'hostname'), 255), 'port': port, 'port_number': number_port,
        'severity': max(0.0, min(10.0, number('severity'))), 'threat': clean(_text(result, 'threat'), 20),
        'qod': int(max(0, min(100, number('qod/value')))), 'qod_type': clean(_text(result, 'qod/type'), 40),
        'result': clean(_text(result, 'description'), 2000), 'summary': clean(tags.get('summary'), 1500),
        'insight': clean(tags.get('insight'), 1500), 'impact': clean(tags.get('impact'), 1500), 'affected': clean(tags.get('affected'), 800),
        'solution': clean(_text(nvt, 'solution') or tags.get('solution'), 1500), 'solution_type': clean(tags.get('solution_type'), 30),
        'cvss_vector': clean(tags.get('cvss_base_vector'), 200), 'cves': cves, 'urls': urls,
    }


def severity_level(score):
    """The Vulnerability severity (0 info .. 4 critical) of a CVSS base score."""
    return 4 if score >= 9.0 else 3 if score >= 7.0 else 2 if score >= 4.0 else 1 if score > 0 else 0


def confirmed(item):
    return item['qod'] >= CONFIRMED_QOD


def fetch_results(gmp, task_id):
    """Every result of a task as parsed dicts (at most ``MAX_RESULTS``), a page at a time, plus how many results had no CVE reference.
    The filter asks for every level down to log and for no QoD floor: what is done with a low-confidence result is decided here."""
    items, no_cve, unusable, first = [], 0, 0, 1
    while first <= MAX_RESULTS:
        page = gmp.get_results(filter_string=f'task_id={task_id} levels=chmlg min_qod=0 apply_overrides=0 sort-reverse=severity rows={RESULT_PAGE} first={first}',
                               details=True)
        elements = page.findall('./results/result')
        for element in elements:
            parsed = parse_result(element)
            if parsed is None:
                unusable += 1
            elif not parsed['cves']:
                no_cve += 1
                items.append({**parsed, 'cves': []})  # kept for the scanned-host set only; never stored
            else:
                items.append(parsed)
        if len(elements) < RESULT_PAGE:
            break
        first += RESULT_PAGE
    return items, no_cve, unusable


def scanned_addresses(gmp, task_status, items):
    """The addresses gvmd really scanned: the hosts of the last report and every host that has a result. A host that was down produces
    neither, and its earlier findings are then not resolved: an absent host says nothing about a vulnerability."""
    seen = {i['address'] for i in items}
    report = task_status.find('./task/last_report/report')
    if report is not None and report.get('id'):
        try:
            detail = gmp.get_report(report.get('id'), filter_string='rows=1 min_qod=0 levels=chmlg', details=False)
            seen |= {_text(h, 'ip') for h in detail.findall('.//report/host') if _text(h, 'ip')}
        except Exception:  # noqa: BLE001 - the report's host list is a bonus; the results are the floor
            logger.info('could not read the host list of the report')
    return seen


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
        hard = ev['qod'] >= CONFIRMED_QOD
        save_vulnerability(
            target_domain=domain, scan_history=sub.scan_history, subdomain=sub, http_url=where, name=f'OpenVAS: {ev["name"]}'[:500],
            severity=severity_level(ev['severity']), description=_description(ev), impact=ev.get('impact') or None,
            remediation=ev.get('solution') or None, source=SOURCE, template_id=template_id, type='openvas', cvss_score=ev['severity'] or None,
            cvss_metrics=ev.get('cvss_vector') or None, extracted_results=[ev['result']] if ev.get('result') else None, cve_ids=list(ev['cves']),
            references=list(ev.get('urls') or []), tags=['openvas', 'qod-confirmed' if hard else 'qod-unconfirmed'])
        product = f'OpenVAS NVT {ev["oid"]} on {ev["port"]}'[:255]
        for cve_id in ev['cves']:
            cve = known.get(cve_id)
            if cve is None:
                continue
            matches.add((cve.id, product))
            rows.append({'cve_entry_id': cve.id, 'subdomain_id': sub.id, 'source': SOURCE, 'matched_product': product, 'matched_version': '',
                         'version_in_range': True if hard else None, 'confidence': 0.95 if hard else min(0.5, ev['qod'] / 100),
                         'scan_history_id': sub.scan_history_id, 'distro_status': 'no_data', 'distro_fixed_version': '',
                         'evidence': {'source': 'openvas', 'oid': ev['oid'], 'nvt': ev['name'], 'port': ev['port'], 'qod': ev['qod'], 'qod_type': ev['qod_type'],
                                      'severity': ev['severity'], 'result': ev['result'][:300], 'tested_at': obs.observed_at.isoformat()}})
    correlation.save_matches(rows)
    now = timezone.now()
    for row in rows:
        hard = row['evidence']['qod'] >= CONFIRMED_QOD
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


def import_results(run, gmp, status_xml):
    """Import a finished task: observations, findings, evidence and resolutions for each host of the run. Returns the run summary."""
    items, no_cve, unusable = fetch_results(gmp, run.task_id)
    scanned = scanned_addresses(gmp, status_xml, items)
    summary = {'results': len(items), 'without_cve': no_cve, 'unusable': unusable, 'hosts_scanned': 0, 'hosts_not_scanned': 0, 'findings': 0,
               'evidence': 0, 'resolved': 0, 'not_in_batch': 0}
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
        record_observations(run.project_id, sub.target_domain_id, host, found, scanned_now=True)
        findings, evidence, resolved = apply_observations(sub)
        summary['hosts_scanned'] += 1
        summary['findings'] += findings
        summary['evidence'] += evidence
        summary['resolved'] += resolved
        names.append(host)
    summary['not_in_batch'] = sum(1 for i in items if not any(_same_address(i['address'], a) for a in run.hosts))
    return summary, names


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

def _record_state(row, **state):
    row.state = {**state, 'checked_at': timezone.now().isoformat()}
    row.save(update_fields=['state', 'updated_at'])


def check(gmp):
    """The connection state shown in Settings: ``{connected, gmp_version, feed, guard}``."""
    version = _text(gmp.get_version(), 'version')
    ok, reason = resource_guard()
    return {'connected': True, 'gmp_version': version, 'feed': feed_state(gmp), 'guard': {'ok': ok, 'reason': reason}, 'error': ''}


def check_now(session_factory=None):
    """Test connection (Settings): record and return the state. Runs in a worker, the only container that has the sidecar's socket."""
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.current()
    try:
        if session_factory is None:
            ensure_login()
        with (session_factory or session)() as gmp:
            state = check(gmp)
    except OpenvasError as exc:
        state = {'connected': False, 'gmp_version': '', 'feed': None, 'guard': None, 'error': str(exc)}
    _record_state(row, **state)
    return {**state, 'checked_at': row.state['checked_at']}


def _stop(gmp, run, status, why):
    try:
        gmp.stop_task(run.task_id)
    except Exception:  # noqa: BLE001 - the task may already be over
        logger.info('could not stop the GVM task of run %s', run.pk)
    finish(run, status, why)
    return {'run': run.pk, 'status': status, 'error': why}


def poll(run, gmp, now=None):
    """One step of the running task: update it, stop it when scanning is paused, memory is critical or it ran too long, import it when Done."""
    from cveFeed import activity, ledger
    from reNgine import resources
    now = now or timezone.now()
    if not run.task_id:  # the worker died between making the run and making the task
        finish(run, 'failed', 'the task was never created')
        return {'run': run.pk, 'status': 'failed'}
    try:
        status = gmp.get_task(run.task_id)
    except Exception as exc:  # noqa: BLE001 - the task is gone from gvmd (deleted by hand, the database was reset)
        finish(run, 'failed', f'gvmd no longer has the task ({type(exc).__name__})')
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
        return {'run': run.pk, 'status': 'failed'}
    task = status.find('./task')
    word = _text(task, 'status')
    progress = _text(task, 'progress')
    run.gvm_status, run.progress = word[:30], _int(progress)
    run.save(update_fields=['gvm_status', 'progress'])
    if word in ACTIVE:
        if resources.global_pause_requested(fail_closed=True):
            return _stop(gmp, run, 'stopped', 'scanning is paused: the hosts stay due')
        if memory_critical():
            return _stop(gmp, run, 'stopped', 'memory ran critically low: the hosts stay due')
        if now - run.started_at > timedelta(hours=max_hours()):
            ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
            return _stop(gmp, run, 'failed', f'the task ran for more than {max_hours()} hours')
        return {'run': run.pk, 'status': 'running', 'gvm_status': word, 'progress': run.progress}
    if word == 'Done':
        entry = activity.log('run_check', f'OpenVAS: importing the results of {len(run.hosts)} host(s)', project=run.project_id, status='running')
        try:
            summary, names = import_results(run, gmp, status)
        except Exception as exc:  # noqa: BLE001
            finish(run, 'failed', f'the results could not be imported ({type(exc).__name__})')
            ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
            activity.settle(entry, 'done', message=activity.diagnostic('OpenVAS result import', exc))
            return {'run': run.pk, 'status': 'failed'}
        gone = [h for h in run.hosts.values() if h not in names]
        ledger.record(SERVICE, names, run.project_id)
        ledger.record(FAILED_SERVICE, gone, run.project_id)  # gvmd found no live host: asked again in three days
        finish(run, 'done', summary=summary)
        try:
            gmp.delete_task(run.task_id, ultimate=True)
        except Exception:  # noqa: BLE001 - the results are imported; a leftover task is harmless
            logger.info('could not remove the finished GVM task of run %s', run.pk)
        activity.settle(entry, 'done', message=(f'OpenVAS: {summary["hosts_scanned"]} host(s) scanned, {summary["findings"]} finding(s) with a CVE, '
                                                f'{summary["resolved"]} resolved' + (f', {summary["without_cve"]} result(s) without a CVE not imported' if summary['without_cve'] else '')))
        return {'run': run.pk, 'status': 'done', **summary}
    # Stopped, Interrupted, a delete in progress or a word this version does not know: not a result.
    hold = 'stopped' if word == 'Stopped' else 'failed'
    if hold == 'failed':
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
    finish(run, hold, f'gvmd reports the task as "{clean(word, 30) or "unknown"}"')
    return {'run': run.pk, 'status': hold}


def tick(session_factory=None, resolve=None, blocked=None):
    """One step of the sweep (every 15 minutes, queue ``openvas_queue``): poll the running task, or start the next due batch. Returns what it
    did, or ``{'skipped': reason}``."""
    from cveFeed import activity, ledger
    from cveFeed.models import OpenvasRun, OpenvasSettings
    from reNgine import resources
    row = OpenvasSettings.current()
    if not row.enabled:
        return {'skipped': 'the OpenVAS add-on is switched off'}
    owner = f'openvas-{os.getpid()}'
    with resources.redis_claim('cvengine:openvas:tick', owner, 600) as holder:
        if holder is not True:
            return {'skipped': 'another OpenVAS step is running'}
        try:
            if session_factory is None:
                ensure_login()
            with (session_factory or session)() as gmp:
                run = OpenvasRun.objects.filter(status='running').first()
                if run is not None:
                    return poll(run, gmp)
                state = check(gmp)
                _record_state(row, **state)
                if not state['feed']['ready']:
                    return {'skipped': state['feed']['reason']}
                if resources.global_pause_requested(fail_closed=True):
                    return {'skipped': 'scanning is paused'}
                if not state['guard']['ok']:
                    return {'skipped': state['guard']['reason']}
                for link in sweep_links():
                    batch = next_batch(link, resolve=resolve, blocked=blocked)
                    if not batch:
                        continue
                    started = start(gmp, link, batch)
                    activity.log('run_check', f'OpenVAS scan of {len(batch)} host(s) started', project=link.project_id)
                    return {'run': started.pk, 'status': 'running', 'hosts': len(batch)}
                return {'skipped': 'no opted-in host is due'}
        except OpenvasError as exc:
            _record_state(row, connected=False, gmp_version='', feed=None, guard=None, error=str(exc))
            return {'error': str(exc)}
