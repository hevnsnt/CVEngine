"""OpenVAS (Greenbone Community Edition) as an optional vulnerability scanner.

The add-on is OFF by default and costs nothing while it is off: its containers belong to the compose profile ``openvas`` (docs/OPENVAS.md),
the beat entry that drives it is created disabled, and nothing in this module contacts the sidecar unless an App Admin switched it on
(Settings > OpenVAS) and opted a project's hosts in. Nothing here runs inside a scan: it is a slow background sweep on its own queue
(``openvas_queue``), like ``cveFeed.testssl_scan``.

How it works. cvENGINE talks GMP (the Greenbone Management Protocol) to gvmd with python-gvm, over the unix socket the sidecar publishes in a
volume (or, for a gvmd on another machine, TLS: ``CVENGINE_OPENVAS_HOST``, always verified, see ``_connection``). gvmd drives the OpenVAS scanner; cvENGINE never talks to the scanner itself. A beat entry calls
``tick`` every 15 minutes, and a tick does one small step, so a worker restart loses nothing:

* nothing is running: pick the next opted-in project with hosts that are due (once a week each, ``ledger`` service ``openvas``), vet every
  host (``scannable_hosts``, exclusions, ``pinned_transport.resolve``: only the vetted numeric address is ever given to GVM, never a name),
  refuse while the feed is not loaded or memory is short (``resource_guard``), make or reuse the GVM target and start one task;
* a task is running: ask its status; when it is Done import its results, when it was stopped, interrupted or lost say so. At most one task
  runs at a time (a unique constraint on ``OpenvasRun``), whichever worker asks.

The scan configuration is a copy of "Full and fast" without the families that can crash or lock out what they test (``EXCLUDED_FAMILIES``)
and with ``safe_checks`` on; it is verified after it is built and again before every use, and the sweep refuses to run with a configuration
that does not pass. Tasks are throttled (``max_checks`` 4 by default, ``max_hosts`` 1).

Results. Every result that names a CVE becomes a ``ProbeObservation`` (one per host, port and NVT OID: the dedupe key and the durable record), a
``Vulnerability`` (source ``openvas``) and ``CVEMatch`` evidence (source ``openvas``). Only a result whose quality of detection (QoD) is at
least ``CONFIRMED_QOD`` (95) or of a hard type (``exploit``, ``remote_vul``, ``remote_app``, ``remote_active``, ``package``, ``registry``: the
check ran against the service or read the installed package) is hard evidence (``template_result`` ``vulnerable``). Greenbone's QoD 80 is
``remote_banner`` and ``executable_version``, a version read from a banner or a binary, which a backport defeats: it is stored with its QoD
and never confirms anything. A result that is absent from a later complete scan of the same host is resolved. The text of an NVT is
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
CONFIRMED_QOD = 95  # the lowest QoD of a hard type when a result carries no type (remote_active is 95, package and registry 97, remote_vul 99)
HARD_QOD_TYPES = frozenset({'exploit', 'remote_vul', 'remote_app', 'remote_active', 'package', 'registry'})
FRESH_DAYS = 21  # an observation older than this is not carried onto a new scan's host row
DEFAULT_MAX_HOSTS = 1  # hosts in one task: a run is slow (hours per host), so one host per task keeps what a stop or a failure costs to one host
DEFAULT_MAX_HOURS = 24  # the time budget PER HOST: a task of n hosts gets n times this; when it runs out, what was found so far is kept
DEFAULT_MAX_CHECKS = 4  # NVTs run at a time against a host (Greenbone's own default); CVENGINE_OPENVAS_MAX_CHECKS
DEFAULT_MAX_INTERRUPTS = 3  # tasks in a row that gvmd reports Interrupted for a host before it waits three days; CVENGINE_OPENVAS_MAX_INTERRUPTS
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

ACTIVE = ('New', 'Requested', 'Queued', 'Running', 'Processing', 'Stop Requested')
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
    """The time budget per host, in hours."""
    return _env_int('CVENGINE_OPENVAS_MAX_HOURS', DEFAULT_MAX_HOURS)


def budget_hours(hosts):
    """The budget of a task of ``hosts`` hosts: ``max_hours()`` for each."""
    return max_hours() * max(1, int(hosts))


def max_interrupts():
    """How many Interrupted tasks in a row a host may cost before it is marked failed (asked again after three days)."""
    return _env_int('CVENGINE_OPENVAS_MAX_INTERRUPTS', DEFAULT_MAX_INTERRUPTS)


def task_preferences():
    """GVM task preferences: ``max_checks`` NVTs at a time (``CVENGINE_OPENVAS_MAX_CHECKS``, 1 to 10) against one host at a time. Fewer is gentler on the
    target and slower: at 2 a host took about a day, at 4 (Greenbone's default) about half that."""
    return {'max_checks': str(min(10, _env_int('CVENGINE_OPENVAS_MAX_CHECKS', DEFAULT_MAX_CHECKS))), 'max_hosts': '1'}


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


def _verified_tls(hostname, port, cafile, certfile=None, keyfile=None, server_name=None):
    """A GMP TLS link that checks who answers. python-gvm's own ``TLSConnection`` verifies the server only when a CA, a client certificate and a
    key are all given, and then still skips the host name check; the GMP password and every scan result travel over this link, so the server
    certificate must chain to ``cafile`` and name ``server_name`` (the host by default). A client certificate is sent only when both halves are given."""
    import socket
    import ssl
    from gvm.connections import TLSConnection

    class VerifiedTLSConnection(TLSConnection):
        def _new_socket(self):
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)  # CERT_REQUIRED and check_hostname
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if self.certfile and self.keyfile:
                context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile, password=self.password)
            sock = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=False, server_hostname=server_name or self.hostname)
            sock.settimeout(self._timeout)
            return sock

    return VerifiedTLSConnection(hostname=hostname, port=port, timeout=120, cafile=cafile, certfile=certfile, keyfile=keyfile)


def _connection():
    """The unix socket the sidecar publishes (the default: a local file, no network), or, for a gvmd on another machine
    (``CVENGINE_OPENVAS_HOST``), TLS that is always verified: without ``CVENGINE_OPENVAS_CA`` it refuses to connect rather than send the login
    to an unverified server. ``CVENGINE_OPENVAS_TLS_NAME`` names the certificate's subject when it is not the host."""
    from gvm.connections import UnixSocketConnection
    host = os.environ.get('CVENGINE_OPENVAS_HOST', '').strip()
    if host:
        cafile = os.environ.get('CVENGINE_OPENVAS_CA', '').strip()
        if not cafile:
            raise OpenvasError('CVENGINE_OPENVAS_HOST is set without CVENGINE_OPENVAS_CA: cvENGINE will not send the GMP login to a server it cannot verify')
        return _verified_tls(host, _env_int('CVENGINE_OPENVAS_PORT', 9390), cafile, os.environ.get('CVENGINE_OPENVAS_CERT') or None,
                             os.environ.get('CVENGINE_OPENVAS_KEY') or None, os.environ.get('CVENGINE_OPENVAS_TLS_NAME', '').strip() or None)
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


def _apply_safe_selection(gmp, config_id):
    """Select every family except ``EXCLUDED_FAMILIES`` (each growing and including all its VTs, the only form gvmd accepts for a family that is
    in use: "growing and all VTs, or static and empty"), leave new families out, and turn ``safe_checks`` on."""
    families = [_text(f, 'name') for f in gmp.get_nvt_families().findall('./families/family')]
    wanted = [(name, True, True) for name in families if name and name not in EXCLUDED_FAMILIES]  # python-gvm: (family, growing, include all)
    gmp.modify_scan_config_set_family_selection(config_id, wanted, auto_add_new_families=False)
    gmp.modify_scan_config_set_scanner_preference(config_id, 'safe_checks', value='yes')


def ensure_config(gmp):
    """The id of the safe scan configuration: found by name, or built as a copy of "Full and fast" without ``EXCLUDED_FAMILIES``. It is
    read back and checked every time. One that does not pass (a copy an earlier failed run left half built) gets the selection applied again
    once; one that still does not pass is an error, never used."""
    existing = [c for c in gmp.get_scan_configs().findall('config') if _text(c, 'name') == CONFIG_NAME]
    if existing:
        config_id = existing[0].get('id')
    else:
        base = _find(gmp.get_scan_configs(), FULL_AND_FAST, 'config')
        if base is None:
            raise OpenvasError('the "Full and fast" scan configuration is not in gvmd yet (the feed is not loaded)')
        created = gmp.create_scan_config(base.get('id'), CONFIG_NAME, comment='cvENGINE: Full and fast without denial of service and brute force')
        config_id = created.get('id')
        _apply_safe_selection(gmp, config_id)
    problems = config_problems(gmp.get_scan_config(config_id).find('config'))
    if problems and existing:
        _apply_safe_selection(gmp, config_id)
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

_DOCUMENTATION = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]
OWN_TTL = 3600
OWN_RETRY = 60  # how long a failed lookup of this server's own name is remembered
_own = {'at': 0.0, 'addresses': frozenset()}


def own_addresses():
    """The addresses this cvENGINE instance answers on: ``CVENGINE_OWN_ADDRESSES`` (comma separated; for an instance behind NAT or a load balancer)
    and what ``DOMAIN_NAME`` resolves to, cached for an hour. A scan of any of them would be this instance scanning itself."""
    import socket
    import time
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
    """Why OpenVAS must not be given this address even though a scanner could reach it from the celery container, or ``None``. The sidecar has
    no tailscale interface, so a tailnet address would leave by the Docker host's default route: never. A documentation range (RFC 5737,
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


def _latest_row(project_id, host):
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name=host).select_related('scan_history', 'target_domain')
            .order_by('-scan_history_id').first())


def _names(items):
    return {str(h).strip().lower() for h in (items or ()) if str(h).strip()}


HOT = ('fire', 'smoke')  # the heats OpenVAS is spent on: a run is slow (hours per host), so it goes where it matters
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
    closed = ('fixed', 'accepted_risk')
    # The current inventory only (not every scan's copy of a name), hottest first, so a large project's fire hosts fall inside the window.
    names = set(CVEMatch.objects.filter(latest_scan_q('subdomain__'), subdomain__target_domain__project_id=project_id).exclude(ai_verdict='not_affected')
                .exclude(remediation_status__in=closed).annotate(heat_rank=match_heat_rank_expr()).filter(heat_rank__gte=2)
                .values('subdomain__name').annotate(top=Max('heat_rank')).order_by('-top', 'subdomain__name').values_list('subdomain__name', flat=True)[:limit])
    names |= set(Vulnerability.objects.filter(latest_scan_q('subdomain__'), target_domain__project_id=project_id, open_status=True, severity__gte=2)
                 .exclude(remediation_status__in=closed).values('subdomain__name').annotate(top=Max('severity')).order_by('-top', 'subdomain__name')
                 .values_list('subdomain__name', flat=True)[:limit])
    return _names(names)


def host_heat(project_id, names):
    """``{name: (heat, (fire reasons, smoke reasons))}`` for each of ``names`` that is a host of the project: the host card's own colour (its
    CVE matches as they apply to it and its open findings, hottest first), read from the latest stored row of the name."""
    from agentapi import services
    from startScan.models import Subdomain
    wanted = sorted(_names(names))
    if not wanted:
        return {}
    rows = (Subdomain.objects.filter(target_domain__project_id=project_id, name__in=wanted).order_by('name', '-scan_history_id').distinct('name')
            .prefetch_related('cve_matches__cve_entry', 'cve_matches__triage', 'vulnerability_set', 'vulnerability_set__triage'))
    out = {}
    for sub in rows:
        reasons = services._heat_reasons(sub)
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

    A host is refused when: it is not a host of the project; it is excluded or archived; (with ``gate``) it is not Fire or Smoke, unless
    ``forced`` names it; it is on a CDN or a platform other tenants share, or at an address that is not the project's to test (documentation
    ranges, this server, the tailnet), or the same address as a host already chosen; it was scanned within a week or failed within three days.
    ``forced`` lifts only the heat gate, never the ownership refusals. Order: Fire before Smoke, then the most fire reasons, then the most smoke
    reasons, then the longest-waiting; a forced host with no heat comes last. ``resolve=None`` reads the stored address (no DNS): the explanation
    shown to people. The real selection passes ``_address``. ``internal`` selects the project's declared internal networks, whose names are their
    own address and which only a Sentinel inside can reach."""
    from cveFeed import exclusions, hosting, ledger
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
    passed = []
    for host in names:
        heat = heats.get(host, ('', (0, 0)))[0]
        sub = _latest_row(project_id, host) if host in heats else None
        if sub is None:
            refuse(host, heat, 'not a host of this project')
        elif host not in kept:
            refuse(host, heat, 'excluded from scanning')
        elif (barred := bounty.refusal(project_id, host)):
            refuse(host, heat, 'bug bounty: ' + barred)
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
    from django.db.models import Q
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
                         'started_at': run.started_at.isoformat(), 'budget_hours': budget_hours(len(run.hosts)), 'via': 'sentinel' if run.sentinel_task_id else 'local'}
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
                               preferences=task_preferences())
        run.task_id = task.get('id') or ''
        run.save(update_fields=['task_id'])
        gmp.start_task(run.task_id)
    except Exception as exc:  # noqa: BLE001 - the scan never ran, so no host is marked failed: gvmd's trouble is not the host's
        finish(run, 'failed', f'could not create or start the task ({type(exc).__name__})')
        raise OpenvasError(f'could not create or start the GVM task ({type(exc).__name__})') from None
    return run


def finish(run, status, error='', summary=None):
    run.status, run.error, run.finished_at = status, clean(error, 300), timezone.now()
    if summary is not None:
        run.summary = summary
    run.save(update_fields=['status', 'error', 'finished_at', 'summary'])


INCONCLUSIVE = 'OpenVAS ran but reported no scanned host'


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


def interrupted_streak(run, names, limit=None):
    """``{host: attempts}``: for each of ``names``, how many tasks in a row gvmd reported Interrupted for it, counting ``run`` (the one
    that just was). Walks the project's earlier runs newest first and stops, for a host, at the first run that covered it and was not
    Interrupted (a success, an inconclusive report, a stop, any other failure) or that already gave it up (``summary.interrupt_limit``:
    three more attempts start from there, once the three days are over). Only ``limit`` attempts need counting, so it reads no more."""
    from cveFeed.models import OpenvasRun
    limit = limit or max_interrupts()
    count, open_ = {host: 1 for host in names}, set(names)
    for earlier in OpenvasRun.objects.filter(project_id=run.project_id, id__lt=run.pk).order_by('-id').only(
            'gvm_status', 'hosts', 'summary')[:max(50, 10 * limit)]:
        if not open_:
            break
        for host in set(earlier.hosts.values()) & open_:
            if earlier.gvm_status == 'Interrupted' and host not in (earlier.summary or {}).get('interrupt_limit', {}):
                count[host] += 1
                if count[host] >= limit:
                    open_.discard(host)
            else:
                open_.discard(host)
    return count


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
    """Whether a result is hard evidence. The type decides when gvmd gave one: QoD 80 is ``remote_banner`` / ``executable_version``, a version
    string that a backport defeats, so the number alone must not confirm anything."""
    qod_type = (item.get('qod_type') or '').strip().lower()
    if qod_type:
        return qod_type in HARD_QOD_TYPES
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


def import_results(run, gmp, status_xml):
    """Import a finished local task: fetch its results from gvmd, then store them exactly as a Sentinel-reported run's own
    results are stored (``_apply_import``, the one path both use). Returns the run summary."""
    items, no_cve, unusable = fetch_results(gmp, run.task_id)
    scanned = scanned_addresses(gmp, status_xml, items)
    # Results come highest severity first and stop at MAX_RESULTS: a scan that hit the cap says nothing about what lies beyond it, so it is
    # partial (nothing earlier is resolved by it) rather than a complete answer.
    return _apply_import(run, items, scanned, no_cve, unusable, partial=len(items) + unusable >= MAX_RESULTS)


def _apply_import(run, items, scanned, no_cve, unusable, partial=False):
    """Observations, findings, evidence and resolutions for each host of ``run``, from already-fetched, already-parsed
    results (``items``, in ``parse_result``'s own shape) and the set of addresses gvmd actually scanned. The one storage
    path for a task cvENGINE ran itself and one a Sentinel ran against its own sidecar and reported back: neither knows or
    cares which produced ``items``. ``partial`` is a scan stopped at its time budget: what it found is kept, but it says nothing about
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
    """Hand a due batch to a Sentinel instead of running gvmd locally for it: one ``SentinelTask`` (kind ``openvas``) and
    one ``OpenvasRun`` that only tracks it (the same unique-running-row cvENGINE's own local run already uses, so a
    Sentinel-dispatched task and a local one can still never run at once). The Sentinel runs its own GVM stack against
    this exact host set and the excluded-NVT-family list named in the task's ``target`` - this instance's own
    ``EXCLUDED_FAMILIES``, never a copy a Sentinel might carry out of date - and reports back when done; the next tick
    imports the result through the same path (``_apply_import``) a local run's own does."""
    from agentapi.models import SentinelTask
    from cveFeed import activity
    from cveFeed.models import OpenvasRun
    hosts = {ip: host for host, ip, _domain in batch}
    task = SentinelTask.objects.create(project=link.project, kind='openvas', ips=sorted(hosts), host=', '.join(sorted(set(hosts.values())))[:500],
                                       target={'hosts': hosts, 'excluded_families': list(EXCLUDED_FAMILIES), 'max_hours': budget_hours(len(hosts)),
                                    'preferences': task_preferences()})
    try:
        with transaction.atomic():  # the same "one task at a time" lock start() uses for a local run
            run = OpenvasRun.objects.create(project=link.project, status='running', sentinel_task=task, hosts=hosts)
    except IntegrityError:
        task.delete()
        return None
    activity.log('run_check', f'Handed an OpenVAS scan of {len(batch)} host(s) to a Sentinel', project=link.project_id, sentinel_task_id=task.pk)
    return run


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


def poll_sentinel(run):
    """One step of a Sentinel-dispatched run: ask its ``SentinelTask``'s own status, exactly as ``poll`` asks gvmd's for a
    local one. No GMP session is opened for this: the Sentinel talks to its own sidecar, never this instance's."""
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
        entry = activity.log('run_check', f'OpenVAS: importing the Sentinel-reported results of {len(run.hosts)} host(s)',
                             project=run.project_id, status='running')
        try:
            summary, names = _apply_import(run, result.get('results') or [], set(result.get('scanned_addresses') or []),
                                           result.get('without_cve', 0), result.get('unusable', 0), partial=bool(result.get('partial')))
        except Exception as exc:  # noqa: BLE001
            finish(run, 'failed', f'the Sentinel-reported results could not be imported ({type(exc).__name__})')
            ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
            activity.settle(entry, 'done', message=activity.diagnostic('OpenVAS Sentinel result import', exc))
            return {'run': run.pk, 'status': 'failed'}
        gone = [h for h in run.hosts.values() if h not in names]
        ledger.record(SERVICE, names, run.project_id)
        ledger.record(FAILED_SERVICE, gone, run.project_id)
        empty = inconclusive(summary)
        finish(run, 'done', error=(INCONCLUSIVE if empty else 'stopped at its time budget; the results found so far were kept' if summary['partial'] else ''), summary=summary)
        if empty:
            activity.settle(entry, 'done', message=f'OpenVAS (Sentinel): {INCONCLUSIVE} ({len(run.hosts)} host(s) asked); none is marked scanned')
            return {'run': run.pk, 'status': 'done', **summary}
        activity.settle(entry, 'done', message=(f'OpenVAS (Sentinel){" stopped at its time budget" if summary["partial"] else ""}: {summary["hosts_scanned"]} host(s) scanned, {summary["findings"]} finding(s) with a CVE, '
                                                f'{summary["resolved"]} resolved' + (f', {summary["without_cve"]} result(s) without a CVE not imported' if summary['without_cve'] else '')))
        return {'run': run.pk, 'status': 'done', **summary}
    # failed or expired: the Sentinel never finished it. A later tick retries, locally or on a Sentinel. The hosts are marked failed (asked again in
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


def _out_of_budget(run, gmp):
    """The task ran past its time budget: stop it and keep what it found. With no result at all it failed like before (the hosts are asked
    again in three days); with some, they are imported as a partial scan (nothing earlier is resolved by it) and the hosts count as scanned."""
    from cveFeed import activity, ledger
    hours = budget_hours(len(run.hosts))
    try:
        items, no_cve, unusable = fetch_results(gmp, run.task_id)
    except Exception:  # noqa: BLE001 - gvmd would not say: nothing to keep
        items, no_cve, unusable = [], 0, 0
    stopped = _stop(gmp, run, 'failed', f'the task ran for more than {hours} hours')
    if not items:
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
        return stopped
    summary, names = _apply_import(run, items, {i['address'] for i in items}, no_cve, unusable, partial=True)
    gone = [h for h in run.hosts.values() if h not in names]
    ledger.record(SERVICE, names, run.project_id)
    ledger.record(FAILED_SERVICE, gone, run.project_id)
    finish(run, 'done', error=f'stopped at the {hours} hour budget; the results found so far were kept', summary=summary)
    activity.log('run_check', f'OpenVAS: stopped at the {hours} hour budget; kept {summary["findings"]} finding(s) of {summary["hosts_scanned"]} host(s)',
                 project=run.project_id)
    return {'run': run.pk, 'status': 'done', **summary}


POLL_RETRIES = 4  # polls in a row (15 minutes apart) gvmd may fail to answer about a running task before the run is given up


def _task_gone(exc):
    """Whether ``exc`` is gvmd saying it has no such task (a 404 answer), as opposed to a socket timeout, a restart or any other trouble."""
    return str(getattr(exc, 'status', '')) == '404'


def _trouble_key(run):
    return f'cvengine:openvas:poll-trouble:{run.pk}:{int(run.started_at.timestamp())}'


def _poll_trouble(run, gmp, exc):
    """gvmd did not answer about a running task (busy, restarting, a timeout). The task may well still be running, so nothing is decided from a
    single failure: the run stays ``running`` and the next tick asks again, no host is marked failed and no second task can start. After
    ``POLL_RETRIES`` ticks in a row it is stopped (best effort) and the run fails without blaming a host."""
    from django.core.cache import cache
    key = _trouble_key(run)
    count = (cache.get(key) or 0) + 1
    if count < POLL_RETRIES:
        cache.set(key, count, 6 * 3600)
        return {'run': run.pk, 'status': 'running', 'error': f'gvmd did not answer about the task ({type(exc).__name__}); asking again at the next step'}
    cache.delete(key)
    return _stop(gmp, run, 'failed', f'gvmd did not answer about the task {POLL_RETRIES} times in a row ({type(exc).__name__}): the hosts stay due')


def poll(run, gmp, now=None):
    """One step of the running task: update it, stop it when scanning is paused, memory is critical or it ran too long, import it when Done."""
    from django.core.cache import cache
    from cveFeed import activity, ledger
    from cveFeed.scan_control import operator_pause_requested
    now = now or timezone.now()
    if not run.task_id:  # the worker died between making the run and making the task
        finish(run, 'failed', 'the task was never created')
        return {'run': run.pk, 'status': 'failed'}
    try:
        status = gmp.get_task(run.task_id)
    except Exception as exc:  # noqa: BLE001
        if not _task_gone(exc):
            return _poll_trouble(run, gmp, exc)
        finish(run, 'failed', f'gvmd no longer has the task ({type(exc).__name__})')  # deleted by hand, or the database was reset
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
        return {'run': run.pk, 'status': 'failed'}
    cache.delete(_trouble_key(run))
    task = status.find('./task')
    word = _text(task, 'status')
    progress = _text(task, 'progress')
    run.gvm_status, run.progress = word[:30], _int(progress)
    run.save(update_fields=['gvm_status', 'progress'])
    if word in ACTIVE:
        if operator_pause_requested():  # an update's drain pause lets running work finish; Pause all scanning does not
            return _stop(gmp, run, 'stopped', 'scanning is paused: the hosts stay due')
        if memory_critical():
            return _stop(gmp, run, 'stopped', 'memory ran critically low: the hosts stay due')
        if now - run.started_at > timedelta(hours=budget_hours(len(run.hosts))):
            return _out_of_budget(run, gmp)
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
        empty = inconclusive(summary)
        finish(run, 'done', error=INCONCLUSIVE if empty else f'more than {MAX_RESULTS} results: the lowest-severity ones were not imported' if summary['partial'] else '',
               summary=summary)
        try:
            gmp.delete_task(run.task_id, ultimate=True)
        except Exception:  # noqa: BLE001 - the results are imported; a leftover task is harmless
            logger.info('could not remove the finished GVM task of run %s', run.pk)
        if empty:
            activity.settle(entry, 'done', message=f'OpenVAS: {INCONCLUSIVE} ({len(run.hosts)} host(s) asked); none is marked scanned')
            return {'run': run.pk, 'status': 'done', **summary}
        activity.settle(entry, 'done', message=(f'OpenVAS: {summary["hosts_scanned"]} host(s) scanned, {summary["findings"]} finding(s) with a CVE, '
                                                f'{summary["resolved"]} resolved' + (f', {summary["without_cve"]} result(s) without a CVE not imported' if summary['without_cve'] else '')))
        return {'run': run.pk, 'status': 'done', **summary}
    # Stopped, Interrupted, a delete in progress or a word this version does not know: not a result. An interrupted task (gvmd or its scanner
    # restarted under it) says nothing about the hosts at first, so none is marked failed and they stay due. A host that is interrupted
    # again and again is the likely cause (it crashes gvmd or its scanner), so after ``max_interrupts()`` tasks in a row it waits three days.
    hold = 'stopped' if word == 'Stopped' else 'failed'
    said = f'gvmd reports the task as "{clean(word, 30) or "unknown"}"'
    if hold == 'failed' and word != 'Interrupted':
        ledger.record(FAILED_SERVICE, run.hosts.values(), run.project_id)
    elif word == 'Interrupted':
        limit = max_interrupts()
        streak = interrupted_streak(run, sorted(set(run.hosts.values())), limit)
        worn = {host: n for host, n in streak.items() if n >= limit}
        if worn:
            ledger.record(FAILED_SERVICE, worn, run.project_id)
            finish(run, hold, interrupted_reason(limit) if len(run.hosts) == 1 else
                   f'OpenVAS was interrupted {limit} times scanning {len(worn)} host(s) of this run; asked again after three days',
                   summary={'interrupt_limit': worn})
            return {'run': run.pk, 'status': hold, 'gave_up': sorted(worn)}
        said += f' (attempt {max(streak.values(), default=1)} of {limit}; the host is tried again)'
    finish(run, hold, said)
    return {'run': run.pk, 'status': hold}


def tick(session_factory=None, resolve=None, blocked=None):
    """One step of the sweep (every 15 minutes, queue ``openvas_queue``): poll the running task, or start the next due batch. Returns what it
    did, or ``{'skipped': reason}``.

    Enablement is this instance's global switch (``row.enabled``, just above) AND the opt-in of the project, its own
    (``OpenvasProject.enabled``) or its organization's (``OpenvasOrg``) unless the project was excluded (``sweep_links``). A
    Sentinel never changes that; it only changes *where* an already-due, already-opted-in batch runs.

    Pausing. This step is exempt from the pause gate of the task layer (``scan_control.PAUSE_EXEMPT_TASKS``) because it is what reaches a
    task that is already running: while scanning is paused it never starts or dispatches a task, and when an App Admin paused everything
    (not just an update's drain, which lets running work finish) it stops the running local GVM task, or expires the running Sentinel task. Before opening a local GMP session for a due project, this also asks whether a live,
    eligible Sentinel (capability ``openvas``) could take that project's work instead - a project with no such Sentinel
    pays for nothing beyond that one query and behaves exactly as before this existed. Only one GVM task, local or
    Sentinel-dispatched, ever runs at a time (``OpenvasRun``'s own unique constraint), so a project already running one
    way is never also started the other.

    ``row.sentinel_only`` (Settings > OpenVAS) refuses the local fallback entirely: when it is set, a due batch with no
    eligible Sentinel right now is simply left due rather than ever touching this instance's own sidecar - the next tick
    tries again, same as a batch that failed to vet. It does not touch a local run already in progress (started before
    the toggle was turned on, or one this process itself is mid-poll of), which is let finish."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity, ledger
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
        if run is None and resources.global_pause_requested(fail_closed=True):
            return {'skipped': 'scanning is paused'}
        if run is not None and run.sentinel_task_id:
            if operator_pause_requested():
                from agentapi import sentinel_broker
                sentinel_broker.expire(run.sentinel_task, 'scanning is paused: the hosts stay due')  # an expired task marks no host failed
            return poll_sentinel(run)
        if run is None:
            found_due = False
            for link in sweep_links():
                if not sentinel_dispatch.any_scanner_for(link.project, 'openvas'):
                    continue
                batch = next_batch(link, resolve=resolve, blocked=blocked)
                if not batch:
                    continue
                found_due = True
                started = dispatch_to_sentinel(link, batch)
                if started is not None:
                    return {'run': started.pk, 'status': 'running', 'hosts': len(batch), 'via': 'sentinel'}
            for link in sweep_links():  # a project's declared internal networks: only a Sentinel inside them can scan, never this server
                if not sentinel_dispatch.any_scanner_for(link.project, 'openvas', internal=True):
                    continue
                batch = internal_batch(link)
                if not batch:
                    continue
                found_due = True
                started = dispatch_to_sentinel(link, batch)
                if started is not None:
                    return {'run': started.pk, 'status': 'running', 'hosts': len(batch), 'via': 'internal sentinel'}
            if row.sentinel_only:
                return {'skipped': ('Sentinel-only mode is on: a due host has no eligible Sentinel right now; it stays due' if found_due
                                    else 'Sentinel-only mode is on and no opted-in host with an eligible Sentinel is due')}
        try:
            if session_factory is None:
                ensure_login()
            with (session_factory or session)() as gmp:
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
            if run is not None and timezone.now() - run.started_at > timedelta(hours=budget_hours(len(run.hosts))):
                # gvmd cannot be reached, so the budget check in ``poll`` never runs: a local run of a sidecar that was removed or stopped would hold
                # the one-at-a-time slot for ever. The hosts are not marked failed: nothing says the scan itself did.
                finish(run, 'failed', 'gvmd could not be reached and the run is past its time budget')
                return {'run': run.pk, 'status': 'failed', 'error': str(exc)}
            return {'error': str(exc)}
