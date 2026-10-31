"""Unauthenticated-database exposure checks: for a database-like service nmap found open, make exactly
ONE read-only connection attempt with NO credentials and see whether the server lets it through. This
never tries a second username/password combination (credential guessing is out of scope here) and
never reads, lists or modifies real data once connected - the single fact recorded is "no credential
was required to reach this service", which is itself the vulnerability for a network-exposed datastore.
"""
import logging
import socket

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 3
MAX_BODY_BYTES = 65536  # a status page or a list of database names; a server that sends more is not answering this question
TOTAL_SECONDS = 10  # the whole request, so a server that drips one byte at a time cannot hold the worker
# What the server said when it let the attempt through, kept as the finding's evidence: (host, port) -> short text. A checker notes
# it just before returning True and run_db_exposure_checks takes it; runs are sequential, so one table is enough.
EVIDENCE = {}


def _note(host, port, text):
    EVIDENCE[(host, port)] = str(text)[:300]


def check_redis(host, port):
    """A single PING with no password: open iff the server answers instead of demanding auth."""
    try:
        import redis
    except ImportError:
        return None
    client = None
    try:
        client = redis.Redis(host=host, port=port, socket_connect_timeout=CONNECT_TIMEOUT,
                             socket_timeout=CONNECT_TIMEOUT)
        if not client.ping():
            return False
        reply = 'PONG'
        try:
            reply += f' (redis {client.info("server").get("redis_version", "?")})'
        except Exception:  # noqa: BLE001 - the version is a nicety; the PONG is the evidence
            pass
        _note(host, port, reply)
        return True
    except redis.AuthenticationError:
        return False
    except redis.ResponseError:  # NOAUTH, WRONGPASS, a protected-mode DENIED, LOADING: the server did not let the PING through
        return False
    except Exception:  # noqa: BLE001 - refused/timeout/reset: simply "not exposed", not a crash
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


def check_memcached(host, port):
    """Memcached has no authentication mechanism at all, so any instance that answers a read-only
    "version" command is, by definition, reachable with none."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.sendall(b'version\r\n')
            reply = sock.recv(256)
        if reply.startswith(b'VERSION'):
            _note(host, port, reply.decode('ascii', 'replace').strip().splitlines()[0])
            return True
        return False
    except OSError:
        return False


def check_postgres(host, port):
    """A single attempt to connect to the default "postgres" database as the default "postgres" role
    with no password: open iff the server's access policy trusts this connection outright."""
    try:
        import psycopg2
    except ImportError:
        return None
    conn = None
    try:
        conn = psycopg2.connect(host=host, port=port, dbname='postgres', user='postgres', password='',
                                connect_timeout=CONNECT_TIMEOUT)
        version = getattr(conn, 'server_version', None)
        _note(host, port, f'PostgreSQL {version // 10000}.{version % 10000}' if isinstance(version, int) else 'connected as postgres, no password')
        return True
    except Exception:  # noqa: BLE001 - OperationalError covers auth failure, refused, no such db, etc.
        return False
    finally:
        if conn is not None:
            conn.close()


def _netloc(host, port):
    """``host:port`` for a URL, an IPv6 literal in brackets."""
    return f'[{host}]:{port}' if ':' in str(host) else f'{host}:{port}'


def _bounded_json(url):
    """GET ``url`` (no redirects) and parse its JSON body, reading at most MAX_BODY_BYTES within TOTAL_SECONDS. None unless the answer
    is a 200 with JSON inside those bounds. The scanned server controls how much it sends and how slowly, so neither is trusted."""
    import json
    import time

    from urllib.parse import urlsplit

    import requests

    from cveFeed import egress_proxy
    deadline = time.monotonic() + TOTAL_SECONDS
    with requests.Session() as session:
        session.trust_env = False  # scanner traffic never takes the environment's proxy or .netrc; Settings > Proxy is the only one
        with session.get(url, timeout=CONNECT_TIMEOUT, allow_redirects=False, stream=True,
                         proxies=egress_proxy.requests_proxies(urlsplit(url).hostname)) as resp:
            if resp.status_code != 200:
                return None
            body, size = [], 0
            # one byte per read: a read of n bytes blocks until n arrive, so a server dripping a byte just inside the socket timeout would
            # hold a larger read (and the deadline check after it) for n times that timeout
            for chunk in resp.iter_content(1):
                body.append(chunk)
                size += len(chunk)
                if size > MAX_BODY_BYTES or time.monotonic() > deadline:
                    return None
            return json.loads(b''.join(body)) if body else None


def check_elasticsearch(host, port):
    """A plain GET /: Elasticsearch with no security plugin configured answers with cluster info and no
    auth challenge at all."""
    try:
        info = _bounded_json(f'http://{_netloc(host, port)}/')
        if not isinstance(info, dict) or 'cluster_name' not in info:
            return False
        _note(host, port, f'cluster {info.get("cluster_name")}, version {(info.get("version") or {}).get("number", "?")}')
        return True
    except Exception:  # noqa: BLE001
        return False


def check_couchdb(host, port):
    """GET /_all_dbs: lists database NAMES only, never document content. CouchDB's "admin party" mode
    (no admin user ever configured) answers this with no credential at all."""
    try:
        names = _bounded_json(f'http://{_netloc(host, port)}/_all_dbs')
        if not isinstance(names, list):
            return False
        _note(host, port, f'/_all_dbs answered with {len(names)} database name(s)')  # a count, never the names
        return True
    except Exception:  # noqa: BLE001
        return False


def check_mysql(host, port):
    """A single connection attempt as root with no password: open iff the server lets it straight through. Like
    check_postgres above, this tries one specific likely-default account, never a second username or password."""
    try:
        import pymysql
    except ImportError:
        return None
    conn = None
    try:
        conn = pymysql.connect(host=host, port=port, user='root', password='', connect_timeout=CONNECT_TIMEOUT,
                               read_timeout=CONNECT_TIMEOUT, write_timeout=CONNECT_TIMEOUT)
        version = conn.get_server_info()
        _note(host, port, f'connected as root with no password (MySQL {version})' if version else 'connected as root with no password')
        return True
    except Exception:  # noqa: BLE001 - access denied, refused, reset: simply "not exposed", not a crash
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def check_mongodb(host, port):
    """A single listDatabases command sent with no prior authentication: open iff the server lets it through. Only
    database NAMES are read, the same care check_couchdb above takes - never a document's content. On a server
    with access control enabled this fails with Unauthorized, which is exactly the point: it is the standard way
    to tell a wide-open MongoDB apart from a secured one without sending any credential at all."""
    try:
        import pymongo
    except ImportError:
        return None
    client = None
    try:
        client = pymongo.MongoClient(host=host, port=port, serverSelectionTimeoutMS=int(CONNECT_TIMEOUT * 1000),
                                     connectTimeoutMS=int(CONNECT_TIMEOUT * 1000), socketTimeoutMS=int(CONNECT_TIMEOUT * 1000),
                                     directConnection=True)
        result = client.admin.command('listDatabases', 1, nameOnly=True)
        names = [str(d.get('name', '')) for d in result.get('databases', [])]
        _note(host, port, f'listDatabases answered with {len(names)} database name(s)')  # a count, never the names
        return True
    except Exception:  # noqa: BLE001 - Unauthorized, refused, timeout: simply "not exposed"
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


CHECKS = {
    'redis': ('Redis', check_redis),
    'memcached': ('Memcached', check_memcached),
    'postgres': ('PostgreSQL', check_postgres), 'postgresql': ('PostgreSQL', check_postgres),
    'elastic': ('Elasticsearch', check_elasticsearch),
    'couchdb': ('CouchDB', check_couchdb),
    'mysql': ('MySQL', check_mysql), 'mariadb': ('MySQL', check_mysql),
    'mongodb': ('MongoDB', check_mongodb), 'mongo': ('MongoDB', check_mongodb),
}


def checker_for(port, table=None):
    """(label, check_fn) for a Port that looks like one of the databases above, else (None, None)."""
    text = f'{port.service_name or ""} {port.product or ""}'.lower()
    for key, (label, fn) in (table if table is not None else CHECKS).items():
        if key in text:
            return label, fn
    return None, None


def _excluded_names(project):
    """Authorization checks fail closed, unlike best-effort discovery filtering."""
    from cveFeed.exclusions import excluded_names
    return excluded_names(project, strict=True)


def run_db_exposure_checks(scan_id, checks=None):
    """One read-only, no-credential connection attempt per database-like port this scan found. Persists
    a critical Vulnerability for every one that let the attempt through. Checker errors are non-fatal;
    authorization lookup failures stop this stage before another connection or finding write.
    ``checks`` overrides the {name-fragment: (label, fn)} table (tests inject fakes here)."""
    from cveFeed import activity
    from cveFeed.exclusions import normalize
    from reNgine import resources
    from startScan.models import open_ports
    from targetApp.target_types import is_scannable_ip
    from reNgine.definitions import NUCLEI_SEVERITY_MAP
    from reNgine.tasks import save_vulnerability
    from startScan.models import ScanHistory, Subdomain

    table = checks if checks is not None else CHECKS
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    targets = []  # (subdomain, host, port_obj, label, check_fn)
    EVIDENCE.clear()
    banned = _excluded_names(project)
    from cveFeed.bounty_gate import Gate
    gate = Gate(blocked=())  # a bug bounty program's scope: a host it does not name, or an address it excludes, is never connected to
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        if normalize(sub.name) in banned or gate.refusal(project, sub.name, unattended=False):
            continue
        for ip in sub.ip_addresses.all():
            if not is_scannable_ip(ip.address, project=project) or gate.refusal(project, ip.address, unattended=False, derived=True):
                continue
            for port in open_ports(ip):
                label, fn = checker_for(port, table)
                if fn:
                    targets.append((sub, ip.address, port, label, fn))
    if not targets:
        return {'checked': 0, 'exposed': 0}
    running = activity.log(
        'run_check', f'Checking {len(targets)} database service(s) on {domain.name} for missing authentication',
        project=project, status='running', scan_id=scan.id)
    exposed = checked = 0
    # Names that share an address share the service: one probe per (address, port), and the finding goes to every host that
    # answers on it, each with the same evidence (one critical per host stays visible on each host's page).
    groups = {}
    for sub, host, port, label, fn in targets:
        groups.setdefault((host, port.number, label), (fn, []))[1].append(sub)
    try:
        # under the resource gate like the other scanner stages: a pause or a stopped scan ends the stage between connections
        with resources.heavy_job('route-probe', label=domain.name) as job:
            for (host, number, label), (fn, subs) in groups.items():
                job.raise_if_killed()
                # Exclusion is organization-wide even when its author could not purge
                # this project's records. Recheck at dispatch, not only while planning.
                banned = _excluded_names(project)
                subs = [sub for sub in subs if normalize(sub.name) not in banned]
                if not subs or not is_scannable_ip(host, project=project):
                    continue
                checked += 1
                try:
                    is_open = fn(host, number)
                except Exception:  # noqa: BLE001 - a checker crashing must never take the pipeline down
                    logger.exception('db exposure check %s failed for %s:%s', label, host, number)
                    continue
                if not is_open:
                    continue
                reply = EVIDENCE.pop((host, number), '')
                banned = _excluded_names(project)
                subs = [sub for sub in subs if normalize(sub.name) not in banned]
                if not subs:
                    continue
                exposed += 1
                for sub in subs:
                    vuln, created = save_vulnerability(
                        target_domain=domain, scan_history=scan, subdomain=sub, source='db_exposure',
                        template_id=f'db-exposure-{label.lower()}', name=f'Unauthenticated {label} exposure',
                        severity=NUCLEI_SEVERITY_MAP['critical'],
                        description=f'{label} on {host}:{number} accepted a connection with no credentials at all.'
                                    + (f' The server replied: {reply}' if reply else ''),
                        impact=f'Anyone who can reach {host}:{number} has the same access as a fully authenticated client.',
                        remediation=f'Require authentication on this {label} instance and restrict network access to trusted hosts only.',
                        extracted_results=[reply] if reply else [], http_url=f'{label.lower()}://{host}:{number}')
                    if created:
                        activity.log('validate', f'{label} on {host}:{number} has no authentication required'
                                     + (f' (reply: {reply})' if reply else ''), project=project, severity='critical')
    except (resources.ScanAborted, resources.MemoryBusy, resources.MemoryKill) as exc:  # the rest is checked on the next scan
        if isinstance(exc, resources.ScannerUnavailable):  # a scanner that is offline is not memory pressure
            activity.settle(running, 'done', message=f'Database exposure check for {domain.name} is waiting: no scanner could take this work ({exc.kind}): '
                            f'{exposed} of {checked} service(s) open with no authentication so far; the rest is checked on the next scan')
            return {'checked': checked, 'exposed': exposed, 'skipped': f'no scanner could take this work ({exc.kind})'}
        activity.settle(running, 'done', message=f'Database exposure check for {domain.name} stopped early ({type(exc).__name__}): '
                        f'{exposed} of {checked} service(s) open with no authentication so far')
        return {'checked': checked, 'exposed': exposed, 'skipped': 'scanning was stopped or memory was short'}
    activity.settle(running, 'done', message=(
        f'Database exposure check for {domain.name}: {exposed} of {checked} service(s) open with no authentication'))
    return {'checked': checked, 'exposed': exposed}
