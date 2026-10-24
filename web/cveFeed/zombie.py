"""Zombie hosts: a name that no longer resolves but whose last known address still answers.

A host that disappears from DNS is normally retired. If the address CVEngine last saw it on still serves web pages, the
asset is not gone, only unnamed: it is reported as a zombie instead (and scores higher), not retired. The check is the same
kind of request as the route auth check, a safe GET: the old address is asked for ``/`` with the old name in the Host header,
no credentials, no cookies, no redirects followed, at most 64 KB read, and only addresses a scanner may touch are asked.
At most ZOMBIE_PORTS_PER_HOST ports of a host and MAX_ZOMBIE_CHECKS hosts per scan are checked. ``endpoints`` and
``check_hosts`` are pure apart from the injectable ``checker``.
"""
import logging

logger = logging.getLogger(__name__)

ZOMBIE_PORTS_PER_HOST = 3
MAX_ZOMBIE_CHECKS = 100
HTTPS_PORTS = (443, 8443, 9443)
WEB_PORTS = (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443, 3000)
CHECK_TIMEOUT = (3, 4)


def _scheme(port, service):
    service = (service or '').lower()
    return 'https' if port in HTTPS_PORTS or 'https' in service or 'ssl' in service else 'http'


def endpoints(state, limit=ZOMBIE_PORTS_PER_HOST):
    """``[(ip, port, scheme)]`` from a stored host snapshot: the web ports it last had open on addresses a scanner may touch,
    443 and 80 first, then the lowest port numbers, at most ``limit``. Non-web ports are not asked (the check is an HTTP GET)."""
    from targetApp.target_types import is_scannable_ip
    found = []
    for ip, info in ((state or {}).get('ips') or {}).items():
        if not is_scannable_ip(ip):
            continue
        for key, port in ((info or {}).get('ports') or {}).items():
            number, _, proto = str(key).partition('/')
            if not number.isdigit() or proto not in ('', 'tcp'):
                continue
            number = int(number)
            service = (port or {}).get('service', '')
            if number in WEB_PORTS or 'http' in (service or '').lower():
                found.append((ip, number, _scheme(number, service)))
    found.sort(key=lambda e: (0 if e[1] == 443 else 1 if e[1] == 80 else 2, e[1], e[0]))
    return found[:limit]


def tcp_endpoints(state, limit=ZOMBIE_PORTS_PER_HOST):
    """``[(ip, port)]``: the non-web TCP ports a host last had open (SSH, RDP, a database), on addresses a scanner may touch, lowest
    port numbers first, at most ``limit``. The web ports are the HTTP check's; these only get a connect."""
    from targetApp.target_types import is_scannable_ip
    found = []
    for ip, info in ((state or {}).get('ips') or {}).items():
        if not is_scannable_ip(ip):
            continue
        for key, port in ((info or {}).get('ports') or {}).items():
            number, _, proto = str(key).partition('/')
            if not number.isdigit() or proto not in ('', 'tcp'):
                continue
            number = int(number)
            if number in WEB_PORTS or 'http' in ((port or {}).get('service') or '').lower():
                continue
            found.append((ip, number))
    found.sort(key=lambda e: (e[1], e[0]))
    return found[:limit]


def tcp_alive(ip, port):
    """Whether a TCP connection to ``ip:port`` is accepted: connect, close, nothing sent, no banner read."""
    import socket
    try:
        with socket.create_connection((ip, port), timeout=CHECK_TIMEOUT[0]):
            return True
    except OSError:
        return False


def tcp_probe_hosts(candidates, states, prober=None):
    """For hosts the HTTP check found nothing on: ``{host: ['ip:port', ...]}`` of the last non-web ports that still accept a
    connection. Evidence for a person to read on the retired row. It is never a zombie: a bare connect cannot tell the old
    asset from a recycled address that now belongs to someone else, which only the HTTP answer for the old Host name can."""
    prober = prober or tcp_alive
    out = {}
    for host in candidates[:MAX_ZOMBIE_CHECKS]:
        answering = [f'{ip}:{port}' for ip, port in tcp_endpoints(states.get(host)) if prober(ip, port)]
        if answering:
            out[host] = answering
    return out


def http_alive(host, ip, port, scheme):
    """Whether ``ip:port`` still answers a plain GET for ``/`` as ``host`` (any HTTP status counts as an answer)."""
    from cveFeed import route_auth
    name = f'[{ip}]' if ':' in ip else ip
    try:
        route_auth.probe_url(f'{scheme}://{name}:{port}/', timeout=CHECK_TIMEOUT, max_bytes=4096, headers={'Host': host})
        return True
    except Exception:  # noqa: BLE001 - a refused connection, a timeout or a TLS failure: nothing answers there
        return False


def check_hosts(candidates, states, checker=None):
    """Ask the last known web addresses of up to MAX_ZOMBIE_CHECKS candidates (host names that no longer resolve). Returns
    ``(alive, checked)``: ``alive`` maps a host to the ``ip:port`` strings that answered, ``checked`` is the list of hosts
    that were asked. Hosts beyond the cap are neither alive nor checked: they wait for the next scan."""
    checker = checker or http_alive
    alive, checked = {}, []
    for host in candidates[:MAX_ZOMBIE_CHECKS]:
        checked.append(host)
        answering = [f'{ip}:{port}' for ip, port, scheme in endpoints(states.get(host)) if checker(host, ip, port, scheme)]
        if answering:
            alive[host] = answering
    return alive, checked
