"""Run nmap, naabu or nuclei against a server-issued SentinelTask's own typed target, and nothing else.

Every argv built here is a fixed list of flags plus the addresses or hosts the task named: there is no shell, no
string interpolation, and no text the server sent is ever read as a flag or a command. ``validate_targets`` is the one
gate every target list passes through before it reaches ``subprocess``; it is deliberately strict, because a
compromised or buggy server asking a Sentinel to run something other than a plain address, host name or host:port
must fail safe here. This mirrors, in reverse, the discipline ``agentapi``'s own header docstring states for what a
Sentinel reports back: nothing untrusted is ever built into, or interpreted as, a command, on either side of the wire.

Each run function returns the exact typed shape ``agentapi.sentinel_broker.clean_result`` expects for that task kind
(``{'hosts': [...]}`` for nmap, ``{'ports': {...}}`` for naabu, ``{'findings': [...]}`` for nuclei), ready to be sent
back under ``{'outcome': 'done', **result}``.
"""
import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

logger = logging.getLogger('sentinel.tools')

MAX_TARGETS = 64  # matches agentapi.sentinel_broker.MAX_ADDRESSES: a task never names more than this many
_HOSTNAME = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*\.?$')
_SHELL_META = set(' \t\n\r;|&$`<>(){}\'"\\')

NMAP_BIN = os.environ.get('CVENGINE_NMAP_BIN', 'nmap')
NAABU_BIN = os.environ.get('CVENGINE_NAABU_BIN', 'naabu')
NUCLEI_BIN = os.environ.get('CVENGINE_NUCLEI_BIN', 'nuclei')

NMAP_FLAGS = ['-Pn', '-sV', '--version-intensity', '5', '-O', '--osscan-limit', '-T4', '--open',
              '--top-ports', '1000', '--host-timeout', '8m', '--max-retries', '2']
NAABU_FLAGS = ['-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
NUCLEI_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1']
_TAG = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
_SEVERITY = re.compile(r'^(info|low|medium|high|critical|unknown)$')


class TargetError(ValueError):
    """A SentinelTask's ``target`` did not have the shape a Sentinel will ever act on. Always reported back as
    ``{'outcome': 'error', ...}``, never retried blindly, and the raw target is never passed to a shell."""


def _split_host_port(value):
    if value.count(':') == 1 and not value.startswith('['):
        host, _, port = value.partition(':')
        if port.isdigit() and 0 < int(port) < 65536:
            return host, port
    return value, None


def _validate_one(value):
    if not isinstance(value, str) or not value or len(value) > 260:
        raise TargetError(f'not a usable target: {value!r}')
    text = value.strip()
    if not text or '://' in text or any(ch in _SHELL_META for ch in text):
        raise TargetError(f'not a usable target: {value!r}')
    host, _port = _split_host_port(text)
    try:
        ipaddress.ip_address(host)
        return text
    except ValueError:
        pass
    if not _HOSTNAME.match(host.rstrip('.')):
        raise TargetError(f'not a usable target: {value!r}')
    return text


def validate_targets(values, limit=MAX_TARGETS):
    """The task's own address/host list, defensively checked: a plain IP, a host name, or ``host:port`` (for nuclei),
    nothing shell-meaningful and no URL, at most ``limit`` entries. Raises ``TargetError`` on anything else, rather
    than ever letting it reach an argv list."""
    if not isinstance(values, list) or not values:
        raise TargetError('target has no usable addresses')
    return [_validate_one(v) for v in values[:limit]]


def _targets_file(values):
    handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
    try:
        handle.write('\n'.join(values) + '\n')
    finally:
        handle.close()
    return handle.name


def _run(argv, timeout, register=None):
    """Run ``argv`` (a fixed list, never a string, never ``shell=True``) and return its stdout. ``register``, if given,
    is called with the live ``Popen`` right after it starts, so a caller (the daemon's SIGTERM handler) can terminate
    it without waiting out the full timeout."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if register is not None:
        register(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    if proc.returncode not in (0, None) and not out:
        logger.warning('%s exited %s: %s', argv[0], proc.returncode, (err or '')[:300])
    return out


# --- nmap -----------------------------------------------------------------------------------------------------------

def parse_nmap_xml(xml_text):
    hosts = []
    if not (xml_text or '').strip():
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        return {'hosts': hosts}
    for host_el in root.findall('host'):
        addr_el = None
        for kind in ('ipv4', 'ipv6'):
            addr_el = host_el.find(f"address[@addrtype='{kind}']")
            if addr_el is not None:
                break
        if addr_el is None:
            addr_el = host_el.find('address')
        if addr_el is None or not addr_el.get('addr'):
            continue
        os_guess = ''
        osmatch = host_el.find('os/osmatch')
        if osmatch is not None:
            os_guess = osmatch.get('name') or ''
        ports = []
        for port_el in host_el.findall('ports/port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            service_el = port_el.find('service')
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            ports.append({'number': number, 'protocol': port_el.get('protocol') or 'tcp', 'state': 'open',
                          'service_name': (service_el.get('name') if service_el is not None else '') or '',
                          'product': (service_el.get('product') if service_el is not None else '') or '',
                          'version': (service_el.get('version') if service_el is not None else '') or ''})
        hosts.append({'ip': addr_el.get('addr'), 'os_guess': os_guess, 'ports': ports})
    return {'hosts': hosts}


def run_nmap(addresses, timeout=600, register=None):
    addresses = validate_targets(addresses)
    path = _targets_file(addresses)
    try:
        argv = [NMAP_BIN, *NMAP_FLAGS, '-oX', '-', '-iL', path]
        return parse_nmap_xml(_run(argv, timeout, register))
    finally:
        os.unlink(path)


# --- naabu ----------------------------------------------------------------------------------------------------------

MAX_OPEN_PER_IP = 500  # an address with more "open" ports than this is a tarpit or a firewall that accepts everything


def parse_naabu_output(text):
    found = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        ip, port = row.get('ip') or row.get('host'), row.get('port')
        if ip and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            found.setdefault(str(ip), set()).add(port)
    return {ip: sorted(ports) for ip, ports in found.items() if len(ports) <= MAX_OPEN_PER_IP}


def run_naabu(addresses, timeout=900, register=None):
    addresses = validate_targets(addresses)
    path = _targets_file(addresses)
    try:
        argv = [NAABU_BIN, '-list', path, *NAABU_FLAGS]
        return {'ports': parse_naabu_output(_run(argv, timeout, register))}
    finally:
        os.unlink(path)


# --- nuclei -----------------------------------------------------------------------------------------------------------

def host_of(line):
    """Hostname or IP a nuclei result line names (``host`` may be a URL or host:port); mirrors
    ``cveFeed.nuclei_scan.host_of`` so a Sentinel-reported finding names the same host a local run would."""
    raw = (line.get('host') or line.get('ip') or '').strip()
    if '://' in raw:
        return (urlparse(raw).hostname or '').lower()
    if raw.count(':') == 1:
        return raw.rsplit(':', 1)[0].strip('[]').lower()
    return raw.strip('[]').lower()


def parse_nuclei_jsonl(text):
    findings = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get('info') or {}
        findings.append({'template_id': row.get('template-id') or '', 'name': info.get('name') or '',
                         'severity': info.get('severity') or 'unknown', 'host': host_of(row),
                         'matched_at': row.get('matched-at') or '', 'description': info.get('description') or '',
                         'matcher_name': row.get('matcher-name') or '',
                         'extracted_results': [v for v in (row.get('extracted-results') or []) if isinstance(v, str)],
                         'tags': [t for t in (info.get('tags') or []) if isinstance(t, str)]})
    return findings


def _clean_words(values, pattern):
    return sorted({v for v in (values or []) if isinstance(v, str) and pattern.match(v)})


def run_nuclei(targets, tags=None, severities=None, timeout=3600, register=None):
    targets = validate_targets(targets)
    path = _targets_file(targets)
    flags = list(NUCLEI_FLAGS)
    clean_tags = _clean_words(tags, _TAG)
    if clean_tags:
        flags += ['-tags', ','.join(clean_tags)]
    clean_severities = _clean_words(severities, _SEVERITY)
    if clean_severities:
        flags += ['-severity', ','.join(clean_severities)]
    try:
        argv = [NUCLEI_BIN, '-l', path, *flags]
        return {'findings': parse_nuclei_jsonl(_run(argv, timeout, register))}
    finally:
        os.unlink(path)


RUNNERS = {'nmap': run_nmap, 'naabu': run_naabu, 'nuclei_light': run_nuclei, 'nuclei_targeted': run_nuclei}


# --- version probing, for the capabilities a bootstrapping Sentinel declares ------------------------------------------

VERSION_ARGS = {'nmap': [NMAP_BIN, '--version'], 'naabu': [NAABU_BIN, '-version'], 'nuclei': [NUCLEI_BIN, '-version']}


def detect_tools():
    """The tool names whose binary actually ran when probed with its own version flag: what a Sentinel declares in
    ``tools`` at bootstrap. Never raises; a missing or broken tool is simply left out."""
    found = []
    for name, argv in VERSION_ARGS.items():
        try:
            subprocess.run(argv, capture_output=True, timeout=10, check=False)
            found.append(name)
        except (OSError, subprocess.TimeoutExpired):
            continue
    return found
