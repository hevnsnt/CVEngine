"""Full-port discovery with naabu, ahead of nmap's service fingerprinting.

nmap's own discovery is what limits it: ``--top-ports 1000`` misses services on 8443, 9200, 27017, 5000, 10250 and the like, and a
full ``-p-`` with ``-sV`` is far too slow. naabu (SYN mode) finds the open TCP ports of every address in a few minutes at a
polite rate, and nmap then runs ``-sV -O`` only on those ports: full coverage for about the cost of today's pass.

It runs by default (``CVENGINE_NAABU=0`` turns it off) and is never a hard dependency of the pipeline: with no naabu binary
(``CVENGINE_NAABU_BIN`` or ``naabu`` on the PATH), a failed or timed out run, or an answer that looks like a firewall
accepting everything, ``discover`` returns None and ``nmap_scan`` keeps today's ``--top-ports 1000`` flags. The run waits
for memory under the ``naabu`` heavy-job kind, is claimed in the ledger so two pipelines never scan the same address, and
each address is scanned at most once per ledger TTL (7 days, ``CVENGINE_TTL_NAABU``). Targets go to naabu through a
``-list`` file, never the command line.
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

SERVICE = 'naabu'  # ledger service (TTL 7 days)
DEFAULT_RATE = 1000  # packets per second (CVENGINE_NAABU_RATE)
MAX_OPEN_PER_IP = 500  # an address with more open ports than this is a tarpit or a firewall that accepts everything
MAX_PORT_ARG = 6000  # characters of -p argument; beyond that nmap keeps its default flags
RUN_TIMEOUT_BASE = 600  # seconds, plus per address
RUN_TIMEOUT_PER_IP = 20
RUN_TIMEOUT_MAX = 3 * 3600


def enabled():
    """naabu runs by default: nmap's own --top-ports 1000 misses real services (8443, 9200, 27017, and the like), and the
    only other way to catch them is the background full-port sweep, which can take days to reach a given host. The cost is
    real too, about a minute per address at the default rate, so a install scanning hundreds of targets on a tight schedule
    may want CVENGINE_NAABU=0 to fall back to nmap's top-1000 pass alone; CVENGINE_NAABU_RATE raises the rate instead."""
    return os.environ.get('CVENGINE_NAABU', '1').strip().lower() in ('1', 'true', 'yes', 'on')


def naabu_path():
    """The naabu binary, or None when it is switched off or not installed."""
    if not enabled():
        return None
    wanted = os.environ.get('CVENGINE_NAABU_BIN', '').strip() or 'naabu'
    return shutil.which(wanted)


def rate():
    try:
        return min(5000, max(100, int(os.environ.get('CVENGINE_NAABU_RATE', DEFAULT_RATE))))
    except ValueError:
        return DEFAULT_RATE


def build_command(binary, list_path, packets_per_second):
    return [binary, '-list', list_path, '-p', '-', '-rate', str(packets_per_second), '-retries', '2', '-c', '25',
            '-warm-up-time', '2', '-json', '-silent', '-nc']


def parse_output(text):
    """naabu JSON lines ({"ip": ..., "port": ...}) -> ``{ip: sorted ports}``; an address over MAX_OPEN_PER_IP is dropped."""
    found = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        ip, port = row.get('ip') or row.get('host'), row.get('port')
        if ip and isinstance(port, int) and 0 < port < 65536:
            found.setdefault(str(ip), set()).add(port)
    return {ip: sorted(ports) for ip, ports in found.items() if len(ports) <= MAX_OPEN_PER_IP}


def run_naabu(ips, binary=None):
    """Run naabu over ``ips`` and return ``{ip: [open ports]}``. Waits its turn for memory; raises reNgine.resources.MemoryKill if
    stopped to protect the container, subprocess.TimeoutExpired past the time limit and RuntimeError on a failed run."""
    from reNgine import resources
    binary = binary or naabu_path()
    if not binary:
        raise RuntimeError('naabu is not installed')
    timeout = min(RUN_TIMEOUT_MAX, RUN_TIMEOUT_BASE + RUN_TIMEOUT_PER_IP * len(ips))
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
        handle.write('\n'.join(ips) + '\n')
    try:
        with resources.heavy_job(SERVICE, label=f'{len(ips)} address(es)') as job:
            proc = subprocess.Popen(build_command(binary, handle.name, rate()), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, start_new_session=True)
            job.attach(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                resources.terminate_group(proc, grace=5)
                proc.communicate()
                raise
            job.raise_if_killed()
        if proc.returncode not in (0, None):
            raise RuntimeError(f'naabu exited with status {proc.returncode}: {(err or "").strip()[-200:]}')
        return parse_output(out)
    finally:
        try:
            os.remove(handle.name)
        except OSError:
            pass


def known_open_ports(ips, org_id=None):
    """``{ip: [ports]}`` the organization's inventory already holds as open for these addresses."""
    from startScan.models import IpAddress
    out = {}
    for ip in IpAddress.objects.filter(address__in=list(ips), org_id=org_id).prefetch_related('ports'):
        out[ip.address] = sorted({p.number for p in ip.ports.all() if p.state in ('', 'open') and p.protocol in ('', 'tcp')})
    return out


def discover(ips, scan=None, runner=None):
    """Open ports per address for ``ips``, or None to keep nmap's default flags.

    Addresses naabu scanned inside the ledger TTL are not scanned again (their open ports are read from the inventory); the rest
    are claimed, scanned and recorded. The result for every address also carries the ports the inventory held open before, so the
    nmap pass that follows re-checks them and can close the ones that are gone. Never raises: any failure is None."""
    from cveFeed import ledger
    from targetApp.target_types import scannable_hosts
    if runner is None and not naabu_path():
        return None
    ips = scannable_hosts(sorted(set(ips)))
    if not ips:
        return None
    runner = runner or run_naabu
    from startScan.ip_rows import org_id_of_project
    project = scan.domain.project_id if scan is not None else None
    org_id = org_id_of_project(project)
    try:
        fresh = set(ledger.fresh(SERVICE, ips, project))
        todo = [i for i in ips if i not in fresh]
        found, lost = {}, []
        if todo:
            with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
                won = [i for i in todo if i in set(won)]
                if won:
                    try:
                        found = runner(won)
                    except Exception:  # noqa: BLE001 - an optional stage: nmap's own flags are the fallback
                        logger.warning('naabu failed; nmap keeps its default ports', exc_info=True)
                        ledger.record(SERVICE, won, project, scan, 'failed')
                        return None
                    ledger.record(SERVICE, won, project, scan)
                    persist_open_ports(found, org_id)
                lost = [i for i in todo if i not in won]  # another pipeline holds these: its result lands in the inventory
        before = known_open_ports(ips, org_id)
    except Exception:  # noqa: BLE001
        logger.warning('naabu stage failed; nmap keeps its default ports', exc_info=True)
        return None
    lost = set(lost)
    # an address another pipeline holds, with nothing known about it, is left out: its chunk keeps nmap's default ports
    return {ip: sorted(set(found.get(ip, [])) | set(before.get(ip, []))) for ip in ips if ip not in lost or before.get(ip)}


def persist_open_ports(found, org_id=None):
    """Write naabu's open ports as open Port rows (source 'naabu'); nmap enriches them next."""
    from cveFeed.nmap_scan import persist_inventory
    inventory = [{'ip': ip, 'os_guess': '', 'ports': [{'number': n, 'state': 'open', 'protocol': 'tcp'} for n in ports]}
                 for ip, ports in found.items()]
    if inventory:
        persist_inventory(inventory, source='naabu', org_id=org_id)


def port_argument(ports):
    """A compact nmap -p argument ("22,80,8000-8010") for a set of ports."""
    ports = sorted(set(ports))
    parts, start, prev = [], None, None
    for port in ports + [None]:
        if start is None:
            start = prev = port
        elif port is not None and port == prev + 1:
            prev = port
        else:
            parts.append(str(start) if start == prev else f'{start}-{prev}')
            start = prev = port
    return ','.join(parts)


def flags_for(ports_by_ip, base_flags):
    """A function ``chunk of addresses -> nmap flags``: the base flags with ``--top-ports 1000`` replaced by ``-p <the open ports of
    those addresses>``. None for a chunk with nothing open anywhere (nothing to fingerprint); the base flags when an address has no
    naabu answer or the port list would be unreasonably long."""
    def build(chunk):
        if any(ip not in ports_by_ip for ip in chunk):
            return list(base_flags)
        ports = sorted({p for ip in chunk for p in ports_by_ip[ip]})
        if not ports:
            return None
        argument = port_argument(ports)
        flag = '--top-ports' if '--top-ports' in base_flags else '-p' if '-p' in base_flags else None
        if len(argument) > MAX_PORT_ARG or not flag:
            return list(base_flags)
        i = base_flags.index(flag)
        return [*base_flags[:i], '-p', argument, *base_flags[i + 2:]]
    return build
