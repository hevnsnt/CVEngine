"""The port stage of a scan: open-port discovery and service fingerprinting of the IPs discovery found, both run by a Sentinel.

Nothing here launches a tool. ``run_for_scan`` picks the scan's IPs that no scan has covered recently (the ledger), hands them to a scanner in
chunks (``agentapi.sentinel_dispatch``: first a port discovery pass, then the OS and service fingerprint), and stores what comes back
(``cveFeed.port_inventory``). The stage never runs on this server: with no scanner able to take the work it raises ``ScannerUnavailable`` and the
IPs stay due until one can. The full ``-p-`` sweep is a slow background task of its own (``cveFeed.fullscan``). Everything feeds the same
Shodan-style inventory (Port / IpAddress) that every scan stage writes to, so correlate_cves and the hosts page see one consistent picture
regardless of which tool found what.

Port discovery (``discover``): addresses scanned inside the ledger TTL are not scanned again (their open ports are read from the inventory); the rest
are claimed, dispatched and recorded. It never raises: any failure leaves the fingerprint pass to its own defaults.
"""
import logging
import os

from cvengine_scanner.flags import MAX_OPEN_PER_IP  # noqa: F401 - a tarpit or an accept-everything firewall: more open ports than this is not a result

logger = logging.getLogger(__name__)

SERVICE = 'naabu'  # ledger service of the discovery pass (TTL 7 days); also the source its Port rows carry
FAST_SERVICE = 'nmap-fast'  # ledger service of the fingerprint pass; what the check coverage of a host reads
MAX_TARGETS = 200


def enabled():
    """The discovery pass runs by default: the fingerprint pass alone covers only the common ports, and the only other way to catch the rest is the
    background full-port sweep, which can take days to reach a given host. ``CVENGINE_NAABU=0`` switches the pass off."""
    return os.environ.get('CVENGINE_NAABU', '1').strip().lower() in ('1', 'true', 'yes', 'on')


def build_targets(ips, limit=MAX_TARGETS):
    """Pure: the deduplicated, sorted IP list. Hostnames are never scanned: they resolve to the very same IPs, and several names on one address would
    be fingerprinted once each."""
    return sorted({i for i in ips if i})[:limit]


def _plural(n, word):
    return f'{n} {word}{"s" if n != 1 else ""}'


def known_open_ports(ips, org_id=None):
    """``{ip: [ports]}`` the organization's inventory already holds as open for these addresses."""
    from startScan.models import IpAddress
    out = {}
    for ip in IpAddress.objects.filter(address__in=list(ips), org_id=org_id).prefetch_related('ports'):
        out[ip.address] = sorted({p.number for p in ip.ports.all() if p.state in ('', 'open') and p.protocol in ('', 'tcp')})
    return out


def _waiting(exc, count, project, scan):
    """The one activity line for a port discovery that no scanner could take: it names the scanner, and says the addresses stay due."""
    from cveFeed import activity
    activity.log('run_check', f'port discovery for {count} address{"es" if count != 1 else ""} is waiting: no scanner could take this work '
                 f'({exc.kind}); the addresses stay due until one can',
                 project=project, scan_id=getattr(scan, 'id', None))


def discover(ips, scan, runner):
    """Open ports per address for ``ips`` through ``runner(ips) -> {ip: [ports]}`` (``sentinel_dispatch.wrap_naabu_runner``), or None when nothing
    could be discovered. The result for every address also carries the ports the inventory held open before. Never raises: any failure is None."""
    from cveFeed import ledger
    from reNgine import resources
    from targetApp.target_types import scannable_hosts
    ips = scannable_hosts(sorted(set(ips)))
    if not ips or runner is None:
        return None
    from startScan.ip_rows import org_id_of_project
    project = scan.domain.project_id if scan is not None else None
    org_id = org_id_of_project(project)
    try:
        fresh = set(ledger.fresh(SERVICE, ips, project))
        todo = [i for i in ips if i not in fresh]
        found, lost, rejected = {}, [], set()
        if todo:
            with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
                won = [i for i in todo if i in set(won)]
                if won:
                    try:
                        answer = runner(won)
                        # A tarpit is not a clean scan with no open ports: it is left out of the port map
                        rejected = {ip for ip, ports in answer.items() if ip in won and (ports is None or len(ports) > MAX_OPEN_PER_IP)}
                        found = {ip: ports for ip, ports in answer.items() if ip in won and ip not in rejected}
                    except resources.ScannerUnavailable as exc:  # no scanner could take it: nothing is recorded and the addresses stay due
                        logger.warning('port discovery is waiting for a scanner: %s', exc)
                        _waiting(exc, len(won), project, scan)
                        return None
                    except Exception:  # noqa: BLE001 - an optional stage
                        logger.warning('port discovery failed', exc_info=True)
                        ledger.record(SERVICE, won, project, scan, 'failed')
                        return None
                    ledger.record(SERVICE, [ip for ip in won if ip not in rejected], project, scan)
                    if rejected:
                        logger.warning('port discovery discarded tarpit results for %s address(es)', len(rejected))
                        ledger.record(SERVICE, rejected, project, scan, 'failed')
                    persist_open_ports(found, org_id)
                lost = [i for i in todo if i not in won]  # another pipeline holds these: its result lands in the inventory
        before = known_open_ports(ips, org_id)
    except Exception:  # noqa: BLE001
        logger.warning('port discovery stage failed', exc_info=True)
        return None
    lost = set(lost)
    # an address another pipeline holds, with nothing known about it, is left out
    return {ip: sorted(set(found.get(ip, [])) | set(before.get(ip, []))) for ip in ips
            if ip not in rejected and (ip not in lost or before.get(ip))}


def persist_open_ports(found, org_id=None):
    """Write the discovered open ports as open Port rows (source ``SERVICE``); the fingerprint pass enriches them next."""
    from cveFeed.port_inventory import persist_inventory
    inventory = [{'ip': ip, 'os_guess': '', 'ports': [{'number': n, 'state': 'open', 'protocol': 'tcp'} for n in ports]}
                 for ip, ports in found.items()]
    if inventory:
        persist_inventory(inventory, source=SERVICE, org_id=org_id)


def run_for_scan(scan_id, force=False):
    """Fingerprint the scan's discovered IPs that no scan has covered recently, on a Sentinel. Only IPs are scanned, each at most once per TTL across
    all scans (see cveFeed.ledger); an IP another pipeline is scanning right now is left to it. With no scanner able to take the work the stage
    waits (``ScannerUnavailable``): the IPs are not recorded and stay due."""
    from agentapi import sentinel_dispatch
    from cveFeed import activity, hosting, ledger
    from cveFeed.nuclei_scan import scan_targets
    from reNgine import resources
    from startScan.ip_rows import org_id_of_project
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    org_id = org_id_of_project(project)
    _hostnames, ips, _ports = scan_targets(scan)
    all_ips = build_targets(ips, limit=None)
    shared = hosting.shared_by_address(all_ips)
    if shared:
        # Netlify, Vercel, a CDN edge: the address belongs to the platform and other customers answer on it, so it is not ours to scan
        hosting.mark_shared(shared)
        all_ips = [i for i in all_ips if i not in shared]
        providers = ', '.join(sorted({v['provider'] for v in shared.values() if v['provider']})) or 'a shared platform'
        activity.log('run_check', f'the port scan left {len(shared)} shared platform address(es) alone for {domain.name} ({providers}): '
                     'other customers answer on them', project=project, scan_id=scan.id)
    if not all_ips:
        if not shared:
            activity.log('run_check', f'the port scan skipped for {domain.name}: discovery found no IPs to scan', project=project)
        return {'targets': 0, 'shared': len(shared)} if shared else {'targets': 0}

    fast_todo = all_ips if force else [i for i in all_ips if i not in ledger.fresh(FAST_SERVICE, all_ips, project)]
    if not fast_todo:
        activity.log('run_check', f'the port scan skipped for {domain.name}: all {_plural(len(all_ips), "IP")} were fingerprinted '
                     f'in the last {ledger.ttl_label(FAST_SERVICE)}', project=project, scan_id=scan.id)
        return {'targets': len(all_ips), 'reused': len(all_ips)}
    result = {'targets': len(all_ips), 'reused': len(all_ips) - len(fast_todo)}

    with ledger.claim_many(f'{FAST_SERVICE}@{project}', fast_todo) as won:
        targets = build_targets(won)
        if targets:
            reused = len(all_ips) - len(fast_todo)
            note = f' ({reused} already fingerprinted in the last {ledger.ttl_label(FAST_SERVICE)})' if reused else ''
            busy = len(fast_todo) - len(won)
            note += f' ({busy} being scanned by another scan)' if busy else ''
            running = activity.log('run_check', f'a scanner is fingerprinting {len(targets)} new IP(s) for {domain.name}{note}, scan #{scan_id}',
                                   project=project, status='running', scan_id=scan.id)
            try:
                if enabled():
                    discover(targets, scan, sentinel_dispatch.wrap_naabu_runner(domain.project, scan))  # raises when no scanner can take it
                fast = sentinel_dispatch.try_nmap(domain.project, scan, targets, org_id=org_id)
            except resources.ScannerUnavailable as exc:  # no scanner can take it, and it never runs here: not the targets' failure, they stay due
                logger.warning('port scan of scan %s is waiting for a scanner: %s', scan_id, exc)
                finished = set(exc.done)
                covered = [ip for ip in targets if ip in finished]  # a Sentinel fingerprinted these in full (persisted already)
                if covered:
                    ledger.record(FAST_SERVICE, covered, project, scan)
                due = len(targets) - len(covered)
                note = f' ({len(covered)} fingerprinted by a Sentinel)' if covered else ''
                activity.settle(running, 'done', message=(
                    f'the port scan for {domain.name} is waiting: no scanner could take this work ({exc.kind}); '
                    f'the {_plural(due, "IP")} stay due until one can{note}'))
                return {**result, 'skipped': f'no scanner could take this work ({exc.kind}): the targets stay due'}
            except Exception as exc:  # noqa: BLE001 - a bad run must not take the rest of the pipeline down
                logger.exception('port scan failed for scan %s', scan_id)
                ledger.record(FAST_SERVICE, targets, project, scan, 'failed')
                activity.settle(running, 'failed', message=f'the port scan failed for {domain.name}: {exc}')
                return {**result, 'error': str(exc)}
            ledger.record(FAST_SERVICE, targets, project, scan)
            activity.settle(running, 'done', message=(
                f'fingerprinted {domain.name}: {_plural(fast["ports"], "service")}, '
                f'{fast["hosts_with_os"]} OS guess{"es" if fast["hosts_with_os"] != 1 else ""}'), **fast)
            result['fast'] = fast
    return result
