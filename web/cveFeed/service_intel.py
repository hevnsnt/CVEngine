"""What nmap's scripts say beyond product and version, kept as host facts and findings.

* ``rdp-ntlm-info`` and ``smb-os-discovery`` name the Windows build, computer name and domain without logging in. They become
  ``IpAddress.fingerprint['facts']`` and, when nmap's own OS guess is empty, the OS shown for the address.
* ``ftp-anon`` says whether the FTP server lets anyone sign in. That is a finding, with the top-level listing nmap read as the
  evidence.

Everything here reads output already stored by the nmap stage; nothing connects to a host.
"""
import logging
import re

logger = logging.getLogger(__name__)

# Windows builds as the NTLM challenge and SMB report them. Server and client builds share numbers, so both are named.
WINDOWS_BUILDS = {
    '10.0.26100': 'Windows Server 2025 / Windows 11 24H2', '10.0.22631': 'Windows 11 23H2', '10.0.22621': 'Windows 11 22H2',
    '10.0.22000': 'Windows 11 21H2', '10.0.20348': 'Windows Server 2022', '10.0.19045': 'Windows 10 22H2',
    '10.0.19044': 'Windows 10 21H2', '10.0.19042': 'Windows 10 20H2', '10.0.19041': 'Windows 10 2004',
    '10.0.18363': 'Windows 10 1909', '10.0.17763': 'Windows Server 2019 / Windows 10 1809', '10.0.14393': 'Windows Server 2016',
    '6.3.9600': 'Windows Server 2012 R2 / Windows 8.1', '6.2.9200': 'Windows Server 2012 / Windows 8',
    '6.1.7601': 'Windows Server 2008 R2 / Windows 7', '6.0.6002': 'Windows Server 2008 / Windows Vista',
}
RDP_FIELDS = {'NetBIOS_Domain_Name': 'domain', 'NetBIOS_Computer_Name': 'computer_name', 'DNS_Domain_Name': 'dns_domain',
              'DNS_Computer_Name': 'fqdn', 'Product_Version': 'build'}
LINE = re.compile(r'^\s*([A-Za-z_ ]+?):\s*(.+?)\s*$')
ANON_OK = re.compile(r'anonymous ftp login allowed', re.I)
MAX_LISTING = 20


def _field_lines(text):
    for raw in str(text or '').splitlines():
        match = LINE.match(raw)
        if match:
            yield match.group(1).strip(), match.group(2).strip()


def parse_rdp_ntlm(text):
    """``{computer_name, domain, fqdn, dns_domain, build, os}`` from rdp-ntlm-info output, only the fields present."""
    facts = {}
    for key, value in _field_lines(text):
        if key in RDP_FIELDS:
            facts[RDP_FIELDS[key]] = value[:200]
    build = facts.get('build', '')
    if build:
        facts['os'] = WINDOWS_BUILDS.get('.'.join(build.split('.')[:3]), f'Windows (build {build})')
    return facts


def parse_smb_os(text):
    """``{os, computer_name, domain, fqdn}`` from smb-os-discovery output, only the fields present."""
    facts = {}
    names = {'OS': 'os_detail', 'Computer name': 'computer_name', 'NetBIOS computer name': 'computer_name',
             'Domain name': 'dns_domain', 'FQDN': 'fqdn', 'Workgroup': 'domain'}
    for key, value in _field_lines(text):
        if key in names:
            facts.setdefault(names[key], re.sub(r'\\x00.*', '', value)[:200])
    detail = facts.pop('os_detail', '')
    if detail:
        facts['os'] = re.split(r'\s*\(', detail, 1)[0][:200]
    return facts


def host_facts(ip_obj):
    """Facts for one address from the stored script output of its ports and the host scripts, ``{}`` when there are none."""
    facts = {}
    smb = ((ip_obj.fingerprint or {}).get('scripts') or {}).get('smb-os-discovery')
    if smb:
        facts.update({**parse_smb_os(smb), 'source': 'smb-os-discovery'})
    for port in ip_obj.ports.all():
        if port.state in ('', 'open') and 'rdp-ntlm-info' in ((port.extra or {}).get('scripts') or {}):
            for key, value in parse_rdp_ntlm(port.extra['scripts']['rdp-ntlm-info']).items():
                facts.setdefault(key, value)  # SMB's answer wins where both say the same thing
            if facts:
                facts.setdefault('source', 'rdp-ntlm-info')
    return facts


def apply_host_facts(ip_obj):
    """Store the address's facts on ``fingerprint['facts']`` and fill an empty OS guess from them. True when anything changed."""
    facts = host_facts(ip_obj)
    if not facts:
        return False
    changed = []
    fingerprint = dict(ip_obj.fingerprint or {})
    if fingerprint.get('facts') != facts:
        fingerprint['facts'] = facts
        ip_obj.fingerprint = fingerprint
        changed.append('fingerprint')
    if facts.get('os') and not ip_obj.os_guess:
        ip_obj.os_guess = facts['os']
        changed.append('os_guess')
    if changed:
        ip_obj.save(update_fields=changed)
    return bool(changed)


def anonymous_ftp(port):
    """The listing lines nmap read when this FTP port lets anyone in, ``None`` when it does not (or nmap did not say)."""
    text = ((port.extra or {}).get('scripts') or {}).get('ftp-anon', '')
    if not ANON_OK.search(text):
        return None
    lines = [line.strip()[:200] for line in text.splitlines()[1:] if line.strip()]
    return lines[:MAX_LISTING]


WEAK_RDP_LAYERS = ('Native RDP', 'RDP', 'SSL')  # accepted without CredSSP: the login screen is reachable before anyone authenticates


def rdp_without_nla(port):
    """The security layers a server accepts that do not require Network Level Authentication, from rdp-enum-encryption. ``None``
    when the script did not run or the server insists on CredSSP."""
    text = ((port.extra or {}).get('scripts') or {}).get('rdp-enum-encryption', '')
    accepted = []
    for key, value in _field_lines(text):
        if value.upper().startswith('SUCCESS') and key in WEAK_RDP_LAYERS:
            accepted.append(key)
    return accepted or None


def record_service_findings(scan):
    """Findings the scan's stored script output proves. Returns how many were new. Idempotent: a finding is one row per host and
    port, and a port that stopped allowing anonymous sign-in is simply no longer reported."""
    from reNgine.tasks import save_vulnerability
    from startScan.models import Subdomain, open_ports
    new = 0
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        for ip in sub.ip_addresses.all():
            apply_host_facts(ip)
            for port in open_ports(ip):
                layers = rdp_without_nla(port) if port.number == 3389 or 'wbt' in (port.service_name or '') else None
                if layers:
                    _vuln, created = save_vulnerability(
                        target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=f'rdp://{ip.address}:{port.number}',
                        name='RDP does not require Network Level Authentication', severity=2, source='nmap',
                        template_id='rdp-enum-encryption', type='rdp',
                        description=('The Remote Desktop service accepts connections that skip Network Level Authentication, so the login '
                                     'screen and the pre-authentication protocol are exposed to anyone who can reach the port. Security '
                                     'layers accepted without CredSSP: ' + ', '.join(layers) + '.'),
                        remediation='Require Network Level Authentication, and keep RDP off the internet behind a VPN or gateway.',
                        extracted_results=[f'{name}: SUCCESS' for name in layers], tags=['rdp', 'misconfiguration'])
                    new += int(created)
                listing = anonymous_ftp(port) if port.number == 21 or (port.service_name or '') == 'ftp' else None
                if listing is None:
                    continue
                _vuln, created = save_vulnerability(
                    target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=f'ftp://{ip.address}:{port.number}',
                    name='Anonymous FTP login allowed', severity=2, source='nmap', template_id='ftp-anon', type='ftp',
                    description=('The FTP server accepts the anonymous account, so anyone on the internet can read what it serves '
                                 'and may be able to write to it. nmap signed in without credentials and listed the top level.'),
                    remediation='Disable anonymous access, or serve only files that are meant to be public from a read-only area.',
                    extracted_results=listing, tags=['ftp', 'misconfiguration'])
                new += int(created)
    return new


def run_nmap_stage(scan_id, **kwargs):
    """The nmap stage plus what its script output proves. Never lets the extras fail the stage."""
    from cveFeed import nmap_scan
    from startScan.models import ScanHistory
    result = nmap_scan.run_nmap_for_scan(scan_id, **kwargs)
    try:
        scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
        found = record_service_findings(scan)
        if found:
            result['service_findings'] = found
    except Exception:  # noqa: BLE001
        logger.exception('service findings failed for scan %s', scan_id)
    return result
