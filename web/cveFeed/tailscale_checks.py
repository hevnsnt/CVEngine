"""Tailscale-specific hygiene findings, decided from the tailnet's own data (the devices list, the policy file, what a scan found open
on a device's tailnet address). Pure functions over plain data, so every rule is unit tested; ``tailscale_sync`` stores the result as
HygieneFinding rows (check names start with ``ts_``) and resolves the ones that no longer apply.

Every rule states a fact the data proves and gives its severity with the reason. Nothing here guesses: a flag a source did not report
is unknown and produces no finding. Where a rule rests on a published claim rather than on Tailscale's own documentation, the finding
says so (the tailworm.com assessment of October 2026 is a single researcher's report; Tailscale acknowledged it and shipped fixes for several of its findings in 1.104.4 on 2026-10-28, with bulletins TS-2026-014 to -017).
"""
import ipaddress
import re
from datetime import datetime, timezone as dt_timezone

from cveFeed.hygiene import HIGH, INFO, LOW, MEDIUM, Finding
from cveFeed.tailscale_api import DEFAULT_ROUTES

PREFIX = 'ts_'
STALE_DAYS = 90
BROAD_PREFIX_V4 = 16  # an approved route this wide (or wider) bridges a whole network into the tailnet
EVIDENCE_RULES = 10  # rules quoted in one finding

REF_BULLETINS = 'https://tailscale.com/security-bulletins'
REF_TAILWORM = 'https://tailworm.com/'
REF_ACL = 'https://tailscale.com/docs/features/access-control/acls'
REF_SSH = 'https://tailscale.com/docs/features/tailscale-ssh'
UNIX_OS = ('linux', 'freebsd', 'openbsd', 'netbsd', 'solaris', 'illumos')

# Security bulletins at https://tailscale.com/security-bulletins whose affected clients and fixed release the bulletin states.
# (id, first fixed version, what applies, summary, cvENGINE rating). Tailscale publishes no severity; the rating is ours: root access
# that bypasses an ACL is HIGH, reaching host-scoped addresses or protected sockets MEDIUM, a leak or a trust-store refresh LOW.
# "what applies": None is every client; 'ssh' needs Tailscale SSH on the device; 'ssh_unix' also Linux or another Unix; '4via6'
# needs an approved 4via6 route. A bulletin whose condition the data does not show (Serve, Funnel, Services, the web interface, a
# macOS MDM policy) is left out, never assumed: TS-2026-016 and -017 (Tailscale Serve, also fixed in 1.104.4) are not listed for that reason.
BULLETINS = (
    ('TS-2026-004', (1, 98, 9), 'ssh_unix', 'Tailscale SSH socket forwarding followed symlinks to sockets outside its allowlist', MEDIUM),
    ('TS-2026-006', (1, 98, 9), 'ssh_unix', 'a numeric UID bypassed the root restriction of SSH rules that rely on autogroup:nonroot', HIGH),
    ('TS-2026-009', (1, 98, 9), 'ssh_unix', 'a user name starting with a dash gave a root session where ACLs forbade root', HIGH),
    ('TS-2026-010', (1, 102, 1), 'ssh', 'values an SSH acceptEnv rule forwards were visible on process command lines and in session logs', LOW),
    ('TS-2026-011', (1, 102, 3), '4via6', 'peers with access to a 4via6 subnet router could reach its loopback, link-local and metadata addresses', MEDIUM),
    ('TS-2026-013', (1, 104, 2), None, 'older builds trust eight compromised eMudhra intermediate certificates', LOW),
    ('TS-2026-014', (1, 104, 4), 'ssh_unix', 'Tailscale SSH forwarded Unix sockets as root, so an authorized peer could reach root-only sockets such as the Docker socket '
                                           'or the tailscaled local API', MEDIUM),
    ('TS-2026-015', (1, 104, 4), 'ssh', 'unbounded memory growth in Tailscale SSH session handling let an authenticated peer exhaust the memory of tailscaled', LOW),
)
# Ports whose service gives remote administration or a control API; (title, severity). Reachable on the tailnet address means every
# peer the policy lets in can try it.
ADMIN_PORTS = {
    23: ('Telnet', MEDIUM), 2375: ('Docker Engine API without TLS', MEDIUM), 5900: ('VNC', LOW), 3389: ('Remote Desktop', LOW),
    445: ('SMB file sharing', LOW),
}
SEVERITY_WORDS = {INFO: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high'}


def parse_version(text):
    """``(major, minor, patch)`` from a client version such as ``1.98.9`` or ``1.99.1-t1234abc``, or None."""
    match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,4})(?:[-+._].*)?$', text or '')
    return tuple(int(g) for g in match.groups()) if match else None


def _label(device):
    return device.get('name') or device.get('hostname') or device.get('node_id')


def _finding(check, severity, title, why, fix, evidence, reference):
    """``why`` is ``(what the data shows, why this severity)``; both land in the finding, and ``fix`` in the detail and the evidence."""
    evidence = {**evidence, 'severity_basis': why[1], 'remediation': fix, 'reference': reference}
    return Finding(PREFIX + check, severity, title, f'{why[0]} Fix: {fix}', '', evidence)


def _condition_holds(condition, device):
    if condition is None:
        return True
    if condition in ('ssh', 'ssh_unix'):
        return device.get('ssh') is True and (condition == 'ssh' or (device.get('os') or '').lower() in UNIX_OS)
    if condition == '4via6':
        return any(_in_4via6(route) for route in device.get('enabled_routes') or [])
    return False


def _in_4via6(route):
    try:
        return ipaddress.ip_network(route, strict=False).subnet_of(ipaddress.ip_network('fd7a:115c:a1e0:b1a::/64'))
    except (ValueError, TypeError):
        return False


def client_bulletins(device):
    """The bulletins that apply to this device's client version: ``[(id, fixed version tuple, summary, severity)]``."""
    version = parse_version(device.get('client_version'))
    if version is None:
        return []
    return [(bid, fixed, summary, sev) for bid, fixed, condition, summary, sev in BULLETINS
            if version < fixed and _condition_holds(condition, device)]


def _version_text(version):
    return '.'.join(str(n) for n in version)


def evaluate_device(device, host, now=None, ports=()):
    """The findings for one device record. ``host`` is the stored host name (its tailnet IPv4 address); ``ports`` the open ports a
    scan found on its tailnet address, as ``[{'number', 'service'}]``."""
    now = now or datetime.now(dt_timezone.utc)
    name = _label(device)
    out = []
    applicable = client_bulletins(device)
    if applicable:
        newest = max(fixed for _, fixed, _, _ in applicable)
        severity = max(sev for _, _, _, sev in applicable)
        out.append(_finding(
            'client_security_update', severity,
            f'{name}: Tailscale {device["client_version"]} is affected by {len(applicable)} security bulletin{"s" if len(applicable) != 1 else ""}',
            (f'The device runs Tailscale {device["client_version"]}; Tailscale fixed the following in {_version_text(newest)} or later: '
             + '; '.join(f'{bid} ({summary})' for bid, _, summary, _ in applicable) + '.',
             f'rated {SEVERITY_WORDS[severity]} by cvENGINE (Tailscale publishes no severity): the worst applicable bulletin sets it, and each '
             'one applies because the device\'s version is older than the fixed version and the feature it needs is present on the device'),
            f'upgrade Tailscale on {name} to {_version_text(newest)} or later.', {
                'device': name, 'client_version': device['client_version'], 'upgrade_to': _version_text(newest),
                'bulletins': [{'id': bid, 'fixed_in': _version_text(fixed), 'summary': summary} for bid, fixed, summary, _ in applicable]},
            REF_BULLETINS))
    if device.get('update_available') is True:
        out.append(_finding(
            'update_available', INFO, f'{name}: a Tailscale update is available',
            (f'Tailscale reports a newer client than {device.get("client_version") or "the one installed"} for this device.',
             'informational: the control plane flags an update, which is not by itself a vulnerability'),
            f'update Tailscale on {name}; enable auto-update in the admin console (Settings, Device management) to stop this recurring.',
            {'device': name, 'client_version': device.get('client_version', '')}, REF_BULLETINS))
    if device.get('key_expiry_disabled') is True and not device.get('tags') and not device.get('is_external'):
        out.append(_finding(
            'key_expiry_disabled', LOW, f'{name}: node key expiry is disabled on a user-owned device',
            ('The device belongs to a person, not a tag, and its node key never expires, so a lost, stolen or abandoned device keeps its '
             'tailnet access until someone deletes it in the admin console.',
             'low: it needs the device to be lost or compromised first, and the control plane can still remove it'),
            f'turn key expiry back on for {name} (admin console, Machines, the device menu, "Disable key expiry"); tagged servers '
            'are a separate decision.', {'device': name, 'user': device.get('user', '')}, REF_ACL))
    stale = _stale_days(device, now)
    if stale is not None and stale >= STALE_DAYS and device.get('online') is not True:
        out.append(_finding(
            'stale_device', LOW, f'{name}: not seen for {stale} days but still authorised',
            (f'The control plane last saw this device {stale} days ago and it is still part of the tailnet with a valid node key.',
             f'low: an unused device is attack surface nobody watches; the threshold is {STALE_DAYS} days'),
            f'remove {name} in the admin console if it is retired; deleting the device is what contains it, reimaging does not '
            '(tailworm.com mitigation).', {'device': name, 'last_seen': device.get('last_seen', ''), 'days': stale}, REF_TAILWORM))
    broad = _broad_routes(device.get('enabled_routes') or [])
    if broad:
        out.append(_finding(
            'broad_subnet_router', MEDIUM, f'{name}: approved subnet routes cover a very wide range ({", ".join(broad[:3])})',
            (f'{name} routes {", ".join(broad[:5])} into the tailnet, so every peer the policy lets reach it can reach that whole network '
             'through this one device.',
             f'medium: a route of /{BROAD_PREFIX_V4} or wider bridges a whole network; a compromised router device exposes all of it'),
            'approve only the narrowest ranges that are needed (admin console, the device\'s route settings) and limit who may use the '
            'router with a grant rather than allowing all traffic.', {'device': name, 'routes': broad[:20]}, REF_ACL))
    if device.get('exit_node') is True:
        out.append(_finding(
            'exit_node', INFO, f'{name}: approved as an exit node',
            ('The device is approved as an exit node, so peers allowed to use it send their internet traffic through it and it sees that traffic.',
             'informational: an intended configuration that is worth knowing about'),
            f'confirm {name} should be an exit node and that only the intended users or tags may use it.',
            {'device': name}, REF_ACL))
    risky = [(ADMIN_PORTS[p['number']], p) for p in ports if p.get('number') in ADMIN_PORTS]
    if risky:
        severity = max(sev for (_, sev), _ in risky)
        listed = ', '.join(f'{p["number"]} ({label})' for (label, _), p in risky)
        out.append(_finding(
            'remote_admin_exposed', severity, f'{name}: remote administration reachable on its tailnet address ({listed})',
            (f'A scan of {host} found {listed} open, so any peer the tailnet policy lets reach this device can try it.',
             f'rated {SEVERITY_WORDS[severity]}: the service is open on the tailnet address; whether it is authenticated was not tested'),
            'close the port or bind the service to localhost, and narrow the policy so only the people who administer this device can reach it.',
            {'device': name, 'ports': [{'port': p['number'], 'service': label} for (label, _), p in risky]}, REF_ACL))
    for finding in out:
        finding.host = host
    return out


def _stale_days(device, now):
    text = device.get('last_seen')
    if not text:
        return None
    try:
        seen = datetime.fromisoformat(text)
    except ValueError:
        return None
    return max(0, (now - seen).days)


def _broad_routes(routes):
    out = []
    for route in routes:
        if route in DEFAULT_ROUTES:
            continue
        try:
            net = ipaddress.ip_network(route, strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen <= BROAD_PREFIX_V4 and net.prefixlen > 0:
            out.append(str(net))
    return out


# --- the policy file ---------------------------------------------------------------------------------------------------------

def _strings(value):
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _quote(rule, keys):
    return {k: _strings(rule.get(k))[:10] for k in keys if k in rule}


def _wide_access(policy):
    """``(severity, rules)``: ACL rules and grants that let everyone, or every member, reach everything."""
    wide, severity = [], 0
    for index, rule in enumerate(policy.get('acls') if isinstance(policy.get('acls'), list) else []):
        if not isinstance(rule, dict) or rule.get('action') != 'accept':
            continue
        src, dst = _strings(rule.get('src')), _strings(rule.get('dst'))
        if '*:*' in dst and ('*' in src or 'autogroup:member' in src):
            severity = max(severity, HIGH if '*' in src else MEDIUM)
            wide.append({'kind': 'acl', 'index': index, **_quote(rule, ('src', 'dst'))})
    for index, rule in enumerate(policy.get('grants') if isinstance(policy.get('grants'), list) else []):
        if not isinstance(rule, dict):
            continue
        src, dst, ip = _strings(rule.get('src')), _strings(rule.get('dst')), _strings(rule.get('ip'))
        if '*' in dst and '*' in ip and ('*' in src or 'autogroup:member' in src):
            severity = max(severity, HIGH if '*' in src else MEDIUM)
            wide.append({'kind': 'grant', 'index': index, **_quote(rule, ('src', 'dst', 'ip'))})
    return severity, wide


def _ssh_broad(policy):
    out = []
    for index, rule in enumerate(policy.get('ssh') if isinstance(policy.get('ssh'), list) else []):
        if not isinstance(rule, dict) or rule.get('action') != 'accept':
            continue
        reasons = []
        if 'root' in _strings(rule.get('users')):
            reasons.append('allows login as root')
        if 'autogroup:member' in _strings(rule.get('src')):
            reasons.append('accepts every member of the tailnet')
        if reasons:
            out.append({'index': index, 'reasons': reasons, **_quote(rule, ('src', 'dst', 'users'))})
    return out


def _broad_tag_owners(policy):
    owners = policy.get('tagOwners') if isinstance(policy.get('tagOwners'), dict) else {}
    return sorted(tag for tag, who in owners.items() if isinstance(tag, str) and 'autogroup:member' in _strings(who))[:EVIDENCE_RULES * 5]


def _funnel_broad(policy):
    out = []
    for index, rule in enumerate(policy.get('nodeAttrs') if isinstance(policy.get('nodeAttrs'), list) else []):
        if not isinstance(rule, dict) or 'funnel' not in _strings(rule.get('attr')):
            continue
        if {'*', 'autogroup:member'} & set(_strings(rule.get('target'))):
            out.append({'index': index, **_quote(rule, ('target', 'attr'))})
    return out


def evaluate_policy(policy, host, tailnet=''):
    """The tailnet-wide findings of a policy file (as the API returns it in JSON). ``host`` names the tailnet on the findings."""
    if not isinstance(policy, dict):
        return []
    out = []
    severity, wide = _wide_access(policy)
    if wide:
        default = len(wide) == 1 and wide[0]['kind'] == 'acl' and wide[0].get('src') == ['*'] and wide[0].get('dst') == ['*:*']
        who = 'any device' if severity == HIGH else 'every member\'s device'
        out.append(_finding(
            'acl_allow_all', severity, f'The tailnet policy lets {who} reach every port of every device',
            (f'{len(wide)} rule{"s" if len(wide) != 1 else ""} in the policy accept traffic from {who} to all devices and ports'
             + (' (this is the policy Tailscale starts a new tailnet with)' if default else '') +
             ', so one compromised or careless device can reach every service on the tailnet, which is how a worm spreads. '
             'tailworm.com found per-pair grants the only control that stopped spread in its lab.',
             'high when the source is any device, medium when it is every member (tagged servers stay reachable)'),
            'replace the allow-all rule with grants that name the sources and destinations that need each other, and keep servers behind tags.',
            {'tailnet': tailnet, 'rules': wide[:EVIDENCE_RULES]}, REF_ACL))
    ssh = _ssh_broad(policy)
    if ssh:
        out.append(_finding(
            'ssh_accept_broad', MEDIUM, 'Tailscale SSH accept rules are broad or allow root',
            (f'{len(ssh)} Tailscale SSH rule{"s" if len(ssh) != 1 else ""} accept without a re-authentication check and either allow login as root or accept '
             'every member. The tailworm.com assessment (a single researcher\'s report that Tailscale has acknowledged) says an approved '
             'session could also forward unix sockets as root through tailscaled (fixed in Tailscale 1.104.4, TS-2026-014), and recommends per-pair SSH rules.',
             'medium: it widens who can open a root-capable session; the forwarding fix is in 1.104.4, the rule scope is yours to narrow'),
            'give each SSH rule a specific source and destination, avoid root and autogroup:member on accept rules, and use "check" for '
            'privileged destinations.', {'tailnet': tailnet, 'rules': ssh[:EVIDENCE_RULES]}, REF_SSH))
    tags = _broad_tag_owners(policy)
    if tags:
        out.append(_finding(
            'tag_owners_broad', MEDIUM, 'Any member can apply tags that carry policy privileges',
            (f'tagOwners lets autogroup:member own {len(tags)} tag{"s" if len(tags) != 1 else ""} ({", ".join(tags[:5])}), so any member can '
             'enrol a device with that tag and inherit every rule written for it.',
             'medium: a tag is an identity in the policy; letting every member mint one defeats rules that trust it'),
            'name the people or groups who run those machines as the tag owners instead of autogroup:member.',
            {'tailnet': tailnet, 'tags': tags}, REF_ACL))
    funnel = _funnel_broad(policy)
    if funnel:
        out.append(_finding(
            'funnel_broad', MEDIUM, 'Every member may publish services to the public internet with Funnel',
            ('A nodeAttrs entry grants the funnel attribute to everyone or to every member, so any member can expose a service on '
             'their device to the whole internet. tailworm.com notes Funnel entitlement is enforced only by the device\'s own capability and local config.',
             'medium: it lets one member put an internal service on the internet without review'),
            'grant funnel only to the specific users or tags that publish services.', {'tailnet': tailnet, 'rules': funnel[:EVIDENCE_RULES]}, REF_TAILWORM))
    for finding in out:
        finding.host = host
    return out
