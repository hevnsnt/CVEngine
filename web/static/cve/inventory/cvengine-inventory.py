#!/usr/bin/env python3
"""cvengine-inventory.py: tell cvENGINE what this machine is (Linux and macOS). Python 3.6 or newer, standard library only.

Collects the operating system and version, the kernel, installed packages and their versions, listening sockets, running services,
containers and a few security settings, and POSTs them as "inventory v1" JSON over HTTPS to cvENGINE. cvENGINE scans from outside and
cannot see any of this: with it, kernel and local-only CVEs become decidable and package versions stop being guesses.

Read-only: it runs only commands that list things (no shell, fixed argument lists) and never installs, changes or deletes anything.
It never reads or sends passwords, keys, tokens, shell history, environment variables or the contents of files other than the OS
metadata: /etc/os-release, /proc/stat (boot time), /etc/machine-id (only as a hash: sha256("cvengine-inventory-v1:" + id), because
systemd's machine-id(5) says the raw id is confidential), the modification time of the package database, one setting in
/etc/apt/apt.conf.d/20auto-upgrades and macOS application Info.plist version strings.

The bearer token is read from the CVENGINE_TOKEN environment variable or --token-file and is never a command-line argument: arguments
are visible to every user in `ps` and are saved in shell history, an environment variable or a root-only file are not.

Exit codes: 0 sent (or dry run), 1 bad usage or configuration, 2 nothing could be collected, 3 could not reach the server or its
certificate is not trusted, 4 the server refused the report (read its message), 5 the server kept failing.
"""
import argparse
import hashlib
import http.client
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone

SCRIPT_NAME = 'cvengine-inventory.py'
SCRIPT_VERSION = '1.0.0'
ROOT = os.environ.get('CVENGINE_ROOT', '')  # a test hook: a directory standing in for / when reading files
RPM_FORMAT = '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\n'
DPKG_FORMAT = '${Package}\t${Version}\t${Architecture}\t${source:Package}\t${db:Status-Abbrev}\n'
SRC_RPM = re.compile(r'-[^-]*-[^-]*\.src\.rpm$')


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def say(message):
    print(message, file=sys.stderr)


# --- running commands ---------------------------------------------------------------------------------------------------

def run(argv, timeout=60):
    """The standard output of a read-only command, '' when it is missing, fails or hangs. Never through a shell."""
    if shutil.which(argv[0]) is None:
        return ''
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                              stdin=subprocess.DEVNULL, universal_newlines=True, errors='replace')
    except (OSError, subprocess.SubprocessError):
        return ''
    return done.stdout if done.returncode == 0 else ''


def run_rc(argv, timeout=30):
    """The exit status of a command, None when it is missing or hangs."""
    if shutil.which(argv[0]) is None:
        return None
    try:
        return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=timeout).returncode
    except (OSError, subprocess.SubprocessError):
        return None


def read(path, limit=1 << 20):
    try:
        with open(ROOT + path, 'r', errors='replace') as handle:
            return handle.read(limit)
    except OSError:
        return ''


def mtime(path):
    try:
        return int(os.stat(ROOT + path).st_mtime)
    except OSError:
        return 0


def iso(epoch):
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if epoch else ''


def lines(text):
    return [line for line in text.splitlines() if line.strip()]


def unique(items):
    return list(dict.fromkeys(items))


# --- parsing what the commands print (pure functions: tested against fixtures) -------------------------------------------

def parse_os_release(text):
    """KEY=value lines as data. The file is shell syntax, but it is read, never sourced, so nothing in it can run."""
    out = {}
    for line in text.splitlines():
        match = re.match(r'^([A-Z][A-Z0-9_]*)=(.*)$', line.strip())
        if match:
            value = match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            out[match.group(1)] = value
    return out


def parse_dpkg(text):
    for line in lines(text):
        parts = line.split('\t')
        if len(parts) >= 5 and parts[4][1:2] == 'i':
            yield {'n': parts[0], 'v': parts[1], 'e': 'dpkg', 'a': parts[2], 's': parts[3]}


def parse_rpm(text):
    """``(packages, newest install time)``."""
    out, newest = [], 0
    for line in lines(text):
        parts = line.split('\t')
        if len(parts) < 6 or parts[0] == 'gpg-pubkey':
            continue
        name, epoch, version, arch, srpm, installed = parts[:6]
        if epoch not in ('(none)', '', '0'):
            version = '%s:%s' % (epoch, version)
        source = '' if srpm == '(none)' else SRC_RPM.sub('', srpm)
        out.append({'n': name, 'v': version, 'e': 'rpm', 'a': arch, 's': source})
        newest = max(newest, int(installed) if installed.isdigit() else 0)
    return out, newest


def parse_apk(text):
    """``apk list -I``: ``openssl-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]``."""
    for line in lines(text):
        match = re.match(r'^(.*)-([0-9][^-]*-r[0-9]+) (\S+) \{([^}]*)\}', line)
        if match:
            yield {'n': match.group(1), 'v': match.group(2), 'e': 'apk', 'a': match.group(3), 's': match.group(4)}


def parse_pairs(text, ecosystem, take_last=False):
    """``name version`` lines (pacman -Q, snap list without its header, brew list --versions)."""
    for line in lines(text):
        parts = line.split()
        if len(parts) >= 2:
            yield {'n': parts[0], 'v': parts[-1] if take_last else parts[1], 'e': ecosystem}


def parse_ss(text):
    """``ss -tulnp`` rows as ``(proto, local address:port, process)``."""
    for line in lines(text):
        cols = line.split()
        if len(cols) >= 5 and cols[0] in ('tcp', 'udp') and cols[1] in ('LISTEN', 'UNCONN'):
            proc = re.search(r'\(\("([^"]*)"', line)
            yield cols[0], cols[4], proc.group(1) if proc else ''


def parse_netstat(text):
    for line in lines(text):
        cols = line.split()
        if len(cols) >= 4 and re.match(r'^(tcp|udp)', cols[0]) and (cols[0].startswith('udp') or cols[-1] == 'LISTEN'):
            yield cols[0][:3], cols[3], ''


def parse_lsof(text):
    """``lsof -F cPn`` fields: a command (c), a protocol (P) and a name (n) per socket."""
    command = proto = ''
    for line in lines(text):
        if line[0] == 'c':
            command = line[1:]
        elif line[0] == 'P':
            proto = line[1:].lower()
        elif line[0] == 'n' and proto in ('tcp', 'udp'):
            yield proto, line[1:].split(' ')[0], command


def service(proto, local, proc):
    """One listening socket as the report's ``{p, a, n, x}``, or None for a row that is not one."""
    match = re.match(r'^(.*)[:.](\d+)$', local)
    if not match:
        return None
    addr = re.sub(r'%.*$', '', match.group(1).strip('[]'))
    out = {'p': proto, 'a': '*' if addr in ('', '0.0.0.0', '::', '*') else addr, 'n': int(match.group(2))}
    if proc:
        out['x'] = proc
    return out


# --- collecting ---------------------------------------------------------------------------------------------------------

def family():
    system = platform.system()
    if system == 'Linux':
        return 'linux'
    if system == 'Darwin':
        return 'macos'
    raise Failure(2, 'this script handles Linux and macOS (this is %s); use cvengine-inventory.ps1 on Windows' % system)


def addresses():
    found = []
    for line in lines(run(['ip', '-o', 'addr', 'show'])):
        cols = line.split()
        if len(cols) >= 4 and cols[2].startswith('inet'):
            found.append(cols[3].split('/')[0])
    if not found:
        found = run(['hostname', '-I']).split()
    if not found:
        found = [c.split()[1] for c in lines(run(['ifconfig', '-a'])) if re.match(r'^\s+inet6? ', c)]
    return unique(re.sub(r'%.*$', '', a) for a in found if not re.match(r'^(127\.|::1$|fe80:)', a))


def macs():
    out = []
    for line in lines(run(['ip', '-o', 'link', 'show'])):
        cols = line.split()
        if 'link/ether' in cols and cols.index('link/ether') + 1 < len(cols):
            out.append(cols[cols.index('link/ether') + 1])
    for line in lines(run(['ifconfig', '-a'])):
        cols = line.split()
        if len(cols) >= 2 and cols[0] == 'ether':
            out.append(cols[1])
    return unique(out)


def machine_id_hash(fam):
    raw = ''
    if fam == 'macos':
        found = re.search(r'"IOPlatformUUID" = "([^"]*)"', run(['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice']))
        raw = found.group(1) if found else ''
    else:
        for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
            raw = read(path, 256).strip()
            if raw:
                break
    return hashlib.sha256(('cvengine-inventory-v1:' + raw).encode()).hexdigest() if raw else ''


def macos_apps(folders=('/Applications', '/Applications/Utilities', '/System/Applications')):
    out = []
    for folder in folders:
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for name in names:
            if not name.endswith('.app'):
                continue
            try:
                with open(os.path.join(folder, name, 'Contents', 'Info.plist'), 'rb') as handle:
                    version = str(plistlib.load(handle).get('CFBundleShortVersionString') or '')
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if version:
                out.append({'n': name[:-4], 'v': version, 'e': 'macapp'})
    return out


def macos_pkgs():
    out = []
    for ident in lines(run(['pkgutil', '--pkgs'])):
        if ident.startswith('com.apple.'):
            continue
        found = re.search(r'^version: (.+)$', run(['pkgutil', '--pkg-info', ident]), re.M)
        if found:
            out.append({'n': ident, 'v': found.group(1), 'e': 'macpkg'})
    return out


def packages(fam):
    """``(packages, last package change time)``."""
    out, newest = list(parse_dpkg(run(['dpkg-query', '-W', '-f=' + DPKG_FORMAT]))), 0
    rpms, newest = parse_rpm(run(['rpm', '-qa', '--qf', RPM_FORMAT]))
    out += rpms
    out += parse_apk(run(['apk', 'list', '-I']))
    out += parse_pairs(run(['pacman', '-Q']), 'pacman')
    out += parse_pairs('\n'.join(run(['snap', 'list']).splitlines()[1:]), 'snap')
    for line in lines(run(['flatpak', 'list', '--columns=application,version,arch'])):
        cols = line.split('\t')
        if len(cols) >= 2 and '.' in cols[0] and cols[1]:
            out.append({'n': cols[0], 'v': cols[1], 'e': 'flatpak', 'a': cols[2] if len(cols) > 2 else ''})
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        out += parse_pairs(run(['brew', 'list', '--versions']), 'brew', take_last=True)
    if fam == 'macos':
        out += macos_apps() + macos_pkgs()
    for pkg in out:  # a package built from the source of the same name says nothing more with it
        if pkg.get('s') in ('', pkg['n']):
            pkg.pop('s', None)
        if not pkg.get('a'):
            pkg.pop('a', None)
    if not newest:
        for path in ('/var/lib/dpkg/status', '/lib/apk/db/installed', '/var/lib/pacman/local'):
            newest = mtime(path)
            if newest:
                break
    return out, newest


def os_block(fam, newest_package_time):
    block = {'family': fam, 'kernel': platform.release(), 'arch': platform.machine()}
    if fam == 'macos':
        name = run(['sw_vers', '-productName']).strip()
        version = run(['sw_vers', '-productVersion']).strip()
        boot = re.search(r'sec = (\d+)', run(['sysctl', '-n', 'kern.boottime']))
        block.update({'id': 'macos', 'name': name, 'version': version, 'build': run(['sw_vers', '-buildVersion']).strip(),
                      'pretty': ('%s %s' % (name, version)).strip(), 'last_boot': iso(boot.group(1)) if boot else ''})
    else:
        release = parse_os_release(read('/etc/os-release') or read('/usr/lib/os-release'))
        boot = re.search(r'^btime (\d+)', read('/proc/stat'), re.M)
        block.update({'id': release.get('ID', '').lower(), 'name': release.get('NAME') or 'Linux', 'version': release.get('VERSION_ID', ''),
                      'codename': release.get('VERSION_CODENAME', ''), 'pretty': release.get('PRETTY_NAME', ''),
                      'cpe': release.get('CPE_NAME', ''), 'last_boot': iso(boot.group(1)) if boot else '',
                      'last_update': iso(newest_package_time)})
        if release.get('ID_LIKE'):
            block['id_like'] = release['ID_LIKE'].lower().split()
    return {k: v for k, v in block.items() if v}


def listening(fam):
    if fam == 'macos':
        rows = parse_lsof(run(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-iUDP', '-F', 'cPn']))
    elif shutil.which('ss'):
        rows = parse_ss(run(['ss', '-tulnp']))
    else:
        rows = parse_netstat(run(['netstat', '-tuln']))
    return [s for s in (service(*row) for row in rows) if s]


def runtime(fam):
    reboot = None
    if os.path.exists(ROOT + '/var/run/reboot-required') or os.path.exists(ROOT + '/run/reboot-required'):
        reboot = True
    elif shutil.which('dpkg-query'):
        reboot = False
    else:
        code = run_rc(['needs-restarting', '-r'])
        reboot = {0: False, 1: True}.get(code)
    kernels = []
    for line in lines(run(['dpkg-query', '-W', '-f=${Package}\t${db:Status-Abbrev}\n', 'linux-image-[0-9]*'])):
        name, _, state = line.partition('\t')
        if state[1:2] == 'i':  # "ii" installed, "hi" installed and held: a held package is often the stale one
            kernels.append(re.sub(r'^linux-image-', '', name))
    if not kernels:
        kernels = [k for k in lines(run(['rpm', '-q', 'kernel-core', 'kernel', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}\n'])) if 'not installed' not in k]
    containers = []
    for rt in ('docker', 'podman'):
        for image in unique(lines(run([rt, 'ps', '--format', '{{.Image}}'], timeout=10))):
            containers.append({'rt': rt, 'image': image})
    units = []
    if os.path.isdir(ROOT + '/run/systemd/system'):
        units = [line.split()[0] for line in lines(run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain', '--no-pager']))]
    return {'reboot_required': reboot, 'kernels_installed': kernels, 'containers': containers, 'units': units}


def security(fam):
    out = {}

    def add(key, value):
        if value:
            out[key] = value

    def first(pattern, text):
        found = re.search(pattern, text, re.M)
        return found.group(1) if found else ''

    if fam == 'macos':
        add('firewall', first(r'is (enabled|disabled)', run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])))
        add('sip', first(r'status: (enabled|disabled)', run(['csrutil', 'status'])))
        add('gatekeeper', first(r'^assessments (enabled|disabled)$', run(['spctl', '--status'])))
        vault = first(r'^FileVault is (On|Off)', run(['fdesetup', 'status']))
        add('disk_encryption', 'FileVault ' + vault if vault else '')
        return out
    for unit in ('firewalld', 'ufw', 'nftables'):
        if run(['systemctl', 'is-active', unit]).strip() == 'active':
            add('firewall', unit + ' active')
            break
    if shutil.which('getenforce'):
        add('selinux', run(['getenforce']).strip().lower())
    elif read('/sys/fs/selinux/enforce'):
        add('selinux', 'enforcing' if read('/sys/fs/selinux/enforce').strip() == '1' else 'permissive')
    if read('/sys/module/apparmor/parameters/enabled'):
        add('apparmor', 'enabled' if read('/sys/module/apparmor/parameters/enabled').strip() == 'Y' else 'disabled')
    auto = read('/etc/apt/apt.conf.d/20auto-upgrades')
    if auto:
        add('auto_updates', 'unattended-upgrades ' + ('enabled' if re.search(r'^APT::Periodic::Unattended-Upgrade "1"', auto, re.M) else 'off'))
    elif run_rc(['systemctl', 'is-enabled', 'dnf-automatic.timer', 'dnf-automatic-install.timer']) == 0:
        add('auto_updates', 'dnf-automatic enabled')
    if 'crypt' in run(['lsblk', '-rno', 'TYPE']).split():
        add('disk_encryption', 'LUKS volume present')
    add('secure_boot', first(r'^SecureBoot (enabled|disabled)', run(['mokutil', '--sb-state'])))
    return out


def build_report(with_macs=False):
    fam = family()
    pkgs, newest = packages(fam)
    hostname = socket.gethostname().split('.')[0]
    fqdn = run(['hostname', '-f'], timeout=5).strip()  # asks the resolver, which can be slow on a machine with no DNS: not for more than a few seconds
    host = {'hostname': hostname, 'fqdn': fqdn if '.' in fqdn else '', 'machine_id': machine_id_hash(fam), 'ips': addresses()}
    if with_macs:
        host['macs'] = macs()
    if not (hostname or host['fqdn']):
        raise Failure(2, "cannot tell this machine's host name")
    return {'schema': 'cvengine-inventory/1', 'script': {'name': SCRIPT_NAME, 'version': SCRIPT_VERSION},
            'collected_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'host': {k: v for k, v in host.items() if v or k == 'ips'}, 'os': os_block(fam, newest), 'packages': pkgs, 'patches': [],
            'services': listening(fam), 'runtime': runtime(fam), 'security': security(fam)}


# --- configuration and sending ------------------------------------------------------------------------------------------

SCHEDULE = """# Nothing has been installed. Copy what you want.
# 1. Store the token where only root can read it:
#      install -m 600 /dev/null /etc/cvengine-inventory.token   # then put the token in it
#      install -m 755 {name} /usr/local/bin/{name}
#
# 2a. cron, daily (/etc/cron.d/cvengine-inventory):
{minute} 3 * * * root /usr/local/bin/{name} --server {url} --project {project} --token-file /etc/cvengine-inventory.token

# 2b. or a systemd timer. /etc/systemd/system/cvengine-inventory.service:
[Unit]
Description=Report this host's inventory to cvENGINE
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/{name} --server {url} --project {project} --token-file /etc/cvengine-inventory.token
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

# /etc/systemd/system/cvengine-inventory.timer, then: systemctl enable --now cvengine-inventory.timer
[Unit]
Description=Daily cvENGINE inventory report
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
"""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure(1, message)


def parse_args(argv):
    parser = Parser(prog=SCRIPT_NAME, description='Report this host\'s inventory to cvENGINE (read-only).')
    parser.add_argument('--server', default=os.environ.get('CVENGINE_URL', ''), help='cvENGINE address, https only (or CVENGINE_URL)')
    parser.add_argument('--project', default=os.environ.get('CVENGINE_PROJECT', ''), help='project slug (or CVENGINE_PROJECT)')
    parser.add_argument('--token-file', default=os.environ.get('CVENGINE_TOKEN_FILE', ''), help='file holding the token (or CVENGINE_TOKEN_FILE); otherwise the CVENGINE_TOKEN environment variable')
    parser.add_argument('--ca-file', default='', help="PEM file of the certificate authority that signed the server (the installer's secrets/certs/ca.crt)")
    parser.add_argument('--insecure', action='store_true', help="DO NOT VERIFY THE SERVER'S CERTIFICATE. Anyone on the path can read the token and the report. Testing only.")
    parser.add_argument('--dry-run', action='store_true', help='print the report that would be sent and send nothing; needs no token')
    parser.add_argument('--macs', action='store_true', help='include network interface MAC addresses (off by default)')
    parser.add_argument('--timeout', type=int, default=30, help='seconds per request (1 to 300), default 30')
    parser.add_argument('--retries', type=int, default=3, help='attempts after the first when the network or server fails (0 to 10), default 3')
    parser.add_argument('--install-cron', action='store_true', help='print (do not apply) a cron line and a systemd timer, then exit')
    parser.add_argument('--version', action='store_true')
    parser.add_argument('--token', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.token is not None:
        raise Failure(1, 'the token is never a command-line argument (it would show in ps and shell history): use CVENGINE_TOKEN or --token-file')
    if not 1 <= args.timeout <= 300 or not 0 <= args.retries <= 10:
        raise Failure(1, '--timeout must be 1 to 300 and --retries 0 to 10')
    return args


def check_server(server):
    """The parts of an https address, or a Failure. Nothing but a plain host (and port and path) is accepted."""
    if not server:
        raise Failure(1, '--server is required (or set CVENGINE_URL)')
    parts = urllib.parse.urlsplit(server)
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.query or parts.fragment
            or not re.fullmatch(r'https://[A-Za-z0-9._:\[\]-]+(/[A-Za-z0-9._~/-]*)?', server)):
        raise Failure(1, '--server must be a plain https:// address: the token never travels in the clear')
    return parts


def check_project(project):
    if not re.fullmatch(r'[-A-Za-z0-9_]+', project):
        raise Failure(1, '--project (the project slug) is required and is letters, digits, - and _')


def check_destination(args):
    """The validated ``(host, port, path, token)``: an https address, a project slug and a token, or a Failure."""
    parts = check_server(args.server)
    check_project(args.project)
    token = os.environ.get('CVENGINE_TOKEN', '')
    if args.token_file:
        try:
            if os.stat(args.token_file).st_mode & 0o077:
                say('cvengine-inventory: warning: %s is readable by other users: chmod 600 it' % args.token_file)
            with open(args.token_file, 'r') as handle:
                token = handle.readline().strip()
        except OSError as exc:
            raise Failure(1, 'cannot read the token file: %s' % exc.strerror)
    if not re.fullmatch(r'cve_[A-Za-z0-9_-]{20,200}', token):
        raise Failure(1, 'no usable token: set CVENGINE_TOKEN or --token-file (a cvENGINE inventory token, cve_...)')
    if args.ca_file and not os.access(args.ca_file, os.R_OK):
        raise Failure(1, 'cannot read --ca-file %s' % args.ca_file)
    path = parts.path.rstrip('/') + '/api/v1/projects/%s/inventory' % args.project
    return parts.hostname, parts.port or 443, path, token


def tls_context(args):
    context = ssl.create_default_context(cafile=args.ca_file or None)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def post(args, host, port, path, token, body):
    """One POST. Returns ``(status, text)``; raises OSError for a network problem and ssl.SSLError for an untrusted certificate. Redirects
    are never followed, so the token only ever goes to the address given."""
    conn = http.client.HTTPSConnection(host, port, timeout=args.timeout, context=tls_context(args))
    try:
        conn.request('POST', path, body=body, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                                                        'User-Agent': '%s/%s' % (SCRIPT_NAME, SCRIPT_VERSION)})
        response = conn.getresponse()
        return response.status, response.read(4096).decode('utf-8', 'replace')
    finally:
        conn.close()


def send(args, body, sleep=time.sleep):
    host, port, path, token = check_destination(args)
    attempt = 0
    while True:
        try:
            status, text = post(args, host, port, path, token, body)
            if 200 <= status < 300:
                say('cvengine-inventory: sent: ' + text.replace('\n', ' ')[:300])
                return 0
            if status not in (408, 429) and status < 500:
                say('cvengine-inventory: the server refused the report (%d): %s' % (status, text.replace('\n', ' ')[:300]))
                return 4
            why, code = 'the server answered %d' % status, 5
        except ssl.SSLError as exc:
            say("cvengine-inventory: the server's certificate is not trusted (%s). For a private certificate authority pass --ca-file "
                "(the installer's secrets/certs/ca.crt)." % (exc.reason or exc))
            return 3
        except (OSError, http.client.HTTPException) as exc:
            why, code = 'could not reach the server: %s' % exc, 3
        attempt += 1
        if attempt > args.retries:
            say('cvengine-inventory: giving up after %d attempts: %s' % (attempt, why))
            return code
        delay = 2 ** attempt + int(time.time()) % 4  # growing, with a little spread so a fleet that failed together does not retry together
        say('cvengine-inventory: %s; retrying in %ds (%d of %d)' % (why, delay, attempt, args.retries))
        sleep(delay)


def main(argv=None):
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        if args.version:
            print('%s %s' % (SCRIPT_NAME, SCRIPT_VERSION))
            return 0
        if args.install_cron:
            if args.server:  # these go into text a person pastes into a root crontab: check them first
                check_server(args.server)
            if args.project:
                check_project(args.project)
            minute = int(hashlib.sha256(socket.gethostname().encode()).hexdigest(), 16) % 60  # spreads a fleet over the hour
            print(SCHEDULE.format(name='cvengine-inventory.py', url=args.server or 'https://cvengine.example.test',
                                  project=args.project or 'my-project', minute=minute), end='')
            return 0
        if not args.dry_run:
            check_destination(args)
            if args.insecure:
                say("cvengine-inventory: *** --insecure: the server's certificate is NOT being checked. Anyone on the network path can read "
                    'the token and this report. ***')
        report = build_report(args.macs)
        body = json.dumps(report, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        say('cvengine-inventory: collected %d package entries (%d bytes) on %s' % (len(report['packages']), len(body), report['host'].get('hostname', '?')))
        if args.dry_run:
            print(body.decode('utf-8'))
            say('cvengine-inventory: dry run: nothing was sent. It would POST to %s/api/v1/projects/%s/inventory' % (args.server or '<--server>', args.project or '<--project>'))
            return 0
        return send(args, body)
    except Failure as exc:
        say('cvengine-inventory: %s' % exc)
        return exc.code


if __name__ == '__main__':
    sys.exit(main())
