"""What one CVE match means, in plain words, and how the host's owner settles it without asking anyone.

The per-match guide (cveFeed.confirm_guide) says how to check a match from outside and where to look; this is the short answer on top of it,
for the person who reads a match without access to the host and has to hand it to the person who has: what cvENGINE found (from the match's
own product, version, source and affected range), why it shows the match and how sure it is (from the evidence class: a version alone, an
OpenVAS result and its quality of detection, a template that fired, the distribution's tracker, a behaviour check), the commands that settle it
on the host with what each answer means, and the closure note each outcome leaves. ``explain(match)`` is the object the match page, the REST
and MCP match payloads carry; ``validate_plan(matches)`` groups a host's open matches by the package that decides them ("Is the installed httpd
package patched?") and orders the groups exploited first, then by heat.

Distribution backports. Red Hat, Debian and Ubuntu fix a CVE in their own build without changing the upstream version a banner states, so an
upstream version comparison is not a verdict there. On a Red Hat family host the package changelog is: ``rpm -q --changelog httpd`` names every
CVE Red Hat fixed in that build. Debian and Ubuntu keep the same list in the package's changelog.Debian.gz.

Safety. A command is built only from constants, an allow-listed package name (cveFeed.distro's mapping of a known product) and a validated
CVE id, never from text a scanned host or a feed supplied: a banner, a header, a technology name or an OpenVAS result only chooses among
those constants (which distribution family, which product). Every command only reads. The prose names the match's product, version and host
after validating or cleaning them; the page draws it as text.

The Red Hat data a later change adds to a match (a distribution state that says Red Hat fixed the CVE in a backport, the fixed package build
and the RHSA advisory) is read when present and never required: see ``_red_hat_fix`` for the fields read."""
import re
import shlex

from cveFeed import confirm_guide, distro

EXPLAIN_VERSION = 1

CONFIRMED, LIKELY, NOT_CONFIRMED, RULED_OUT = 'confirmed', 'likely', 'not_confirmed', 'ruled_out'
CONFIDENCE_WORDS = {CONFIRMED: 'Confirmed', LIKELY: 'Likely', NOT_CONFIRMED: 'Not confirmed', RULED_OUT: 'Ruled out'}

# The distribution families a host can be read as, with what their package tools and trackers are. The scanned text only picks a key.
FAMILIES = {
    'rhel': {'label': 'Red Hat', 'long': 'Red Hat Enterprise Linux or a rebuild of it (CentOS, Rocky Linux, AlmaLinux)', 'packager': 'rpm',
             'tracker': 'https://access.redhat.com/security/cve/{cve}'},
    'debian': {'label': 'Debian', 'long': 'Debian', 'packager': 'dpkg', 'tracker': 'https://security-tracker.debian.org/tracker/{cve}'},
    'ubuntu': {'label': 'Ubuntu', 'long': 'Ubuntu', 'packager': 'dpkg', 'tracker': 'https://ubuntu.com/security/{cve}'},
    'alpine': {'label': 'Alpine', 'long': 'Alpine Linux', 'packager': 'apk', 'tracker': 'https://security.alpinelinux.org/vuln/{cve}'},
}
_FAMILY_TEXT = (
    ('rhel', re.compile(r'red ?hat|\brhel\b|centos|rocky|almalinux|\balma ?linux|\.el[5-9](?:_\d+)?\b|enterprise_linux', re.I)),
    ('ubuntu', re.compile(r'ubuntu', re.I)),
    ('debian', re.compile(r'debian|deb\d+u\d+', re.I)),
    ('alpine', re.compile(r'\balpine\b', re.I)),
)

# How a scanner or the advisory names a product, as the key cveFeed.distro.PACKAGES knows it, and the name a person reads.
_PRODUCT_KEYS = {
    'apache': 'apachehttpd', 'httpd': 'apachehttpd', 'apache2': 'apachehttpd', 'apachehttpd': 'apachehttpd', 'apachehttpserver': 'apachehttpd',
    'httpserver': 'apachehttpd', 'openssh': 'openssh', 'opensshd': 'openssh', 'nginx': 'nginx', 'nginxopensource': 'nginx', 'openssl': 'openssl',
    'php': 'php', 'phpfpm': 'php', 'mysql': 'mysql', 'mysqlserver': 'mysql', 'mariadb': 'mariadb', 'postgresql': 'postgresql',
    'eximsmtpd': 'exim', 'exim': 'exim', 'proftpd': 'proftpd', 'iscbind': 'bind', 'bind': 'bind', 'dovecot': 'dovecot',
    'dovecotimapd': 'dovecot', 'dovecotpop3d': 'dovecot', 'vsftpd': 'vsftpd',
}
_LABELS = {'apachehttpd': 'Apache httpd', 'openssh': 'OpenSSH', 'nginx': 'nginx', 'openssl': 'OpenSSL', 'php': 'PHP', 'mysql': 'MySQL',
           'mariadb': 'MariaDB', 'postgresql': 'PostgreSQL', 'exim': 'Exim', 'proftpd': 'ProFTPD', 'bind': 'BIND', 'dovecot': 'Dovecot',
           'vsftpd': 'vsftpd'}
# the product an OpenVAS result identified, by its CPE vendor and product
_CPE_KEYS = {('apache', 'http_server'): 'apachehttpd', ('openbsd', 'openssh'): 'openssh', ('openssl', 'openssl'): 'openssl', ('php', 'php'): 'php',
             ('nginx', 'nginx'): 'nginx', ('f5', 'nginx'): 'nginx', ('mysql', 'mysql'): 'mysql', ('oracle', 'mysql'): 'mysql',
             ('mariadb', 'mariadb'): 'mariadb', ('postgresql', 'postgresql'): 'postgresql', ('exim', 'exim'): 'exim',
             ('proftpd', 'proftpd'): 'proftpd', ('isc', 'bind'): 'bind', ('dovecot', 'dovecot'): 'dovecot', ('beasts', 'vsftpd'): 'vsftpd'}
_CPE = re.compile(r'^cpe:(?:/a|2\.3:a):([a-z0-9_.\-]{1,60}):([a-z0-9_.\-]{1,60})', re.I)

# The binary package that carries a source package's changelog and build, where the two names differ. The changelog and build of every binary
# built from one source are the same, so any one that is always installed with the product will do.
_RPM_BINARY = {'openssh': 'openssh-server', 'php': 'php-common', 'mysql': 'mysql-server', 'mariadb': 'mariadb-server',
               'postgresql': 'postgresql-server'}
_DEB_BINARY = {'openssh': 'openssh-server', 'exim4': 'exim4-base', 'proftpd-dfsg': 'proftpd-core', 'dovecot': 'dovecot-core', 'mariadb': 'mariadb-server'}
_DEB_PATTERNS = ((re.compile(r'^(php\d+\.\d+)\Z'), r'\1-common'), (re.compile(r'^mysql-(\d+\.\d+)\Z'), r'mysql-server-\1'),
                 (re.compile(r'^mariadb-(\d+\.\d+)\Z'), r'mariadb-server-\1'))
_PACKAGE = re.compile(r'^[a-z0-9][a-z0-9.+-]{0,63}\Z')

# What a later change records about Red Hat's own fix. A distribution state other than these four is read as "the distribution says it is
# fixed in a build: confirm the installed build" when it names a fixed build, else as unknown.
_KNOWN_STATES = (distro.PATCHED, distro.VULNERABLE, distro.UNKNOWN, distro.NO_DATA, '')
_ADVISORY = re.compile(r'^RH[SBE]A-\d{4}:\d{3,7}\Z')
_BUILD = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+~^:-]{0,127}\Z')
_PORT = re.compile(r'^(\d{1,5})/(tcp|udp)\Z')

SHELL = 'A shell on the host (no administrator rights needed)'
DNF_NEEDS = 'A shell on the host. It reads the repository metadata (it may refresh the metadata cache) and installs nothing'
NOTE_MAX = 2000


# --- what the match is about ------------------------------------------------------------------------------------------------------------

def _norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value or '').lower())


def _ev(match):
    return match.evidence if isinstance(match.evidence, dict) else {}


def _cve_id(match):
    value = str(getattr(match.cve_entry, 'cve_id', '') or '').upper()
    return value if confirm_guide._CVE.match(value) else ''


def _product_key(match):
    """The known product (a key of cveFeed.distro.PACKAGES) the match is about, or ''."""
    ev = _ev(match)
    if match.source == 'openvas':
        found = _CPE.match(str(ev.get('cpe') or ''))
        if found:
            key = _CPE_KEYS.get((found.group(1).lower(), found.group(2).lower()))
            if key:
                return key
        return _PRODUCT_KEYS.get(_norm(ev.get('product')), '')
    return _PRODUCT_KEYS.get(_norm(match.matched_product), '')


def _plain(text, limit=80):
    """A product name from a scanner or a feed, reduced to the characters a product name uses (shown as text, never run)."""
    from reNgine.ai_providers import clean_text
    return clean_text(str(text or ''), limit, strict=True)


def _label(match, key):
    if key:
        return _LABELS[key]
    ev = _ev(match)
    if match.source == 'openvas':
        return _plain(ev.get('product')) or 'the product the advisory names'
    from cveFeed.detection import _libraries, library_key
    lib = library_key(match.matched_product) if match.source == 'tech' else ''
    if lib:
        return _libraries()[lib][0]
    return _plain(match.matched_product) or 'the product'


def _version(match):
    ev = _ev(match)
    if match.source == 'openvas':
        return confirm_guide._version(ev.get('installed_version'))
    return confirm_guide._version(match.matched_version)


def family_of(text):
    """The distribution family ``text`` (a banner, a header, a technology list) names, or '' when it names none or more than one."""
    found = {key for key, pattern in _FAMILY_TEXT if pattern.search(str(text or ''))}
    if 'ubuntu' in found:
        found.discard('debian')  # an Ubuntu banner often says Debian too ("Debian-based"); Ubuntu is the more precise of the two
    return found.pop() if len(found) == 1 else ''


def host_hint(sub):
    """What the host's other records say about its distribution, as one text to read a family from: its Server header, its technologies,
    each address's OS guess and each port's product, version, distribution and CPE. Uses what a prefetch loaded (or a few queries)."""
    if sub is None:
        return ''
    parts = [str(getattr(sub, 'webserver', '') or '')]
    try:
        parts += [str(t.name or '') for t in sub.technologies.all()]
        for ip in sub.ip_addresses.all():
            parts.append(str(ip.os_guess or ''))
            for p in ip.ports.all():
                parts += [str(p.distro or ''), str(p.product or ''), str(p.version or ''), str(p.service_extra or ''), str(p.cpe or '')]
    except Exception:  # noqa: BLE001 - a hint only: a host whose records cannot be read is explained without it
        pass
    return ' '.join(x for x in parts if x)


def _family(match, hint=''):
    """The distribution family of the match's host: the distribution its own evidence read, else its banner and CPE, else the Server header,
    else the rest of the host (``hint``). Each only picks a key of FAMILIES."""
    ev = _ev(match)
    recorded = ev.get('distro') if isinstance(ev.get('distro'), dict) else {}
    name = str(recorded.get('distro') or '').lower()
    if name in ('rhel', 'centos'):
        return 'rhel'
    if name in FAMILIES:
        return name
    own = ' '.join(str(ev.get(k) or '') for k in ('raw_version', 'service_extra', 'cpe')) + ' ' + str(match.matched_version or '')
    sub = match.subdomain
    for text in (own, str(getattr(sub, 'webserver', '') or ''), hint):
        family = family_of(text)
        if family:
            return family
    return ''


def _subject(match, hint=''):
    """``(family, key, package, binary)``: the host's distribution family ('' when unknown), the known product, the distribution's source package
    for it (cveFeed.distro.package_for, allow-listed) and the binary package the commands ask about. ``package`` is '' when the product is not
    one cveFeed.distro maps."""
    family = _family(match, hint)
    key = _product_key(match)
    if not key:
        return family, '', '', ''
    # a host whose family is not known is asked as a Red Hat one first (the rpm names), with the Debian names beside them (package_steps)
    package, binary = _packages(key, family or 'rhel', _version(match))
    return (family, key, package, binary) if package else (family, key, '', '')


def _packages(key, family, upstream=''):
    """``(source package, binary package)`` of a known product on ``family``, both allow-listed, or ('', '')."""
    package = distro.package_for(key, family, upstream)
    if not package or not _PACKAGE.match(package) or not distro.is_known_package(package):
        return '', ''
    if family == 'rhel':
        binary = _RPM_BINARY.get(package, package)
    elif family in ('debian', 'ubuntu'):
        binary = _DEB_BINARY.get(package, package)
        for pattern, repl in _DEB_PATTERNS:
            if pattern.match(package):
                binary = pattern.sub(repl, package)
    else:
        binary = package
    return (package, binary) if _PACKAGE.match(binary) else ('', '')


def _red_hat_fix(match):
    """``{'advisory', 'url', 'fixed_build'}`` of Red Hat's own fix when the match records one, else {}. Read from the match's
    ``evidence['distro_fix']`` (the Red Hat row that judged it), the match's ``distro_fixed_version`` and, when present, the evidence's
    ``advisory`` / ``rhsa`` and ``fixed_nvr`` / ``fixed_build`` (top level or under ``evidence['distro']``): every one optional, each
    validated before it is shown."""
    ev = _ev(match)
    recorded = ev.get('distro') if isinstance(ev.get('distro'), dict) else {}
    # cveFeed.correlation.distro_fix_evidence: the Red Hat row that judged the match (its fixed build is "name-version-release", or
    # "name version" when the fixed version has no epoch, which reads the same with a hyphen)
    red_hat = ev.get('distro_fix') if isinstance(ev.get('distro_fix'), dict) and ev['distro_fix'].get('source') == 'redhat' else {}
    if red_hat.get('fixed_build'):
        red_hat = {**red_hat, 'fixed_build': str(red_hat['fixed_build']).strip().replace(' ', '-', 1)}
    out = {}
    for source in (red_hat, recorded, ev):
        for key in ('advisory', 'rhsa', 'errata'):
            value = str(source.get(key) or '').strip().upper()
            if value and _ADVISORY.match(value) and 'advisory' not in out:
                out['advisory'] = value
                out['url'] = f'https://access.redhat.com/errata/{value}'
        for key in ('fixed_nvr', 'fixed_build', 'fixed_package'):
            value = str(source.get(key) or '').strip()
            if value and _BUILD.match(value) and 'fixed_build' not in out:
                out['fixed_build'] = value
    fixed = str(match.distro_fixed_version or '').strip()
    if 'fixed_build' not in out and fixed and fixed != '0' and _BUILD.match(fixed):
        out['fixed_build'] = fixed
    return out


def _backport_state(match):
    """Whether the match's distribution state is "fixed in a backport, confirm the installed build" (cveFeed.distro.BACKPORT), or any other
    state this module does not know that comes with a fixed build or an advisory."""
    state = str(match.distro_status or '')
    return state == distro.BACKPORT or (state not in _KNOWN_STATES and bool(_red_hat_fix(match)))


# --- why it is shown, and how sure cvENGINE is --------------------------------------------------------------------------------------------

def _validation_status(match):
    from cveFeed.match_policy import _validation_status
    return _validation_status(match)


def _qod(ev):
    qod = ev.get('qod')
    return qod if isinstance(qod, (int, float)) and not isinstance(qod, bool) else None


def _where_version(match, key):
    """Where the version came from, in a few words: "the version in the Server header", "the service banner on port 22/tcp", ..."""
    ev = _ev(match)
    if match.source == 'port':
        port = confirm_guide._port(ev.get('port'))
        proto = 'udp' if str(ev.get('protocol') or '').lower() == 'udp' else 'tcp'
        return f'the version in the service banner on port {port}/{proto}' if port else 'the version in a service banner'
    if match.source == 'tech':
        header = str(getattr(match.subdomain, 'webserver', '') or '').lower()
        token = {'apachehttpd': 'apache', 'nginx': 'nginx', 'php': 'php', 'openssl': 'openssl'}.get(key, '')
        version = _version(match)
        if token and version and token in header and version in header:
            return 'the version in the Server header'
        if ev.get('version_source') == 'body':
            return 'the version the library file states'
        return 'the version the technology fingerprint read'
    if match.source == 'wp-plugin':
        return 'the version the plugin\'s readme states'
    if match.source == 'host':
        return 'the version in the host\'s own inventory report'
    return 'the version cvENGINE read'


def _backport_words(family, key):
    if family == 'rhel':
        return 'Red Hat often fixes bugs without changing that version, so this may not be a real problem.'
    if family in ('debian', 'ubuntu'):
        return f'{FAMILIES[family]["label"]} often fixes bugs without changing that version, so this may not be a real problem.'
    if key:
        return 'Linux distributions often fix bugs without changing that version, so this may not be a real problem.'
    return ''


# --- a CVE in the Java runtime (cveFeed.java_runtime) ---------------------------------------------------------------------------------

# The commands that read which Java a process runs, on the host itself. Constants only: <PID> is the reader's to fill in from the first step.
JAVA_QUESTION = {'key': 'java:runtime', 'text': 'Which Java runtime does this host run?'}
JAVA_STEPS = (
    ('Find the Java process (the application server, Jenkins, Confluence ...) and note its PID.', 'pgrep -a java',
     {'fixed': '', 'affected': '', 'cant_tell': 'No java process: the application runs in a container. Run the same steps inside it '
                                                '(docker exec <CONTAINER> ...), or read the image\'s Java version.'}),
    ('Ask the running JVM its version (jcmd ships with the JDK; run it as the user the process runs as).', 'jcmd <PID> VM.version',
     {'fixed': 'The JDK version it prints is outside the affected range (or the vendor\'s build names this CVE as fixed): not affected.',
      'affected': 'The version is inside the affected range: affected. Update the JDK or JRE this application runs on, then restart it.',
      'cant_tell': 'jcmd is not installed (a JRE has none): use the next step.'}),
    ('Find the java binary the process runs, and ask it its version.', 'readlink -f /proc/<PID>/exe && "$(readlink -f /proc/<PID>/exe)" -version',
     {'fixed': 'The version printed is outside the affected range: not affected.', 'affected': 'The version printed is inside the affected range: affected.',
      'cant_tell': 'Permission denied: run it as the process owner or root.'}),
    ('Read the release file of that JDK or JRE (its version and vendor).', 'cat "$(dirname "$(dirname "$(readlink -f /proc/<PID>/exe)")")/release"',
     {'fixed': 'JAVA_VERSION is outside the affected range: not affected.', 'affected': 'JAVA_VERSION is inside the affected range: affected.',
      'cant_tell': 'No release file: a distribution package; ask the package manager (rpm -qf or dpkg -S on the binary).'}),
)


def java_steps():
    return [_step(text, command, outcomes=outcomes) for text, command, outcomes in JAVA_STEPS]


def _java_tried(ev):
    rows = [r for r in (ev.get('java') or []) if isinstance(r, dict)][:6]
    return [f"{_plain(r.get('version'), 20) or 'line ' + str(r.get('major'))} ({_plain(r.get('source'), 20)}, {_plain(r.get('confidence'), 10)})"
            for r in rows]


def _java_assessment(match):
    ev = _ev(match)
    cve_id = _cve_id(match) or 'this CVE'
    if ev.get('java_unknown'):
        known = _java_tried(ev)
        note = _plain(ev.get('java_note'), 300)
        why = ('What an outside check could not see: which Java runtime this host runs. The application on it runs on Java, but none of the '
               'parts of it that answer from outside (a debug port, an actuator or Jolokia endpoint, a status page, a header or an error page) '
               'stated the runtime\'s version' + (f'; what is known: {", ".join(known)}' if known else '') + '.'
               + (f' {note[:1].upper() + note[1:]}.' if note else '')
               + (f' The host starts only on Java {ev.get("java_floor")} or later.' if ev.get('java_floor') else '')
               + f' Whether {cve_id} applies depends only on that version, which the host owner can read in a minute with the commands below. '
               'Not confirmed, and it never raises the host\'s heat on its own.')
        return 'java_unknown', NOT_CONFIRMED, why
    reading = _plain(ev.get('reading'), 120)
    return ('java_version', NOT_CONFIRMED, f'The Java runtime stated its version{": " + reading if reading else ""}. That is a version, not a test of '
                                           'the flaw; a distribution\'s Java build may carry a backported fix. Not confirmed: nothing tested for '
                                           'the flaw itself.')


def _assessment(match, family, key, package):
    """``(basis, confidence, why)`` from the evidence class of the match."""
    ev = _ev(match)
    cve_id = _cve_id(match) or 'this CVE'
    fam = FAMILIES.get(family, {}).get('label', 'The distribution')
    pkg = package or 'the package'
    fix = _red_hat_fix(match)
    state = str(match.distro_status or '')
    if state == distro.PATCHED:
        fixed = f' (fixed in {fix["fixed_build"]})' if fix.get('fixed_build') else ''
        return ('distro_patched', RULED_OUT, f"{fam}'s security tracker lists the installed {pkg} build as fixed{fixed}. The version in range is "
                                              'kept for the record, but the match does not count against the host.')
    if _backport_state(match):
        named = ' '.join(x for x in (fix.get('advisory', ''), f'({fix["fixed_build"]})' if fix.get('fixed_build') else '') if x)
        return ('distro_backport', NOT_CONFIRMED, f'Red Hat says it fixed {cve_id} in a backport' + (f' in {named}' if named else '')
                + ', without changing the version. Whether this host has that build installed is not known. Not confirmed: the installed '
                  'build decides.')
    if state == distro.VULNERABLE:
        fixed = f'; the fixed build is {fix["fixed_build"]}' if fix.get('fixed_build') else '; no fixed build is listed yet'
        return ('distro_vulnerable', LIKELY, f"{fam}'s security tracker lists the installed {pkg} build as affected{fixed}. That is the "
                                             'distribution\'s own word, not just the version.')
    if match.source == 'java':
        return _java_assessment(match)
    if match.source == 'openvas':
        qod = _qod(ev)
        quality = f' (quality of detection {qod}%)' if qod is not None else ''
        if ev.get('generic_check'):
            return ('generic_check', NOT_CONFIRMED, f'The OpenVAS check saw a behaviour{quality}, not the product: it identified no product or '
                                                    f'version, and the advisories it lists belong to several vendors. It does not show that {cve_id} '
                                                    'applies to this host. Not confirmed.')
        if match.template_result == 'vulnerable':
            return ('openvas_confirmed', CONFIRMED, f'OpenVAS tested the host directly{quality}: an active or authenticated check saw the flaw, '
                                                    'not only a version. Confirmed by a check.')
        backport = _backport_words(family, key)
        return ('openvas_version', NOT_CONFIRMED, f'OpenVAS inferred this from the version it read{quality}, not from a test of the flaw. '
                                                  + (backport + ' ' if backport else '') + 'Not confirmed: nothing tested for the flaw itself.')
    if match.source == 'testssl':
        return ('tls_check', CONFIRMED, 'testssl.sh saw the weakness in this service\'s TLS handshake. Confirmed by a check, not just a version.')
    if match.template_result == 'vulnerable':
        template = str(match.template_id or '')
        named = f' (template {template})' if template and confirm_guide._TEMPLATE.match(template) else ''
        return ('template', CONFIRMED, f'A cvENGINE check{named} tested the host and the flaw answered. Confirmed by a check, not just a version.')
    if _validation_status(match) == 'hit':
        return ('validation_hit', CONFIRMED, 'A validation check cvENGINE ran against the host reproduced it. Confirmed by a check, not just a version.')
    if match.source == 'host' or ev.get('host_reported'):
        return ('host_inventory', LIKELY, 'The host\'s own inventory report lists the package at an affected version. That is the installed '
                                          'package, not a banner; a distribution build may still carry a backported fix.')
    if match.version_in_range is None:
        return ('version_unknown', NOT_CONFIRMED, 'No version was read, so whether the installed version is affected is not known. Not confirmed.')
    where = _where_version(match, key)
    if match.source == 'tech' and ev.get('version_source') == 'body':
        return ('library_file', NOT_CONFIRMED, 'The version was read from the library file the page loads, so the version is certain; whether '
                                               'the page uses the affected function is not. Not confirmed: nothing tested for the flaw itself.')
    template_note = ' A version check read the same version on the host again.' if match.template_result == 'version_only' else ''
    backport = _backport_words(family, key)
    return ('version_only', NOT_CONFIRMED, f'This is based only on {where}.{template_note} ' + (backport + ' ' if backport else '')
            + 'Not confirmed: cvENGINE did not test for the flaw itself.')


# --- what it found -------------------------------------------------------------------------------------------------------------------

def _found(match, family, key, label, version):
    ev = _ev(match)
    cve_id = _cve_id(match) or 'This CVE'
    on = f' on {FAMILIES[family]["label"]}' if family else ''
    named = f'{label} {version}'.strip() if version else label
    if match.source == 'openvas':
        port = _PORT.match(str(ev.get('port') or ''))
        where = f' on port {port.group(1)}/{port.group(2)}' if port else ''
        if ev.get('generic_check'):
            return (f'OpenVAS reported {cve_id}{where}. The check that found it looks for a behaviour several vendors share; {cve_id} is one of '
                    'the advisories it lists.')
        seen = f', and read {named}{on}' if (key or ev.get('product')) and version else (f', on {named}{on}' if key else '')
        head = f'OpenVAS reported {cve_id}{where}{seen}.'
    elif match.source == 'port':
        port = confirm_guide._port(ev.get('port'))
        proto = 'udp' if str(ev.get('protocol') or '').lower() == 'udp' else 'tcp'
        head = (f'The service on port {port}/{proto} says it is {named}{on}.' if port else f'A service on this host says it is {named}{on}.')
    elif match.source == 'tech':
        if 'Server header' in _where_version(match, key):
            head = f'The web server says it is {named}{on}.'
        elif ev.get('version_source') or ev.get('script_url'):
            head = f'The page loads {named}.'
        else:
            head = f'The site\'s technology fingerprint names {named}{on}.'
    elif match.source == 'host':
        head = f'The host\'s own inventory report lists {named}{on}.'
    elif match.source == 'testssl':
        port = confirm_guide._port(ev.get('port'))
        return f'testssl.sh found a TLS weakness{f" on port {port}" if port else ""} that {cve_id} describes.'
    elif match.source == 'wp-plugin':
        head = f'The WordPress site reports {named}.'
    elif match.source == 'java':
        head = ('This host runs Java, but the version of its runtime was not read from outside.' if ev.get('java_unknown')
                else f'The Java runtime on this host stated {_plain(ev.get("reading"), 120) or named}.')
    else:
        head = f'cvENGINE found {named} on this host.'
    own, every = confirm_guide._ranges_of(match)
    if own or every:
        words = '; '.join(confirm_guide._range_words(r) for r in (every or [own])[:3])
        return f'{head} {cve_id} affects {label} {words}.'
    return f'{head} {cve_id} names {label} among the affected products.'


# --- what to do, and what each answer means ------------------------------------------------------------------------------------------

def _step(text, command='', needs=SHELL, outcomes=None, url=''):
    out = {'text': text, 'command': command, 'needs': needs if command else '', 'read_only': True, 'outcomes': outcomes or {}}
    if url:
        out['url'] = url
    return out


def _tracker(family, cve_id):
    return FAMILIES[family]['tracker'].format(cve=cve_id) if family in FAMILIES and cve_id else ''


def _cves_args(cve_ids):
    return ' '.join(f'-e {shlex.quote(c)}' for c in cve_ids)


def rpm_steps(binary, cve_ids, fix=None):
    """The Red Hat family steps for ``binary`` and the validated ``cve_ids``: the changelog (the verdict), the exact build, the pending update."""
    fix = fix or {}
    one = cve_ids[0] if len(cve_ids) == 1 else ''
    names = one or 'a CVE of the list'
    grep = f'grep -F -e {shlex.quote(one)}' if one else f'grep -o -F {_cves_args(cve_ids)} | sort -u'
    changelog = _step(
        f'See whether the installed {binary} package carries Red Hat\'s fix. Red Hat names every CVE it fixed in the package changelog, even when '
        'the version stays the same.' if one else
        f'See which of these CVEs the installed {binary} package already carries Red Hat\'s fix for: the command prints each one the package '
        'changelog names.',
        f'rpm -q --changelog {shlex.quote(binary)} | {grep}',
        outcomes={'fixed': (f'A line names {one}: the installed build includes the fix.' if one else
                            'Each CVE printed is fixed in the installed build.'),
                  'cant_tell': (f'No line: this build does not mention {names}. Either it predates the fix or Red Hat did not change this package for '
                                'it; the next steps tell which.') + ' "package is not installed" means the server is not this package (built from '
                               'source, or in a container): read its version by hand.'})
    build_outcomes = {'cant_tell': 'The version part does not decide: Red Hat keeps it after a fix. Compare the whole build with the fixed build in '
                                   'Red Hat\'s advisory.'}
    if fix.get('fixed_build'):
        build_outcomes = {'fixed': f'{fix["fixed_build"]} or a newer build: fixed.',
                          'affected': f'A build older than {fix["fixed_build"]}: still affected. Update the package.'}
    build = _step('Print the exact installed build, to quote when you close the match.',
                  f"rpm -q --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}\\n' {shlex.quote(binary)}", outcomes=build_outcomes)
    advisory = fix.get('advisory', '')
    pending_text = ((f'Red Hat fixed it in {advisory}' + (f' ({fix["fixed_build"]})' if fix.get('fixed_build') else '') + '. See whether that '
                     'update is waiting to be installed (on RHEL 7, use yum instead of dnf).') if advisory else
                    'Ask the package manager whether an update that fixes it is waiting to be installed (on RHEL 7, use yum instead of dnf).')
    pending = _step(pending_text, f'dnf updateinfo list cves | grep -F {_cves_args(cve_ids)}', needs=DNF_NEEDS,
                    outcomes={'affected': ('A line names the CVE with an advisory (RHSA-...) and a newer build: the fix is published but not '
                                           f'installed, so the host is still affected. Install it with dnf update {binary}.'),
                              'fixed': f'No line, and the changelog named {names}: fixed.',
                              'cant_tell': ('No line, and the changelog named nothing: Red Hat ships no fix for this release, or the host cannot '
                                            'reach its repositories. Read Red Hat\'s page for the CVE.')},
                    url=fix.get('url', '') or (_tracker('rhel', one) if one else ''))
    return [changelog, build, pending]


def deb_steps(family, binary, cve_ids, fix=None):
    """The Debian and Ubuntu steps: the package changelog (the verdict), the installed version, the tracker."""
    fix = fix or {}
    one = cve_ids[0] if len(cve_ids) == 1 else ''
    grep = f'zgrep -F -e {shlex.quote(one)}' if one else f'zgrep -o -F {_cves_args(cve_ids)}'
    tail = '' if one else ' | sort -u'
    label = FAMILIES[family]['label'] if family in FAMILIES else ''
    whose = f"{label}'s" if label else "the distribution's"
    changelog = _step(
        f'See whether the installed {binary} package carries {whose} fix. The package changelog names every CVE it fixed, even when the '
        'version stays the same.' if one else f'See which of these CVEs the installed {binary} package already carries {whose} fix for.',
        f'{grep} /usr/share/doc/{binary}/changelog.Debian.gz{tail}',
        outcomes={'fixed': f'A line names {one}: the installed build includes the fix.' if one else 'Each CVE printed is fixed in the installed build.',
                  'cant_tell': f'No line: this build does not mention it. Compare the installed version with the fixed version {whose} '
                               'security tracker lists for your release.'})
    version_outcomes = ({'fixed': f'{fix["fixed_build"]} or newer: fixed.', 'affected': f'Older than {fix["fixed_build"]}: still affected. Update the package.'}
                        if fix.get('fixed_build') else
                        {'cant_tell': f'Compare it with the fixed version {whose} security tracker lists for your release.'})
    version = _step('Print the installed package version, to quote when you close the match.',
                    f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {shlex.quote(binary)}", outcomes=version_outcomes)
    out = [changelog, version]
    url = _tracker(family, one) if one and family in ('debian', 'ubuntu') else ''
    if url:
        out.append(_step(f'Open {label}\'s page for {one}: it lists the fixed package version for each release.', url=url,
                         outcomes={'affected': 'The installed version is older than the fixed version for your release: still affected.',
                                   'fixed': 'The installed version is the fixed version or newer: fixed.'}))
    return out


def apk_steps(binary, cve_ids):
    one = cve_ids[0] if len(cve_ids) == 1 else ''
    out = [_step('Print the installed package version.', f'apk info -v {shlex.quote(binary)}',
                 outcomes={'cant_tell': 'Compare it with the fixed version Alpine\'s security tracker lists for your release.'})]
    if one:
        out.append(_step(f'Open Alpine\'s page for {one}.', url=_tracker('alpine', one)))
    return out


def _os_release_step():
    return _step('Find out which distribution the host runs.', 'cat /etc/os-release',
                 outcomes={'cant_tell': 'ID=rhel, centos, rocky or almalinux: use the rpm commands. ID=debian or ubuntu: use the dpkg commands.'})


def package_steps(family, binary, cve_ids, fix=None, key='', upstream=''):
    """The steps that settle ``cve_ids`` on a host whose distribution family is ``family`` ('' when unknown), for one allow-listed binary
    package. On a host of unknown family ``binary`` is the Red Hat name, and ``key`` (the product) gives the Debian one."""
    if family == 'rhel':
        return rpm_steps(binary, cve_ids, fix)
    if family in ('debian', 'ubuntu'):
        return deb_steps(family, binary, cve_ids, fix)
    if family == 'alpine':
        return apk_steps(binary, cve_ids)
    # not known: both families' changelog checks after the one that says which applies
    _deb_package, deb_binary = _packages(key, 'debian', upstream) if key else ('', '')
    rpm = rpm_steps(binary, cve_ids, fix)[:2]
    deb = deb_steps('', deb_binary, cve_ids)[:1] if deb_binary else []
    for step in rpm:
        step['text'] = 'On Red Hat, CentOS, Rocky or AlmaLinux: ' + step['text'][0].lower() + step['text'][1:]
    for step in deb:
        step['text'] = 'On Debian or Ubuntu: ' + step['text'][0].lower() + step['text'][1:]
    return [_os_release_step(), *rpm, *deb]


def _other_steps(match, basis, label, cve_id):
    """What to do when no package decides it: text only (the per-match guide under "Confirm it yourself" has the commands for this host)."""
    if basis in ('java_unknown', 'java_version'):
        return java_steps()
    if basis == 'tls_check':
        return [_step('Change the TLS configuration of the service on that port (turn off the protocol, cipher or renegotiation the test names), '
                      'or update its TLS library, then mark the match fixed: cvENGINE runs the same test again to verify (Retest).')]
    if basis in ('template', 'validation_hit', 'openvas_confirmed'):
        return [_step(f'Apply the fix for {label} (the vendor\'s fixed release, or the distribution\'s fixed package), then mark the match fixed: '
                      'cvENGINE runs the check that found it again to verify (Retest).')]
    if basis == 'generic_check':
        return [_step(f'Check whether this host runs the product {cve_id or "the advisory"} is about. The OpenVAS check only saw a behaviour '
                      'several vendors share. If the host does not run it, close the match as a false positive and say what it runs.')]
    if basis == 'library_file':
        return [_step(f'Find where the page\'s own code calls the {label} functions the advisory names, or load a fixed {label} release: see '
                      '"Confirm it yourself" below for the file, the page and the commands.')]
    return [_step(f'Read the {label} version on the host itself: see "Confirm it yourself" below for where to look and the commands for this match.')]


def _outcomes(basis, family, package, cve_id, fix):
    fam = FAMILIES.get(family, {}).get('label', 'the distribution')
    if package:
        return {'fixed': (f'The {package} changelog names {cve_id or "the CVE"}' + (f', or the installed build is {fix["fixed_build"]} or newer'
                                                                                     if fix.get('fixed_build') else '')
                          + f': {fam}\'s fix is installed. Close the match as fixed, or as a false positive when the host never had the flaw.'),
                'affected': ((f'The installed build is older than {fix["fixed_build"]}' if fix.get('fixed_build') else
                              'An update that names the CVE is waiting to be installed')
                             + ': still affected. Install the update, then close the match as fixed.'),
                'cant_tell': ('Neither the changelog nor a pending update names it, or the package is not installed: the server may be built '
                              'from source or run in a container. Read the version by hand ("Confirm it yourself"), and leave the match open.')}
    if basis in ('template', 'tls_check', 'validation_hit', 'openvas_confirmed'):
        return {'fixed': 'After the fix, the check no longer reproduces it: close the match as fixed (Retest verifies it).',
                'affected': 'The check still reproduces it: still affected.', 'cant_tell': 'The check cannot reach the host: test it from inside.'}
    return {'fixed': 'The version on the host is the fixed release or newer: close the match as fixed, or as a false positive.',
            'affected': 'The version on the host is inside the affected range and nothing else rules it out: still affected.',
            'cant_tell': 'The version cannot be read: leave the match open and ask the host owner.'}


def _close_notes(match, basis, family, package, binary, cve_id, label, version, host):
    """The closure notes a person can start from: one for "fixed" and one for "false positive", with the evidence the steps produce."""
    where = f' on {host}' if host else ''
    fam = FAMILIES.get(family, {}).get('label', 'the distribution')
    if package and cve_id:
        if family in ('debian', 'ubuntu'):
            check = f'zgrep -F -e {cve_id} /usr/share/doc/{binary}/changelog.Debian.gz'
        else:
            check = f'rpm -q --changelog {binary} | grep -F -e {cve_id}'
        build = 'Installed build (paste the output of the build command): '
        fixed = (f'Checked{where}: `{check}` names {cve_id}, so the installed {package} build carries {fam}\'s fix'
                 + (f' (the version stays {version})' if version else '') + f'. {build}')
        false = (f'Not affected{where}: {label} {version} is {fam}\'s {package} package, and its changelog names {cve_id} (`{check}`): the fix '
                 f'was backported without changing the version. {build}').replace('  ', ' ')
    elif basis == 'generic_check':
        fixed = f'Fixed{where}: (say what was changed, for example the behaviour the OpenVAS check saw was turned off).'
        false = (f'Not affected{where}: the OpenVAS check only saw a behaviour several vendors\' advisories share, and this host does not run the '
                 f'product {cve_id or "the advisory"} is about. It runs: ')
    else:
        fixed = f'Fixed{where}: (say what was changed, for example {label} updated to the fixed release, and how you checked it).'
        false = f'Not affected{where}: (say what you checked on the host and what it showed).'
    return [{'status': 'fixed', 'label': 'Close as fixed', 'note': fixed[:NOTE_MAX]},
            {'status': 'false_positive', 'label': 'Close as false positive', 'note': false[:NOTE_MAX]}]


def explain(match, hint=''):
    """The plain-words explanation of one CVEMatch (its ``cve_entry`` and ``subdomain`` loaded): ``{version, found, why, confidence,
    confidence_label, basis, platform, question, who, steps: [{text, command, needs, read_only, outcomes}], outcomes, close, advisory}``.
    ``hint`` is what the rest of the host says about its distribution (``host_hint``). Pure but for the Triage row a list already loads."""
    from cveFeed.closure import CLOSED
    cve_id = _cve_id(match)
    family, key, package, binary = _subject(match, hint)
    label = _label(match, key)
    version = _version(match)
    basis, confidence, why = _assessment(match, family, key, package)
    fix = _red_hat_fix(match) if family in ('rhel', '') else {k: v for k, v in _red_hat_fix(match).items() if k == 'fixed_build'}
    host = confirm_guide._host(getattr(match.subdomain, 'name', ''))
    if package and cve_id:
        steps = package_steps(family, binary, [cve_id], fix, key, version)
        if confidence == CONFIRMED:
            # a check saw the flaw answer: fix it first; the package steps then show the installed build carries the fix
            steps = [*_other_steps(match, basis, label, cve_id), *steps]
    else:
        steps = _other_steps(match, basis, label, cve_id)
    commands = any(s['command'] for s in steps)
    out = {
        'version': EXPLAIN_VERSION,
        'found': _found(match, family, key, label, version),
        'why': why,
        'confidence': confidence,
        'confidence_label': CONFIDENCE_WORDS[confidence],
        'basis': basis,
        'platform': {'family': family, 'label': FAMILIES.get(family, {}).get('long', ''), 'package': package, 'query_package': binary},
        'question': ({'key': f'{family or "any"}:{package}', 'text': f'Is the installed {package} package patched?'} if package and cve_id
                     else dict(JAVA_QUESTION) if basis in ('java_unknown', 'java_version') else None),
        'who': (f'Someone with a shell on {host or "the host"} (its owner or administrator) can run these. No administrator rights are needed, '
                'and every command only reads: none installs, changes or restarts anything.') if commands else '',
        'steps': steps,
        'outcomes': _outcomes(basis, family, package, cve_id, fix),
        'close': ([] if match.remediation_status in CLOSED else
                  _close_notes(match, basis, family, package, binary, cve_id, label, version, host)),
    }
    if fix.get('advisory') or fix.get('fixed_build'):
        out['advisory'] = fix
    return out


def package_decides(match, hint=''):
    """Whether a distribution package decides a Java runtime match (a distribution's build read exactly): then its package question asks it."""
    ev = _ev(match)
    return bool(isinstance(ev.get('distro'), dict) and ev['distro'].get('package') and not ev.get('java_unknown') and _subject(match, hint)[2])


# --- one host: the commands that settle the most matches ----------------------------------------------------------------------------

_HEAT_RANK = {'fire': 3, 'smoke': 2, 'ice': 1}
MAX_GROUP_CVES = 200  # the most CVEs one command names (a host past it settles the rest after the first ones are closed)


def validate_plan(matches, hint='', heat_of=None):
    """The short list of commands for a host's owner that settles the most of its open ``matches``: one group per package that decides them
    ("Is the installed httpd package patched?"), each with its steps and the matches it resolves, ordered exploited (KEV) first, then by heat,
    then by how many matches it settles. Matches are grouped for reading only; nothing stored changes. ``heat_of`` maps a match id to the
    heat the host shows for it (``threat.match_heat`` when absent)."""
    from cveFeed.counts import match_is_live
    from cveFeed.threat import match_heat
    groups, seen = {}, set()
    for m in matches:
        if not match_is_live(m):
            continue
        same = (m.cve_entry_id, m.source, m.matched_product)
        if same in seen:  # the same match on another copy of the host's name (an earlier scan's row): read once
            continue
        seen.add(same)
        cve_id = _cve_id(m)
        if m.source == 'java' and cve_id and not package_decides(m, hint):
            # one question settles every Java runtime CVE of the host: which Java it runs
            heat = (heat_of or {}).get(m.id) or match_heat(m)
            group = groups.setdefault(('java', 'java-runtime'), {'java': True, 'rows': []})
            group['rows'].append({'match_id': m.id, 'cve_id': cve_id, 'kev': bool(getattr(m.cve_entry, 'kev', False)), 'heat': heat,
                                  'product': 'Java runtime', 'source': m.source})
            continue
        family, key, package, binary = _subject(m, hint)
        if not (package and cve_id):
            continue
        heat = (heat_of or {}).get(m.id) or match_heat(m)
        group = groups.setdefault((family, package), {'family': family, 'key': key, 'package': package, 'binary': binary, 'rows': [],
                                                       'fix': {}, 'upstream': _version(m)})
        fix = _red_hat_fix(m) if family in ('rhel', '') else {}
        if fix.get('fixed_build') and not group['fix'].get('fixed_build'):
            group['fix'] = {'fixed_build': fix['fixed_build']}  # one build is the fix of one CVE; the group's steps name no single one
        group['rows'].append({'match_id': m.id, 'cve_id': cve_id, 'kev': bool(getattr(m.cve_entry, 'kev', False)), 'heat': heat,
                              'product': _LABELS.get(key, ''), 'source': m.source})
    out = []
    for (family, package), g in groups.items():
        rows = sorted(g['rows'], key=lambda r: (not r['kev'], -_HEAT_RANK.get(r['heat'], 0), r['cve_id'], r['match_id']))
        cves = sorted({r['cve_id'] for r in rows}, key=lambda c: (not any(r['kev'] for r in rows if r['cve_id'] == c), c))
        if g.get('java'):
            out.append({'key': JAVA_QUESTION['key'], 'question': JAVA_QUESTION['text'], 'product': 'Java runtime', 'package': '', 'query_package': '',
                        'platform': '', 'platform_label': '', 'kev': any(r['kev'] for r in rows),
                        'heat': max((r['heat'] for r in rows), key=lambda h: _HEAT_RANK.get(h, 0)), 'count': len(rows), 'cves': cves,
                        'resolves': rows, 'steps': java_steps(),
                        'outcomes': {'fixed': 'The Java version printed is outside each CVE\'s affected range: close those matches as false positives, '
                                              'quoting the output and the version.',
                                     'affected': 'The version is inside a CVE\'s range: update the Java runtime the application runs on, restart '
                                                 'it, then close those matches as fixed.',
                                     'cant_tell': 'The process or its Java could not be read: leave the matches open and ask the application\'s owner.'}})
            continue
        steps = package_steps(family, g['binary'], cves[:MAX_GROUP_CVES], {}, g['key'], g['upstream'])
        kev = any(r['kev'] for r in rows)
        heat = max((r['heat'] for r in rows), key=lambda h: _HEAT_RANK.get(h, 0))
        out.append({
            'key': f'{family or "any"}:{package}', 'question': f'Is the installed {package} package patched?',
            'product': _LABELS.get(g['key'], ''), 'package': package, 'query_package': g['binary'], 'platform': family,
            'platform_label': FAMILIES.get(family, {}).get('long', ''), 'kev': kev, 'heat': heat,
            'count': len(rows), 'cves': cves, 'resolves': rows, 'steps': steps,
            'outcomes': {'fixed': 'Each CVE the changelog names is fixed in the installed build: close those matches as fixed (or as false '
                                  'positives), quoting the output.',
                         'affected': 'A CVE a pending update names is still open on the host: install the update, then close those matches.',
                         'cant_tell': 'A CVE neither names stays open: read the version by hand on each of those matches ("Confirm it yourself").'},
        })
    out.sort(key=lambda g: (not g['kev'], -_HEAT_RANK.get(g['heat'], 0), -g['count'], g['key']))
    return out
