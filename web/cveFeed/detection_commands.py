"""Turning a detection check into something a person can run, and something a future authenticated scan can run.

Every command here is rendered by this module from a check whose parameters were validated against an allowlist
(cveFeed.detection): never written by a model. A model chooses a kind and its parameters; the registry below owns the
command text, the quoting, and what the output means. Each command is read-only, carries the platform and shell it is for,
whether it needs elevated rights, and a structured ``expect`` that says how to decide from its output, so a person reads the
``command`` and ``explain`` and a scanner that logs in to a host can run the same ``command`` and evaluate the same ``expect``.

Remote checks render to ``how``: the tool, the invocation with ``<TARGET>`` (and ``<PORT>``) to fill in, and how to decide; the guidance
for one match (cveFeed.confirm_guide) fills in the real host, port and URL. Local checks render to ``commands``: one entry per platform
(``app`` for a language package: run in the application's source or deployment directory, never by an OS package manager)."""
import re
import shlex

TARGET = '<TARGET>'
PORT = '<PORT>'


def _ps(text):
    """A PowerShell single-quoted literal."""
    return "'" + str(text).replace("'", "''") + "'"


def _range_text(ranges):
    parts = []
    for rng in ranges or []:
        low, high, last = rng.get('introduced'), rng.get('fixed'), rng.get('last_affected')
        if low and high:
            parts.append(f'{low} up to but not including {high}')
        elif high:
            parts.append(f'every version before {high}')
        elif low and last:
            parts.append(f'{low} through {last}')
        elif low:
            parts.append(f'{low} and later')
        elif last:
            parts.append(f'every version through {last}')
    return '; '.join(parts) or 'the affected range'


# --- remote -----------------------------------------------------------------------------------------------------------------

def render_remote(check):
    """``{'tool', 'invocation', 'decide'}`` for one remote check, or None for a kind with no rendering."""
    kind, p = check['kind'], check['params']
    from cveFeed.detection import banner_reading, is_script_read, script_library
    if is_script_read(check):
        return _render_script_read({**p, 'library': p.get('library') or script_library(check)})
    reading = banner_reading(check) if kind == 'version_banner' else ''
    if reading == 'platform':
        return {'tool': 'host package', 'invocation': '',
                'decide': f"{p['product']} is a distribution release, not a product a banner states: on a host of that release, check the "
                          "installed package the advisory names against the distribution's own fixed build."}
    if kind == 'version_banner' and reading == 'header':
        return {'tool': 'curl', 'invocation': f'curl -gsS -I --max-time 15 https://{TARGET}/',
                'decide': f"Read the Server header (X-Powered-By for a runtime such as PHP or ASP.NET): the reported {p['product']} version is "
                          f"inside {_range_text(p['ranges'])}. A Linux distribution keeps the upstream version in the header after a backported "
                          'fix, and a proxy or CDN in front may answer with its own: the host\'s package release decides.'}
    if kind == 'version_banner' and reading == 'technology':
        return {'tool': 'technology fingerprint', 'invocation': f'curl -gsS -i --max-time 15 https://{TARGET}/',
                'decide': f"cvENGINE's technology fingerprint (headers, page markers, a generator tag, a readme) names {p['product']} at a "
                          f"version inside {_range_text(p['ranges'])}. That names the product, rarely the exact version of a dependency: the "
                          "application's lockfile, package manager or the component's own files decide."}
    if kind == 'version_banner':
        return {'tool': 'nmap', 'invocation': f'nmap -Pn -sV --version-intensity 5 -p {PORT} {TARGET}',
                'decide': f"The reported {p['product']} version is inside {_range_text(p['ranges'])}. A banner can hide a backported "
                          'fix, so a match here needs the host check or a template to be confirmed.'}
    if kind == 'http_probe':
        url = f"https://{TARGET}{p['path']}"
        flags = '-sS -i' + (' -I' if p['method'] == 'HEAD' else '')
        method = '' if p['method'] == 'HEAD' else f" -X {p['method']}"
        expected = f"status {', '.join(str(s) for s in p['expect_status'])}"
        if p.get('expect_contains'):
            expected += f" and the body contains {p['expect_contains']!r}"
        if p.get('expect_absent'):
            expected += f" and the body does not contain {p['expect_absent']!r}"
        return {'tool': 'curl', 'invocation': f'curl -g {flags}{method} --max-time 15 {shlex.quote(url)}',
                'decide': f'Vulnerable when the response has {expected}.'}
    if kind == 'nuclei_template':
        return {'tool': 'nuclei', 'invocation': f"nuclei -duc -id {shlex.quote(p['template_id'])} -u {TARGET}",
                'decide': 'Vulnerable when the template reports a match; no match means the check did not fire, not that the host is safe.'}
    if kind == 'nse_script':
        extra = f" and the output contains {p['expect_contains']!r}" if p.get('expect_contains') else ''
        return {'tool': 'nmap', 'invocation': f"nmap -Pn -sV --script {shlex.quote(p['script'])} -p {PORT} {TARGET}",
                'decide': f"Read the {p['script']} output{extra}."}
    if kind == 'tls_check':
        prop = p['property']
        if prop == 'protocol':
            invocation = f"openssl s_client -connect {TARGET}:443 -servername {TARGET} </dev/null"
        else:
            invocation = f"nmap -Pn -p 443 --script ssl-cert {TARGET}"
        return {'tool': 'openssl' if prop == 'protocol' else 'nmap', 'invocation': invocation,
                'decide': f"Vulnerable when the {prop} is {p['expect']!r}."}
    if kind == 'port_service':
        port = p['port']
        service = f" and the service is {p['service']}" if p.get('service') else ''
        return {'tool': 'nmap', 'invocation': f'nmap -Pn -sV -p {port} {TARGET}',
                'decide': f'Port {port} is open{service}.'}
    return None


def _render_script_read(p):
    """A client-side JavaScript library (``script_version``, or a banner check whose product is one): read from the script files the page
    loads by cvENGINE's own html-libraries read (``cveFeed.js_libraries``), which nmap cannot do."""
    from cveFeed.detection import _script_product
    from cveFeed.js_libraries import MAX_SCRIPT_BYTES, MAX_SCRIPTS_PER_HOST
    product = _script_product({'kind': 'script_version', 'params': p})
    return {'tool': 'html-libraries probe',
            'invocation': f'curl -gsS --max-time 15 https://{TARGET}/',
            'decide': (f"cvENGINE's html-libraries read (Validate now) fetches the page and up to {MAX_SCRIPTS_PER_HOST} of the scripts it loads; "
                       f'by hand, fetch each script the page names (curl -sS <script URL>; cvENGINE reads up to {MAX_SCRIPT_BYTES // 1024} KB '
                       'of each). Vulnerable version when the '
                       f"{product} file the page loads states a version inside {_range_text(p['ranges'])}. The version is read from the file "
                       'itself (its banner or code), never from a ?ver= query string or the file name alone. When the page loads several '
                       'copies, the one that runs last is effective and the earlier ones are shadowed: the effective copy decides. A hit '
                       'proves the version is present on the page, not that the page is exploitable: that depends on how the page uses '
                       f'{product} (an XSS flaw needs attacker-controlled HTML to reach its DOM-manipulation functions).')}


# --- local ------------------------------------------------------------------------------------------------------------------

def _command(platform, shell, command, expect, explain, root=False):
    return {'platform': platform, 'shell': shell, 'command': command, 'read_only': True, 'needs_root': root,
            'expect': expect, 'explain': explain}


# the language ecosystems: read in the application's source or deployment directory ("app"), never by an OS package manager. Each command
# only reads: a package manager's listing or a lockfile search. ``{q}`` is the shell-quoted package name, ``{re}`` a grep pattern for it.
APP = 'app'
_LANGUAGE_COMMANDS = {
    'npm': (("npm ls {q} --all", 'Lists every copy of {name} in the dependency tree with its version (run where package.json is).'),
            ("grep -n -A 3 -F -e {lock} package-lock.json", 'Each "version" under a node_modules/{name} entry is a copy that is installed.')),
    'composer': (("composer show {q}", 'Prints the installed {name} with its version (run where composer.json is).'),
                 ("grep -n -A 3 -F -e {lock} composer.lock", 'The "version" under that name is the locked version.')),
    'gem': (("grep -n -E {gemlock} Gemfile.lock", 'The version in parentheses is the locked {name} gem (run where the Gemfile is).'),
            ("gem list -e {q}", 'Prints the installed versions of the {name} gem.')),
    'maven': (("mvn -q dependency:tree -Dincludes={q}", 'Prints {name} in the resolved dependency tree with its version (run where '
               'pom.xml is). Note: Maven downloads the dependency plugin and any missing artifacts from its repositories the first time; the '
               'grep below only reads the build files.'),
              ("grep -rn -F -e {q} --include='*.gradle' --include='*.gradle.kts' --include='*.lockfile' .", 'A Gradle build declares {name} '
               'with its version on that line.')),
    'nuget': (("dotnet list package --include-transitive", 'Read the version of {name} in the list (run where the project or solution '
               'file is).'),
              ("grep -rn -i -F -e {q} --include=packages.config --include='*.csproj' --include=packages.lock.json .", 'The Version (or '
               'version) next to {name} is the referenced version.')),
    'pip': (("python3 -m pip show {q}", 'Read the Version line (run in the application\'s virtual environment).'),
            ("grep -rn -i -E {pipreq} --include='requirements*.txt' --include=poetry.lock --include=Pipfile.lock .", 'The pinned version '
             'of {name}.')),
    'go': (("go list -m all", 'Read the version printed next to {name} (run where go.mod is).'),
           ("grep -n -F -e {q} go.mod", 'The version on that line is the required version of {name}.')),
    'cargo': (("cargo tree --locked -i {q}", 'Prints {name} with its version and what pulls it in, from Cargo.lock as it is (run where '
               'Cargo.toml is; --locked never updates the lockfile).'),
              ("grep -n -A 1 -F -e {cratelock} Cargo.lock", 'The version line under it is the locked version of {name}.')),
}


def _ere(text):
    """``text`` as a literal inside an extended regular expression (only the ERE metacharacters are escaped: GNU grep warns on others)."""
    return re.sub(r'([.\[\]()*+?{}|^$\\])', r'\\\1', str(text))


def _language_commands(eco, package, below):
    name = str(package)
    values = {'q': shlex.quote(name), 'name': name, 'lock': shlex.quote(f'node_modules/{name}"' if eco == 'npm' else f'"name": "{name}"'),
              'gemlock': shlex.quote(r'^    ' + _ere(name) + r' \('), 'pipreq': shlex.quote('^' + _ere(name) + r'([=<>~!; ]|$)|name = "' + _ere(name) + '"'),
              'cratelock': shlex.quote(f'name = "{name}"')}
    return [_command(APP, 'sh', command.format(**values), below, explain.format(**values)) for command, explain in _LANGUAGE_COMMANDS.get(eco, ())]


def _package_commands(p):
    from cveFeed.detection_classes import LANGUAGE, language_ecosystem_of
    eco = p['ecosystem']
    bound = p.get('affected_below') or p.get('fixed_version')
    below = {'kind': 'version_lt', 'than': bound} if bound else {'kind': 'version_present'}
    if eco == 'any' and language_ecosystem_of(p['package']):
        inferred = language_ecosystem_of(p['package'])
        # a name that can only be a language coordinate is never an OS package; a path-like name may be a container image too, so only
        # the unambiguous Maven and npm shapes get their ecosystem's commands
        return _language_commands(inferred, p['package'], below) if inferred in ('maven', 'npm') else []
    if eco in LANGUAGE:
        return _language_commands(eco, p['package'], below)
    # OS package names are lowercase; an advisory or a model may write the product's own capitalisation (OpenSSH)
    name = p['package'].lower() if eco == 'any' else p['package']
    package = shlex.quote(name)
    out = []
    if eco in ('any', 'dpkg'):
        # the epoch ("1:" on OpenSSH, bind9, dovecot) is not part of the upstream version the bound is written in; a package that is not
        # installed under this name (a source name such as openssh is not the binary openssh-server) is UNKNOWN, never NOT-AFFECTED
        compare = (f"v=$(dpkg-query -W -f='${{Version}}' {package} 2>/dev/null) && [ -n \"$v\" ] && "
                   f"{{ dpkg --compare-versions \"${{v#*:}}\" lt {shlex.quote(re.sub(r'^[0-9]+:', '', str(bound)))} "
                   "&& echo AFFECTED || echo NOT-AFFECTED; } || echo UNKNOWN") if bound else f"dpkg-query -W -f='${{Version}}\\n' {package}"
        out.append(_command('debian', 'sh', compare, below,
                            f"Prints AFFECTED when the installed {name} package is older than {bound} (an epoch such as 1: is "
                            'ignored), and UNKNOWN when no package of that name is installed: check the binary package name '
                            '(for example openssh-server for openssh).' if bound else 'Prints the installed version.'))
    if eco in ('any', 'rpm'):
        out.append(_command('rhel', 'sh', f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}\\n' {package}", below,
                            'Prints the installed version-release; compare it with the fixed release in the vendor advisory '
                            '(a vendor backports fixes without raising the upstream version).'))
    if eco in ('any', 'apk'):
        out.append(_command('alpine', 'sh', f'apk info -v {package}', below, 'Prints the installed package and version.'))
    return out


def _bundled_commands(p):
    """Find a bundled copy of a client-side library on the web server by its own banner line (the pattern is cvENGINE's own, per library)."""
    from cveFeed.detection import _libraries
    from cveFeed.detection_classes import LIBRARY_FACTS
    pattern = LIBRARY_FACTS.get(p['library'], {}).get('grep')
    if not pattern:
        return []
    product = _libraries()[p['library']][0]
    return [_command('linux', 'sh', f"grep -rIoE --include='*.js' {shlex.quote(pattern)} /var/www /srv /opt 2>/dev/null | sort -u",
                     {'kind': 'output_lists', 'what': 'files and versions'},
                     f'Prints each {product} file under the usual web roots with the version its banner states (add the site\'s own '
                     'document root if it is elsewhere); a version inside the affected range is a vulnerable bundled copy.')]


def render_local(check):
    """The list of commands for one local check, one per platform; empty for a kind with no rendering."""
    kind, p = check['kind'], check['params']
    if kind == 'package_version':
        return _package_commands(p)
    if kind == 'bundled_copy':
        return _bundled_commands(p)
    if kind == 'file_version':
        return [
            _command('linux', 'sh', f"grep -F -e {shlex.quote(p['contains'])} -- {shlex.quote(p['path'])}",
                     {'kind': 'exit_code', 'equals': 0}, f"Exit status 0 means {p['path']} contains {p['contains']!r}."),
            _command('windows', 'powershell', f"Select-String -Path {_ps(p['path'])} -SimpleMatch {_ps(p['contains'])} -Quiet",
                     {'kind': 'output_equals', 'value': 'True'}, f"True means {p['path']} contains {p['contains']!r}.")]
    if kind == 'config_setting':
        key = re.escape(p['key'])
        if p['match'] == 'equals':
            pattern = f"^[[:space:]]*{key}[[:space:]]*[=: ][[:space:]]*{re.escape(p['value'])}[[:space:]]*$"
            expect, explain = {'kind': 'exit_code', 'equals': 0}, f"Exit status 0 means {p['key']} is set to {p['value']!r} in {p['path']}."
        else:
            pattern = f"^[[:space:]]*{key}([[:space:]=:]|$)"
            present = p['match'] == 'present'
            expect = {'kind': 'exit_code', 'equals': 0 if present else 1}
            explain = f"Exit status {0 if present else 1} means {p['key']} is {'set' if present else 'not set'} in {p['path']}."
        return [_command('linux', 'sh', f"grep -Eq -- {shlex.quote(pattern)} {shlex.quote(p['path'])}", expect, explain)]
    if kind == 'service_state':
        service, state = p['service'], p['state']
        verb = 'is-enabled' if state in ('enabled', 'disabled') else 'is-active'
        want = {'running': 'active', 'stopped': 'inactive', 'enabled': 'enabled', 'disabled': 'disabled'}[state]
        win = {'running': 'Running', 'stopped': 'Stopped'}.get(state)
        out = [_command('linux', 'sh', f'systemctl {verb} {shlex.quote(service)}', {'kind': 'output_equals', 'value': want},
                        f'Prints {want} when {service} is {state}.')]
        if win:
            out.append(_command('windows', 'powershell', f'(Get-Service -Name {_ps(service)}).Status', {'kind': 'output_equals', 'value': win},
                                f'Prints {win} when {service} is {state}.'))
        return out
    return []
