"""Turning a detection check into something a person can run, and something a future authenticated scan can run.

Every command here is rendered by this module from a check whose parameters were validated against an allowlist
(cveFeed.detection): never written by a model. A model chooses a kind and its parameters; the registry below owns the
command text, the quoting, and what the output means. Each command is read-only, carries the platform and shell it is for,
whether it needs elevated rights, and a structured ``expect`` that says how to decide from its output, so a person reads the
``command`` and ``explain`` and a scanner that logs in to a host can run the same ``command`` and evaluate the same ``expect``.

Remote checks render to ``how``: the tool, the invocation with ``<TARGET>`` (and ``<PORT>``) to fill in, and how to decide.
Local checks render to ``commands``: one entry per platform."""
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
        return {'tool': 'curl', 'invocation': f'curl {flags}{method} --max-time 15 {shlex.quote(url)}',
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


# --- local ------------------------------------------------------------------------------------------------------------------

def _command(platform, shell, command, expect, explain, root=False):
    return {'platform': platform, 'shell': shell, 'command': command, 'read_only': True, 'needs_root': root,
            'expect': expect, 'explain': explain}


def _package_commands(p):
    package = shlex.quote(p['package'])
    eco = p['ecosystem']
    bound = p.get('affected_below') or p.get('fixed_version')
    below = {'kind': 'version_lt', 'than': bound} if bound else {'kind': 'version_present'}
    out = []
    if eco in ('any', 'dpkg'):
        compare = (f"v=$(dpkg-query -W -f='${{Version}}' {package} 2>/dev/null) && dpkg --compare-versions \"$v\" lt {shlex.quote(bound)} "
                   "&& echo AFFECTED || echo NOT-AFFECTED") if bound else f"dpkg-query -W -f='${{Version}}\\n' {package}"
        out.append(_command('debian', 'sh', compare, below,
                            f"Prints AFFECTED when the installed {p['package']} package is older than {bound}; a package that is not "
                            'installed prints NOT-AFFECTED.' if bound else 'Prints the installed version.'))
    if eco in ('any', 'rpm'):
        out.append(_command('rhel', 'sh', f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}\\n' {package}", below,
                            'Prints the installed version-release; compare it with the fixed release in the vendor advisory '
                            '(a vendor backports fixes without raising the upstream version).'))
    if eco in ('any', 'apk'):
        out.append(_command('alpine', 'sh', f'apk info -v {package}', below, 'Prints the installed package and version.'))
    if eco == 'pip':
        out.append(_command('any', 'sh', f'python3 -m pip show {package}', below, 'Read the Version line.'))
    if eco == 'npm':
        out.append(_command('any', 'sh', f'npm ls -g --depth=0 {package}', below, 'Read the version in the tree.'))
    if eco == 'gem':
        out.append(_command('any', 'sh', f'gem list -e {package}', below, 'Read the version in parentheses.'))
    return out


def render_local(check):
    """The list of commands for one local check, one per platform; empty for a kind with no rendering."""
    kind, p = check['kind'], check['params']
    if kind == 'package_version':
        return _package_commands(p)
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
