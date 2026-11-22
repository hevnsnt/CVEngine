"""How a person confirms a scanner finding, a hygiene finding or an open web route by hand: the "Confirm it yourself" guide of every finding
kind that is not a CVE match (cveFeed.confirm_guide builds that one) and not a TLS audit finding (cveFeed.tls_catalogue builds that one).

Each guide has the shape ``confirm_guide.match_guide`` returns, so the finding page draws them all the same way: where it was found, what
to look for (the scanner's own evidence), read-only steps with this finding's real host, port and URL filled in, how to read the answer, and
the fix. It is built per source, by rules, from what the finding stored: no model is asked.

- OpenVAS: the test (NVT) and its OID with its Greenbone page, the version OpenVAS claimed and how sure it was (its quality of detection,
  said plainly when it is only an inference), a remote hint where one means something, the on-host version and package commands, and the
  distribution trackers of every CVE (Red Hat when the banner says Red Hat).
- nuclei: the template with a link to it, the matched URL, the command that runs the template again, a curl that repeats the stored request
  (a GET or HEAD only, its credentials and cookies left out), what the matcher looked for and the request excerpt with secrets redacted.
- WPScan: the plugin, theme or core version the scan read and how it read it, the fixed version, and a curl of the readme or version file.
- Any other source: where it was found and what the scanner reported, a banner or page read, and the AI review's advice as plain steps.
- Hygiene: a read-only check per family (``openssl s_client`` for a certificate, ``dig`` for SPF, DMARC, DKIM, CAA and MTA-STS, ``curl -I``
  for HSTS, the FTP greeting and AUTH TLS for cleartext FTP, ...).

Safety, as in confirm_guide: every value placed in a command is validated first (``confirm_guide._host``, ``_port``, ``_url``, a template id,
a slug, a version) and shell-quoted; a step that cannot be built from valid values is left out, never built unsafely. Text from a scanned host,
a feed or the AI review is returned as ``quote`` data, never as a command. Every step only reads (a GET or HEAD request, a banner read, a DNS
query, a package listing); re-running a nuclei template is labelled as an active check. cvENGINE never runs these commands: they are shown for
a person, and the server scans only through Sentinels."""
import re
from urllib.parse import urlsplit

from cveFeed import confirm_guide as cg

GUIDE_VERSION = 1
NOTICE = ('cvENGINE does not run these commands. They only read: run them yourself from a machine that is allowed to test this host. '
          'Anything marked "seen on the host", "feed text" or "AI advice" is data to compare, never a command.')

_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]')
_OPENVAS_WHERE = re.compile(r'^(?P<host>[^\s/]+):(?P<port>\d{1,5})/(?P<proto>tcp|udp)\Z', re.IGNORECASE)
_HOST_PORT = re.compile(r'^(?P<host>[^\s/:]+|\[[0-9a-fA-F:.]+\]):(?P<port>\d{1,5})\Z')
_TEMPLATE_PATH = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,299}\.ya?ml\Z')
_HEADER_VALUE = re.compile(r'^[A-Za-z0-9 ._,=*/+:-]{1,200}\Z')
_HEADER_NAME = re.compile(r'^[A-Za-z0-9-]{1,60}\Z')
# the request headers a repeated GET may carry: what a matcher can depend on, none of them a credential
_SAFE_HEADERS = ('accept', 'accept-language', 'content-type', 'x-requested-with')
_SECRET_HEADERS = ('authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token')
_TEMPLATE_HOSTS = ('github.com', 'cloud.projectdiscovery.io', 'templates.nuclei.sh')
_WEB_PORTS = {80: 'http', 8080: 'http', 8000: 'http', 8008: 'http', 443: 'https', 8443: 'https', 9443: 'https'}
GREENBONE_NVT = 'https://secinfo.greenbone.net/nvt/{oid}'

# What an OpenVAS quality-of-detection type says about the version it reports (Greenbone's QoD table). A type in HARD tested the host itself.
HARD_QOD = frozenset({'exploit', 'remote_vul', 'remote_app', 'remote_active', 'package', 'registry'})
BANNER_QOD = frozenset({'remote_banner', 'executable_version', 'remote_analysis', 'remote_probe'})

# The product an OpenVAS test names at the start of its title ("PHP < 8.1.31 ...", "OpenSSH < 9.8 ..."), as the constants the commands and
# trackers are built from. The title only chooses among these.
OPENVAS_PRODUCTS = (
    (re.compile(r'^php\b', re.IGNORECASE), 'PHP', 'php'),
    (re.compile(r'^(apache http server|apache httpd|apache)\b', re.IGNORECASE), 'Apache HTTP Server', 'apache http server'),
    (re.compile(r'^nginx\b', re.IGNORECASE), 'nginx', 'nginx'),
    (re.compile(r'^openssh\b', re.IGNORECASE), 'OpenSSH', 'openssh'),
    (re.compile(r'^openssl\b', re.IGNORECASE), 'OpenSSL', 'openssl'),
    (re.compile(r'^(oracle )?mysql\b', re.IGNORECASE), 'MySQL', 'mysql'),
    (re.compile(r'^postgresql\b', re.IGNORECASE), 'PostgreSQL', 'postgresql'),
    (re.compile(r'^(isc )?bind\b', re.IGNORECASE), 'ISC BIND', 'bind'),
    (re.compile(r'^samba\b', re.IGNORECASE), 'Samba', 'samba'),
    (re.compile(r'^exim\b', re.IGNORECASE), 'Exim', 'exim'),
    (re.compile(r'^lighttpd\b', re.IGNORECASE), 'lighttpd', 'lighttpd'),
)


# --- small pieces --------------------------------------------------------------------------------------------------------------------

def _block(text, limit=800):
    """Multi-line text from a scanned host (a request excerpt), cleaned of control characters but its line breaks kept, and capped."""
    text = _CONTROL.sub('', str(text or '').replace('\r\n', '\n'))
    return text[:limit].strip()


def _versions(text):
    return [v for v in (cg._version(x) for x in re.findall(r'<\s*=?\s*([0-9][0-9A-Za-z.+~_-]{0,63})', str(text or ''))) if v]


def _location(raw, fallback_host=''):
    """``{'url', 'scheme', 'host', 'port', 'proto', 'text'}`` of where a finding was found (its ``http_url``): an http(s) URL, a
    ``scheme://host:port`` service (ssh, ftp, rdp, ...), OpenVAS's ``host:443/tcp`` or a plain ``host:port``. Every value validated; the
    finding's own host name when the stored text has none."""
    text = str(raw or '').strip()
    out = {'url': '', 'scheme': '', 'host': '', 'port': 0, 'proto': 'tcp', 'text': ''}
    url = cg._url(text)
    if url:
        parts = urlsplit(url)
        out.update(url=url, scheme=parts.scheme, host=cg._host(parts.hostname), port=parts.port or (443 if parts.scheme == 'https' else 80))
    else:
        found = _OPENVAS_WHERE.match(text)
        if found:
            out.update(host=cg._host(found.group('host')), port=cg._port(found.group('port')), proto=found.group('proto').lower())
        elif re.match(r'^[a-z][a-z0-9+.-]{1,15}://', text, re.IGNORECASE):
            try:
                parts = urlsplit(text)
                out.update(scheme=parts.scheme.lower(), host=cg._host(parts.hostname), port=cg._port(parts.port))
            except ValueError:
                pass
        else:
            found = _HOST_PORT.match(text)
            if found:
                out.update(host=cg._host(found.group('host').strip('[]')), port=cg._port(found.group('port')))
            else:
                out['host'] = cg._host(text)
    if not out['host']:
        out.update(host=cg._host(fallback_host), url='', scheme='', port=0)
    if out['url']:
        out['text'] = out['url']
    elif out['host']:
        port = f":{out['port']}" if out['port'] else ''
        out['text'] = (f"{out['scheme']}://" if out['scheme'] else '') + cg._bracket(out['host']) + port + (
            f"/{out['proto']}" if port and not out['scheme'] else '')
    return out


def _web_url(loc, path='/'):
    """An http(s) URL on the finding's host: its own URL's site, else the scheme its port implies (https when no port is known)."""
    if not loc['host']:
        return ''
    if loc['url']:
        parts = urlsplit(loc['url'])
        return cg._url(f'{parts.scheme}://{parts.netloc}{path}')
    port = loc['port']
    if port and loc['proto'] == 'udp':
        return ''
    scheme = _WEB_PORTS.get(port) or ('https' if not port else '')
    if not scheme:
        return ''
    return cg._url(cg._base(scheme, loc['host'], port or 443) + path)


def _nmap(loc, title='Read the service banner with nmap', detail=''):
    if not loc['host'] or not loc['port']:
        return None
    udp = loc['proto'] == 'udp'
    return cg._step(title, detail or 'Prints what answers on the port and, when it says, its product and version (a version scan only).',
                    f"nmap -Pn {'-6 ' if ':' in loc['host'] else ''}{'-sU ' if udp else ''}-sV -p {loc['port']} {cg._q(loc['host'])}")


def _where(loc, label='Where it was found'):
    out = []
    if loc['url']:
        out.append({'label': label, 'url': loc['url']})
    elif loc['text']:
        out.append({'label': label, 'text': loc['text']})
    if loc['host'] and loc['port'] and loc['url']:
        out.append({'label': 'Host and port', 'text': f"{cg._bracket(loc['host'])}:{loc['port']}"})
    return out


def _cve_ids(vuln):
    try:
        return [c for c in dict.fromkeys(str(c.name).upper() for c in vuln.cve_ids.all()) if cg._CVE.match(c)][:12]
    except Exception:  # noqa: BLE001 - an unsaved row in a test, or a row whose relation cannot be read: no CVEs
        return []


def _extracted(vuln, limit=5):
    return [q for q in (cg._quote(x, 300) for x in (getattr(vuln, 'extracted_results', None) or [])[:limit]) if q]


def _scanner_said(vuln, label='What the scanner reported (seen on the host)'):
    out = []
    values = _extracted(vuln)
    if values:
        out.append({'label': label, 'quote': '\n'.join(values)})
    if getattr(vuln, 'matcher_name', ''):
        out.append({'label': 'Matcher that fired (scanner text)', 'quote': cg._quote(vuln.matcher_name, 120)})
    return out


def _advice_steps(advice):
    """The AI review's advice (``[{kind, note}]``, read-only by its prompt: never commands) as plain steps a person follows, marked as the
    model's words."""
    steps = []
    for item in (advice or [])[:5]:
        if not isinstance(item, dict):
            continue
        note = cg._quote(item.get('note'), 240)
        kind = str(item.get('kind') or 'manual').lower()
        if note:
            steps.append(cg._step({'curl': 'Suggested by the AI review: a web request', 'nmap': 'Suggested by the AI review: a port check',
                                   'nuclei': 'Suggested by the AI review: a template check'}.get(kind, 'Suggested by the AI review'),
                                  note, run_in='advice'))
    return steps


def _finish(guide, loc=None, fill=True):
    guide['steps'] = [s for s in guide.get('steps', []) if s]
    guide['local'] = [s for s in guide.get('local', []) if s and s.get('commands')]
    if fill and loc and loc.get('host'):
        guide['fill'] = {k: v for k, v in (('TARGET', loc['host'] if ':' not in loc['host'] else ''),
                                            ('PORT', str(loc['port']) if loc.get('port') else '')) if v}
    guide['version'] = GUIDE_VERSION
    guide.setdefault('notice', NOTICE)
    return guide


def _tracker_links(cve_ids, hint, limit=12):
    links = []
    for cve_id in cve_ids:
        links += cg._tracker_links(cve_id, hint) if any(t[0].search(hint or '') for t in cg.TRACKERS) else cg._tracker_links(cve_id)[:1]
    return links[:limit]


def _host_banner(vuln):
    sub = getattr(vuln, 'subdomain', None)
    return cg._quote(getattr(sub, 'webserver', '') or '', 200) if sub is not None else ''


# --- OpenVAS ---------------------------------------------------------------------------------------------------------------------------

def _openvas_observation(vuln, oid, loc):
    """What the OpenVAS import stored about this result (cveFeed.openvas_scan.record_observations): the QoD and its type, the CPE, the
    test's insight. {} when it is not there (a result imported before, or another project's host of the same name is never read)."""
    try:
        from cveFeed import openvas_scan
        from cveFeed.models import ProbeObservation
        project_id = vuln.target_domain.project_id if vuln.target_domain_id else None
        if not project_id or not loc['host'] or not loc['port']:
            return {}
        product = oid + ('/udp' if loc['proto'] == 'udp' else '')
        row = (ProbeObservation.objects.filter(project_id=project_id, host=loc['host'], probe=openvas_scan.PROBE, kind=openvas_scan.OBS_KIND,
                                               product=product[:120], port=loc['port']).only('evidence').first())
        return row.evidence if row is not None and isinstance(row.evidence, dict) else {}
    except Exception:  # noqa: BLE001 - the stored observation only adds detail
        return {}


def _qod(vuln, obs):
    """``(qod, type)`` of an OpenVAS result: the stored observation's, else the head of the finding's description that the import wrote
    ("OpenVAS detection quality 30% (remote_banner_unreliable): ..."). ``(None, '')`` when neither says."""
    qod, qtype = obs.get('qod'), str(obs.get('qod_type') or '')
    if not isinstance(qod, int) or isinstance(qod, bool):
        found = re.match(r'OpenVAS detection quality (\d{1,3})% \(([a-z_]{1,40})\)', str(getattr(vuln, 'description', '') or ''))
        qod, qtype = (int(found.group(1)), found.group(2)) if found else (None, qtype)
    qtype = qtype if re.match(r'^[a-z_]{1,40}\Z', qtype or '') and qtype != 'unknown' else ''
    return qod, qtype


def qod_level(qod, qtype):
    """``hard`` (OpenVAS tested it itself), ``banner`` (read from a banner or a binary), ``inferred`` (a guess) or '' (not said)."""
    if qod is None:
        return ''
    if qtype in HARD_QOD or (not qtype and qod >= 95):
        return 'hard'
    if qtype in BANNER_QOD or (not qtype and qod >= 70):
        return 'banner'
    return 'inferred'


def qod_words(qod, qtype):
    """What a quality of detection means for the version OpenVAS reports, in plain words."""
    level = qod_level(qod, qtype)
    if not level:
        return 'OpenVAS did not say how sure it is: treat the version as a claim to check.'
    shown = f'QoD {qod}%' + (f', {qtype}' if qtype else '')
    if level == 'hard':
        return f'{shown}: OpenVAS tested this itself (a remote check or an authenticated package check).'
    if level == 'banner':
        return (f'{shown}: OpenVAS read this version from a banner or a binary. A distribution backports fixes without raising the version, '
                'so it is not proof.')
    return f'{shown}: OpenVAS inferred this version; it was not read from the service. It is a guess, not proof.'


def _openvas_product(name, cpe_product):
    head = re.split(r'\s*(?:<|>|=|\(|\bmultiple\b|\bvulnerabilit)', str(name or ''), maxsplit=1, flags=re.IGNORECASE)[0]
    for pattern, label, key in OPENVAS_PRODUCTS:
        if pattern.search(head) or (cpe_product and pattern.search(cpe_product)):
            return label, key
    return '', ''


def _branch(version):
    return '.'.join(str(version).split('.')[:2])


def _openvas_local(product, key, hint, cve_ids):
    """The on-host commands for an OpenVAS version check: the binary's own version, the loaded extensions (PHP), the installed package and
    its changelog lines for these CVEs (Red Hat backports fixes without raising the version)."""
    from cveFeed.detection_classes import os_package_name
    local = []
    version_cmd = cg._host_version_step(key)
    if version_cmd:
        local.append({'title': 'On the host: the version of the installed binary', 'commands': [version_cmd]})
    if key == 'php':
        local.append({'title': 'On the host: the loaded PHP extensions', 'commands': [
            {'platform': 'linux', 'command': 'php -m',
             'explain': 'Lists the extensions PHP loads. Several PHP flaws sit in one extension (the advisory of each CVE names it): a flaw in an '
                        'extension the host does not load cannot be reached. The web server\'s PHP (php-fpm or the Apache module) normally loads the '
                        'same list; php-fpm -m prints its own.'}]})
    families = [t[3] for t in cg.TRACKERS if t[0].search(hint or '')] or ['dpkg', 'rpm']
    commands = []
    for eco in dict.fromkeys(families):
        name = os_package_name(key, eco)
        if not name:
            continue
        if eco == 'dpkg':
            if key == 'php':
                commands.append({'platform': 'debian', 'command': "dpkg -l 'php*' | grep '^ii'",
                                 'explain': 'Lists the installed PHP packages with their release (Debian and Ubuntu name them by version, php7.4, '
                                            'php8.1, ...). Compare each with the fixed release the distribution\'s tracker lists, not with the upstream version.'})
            else:
                commands.append({'platform': 'debian', 'command': f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {cg._q(name)}",
                                 'explain': f'Prints the installed {name} package release (Debian and Ubuntu). Compare it with the fixed release '
                                            'the distribution\'s tracker lists, not with the upstream version.'})
        elif eco == 'rpm':
            name = 'php-common' if key == 'php' else name  # every PHP install on Red Hat has php-common; php alone is only the Apache module
            commands.append({'platform': 'rhel', 'command': f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}}\\n' {cg._q(name)}",
                             'explain': f'Prints the installed {name} version-release (Red Hat, SUSE). Compare it with the fixed build in the vendor\'s '
                                        'advisory, not with the upstream version.'})
            if cve_ids:
                grep = ' '.join(f'-e {cg._q(c)}' for c in cve_ids[:8])
                commands.append({'platform': 'rhel', 'command': f'rpm -q --changelog {cg._q(name)} | grep -F {grep}',
                                 'explain': f'Prints the changelog lines of the installed {name} package that name these CVEs: a line means this '
                                            'build carries that fix, whatever version it reports (Red Hat backports fixes).'})
        elif eco == 'apk':
            commands.append({'platform': 'alpine', 'command': f'apk info -v {cg._q(name)}', 'explain': f'Prints the installed {name} package.'})
    if commands:
        local.append({'title': 'On the host: the installed package (a backported fix keeps the old upstream version)', 'commands': commands})
    return local


def _openvas_remote(product, key, loc):
    """A remote step that means something for this product: the response headers of a web runtime or server (a hint only), the SSH greeting,
    else a version scan of the port."""
    token = next((t for pattern, t in cg.HEADER_TOKENS if pattern.search(product)), '')
    if key in ('php', 'apache http server', 'nginx', 'lighttpd') and loc['proto'] == 'tcp':
        url = _web_url(loc)
        if url:
            header = 'X-Powered-By' if key == 'php' else 'Server'
            return cg._step(f'Hint only: read the {header} header', f'HEAD request. A site running {product} may send "{header}: {token}/x.y.z"; '
                            'most production sites hide it, a load balancer or CDN may answer instead of the server behind it, and a distribution '
                            'build keeps the upstream number after a backport. Its absence proves nothing and its presence is no verdict: the '
                            'on-host commands below decide.',
                            f"curl -gsS -I --max-time 15 {cg._q(url)} | grep -i -E '^(server|x-powered-by):'")
    if key == 'openssh' and loc['port'] and loc['proto'] == 'tcp':
        return cg._step('Read the SSH greeting', 'The first line the server sends states the OpenSSH version and, after it, the distribution build.',
                        f"nc -w 5 {cg._q(loc['host'])} {loc['port']} </dev/null | head -n 1")
    return _nmap(loc)


def _openvas(vuln, loc, advice):
    oid = str(vuln.template_id or '')[len('openvas:'):]
    oid = oid if cg._OID.match(oid) else ''
    obs = _openvas_observation(vuln, oid, loc) if oid else {}
    qod, qtype = _qod(vuln, obs)
    nvt = str(obs.get('name') or re.sub(r'^OpenVAS:\s*', '', str(vuln.name or '')))
    result = '\n'.join(str(x) for x in (vuln.extracted_results or [])[:3]) or str(obs.get('result') or '')
    from cveFeed.openvas_scan import identified
    seen = identified({'cpe': obs.get('cpe') or '', 'result': result})
    product, key = _openvas_product(nvt, seen.get('product'))
    installed = cg._version(seen.get('installed_version'))
    fixed = list(dict.fromkeys(v for v in [cg._version(seen.get('fixed_version'))] + _versions(nvt) if v))
    cves = _cve_ids(vuln)
    banner = _host_banner(vuln)
    hint = banner + ' ' + str(obs.get('cpe') or '')
    port = f"{loc['port']}/{loc['proto']}" if loc['port'] else ''
    where = [{'label': 'Host and port (as OpenVAS reported it)', 'text': f"{cg._bracket(loc['host'])}:{port}" if port else loc['host']}] if loc['host'] else []
    if banner:
        where.append({'label': 'Web server banner cvENGINE recorded for this host (seen on the host)', 'quote': banner})
    look_for = []
    if oid:
        look_for.append({'label': 'OpenVAS test (NVT) OID', 'text': oid})
    if nvt:
        look_for.append({'label': 'Test name (feed text)', 'quote': cg._quote(nvt, 200)})
    if result:
        look_for.append({'label': 'What OpenVAS reported (seen on the host)', 'quote': _block(result, 400)})
    if installed or fixed:
        look_for.append({'label': 'Version OpenVAS claimed', 'text': ' / '.join(x for x in (
            f'installed {installed}' if installed else '', f"fixed in {', '.join(fixed)}" if fixed else '') if x)})
    look_for.append({'label': 'How sure OpenVAS is', 'text': qod_words(qod, qtype)})
    if cves:
        look_for.append({'label': 'CVEs the test names', 'text': ', '.join(cves)})
    if obs.get('insight'):
        look_for.append({'label': 'What the test says the flaws are (feed text)', 'quote': cg._quote(obs.get('insight'), 500)})
    steps = [_openvas_remote(product, key, loc)] if product else [_nmap(loc)]
    if not product:
        steps.append(cg._step('Open the result in Greenbone', 'Scans > Results, filtered on the OID above and this host: the Detection Result and '
                              'Insight sections say what the test saw and how.', run_in='browser'))
        steps += _advice_steps(advice)
    local = _openvas_local(product, key, hint, cves) if key else []
    links = []
    if oid:
        links.append({'label': f'Greenbone SecInfo page of NVT {oid} (the newest tests may not be listed yet)', 'url': GREENBONE_NVT.format(oid=oid)})
    links += _tracker_links(cves, hint)
    name = product or 'the product'
    notes = []
    if qod_level(qod, qtype) == 'inferred':
        notes.append('OpenVAS inferred this version; it was not read from the service. Confirm it on the host before acting on it.')
    if product and banner and key in ('php', 'apache http server', 'nginx', 'lighttpd'):
        token = next((t for pattern, t in cg.HEADER_TOKENS if pattern.search(product)), product)
        if token.lower() not in banner.lower():
            notes.append(f'The web server banner cvENGINE recorded for this host (above) does not name {product}: nothing seen from outside shows '
                         f'{product} on this port.')
    tracker = next((t for t in cg.TRACKERS if t[0].search(hint)), None)
    if tracker:
        notes.append(f'The banner names {tracker[1]}: a {tracker[1]} package can carry a backported fix while it reports the old upstream version. '
                     'Its security tracker and the package changelog decide.')
    if installed and fixed and _branch(installed) not in {_branch(f) for f in fixed}:
        notes.append(f'{installed} is not on any release line the test names ({", ".join(_branch(f) + ".x" for f in fixed)}): upstream no longer '
                     f'fixes the {_branch(installed)} line, so only a distribution that still supports it can carry these fixes.')
    if fixed:
        affected = (f'On the host, {name} reports a version below the fixed release of its line ({", ".join(fixed)}) and its distribution package '
                    'carries no backported fix for these CVEs (the tracker lists the package as affected, or its changelog does not name them): affected.')
        not_affected = (f'{name[0].upper() + name[1:]} is not installed or does not serve this port, or it reports a fixed release of its line '
                        f'({", ".join(fixed)}) or later, or the distribution package carries a backported fix (its tracker lists your package release as '
                        'fixed, or the changelog names the CVE): not affected.')
    else:
        affected = 'A new OpenVAS scan reports the result again and the on-host check agrees: affected.'
        not_affected = 'A new scan no longer reports the result, or the on-host check shows a fixed version or package: not affected.'
    guide = {'class': 'openvas', 'class_label': 'OpenVAS (Greenbone) result' + (': version check' if product else ''),
             'headline': (f'Confirm {product} {installed} on {cg._bracket(loc["host"])}' + (f':{loc["port"]}' if loc['port'] else '')).replace('  ', ' ')
             if product else f'Confirm the OpenVAS result on {loc["text"] or "this host"}',
             'where': where, 'look_for': look_for, 'steps': steps,
             'verdict': {'fixed': ', '.join(fixed), 'affected': affected, 'not_affected': not_affected,
                         'cant_tell': 'The on-host commands cannot be run (ask the host\'s owner to run them), or a load balancer or CDN answers on this '
                                      'port and the server behind it is not known.', 'notes': notes},
             'local': local, 'links': links, 'links_title': 'Trackers and references',
             'fix': (f'Upgrade {name} to {fixed[0]} or later' + (f' ({", ".join(fixed[1:])} on their release lines)' if fixed[1:] else '')
                     + f', or install your distribution\'s fixed {name} package (its tracker names the build); then let OpenVAS scan the host again.'
                     if fixed else 'Apply the fix the OpenVAS result names (the Fix section above), then let OpenVAS scan the host again.'),
             'oid': oid}
    return guide


# --- nuclei ----------------------------------------------------------------------------------------------------------------------------

def _template_path(raw):
    """The template's path inside the nuclei-templates repository (``http/cves/2021/CVE-2021-44228.yaml``), or '' (an absolute path on the
    scanner keeps only the part after its nuclei-templates folder)."""
    text = str(raw or '').strip().replace('\\', '/')
    if 'nuclei-templates/' in text:
        text = text.split('nuclei-templates/', 1)[1]
    return text if _TEMPLATE_PATH.match(text) and '..' not in text and not text.startswith('/') else ''


def _template_link(vuln, template_id, path):
    url = vuln.template_url[0] if isinstance(vuln.template_url, (list, tuple)) and vuln.template_url else vuln.template_url
    url = cg._url(url)
    if url and urlsplit(url).scheme == 'https' and (urlsplit(url).hostname or '') in _TEMPLATE_HOSTS:
        return {'template_url': url}
    if path:
        return {'template_url': f'https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}'}
    return {'template_search_url': f'https://github.com/projectdiscovery/nuclei-templates/search?q={template_id}'}


def stored_request(text):
    """``(method, path, headers, has_body)`` of a stored HTTP request excerpt (its first line and headers), or None when it is not one."""
    lines = str(text or '').replace('\r\n', '\n').split('\n')
    first = re.match(r'^([A-Z]{3,10}) (\S{1,2000}) HTTP/[0-9.]{1,3}\s*\Z', lines[0].strip()) if lines else None
    if not first:
        return None
    headers, body = [], False
    for index, line in enumerate(lines[1:], 1):
        if not line.strip():
            body = any(rest.strip() for rest in lines[index + 1:])
            break
        name, sep, value = line.partition(':')
        if sep:
            headers.append((name.strip(), value.strip()))
    return first.group(1), first.group(2), headers, body


def _repeat_request(vuln, matched):
    """A curl that repeats the stored request: a GET or HEAD with no body only, to the matched host, carrying only harmless headers (the
    credentials and cookies of an authenticated scan are left out and said so). ``(step, read_only, note)``."""
    parsed = stored_request(vuln.request)
    if parsed is None or not matched:
        return None, None, ''
    method, path, headers, body = parsed
    if method not in ('GET', 'HEAD') or body:
        return None, False, (f'The scan sent a {method} request' + (' with a body' if body else '') + ': it is not turned into a command here, '
                             'because it may change something on the host. Read the request excerpt below.')
    parts = urlsplit(matched)
    target = path if path.startswith('/') else ''
    if path.startswith(('http://', 'https://')):
        target_url = cg._url(path)
    else:
        target_url = cg._url(f'{parts.scheme}://{parts.netloc}{target}') if target else ''
    if not target_url or urlsplit(target_url).hostname != parts.hostname:
        return None, True, 'The stored request path could not be checked as a URL on this host, so no command is built from it.'
    options = ['-I' if method == 'HEAD' else '-i']
    secret = []
    for name, value in headers:
        low = name.lower()
        if low in _SECRET_HEADERS:
            secret.append(name)
        elif low in _SAFE_HEADERS and _HEADER_NAME.match(name) and _HEADER_VALUE.match(value):
            options.append(f'-H {cg._q(name + ": " + value)}')
    detail = (f'Repeats the {method} request the scan stored. Its reply should contain what the matcher looked for (above).'
              + (f' The scan also sent {", ".join(sorted(set(secret)))} (left out here): a page behind a login needs your own session to answer the same way.'
                 if secret else ''))
    command = f"curl -gsS {' '.join(options)} --max-time 15 {cg._q(target_url)}" + ('' if method == 'HEAD' else ' | head -c 4000')
    return cg._step('Repeat the request the scan sent', detail, command), True, ''


def _nuclei(vuln, loc, advice):
    template_id = str(vuln.template_id or '')
    template_id = template_id if cg._TEMPLATE.match(template_id) else ''
    path = _template_path(vuln.template)
    generated = str(vuln.source or '') == 'nuclei-cve'  # written by cvENGINE and kept on this server: no public link, nuclei elsewhere cannot find it
    matched = loc['url']
    where = _where(loc, 'Matched at')
    look_for = []
    if template_id:
        look_for.append({'label': 'Template', 'text': template_id + (f' ({path})' if path else '')})
    look_for += _scanner_said(vuln, 'What the template extracted (seen on the host)')
    cves = _cve_ids(vuln)
    if cves:
        look_for.append({'label': 'CVEs the template names', 'text': ', '.join(cves)})
    repeat, read_only, note = _repeat_request(vuln, matched)
    steps = [repeat] if repeat else []
    if not repeat and matched:
        steps.append(cg._step('Open the matched URL', note or 'A GET in your browser: compare the page with what the matcher looked for (above).',
                              run_in='browser', url=matched))
    elif not repeat:
        steps.append(_nmap(loc))
    steps = [s for s in steps if s]
    template = {'template_id': template_id or cg._quote(vuln.template_id, 80), 'result': 'matched'}
    if template_id and not generated:
        template.update(_template_link(vuln, template_id, path))
    elif generated:
        template['generated'] = True
    target = matched or (f"{cg._bracket(loc['host'])}:{loc['port']}" if loc['host'] and loc['port'] else '')
    if template_id and target and not generated:
        selector = f'-t {cg._q(path)}' if path else f'-id {cg._q(template_id)}'
        # not read-only in general: a template may send more than the request the scan stored; -ni keeps it off out-of-band callback servers
        template['command'] = f'nuclei -duc -ni {selector} -u {cg._q(target)}'
        template['active'] = ('Active check: sends the template\'s own requests to this host. '
                              + ('The request the scan stored was a plain read, but a template can send more than one request. ' if read_only else
                                 'The stored request was not a plain read (see the excerpt). ' if read_only is False else '')
                              + 'Run it only where you are allowed to test.')
    if matched:
        template['matched_at'] = matched
    if vuln.matcher_name:
        template['matcher'] = cg._quote(vuln.matcher_name, 120)
    extracted = _extracted(vuln)
    if extracted:
        template['extracted'] = extracted
    if vuln.request:
        template['request'] = _block(cg._redact_request(vuln.request), 1200)
    notes = [note] if note and repeat is None and read_only is not None else []
    return {'class': 'nuclei', 'class_label': 'nuclei template match' + (' (template written by cvENGINE)' if generated else ''),
            'headline': f'Confirm {template_id or "the template match"} on {loc["text"] or "this host"}',
            'where': where, 'look_for': look_for, 'steps': steps or _advice_steps(advice),
            'verdict': {'fixed': '', 'affected': 'The reply contains what the matcher looked for again (the matcher and extracted values above): the '
                                                 'finding stands.',
                        'not_affected': 'The reply no longer contains it, or the page now answers 404, a redirect or a login page: not reproduced. '
                                        'A rescan closes the finding.',
                        'cant_tell': 'A WAF or CDN answers instead of the server, the page needs a login the scan had, or the reply changes from one '
                                     'request to the next: re-run the template from a machine allowed to test, or check the server behind the front end.',
                        'notes': notes},
            'template': template, 'local': [],
            'fix': 'Apply the fix the template names (the Fix section above), then rescan the host.'}


# --- WPScan ----------------------------------------------------------------------------------------------------------------------------

_WP_COMPONENT = re.compile(r'^WordPress (plugin|theme) ([A-Za-z0-9._-]{1,80})( outdated)?\Z')


def _wp_observation(vuln, host, probe, product):
    try:
        from cveFeed.models import ProbeObservation
        project_id = vuln.target_domain.project_id if vuln.target_domain_id else None
        if not project_id or not host:
            return None
        return ProbeObservation.objects.filter(project_id=project_id, host=host, probe=probe, product=product).only('version', 'evidence').first()
    except Exception:  # noqa: BLE001
        return None


def _wpscan(vuln, loc, advice):
    component = str(vuln.template_id or '')[len('wpscan:'):]
    found = _WP_COMPONENT.match(component)
    core = re.match(r'^WordPress( outdated)?\Z', component)
    if not found and not core:
        return None  # users, timthumb and the other interesting findings: the generic guide (where, what the scan reported, a page read)
    kind = found.group(1) if found else 'core'
    slug = found.group(2).lower() if found else ''
    slug = slug if not slug or (cg._SLUG.match(slug) and '..' not in slug) else ''
    label = f'WordPress {kind} {found.group(2)}' if found else 'WordPress'
    said = re.match(re.escape(label) + r' ([0-9][0-9A-Za-z.+~_-]{0,63})', str(vuln.name or ''))
    obs = _wp_observation(vuln, loc['host'], {'plugin': 'wpscan-plugin', 'theme': 'wpscan-theme', 'core': 'wpscan-core'}[kind], slug or 'WordPress')
    version = cg._version(said.group(1) if said else '') or cg._version(getattr(obs, 'version', ''))
    fixed_text = re.search(r'Fixed in ([0-9][0-9A-Za-z.+~_-]{0,63}?)\.?(?:\s|\Z)', str(vuln.description or ''))
    fixed = cg._version(fixed_text.group(1)) if fixed_text else ''
    found_by = cg._quote(((getattr(obs, 'evidence', None) or {}) if isinstance(getattr(obs, 'evidence', None), dict) else {}).get('found_by'), 80)
    base = (_web_url(loc, '') or '').rstrip('/')
    look_for = []
    steps = []
    local = []
    if kind in ('plugin', 'theme') and slug:
        rel = f'/wp-content/themes/{slug}/style.css' if kind == 'theme' else f'/wp-content/plugins/{slug}/readme.txt'
        url = cg._url(base + rel) if base else ''
        field = 'Version' if kind == 'theme' else 'Stable tag'
        file = 'style.css' if kind == 'theme' else 'readme.txt'
        where = [{'label': f'The {kind}\'s {file}', 'url': url}] if url else _where(loc, 'The site')
        look_for.append({'label': 'The line to read', 'text': f'{field}: {version or "x.y.z"}'})
        if url:
            steps.append(cg._step(f'Open the {kind}\'s {file}', f'The "{field}:" line states the version the WordPress scan read.', run_in='browser', url=url))
            steps.append(cg._step('Or read that line from a shell', 'One GET request.',
                                  f"curl -gsS --max-time 15 {cg._q(url)} | grep -i -m1 -E {cg._q('^[[:space:]]*' + field + ':')}"))
        local.append({'title': 'On the WordPress server (WP-CLI, read-only)', 'commands': [
            {'platform': 'app', 'command': f'wp {kind} get {cg._q(slug)} --fields=name,status,version',
             'explain': f'Prints whether the {kind} is installed and active, and its version (run in the WordPress directory). It is the authority '
                        'when the readme lags the code.'}]})
        subject, reader = f'the {slug} {kind}', f'The {kind}\'s {field} line (or WP-CLI)'
    else:
        front = cg._url(base + '/') if base else ''
        feed = cg._url(base + '/feed/') if base else ''
        where = [{'label': 'The site', 'url': front}] if front else _where(loc, 'The site')
        look_for.append({'label': 'What states the version', 'text': f'<meta name="generator" content="WordPress {version or "x.y.z"}" /> '
                                                                     f'or https://wordpress.org/?v={version or "x.y.z"}'})
        if front:
            steps.append(cg._step('Read the generator tag of the front page', 'WordPress states its version there unless a plugin removes it.',
                                  f"curl -gsS --max-time 15 {cg._q(front)} | grep -o -i -E {cg._q('<meta name=.generator. content=.WordPress [0-9.]+')}"))
        if feed:
            steps.append(cg._step('Or read the feed\'s generator line', '',
                                  f"curl -gsS --max-time 15 {cg._q(feed)} | grep -o -E {cg._q('wordpress.org/[?]v=[0-9.]+')}"))
        local.append({'title': 'On the WordPress server (WP-CLI, read-only)', 'commands': [
            {'platform': 'app', 'command': 'wp core version', 'explain': 'Prints the installed WordPress version (run in the WordPress directory).'}]})
        subject, reader = 'WordPress', 'The generator tag (or WP-CLI)'
    look_for.append({'label': 'Version the WordPress scan read', 'text': version or 'not stated'})
    if found_by:
        look_for.append({'label': 'How the scan read it (scanner text)', 'quote': found_by})
    if fixed:
        look_for.append({'label': 'Fixed in', 'text': fixed})
    cves = _cve_ids(vuln)
    if cves:
        look_for.append({'label': 'CVEs', 'text': ', '.join(cves)})
    outdated = component.endswith(' outdated')
    return {'class': 'wpscan', 'class_label': f'WordPress {kind}' + (' (WordPress scan)' if kind != 'core' else ' core (WordPress scan)'),
            'headline': f'Confirm {subject} {version} on {loc["host"]}'.replace('  ', ' '), 'where': where, 'look_for': look_for, 'steps': steps,
            'verdict': {'fixed': fixed,
                        'affected': (f'{reader} states {version or "the version above"}, or any version before {fixed}: affected.' if fixed else
                                     f'{reader} states {version or "the version above"}' + (', older than the latest release: outdated.' if outdated else
                                                                                            ': the version the scan reported is still installed.')),
                        'not_affected': (f'It states {fixed} or later' if fixed else 'It states a newer version') +
                                        (f', or the {kind} is gone (the file answers 404) or inactive' if kind != 'core' else '') + ': not affected.',
                        'cant_tell': (f'The file is missing or hidden, or its {"Stable tag" if kind == "plugin" else "Version"} says "trunk": check the '
                                      f'version with WP-CLI or on the {kind.title()}s page of the WordPress admin.' if kind != 'core' else
                                      'The generator tag is removed: check Dashboard > Updates, or wp-includes/version.php on the server.')},
            'local': local,
            'fix': (f'Update {subject} to {fixed} or later in the WordPress admin' + (f' (or with wp {kind} update {slug})' if slug else ' (or wp core update)')
                    + ', then rescan.' if fixed else f'Update {subject} to its latest release, or remove it if it is not needed, then rescan.')}


# --- any other source ------------------------------------------------------------------------------------------------------------------

def _generic(vuln, loc, advice):
    where = _where(loc)
    look_for = _scanner_said(vuln)
    template_id = str(vuln.template_id or '')
    if template_id:
        look_for.insert(0, {'label': 'Check that fired (scanner text)', 'quote': cg._quote(template_id, 120)})
    cves = _cve_ids(vuln)
    if cves:
        look_for.append({'label': 'CVEs', 'text': ', '.join(cves)})
    steps = []
    if loc['url']:
        steps.append(cg._step('Fetch the page the scanner flagged', 'One GET request: the status line, the headers and the start of the page. Compare '
                              'them with what the scanner reported (above).', f"curl -gsS -i --max-time 15 {cg._q(loc['url'])} | head -c 4000"))
    elif loc['scheme'] == 'ssh' and loc['port']:
        steps.append(cg._step('Read the SSH greeting', 'The first line the server sends.',
                              f"nc -w 5 {cg._q(loc['host'])} {loc['port']} </dev/null | head -n 1"))
    else:
        steps.append(_nmap(loc))
    steps += _advice_steps(advice)
    source = cg._quote(vuln.source or 'the scanner', 40)
    return {'class': 'scanner', 'class_label': f'Scanner finding ({source})', 'headline': f'Confirm this finding on {loc["text"] or "the host"}',
            'where': where, 'look_for': look_for, 'steps': steps,
            'verdict': {'fixed': '', 'affected': 'The same page or service answers again with what the scanner reported (above): the finding stands.',
                        'not_affected': 'The page or port no longer answers, or answers without what the scanner reported: not reproduced. A rescan '
                                        'closes the finding.',
                        'cant_tell': 'A WAF, CDN or load balancer answers instead of the server, or the check needs access the scan had: ask the host\'s '
                                     'owner to confirm on the host.'},
            'local': [], 'fix': f'Apply the fix the scanner names (the Fix section above), then rescan {loc["host"] or "the host"}.'}


def scanner_guide(vuln, advice=()):
    """The confirm guide of one scanner finding (startScan.Vulnerability, its subdomain and target loaded), by its source. ``advice`` is the AI
    review's ``validation_notes`` as the finding page may show them. Never None: at least where it was found and what the scanner reported."""
    sub = getattr(vuln, 'subdomain', None)
    loc = _location(vuln.http_url, sub.name if sub is not None else (vuln.target_domain.name if vuln.target_domain_id else ''))
    source = str(vuln.source or '').lower()
    template_id = str(vuln.template_id or '')
    guide = None
    if source == 'openvas' or template_id.startswith('openvas:'):
        guide = _openvas(vuln, loc, advice)
    elif source == 'wpscan' or template_id.startswith('wpscan:'):
        guide = _wpscan(vuln, loc, advice)
    elif source.startswith('nuclei') or (source in ('', 'auth-nuclei') and vuln.request and cg._TEMPLATE.match(template_id)):
        guide = _nuclei(vuln, loc, advice)
    if guide is None:
        guide = _generic(vuln, loc, advice)
    return _finish(guide, loc)


# --- hygiene ---------------------------------------------------------------------------------------------------------------------------

def _dig(name, rtype, title, detail):
    host = cg._host(name)
    if not host or cg._is_ip(host):
        return None
    return cg._step(title, detail, f'dig +short {rtype} {cg._q(host)}')


def _cert_steps(host, port, check):
    target = f'{cg._bracket(host)}:{port}'
    sni = '' if cg._is_ip(host) else f' -servername {cg._q(host)}'
    starttls = {25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp'}.get(port)
    connect = f'openssl s_client{f" -starttls {starttls}" if starttls else ""} -connect {cg._q(target)}{sni}'
    if check == 'tls_legacy_protocol':
        return [cg._step('Offer only TLS 1.1', 'A completed handshake (a certificate printed, "Protocol : TLSv1.1") means the server still accepts it; '
                         '"no protocols available", "unsupported protocol" or an alert means it refuses. Repeat with -tls1 for TLS 1.0. Only a '
                         'handshake is sent.', f'{connect} -tls1_1 </dev/null 2>&1 | grep -E -i "protocol|alert|error" | head -n 5'),
                cg._step('Or list every protocol and cipher with nmap', 'The ssl-enum-ciphers script lists the protocols the server accepts.',
                         f"nmap -Pn {'-6 ' if ':' in host else ''}--script ssl-enum-ciphers -p {port} {cg._q(host)}")]
    fields = {'tls_hostname_mismatch': '-subject -ext subjectAltName', 'tls_weak_key': '-text', 'tls_weak_signature': '-text'}.get(
        check, '-dates -subject -issuer')
    grep = {'tls_weak_key': " | grep -E 'Public-Key|Public Key Algorithm'", 'tls_weak_signature': " | grep -m1 'Signature Algorithm'"}.get(check, '')
    steps = [cg._step('Read the certificate the server presents', {
        'tls_expired': 'notAfter is the expiry date: a date in the past confirms it.',
        'tls_expiring': 'notAfter is the expiry date: compare it with today.',
        'tls_hostname_mismatch': f'The subject and the subjectAltName list: {host} (or a wildcard covering it) missing from both confirms it.',
        'tls_weak_key': 'The Public-Key line states the key size: an RSA key under 2048 bits confirms it.',
        'tls_weak_signature': 'The Signature Algorithm line: sha1 or md5 confirms it.',
    }.get(check, 'Prints the validity dates, the subject and the issuer of the certificate the server sends.'),
        f'{connect} </dev/null 2>/dev/null | openssl x509 -noout {fields}{grep}')]
    if check in ('tls_self_signed', 'tls_untrusted_chain'):
        steps = [cg._step('Ask openssl to verify the chain', '"Verify return code: 0 (ok)" means the chain is trusted; "self-signed certificate" or '
                          '"unable to get local issuer certificate" confirms the finding.',
                          f'{connect} -showcerts </dev/null 2>&1 | grep -E "Verify return code|^ *[0-9] s:|^ *i:"')]
    return steps


def _hygiene_where(f):
    """``(host, port)`` of a hygiene finding: a certificate finding's host is ``name:port``; a cleartext one names its port in the evidence."""
    from cveFeed import tls_catalogue
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    name, port = tls_catalogue.split_where(f.host)
    return cg._host(name), cg._port(port) or cg._port(ev.get('port'))


def hygiene_guide(f, advice=()):
    """The confirm guide of a hygiene finding that is not a TLS audit result (those use ``tls_catalogue.guide``): a read-only check per family.
    Never None."""
    check = str(f.check_name or '')
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    host, port = _hygiene_where(f)
    loc = {'url': '', 'scheme': '', 'host': host, 'port': port, 'proto': str(ev.get('protocol') or 'tcp').lower() if ev.get('protocol') in ('tcp', 'udp') else 'tcp',
           'text': (f'{cg._bracket(host)}:{port}' if port else host)}
    where = [{'label': 'Where it was found', 'text': loc['text']}] if host else []
    look_for = []
    for key in ('record', 'records', 'banner', 'error', 'names', 'not_after', 'days_left', 'signature', 'key', 'selector', 'bits', 'lookups', 'urls',
                'service', 'product', 'version', 'exposure'):
        value = ev.get(key)
        if value in (None, '', [], {}):
            continue
        text = ', '.join(str(v) for v in value[:8]) if isinstance(value, list) else str(value)
        look_for.append({'label': f'{key.replace("_", " ").capitalize()} (as cvENGINE recorded it)', 'quote': cg._quote(text, 300)})
    steps, verdict = [], {}
    if check.startswith(('tls_', 'cert_')) and host and (port or check.startswith('tls_')):
        steps = _cert_steps(host, port or 443, check)
        verdict = {'affected': 'The certificate or handshake shows what the finding says (above): it stands.',
                   'not_affected': 'The certificate the server sends now is renewed, covers the name, is trusted or strong, or the old protocol is refused: '
                                   'fixed. The next hygiene run closes it.'}
    elif check.startswith('spf_'):
        steps = [_dig(host, 'TXT', 'Read the domain\'s SPF record', 'The line starting "v=spf1" is the record; its last term (-all, ~all, ?all, +all) '
                      'decides what receivers do with other senders. No such line means there is no SPF record.')]
        verdict = {'affected': 'The record reads as the finding says (missing, more than one, or ending as described): it stands.',
                   'not_affected': 'One v=spf1 record that ends in -all (or ~all while you roll out) and needs at most 10 lookups: fixed.'}
    elif check.startswith('dmarc_'):
        steps = [_dig('_dmarc.' + host if host else '', 'TXT', 'Read the domain\'s DMARC record', 'The line starting "v=DMARC1" is the policy: p= is '
                      'what receivers do with failing mail, rua= where reports go. No answer means there is no DMARC record (a parent domain\'s '
                      'record may still apply to a subdomain).')]
        verdict = {'affected': 'The record is missing or reads as the finding says: it stands.',
                   'not_affected': 'One v=DMARC1 record with p=quarantine or p=reject (and a rua address): fixed.'}
    elif check.startswith('dkim_'):
        name = host if '._domainkey.' in host else (f"{ev.get('selector')}._domainkey.{host}" if cg._SLUG.match(str(ev.get('selector') or '')) else '')
        steps = [_dig(name, 'TXT', 'Read the DKIM key record', 'The p= value is the public key; a longer value is a longer key (about 400 characters for '
                      '2048 bits). Selectors are arbitrary names: ask the mail provider which selector it signs with.')] if name else [
            cg._step('Find the selector your mail is signed with', 'Open the headers of a message the domain sent: the DKIM-Signature header names '
                     'the selector (s=) and the domain (d=). Then read that key with dig TXT <selector>._domainkey.<domain>.', run_in='manual')]
        verdict = {'affected': 'No key on the selector the mail is signed with, or a short key: it stands.',
                   'not_affected': 'Outgoing mail carries a DKIM-Signature whose key is 2048 bits: fixed (or the finding was a selector cvENGINE could not guess).'}
    elif check.startswith('caa_'):
        steps = [_dig(host, 'CAA', 'Read the domain\'s CAA records', 'Each line names an authority allowed to issue certificates. No answer means no CAA '
                      'record (a parent domain\'s record may apply).')]
        verdict = {'affected': 'No CAA record: it stands.', 'not_affected': 'A CAA record naming your certificate authority: fixed.'}
    elif check.startswith('mta_sts_'):
        policy = cg._url(f'https://mta-sts.{host}/.well-known/mta-sts.txt') if host and not cg._is_ip(host) else ''
        steps = [_dig('_mta-sts.' + host if host else '', 'TXT', 'Read the MTA-STS record', 'A "v=STSv1; id=..." line means a policy is published.'),
                 cg._step('Read the MTA-STS policy file', 'mode: enforce is the protected setting; testing only reports.',
                          f'curl -gsS --max-time 15 {cg._q(policy)}') if policy else None]
        verdict = {'affected': 'No record, no policy file, or mode: testing or none: it stands.', 'not_affected': 'A record and a policy in mode: enforce: fixed.'}
    elif check.startswith('hsts_'):
        url = cg._url(cg._base('https', host, port or 443) + '/') if host else ''
        steps = [cg._step('Read the Strict-Transport-Security header', 'HEAD request. No line means no HSTS; max-age is in seconds (six months is '
                          '15768000).', f"curl -gsS -I --max-time 15 {cg._q(url)} | grep -i '^strict-transport-security:'")] if url else []
        verdict = {'affected': 'No Strict-Transport-Security header, or a short max-age: it stands.',
                   'not_affected': 'The header with a max-age of six months or more: fixed.'}
    elif check == 'cleartext_ftp':
        ftp_port = port or 21
        if host:
            steps = [cg._step('Read the FTP greeting and ask for TLS', 'The first line is the greeting (220 ...). The reply to AUTH TLS decides: 234 means '
                              'the server offers TLS (FTPS), 500, 502 or 504 means it does not. No login is sent.',
                              f"printf 'AUTH TLS\\r\\nQUIT\\r\\n' | nc -w 5 {cg._q(host)} {ftp_port}"),
                     cg._step('Or try the TLS upgrade with openssl', 'A printed certificate means the server upgrades to TLS; "didn\'t find STARTTLS" or '
                              'an error means it does not.', f'openssl s_client -starttls ftp -connect {cg._q(cg._bracket(host) + ":" + str(ftp_port))} </dev/null 2>&1 | head -n 20')]
        verdict = {'affected': 'The server answers AUTH TLS with 500, 502 or 504 (no TLS): logins cross the network in clear text.',
                   'not_affected': 'The port is closed, or AUTH TLS answers 234 and the server requires it: fixed.'}
    elif check.startswith('cleartext_'):
        if check == 'cleartext_http_login':
            urls = [u for u in (cg._url(x) for x in (ev.get('urls') or [])[:3]) if u]
            steps = [cg._step('Read the login page over plain HTTP', 'HEAD request. A 200 answer (not a redirect to https://) means the login form is '
                              'served without encryption.', f'curl -gsS -I --max-time 15 {cg._q(u)}') for u in urls]
            verdict = {'affected': 'The page answers 200 over http://: it stands.', 'not_affected': 'The page redirects to https:// or is gone: fixed.'}
        else:
            steps = [_nmap(loc, 'See whether the service still answers', 'Prints whether the port is open and what answers (a version scan only).')]
            if host and port and check == 'cleartext_telnet':
                steps.append(cg._step('Or read the greeting', 'The first bytes the service sends: a login prompt confirms it. Nothing is typed.',
                                      f'nc -w 5 {cg._q(host)} {port} </dev/null | head -c 300'))
            verdict = {'affected': 'The port is open and the service answers: it stands.', 'not_affected': 'The port is closed or filtered: fixed.'}
    else:
        urls = [u for u in (cg._url(x) for x in ([ev.get('url')] + list(ev.get('urls') or []))[:2]) if u]
        steps = [cg._step('Fetch the page the finding names', 'One GET request: compare the answer with what cvENGINE recorded (above).',
                          f'curl -gsS -i --max-time 15 {cg._q(u)} | head -c 4000') for u in urls] or [_nmap(loc)]
        verdict = {'affected': 'The check shows what cvENGINE recorded (above) again: it stands.',
                   'not_affected': 'It no longer does: fixed. The next run of the check closes it.'}
    steps = [s for s in steps if s] + _advice_steps(advice)
    from cveFeed.report_data import CHECK_TEXT
    known = CHECK_TEXT.get(check)
    verdict.setdefault('affected', '')
    verdict.setdefault('not_affected', '')
    verdict.update(fixed='', cant_tell='A resolver, proxy or load balancer answers differently from what the outside world sees: ask from another '
                                        'network, or check the server itself.')
    return _finish({'class': 'hygiene', 'class_label': 'Configuration check', 'headline': f'Confirm "{cg._quote(f.title, 120)}"',
                    'where': where, 'look_for': look_for, 'steps': steps, 'verdict': verdict, 'local': [],
                    'fix': (known[2] if known else 'Apply the fix above, then let the hygiene check run again.')}, loc)


# --- an open web route, and the guide every finding falls back to ---------------------------------------------------------------------

def route_guide(r, advice=()):
    """The confirm guide of a web route that answered an anonymous GET (cveFeed.models.RouteAuth)."""
    url = cg._url(r.url)
    loc = _location(url, r.host)
    steps = [cg._step('Ask for the page without logging in', 'One GET request with no cookie: the status line and the start of the page. Run it from a '
                      'private window or a machine with no session on the site.', f'curl -gsS -i --max-time 15 {cg._q(url)} | head -c 4000')] if url else []
    return _finish({'class': 'route', 'class_label': 'Web route open without a login', 'headline': f'Confirm {cg._quote(r.path, 120) or "the page"} '
                    f'is open on {loc["host"] or "the host"}', 'where': _where(loc, 'The page'),
                    'look_for': [{'label': 'What cvENGINE saw', 'text': f'HTTP {r.http_status}, {str(r.auth_state or "").replace("_", " ")}'}],
                    'steps': steps + _advice_steps(advice),
                    'verdict': {'fixed': '', 'affected': 'The page answers 200 with its content: it is open to anyone.',
                                'not_affected': 'It answers 401 or 403, or redirects to a login page: closed.',
                                'cant_tell': 'A WAF or CDN answers with a challenge page: try from another network, or check the server\'s access rules.'},
                    'local': [], 'fix': 'Put the page behind a login, or remove it if nobody needs it, then let the route check run again.'}, loc)


def minimal_guide(title, host, advice=()):
    """The guide when nothing better can be built: where it is and the AI review's advice. Never fails, never empty."""
    name = cg._host(host)
    steps = _advice_steps(advice) or [cg._step('Compare the evidence above with the host', 'Read "How it was found" above and check the same '
                                              'thing on the host, or ask its owner to.', run_in='manual')]
    return {'class': 'finding', 'class_label': 'Finding', 'headline': f'Confirm {cg._quote(title, 160) or "this finding"}',
            'where': [{'label': 'Host', 'text': name}] if name else [], 'look_for': [], 'steps': steps, 'local': [],
            'verdict': {'fixed': '', 'affected': '', 'not_affected': '', 'cant_tell': ''}, 'fix': '', 'version': GUIDE_VERSION, 'notice': NOTICE}
