#!/usr/bin/env python3
"""Write a CycloneDX 1.5 software bill of materials for cvENGINE from the pins in this repository.

  python3 scripts/generate_sbom.py [--output cvengine.sbom.cdx.json]

It lists what a build is made of, read from the files that pin it: the scanner tools, the base image and the apt packages (web/Dockerfile), the Python
packages (web/requirements.txt) and the service images (docker-compose.yml). Nothing is downloaded and the output is reproducible: the
same commit gives the same document (the timestamp is the commit's). A component that is not pinned to an exact version (a floating
image tag, a version range, nuclei's templates) is listed with `cvengine:pinned` = `false` so a reader can see what the bill cannot vouch
for. What the finished image really contains (what the apt packages pull in, and the base image's own packages) is not in this file: scan the built
image for that, for example `syft cvengine/web:latest -o cyclonedx-json`. The release workflow attaches this file to every release."""
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOMOD = 'pkg:golang/github.com/projectdiscovery/{}@v{}'


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def arg(dockerfile, name):
    match = re.search(rf'(?m)^ARG {name}=(\S+)$', dockerfile)
    return match.group(1) if match else None


def component(name, version, purl, kind='application', hashes=(), pinned=True, note=None, url=None):
    item = {'type': kind, 'bom-ref': purl or f'{name}@{version or "unpinned"}', 'name': name}
    if version:
        item['version'] = version
    if purl:
        item['purl'] = purl
    if hashes:
        item['hashes'] = [{'alg': 'SHA-256', 'content': value} for value in hashes if value]
    if url:
        item['externalReferences'] = [{'type': 'website', 'url': url}]
    properties = [{'name': 'cvengine:pinned', 'value': 'true' if pinned else 'false'}]
    if note:
        properties.append({'name': 'cvengine:note', 'value': note})
    item['properties'] = properties
    return item


def tools(dockerfile):
    nmap, go = arg(dockerfile, 'NMAPVERSION'), arg(dockerfile, 'GOVERSION')
    out = [
        component('nmap', nmap, f'pkg:generic/nmap@{nmap}', hashes=[arg(dockerfile, 'NMAP_SHA256'), arg(dockerfile, 'NMAP_RPM_SHA256_AMD64')],
                  note='amd64: the official x86_64 release RPM; arm64: compiled from the release tarball (hashes: tarball, RPM)', url='https://nmap.org'),
        component('go', go, f'pkg:generic/go@{go}', hashes=[arg(dockerfile, 'GO_SHA256_AMD64'), arg(dockerfile, 'GO_SHA256_ARM64')],
                  note='build toolchain for nuclei and naabu (hashes: amd64, arm64)', url='https://go.dev'),
        component('nuclei', arg(dockerfile, 'NUCLEI_VERSION'), GOMOD.format('nuclei/v3', arg(dockerfile, 'NUCLEI_VERSION')),
                  url='https://github.com/projectdiscovery/nuclei'),
        component('naabu', arg(dockerfile, 'NAABU_VERSION'), GOMOD.format('naabu/v2', arg(dockerfile, 'NAABU_VERSION')),
                  url='https://github.com/projectdiscovery/naabu'),
        component('bbot', arg(dockerfile, 'BBOT_VERSION'), f'pkg:pypi/bbot@{arg(dockerfile, "BBOT_VERSION")}', url='https://github.com/blacklanternsecurity/bbot'),
        component('tzdata', arg(dockerfile, 'TZDATA_VERSION'), f'pkg:pypi/tzdata@{arg(dockerfile, "TZDATA_VERSION")}', kind='library', note='installed beside bbot'),
        component('wpscan', arg(dockerfile, 'WPSCAN_VERSION'), f'pkg:gem/wpscan@{arg(dockerfile, "WPSCAN_VERSION")}', url='https://github.com/wpscanteam/wpscan'),
        component('testssl.sh', arg(dockerfile, 'TESTSSL_VERSION'), f'pkg:github/testssl/testssl.sh@v{arg(dockerfile, "TESTSSL_VERSION")}',
                  hashes=[arg(dockerfile, 'TESTSSL_SHA256')], note='GPLv2, run as a separate program; the release tarball (hash: tarball)',
                  url='https://testssl.sh'),
        component('nuclei-templates', None, None, kind='data', pinned=False, note='refreshed at runtime, by design',
                  url='https://github.com/projectdiscovery/nuclei-templates'),
    ]
    base = re.search(r'(?m)^FROM ([\w.-]+):([\w.-]+)', dockerfile)
    if base:
        out.append(component(base.group(1), base.group(2), f'pkg:docker/{base.group(1)}@{base.group(2)}', kind='container',
                             pinned=False, note='a tag, not a digest: the operating system packages are those of the day the image was built'))
    return out


def apt_packages(dockerfile):
    """The operating system packages the Dockerfile asks apt for by name (not what they pull in, and not the version: apt installs the
    base release's current one, so they are listed unpinned). A package that is installed and purged in the same build is left out."""
    text = dockerfile.replace('\\\n', ' ')
    names = set()
    for match in re.finditer(r'apt-get install\s+([^&|;)\n]*)', text):
        names.update(word for word in match.group(1).split() if not word.startswith('-') and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', word))
    for match in re.finditer(r'apt-get purge\s+([^&|;)\n]*)', text):
        names.difference_update(match.group(1).split())
    base = re.search(r'(?m)^FROM ubuntu:([\w.-]+)', dockerfile)
    distro = f'ubuntu-{base.group(1)}' if base else 'ubuntu'
    return [component(name, None, f'pkg:deb/ubuntu/{name}?distro={distro}', kind='library', pinned=False,
                      note='installed with apt-get in web/Dockerfile; the version is the base release\'s on the day the image was built')
            for name in sorted(names)]


def python_packages(requirements):
    out = []
    for line in requirements.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith('-'):
            continue
        match = re.match(r'([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|<|>|!=)?\s*([^\s;]*)', line)
        if not match:
            continue
        name, operator, rest = match.groups()
        exact = operator == '==' and re.fullmatch(r'[0-9][\w.+!-]*', rest or '')
        item = component(name, rest if exact else None, f'pkg:pypi/{name.lower().replace("_", "-")}' + (f'@{rest}' if exact else ''),
                         kind='library', pinned=bool(exact), note=None if exact else f'range {line}')
        out.append(item)
    return out


def image_note(name):
    if name.startswith('registry.community.greenbone.net/'):
        return 'optional OpenVAS add-on feed image: a moving tag on purpose, so the vulnerability definitions keep updating (what it holds changes without a cvENGINE release)'
    return 'a moving tag, by design: refreshed with every update' if name == 'nginx' else 'a moving tag'


def service_images(compose):
    out, seen = [], set()
    for image in re.findall(r'(?m)^\s*image:\s*"?([^"\s]+)"?\s*$', compose):
        match = re.search(r'\$\{[A-Z_]+:-([^}]+)\}', image)
        image = match.group(1) if match else image
        if image in seen or image.startswith('cvengine/'):
            continue
        seen.add(image)
        image, _, digest = image.partition('@sha256:')  # a digest pin: the tag is a label, the digest is what runs
        name, _, tag = image.partition(':')
        tag = tag or 'latest'
        exact = bool(re.fullmatch(r'v?\d+(\.\d+){2,}', tag))
        out.append(component(name, tag.lstrip('v') if exact else tag, f'pkg:docker/{name}@{tag}', kind='container', pinned=exact or bool(digest),
                             hashes=[digest] if digest else (),
                             note=None if exact or digest else image_note(name)))
    return out


def commit_time():
    try:
        out = subprocess.run(['git', 'log', '-1', '--format=%ct'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        return datetime.fromtimestamp(int(out), timezone.utc)
    except (OSError, ValueError, subprocess.CalledProcessError):
        return datetime.fromtimestamp(0, timezone.utc)


def build():
    version = read('web/.version').strip()
    dockerfile = read('web/Dockerfile')
    components = tools(dockerfile) + apt_packages(dockerfile) + python_packages(read('web/requirements.txt')) + service_images(read('docker-compose.yml'))
    components.sort(key=lambda c: (c['type'], c['name'].lower()))
    app = {'type': 'application', 'bom-ref': 'cvengine', 'name': 'cvENGINE', 'version': version,
           'licenses': [{'license': {'id': 'GPL-3.0-only'}}], 'externalReferences': [{'type': 'vcs', 'url': 'https://github.com/hevnsnt/CVEngine'}]}
    document = {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'timestamp': commit_time().strftime('%Y-%m-%dT%H:%M:%SZ'), 'component': app,
                     'tools': {'components': [{'type': 'application', 'name': 'scripts/generate_sbom.py'}]}},
        'components': components,
        'dependencies': [{'ref': 'cvengine', 'dependsOn': [c['bom-ref'] for c in components]}],
    }
    document['serialNumber'] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(document, sort_keys=True))}"
    return document


def main():
    text = json.dumps(build(), indent=2, sort_keys=True) + '\n'
    if '--output' in sys.argv:
        Path(sys.argv[sys.argv.index('--output') + 1]).write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
