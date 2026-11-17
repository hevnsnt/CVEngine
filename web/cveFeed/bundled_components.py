"""The components a vendor bundles with a release of its product, inferred from that product's exact version (``data/bundled_components.json``).

The bundled-JDK table (``cveFeed.java_runtime``, ``data/bundled_jdk.json``) generalised: a host that states Jira 9.12.0 runs, unless its owner
replaced it, the Tomcat Atlassian's installer bundles with 9.12.0; Elasticsearch 7.10.2 ships Lucene 8.7.0 and Log4j 2.11.1; Jenkins 2.426.1's
war launches Jetty 10.0.17 through Winstone 6.14; the Omnibus GitLab package embeds its own nginx, Redis and Ruby; Keycloak is built on one
Quarkus release and a Grafana release with one Go release. Pure data and pure lookups: nothing here touches the network or the database.

A reading made here is always ``inferred`` and carries its basis and citation: the owner may have replaced the component (an archive install
on a system Tomcat, a jar swapped after an advisory, an external Redis). ``cveFeed.version_sources`` stores it next to the reading it came from
(never as a technology of the host) and matches it so that it is never a version inside a range: an inferred product inside an affected range
is at most a needs-validation candidate (``evidence.bundled_inferred``), an inferred language runtime goes through the runtime rules.
"""
import functools
import json
import re
from pathlib import Path

from cveFeed import version_catalogue as catalogue

DATA = Path(__file__).with_name('data') / 'bundled_components.json'
SOURCE = 'bundled'


@functools.lru_cache(maxsize=1)
def table():
    """The bundled-component table, read once."""
    return json.loads(DATA.read_text(encoding='utf-8'))


def _key(version):
    """``9.12.0`` from ``9.12.0``, ``9.12`` (a two-part release is its .0) or ``v9.12.0``; Jenkins keeps its own two- or three-part form."""
    found = re.match(r'^v?(\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?', (version or '').strip())
    if not found:
        return '', ''
    full = f'{found.group(1)}.{found.group(2)}.{found.group(3) or 0}'
    short = f'{found.group(1)}.{found.group(2)}' + (f'.{found.group(3)}' if found.group(3) else '')
    return full, short


def _entries(name):
    token = re.sub(r'[^a-z0-9 ]', ' ', (name or '').lower()).strip()
    token = re.sub(r'\s+', ' ', token)
    for entry in table()['products']:
        if any(re.search(rf'(?:^|\s){re.escape(m)}(?:\s|$)', token) for m in entry['match']):
            yield entry


def infer(name, version, url='', said=''):
    """The inferred readings (``version_catalogue.reading`` dicts, source ``bundled``) of the components the vendor bundles with product ``name``
    at ``version``, the release the host stated. Only a release the vendor's own table or the release tag lists gives a reading: a release
    it does not list gives nothing, never a guess from a neighbour. Each reading's ``bundled`` names the product, the basis and the citation."""
    full, short = _key(version)
    if not full:
        return []
    out = []
    for entry in _entries(name):
        releases = entry['releases']
        got = releases.get(full) if full in releases else releases.get(short)
        if got is None:
            continue
        release = full if full in releases else short
        value, via = (got['version'], got.get('via', '')) if isinstance(got, dict) else (got, '')
        source = entry['source'].replace('{version}', release).replace('{via}', via)
        detail = {'id': entry['id'], 'product': entry['product'], 'product_version': catalogue.clip(version, 40), 'basis': entry['basis'],
                  'note': entry['note'], 'source': source, **({'via': via} if via else {})}
        what = f"{entry['label']} {value}" + (f' (through Winstone {via})' if via and entry['component'] == 'jetty' else '')
        evidence = f"{entry['product']} {release} bundles {what}: {entry['note']}" + (f'; read from {said}' if said else '')
        reading = catalogue.reading(entry['component'], entry['label'], value, kind=entry['kind'], confidence='inferred', evidence=evidence,
                                    url=url, source=SOURCE)
        reading['bundled'] = detail
        out.append(reading)
    return out


def infer_from(readings):
    """The bundled readings the exact product readings of ``readings`` give (a reading's component or label names the product)."""
    out = []
    for r in readings:
        if r.get('kind') != 'product' or r.get('confidence') != 'exact' or not r.get('version'):
            continue
        for name in dict.fromkeys((r.get('component') or '', r.get('label') or '')):
            got = infer(name, r['version'], url=r.get('url') or '', said=f"{r.get('label')} {r['version']} ({r.get('source') or 'read'})")
            if got:
                out += got
                break
    return out
