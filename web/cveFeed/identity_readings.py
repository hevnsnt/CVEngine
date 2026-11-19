"""Identity readings: a product a source names on a host with no version.

A version reading (``cveFeed.source_versions``, ``cveFeed.version_sources``) needs a stated version to be a technology. A source often names the
product and nothing more: a network operating system's certificate or OS guess, Recog's fingerprint of a banner that carries no version, a second
product a network detection template names, a CPE without a version. Such a reading is stored like any other (``version_sources.store_readings``:
a ``version`` row with outcome ``hidden``, the product answers and states no version), so it is shown and searched (``tech:``, ``component:``,
``vsource:``, and ``os:`` for an operating system CPE), it is a lead for the version source reads (``version_sources.host_products``) and for
correlation (a product seen without a version is a lead, never a match), and it is never a technology.
"""
import re

from cveFeed import version_catalogue as catalogue


def _component(label):
    return re.sub(r'[^a-z0-9]+', '-', (label or '').lower()).strip('-')[:60]


def reading(label, source, evidence='', url='', cpe=''):
    """The identity reading of ``label`` (``version_catalogue.reading``'s shape, version ''), with ``cpe`` kept; None for an empty label."""
    label = catalogue.clip(label, 80)
    if not label:
        return None
    out = catalogue.reading(_component(label), label, '', evidence=evidence, url=url, source=source)
    if cpe:
        out['cpe'] = catalogue.clip(cpe, 200)
    return out
