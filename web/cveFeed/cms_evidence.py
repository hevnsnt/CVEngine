"""The database half of the CMS version rules: what a probe stored for a host, and which of a host's versions that evidence disproves.

The rules themselves are pure and live in the scanner library (``cvengine_scanner.cms``: where a CMS states its version, ``key``, ``disproven``);
this module only reads the probe observations they are applied to.
"""
from cvengine_scanner import cms


def attested(project_id, host, keys):
    """``{product key: {versions}}`` a probe read on this host for the products in ``keys`` (any probe that stored a trusted
    reading of the version: the WordPress core check, the WordPress probe, a version probe)."""
    from cveFeed.models import ProbeObservation
    found = {}
    rows = ProbeObservation.objects.filter(project_id=project_id, host=str(host).lower(), outcome='found', confidence__gte=cms.TRUSTED) \
        .exclude(version='').values_list('product', 'version')
    for product, version in rows:
        if cms.key(product) in keys:
            found.setdefault(cms.key(product), set()).add(version)
    return found


def superseded(subdomain, technologies, stated=()):
    """``{(product key, version)}`` of ``subdomain``'s technologies that ``disproven`` rules out. Reads the probe evidence only when a one-core
    product has more than one version, or one a library's own file states (``stated``), so a host with no dispute costs no query.
    ``technologies`` is the host's Technology rows (or names)."""
    from cveFeed.correlation import split_name_version
    pairs = [split_name_version(getattr(t, 'name', t) or '') for t in technologies]
    stated = set(stated or ())
    seen = {}
    for name, version in pairs:
        if version and cms.key(name) in cms.SINGLE_INSTANCE:
            seen.setdefault(cms.key(name), set()).add(version)
    disputed = {k for k, versions in seen.items() if len(versions) > 1 or versions & stated}
    if not disputed:
        return set()
    project = subdomain.target_domain.project_id
    return cms.disproven(pairs, attested(project, subdomain.name, disputed), stated)
