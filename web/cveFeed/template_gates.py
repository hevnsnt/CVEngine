"""Templates that cannot tell a patched release from a vulnerable one: their hit counts only on a host whose product version is affected.

Some nuclei CVE templates test for a behaviour that the fix did not remove, only narrowed. CVE-2023-5561 (WordPress post author email
disclosure, fixed in 6.3.2) is one: the template asks ``/wp-json/wp/v2/users?search=@`` for a 200 JSON list of users, which every WordPress
whose REST user list is public answers, patched or not (a site whose logins are email addresses matches "@" in their names). Such a hit is
only a finding on a host whose product version is still affected, so ``GATES`` names, for each such template, the product and the last
release it affects, and a hit on a host whose version is known to be newer is not recorded: neither as a scanner finding (``nuclei_scan``,
``auth_nuclei``) nor as a template confirmation of a CVE match (``templategen``).

The host's version is what a probe read (the WordPress scan, the WordPress probe: ``cms_evidence.attested``), else what its technologies state once the
versions the evidence disproves are set aside (``cms_evidence.superseded``: jQuery's 3.7.1 read as WordPress'). A host whose version is not known keeps
the hit: nothing says it is patched."""
from cvengine_scanner import cms

from cveFeed import cms_evidence

# template or CVE id -> (product, the last release it affects): a hit on a host running a newer release is the patched behaviour
GATES = {
    'CVE-2023-5561': ('WordPress', '6.3.1'),
}


def _ids(line):
    info = (line or {}).get('info') or {}
    classification = info.get('classification') or {}
    found = {str((line or {}).get('template-id') or '').upper()}
    cves = classification.get('cve-id') or []
    found |= {str(c).upper() for c in (cves if isinstance(cves, list) else [cves])}
    return {i for i in found if i}


def host_versions(sub, product):
    """The versions of ``product`` on ``sub``: what a probe read with confidence, else its technologies' versions the evidence does not
    disprove. An empty set when none is known."""
    from cveFeed.correlation import split_name_version
    if sub is None:
        return set()
    k = cms.key(product)
    project = sub.target_domain.project_id if sub.target_domain_id else None
    if project:
        read = cms_evidence.attested(project, sub.name, {k}).get(k)
        if read:
            return set(read)
    technologies = list(sub.technologies.all())
    wrong = cms_evidence.superseded(sub, technologies)
    out = set()
    for tech in technologies:
        name, version = split_name_version(tech.name)
        if version and cms.key(name) == k and (k, version) not in wrong:
            out.add(version)
    return out


def out_of_range(ids, sub):
    """Why a hit of a template among ``ids`` (template or CVE ids) on ``sub`` is the patched behaviour, or '': every version of the gated
    product known on the host is newer than the last release the template's CVE affects."""
    from cveFeed.correlation import parse_version
    for gated in sorted({str(i).upper() for i in ids or ()} & set(GATES)):
        product, last = GATES[gated]
        known = host_versions(sub, product)
        parsed = [parse_version(v) for v in known]
        ceiling = parse_version(last)
        if known and ceiling is not None and all(p is not None and p > ceiling for p in parsed):
            return (f'{gated} affects {product} up to {last}; the host runs {product} {", ".join(sorted(known))}, so the template\'s hit is '
                    'the patched behaviour')
    return ''


def held_back(line, sub):
    """``out_of_range`` for one nuclei JSON result line on ``sub``."""
    return out_of_range(_ids(line), sub)
