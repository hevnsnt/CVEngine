"""Un-confirm the OpenVAS CVE matches a generic NVT confirmed on a CVE whose record names no vendor and no product.

An OpenVAS result is hard evidence for the CVEs its NVT lists only when the NVT tested the product those CVEs are about. A check of a behaviour
(``openvas_scan.generic_check``: it identified no product and no version) was already kept from confirming CVEs that name several vendors, but a
CVE whose CVE List record says ``vendor: n/a, product: n/a`` (CVE-2005-3398, listed by "HTTP Debugging Methods (TRACE/TRACK) Enabled",
1.3.6.1.4.1.25623.1.0.11213) passed as one vendor: the match was stored as a template hit, the triage floored it to confirmed, and a correct AI
verdict that it does not apply was overruled on every host with TRACE on. The import now treats such a record as generic; this command applies
the same rule to the matches already stored.

For every OpenVAS match recorded as confirmed by its NVT (``template_result`` vulnerable, ``template_id`` openvas:<oid>) the NVT's CVEs on that
host and port are read again through ``generic_check``. A generic one loses the confirmation exactly as a fresh import would store it: no template
result, the version range unknown, the import's unconfirmed confidence, ``generic_check`` in its evidence. Its triage row is tracked, so the changed
evidence resets it and the next triage pass judges the match on what it is (the floor is gone, the AI may rule it out); the hosts are rescored.
The OpenVAS finding (the Vulnerability row) is left as it is: the NVT did see the behaviour. A match a person worked keeps its remediation state.
A dry run by default: it lists the matches per project and writes nothing.

    python3 manage.py recheck_openvas_generic_checks                  # dry run, every project
    python3 manage.py recheck_openvas_generic_checks --project slug   # dry run, one project (repeatable)
    python3 manage.py recheck_openvas_generic_checks --apply          # un-confirm them
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from ._finding_backfill import add_arguments, line, projects

SOURCE = 'openvas'


def candidates(project):
    """The confirmed OpenVAS matches of ``project`` whose NVT is generic for its CVEs: ``[(match, ...)]`` in id order."""
    from cveFeed import openvas_scan
    from cveFeed.models import CVEMatch
    confirmed = list(CVEMatch.objects.filter(source=SOURCE, template_result='vulnerable', template_id__startswith='openvas:',
                                             subdomain__target_domain__project=project)
                     .select_related('cve_entry', 'subdomain').order_by('pk'))
    if not confirmed:
        return []
    # every CVE the same NVT listed on the same host and port: the match key (``matched_product``) is one per NVT and port
    siblings = {}
    for m in (CVEMatch.objects.filter(source=SOURCE, subdomain_id__in={m.subdomain_id for m in confirmed},
                                      matched_product__in={m.matched_product for m in confirmed}).select_related('cve_entry')):
        siblings.setdefault((m.subdomain_id, m.matched_product), {})[m.cve_entry_id] = m.cve_entry
    out = []
    for m in confirmed:
        evidence = m.evidence if isinstance(m.evidence, dict) else {}
        if evidence.get('generic_check'):
            continue
        seen = {'product': evidence.get('product') or '', 'installed_version': evidence.get('installed_version') or ''}
        cves = list((siblings.get((m.subdomain_id, m.matched_product)) or {m.cve_entry_id: m.cve_entry}).values())
        if openvas_scan.generic_check(seen, cves):
            out.append(m)
    return out


def unconfirmed_confidence(match):
    """The confidence the OpenVAS import gives a result that is not hard evidence: its QoD, at most 0.5 (``apply_observations``)."""
    qod = (match.evidence or {}).get('qod') if isinstance(match.evidence, dict) else None
    return min(0.5, qod / 100) if isinstance(qod, (int, float)) and not isinstance(qod, bool) and qod >= 0 else 0.3


def unconfirm(matches, now=None):
    """Store ``matches`` (from ``candidates``) as a fresh import would, then track them and rescore their hosts. Returns how many."""
    from cveFeed import scoring, triage
    from cveFeed.models import CVEMatch
    now = now or timezone.now()
    done = []
    with transaction.atomic():
        for m in matches:
            evidence = {**(m.evidence if isinstance(m.evidence, dict) else {}), 'generic_check': True}
            if CVEMatch.objects.filter(pk=m.pk, template_result='vulnerable').update(
                    template_result='', template_tested_at=now, version_in_range=None, confidence=unconfirmed_confidence(m), evidence=evidence,
                    updated_at=now):
                done.append(m.pk)
    if done:
        fresh = triage.with_cves(CVEMatch.objects.filter(pk__in=done).select_related('subdomain__target_domain'))
        triage.track(fresh)  # the evidence changed (no template hit): the row is reset and judged again, without the floor
        scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=done).select_related('subdomain__target_domain'))
    return len(done)


class Command(BaseCommand):
    help = 'Un-confirm OpenVAS CVE matches a generic NVT confirmed on a CVE whose record names no vendor or product; a dry run unless --apply.'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        from cveFeed import activity
        apply = opts['apply']
        total = 0
        for project in projects(opts):
            matches = candidates(project)
            if not matches:
                continue
            for m in matches:
                self.stdout.write(f'  {project.slug}: {m.cve_entry.cve_id} on {m.subdomain.name if m.subdomain_id else "?"} '
                                  f'({(m.evidence or {}).get("nvt") or m.matched_product})')
            count = unconfirm(matches) if apply else len(matches)
            total += count
            self.stdout.write(line(project, {'unconfirmed' if apply else 'would unconfirm': count}))
            if apply and count:
                activity.log('confirm', f'{count} OpenVAS CVE match(es) are no longer confirmed by their NVT: it checks a behaviour, and the CVE '
                                        'record names no vendor or product it could have tested; the AI triage judges them again',
                             project=project.pk, decision='recheck_openvas_generic_checks', unconfirmed=count)
        verb = 'unconfirmed' if apply else 'would unconfirm (dry run, nothing written)'
        self.stdout.write(self.style.SUCCESS(f'{verb} {total} OpenVAS match(es) a generic check had confirmed'))
