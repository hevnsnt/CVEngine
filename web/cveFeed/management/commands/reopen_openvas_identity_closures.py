"""Reopen the OpenVAS CVE matches the product-identity check closed as "different product" (#414).

Before the fix, ``correlation.invalid_identity_reason`` compared an OpenVAS match's stored name ("OpenVAS NVT <oid> on <port>") with the
advisory's products. It never matched, so every OpenVAS match an NVT did not confirm with a hard quality of detection was closed
automatically ("Closed automatically: different product", not affected, confidence 0) minutes after the import. The reason was not true:
the NVT had tested that product. OpenVAS matches are no longer compared by name; this command reopens the ones already closed that way.

It reopens only a closure the deterministic correlation made (``ai_model`` deterministic-correlation, the "different product" wording, or
its earlier "invalid product correlation" one) on an OpenVAS match nobody has worked (remediation status open). A closure a person or the
AI made, or any other automatic closure (a later scan no longer reports it, a rejected CVE), is left alone. A reopened match goes back to
unjudged at its import confidence and its triage row to pending, so the next triage pass rates it on the scanner's evidence. A dry run by
default: it lists the matches per project and writes nothing.

    python3 manage.py reopen_openvas_identity_closures                  # dry run, every project
    python3 manage.py reopen_openvas_identity_closures --project slug   # dry run, one project (repeatable)
    python3 manage.py reopen_openvas_identity_closures --apply          # reopen them
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from ._finding_backfill import add_arguments, line, projects

AUTOMATIC_MODEL = 'deterministic-correlation'  # what correlation.close_invalid_correlation writes
SOURCE = 'openvas'


def closure_reasons():
    from cveFeed.correlation import AUTO_CLOSED, DIFFERENT_PRODUCT
    return (DIFFERENT_PRODUCT, *(r for r in AUTO_CLOSED if r.endswith('invalid product correlation')))


def candidates(project):
    from django.db.models import Q

    from cveFeed.models import CVEMatch
    reason = Q()
    for text in closure_reasons():
        reason |= Q(ai_reason__startswith=text)
    return (CVEMatch.objects.filter(reason, source=SOURCE, ai_verdict='not_affected', ai_model=AUTOMATIC_MODEL, remediation_status='open',
                                    subdomain__target_domain__project=project)
            .select_related('cve_entry', 'subdomain').order_by('pk'))


def import_confidence(match):
    """The confidence the OpenVAS import gives an unconfirmed result (cveFeed.openvas_scan.apply_observations): its QoD, at most 0.5."""
    qod = (match.evidence or {}).get('qod') if isinstance(match.evidence, dict) else None
    return min(0.5, qod / 100) if isinstance(qod, (int, float)) and not isinstance(qod, bool) and qod >= 0 else 0.3


def reopen(matches, now=None):
    """Reopen ``matches`` (from ``candidates``): the closure is cleared, the triage row goes back to pending. Returns how many."""
    from cveFeed import scoring
    from cveFeed.models import CVEMatch, Triage
    now = now or timezone.now()
    done = []
    with transaction.atomic():
        for m in matches:
            evidence = {**(m.evidence if isinstance(m.evidence, dict) else {}), 'identity_reopened_at': now.isoformat()}
            if CVEMatch.objects.filter(pk=m.pk, ai_verdict='not_affected', ai_model=AUTOMATIC_MODEL, remediation_status='open').update(
                    ai_verdict='', ai_reason='', ai_model='', confidence=import_confidence(m), evidence=evidence, updated_at=now):
                done.append(m.pk)
        reasons = closure_reasons()
        rows = Triage.objects.filter(match_id__in=done, classification='not_applicable')
        for row in rows:
            if (row.reason or '').startswith(reasons):  # only the automatic closure's own row, never a classification someone set
                row.verdict, row.status, row.classification, row.reason = None, 'pending', '', ''
                row.save(update_fields=['verdict', 'status', 'classification', 'reason', 'updated_at'])
    if done:
        scoring.rescore_for_matches(CVEMatch.objects.filter(pk__in=done).select_related('subdomain__target_domain'))
    return len(done)


class Command(BaseCommand):
    help = 'Reopen OpenVAS CVE matches closed automatically as "different product" (#414); a dry run unless --apply.'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        from cveFeed import activity
        apply = opts['apply']
        total = 0
        for project in projects(opts):
            matches = list(candidates(project))
            if not matches:
                continue
            for m in matches:
                self.stdout.write(f'  {project.slug}: {m.cve_entry.cve_id} on {m.subdomain.name if m.subdomain_id else "?"} '
                                  f'({m.matched_product}, QoD {(m.evidence or {}).get("qod", "?")})')
            count = reopen(matches) if apply else len(matches)
            total += count
            self.stdout.write(line(project, {'reopened' if apply else 'would reopen': count}))
            if apply and count:
                activity.log('confirm', f'{count} OpenVAS CVE match(es) reopened: an earlier build closed them as "different product" by comparing '
                                        'the NVT\'s name with the advisory\'s products; the NVT had tested that product (#414)',
                             project=project.pk, decision='reopened_openvas_identity_closures', reopened=count)
        verb = 'reopened' if apply else 'would reopen (dry run, nothing written)'
        self.stdout.write(self.style.SUCCESS(f'{verb} {total} OpenVAS match(es) closed automatically as "different product"'))
