"""Give back to validation the AI-written checks closed only because no scanner could check them, and name every rejection by its reason.

Before this update a check the AI had already written was closed as ``invalid`` when no Sentinel could run its syntax check at that moment ("not
validated: no scanner could take this work (nuclei_validate); the CVE is tried again later"). Nothing was wrong with it, but the row was the CVE's
attempt for ``TEMPLATE_GEN_CVE_DAYS`` and the paid answer was thrown away. ``templategen.job_answer`` now keeps such a draft in the ``syntax``
stage for ``cveFeed.templatevalidate`` to check again; this command does the same for the rows already closed that way:

* such a row goes back to ``draft`` in the ``syntax`` stage, due now, with a fresh expiry window and no try used, when its text still passes the
  static check and it is the newest such row of its CVE, its CVE has no other draft or valid check, and no revision was made of it. A draft never
  runs on a host: it is promoted only by every automatic gate (Sentinel syntax check and benign control, AI fixture, offline matcher test,
  second-pass review), exactly as a new one. A row whose text no longer passes the static check is left closed, with that reason.
* a closed row (``invalid`` or ``expired``) with no ``validation_reason`` (a static-check rejection or a failed provider call stored only the
  output) takes the plain reason of its output, and a reason that is a tool's warning line ("WARNING: sonic/ast only supports ...") is read
  again without it (``templategen.plain_reason``).

A dry run by default: it prints the counts and changes nothing.

    python3 manage.py revalidate_ai_drafts            # dry run
    python3 manage.py revalidate_ai_drafts --apply    # change the rows
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

NO_SCANNER = 'not validated: no scanner could take this work'
WAIT_REASON = 'waiting: validated again after an update (no Sentinel could check it when it was written)'


def stranded():
    """The rows closed only because no scanner could check them that may go back to validation, and the ones that may not, with why:
    ``(revalidate, keep)``, ``keep`` a list of ``(row, reason)``."""
    from cveFeed import templategen
    from cveFeed.models import GeneratedTemplate as G
    rows = list(G.objects.filter(status=G.STATUS_INVALID, validation_reason__startswith=NO_SCANNER).exclude(yaml='')
                .select_related('cve_entry').order_by('-created_at', '-id'))
    busy = set(G.objects.filter(status__in=(G.STATUS_DRAFT, G.STATUS_VALID)).values_list('cve_entry_id', flat=True))
    revised = set(G.objects.filter(supersedes__isnull=False).values_list('supersedes_id', flat=True))
    revalidate, keep, seen = [], [], set()
    for row in rows:
        if row.cve_entry_id in busy:
            keep.append((row, 'its CVE has a draft or valid check already'))
        elif row.cve_entry_id in seen:
            keep.append((row, 'a newer check of its CVE goes back to validation'))
        elif row.pk in revised:
            keep.append((row, 'a revision was made of it'))
        else:
            ok, why = templategen.static_check(row.yaml, expected_cve_id=row.cve_entry.cve_id)
            if ok:
                revalidate.append(row)
                seen.add(row.cve_entry_id)
            else:
                keep.append((row, f'static check: {why}'))
    return revalidate, keep


def unnamed():
    """Closed rows whose reason is empty or a tool's warning line, each with the reason it should have: ``[(row, reason)]``."""
    from cveFeed import templategen
    from cveFeed.models import GeneratedTemplate as G
    out = []
    for row in G.objects.filter(status__in=(G.STATUS_INVALID, G.STATUS_EXPIRED)).order_by('id'):
        current = (row.validation_reason or '').strip()
        if current and not templategen.holds_warning(current):
            continue
        reason = templategen.plain_reason(current) or templategen.plain_reason(row.validation_output)
        if reason and reason != current:
            out.append((row, reason))
    return out


class Command(BaseCommand):
    help = 'Give AI-written checks closed only because no scanner could check them back to validation, and name every rejection'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Change the rows. Without it the command only counts.')

    def handle(self, *args, **opts):
        from cveFeed.models import GeneratedTemplate as G
        now = timezone.now()
        revalidate, keep = stranded()
        for row, why in keep:
            if why.startswith('static check:'):
                self.stdout.write(f'#{row.pk} {row.cve_entry.cve_id}: stays closed ({why})')
        if opts['apply']:
            with transaction.atomic():
                for row in revalidate:
                    G.objects.filter(pk=row.pk, status=G.STATUS_INVALID).update(
                        status=G.STATUS_DRAFT, validation_stage='syntax', validation_next_at=now, validation_started_at=now, validation_attempts=0,
                        validated_at=None, validation_reason=WAIT_REASON,
                        validation_output=(row.validation_output + '\nupdate: given back to automatic validation').strip()[:6000])
                for row, why in keep:
                    if why.startswith('static check:'):
                        G.objects.filter(pk=row.pk).update(validation_reason=why[:400])
        named = unnamed()  # read after the moves: a row given back to validation is no longer closed
        if opts['apply']:
            for row, reason in named:
                G.objects.filter(pk=row.pk).update(validation_reason=reason)
        verb = 'given back' if opts['apply'] else 'would be given back'
        self.stdout.write(f'{len(revalidate)} AI-written check(s) {verb} to validation, {len(keep)} left closed, '
                          f'{len(named)} rejection reason(s) {"named" if opts["apply"] else "to name"}')
