"""Release the findings an earlier version closed with another tenant's stored answer (cveFeed.verdict_tenancy, task 256).

A dry run by default: it counts and changes nothing. With --apply the findings are put back where their own evidence leaves them (held for
validation while their own review is asked, or unjudged so their own triage decides), the words of another organization's answer are taken
off them, and the shared not_affected rows are deleted. A finding's own closure is kept. On an instance with one organization it changes
nothing. Safe to run again: a second run finds nothing.

    python3 manage.py release_shared_closures
    python3 manage.py release_shared_closures --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import verdict_tenancy


class Command(BaseCommand):
    help = "Reopen findings that were closed by a verdict reached on another tenant's host (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Change the findings. Without it the command only counts.")

    def handle(self, *args, **opts):
        counts = verdict_tenancy.release_shared_closures(apply=opts["apply"])
        verb = "released" if opts["apply"] else "would release"
        self.stdout.write(self.style.SUCCESS(
            f"{verb}: {counts['triage_rows']} finding(s) closed by another organization's stored answer, {counts['seeded_matches']} CVE "
            f"match(es) seeded closed at correlation, {counts['shared_text']} finding(s) showing another project's notes; "
            f"{counts['kept_own']} own identity closure(s) kept; {counts['shared_rows']} shared closing row(s) "
            f"{'deleted' if opts['apply'] else 'to delete'}"))
