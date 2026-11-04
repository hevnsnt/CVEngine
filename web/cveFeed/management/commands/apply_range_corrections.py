"""Apply cvENGINE's sourced range corrections (cveFeed.range_corrections) to the CVEs already stored.

A dry run by default: it lists the CVEs whose stored ranges would change and, per project, the current hosts whose version falls in a span a
correction adds, and changes nothing. With --apply the ranges are written and each changed CVE is marked for re-correlation (the
correlate_refreshed_cves task picks it up, as after a feed refresh); no finding row is written by this command. New CVEs and feed refreshes
get the corrections as they are stored. Safe to run again: a second run finds nothing.

    python3 manage.py apply_range_corrections
    python3 manage.py apply_range_corrections --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import range_corrections


class Command(BaseCommand):
    help = "Apply the sourced affected-range corrections to stored CVEs (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Write the corrected ranges. Without it the command only reports.")

    def handle(self, *args, **opts):
        result = range_corrections.backfill(apply=opts["apply"])
        verb = "corrected" if opts["apply"] else "would correct"
        if not result["cves"]:
            self.stdout.write(self.style.SUCCESS("nothing to correct: every stored range already carries the corrections"))
            return
        for cve_id, changed in sorted(result["cves"].items()):
            self.stdout.write(f"{verb} {cve_id}: {changed} range(s)")
        for slug, hosts in sorted(result["hosts"].items()):
            self.stdout.write(f"  project {slug}: {hosts} current host(s) with a version the corrected range adds")
        if opts["apply"]:
            self.stdout.write(self.style.SUCCESS("marked for re-correlation; the next correlate_refreshed_cves run matches them"))
        else:
            self.stdout.write(self.style.SUCCESS("dry run: nothing was written (run again with --apply)"))
