"""Leave out the open ranges a CVE List upper bound written as text made (issue 696), on the CVEs already stored
(cveFeed.intel.backfill_open_ranges).

A CVE 5 ``versions`` entry such as ``{"version": "2.4.7", "lessThan": "Apache HTTP Server 2.4*"}`` (CVE-2021-44224; CVE-2021-43557 writes
"Apache APISIX 1.5*") states an upper bound no reader can take as a version. cve.now, and cvENGINE's own conversion before this fix, kept only
the lower bound, so the range was open and every later release (Apache 2.4.58) was "in range". New and refreshed CVEs are checked when they
are stored; this reads the CVE List record of the CVEs stored before that have a CVE List block with an open range, leaves out each open range
whose upper bound the record writes as text (the block keeps the lower bound in ``upper_unreadable``) and marks the CVE for re-correlation,
so its matches outside the real range close. A range the record means open ("*") is kept and noted, never read again.

A dry run by default: it counts the CVEs whose record it would read. With --apply it reads them in bounded passes (--limit records each)
from where the last run stopped, as backfill_bare_versions does (the same waits for a record GitHub does not serve at once, the same
restart of the walk at the next run when one still fails). The walk also runs a bounded step with every threat-intel pass.

    python3 manage.py repair_open_ranges
    python3 manage.py repair_open_ranges --apply
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed import intel


class Command(BaseCommand):
    help = "Leave out the open ranges a CVE List upper bound written as text made, on stored CVEs (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Read the records and write the ranges. Without it the command only counts.")
        parser.add_argument("--limit", type=int, default=200, help="CVE List records to read per pass. Default 200.")
        parser.add_argument("--passes", type=int, default=1000, help="Most passes in this run. Default 1000.")
        parser.add_argument("--reset", action="store_true", help="Start from the first stored CVE instead of where the last run stopped.")

    def handle(self, *args, **opts):
        if opts["reset"]:
            intel.reset_open_ranges()
        if not opts["apply"]:
            count = intel.open_candidates().count()
            self.stdout.write(self.style.SUCCESS(f"dry run: {count} stored CVEs would have their CVE List record read for the upper bounds of their "
                                                 "open ranges (run again with --apply)"))
            return
        total = {"scanned": 0, "updated": 0, "failed": 0, "skipped": 0}
        failed_ids, skipped_ids = [], []
        for _ in range(max(1, opts["passes"])):
            out = intel.backfill_open_ranges(limit=max(1, opts["limit"]))
            for key in total:
                total[key] += out[key]
            failed_ids += out["failed_ids"]
            skipped_ids += out.get("skipped_ids", [])
            if out["done"]:
                break
        summary = (f"open ranges: {total['scanned']} CVEs looked at, {total['updated']} had an open range left out and were marked for "
                   f"re-correlation, {total['failed']} records unreadable")
        if skipped_ids:
            summary += f", {total['skipped']} left as stored because their record cannot be read ({', '.join(skipped_ids[:10])})"
        if failed_ids:
            intel.reset_open_ranges()  # the next run walks again; a CVE that got its ranges is not read twice
            raise CommandError(summary + f" ({', '.join(failed_ids[:10])}); the walk starts again at the next run")
        self.stdout.write(self.style.SUCCESS(summary))
