"""Give the stored CVEs the ranges their CVE List record states for the blocks cve.now passed on as a bare versions list
(cveFeed.intel.backfill_bare_versions).

cve.now passes some CVE List blocks on with no range and only a ``versions`` list: the Linux kernel CNA's release entry (the release each flaw
began in, next to "defaultStatus: affected" and the fixed releases of each stable line), Microsoft's older records, VulDB's and many other
CNAs' exact versions. cvENGINE never reads that list (its meaning is not known), so such a CVE was stored with no range and could only be a
"version unknown" KEV candidate. New and refreshed CVEs take the record's ranges when they are stored; this reads the record again for the
CVEs stored before. A block is given ranges only when every version of the record's block reads exactly and every range has an upper bound;
any other block (Microsoft's product names, a git-only list, an open range) stays as it was.

A dry run by default: it counts the CVEs whose record it would read. With --apply it reads them in bounded passes (--limit records each) from
where the last run stopped, writes the ranges and marks each changed CVE for re-correlation (correlate_refreshed_cves matches them); no finding
row is written here. A record GitHub does not serve at once (rate limited, a server error, a cut connection) is asked again up to
three times with growing waits (intel.FETCH_WAITS, longer when GitHub asks for longer); one that still fails makes the walk start again at
the next run and the command fail, so the update step is tried again. A record that cannot be read on any try (over the size limit, not
JSON) is left as stored and named in the summary; it never holds the step back. Safe to run again: a CVE that got its ranges is not read twice.

    python3 manage.py backfill_bare_versions
    python3 manage.py backfill_bare_versions --apply
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed import intel


class Command(BaseCommand):
    help = "Read the CVE List record again for stored CVEs with a block cve.now passed on as bare versions (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Read the records and write the ranges. Without it the command only counts.")
        parser.add_argument("--limit", type=int, default=200, help="CVE List records to read per pass. Default 200.")
        parser.add_argument("--passes", type=int, default=1000, help="Most passes in this run. Default 1000.")
        parser.add_argument("--reset", action="store_true", help="Start from the first stored CVE instead of where the last run stopped.")

    def handle(self, *args, **opts):
        if opts["reset"]:
            intel.reset_bare_versions()
        if not opts["apply"]:
            count = intel.bare_candidates().count()
            self.stdout.write(self.style.SUCCESS(f"dry run: {count} stored CVEs would have their CVE List record read for the ranges of their "
                                                 "bare versions lists (run again with --apply)"))
            return
        total = {"scanned": 0, "updated": 0, "failed": 0, "skipped": 0}
        failed_ids, skipped_ids = [], []
        for _ in range(max(1, opts["passes"])):
            out = intel.backfill_bare_versions(limit=max(1, opts["limit"]))
            for key in total:
                total[key] += out[key]
            failed_ids += out["failed_ids"]
            skipped_ids += out.get("skipped_ids", [])
            if out["done"]:
                break
        summary = (f"bare versions: {total['scanned']} CVEs looked at, {total['updated']} given their record's ranges and marked for "
                   f"re-correlation, {total['failed']} records unreadable")
        if skipped_ids:
            summary += f", {total['skipped']} left as stored because their record cannot be read ({', '.join(skipped_ids[:10])})"
        if failed_ids:
            intel.reset_bare_versions()  # the next run walks again; a CVE that got its ranges is not read twice
            raise CommandError(summary + f" ({', '.join(failed_ids[:10])}); the walk starts again at the next run")
        self.stdout.write(self.style.SUCCESS(summary))
