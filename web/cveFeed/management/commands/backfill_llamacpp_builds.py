"""Read the CVE List record again for the stored llama.cpp CVEs whose block was kept with no range (cveFeed.intel.backfill_llamacpp_builds).

llama.cpp names its releases by build tag, and its advisories write their bounds that way ("< b5662"). A build tag read as no version, so such
a block was stored with no range and every llama.cpp host was at best a "version unknown" candidate. llama.cpp's build tags now read as the
build number (cveFeed.correlation.llamacpp_range, cveFeed.intel._llamacpp_builds), and new and refreshed CVEs take the ranges when they are
stored; this reads the record again for the llama.cpp blocks stored before. The same rules as backfill_bare_versions: a block whose record lists
a commit or anything else that is not a version stays as it was.

A dry run by default: it counts the CVEs whose record it would read. With --apply it reads them in bounded passes, writes the ranges and marks
each changed CVE for re-correlation. A record that fails for a passing reason makes the walk start again at the next run and the command fail,
so the update step is tried again. Safe to run again.

    python3 manage.py backfill_llamacpp_builds
    python3 manage.py backfill_llamacpp_builds --apply
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed import intel


class Command(BaseCommand):
    help = "Read the CVE List record again for stored llama.cpp CVEs kept with no range (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Read the records and write the ranges. Without it the command only counts.")
        parser.add_argument("--limit", type=int, default=200, help="CVE List records to read per pass. Default 200.")
        parser.add_argument("--passes", type=int, default=100, help="Most passes in this run. Default 100.")
        parser.add_argument("--reset", action="store_true", help="Start from the first stored CVE instead of where the last run stopped.")

    def handle(self, *args, **opts):
        if opts["reset"]:
            intel.reset_llamacpp_builds()
        if not opts["apply"]:
            count = intel.llamacpp_candidates().count()
            self.stdout.write(self.style.SUCCESS(f"dry run: {count} stored llama.cpp CVEs would have their CVE List record read for their build "
                                                 "ranges (run again with --apply)"))
            return
        total = {"scanned": 0, "updated": 0, "failed": 0, "skipped": 0}
        failed_ids = []
        for _ in range(max(1, opts["passes"])):
            out = intel.backfill_llamacpp_builds(limit=max(1, opts["limit"]))
            for key in total:
                total[key] += out[key]
            failed_ids += out["failed_ids"]
            if out["done"]:
                break
        summary = (f"llama.cpp builds: {total['scanned']} CVEs looked at, {total['updated']} given their record's ranges and marked for "
                   f"re-correlation, {total['failed']} records unreadable, {total['skipped']} left as stored")
        if failed_ids:
            intel.reset_llamacpp_builds()
            raise CommandError(summary + f" ({', '.join(failed_ids[:10])}); the walk starts again at the next run")
        self.stdout.write(self.style.SUCCESS(summary))
