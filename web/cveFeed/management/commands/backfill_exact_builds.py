"""Give the stored CVEs the exact builds their CVE List record lists (cveFeed.intel.backfill_exact_builds).

Cisco's records list every affected build one by one (CVE-2023-20109: 674 IOS builds, 364 IOS XE builds). The conversion used to keep 30 ranges
and drop every parenthesised build ("15.2(4)M7"), so an IOS XE or ASA host whose build came after the first 30, and every IOS and NX-OS host, had
no match. New and refreshed records carry the whole list; this reads the record again for the CVEs stored before.

A dry run by default: it counts the CVEs whose record it would read. With --apply it reads them in bounded passes (--limit records each) from
where the last run stopped, writes the builds and marks each changed CVE for re-correlation (correlate_refreshed_cves matches them); no finding
row is written here. When a record could not be read, the walk starts again at the next run and the command fails, so the update step is tried
again. Safe to run again: a CVE that has its builds is not read twice.

    python3 manage.py backfill_exact_builds
    python3 manage.py backfill_exact_builds --apply
    python3 manage.py backfill_exact_builds --apply --wide   # also every other block with no range (more records read)
"""
from django.core.management.base import BaseCommand, CommandError

from cveFeed import intel


class Command(BaseCommand):
    help = "Read the CVE List record again for stored CVEs whose exact affected builds were cut or dropped (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Read the records and write the builds. Without it the command only counts.")
        parser.add_argument("--limit", type=int, default=200, help="CVE List records to read per pass. Default 200.")
        parser.add_argument("--passes", type=int, default=1000, help="Most passes in this run. Default 1000.")
        parser.add_argument("--wide", action="store_true", help="Also read the record of every CVE with a block that states no range.")
        parser.add_argument("--reset", action="store_true", help="Start from the first stored CVE instead of where the last run stopped.")

    def handle(self, *args, **opts):
        if opts["reset"]:
            intel.reset_exact_builds()
        if not opts["apply"]:
            count = intel.builds_candidates(opts["wide"]).count()
            self.stdout.write(self.style.SUCCESS(f"dry run: {count} stored CVEs would have their CVE List record read for exact builds "
                                                 "(run again with --apply)"))
            return
        total = {"scanned": 0, "updated": 0, "failed": 0}
        failed_ids = []
        for _ in range(max(1, opts["passes"])):
            out = intel.backfill_exact_builds(limit=max(1, opts["limit"]), wide=opts["wide"])
            for key in total:
                total[key] += out[key]
            failed_ids += out["failed_ids"]
            if out["done"]:
                break
        summary = (f"exact builds: {total['scanned']} CVEs looked at, {total['updated']} given their builds and marked for re-correlation, "
                   f"{total['failed']} records unreadable")
        if failed_ids:
            intel.reset_exact_builds()  # the next run walks again; a CVE that got its builds is not read twice
            raise CommandError(summary + f" ({', '.join(failed_ids[:10])}); the walk starts again at the next run")
        self.stdout.write(self.style.SUCCESS(summary))
