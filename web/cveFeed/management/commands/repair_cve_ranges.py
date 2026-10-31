"""Re-derive the version ranges of stored CVEs that an older conversion got wrong (cveFeed.intel.repair_ranges).

Bounded and resumable: it continues from where the last run stopped, and the hourly threat-intelligence run does a small step of it too.

    python3 manage.py repair_cve_ranges --limit 500
    python3 manage.py repair_cve_ranges --reset      # walk every stored CVE again
"""
from django.core.management.base import BaseCommand

from cveFeed import intel


class Command(BaseCommand):
    help = "Re-derive the stored version ranges of CVEs an older conversion got wrong (Jenkins default-status, Junos, Confluence shapes)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=500, help="CVE List records to read per pass. Default 500.")
        parser.add_argument("--passes", type=int, default=100, help="Most passes in this run (each reads up to --limit records). Default 100.")
        parser.add_argument("--reset", action="store_true", help="Start from the first stored CVE instead of where the last run stopped.")

    def handle(self, *args, **opts):
        from cveFeed.models import IntelSource
        if opts["reset"]:
            IntelSource.objects.filter(name=intel.RANGES_MARKER).update(cves=0, last_changed=None)
        total = {"scanned": 0, "examined": 0, "normalized": 0, "repaired": 0, "failed": 0}
        for _ in range(max(1, opts["passes"])):
            out = intel.repair_ranges(limit=opts["limit"])
            for key in total:
                total[key] += out[key]
            if not out["scanned"]:
                break
        self.stdout.write(self.style.SUCCESS(
            f"ranges: {total['scanned']} entries looked at, {total['examined']} CVE List records read, {total['repaired']} repaired from them, "
            f"{total['normalized']} rewritten from what was stored, {total['failed']} unreadable"))
