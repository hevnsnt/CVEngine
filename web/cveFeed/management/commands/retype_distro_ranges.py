"""Type the stored ranges whose bounds are distribution package builds (cveFeed.intel.retype_distro_ranges).

Red Hat's and Debian's CVE records state a fix as the package build that carries it ("0:8.7p1-38.el9_4.4", versionType rpm). Read as an
upstream release, that bound is 8.7p1, and every RHEL 9 host with OpenSSH 8.7 was "in range" whatever build it ran. Such a range is now typed
RPM (or DEB), which correlation never compares with an upstream version: the distribution's own data (distro sync) decides those hosts. New
and refreshed CVEs are typed as they are stored; this types the stored ones and marks each changed CVE for re-correlation. Reads only the
database. A dry run by default; safe to run again.

    python3 manage.py retype_distro_ranges
    python3 manage.py retype_distro_ranges --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import intel


class Command(BaseCommand):
    help = "Type stored ranges whose bounds are distribution package builds (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Write the typed ranges. Without it the command only counts.")

    def handle(self, *args, **opts):
        out = intel.retype_distro_ranges(apply=opts["apply"])
        verb = "typed and marked for re-correlation" if opts["apply"] else "would be typed (run again with --apply)"
        self.stdout.write(self.style.SUCCESS(f"distribution build ranges: {out['cves']} CVEs {verb}"
                                             + (f" ({', '.join(out['ids'][:10])})" if out['ids'] else "")))
