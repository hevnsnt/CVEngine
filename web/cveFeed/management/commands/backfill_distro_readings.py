"""Read every stored service banner again for its distribution package build, and judge the matches by it
(cveFeed.distro_releases.catch_up).

A banner such as ``OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` names an exact Ubuntu package build. Rows stored before this update kept the
distribution and build, but often not the release (nmap's OS CPE rarely states it), never the SSH identification string's build, and nothing
for Amazon Linux, SUSE or FreeBSD. This reads the stored product, version, extra info, CPEs and banner of each port again, rewrites the rows
whose reading changed, and correlates again the hosts with a distribution reading, so a match is judged by the distribution's own fixed
build. Nothing is fetched.

A dry run by default: it counts the rows it would rewrite and the hosts it would correlate. Safe to run again.

    python3 manage.py backfill_distro_readings
    python3 manage.py backfill_distro_readings --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import distro_releases


class Command(BaseCommand):
    help = "Read the stored service banners again for their distribution package build and correlate those hosts (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Rewrite the rows and correlate. Without it the command only counts.")

    def handle(self, *args, **opts):
        out = distro_releases.catch_up(apply=bool(opts["apply"]))
        if opts["apply"]:
            self.stdout.write(self.style.SUCCESS(
                f"distro readings: {out['ports']} service records read, {out['changed']} rewritten, {out['hosts']} hosts correlated, "
                f"{out['matches']} CVE matches"))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"dry run: {out['changed']} of {out['ports']} service records would be rewritten and {out['hosts']} hosts correlated "
                "(run again with --apply)"))
