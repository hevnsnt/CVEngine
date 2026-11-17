from django.core.management.base import BaseCommand

from cveFeed import version_sources


class Command(BaseCommand):
    help = ('Store the versions and language runtimes every current host already states in what the scans stored (the headers the port scan read on each '
            'port, the Server header, a runtime technology such as Python:3.11.4 or .NET Framework CLR:4.0.30319), and correlate the hosts that gained '
            'a runtime reading against the CVEs in that runtime (cveFeed.version_sources). The active reads are left to the work planner. A dry run '
            'by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = version_sources.catch_up(apply=apply)
        self.stdout.write(f'Applied: {out["hosts"]} hosts; {out["readings"]} readings stored, {out["matches"]} runtime CVE matches.' if apply
                          else f'Dry run: {out["hosts"]} hosts would be read for their stored version sources and correlated.')
