from django.core.management.base import BaseCommand

from cveFeed import java_runtime


class Command(BaseCommand):
    help = ('Store the Java runtime every current Java host gives away without a request (an nmap JDWP port, a stored X-Powered-By or Server header, '
            'the runtime its product version bundles), file the exposure of an open JDWP port, and correlate those hosts against the stored CVEs in the '
            'Java runtime (cveFeed.java_runtime). The active reads are left to the work planner. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = java_runtime.catch_up(apply=apply)
        self.stdout.write(f'{"Applied" if apply else "Dry run"}: {out["hosts"]} Java hosts; {out["readings"]} readings stored, '
                          f'{out["matches"]} runtime CVE matches.' if apply else f'Dry run: {out["hosts"]} Java hosts would be read and correlated.')
