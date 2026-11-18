from django.core.management.base import BaseCommand

from cveFeed import source_versions


class Command(BaseCommand):
    help = ('Store the exact versions and CPEs that data already received states (cveFeed.source_versions): the other CPEs, extrainfo modules and NSE '
            'script versions of every stored port, the operating system runZero states for an address, the Shodan InternetDB CPEs the discovery feed '
            'kept (as third-party readings: the CPE technology an earlier discovery stored is taken off the current host row), and the versions the '
            'database exposure findings\' replies state; then correlate the hosts that gained or lost a reading. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = source_versions.catch_up(apply=apply)
        self.stdout.write(f'Applied: {out["hosts"]} hosts; {out["readings"]} readings stored, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["hosts"]} hosts would be read for the versions their stored data states and correlated.')
