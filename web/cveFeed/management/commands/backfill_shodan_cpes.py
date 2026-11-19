from django.core.management.base import BaseCommand

from cveFeed import source_versions


class Command(BaseCommand):
    help = ('Store every CPE Shodan\'s InternetDB handed discovery as a vsrc:shodan-idb reported reading labelled "vendor product" '
            '(cveFeed.source_versions.shodan_reading: unversioned and operating system CPEs too), relabel the readings stored before, turn the '
            'technologies stored as a CPE or under its bare product name ("http server") into the reading they are, and correlate the hosts '
            'that moved. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = source_versions.catch_up_shodan(apply=apply)
        self.stdout.write(f'Applied: {out["relabelled"]} readings relabelled, {out["readings"]} Shodan InternetDB CPEs stored as readings, '
                          f'{out["technologies"]} CPE technologies removed; {out["hosts"]} hosts correlated, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["relabelled"]} readings would be relabelled and {out["technologies"]} CPE technologies turned into '
                               'readings; the CPEs the discovery feed kept would be read again.')
