from django.core.management.base import BaseCommand

from cveFeed import php_tells


class Command(BaseCommand):
    help = ('PHP read from nothing but a link to a .php URL ("page:.php link") is a lead, not a technology (cveFeed.php_tells): judge the stored route '
            'answers that carry the marker, turn the headers-root probe rows it made into leads, remove the bare PHP technology links the route check '
            'made on hosts whose routes do not confirm PHP (an X-Powered-By or Server header naming PHP, a PHPSESSID cookie), and correlate the hosts '
            'that lost one, so their version-unknown PHP candidates close. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the changes (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = php_tells.catch_up(apply=apply)
        if apply:
            self.stdout.write(f'Applied: {out["routes"]} route answers judged, {out["probes"]} probe readings turned into leads, {out["links"]} PHP technology '
                              f'links removed; {out["hosts"]} hosts correlated, {out["matches"]} CVE matches.')
        else:
            self.stdout.write(f'Dry run: {out["routes"]} route answers would be judged, {out["probes"]} probe readings turned into leads and {out["links"]} PHP '
                              'technology links removed (the hosts that lose one correlated again).')
