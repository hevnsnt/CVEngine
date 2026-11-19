from django.core.management.base import BaseCommand

from cveFeed import identities


class Command(BaseCommand):
    help = ('Decode the service fingerprints the ports already store (Port.extra["servicefp"]), then read every current host\'s stored data '
            'again for what it names with or without a version (cveFeed.identities: a network operating system its OS guess, a factory certificate '
            'or an OS CPE names; Recog identities and hardware; the headers of a decoded fingerprint), and correlate the hosts that gained or '
            'lost a reading. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = identities.catch_up(apply=apply)
        self.stdout.write(f'Applied: {out["ports"]} service fingerprints decoded; {out["hosts"]} hosts read again, {out["moved"]} gained or lost a '
                          f'reading, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["ports"]} service fingerprints would be decoded and {out["hosts"]} current hosts read again and correlated.')
