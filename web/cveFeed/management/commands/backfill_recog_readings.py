from django.core.management.base import BaseCommand

from cveFeed import recog, source_versions


class Command(BaseCommand):
    help = ('Read the banners every current host already stores (SSH, SMTP, FTP, POP3, IMAP and telnet banners, the Server and Set-Cookie lines, '
            'mysql-info, ntp-info, SNMP sysDescr, the Server header and live routes) with Rapid7 Recog\'s fingerprints (cveFeed.recog), store what '
            'they state as vsrc:recog readings, and correlate the hosts that gained or lost one. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        info = recog.stats()
        out = source_versions.catch_up_recog(apply=apply)
        loaded = f'Recog {info["commit"][:12]}: {info["loaded"]} fingerprints loaded, {sum(info["skipped"].values())} skipped.'
        self.stdout.write(loaded)
        self.stdout.write(f'Applied: {out["hosts"]} hosts; {out["readings"]} Recog readings stored, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["hosts"]} hosts would have their stored banners read with Recog and be correlated.')
