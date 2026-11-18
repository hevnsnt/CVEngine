from django.core.management.base import BaseCommand

from cveFeed import windows_builds


class Command(BaseCommand):
    help = ('Store the Windows release that stored NTLM script output (rdp-ntlm-info, ms-sql-ntlm-info and the other *-ntlm-info scripts) and '
            'smb-os-discovery state for every current host (cveFeed.windows_builds: release known, patch level unknown), then correlate those '
            'hosts against the stored Windows CVEs. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = windows_builds.catch_up(apply=apply)
        self.stdout.write(f'Applied: {out["hosts"]} hosts; {out["readings"]} Windows release readings stored, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["hosts"]} hosts state a Windows build in stored NTLM or SMB script output and would be read and correlated.')
