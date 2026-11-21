from django.core.management.base import BaseCommand

from cveFeed import source_versions


class Command(BaseCommand):
    help = ('Close, as automatic false positives, the open CVE matches whose only basis is a Shodan InternetDB reading '
            '(cveFeed.source_versions.cleanup_shodan_matches): Shodan data is keyed by address, so cvENGINE uses it as a lead for its own '
            'checks, never as a finding. Matches a person worked, and matches with any other evidence, are left alone. Idempotent. '
            'A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='close the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = source_versions.cleanup_shodan_matches(apply=apply)
        self.stdout.write(f'Applied: {out["closed"]} of {out["matches"]} Shodan-only CVE matches closed.' if apply
                          else f'Dry run: {out["matches"]} open CVE matches rest only on a Shodan InternetDB reading and would be closed.')
