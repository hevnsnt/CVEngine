from django.core.management.base import BaseCommand

from cveFeed import panel_versions


class Command(BaseCommand):
    help = ('Read the version every stored info-level nuclei panel finding (tag "panel") extracted as a version reading of its host '
            '(cveFeed.panel_versions: probe vsrc:panel, never over a version another source states), then correlate the hosts that '
            'gained or changed one. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = panel_versions.catch_up(apply=apply)
        self.stdout.write(f'Applied: {out["findings"]} panel findings read; {out["readings"]} readings stored on {out["hosts"]} hosts, '
                          f'{out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["findings"]} panel findings on {out["hosts"]} hosts state a version that would be stored and correlated.')
