from django.core.management.base import BaseCommand

from cveFeed import shots


class Command(BaseCommand):
    help = ('Rename or remove stored discovery screenshots whose file name is not a picture name (.png, .jpg, .jpeg). Before this release a Sentinel\'s '
            'screenshot was stored under the name the Sentinel sent; a real PNG or JPEG is renamed to a server-made name, anything else is removed and the '
            'host\'s screenshot cleared. A dry run by default: --apply changes the files and rows.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='rename and remove the files and update the rows (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = shots.neutralise_discovery_paths(apply=apply)
        verb = ('renamed', 'cleared') if apply else ('would be renamed', 'would be cleared')
        self.stdout.write(f'{"Applied" if apply else "Dry run"}: {out["paths"]} stored screenshot files ({out["rows"]} hosts) had a name that is not a '
                          f'picture name; {out["renamed"]} {verb[0]} (real pictures), {out["cleared"]} {verb[1]} (not a picture).')
