from django.core.management.base import BaseCommand

from cveFeed import hygiene_rating


class Command(BaseCommand):
    help = ('Re-rate the open hygiene findings stored before 1.3.5 with the endpoint-aware rules (vendor-managed and vendor-owned names, '
            'expected private CA, BREACH without a session, managed and dev-host certificates). A dry run by default: it reports, per '
            'project, how many rows would be lowered or resolved and how their heat would move. --apply writes the change.')

    def add_arguments(self, parser):
        parser.add_argument('--project', help='one project slug (default: every project)')
        parser.add_argument('--apply', action='store_true', help='write the new ratings (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        report = hygiene_rating.rerate_open(project=options.get('project'), apply=apply)
        verb = ('Lowered', 'Resolved') if apply else ('Would lower', 'Would resolve')
        total = {'rows': 0, 'lowered': 0, 'dropped': 0}
        for slug, stats in sorted(report.items()):
            moves = ', '.join(f'{k}: {v}' for k, v in sorted(stats['heat'].items())) or 'no change'
            self.stdout.write(f'{slug}: {stats["rows"]} open; {verb[0]} {stats["lowered"]}, {verb[1]} {stats["dropped"]} ({moves})')
            for key in total:
                total[key] += stats[key]
        self.stdout.write(f'{"Applied" if apply else "Dry run"}: {total["rows"]} open hygiene findings, {total["lowered"]} lowered, '
                          f'{total["dropped"]} resolved as the vendor\'s own endpoint.')
