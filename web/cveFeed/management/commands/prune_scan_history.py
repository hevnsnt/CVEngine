from django.core.management.base import BaseCommand

from cveFeed import scan_retention


class Command(BaseCommand):
    help = ('Delete the old scans a domain no longer needs (cveFeed.scan_retention). Never touches the current inventory, a domain\'s newest '
            'scans or a scan holding work a person did. --dry-run only counts.')

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, help='age in days (default CVENGINE_SCAN_HISTORY_RETENTION_DAYS, else 180)')
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, **options):
        days = options['days']
        if days is not None:
            days = max(scan_retention.MIN_DAYS, days)
        result = scan_retention.run(days=days, dry_run=options['dry_run'], budget_seconds=24 * 3600)
        if result['days'] is None:
            self.stdout.write('Scan history retention is off (CVENGINE_SCAN_HISTORY_RETENTION_DAYS=0).')
            return
        self.stdout.write(f'{"Would delete" if options["dry_run"] else "Deleted"} {result["scans"]:,} scan(s) older than {result["days"]} days.')
