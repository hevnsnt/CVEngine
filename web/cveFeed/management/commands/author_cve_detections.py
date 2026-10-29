from django.core.management.base import BaseCommand

from cveFeed import detection_author


class Command(BaseCommand):
    help = ('Write the shared detection record of every CVE that has none (rules author), refresh changed ones, and, with --ai, '
            'spend the AI budget on the hottest. The periodic task does the same in small batches; this is for a first full backfill.')

    def add_arguments(self, parser):
        parser.add_argument('--batch', type=int, default=5000, help='records per round (default 5000)')
        parser.add_argument('--ai', action='store_true', help='also ask the configured AI model, within the daily budget (Settings > AI model)')
        parser.add_argument('--count', type=int, default=0, help='with --ai: write this many CVEs now, whatever is left of the daily budget')
        parser.add_argument('--workers', type=int, default=4, help='with --ai: requests in flight at once (default 4)')

    def handle(self, *args, **options):
        total = 0
        while True:
            written = detection_author.author_rules(batch=options['batch'])
            total += written
            if not written:
                break
        refreshed = detection_author.refresh_rules(batch=options['batch'])
        self.stdout.write(f'{total} detection record(s) written, {refreshed} refreshed')
        if options['ai']:
            from reNgine.ai_settings import get_configured_provider
            provider = get_configured_provider()
            if provider is None:
                self.stdout.write('no AI provider is configured; skipped')
            else:
                if options['count']:
                    wrote = detection_author.author_with_ai(provider, per_run=options['count'], workers=options['workers'], within_budget=False)
                else:
                    wrote = detection_author.author_with_ai(provider, workers=options['workers'])
                self.stdout.write(f'{wrote} record(s) gained the model\'s guidance')
            self.stdout.write(str(detection_author.progress()))
