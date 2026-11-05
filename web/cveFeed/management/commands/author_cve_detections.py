from django.core.management.base import BaseCommand

from cveFeed import detection_author


class Command(BaseCommand):
    help = ('Write the shared detection record of every CVE that has none (rules author), refresh changed ones, and, with --ai, '
            'spend the AI budget on the hottest. Rules records written under an older schema are regenerated (AI-written and person-written '
            'records never are). The periodic task does the same in small batches; this is for a first full backfill.')

    def add_arguments(self, parser):
        parser.add_argument('--batch', type=int, default=5000, help='records per round (default 5000)')
        parser.add_argument('--ai', action='store_true', help='also ask the configured AI model, within the daily budget (Settings > AI model)')
        parser.add_argument('--count', type=int, default=0, help='with --ai: write this many CVEs now, whatever is left of the daily budget')

    def handle(self, *args, **options):
        total = 0
        while True:
            written = detection_author.author_rules(batch=options['batch'])
            total += written
            if not written:
                break
        refreshed = detection_author.refresh_rules(batch=options['batch'])
        regenerated = detection_author.regenerate_rules_records(seconds=3600)  # rules records of an older schema; ai and manual never
        libraries = detection_author.refresh_client_library_records(seconds=3600)
        self.stdout.write(f'{total} detection record(s) written, {refreshed} refreshed, {regenerated} rules record(s) regenerated, '
                          f'{libraries} client-library record(s) corrected')
        if options['ai']:
            from cveFeed import ai_jobs
            if not ai_jobs.ai_on():
                self.stdout.write('no AI provider is configured; skipped')
            else:
                if options['count']:
                    asked = detection_author.author_with_ai(per_run=options['count'], within_budget=False)
                else:
                    asked = detection_author.author_with_ai()
                self.stdout.write(f'{asked} record(s) asked of the AI reviewer container; each is stored when its answer lands')
            self.stdout.write(str(detection_author.progress()))
