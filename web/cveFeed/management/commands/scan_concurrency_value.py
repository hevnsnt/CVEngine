from django.core.management.base import BaseCommand, CommandError

from cveFeed import scan_concurrency


class Command(BaseCommand):
    help = ('Print the value one scan concurrency setting has now: what an App Admin saved on Settings, configMaxxing, else the environment variable, '
            'else the default. celery-entrypoint.sh asks for discovery_concurrency before it starts the workers, so a restart lands on the saved value.')

    def add_arguments(self, parser):
        parser.add_argument('key', help='discovery_concurrency, work_depth or heavy.<kind>')

    def handle(self, *args, **options):
        if options['key'] not in scan_concurrency.BY_KEY:
            raise CommandError(f'unknown setting {options["key"]}')
        self.stdout.write(str(scan_concurrency.bootstrap_value(options['key'])))
