from django.core.management.base import BaseCommand, CommandError

from cveFeed import seed


class Command(BaseCommand):
    help = ('Import a CVE seed (see export_cve_seed): the CVEs this instance lacks, and detection records where a CVE has none. '
            'Existing CVEs are never overwritten. With no argument, downloads the published seed and verifies its checksum.')

    def add_arguments(self, parser):
        parser.add_argument('path', nargs='?', help='a local seed file (default: download the published seed)')
        parser.add_argument('--url', help='https URL of the seed (its .manifest.json must sit beside it)')

    def handle(self, *args, **options):
        try:
            if options['path']:
                counts = seed.import_seed(options['path'], progress=lambda c: self.stdout.write(f"  {c['seen']} read, {c['created']} new..."))
            else:
                counts = seed.load_published_seed(options['url'])
        except (OSError, ValueError) as exc:
            raise CommandError(str(exc))
        counts.pop('manifest', None)
        self.stdout.write(f"seed imported: {counts['created']} new CVEs, {counts['skipped']} already here, {counts['detections']} detection records, "
                          f"{counts['invalid']} unusable lines")
