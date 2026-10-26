from django.core.management.base import BaseCommand

from cveFeed import detection_author, seed


class Command(BaseCommand):
    help = ('Write this instance\'s whole CVE catalog, with the shared detection records, as a seed file other installs import on first '
            'start. Writes <out> and <out>.manifest.json (count, size, sha256). Publish both as release assets named cve-seed.jsonl.gz '
            'and cve-seed.jsonl.gz.manifest.json (scripts/publish-cve-seed.sh).')

    def add_arguments(self, parser):
        parser.add_argument('--out', default='cve-seed.jsonl.gz', help='file to write (default cve-seed.jsonl.gz in the working directory)')
        parser.add_argument('--no-detections', action='store_true', help='skip writing missing detection records first')

    def handle(self, *args, **options):
        if not options['no_detections']:
            written = 0
            while True:
                batch = detection_author.author_rules(batch=5000)
                written += batch
                if not batch:
                    break
            detection_author.refresh_rules(batch=5000)
            self.stdout.write(f'{written} detection record(s) written before the export')
        manifest = seed.export_seed(options['out'], progress=lambda n: self.stdout.write(f'  {n} CVEs...'))
        self.stdout.write(f"{options['out']}: {manifest['count']} CVEs (fire {manifest['tiers']['fire']}, smoke {manifest['tiers']['smoke']}, "
                          f"ice {manifest['tiers']['ice']}), {manifest['with_detection']} with a detection record, "
                          f"{manifest['bytes'] // (1 << 20)} MB, sha256 {manifest['sha256']}")
