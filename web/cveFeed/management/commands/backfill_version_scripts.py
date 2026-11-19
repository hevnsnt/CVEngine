from django.core.management.base import BaseCommand

from cveFeed import source_versions


class Command(BaseCommand):
    help = ('Read the output of the port scan\'s version category scripts that every current host\'s ports already store (vmware-version\'s VMware ESXi or vCenter '
            'release and build, amqp-info, docker-version, wdb-version) as port scan version readings, and the firmware a stored runZero block\'s hardware '
            'states as a hint (cveFeed.source_versions); then correlate the hosts that gained or lost one and every host that names VMware ESXi, '
            'whose CVE ranges are now read by build. A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the readings and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = source_versions.catch_up_version_scripts(apply=apply)
        self.stdout.write(f'Applied: {out["hosts"]} hosts; {out["readings"]} version script readings stored, {out["matches"]} CVE matches.' if apply
                          else f'Dry run: {out["hosts"]} hosts would have their stored version script output and runZero blocks read and be correlated.')
