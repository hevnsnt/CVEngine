from django.core.management.base import BaseCommand

from cveFeed import port_trim


class Command(BaseCommand):
    help = ('Cut the stored port list of every address that answers on a very large number of ports (a tarpit, a load balancer, a filtering device) to the '
            'lowest 100 open TCP ports, as a Sentinel report is cut. The port-flood finding stays. A dry run by default: --apply removes the rows.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='remove the surplus rows (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        apply = bool(options['apply']) and not options['dry_run']
        out = port_trim.trim(apply=apply)
        self.stdout.write(f'{"Applied" if apply else "Dry run"}: {out["addresses"]} flooded addresses held {out["ports_before"]} open ports; '
                          f'{out["removed"]} {"removed" if apply else "would be removed"}.')
