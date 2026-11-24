"""manage.py client_address_probe start | read TOKEN | trusted: the server side of scripts/client-address-check.sh (reNgine.client_probe).
The answer is the one line that starts with "probe: " (the process may print other lines while it starts)."""
import sys

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Issue a client address probe token, read what address the server took for it, or print the trusted proxies.'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=('start', 'read', 'trusted'))
        parser.add_argument('token', nargs='?', default='')

    def handle(self, *args, action='', token='', **options):
        from reNgine import client_probe
        if action == 'start':
            self.stdout.write(f'probe: {client_probe.start()}')
        elif action == 'trusted':
            from reNgine.client_ip import trusted_proxies
            self.stdout.write('probe: ' + ','.join(str(net) for net in trusted_proxies()))
        else:
            value = client_probe.read(token)
            if not value:
                sys.exit(1)
            self.stdout.write(f'probe: {value}')
