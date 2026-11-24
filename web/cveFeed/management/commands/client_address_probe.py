"""manage.py client_address_probe start | read TOKEN | trusted | verdict TOKEN [--seen ADDRESS] [--published ADDRESS:PORT]: the server side of
scripts/client-address-check.sh (reNgine.client_probe, cveFeed.client_address). ``verdict`` reads what the probe of TOKEN found, decides what it
means (nothing in front of the bundled proxy, a host proxy whose address is not believed yet, ok, ...), opens or clears the App Admin notice, and
prints the verdict line for the update log. The answer is the one line that starts with "probe: " (the process may print other lines while it
starts)."""
import sys

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Issue a client address probe token, read what address the server took for it, print the trusted proxies, or record the verdict.'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=('start', 'read', 'trusted', 'verdict'))
        parser.add_argument('token', nargs='?', default='')
        parser.add_argument('--seen', default='', help='verdict: the address Cloudflare saw for the probe, when there is one')
        parser.add_argument('--published', default='', help='verdict: where the proxy publishes its port 443 (docker compose port proxy 443)')

    def handle(self, *args, action='', token='', seen='', published='', **options):
        from reNgine import client_probe
        if action == 'start':
            self.stdout.write(f'probe: {client_probe.start()}')
        elif action == 'trusted':
            from reNgine.client_ip import trusted_proxies
            self.stdout.write('probe: ' + ','.join(str(net) for net in trusted_proxies()))
        elif action == 'verdict':
            from cveFeed import client_address
            recorded, forwarded = client_probe.read(token) or '', client_probe.read_forwarded(token)
            kind, line = client_address.classify(recorded, forwarded, seen.strip(), published)
            client_address.apply(kind, {'recorded': recorded, 'forwarded': forwarded, 'seen': seen.strip(), 'published': published.strip()})
            self.stdout.write(f'probe: {line}')
        else:
            value = client_probe.read(token)
            if not value:
                sys.exit(1)
            self.stdout.write(f'probe: {value}')
