"""cveFeed.port_trim: an address that answers on almost every port keeps the lowest 100, and nothing else is touched."""
from django.core.management import call_command
from django.test import TestCase

from cveFeed import port_flood, port_trim
from startScan.models import IpAddress, Port


def ports_of(ip):
    return sorted(ip.ports.values_list('number', flat=True))


class PortTrimTests(TestCase):
    def ip(self, address, numbers, **kw):
        ip = IpAddress.objects.create(address=address)
        for n in numbers:
            ip.ports.add(Port.objects.create(number=n, state=kw.get('state', 'open'), protocol=kw.get('protocol', 'tcp')))
        return ip

    def test_a_flooded_address_keeps_its_lowest_hundred_open_ports(self):
        flooded = self.ip('192.0.2.1', range(1, 701))
        small = self.ip('192.0.2.2', [22, 80, 443])
        out = port_trim.trim(apply=True)
        self.assertEqual(out, {'addresses': 1, 'ports_before': 700, 'removed': 600})
        self.assertEqual(ports_of(flooded), list(range(1, 101)))
        self.assertEqual(ports_of(small), [22, 80, 443])
        self.assertEqual(Port.objects.count(), 103)  # the removed rows are gone, not just unlinked

    def test_a_dry_run_changes_nothing_and_a_second_run_finds_nothing(self):
        flooded = self.ip('192.0.2.3', range(1, 301))
        self.assertEqual(port_trim.trim(apply=False)['removed'], 200)
        self.assertEqual(len(ports_of(flooded)), 300)
        port_trim.trim(apply=True)
        self.assertEqual(port_trim.trim(apply=True), {'addresses': 0, 'ports_before': 0, 'removed': 0})

    def test_only_open_tcp_ports_count_and_only_they_are_cut(self):
        ip = self.ip('192.0.2.4', range(1, 151))
        udp = self.ip('192.0.2.5', range(1, 201), protocol='udp')  # UDP rows are not "open TCP ports"
        closed = self.ip('192.0.2.6', range(1, 201), state='closed')
        port_trim.trim(apply=True)
        self.assertEqual(len(ports_of(ip)), 100)
        self.assertEqual(len(ports_of(udp)), 200)
        self.assertEqual(len(ports_of(closed)), 200)

    def test_the_port_flood_finding_still_fires_after_the_cut(self):
        self.assertGreaterEqual(port_trim.keep_count(), port_flood.THRESHOLD)  # a cut list reaches the threshold exactly
        ip = self.ip('192.0.2.7', range(1, 401))
        port_trim.trim(apply=True)
        counts = {ip.address: ip.ports.count()}
        self.assertIsNotNone(port_flood.evaluate('www.example.test', counts))

    def test_the_command_defaults_to_a_dry_run(self):
        from io import StringIO
        flooded = self.ip('192.0.2.8', range(1, 251))
        out = StringIO()
        call_command('trim_flooded_ports', stdout=out)
        self.assertIn('Dry run: 1 flooded addresses held 250 open ports; 150 would be removed.', out.getvalue())
        self.assertEqual(len(ports_of(flooded)), 250)
        call_command('trim_flooded_ports', '--apply', stdout=out)
        self.assertEqual(len(ports_of(flooded)), 100)
