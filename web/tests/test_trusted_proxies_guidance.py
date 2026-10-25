import os
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from reNgine.client_ip import client_ip

GATEWAY = '172.18.0.1'     # what the web container sees when a proxy on the Docker host connects to it
REAL_CLIENT = '198.51.100.9'
MY_PROXY_LAN = '203.0.113.0/24'  # the proxy's own network, which is NOT the address the web container sees


def ip_for(trusted, remote=GATEWAY, forwarded=REAL_CLIENT):
    request = RequestFactory().get('/', REMOTE_ADDR=remote, HTTP_X_FORWARDED_FOR=forwarded)
    with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': trusted}):
        return client_ip(request)


class TrustedProxiesGuidanceTests(SimpleTestCase):
    """What the proxy docs must tell operators, pinned to the behaviour: CVENGINE_TRUSTED_PROXIES lists the addresses the web container
    sees CONNECTING to it. Replacing the Docker default with the proxy's own network makes the allowlist and the abuse guard see the
    Docker gateway for every request."""

    def test_the_docker_default_gives_the_real_client_behind_a_proxy_on_the_host(self):
        self.assertEqual(ip_for('172.16.0.0/12'), REAL_CLIENT)

    def test_replacing_the_default_with_the_proxys_own_network_hides_every_client(self):
        self.assertEqual(ip_for(MY_PROXY_LAN), GATEWAY)  # the gateway is not trusted, so X-Forwarded-For is ignored

    def test_adding_a_proxy_network_to_the_default_keeps_the_real_client(self):
        self.assertEqual(ip_for(f'172.16.0.0/12,{MY_PROXY_LAN}'), REAL_CLIENT)

    def test_a_further_proxy_hop_that_appends_is_skipped_only_when_its_network_is_added(self):
        chain = f'{REAL_CLIENT}, 203.0.113.7'  # the CDN edge appended itself
        self.assertEqual(ip_for('172.16.0.0/12', forwarded=chain), '203.0.113.7')  # only the Docker range trusted: the edge is taken for the client
        self.assertEqual(ip_for(f'172.16.0.0/12,{MY_PROXY_LAN}', forwarded=chain), REAL_CLIENT)

    def test_a_client_cannot_pick_its_own_address_through_an_untrusted_peer(self):
        self.assertEqual(ip_for('172.16.0.0/12', remote='192.0.2.50', forwarded='10.9.9.9'), '192.0.2.50')
