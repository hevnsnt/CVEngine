"""The scanner library's own anonymous GET (``cvengine_scanner.probes.http.probe_url``), for the tests that need the real request code.

The GET a Sentinel makes lives in the pinned ``cvengine-scanner`` library; this server has none (it sends a site nothing). A test that wants the
real bytes on a wire (a local server, the Host header, a body cap, a gzip a device sends against ``identity``) runs the library's function here,
under a scope policy that names the hosts the test asks and, where the test talks to its own loopback server, ``allow_loopback``."""
from unittest import mock

from cvengine_scanner.probes import http, transport
from cvengine_scanner.probes.policy import ScopePolicy

HOSTS = ('portal.example.test', 'original.example.test', 'www.rt.test', 'app.example.test', 'v6.example.test', 'evil.example.test', 'mixed.example.test', '127.0.0.1')


def policy(*hosts):
    return ScopePolicy({'hosts': list(hosts or HOSTS)}, internal=False)


def allow_loopback(testcase):
    """This fixture talks to its own loopback server: the address floor says yes for the test (a name's scope is still the policy's)."""
    patcher = mock.patch.object(ScopePolicy, 'address_refusal', return_value='')
    patcher.start()
    testcase.addCleanup(patcher.stop)


def allow_test_net(testcase):
    """The address floor with documentation space (192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::) let through, as the fixtures use it for a target; loopback,
    link-local, metadata and private space stay refused, as in production."""
    import ipaddress

    def refusal(self, value, literal=False):
        ip = ipaddress.ip_address(str(value).strip('[]'))
        return 'prohibited' if (ip.is_loopback or ip.is_link_local or ip.is_private and not any(
            ip in ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))) else ''
    patcher = mock.patch.object(ScopePolicy, 'address_refusal', refusal)
    patcher.start()
    testcase.addCleanup(patcher.stop)


def probe_url(url, policy_=None, **kwargs):
    return http.probe_url(url, policy_ or policy(), **kwargs)


__all__ = ['http', 'transport', 'policy', 'allow_loopback', 'probe_url']
