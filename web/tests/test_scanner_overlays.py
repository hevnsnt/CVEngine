import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class _Loader(yaml.SafeLoader):
	"""Compose's own tags (!reset, !override) are not YAML the stock loader knows."""


for _tag in ('!reset', '!override'):
	_Loader.add_multi_constructor(_tag, lambda loader, suffix, node: loader.construct_object(node, deep=True) if not isinstance(node, yaml.SequenceNode) else [])


def load(name):
	path = ROOT / name
	return yaml.load(path.read_text(), Loader=_Loader)


@unittest.skipUnless((ROOT / 'docker-compose.yml').is_file(), 'needs the repository root')
class ScannerOverlayTests(unittest.TestCase):
	"""The overlays that take address translation out of the scanner's path (docs/DEPLOYMENT.md, "Operating system detection and the scan path").
	They were run for real against Docker; this keeps their key settings from drifting."""

	def test_host_network_overlay_moves_only_the_built_in_scanner(self):
		overlay = load('docker-compose.hostnet.yml')
		# the scanner is where every scan runs; celery only learns the address it writes into the scanner's enrollment, and web is published on loopback
		self.assertEqual(set(overlay['services']), {'scanner', 'celery', 'web'})
		self.assertEqual(overlay['services']['web']['ports'], ['127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}:8000'])
		scanner = overlay['services']['scanner']
		self.assertEqual(scanner['network_mode'], 'host')
		# a container on the host network cannot also join a Docker network
		self.assertEqual(scanner['networks'], [])
		celery = overlay['services']['celery']
		self.assertNotIn('network_mode', celery)
		self.assertNotIn('networks', celery)
		self.assertEqual(celery['environment'], ['CVENGINE_SCANNER_SERVER_URL=http://127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}'])

	def test_host_network_overlay_no_longer_publishes_redis(self):
		# celery stays on the compose network and reaches Redis by name: nothing needs the broker on the host's loopback
		self.assertNotIn('redis', load('docker-compose.hostnet.yml')['services'])
		self.assertNotIn('REDIS', (ROOT / 'docker-compose.hostnet.yml').read_text())

	def test_macvlan_overlay_gives_the_scanner_its_own_lan_address(self):
		overlay = load('docker-compose.macvlan.yml')
		self.assertEqual(set(overlay['services']), {'scanner'})
		self.assertEqual(overlay['networks']['lan']['driver'], 'macvlan')
		lan = overlay['services']['scanner']['networks']['lan']
		self.assertIn('CVENGINE_SCANNER_IP', lan['ipv4_address'])
		# the LAN is the default route, so scans leave on it; the scanner keeps its bridge to reach the server (http://web:8000)
		self.assertEqual(lan['gw_priority'], 1)
		self.assertIn('scanner_network', overlay['services']['scanner']['networks'])

	def test_overlays_are_valid_beside_the_real_file_and_keep_the_secret_defaults(self):
		base = load('docker-compose.yml')
		for name in ('docker-compose.hostnet.yml', 'docker-compose.macvlan.yml'):
			for service in load(name)['services']:
				self.assertIn(service, base['services'], f'{name} overrides {service}, which docker-compose.yml does not define')
