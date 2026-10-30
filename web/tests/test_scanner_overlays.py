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

	def test_host_network_overlay_moves_only_the_celery_container(self):
		overlay = load('docker-compose.hostnet.yml')
		self.assertEqual(set(overlay['services']), {'celery', 'redis'})
		celery = overlay['services']['celery']
		self.assertEqual(celery['network_mode'], 'host')
		# a container on the host network cannot also join a Docker network
		self.assertEqual(celery['networks'], [])
		env = ' '.join(celery['environment'])
		for name in ('CELERY_BROKER', 'CELERY_BACKEND', 'POSTGRES_HOST'):
			self.assertIn(name, env)
		self.assertNotIn('redis:6379', env, 'Docker DNS names do not resolve from the host network')

	def test_host_network_overlay_publishes_redis_on_loopback_only(self):
		ports = load('docker-compose.hostnet.yml')['services']['redis']['ports']
		self.assertTrue(all(str(p).startswith('127.0.0.1:') for p in ports), ports)

	def test_macvlan_overlay_gives_celery_its_own_lan_address(self):
		overlay = load('docker-compose.macvlan.yml')
		self.assertEqual(overlay['networks']['lan']['driver'], 'macvlan')
		lan = overlay['services']['celery']['networks']['lan']
		self.assertIn('CVENGINE_SCANNER_IP', lan['ipv4_address'])
		# the LAN is the default route, so scans leave on it; Redis and PostgreSQL stay on the bridge
		self.assertEqual(lan['gw_priority'], 1)
		self.assertIn('rengine_network', overlay['services']['celery']['networks'])

	def test_overlays_are_valid_beside_the_real_file_and_keep_the_secret_defaults(self):
		base = load('docker-compose.yml')
		for name in ('docker-compose.hostnet.yml', 'docker-compose.macvlan.yml'):
			for service in load(name)['services']:
				self.assertIn(service, base['services'], f'{name} overrides {service}, which docker-compose.yml does not define')
