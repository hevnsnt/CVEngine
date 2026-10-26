import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ProxyImageTests(unittest.TestCase):
	def test_the_proxy_image_is_pulled_on_every_up_so_an_update_brings_nginx_security_releases(self):
		"""A stock image is only as new as the day it was first pulled. Compose pulls it itself on `up`, whichever version of the update script
		runs it (the script that applies an update is the copy already on the host, and cannot be relied on to know about a new step)."""
		compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
		proxy = compose['services']['proxy']
		self.assertEqual(proxy['image'], 'nginx:alpine')
		self.assertEqual(proxy['pull_policy'], 'always')
		self.assertNotIn('proxy', yaml.safe_load((ROOT / 'docker-compose.dev.yml').read_text())['services'])
