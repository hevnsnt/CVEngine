import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ProxyImageTests(unittest.TestCase):
	def test_the_proxy_image_is_pulled_by_the_update_scripts_before_they_stop_anything_not_by_up(self):
		"""A stock image is only as new as the day it was first pulled, so an update brings nginx's security releases by pulling it. That pull used to
		be `pull_policy: always`, which makes it part of `up`, which runs AFTER the database migration: an unreachable or rate-limiting registry then
		failed an update that was otherwise done (and was retried by the watcher for ever), and an offline host could never update at all. The scripts
		pull it up front and keep the image on the host when that fails."""
		compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
		proxy = compose['services']['proxy']
		self.assertEqual(proxy['image'], 'nginx:alpine')
		self.assertNotIn('pull_policy', proxy)
		self.assertNotIn('proxy', yaml.safe_load((ROOT / 'docker-compose.dev.yml').read_text())['services'])
		for script in ('update-deploy.sh', 'update.sh'):
			text = (ROOT / 'scripts' / script).read_text()
			self.assertIn('pull --quiet proxy', text, script)
			self.assertLess(text.index('pull --quiet proxy'), text.index('build web celery celery-beat'), script)

	def test_redis_and_postgres_are_pulled_before_anything_stops_and_recreated_only_when_moved(self):
		"""redis:alpine and postgres:18-alpine are moving tags inside one major version. Nothing pulled them, so an install kept the Redis and
		Postgres it was installed with (the production VPS was on Redis 8.10.2 with 8.10.3 published). Both scripts pull them before the build,
		and bring each up with a plain `up -d --no-deps`, which recreates a container only when its image moved."""
		compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
		self.assertTrue(compose['services']['redis']['image'].startswith('redis:'))
		self.assertTrue(compose['services']['db']['image'].startswith('postgres:18'))  # a major move is a migration, never a pull
		for script in ('update-deploy.sh', 'update.sh'):
			text = (ROOT / 'scripts' / script).read_text()
			self.assertIn('pull --quiet db redis', text, script)
			self.assertLess(text.index('pull --quiet db redis'), text.index('build web celery celery-beat'), script)
			self.assertIn('up -d --no-deps redis', text, script)
			self.assertNotIn('pull_policy', compose['services']['redis'])
