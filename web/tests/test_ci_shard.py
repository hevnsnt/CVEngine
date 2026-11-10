"""The CI split of the Django suite puts every test module in exactly one shard (scripts/ci_shard.py)."""
import importlib.util
import os

from django.test import SimpleTestCase

SCRIPT = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'ci_shard.py')


class ShardTests(SimpleTestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('ci_shard', SCRIPT)
        self.shard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.shard)
        self.here = os.getcwd()
        os.chdir(os.path.join(os.path.dirname(__file__), '..'))
        self.addCleanup(os.chdir, self.here)

    def test_every_test_module_is_in_exactly_one_of_three_shards(self):
        flat = [m for shard in self.shard.shards(3) for m in shard]
        self.assertEqual(sorted(flat), sorted(self.shard.modules()))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertIn('test_ci_shard', flat)

    def test_the_shards_are_about_the_same_size(self):
        sizes = self.shard.modules()
        loads = [sum(sizes[m] for m in shard) for shard in self.shard.shards(3)]
        self.assertLess(max(loads) - min(loads), 0.1 * max(loads))
