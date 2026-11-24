"""The CI split of the Django suite puts every test module in exactly one shard (scripts/ci_shard.py), balanced by the module times the CI logs print
(scripts/ci_shard_weights.json, ``ci_shard.py --refresh``, the runner's ``--module-times``)."""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from django.test import SimpleTestCase

from reNgine import test_runner as runner

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
SCRIPT = os.path.join(ROOT, 'scripts', 'ci_shard.py')
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'build-pr.yml')


def load_script():
    spec = importlib.util.spec_from_file_location('ci_shard', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ShardTests(SimpleTestCase):
    def setUp(self):
        self.shard = load_script()
        self.here = os.getcwd()
        os.chdir(os.path.join(os.path.dirname(__file__), '..'))
        self.addCleanup(os.chdir, self.here)

    def workflow_count(self):
        """The shard count the workflow runs: the count it passes to ci_shard.py, checked against its matrix and its job name."""
        with open(WORKFLOW, encoding='utf-8') as handle:
            text = handle.read()
        count = int(re.search(r'ci_shard\.py \$\{\{ matrix\.shard \}\} (\d+)', text).group(1))
        matrix = re.search(r'^\s+shard: \[([0-9, ]+)\]', text, re.M).group(1)
        self.assertEqual([int(n) for n in matrix.split(',')], list(range(1, count + 1)), 'the matrix must list every shard once')
        self.assertIn(f'(${{{{ matrix.shard }}}} of {count})', text, 'the job name must say how many shards there are')
        return count

    def assert_one_shard_each(self, count, data=None):
        parts = self.shard.shards(count, data)
        flat = [m for shard in parts for m in shard]
        self.assertEqual(len(parts), count)
        self.assertEqual(sorted(flat), sorted(self.shard.modules()))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertTrue(all(parts), 'a shard with no module')

    def test_every_test_module_is_in_exactly_one_of_three_shards(self):
        flat = [m for shard in self.shard.shards(3) for m in shard]
        self.assertEqual(sorted(flat), sorted(self.shard.modules()))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertIn('test_ci_shard', flat)

    def test_the_shards_are_about_the_same_size(self):
        # by their measured time (seconds of one process), no longer by their number of test methods: a test method takes from a millisecond to
        # two minutes, so equal counts left one shard five minutes behind the others
        sizes = self.shard.weights()
        loads = [sum(sizes[m] for m in shard) for shard in self.shard.shards(3)]
        self.assertLess(max(loads) - min(loads), 0.1 * max(loads))

    def test_every_test_module_is_in_exactly_one_shard_of_the_count_the_workflow_runs(self):
        for count in sorted({self.workflow_count(), 2, 3, 4, 5}):
            with self.subTest(count=count):
                self.assert_one_shard_each(count)

    def test_the_shards_finish_within_a_minute_of_each_other_by_the_weights(self):
        minutes = self.shard.predict(self.workflow_count())
        self.assertLessEqual(max(minutes) - min(minutes), 1.0, minutes)

    def test_the_weights_file_names_real_modules_and_holds_its_costs(self):
        data = self.shard.load_weights()
        self.assertGreater(data['runs'], 0, 'the weights come from CI runs')
        for key in ('workers', 'fixed_seconds', 'shard_one_seconds', 'seconds_per_test'):
            self.assertGreater(data[key], 0, key)
        present = self.shard.modules()
        self.assertTrue(all(re.fullmatch(r'test_\w+', name) for name in data['modules']))
        self.assertGreater(len(set(data['modules']) & set(present)), 0.8 * len(present), 'most modules have a measured time: run --refresh')

    def test_the_split_is_the_same_on_every_call(self):
        self.assertEqual(self.shard.shards(3), self.shard.shards(3))
        self.assertEqual(self.shard.shards(4), load_script().shards(4))

    def test_a_shard_prints_its_labels_longest_first(self):
        every = self.shard.weights()
        labels = subprocess.run([sys.executable, SCRIPT, '1', str(self.workflow_count())], capture_output=True, text=True, check=True).stdout.split()
        names = [label.removeprefix('tests.') for label in labels]
        self.assertEqual(sorted(names), sorted(self.shard.shards(self.workflow_count())[0]))
        self.assertEqual([every[n] for n in names], sorted((every[n] for n in names), reverse=True))

    def test_a_module_with_no_measured_time_weighs_its_tests_and_still_lands_once(self):
        data = {**self.shard.load_weights(), 'modules': {}, 'seconds_per_test': 0.5, 'shard_one_seconds': 0}
        with mock.patch.object(self.shard, 'modules', return_value={'test_new_a': 4, 'test_new_b': 10, 'test_new_c': 1}):
            self.assertEqual(self.shard.weights(data), {'test_new_a': 2.0, 'test_new_b': 5.0, 'test_new_c': 0.5})
            self.assert_one_shard_each(2, data)
            self.assertEqual(self.shard.shards(2, data), [['test_new_b'], ['test_new_a', 'test_new_c']])

    def test_shard_one_carries_its_own_steps(self):
        data = {**self.shard.load_weights(), 'modules': {}, 'seconds_per_test': 1.0, 'workers': 2, 'shard_one_seconds': 3.0}
        with mock.patch.object(self.shard, 'modules', return_value={'test_a': 6, 'test_b': 6}):
            # shard 1 starts with 3 seconds of its own steps on each of 2 workers, so the first module goes to shard 2
            self.assertEqual(self.shard.shards(2, data), [['test_b'], ['test_a']])

    def test_refresh_reads_the_module_times_and_the_database_setup_from_a_log(self):
        log = '\n'.join([
            "2026-11-24T03:22:59.8533065Z Creating test database for alias 'default'...",
            "2026-11-24T03:23:56.8990346Z Cloning test database for alias 'default'...",
            "2026-11-24T03:23:57.4793105Z Cloning test database for alias 'default'...",
            '2026-11-24T03:38:58.0000000Z MODULE-TIME    130.25 tests.test_report_memory',
            '2026-11-24T03:38:58.0000000Z MODULE-TIME      0.20 tests.test_ci_shard',
            '2026-11-24T03:38:58.0000000Z MODULE-TIME total 130.45',
        ])
        parsed = self.shard.parse_log(log)
        self.assertEqual(parsed['modules'], {'test_report_memory': 130.25, 'test_ci_shard': 0.2})
        self.assertEqual(parsed['workers'], 2)
        self.assertAlmostEqual(parsed['database_seconds'], 57.6, places=1)

    def test_refresh_takes_the_median_of_the_runs_and_drops_removed_modules(self):
        logs = [[{'modules': {'test_ci_shard': s, 'test_gone_long_ago': 9.0}, 'database_seconds': 60, 'workers': 4, 'outside_seconds': o,
                  'shard_one_seconds': 20}] for s, o in ((1.0, 50), (2.0, 70), (9.0, 60))]
        data = self.shard.build(logs)
        self.assertEqual(data['modules']['test_ci_shard'], 2.0)
        self.assertNotIn('test_gone_long_ago', data['modules'])
        self.assertEqual((data['runs'], data['workers'], data['fixed_seconds'], data['shard_one_seconds']), (3, 4, 120.0, 20))


class ModuleTimesTests(SimpleTestCase):
    """The runner's --module-times: each class's wall time, its class fixtures included, summed per module."""

    def folder(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        return folder

    def test_each_class_is_timed_with_its_fixtures_and_summed_per_module(self):
        folder = self.folder()

        class SlowFixtures(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                time.sleep(0.2)

            def test_one(self):
                pass

        class Quick(unittest.TestCase):
            def test_one(self):
                pass

            def test_two(self):
                time.sleep(0.05)

        with mock.patch.dict(os.environ, {runner.MODULE_TIMES_ENV: folder}):
            runner.time_classes(force=True)
            suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in (SlowFixtures, Quick)])
            suite.run(unittest.TestResult())
        with open(os.path.join(folder, f'times-{os.getpid()}.tsv'), encoding='utf-8') as handle:
            rows = [line.rstrip('\n').split('\t') for line in handle]
        timed = {qualname.rsplit('.', 1)[-1]: float(seconds) for module, qualname, seconds in rows if module == __name__}
        self.assertGreaterEqual(timed['SlowFixtures'], 0.2)
        self.assertGreaterEqual(timed['Quick'], 0.05)
        self.assertLess(timed['Quick'], 0.2)
        self.assertAlmostEqual(runner.module_times(folder)[__name__], sum(timed.values()), places=2)

    def test_nothing_is_written_while_the_variable_is_unset(self):
        folder = self.folder()
        runner.time_classes(force=True)

        class Case(unittest.TestCase):
            def test_one(self):
                pass
        with mock.patch.dict(os.environ, {}):
            os.environ.pop(runner.MODULE_TIMES_ENV, None)
            unittest.defaultTestLoader.loadTestsFromTestCase(Case).run(unittest.TestResult())
        self.assertEqual(os.listdir(folder), [])

    def test_the_printed_lines_are_what_refresh_reads(self):
        folder = self.folder()
        with open(os.path.join(folder, 'times-1.tsv'), 'w', encoding='utf-8') as handle:
            handle.write('tests.test_a\tA\t1.5\ntests.test_a\tB\t2.0\ntests.test_b\tC\t0.25\n')
        printer = runner.IsolatedRedisRunner.__new__(runner.IsolatedRedisRunner)
        printer.module_times_dir = folder
        with mock.patch('builtins.print') as printed:
            printer.print_module_times()
        text = '\n'.join(' '.join(str(a) for a in call.args) for call in printed.call_args_list)
        self.assertEqual(load_script().parse_log(text)['modules'], {'test_a': 3.5, 'test_b': 0.25})
        self.assertFalse(os.path.exists(folder), 'the folder is removed once printed')
