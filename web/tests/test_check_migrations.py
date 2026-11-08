"""scripts/check_migrations.py: a migration number used twice in one app fails the CI step, the pair that is already applied is allowed, and
the migrations in the repository pass. Run on a temporary tree of empty files: the script reads names only."""
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / 'scripts' / 'check_migrations.py'

spec = importlib.util.spec_from_file_location('check_migrations', SCRIPT)
check_migrations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_migrations)


class CheckMigrationsTests(SimpleTestCase):
    def tree(self, **apps):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        for app, names in apps.items():
            directory = Path(root.name) / app / 'migrations'
            directory.mkdir(parents=True)
            for name in names:
                (directory / name).write_text('')
        return Path(root.name)

    def run_script(self, root):
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(root)], capture_output=True, text=True, check=False)

    def test_a_clean_tree_passes(self):
        root = self.tree(app=['__init__.py', '0001_initial.py', '0002_more.py'], other=['0001_initial.py', '0002_more.py'])
        self.assertEqual(check_migrations.duplicates(root), [])
        result = self.run_script(root)
        self.assertEqual((result.returncode, result.stderr), (0, ''))

    def test_the_same_prefix_twice_in_one_app_fails_and_names_the_pair(self):
        root = self.tree(app=['0001_initial.py', '0002_first.py', '0002_second.py'])
        self.assertEqual(check_migrations.duplicates(root), [('app', '0002', ['0002_first.py', '0002_second.py'])])
        result = self.run_script(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn('app/migrations: 0002 is used by 2 files: 0002_first.py, 0002_second.py', result.stderr)

    def test_every_offending_app_is_reported(self):
        root = self.tree(one=['0003_a.py', '0003_b.py'], two=['0007_a.py', '0007_b.py', '0007_c.py'], fine=['0001_initial.py'])
        self.assertEqual([found[:2] for found in check_migrations.duplicates(root)], [('one', '0003'), ('two', '0007')])
        result = self.run_script(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn('one/migrations: 0003', result.stderr)
        self.assertIn('two/migrations: 0007 is used by 3 files', result.stderr)

    def test_the_same_prefix_in_two_apps_is_fine(self):
        root = self.tree(one=['0002_a.py'], two=['0002_b.py'])
        self.assertEqual(check_migrations.duplicates(root), [])

    def test_the_applied_pair_is_allowed_but_a_third_file_with_its_prefix_is_not(self):
        pair = ['0129_builtin_scanner_schedule.py', '0129_feedwatermark_failures_assumed.py']
        root = self.tree(cveFeed=['0128_before.py', *pair])
        self.assertEqual(check_migrations.duplicates(root), [])
        self.assertEqual(self.run_script(root).returncode, 0)
        root = self.tree(cveFeed=[*pair, '0129_third.py'])
        self.assertEqual(len(check_migrations.duplicates(root)), 1)
        self.assertEqual(self.run_script(root).returncode, 1)

    def test_the_allowlist_is_per_app(self):
        root = self.tree(other=['0129_builtin_scanner_schedule.py', '0129_feedwatermark_failures_assumed.py'])
        self.assertEqual(len(check_migrations.duplicates(root)), 1)

    def test_files_that_are_not_migrations_are_ignored(self):
        root = self.tree(app=['__init__.py', '0001_initial.py', '0001_notes.txt', 'helpers.py', '0001.py', '00011_long.py'])
        self.assertEqual(check_migrations.duplicates(root), [])

    def test_the_migrations_in_the_repository_pass(self):
        self.assertEqual(check_migrations.duplicates(REPO / 'web'), [])
        self.assertEqual(self.run_script(REPO / 'web').returncode, 0)

    def test_every_allowed_pair_exists_in_the_repository(self):
        # a stale allowlist entry would let a new collision of that number through
        for key, names in check_migrations.ALLOWED_DUPLICATES.items():
            app, _ = key.split('/')
            for name in names:
                self.assertTrue((REPO / 'web' / app / 'migrations' / name).is_file(), name)
