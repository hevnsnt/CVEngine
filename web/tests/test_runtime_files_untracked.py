"""Runtime state files must never be tracked in git.

web/.update-source was committed by mistake (21a95eb). The app writes that file on every server, so the update's `git merge --ff-only` found an
untracked file that the new commit also tracks and refused: "cannot be fast-forwarded onto this server's checkout". Every install pressing Update
would have stopped there.
"""
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Dotfiles in web/ that belong to the repository. Anything else starting with a dot is runtime state.
TRACKED_DOTFILES = {'web/.dockerignore', 'web/.gitignore', 'web/.version'}

RUNTIME = [
    'web/.commit', 'web/.update-source', 'web/.update-source.tmp', 'web/.update-phase.json', 'web/.update-disk.json',
    'web/.update-approved', 'web/.update-branch', 'web/.update-mode', 'web/.update-log', 'web/.update-lock',
    'web/.update-sentinels', 'web/.updater-heartbeat', 'web/.upstream-state.json', 'web/.cert-status.json',
    'web/.scanner-update-requested', 'web/.scanner-update-done', 'web/.scanner-plan-wanted', 'web/.scanner-plan-applied.json',
    'web/.openvas-wanted', 'web/.openvas-applied', 'web/.openvas-restart', 'web/.openvas-restarted', 'web/.openvas-log',
    'web/exports/file.csv',
]


def git(*args):
    return subprocess.run(['git', '-C', ROOT, *args], capture_output=True, text=True)


@unittest.skipUnless(os.path.isdir(os.path.join(ROOT, '.git')) or os.path.isfile(os.path.join(ROOT, '.git')), 'not a git checkout')
class RuntimeFilesUntrackedTests(unittest.TestCase):
    def test_no_runtime_dotfile_is_tracked(self):
        listed = git('ls-files', 'web')
        self.assertEqual(listed.returncode, 0, listed.stderr)
        bad = [p for p in listed.stdout.splitlines()
               if os.path.basename(p).startswith('.') and p.count('/') == 1 and p not in TRACKED_DOTFILES]
        self.assertEqual(bad, [], 'runtime state is tracked in git; git rm --cached it and add it to .gitignore')

    def test_every_runtime_file_is_ignored(self):
        missing = [p for p in RUNTIME if git('check-ignore', '-q', p).returncode != 0]
        self.assertEqual(missing, [], 'add these to .gitignore: they are written on the server')


if __name__ == '__main__':
    unittest.main()
