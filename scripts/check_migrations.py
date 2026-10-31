#!/usr/bin/env python3
"""Fail when two migrations of one app share a numeric prefix.

  python3 scripts/check_migrations.py [--root web]

Two branches that each add the next migration of an app give it the same number (cveFeed had two 0129 files). `makemigrations --check` only
catches the collision when the two end up as separate leaf nodes of the graph; a second file that depends on the first is a single leaf and
passes, yet leaves a number used twice, so the order of the files on disk no longer says the order they run in. This reads file names only
(standard library, no Django import), so it runs before anything else is set up. Exit status is 0 when every prefix is used once (or the
pair is in ALLOWED_DUPLICATES), 1 with each offending pair printed otherwise.

Rule when it fires: the branch that lands second renumbers its migration (and the dependencies that name it)."""
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# Pairs that are already applied on installed systems. A migration's name is recorded in django_migrations, so renaming one that has run
# makes Django apply it a second time (or fail on the dependencies that name it): these stay as they are. Keys are '<app>/<prefix>', values
# the exact file names allowed to share it, each with the reason. Nothing is added here for a new collision: the branch that lands second renumbers.
ALLOWED_DUPLICATES = {
    # both applied; builtin_scanner_schedule depends on feedwatermark_failures_assumed, so they form one leaf and the graph is sound
    'cveFeed/0129': {'0129_builtin_scanner_schedule.py', '0129_feedwatermark_failures_assumed.py'},
}

PREFIX = re.compile(r'^(\d{4})_.*\.py$')


def duplicates(root):
    """Every ``(app, prefix, names)`` where two or more migration files of ``<root>/<app>/migrations`` share ``prefix`` and are not allowed."""
    found = []
    for directory in sorted(Path(root).glob('*/migrations')):
        if not directory.is_dir():
            continue
        by_prefix = defaultdict(list)
        for path in directory.glob('*.py'):
            match = PREFIX.match(path.name)
            if match:
                by_prefix[match.group(1)].append(path.name)
        for prefix, names in sorted(by_prefix.items()):
            names = sorted(names)
            if len(names) > 1 and set(names) != ALLOWED_DUPLICATES.get(f'{directory.parent.name}/{prefix}'):
                found.append((directory.parent.name, prefix, names))
    return found


def main(argv=None):
    default_root = Path(__file__).resolve().parent.parent / 'web'
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--root', default=str(default_root), help='the directory holding the apps (default: web/)')
    args = parser.parse_args(argv)
    found = duplicates(args.root)
    for app, prefix, names in found:
        print(f'{app}/migrations: {prefix} is used by {len(names)} files: {", ".join(names)}', file=sys.stderr)
    if found:
        print('Renumber the migration of the branch that lands second (and the dependencies that name it).', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
