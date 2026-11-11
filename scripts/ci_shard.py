#!/usr/bin/env python3
"""Print the Django test labels of one CI shard: ``ci_shard.py INDEX COUNT`` (INDEX from 1), run from ``web/``.

Test modules are dealt out by their number of test methods, biggest first, to the emptiest shard, so the shards are about the same size and the split is
the same on every run for the same files. A module added later lands in a shard by the same rule. Every module is in exactly one shard
(``--check`` proves it)."""
import os
import re
import sys

TESTS = 'tests'


def modules():
    sizes = {}
    for name in sorted(os.listdir(TESTS)):
        if name.startswith('test_') and name.endswith('.py'):
            with open(os.path.join(TESTS, name), encoding='utf-8', errors='ignore') as handle:
                sizes[name[:-3]] = max(1, len(re.findall(r'^\s+(?:async )?def test', handle.read(), re.M)))
    return sizes


def shards(count):
    out, load = [[] for _ in range(count)], [0] * count
    for name, size in sorted(modules().items(), key=lambda item: (-item[1], item[0])):
        index = load.index(min(load))
        out[index].append(name)
        load[index] += size
    return out


if __name__ == '__main__':
    if sys.argv[1:2] == ['--check']:
        count = int(sys.argv[2])
        flat = [m for shard in shards(count) for m in shard]
        assert sorted(flat) == sorted(modules()) and len(flat) == len(set(flat)), 'a test module is missing from the shards or in two of them'
        print(f'{len(flat)} modules in {count} shards')
    else:
        index, count = int(sys.argv[1]), int(sys.argv[2])
        print(' '.join(f'tests.{m}' for m in sorted(shards(count)[index - 1])))
