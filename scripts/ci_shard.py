#!/usr/bin/env python3
"""Print the Django test labels of one CI shard: ``ci_shard.py INDEX COUNT`` (INDEX from 1), run from ``web/``.

The modules are split by their measured run time so the shards finish at about the same time, and the split is the same on every run for the same
files and the same weights. The weights come from the CI logs (scripts/ci_shard_weights.json, written by ``ci_shard.py --refresh``): the Django
test step runs with ``--module-times``, which prints one ``MODULE-TIME`` line per module with its seconds, the group Django runs it in and its
longest class. A module with no measured time yet (a new file) weighs its number of test methods times the median seconds per test of the
measured modules, so it lands in a shard by the same rule.

Each module, longest first, goes to the shard whose predicted finish it delays least. A shard's finish is simulated the way Django runs it: the
TestCase classes first, then the other SimpleTestCase ones, then plain unittest classes, each group in label order, each class on the first free
worker. That matters because a long plain unittest class (the update script tests run about five minutes in one class) only starts when the rest
of its shard is done. The steps only shard 1 runs (the migration checks, the front-end tests) count toward shard 1. The labels of a shard are
printed longest first, the order the simulation assumes. Every module is in exactly one shard (``--check`` proves it).

  ci_shard.py INDEX COUNT        the labels of shard INDEX of COUNT
  ci_shard.py --check COUNT      every module in exactly one of COUNT shards
  ci_shard.py --predict COUNT    the predicted minutes of each shard's job from the weights
  ci_shard.py --refresh [--runs N] [--repo OWNER/NAME] [--workflow FILE] [--run ID ...] [LOG ...]
                                 rewrite the weights from the logs of the last N (default 5) successful pull request runs of build-pr.yml (any
                                 event for another workflow) that printed module times (gh must be logged in), of the runs given by id, or from
                                 saved job logs given by name
"""
import json
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime

TESTS = 'tests'
WEIGHTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ci_shard_weights.json')
WORKFLOW = 'build-pr.yml'
REPO = 'hevnsnt/CVEngine'
JOB_NAME = 'Django security and tenancy tests'
TEST_STEP = 'Django test suite'
MODULE_TIME = re.compile(r'MODULE-TIME\s+([0-9.]+)\s+tests\.(test_\w+)(?:\s+group=(\d))?(?:\s+longest=([0-9.]+))?')
DEFAULTS = {'workers': 4, 'fixed_seconds': 120.0, 'shard_one_seconds': 30.0, 'seconds_per_test': 0.5, 'modules': {}, 'runs': 0}


def modules():
    sizes = {}
    for name in sorted(os.listdir(TESTS)):
        if name.startswith('test_') and name.endswith('.py'):
            with open(os.path.join(TESTS, name), encoding='utf-8', errors='ignore') as handle:
                sizes[name[:-3]] = max(1, len(re.findall(r'^\s+(?:async )?def test', handle.read(), re.M)))
    return sizes


def load_weights(path=WEIGHTS):
    try:
        with open(path, encoding='utf-8') as handle:
            return {**DEFAULTS, **json.load(handle)}
    except FileNotFoundError:
        return dict(DEFAULTS)


def table(data=None):
    """``(seconds, longest class, group)`` per module: measured, or for a module not measured yet its test methods times the median seconds per
    test, as one class of the TestCase group."""
    data = load_weights() if data is None else data
    measured, out = data['modules'], {}
    for name, size in modules().items():
        if name in measured:
            seconds, longest, group = measured[name]
            out[name] = (float(seconds), float(longest), int(group))
        else:
            seconds = round(size * data['seconds_per_test'], 1)
            out[name] = (seconds, seconds, 0)
    return out


def weights(data=None):
    """Seconds of one test process per module."""
    return {name: row[0] for name, row in table(data).items()}


def label_order(names, rows):
    """Longest first: Django keeps the label order inside each group it runs, so a long module starts while short ones can still fill the other
    workers instead of running alone at the end."""
    return sorted(names, key=lambda m: (-rows[m][0], m))


def finish(names, rows, workers):
    """Seconds until the last worker is done with these modules: each group in label order, a module's longest class on the first free worker and
    the rest of the module spread over the workers that are free first (its other classes are short next to the longest)."""
    free = [0.0] * workers
    for name in sorted(label_order(names, rows), key=lambda m: rows[m][2]):  # a stable sort: label order inside each group
        seconds, longest, _ = rows[name]
        block = min(longest, seconds)
        index = free.index(min(free))
        free[index] += block
        rest = seconds - block
        while rest > 1e-9:  # fill the lowest workers up to the next level
            free.sort()
            low = [i for i, value in enumerate(free) if value == free[0]]
            step = (free[len(low)] - free[0]) if len(low) < workers else rest / workers
            step = min(step, rest / len(low))
            for i in low:
                free[i] += step
            rest -= step * len(low)
    return max(free)


def shards(count, data=None):
    data = load_weights() if data is None else data
    rows, workers = table(data), data['workers']
    own = [data['shard_one_seconds']] + [0.0] * (count - 1)  # shard 1's own steps
    out, done = [[] for _ in range(count)], [own[i] for i in range(count)]
    for name in label_order(rows, rows):
        candidates = [(own[i] + finish(out[i] + [name], rows, workers), done[i], i) for i in range(count)]
        _, _, index = min(candidates)
        out[index].append(name)
        done[index] = candidates[index][0]
    return out


def predict(count, data=None):
    """Predicted minutes of each shard's job: the fixed cost every job pays, shard 1's own steps, and the simulated finish of its modules."""
    data = load_weights() if data is None else data
    rows = table(data)
    return [round((data['fixed_seconds'] + (data['shard_one_seconds'] if index == 0 else 0) + finish(shard, rows, data['workers'])) / 60, 1)
            for index, shard in enumerate(shards(count, data))]


# --refresh: the module times and the fixed costs, read back from the CI logs

def _gh(*args):
    return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout


def _stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def parse_log(text):
    """Per module ``(seconds, longest class, group)``, the test database setup seconds and the worker count from one Django test job log."""
    times = {}
    for seconds, name, group, longest in MODULE_TIME.findall(text):
        times[name] = (float(seconds), float(longest or seconds), int(group or 0))
    lines = text.splitlines()
    created = next((line for line in lines if 'Creating test database for alias' in line), None)
    cloned = [line for line in lines if 'Cloning test database for alias' in line]
    database = None
    if created and cloned:
        try:
            database = (_stamp(cloned[-1].split(' ', 1)[0]) - _stamp(created.split(' ', 1)[0])).total_seconds()
        except ValueError:  # a log saved without the runner's timestamps
            pass
    return {'modules': times, 'database_seconds': database, 'workers': len(cloned) or None}


def _seconds(entry):
    return (_stamp(entry['completed_at']) - _stamp(entry['started_at'])).total_seconds()


def _job_costs(job, skipped_elsewhere):
    """Seconds of the job outside its test step, and of the steps that ran here but were skipped on the other shards."""
    steps = {s['name']: s for s in job['steps'] if s.get('started_at') and s.get('completed_at')}
    outside = _seconds(job) - _seconds(steps[TEST_STEP])
    only = sum(_seconds(s) for name, s in steps.items() if s.get('conclusion') == 'success' and skipped_elsewhere.get(name) == 'skipped')
    return outside, only


def collect(runs, repo, workflow=WORKFLOW, run_ids=()):
    """The parsed test job logs of the last ``runs`` successful runs (pull request runs of build-pr.yml) whose test jobs printed module times, or
    of the runs ``run_ids`` (a job with a failed test counts too: its module times are printed all the same)."""
    if run_ids:
        listed, wanted = [{'databaseId': run} for run in run_ids], ('success', 'failure')
    else:
        event = ['--event', 'pull_request'] if workflow == WORKFLOW else []
        listed = json.loads(_gh('run', 'list', '--repo', repo, '--workflow', workflow, *event, '--status', 'success', '--limit', '100',
                                '--json', 'databaseId'))
        wanted = ('success',)
    samples = []
    for run in listed:
        jobs = json.loads(_gh('api', f'repos/{repo}/actions/runs/{run["databaseId"]}/jobs?per_page=100'))['jobs']
        jobs = [j for j in jobs if JOB_NAME in j['name'] and j['conclusion'] in wanted]
        if not jobs:
            continue
        logs = [parse_log(_gh('api', '--allow-escape-sequences', f'repos/{repo}/actions/jobs/{j["id"]}/logs')) for j in jobs]
        if not all(log['modules'] for log in logs):
            continue  # a run from before --module-times
        other = next((j for j in jobs if '(1 of' not in j['name']), {'steps': []})
        skipped = {s['name']: s['conclusion'] for s in other['steps']}
        for job, log in zip(jobs, logs):
            outside, only = _job_costs(job, skipped)
            log.update(outside_seconds=outside, shard_one_seconds=only if '(1 of' in job['name'] else None)
        samples.append(logs)
        print(f'run {run["databaseId"]}: {len(jobs)} jobs, {sum(len(log["modules"]) for log in logs)} module times', file=sys.stderr)
        if len(samples) >= runs and not run_ids:
            break
    return samples


def build(samples):
    """The weights file from samples (one list of parsed job logs per run). The same job can run on a machine a third faster or slower than the
    next, so each job's times are first divided by its speed (its modules' sum over the sum of their plain medians), then the median is taken."""
    jobs = [log for logs in samples for log in logs]
    raw = {}
    for log in jobs:
        for name, row in log['modules'].items():
            raw.setdefault(name, []).append(row[0])
    plain = {name: statistics.median(values) for name, values in raw.items()}
    per_module = {}
    for log in jobs:
        expected = sum(plain[name] for name in log['modules'])
        speed = (sum(row[0] for row in log['modules'].values()) / expected) if expected else 1.0
        for name, (seconds, longest, group) in log['modules'].items():
            per_module.setdefault(name, []).append((seconds / speed, longest / speed, group))
    present = modules()
    measured = {}
    for name, rows in sorted(per_module.items()):
        if name in present:
            groups = [row[2] for row in rows]
            group = max(sorted(set(groups)), key=groups.count)
            measured[name] = [round(statistics.median(r[0] for r in rows), 1), round(statistics.median(r[1] for r in rows), 1), group]
    per_test = statistics.median(measured[name][0] / present[name] for name in measured) if measured else DEFAULTS['seconds_per_test']

    def median_of(key):
        values = [log[key] for log in jobs if log.get(key) is not None]
        return statistics.median(values) if values else None
    outside, database, workers, shard_one = (median_of(key) for key in ('outside_seconds', 'database_seconds', 'workers', 'shard_one_seconds'))
    return {
        'about': ('Per test module: [seconds of one test process, its longest class, the group Django runs it in (0 TestCase, 1 other SimpleTestCase, '
                  '2 plain unittest)], the median of the CI jobs that ran it, each job scaled by its machine speed. Written by scripts/ci_shard.py --refresh.'),
        'runs': len(samples),
        'samples': int(statistics.median(len(rows) for rows in per_module.values())) if per_module else 0,
        'workers': int(workers) if workers else DEFAULTS['workers'],
        'fixed_seconds': round(outside + (database or 0), 1) if outside is not None else DEFAULTS['fixed_seconds'],
        'shard_one_seconds': round(shard_one, 1) if shard_one is not None else DEFAULTS['shard_one_seconds'],
        'seconds_per_test': round(per_test, 3),
        'modules': measured,
    }


def dumps(data):
    """The weights file text: one module a line, so a refresh reads as a short diff."""
    head = {key: value for key, value in sorted(data.items()) if key != 'modules'}
    lines = [f' {json.dumps(key)}: {json.dumps(value)},' for key, value in head.items()]
    rows = [f'  {json.dumps(name)}: {json.dumps(row)}' for name, row in sorted(data['modules'].items())]
    return '{\n' + '\n'.join(lines) + '\n "modules": {\n' + ',\n'.join(rows) + '\n }\n}\n'


def refresh(argv):
    runs, repo, workflow, run_ids, files = 5, REPO, WORKFLOW, [], []
    args = iter(argv)
    for arg in args:
        if arg == '--runs':
            runs = int(next(args))
        elif arg == '--repo':
            repo = next(args)
        elif arg == '--workflow':
            workflow = next(args)
        elif arg == '--run':
            run_ids.append(next(args))
        else:
            files.append(arg)
    if files:
        samples = []
        for name in files:
            with open(name, encoding='utf-8', errors='ignore') as handle:
                samples.append([parse_log(handle.read())])
    else:
        samples = collect(runs, repo, workflow, run_ids)
    if not any(log['modules'] for logs in samples for log in logs):
        sys.exit('no module times found: the Django test step must run with --module-times')
    data = build(samples)
    if files:  # a saved log carries no job timings: keep the costs the weights file already holds
        old = load_weights()
        data.update({key: old[key] for key in ('workers', 'fixed_seconds', 'shard_one_seconds')})
    with open(WEIGHTS, 'w', encoding='utf-8') as handle:
        handle.write(dumps(data))
    print(f'{len(data["modules"])} modules from {data["runs"]} runs ({data["samples"]} samples a module) written to {WEIGHTS}')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--refresh']:
        refresh(sys.argv[2:])
    elif sys.argv[1:2] == ['--predict']:
        count = int(sys.argv[2])
        print(' '.join(f'{m} min' for m in predict(count)), f'(shards of {count}, weights from {load_weights()["runs"]} runs)')
    elif sys.argv[1:2] == ['--check']:
        count = int(sys.argv[2])
        flat = [m for shard in shards(count) for m in shard]
        assert sorted(flat) == sorted(modules()) and len(flat) == len(set(flat)), 'a test module is missing from the shards or in two of them'
        print(f'{len(flat)} modules in {count} shards')
    else:
        index, count = int(sys.argv[1]), int(sys.argv[2])
        rows = table()
        print(' '.join(f'tests.{m}' for m in label_order(shards(count)[index - 1], rows)))
