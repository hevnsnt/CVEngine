#!/usr/bin/env python3
"""What this host can carry, and the settings that do not fit it: one review for every way an install is updated.

Run by the updater (the Update button, scripts/update.sh, cron, unattended) through ``cvengine_fit_review`` in scripts/host-fit.sh, and by hand:

    python3 scripts/host-review.py                      # report only: nothing is changed
    python3 scripts/host-review.py --apply              # also put right what is safe to put right

It exists because an owner who upgrades from 1.3.x must not have to find these by hand (a 1.4 server was found with a leftover one-host-at-a-time pin and a
database held to 512 MB, which the kernel killed). It never asks a question and never blocks an update. Everything it changes is backed up first
(``<file>.cvengine-review-<time>``) and written to the update log with the line it replaced, so it can be put back by hand.

What it checks, with the host's cores, memory and free disk in front of it:

  pin      DISCOVERY_CONCURRENCY below 4 in the env files. On 1.4 a host assessment holds a discovery slot while it waits for a Sentinel, so a leftover
           pin from 1.3 (one slot) lets one host be assessed at a time while the Sentinels idle, and the auto-tuner may not move it. On a host with
           4 GB or more the line is removed (the number falls back to what auto-tuning chooses).
  limits   A container memory ceiling below what its service needs (the database: 1 GB on a host with 6 GB or more, else 768 MB; the web server 768 MB).
           A ceiling below that is the one the kernel enforces by killing the process. It is raised, in the file that sets it.
  budget   The ceilings together against the host: said, never changed (the ceilings are not use, and the one to lower is the owner's to choose).
  disk     Free space below what an update needs: said.

Only a value that is plainly wrong for the host is touched. A value above the floor is the owner's own and is left as it is.
"""
import argparse
import json
import os
import re
import shutil
import sys
import time

PIN_BELOW = 4                       # cveFeed.autotune.DISCOVERY_PIN_BELOW says the same
PIN_HOST_MB = 4000                  # below this the host is too small for a pin of one to be a mistake: it is left
BIG_HOST_MB = 6000                  # the database floor is 1 GB from here, 768 MB below
FLOORS_MIB = {'db': (1024, 768), 'web': (768, 768)}   # service: (host at BIG_HOST_MB or more, smaller host)
LIMIT_VARS = {'db': 'DB_MEM_LIMIT', 'web': 'WEB_MEM_LIMIT'}
BUDGET_PERCENT = 90
DISK_FLOOR_GB = 14                  # what the first 1.4 update needs (docs/UPGRADE.md)

SIZE = re.compile(r'^(\d+(?:\.\d+)?)\s*([kKmMgG]?)[bB]?$')


def size_bytes(text):
    m = SIZE.match(str(text).strip().strip('"\''))
    if not m:
        return None
    n = float(m.group(1))
    return int(n * {'': 1, 'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}[m.group(2).lower()])


def mib_text(mib):
    return f'{mib // 1024}g' if mib % 1024 == 0 else f'{mib}m'


def host_facts(args):
    mem_mb = args.mem_mb or int(os.environ.get('CVENGINE_HOST_MEM_MB') or 0)
    if not mem_mb:
        try:
            with open('/proc/meminfo') as fh:
                for line in fh:
                    if line.startswith('MemTotal:'):
                        mem_mb = int(line.split()[1]) // 1024
                        break
        except OSError:
            mem_mb = 0
    cores = args.cores or os.cpu_count() or 0
    disk_gb = args.disk_gb
    if disk_gb is None:
        try:
            disk_gb = shutil.disk_usage('.').free // 1024 ** 3
        except OSError:
            disk_gb = None
    return {'cores': cores, 'mem_mb': mem_mb, 'disk_gb': disk_gb}


# --- env files ---------------------------------------------------------------------------------------------------------------------------------------

def env_value(files, key):
    value = None
    for path in files:
        try:
            with open(path) as fh:
                for line in fh:
                    if line.startswith(key + '='):
                        value = line.split('=', 1)[1].strip().strip('"\'')
        except OSError:
            continue
    return value


def backup(path, stamp, done):
    if path in done:
        return done[path]
    target = f'{path}.cvengine-review-{stamp}'
    shutil.copy2(path, target)
    done[path] = target
    return target


def remove_line(path, key):
    """Remove every ``KEY=`` line of an env file in place (same inode, same owner and mode); returns the lines removed."""
    with open(path) as fh:
        lines = fh.read().split('\n')
    kept, gone = [], []
    for line in lines:
        (gone if line.startswith(key + '=') else kept).append(line)
    if gone:
        with open(path, 'w') as fh:
            fh.write('\n'.join(kept))
    return gone


def put_line(path, key, value, note):
    with open(path) as fh:
        text = fh.read()
    lines = [l for l in text.split('\n') if not l.startswith(key + '=')]
    while lines and lines[-1] == '':
        lines.pop()
    lines += [f'# {note}', f'{key}={value}', '']
    with open(path, 'w') as fh:
        fh.write('\n'.join(lines))


# --- compose files -----------------------------------------------------------------------------------------------------------------------------------

def service_limit_lines(path, service):
    """[(line index, key, raw value)] of mem_limit and memswap_limit inside ``services: <service>:`` of one compose file, read as text."""
    try:
        with open(path) as fh:
            lines = fh.read().split('\n')
    except OSError:
        return [], []
    found, inside = [], False
    for i, line in enumerate(lines):
        if re.match(r'^  ' + re.escape(service) + r':\s*(#.*)?$', line):
            inside = True
            continue
        if inside:
            if line.strip() and not line.lstrip().startswith('#') and len(line) - len(line.lstrip()) <= 2:
                inside = False
                continue
            m = re.match(r'^(\s{4})(mem_limit|memswap_limit):\s*(.*?)\s*(#.*)?$', line)
            if m:
                found.append((i, m.group(2), m.group(3)))
    return lines, found


def literal(raw):
    return size_bytes(raw)


def interpolated(raw):
    """``"${DB_MEM_LIMIT:-512m}"`` -> ('DB_MEM_LIMIT', '512m'), else None."""
    m = re.match(r'^["\']?\$\{([A-Z_][A-Z0-9_]*):?-([^}]*)\}["\']?$', raw.strip())
    return (m.group(1), m.group(2)) if m else None


def effective_limit(compose_files, env_files, service):
    """The limit in bytes that the last file defining one wins, plus where it comes from: ('file', path) or ('env', name, default)."""
    result = None
    for path in compose_files:
        _, found = service_limit_lines(path, service)
        for _, key, raw in found:
            if key != 'mem_limit':
                continue
            if literal(raw) is not None:
                result = (literal(raw), ('file', path))
            else:
                var = interpolated(raw)
                if var:
                    value = env_value(env_files, var[0]) or var[1]
                    if size_bytes(value) is not None:
                        result = (size_bytes(value), ('env', var[0], path))
    return result


def rewrite_limits(path, service, new_text, stamp, backups):
    lines, found = service_limit_lines(path, service)
    changes = []
    for i, key, raw in found:
        if literal(raw) is None:
            continue
        backup(path, stamp, backups)
        quote = '"' if raw.strip().startswith('"') else ''
        lines[i] = re.sub(r'(:\s*).*?(\s*(#.*)?)$', lambda m: f'{m.group(1)}{quote}{new_text}{quote}{m.group(2)}', lines[i], count=1)
        changes.append(f'{key}: {raw.strip()} -> {new_text}')
    if changes:
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines))
    return changes


# --- the review --------------------------------------------------------------------------------------------------------------------------------------

def review(args):
    facts = host_facts(args)
    env_files = [f for f in args.env_file if f]
    base = os.path.dirname(os.path.abspath(env_files[0])) if env_files else os.getcwd()
    default = os.path.join(base, '.env')  # the .env next to the env file Compose reads (the install directory)
    if default not in [os.path.abspath(f) for f in env_files]:
        env_files.append(default)
    env_files = [f for f in dict.fromkeys(env_files) if os.path.isfile(f)]
    compose_files = [f for f in args.compose_file if os.path.isfile(f)]
    stamp = time.strftime('%Y%m%dT%H%M%S')
    backups, out = {}, []

    def say(kind, rule, text, **extra):
        out.append({'kind': kind, 'rule': rule, 'text': text, **extra})

    mem_mb = facts['mem_mb']
    say('info', 'host', f"This host has {facts['cores']} core{'s' if facts['cores'] != 1 else ''}, {mem_mb / 1024:.1f} GB of memory"
        + (f" and {facts['disk_gb']} GB free on this disk." if facts['disk_gb'] is not None else '.'))

    # pin
    value = env_value(env_files, 'DISCOVERY_CONCURRENCY')
    if value and value.isdigit() and int(value) < PIN_BELOW:
        scanner_off = env_value(env_files, 'CVENGINE_BUILTIN_SCANNER') == '0' and args.sentinels_live == 0
        if scanner_off:
            say('info', 'pin', f'DISCOVERY_CONCURRENCY={value} is set, and nothing scans here (no built-in scanner, no Sentinel live), so it does nothing: left.')
        elif mem_mb and mem_mb < PIN_HOST_MB:
            say('info', 'pin', f'DISCOVERY_CONCURRENCY={value} is set on a host with {mem_mb / 1024:.1f} GB of memory: left, it may be deliberate.')
        elif args.apply:
            removed = []
            for path in env_files:
                if any(l.startswith('DISCOVERY_CONCURRENCY=') for l in open(path).read().split('\n')):
                    backup(path, stamp, backups)
                    removed += [f'{path}: {l}' for l in remove_line(path, 'DISCOVERY_CONCURRENCY')]
            say('fixed', 'pin', f'Removed DISCOVERY_CONCURRENCY={value} from {", ".join(sorted({r.split(": ")[0] for r in removed}))}. It was a leftover from 1.3, when '
                'that pool only ran discovery: on 1.4 it let one host be assessed at a time while the Sentinels idled, and the auto-tuner may not move a pinned number. '
                'It now follows what auto-tuning chooses for this host. To put it back, copy the line back from the backup named below.', removed=removed)
        else:
            say('warn', 'pin', f'DISCOVERY_CONCURRENCY={value} in the env files holds hosts assessed at once to {value}; --apply removes it.')

    # limits
    big = bool(mem_mb and mem_mb >= BIG_HOST_MB)
    for service, (floor_big, floor_small) in FLOORS_MIB.items():
        floor = floor_big if big else floor_small
        got = effective_limit(compose_files, env_files, service)
        if not got:
            continue  # no ceiling set: nothing can be killed for it
        limit, source = got
        if limit >= floor * 1024 ** 2:
            continue
        have = f'{limit // 1024 ** 2} MB'
        if not args.apply:
            say('warn', 'limits', f'The {service} container is held to {have}; it needs at least {floor} MB here, or the kernel kills it. --apply raises it.', service=service)
            continue
        new = mib_text(floor)
        if source[0] == 'file':
            changes = rewrite_limits(source[1], service, new, stamp, backups)
            where = source[1]
        else:
            target = env_files[0]  # the env file Compose reads is the first one given
            backup(target, stamp, backups)
            put_line(target, source[1], new, f'written by the updater: the {service} container needs at least {new} on this host')
            changes, where = [f'{source[1]} -> {new}'], target
        say('fixed', 'limits', f'The {service} container was held to {have}, less than the {floor} MB it needs on this host (the kernel kills a process that reaches the '
            f'ceiling: the database was killed this way). Raised to {new} in {where}.', service=service, changes=changes)

    # budget
    total = 0
    for service in ('db', 'web', 'celery', 'celery-beat', 'redis', 'proxy', 'reviewer', 'scanner'):
        got = effective_limit(compose_files, env_files, service)
        if got:
            total += got[0]
    if mem_mb and total and total * 100 > mem_mb * 1024 ** 2 * BUDGET_PERCENT:
        say('warn', 'budget', f'The container limits in your compose files add up to {total / 1024 ** 3:.1f} GB on a host with {mem_mb / 1024:.1f} GB. They are ceilings, not use, so '
            'nothing is changed; if the host runs short of memory, lower the largest (CELERY_MEM_LIMIT) first.')

    # disk
    if facts['disk_gb'] is not None and facts['disk_gb'] < DISK_FLOOR_GB:
        say('warn', 'disk', f"Only {facts['disk_gb']} GB is free on this disk; the first update to 1.4 needs about {DISK_FLOOR_GB} GB (docker system prune frees old images).")

    for path, target in backups.items():
        say('info', 'backup', f'{path} was backed up first, to {target}.')
    return {'facts': facts, 'findings': out, 'changed': any(f['kind'] == 'fixed' for f in out)}


def parse_compose_args(argv):
    """From a ``docker compose --env-file F -p P -f A -f B`` command line: the env file and the compose files."""
    env, files, i = '', [], 0
    while i < len(argv):
        if argv[i] == '--env-file' and i + 1 < len(argv):
            env = argv[i + 1]
            i += 1
        elif argv[i] in ('-f', '--file') and i + 1 < len(argv):
            files.append(argv[i + 1])
            i += 1
        i += 1
    return env, files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--apply', action='store_true', help='put right what is safe to put right (default: report only)')
    parser.add_argument('--env-file', action='append', default=[])
    parser.add_argument('--compose-file', action='append', default=[])
    parser.add_argument('--compose-args', nargs=argparse.REMAINDER, default=[], help='a docker compose command line: its --env-file and -f are used')
    parser.add_argument('--sentinels-live', type=int, default=None, help='how many Sentinels of your own are live, when known')
    parser.add_argument('--mem-mb', type=int, default=0)
    parser.add_argument('--cores', type=int, default=0)
    parser.add_argument('--disk-gb', type=int, default=None)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    env, files = parse_compose_args(args.compose_args)
    if env:
        args.env_file.append(env)
    args.compose_file += files
    if not args.compose_file:
        args.compose_file = [f for f in ('docker-compose.yml', 'docker-compose.vps.yml') if os.path.isfile(f)]
    result = review(args)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for f in result['findings']:
            print(f"{'Fixed' if f['kind'] == 'fixed' else 'Warning' if f['kind'] == 'warn' else 'Host'}: {f['text']}" if f['kind'] != 'info' else f['text'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
