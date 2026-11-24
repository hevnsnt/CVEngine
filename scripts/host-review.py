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
  postgres The database's memory settings (POSTGRES_SHARED_BUFFERS, POSTGRES_EFFECTIVE_CACHE_SIZE, POSTGRES_WORK_MEM, POSTGRES_MAINTENANCE_WORK_MEM),
           sized from the memory the database can really use: its container ceiling (after the limits rule raised it), else its share of the host.
           Only a value that is absent or still the shipped default is raised, in the env file Compose reads; a value the owner set is left, nothing
           is lowered, and the sizes always fit inside the container ceiling (the kernel kills a database that reaches it). The update recreates the
           database container once, because its command line changed.
  diagnose The database's lock wait log and WAL timing (log_lock_waits, track_wal_io_timing), on by default in docker-compose.yml through
           POSTGRES_LOG_LOCK_WAITS and POSTGRES_TRACK_WAL_IO_TIMING: said, never changed. Off in the env file is the owner's own choice and is left; a compose
           file that passes the other database settings but not these (PostgreSQL's default is off) is a warning, because a slow write then
           cannot be told from a lock wait.
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

# postgres: the settings docker-compose.yml reads from the env file, with the defaults it ships (read from the compose file itself when it says)
PG_DEFAULTS = {'POSTGRES_SHARED_BUFFERS': '256MB', 'POSTGRES_EFFECTIVE_CACHE_SIZE': '768MB', 'POSTGRES_WORK_MEM': '4MB',
               'POSTGRES_MAINTENANCE_WORK_MEM': '64MB'}
PG_SETTING = {'POSTGRES_SHARED_BUFFERS': 'shared_buffers', 'POSTGRES_EFFECTIVE_CACHE_SIZE': 'effective_cache_size', 'POSTGRES_WORK_MEM': 'work_mem',
              'POSTGRES_MAINTENANCE_WORK_MEM': 'maintenance_work_mem'}
PG_SHARED_MAX_MIB = 2048            # shared_buffers: a quarter of what the database may use, never more than this
PG_TIERS_MIB = ((3072, 16, 256), (1536, 8, 128))   # memory the database may use: (at least, work_mem, maintenance_work_mem); below the last, left
PG_BUSY = 24                        # connections that may sort at once: the web server's 16 threads and the workers'
PG_SORTS = 4                        # sort or hash steps one busy query may hold (work_mem is per step, per connection)
PG_FIT_PERCENT = 90                 # what the settings may plan for, out of the memory the database may use (the rest: connections, the server itself)
PG_CACHE_PERCENT = 55               # effective_cache_size: at most this share of the host
PG_NOTE = 'written by the updater: Postgres'
# diagnose: the database diagnostics docker-compose.yml turns on by default ({env name: the PostgreSQL setting}), reported, never written
PG_DIAGNOSTICS = {'POSTGRES_LOG_LOCK_WAITS': 'log_lock_waits', 'POSTGRES_TRACK_WAL_IO_TIMING': 'track_wal_io_timing'}
PG_ON = ('on', 'true', 'yes', '1')

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


def pg_defaults(compose_files):
    """{env name: shipped default} of the Postgres memory settings the compose files read (``${POSTGRES_WORK_MEM:-4MB}``); empty when none does."""
    found = {}
    for path in compose_files:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError:
            continue
        for name, default in re.findall(r'\$\{(POSTGRES_[A-Z_]+):?-([^}]*)\}', text):
            if name in PG_DEFAULTS:
                found[name] = default or PG_DEFAULTS[name]
    return found


def pg_text(mib):
    """Megabytes as Postgres writes them: 1024 -> 1GB, 512 -> 512MB."""
    return f'{mib // 1024}GB' if mib % 1024 == 0 else f'{mib}MB'


def written_by_us(path, key):
    """Was the KEY= line of this env file written by this rule (the note line just above it)? Such a value may be raised again later."""
    try:
        with open(path) as fh:
            lines = fh.read().split('\n')
    except OSError:
        return False
    for i, line in enumerate(lines):
        if line.startswith(key + '=') and i and lines[i - 1].startswith('# ' + PG_NOTE):
            return True
    return False


def pg_plan(usable_mib, host_mib, others_mib):
    """What the settings should be for a database that may use ``usable_mib``: {env name: MiB}, a setting left out when it stays as shipped."""
    plan = {'POSTGRES_SHARED_BUFFERS': min(PG_SHARED_MAX_MIB, usable_mib // 4 // 128 * 128)}
    for floor, work, maint in PG_TIERS_MIB:
        if usable_mib >= floor:
            plan['POSTGRES_WORK_MEM'], plan['POSTGRES_MAINTENANCE_WORK_MEM'] = work, maint
            break
    # what the planner may assume the operating system caches for it: the host's share after the other containers' ceilings, never less than what the
    # database itself may use, never more than PG_CACHE_PERCENT of the host (it reserves nothing, so it only has to be a fair guess)
    cache = min(host_mib * PG_CACHE_PERCENT // 100, max(host_mib - others_mib, usable_mib))
    plan['POSTGRES_EFFECTIVE_CACHE_SIZE'] = min(cache, host_mib) // 256 * 256
    return plan


def pg_needs(values):
    """MiB the settings can take at the busiest moment: shared buffers, every busy connection's sorts, one maintenance job."""
    return values['POSTGRES_SHARED_BUFFERS'] + PG_SORTS * values['POSTGRES_WORK_MEM'] * PG_BUSY + values['POSTGRES_MAINTENANCE_WORK_MEM']


def pg_step_down(key, value, floor):
    """The next smaller size of one planned setting, never below ``floor`` (what is there now): the plan shrinks until it fits the ceiling."""
    if key == 'POSTGRES_WORK_MEM':
        lower = [v for v in (8,) if floor < v < value]
    elif key == 'POSTGRES_MAINTENANCE_WORK_MEM':
        lower = [v for v in (128,) if floor < v < value]
    else:
        half = value // 2 // 128 * 128
        lower = [half] if floor < half < value else []
    return lower[0] if lower else floor


def pg_put(path, key, value, note):
    """put_line, and the note this rule wrote above an earlier value of the same key goes with it (no orphaned comment)."""
    with open(path) as fh:
        lines = fh.read().split('\n')
    kept = [l for i, l in enumerate(lines)
            if not (l.startswith('# ' + PG_NOTE) and i + 1 < len(lines) and lines[i + 1].startswith(key + '='))]
    if kept != lines:
        with open(path, 'w') as fh:
            fh.write('\n'.join(kept))
    put_line(path, key, value, note)


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


# --- the postgres rule -------------------------------------------------------------------------------------------------------------------------------

MIB = 1024 ** 2


def postgres_rule(args, facts, env_files, compose_files, stamp, backups, say):
    """Size the database's memory settings for this host. Raises only a value that is absent or still the shipped default (or one this rule wrote
    before), never lowers one, never writes a ceiling (the limits rule owns those), and never plans past the database's container ceiling."""
    defaults = pg_defaults(compose_files)
    host = facts['mem_mb']
    if not defaults or not host or not env_files:
        return  # a compose file that does not read these from the env file, an unknown host, or no env file to write: nothing to size
    target = env_files[0]  # the env file Compose reads, where the limits rule writes too

    got = effective_limit(compose_files, env_files, 'db')
    ceiling = got[0] // MIB if got else None
    if ceiling is not None and not args.apply:
        # report only: size against the ceiling --apply would leave (the limits rule raises one below its floor first)
        floor = FLOORS_MIB['db'][0 if host >= BIG_HOST_MB else 1]
        ceiling = max(ceiling, floor)
    others = 0
    for service in ('web', 'celery', 'celery-beat', 'redis', 'proxy', 'reviewer', 'scanner'):
        other = effective_limit(compose_files, env_files, service)
        others += other[0] // MIB if other else 0
    if ceiling is not None:
        usable = min(ceiling, host * 3 // 4)  # the container ceiling, never most of a host smaller than it
        where = f'its container ceiling of {ceiling} MB'
    else:
        usable = min(host // 2, max(host - others, host // 4))  # no ceiling: its share of the host after the other containers' ceilings
        where = f'its share of this host ({host} MB, less the other containers\' ceilings)'

    current, ours, unread = {}, {}, []
    for key, shipped in PG_DEFAULTS.items():
        default = defaults.get(key, shipped)
        text = env_value([target], key)
        value = size_bytes(text if text is not None else default)
        if value is None:
            unread.append(f'{key}={text}')
            continue
        current[key] = value // MIB
        ours[key] = key in defaults and (text is None or value == size_bytes(default) or written_by_us(target, key))
    if unread:
        say('info', 'postgres', f'{", ".join(unread)} in {target} is not a size this review reads, so the database settings were not sized: left as they are.')
        return

    plan = pg_plan(usable, host, others)
    values = {k: max(v, plan[k]) if ours[k] and k in plan else v for k, v in current.items()}
    room = usable * PG_FIT_PERCENT // 100
    for key in ('POSTGRES_WORK_MEM', 'POSTGRES_MAINTENANCE_WORK_MEM', 'POSTGRES_SHARED_BUFFERS'):
        while pg_needs(values) > room and values[key] > current[key]:
            values[key] = pg_step_down(key, values[key], current[key])
    raised = {k: v for k, v in values.items() if v > current[k]}
    left = sorted(f'{k}={env_value([target], k)}' for k in plan if k in defaults and not ours[k] and plan[k] > current[k])
    if left:
        say('info', 'postgres', f'{", ".join(left)} in {target} is your own and is left as it is (this host would get more).')
    shipped = {k: size_bytes(defaults.get(k, d)) // MIB for k, d in PG_DEFAULTS.items()}
    if pg_needs(values) > room and any(current[k] > shipped[k] for k in current):  # said only for values somebody raised: the shipped ones are not news
        say('warn', 'postgres', f'The database settings can take about {pg_needs(values)} MB at the busiest moment (shared_buffers, plus work_mem for '
            f'{PG_SORTS} sort steps on each of {PG_BUSY} busy connections, plus maintenance_work_mem), more than fits in {where}. Nothing was lowered: '
            'lower POSTGRES_WORK_MEM or POSTGRES_SHARED_BUFFERS in the env file, or raise DB_MEM_LIMIT (docs/DEPLOYMENT.md, Sizing the database).')
    if not raised:
        return
    words = ', '.join(f'{PG_SETTING[k]} {pg_text(current[k])} -> {pg_text(v)}' for k, v in raised.items())
    if not args.apply:
        say('warn', 'postgres', f'The database runs with settings sized for a small host: {words} would fit {where}. --apply raises them '
            '(the database then restarts once).', changes=[words])
        return
    if getattr(args, 'no_db_restart', False):
        # the caller does not restart the database (Settings > Sentinels recreates only the server's processes): a value written now would wait
        # unseen for the next restart, so it is left for the next update, which writes it and restarts the database once
        say('info', 'postgres', f'The database settings would be raised ({words}); the next update does it, because this run does not restart the database.')
        return
    backup(target, stamp, backups)
    changes = []
    for key, value in raised.items():
        before = env_value([target], key)
        pg_put(target, key, pg_text(value), f'{PG_NOTE} {PG_SETTING[key]} for a database that may use {usable} MB on this host')
        changes.append(f'{key}: {before if before is not None else "(not set, " + pg_text(current[key]) + ")"} -> {pg_text(value)}')
    say('fixed', 'postgres', f'Postgres settings changed, the database restarts once during this update: {words}, written to {target}, sized for '
        f'{where} (work_mem is per sort step and per connection, so it stays modest). Run by hand outside an update, they take effect with '
        'docker compose up -d db (with your usual -f files and --env-file).', changes=changes, restart='db')


# --- the diagnose rule -------------------------------------------------------------------------------------------------------------------------------

def pg_diagnostic_defaults(compose_files):
    """{env name: shipped default} of the database diagnostics the compose files pass (``${POSTGRES_LOG_LOCK_WAITS:-on}``); empty when none does."""
    found = {}
    for path in compose_files:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError:
            continue
        for name, default in re.findall(r'\$\{(POSTGRES_[A-Z_]+):?-([^}]*)\}', text):
            if name in PG_DIAGNOSTICS:
                found[name] = default
    return found


def diagnose_rule(env_files, compose_files, say):
    """Say whether the database logs lock waits and times its WAL writes. Never writes: on is the shipped default, and off is the owner's own."""
    shipped = pg_diagnostic_defaults(compose_files)
    if not shipped and not pg_defaults(compose_files):
        return  # compose files that pass the database no settings from the env file at all (not ours): nothing to say, as for the postgres rule
    target = env_files[:1]  # the env file Compose reads
    on, own, missing = [], [], []
    for key, setting in PG_DIAGNOSTICS.items():
        if key not in shipped:
            missing.append(setting)
            continue
        text = env_value(target, key)
        value = text if text else shipped[key]  # ${KEY:-on}: an empty value takes the default too
        if value.strip().lower() in PG_ON:
            on.append(setting)
        else:
            own.append(f'{key}={text}')
    if on:
        say('info', 'diagnose', f'The database runs with {" and ".join(on)} on: a lock wait longer than deadlock_timeout is logged with the process '
            'that holds the lock, and the time spent writing WAL is counted in pg_stat_io.')
    if own:
        say('info', 'diagnose', f'{", ".join(own)} in {target[0]} is your own and is left as it is (the shipped default is on).')
    if missing:
        say('warn', 'diagnose', f'The compose files do not pass {" and ".join(missing)} to the database, so it runs with PostgreSQL\'s default (off): '
            'a slow write cannot be told from a lock wait. The shipped docker-compose.yml turns them on (POSTGRES_LOG_LOCK_WAITS, POSTGRES_TRACK_WAL_IO_TIMING).')


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

    # postgres (after limits: it sizes against the ceiling that rule raised)
    postgres_rule(args, facts, env_files, compose_files, stamp, backups, say)

    # diagnose
    diagnose_rule(env_files, compose_files, say)

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
    parser.add_argument('--no-db-restart', action='store_true', help='the caller does not restart the database: the postgres rule only reports')
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
