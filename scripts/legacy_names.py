#!/usr/bin/env python3
"""The one place that still knows the names cvENGINE used before 1.5.0 (they came from the upstream project, reNgine).

1.5.0 renamed them: the Python package (web/cvengine), the environment variables (CVENGINE_*), the proxy configuration
(config/nginx/cvengine.conf), the certificate files (secrets/certs/cvengine*.pem, cvengine_rsa.key) and the Compose network
(cvengine_network). An install made before that still has the old names in files the repository does not track: its .env (and the
env file its Compose layout names), an overlay Compose file of its own, and its certificates. Every update path runs this script
before Compose reads anything (``migrate``) and again after the updated site answered (``cleanup``):

    migrate  adds the new name beside each old one: a CVENGINE_ line under each old variable line (the value copied, never printed), a
             hard link under the new name for each certificate file, the new network and file names in an overlay of the install's own.
             The old names stay until the update is verified, so a failed update that goes back to the previous commit still finds them.
             A backup of each file it edits is kept once, as <file>.pre-cvengine-rename (mode 0600).
    cleanup  removes the old names: the old variable lines, the old certificate names (only when the new name is the same file), the old
             Compose network once no container of the install is on it (a container of the install still on it is moved first), and a
             leftover web/<old package> folder that only holds Python byte code.

Both are idempotent and print names only, never a value. ``migrate`` exits 1 when it could not do its work (the update then stops before
it changes anything); ``cleanup`` never fails. Database, role and volume names are not renamed: an install keeps the ones in its .env
(POSTGRES_DB, POSTGRES_USER, COMPOSE_PROJECT_NAME), which is what Compose reads; new installs get cvengine from .env.example.

This file and its test (web/tests/test_legacy_names.py) are the only code that may spell the old name (web/tests/test_no_legacy_name.py).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

OLD = 'rengine'
NEW = 'cvengine'
OLD_ENV = re.compile(r'^(\s*(?:export\s+)?)RENGINE_([A-Z0-9_]+)(\s*=)(.*)$')
NEW_ENV = re.compile(r'^\s*(?:export\s+)?CVENGINE_([A-Z0-9_]+)\s*=')
CERTS = ('rengine.pem', 'rengine_rsa.key', 'rengine_chain.pem')
# whole names an overlay of the install's own may use (a network, the proxy configuration file, the certificate names)
OVERLAY_TOKENS = (('rengine_network', 'cvengine_network'), ('config/nginx/rengine.conf', 'config/nginx/cvengine.conf'),
                  ('conf.d/rengine.conf', 'conf.d/cvengine.conf'), ('rengine_chain.pem', 'cvengine_chain.pem'),
                  ('rengine_rsa.key', 'cvengine_rsa.key'), ('rengine.pem', 'cvengine.pem'))
OLD_PACKAGE = 'reNgine'
BACKUP = '.pre-cvengine-rename'


def say(line):
    print(f'names: {line}', flush=True)


def compose_parts(argv):
    """The -f files, the --env-file files and the -p name of a compose command line."""
    files, env_files, project = [], [], None
    i = 0
    while i < len(argv):
        arg, value = argv[i], argv[i + 1] if i + 1 < len(argv) else None
        for flags, into in ((('-f', '--file'), files), (('--env-file',), env_files), (('-p', '--project-name'), None)):
            hit = next((f for f in flags if arg == f or arg.startswith(f + '=')), None)
            if hit is None:
                continue
            got = arg.split('=', 1)[1] if '=' in arg and arg != hit else value
            if arg == hit:
                i += 1
            if into is None:
                project = got
            elif got:
                into.append(got)
            break
        i += 1
    return files, env_files, project


def env_files(root, argv):
    _, named, _ = compose_parts(argv)
    seen, out = set(), []
    for name in ['.env'] + named:
        path = os.path.realpath(os.path.join(root, name))
        if path not in seen and os.path.isfile(path):
            seen.add(path)
            out.append(path)
    return out


def backup_once(path):
    target = path + BACKUP
    if os.path.lexists(target):
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out, open(path, 'rb') as src:
        shutil.copyfileobj(src, out)
    st = os.stat(path)
    try:
        os.chown(target, st.st_uid, st.st_gid)
    except OSError:
        pass


def write_like(path, text):
    """Replace ``path`` with ``text`` keeping its mode and owner, through a file beside it (never half written)."""
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix='.names-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as out:
            out.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read(path):
    with open(path, encoding='utf-8', newline='') as f:
        return f.read()


def migrate_env(path):
    """Under each RENGINE_X line, a CVENGINE_X line with the same value. A CVENGINE_X line that was already there held a value nothing
    read (the code read the old name), so it is commented out and the old name's value, the one in effect, is carried over."""
    lines = read(path).splitlines(keepends=True)
    olds, last = {}, {}
    for i, line in enumerate(lines):
        m = OLD_ENV.match(line.rstrip('\r\n'))
        if m:
            olds[m.group(2)], last[m.group(2)] = m, i  # the last line of a name is the one in effect
    if not olds:
        return []

    def wanted(key):
        m = olds[key]
        return f'{m.group(1)}CVENGINE_{m.group(2)}{m.group(3)}{m.group(4)}'

    bares = [x.rstrip('\r\n') for x in lines]
    satisfied = {k for k in olds if wanted(k) in bares}  # migrated by an earlier run
    out, renamed = [], []
    for i, (line, bare) in enumerate(zip(lines, bares)):
        end = line[len(bare):] or '\n'
        n = NEW_ENV.match(bare)
        if n and n.group(1) in olds:
            if bare == wanted(n.group(1)):
                out.append(line)
            else:
                out.append(f'# {bare}  (replaced in 1.5.0 by the value of the old name, which was the one in effect)' + end)
            continue
        out.append(line)
        m = OLD_ENV.match(bare)
        if m and last[m.group(2)] == i and m.group(2) not in satisfied:
            out.append(wanted(m.group(2)) + end)
            renamed.append(m.group(2))
    text = ''.join(out)
    if text == ''.join(lines):
        return []
    backup_once(path)
    write_like(path, text)
    return [f'CVENGINE_{k}' for k in renamed]


def cleanup_env(path):
    lines = read(path).splitlines(keepends=True)
    have = {n.group(1) for n in (NEW_ENV.match(x) for x in lines) if n}
    keep = [x for x in lines if not ((m := OLD_ENV.match(x.rstrip('\r\n'))) and m.group(2) in have)]
    if len(keep) == len(lines):
        return 0
    backup_once(path)
    write_like(path, ''.join(keep))
    return len(lines) - len(keep)


def tracked(root, path):
    try:
        return subprocess.run(['git', '-C', root, 'ls-files', '--error-unmatch', '--', os.path.relpath(path, root)],
                              capture_output=True).returncode == 0
    except OSError:
        return True  # cannot tell: leave the file alone


def migrate_overlays(root, argv):
    files, _, _ = compose_parts(argv)
    changed = []
    for name in files:
        path = os.path.join(root, name)
        if not os.path.isfile(path) or tracked(root, path):
            continue
        text = read(path)
        new = text
        for old, repl in OVERLAY_TOKENS:
            new = re.sub(r'(?<![A-Za-z0-9_])' + re.escape(old) + r'(?![A-Za-z0-9_])', repl, new)
        if new != text:
            backup_once(path)
            write_like(path, new)
            changed.append(name)
    return changed


def migrate_certs(root):
    folder = os.path.join(root, 'secrets', 'certs')
    linked = []
    for old in CERTS:
        src, dst = os.path.join(folder, old), os.path.join(folder, old.replace(OLD, NEW))
        if os.path.lexists(src) and not os.path.lexists(dst):
            try:
                os.link(src, dst, follow_symlinks=False)
            except OSError:
                shutil.copy2(src, dst, follow_symlinks=False)
            linked.append(os.path.basename(dst))
    return linked


def cleanup_certs(root):
    folder = os.path.join(root, 'secrets', 'certs')
    removed, kept = [], []
    for old in CERTS:
        src, dst = os.path.join(folder, old), os.path.join(folder, old.replace(OLD, NEW))
        if not os.path.lexists(src) or not os.path.lexists(dst):
            continue
        if os.path.samestat(os.lstat(src), os.lstat(dst)) or _same_bytes(src, dst):
            os.unlink(src)
            removed.append(old)
        else:
            kept.append(old)
    return removed, kept


def _same_bytes(a, b):
    try:
        with open(a, 'rb') as x, open(b, 'rb') as y:
            return x.read() == y.read()
    except OSError:
        return False


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def project_name(root, argv):
    _, named, project = compose_parts(argv)
    if project:
        return project
    got = run(list(argv) + ['config', '--format', 'json'], cwd=root)
    if got.returncode == 0:
        try:
            return json.loads(got.stdout)['name']
        except (ValueError, KeyError, TypeError):
            pass
    return None


def cleanup_network(root, argv):
    """The install's old network: its containers are moved to the new one (Compose recreates them), then it is removed."""
    project = project_name(root, argv)
    if not project:
        return 'could not tell the Compose project name; the old network is left as it is'
    network = f'{project}_{OLD}_network'
    if run(['docker', 'network', 'inspect', network]).returncode != 0:
        return None
    listed = run(list(argv) + ['config', '--services'], cwd=root)
    services = set(listed.stdout.split()) if listed.returncode == 0 else set()
    attached = run(['docker', 'ps', '-a', '--filter', f'network={network}', '--format',
                    '{{.Names}}\t{{.State}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Label "com.docker.compose.oneoff"}}'])
    move_running, move_stopped, foreign = [], [], []
    for row in attached.stdout.splitlines():
        name, state, owner, service, oneoff = (row.split('\t') + [''] * 5)[:5]
        if owner == project and service in services and oneoff != 'True':
            (move_running if state == 'running' else move_stopped).append(service)
        else:
            foreign.append(name)
    if move_running:
        run(list(argv) + ['up', '-d', '--no-deps'] + sorted(set(move_running)), cwd=root)
    if move_stopped:
        run(list(argv) + ['up', '--no-start', '--no-deps'] + sorted(set(move_stopped) - set(move_running)), cwd=root)
    if foreign:
        return f'the old network {network} is kept: {", ".join(sorted(foreign))} still use it'
    gone = run(['docker', 'network', 'rm', network])
    if gone.returncode != 0:
        return f'could not remove the old network {network}: {gone.stderr.strip()[:200]}'
    moved = sorted(set(move_running) | set(move_stopped))
    return f'removed the old network {network}' + (f' (moved to the new one first: {", ".join(moved)})' if moved else '')


def cleanup_package(root):
    folder = os.path.join(root, 'web', OLD_PACKAGE)
    if not os.path.isdir(folder) or os.path.islink(folder):
        return False
    for here, _, files in os.walk(folder):
        if any(not f.endswith(('.pyc', '.pyo')) for f in files):
            return False
    shutil.rmtree(folder)
    return True


def cleanup_proxy_conf(root):
    """config/nginx/<old>.conf left in the checkout after the update (git removed the tracked file; what is left is a copy kept on this host,
    or the empty folder Docker makes when a container restarts with a bind mount whose file is gone). The proxy reads only the new file, so a
    copy is kept beside it under a backup name (its edits may matter to someone) and an empty folder is removed."""
    path = os.path.join(root, 'config', 'nginx', f'{OLD}.conf')
    if os.path.islink(path) or not os.path.lexists(path):
        return None
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError:
            return f'config/nginx/{OLD}.conf is a folder that is not empty; it is left as it is (the proxy does not read it)'
        return f'removed the empty folder config/nginx/{OLD}.conf'
    if tracked(root, path):
        return None
    target = path + BACKUP
    if os.path.lexists(target):
        return None
    os.replace(path, target)
    return f'config/nginx/{OLD}.conf (a copy of this host, not read any more) is kept as {os.path.basename(target)}'


def migrate(root, argv):
    for path in env_files(root, argv):
        renamed = migrate_env(path)
        if renamed:
            say(f'{os.path.relpath(path, root)}: added {", ".join(renamed)} beside the old names (values kept; backup {os.path.basename(path)}{BACKUP})')
    for name in migrate_overlays(root, argv):
        say(f'{name}: now names the 1.5.0 network and files (backup {name}{BACKUP})')
    linked = migrate_certs(root)
    if linked:
        say(f'secrets/certs: {", ".join(linked)} (the same files under their 1.5.0 names)')
    return 0


def cleanup(root, argv):
    for path in env_files(root, argv):
        count = cleanup_env(path)
        if count:
            say(f'{os.path.relpath(path, root)}: removed {count} line(s) of the old variable names (the new ones hold the values)')
    removed, kept = cleanup_certs(root)
    if removed:
        say(f'secrets/certs: removed the old names {", ".join(removed)}')
    if kept:
        say(f'secrets/certs: kept {", ".join(kept)}: it differs from the file under the new name')
    line = cleanup_proxy_conf(root)
    if line:
        say(line)
    line = None
    if argv:  # the Compose command of the install: without it there is no network to look at
        try:
            line = cleanup_network(root, argv)
        except OSError as exc:
            line = f'could not check the old network: {exc}'
    if line:
        say(line)
    if cleanup_package(root):
        say(f'removed web/{OLD_PACKAGE}, which only held Python byte code')
    return 0


def main(args):
    if not args or args[0] not in ('migrate', 'cleanup'):
        print('usage: legacy_names.py migrate|cleanup [--root DIR] [-- COMPOSE COMMAND...]', file=sys.stderr)
        return 2
    action, rest = args[0], args[1:]
    root = os.getcwd()
    if rest[:1] == ['--root']:
        root, rest = os.path.abspath(rest[1]), rest[2:]
    if rest[:1] == ['--']:
        rest = rest[1:]
    if action == 'migrate':
        try:
            return migrate(root, rest)
        except OSError as exc:
            print(f'names: could not move this install to the 1.5.0 names: {exc.strerror or exc} ({getattr(exc, "filename", "") or ""})', file=sys.stderr)
            return 1
    try:
        return cleanup(root, rest)
    except Exception as exc:  # never fails the update: the old names only stay one more update
        say(f'cleanup stopped early ({type(exc).__name__}); the old names that are left go at the next update')
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
