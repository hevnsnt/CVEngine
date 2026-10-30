#!/usr/bin/env python3
"""Host-side update state. Never follow paths supplied by the shared web mount."""
import os
import json
import re
import stat
import subprocess
import sys
import time
import uuid

MAX_LEGACY_LOG_BYTES = 8 * 1024 * 1024
PHASE_VALUES = ('idle', 'draining', 'applying', 'done', 'failed')


def regular_fd(path, *, dir_fd=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError('update state must be a regular file with one link')
    return fd


def publish(web_fd, name, chunks):
    # Exclusive temporary creation and descriptor-relative replacement avoid opening
    # the destination, even if a container has replaced it with a symlink/hardlink.
    temporary = '.update-publish-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644, dir_fd=web_fd)
    try:
        with os.fdopen(fd, 'wb') as output:
            for chunk in chunks:
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=web_fd, dst_dir_fd=web_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=web_fd)
        except FileNotFoundError:
            pass


REPO_RE = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}')
BRANCH_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}')
SHA_RE = re.compile(r'[0-9a-f]{40}')
FETCH_SECONDS = 120


def read_small(web_fd, name, limit=256):
    """The text of a state file the web container wrote, read without following a link it may have planted; '' when it is missing or unsafe."""
    try:
        with os.fdopen(regular_fd(name, dir_fd=web_fd), 'rb') as source:
            return source.read(limit).decode('ascii', 'replace').strip()
    except (OSError, ValueError):
        return ''


def valid_branch(name):
    return bool(BRANCH_RE.fullmatch(name)) and '..' not in name and not name.endswith(('/', '.lock'))


def git(*args, timeout=60, env=None):
    return subprocess.run(['git', '-c', 'safe.directory=' + os.getcwd(), *args], capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, **(env or {})})


def same_repo(url, repo):
    """Whether a remote's URL names ``repo`` ("owner/name") on github.com, in any of the ways a clone writes it."""
    match = re.fullmatch(r'(?:https?://(?:[^@/]+@)?|git@|ssh://git@)github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?', url.strip(), re.I)
    return bool(match) and match.group(1).lower() == repo.lower()


def upstream(web_fd):
    """Where the running build stands against the repository and branch Settings > Updates tracks, published as ``web/.upstream-state.json``.

    Only this host has git. The web container asks GitHub how far behind a commit is, and GitHub has never seen a fork's own commits (or a
    server's unpushed ones): it answers "not found" for them, so the banner offered an update for ever. Here the tracked branch is fetched (from
    ``origin`` when that is the tracked repository, otherwise from its public https address) into a private ref, and the build's commit is
    compared with it: ``base`` (the newest commit they share, which GitHub does know, and which the web container compares with the branch head),
    ``ahead`` (commits of this server's own) and ``behind`` (upstream commits it lacks). A server with commits of its own cannot be fast-forwarded,
    which is what an approved update does, so ``ahead`` and ``behind`` both above zero is a divergence the app reports instead of offering Approve."""
    source = read_small(web_fd, '.update-source').split()
    if len(source) != 2 or not REPO_RE.fullmatch(source[0]) or '..' in source[0] or not valid_branch(source[1]):
        return  # the app has not said what it tracks (an older app, or the check has not run yet): nothing to compare
    repo, branch = source
    installed = read_small(web_fd, '.commit').splitlines()[:1]
    installed = installed[0].strip().lower() if installed else ''
    state = {'repo': repo, 'branch': branch, 'at': time.time()}

    def finish(**fields):
        state.update(fields)
        publish(web_fd, '.upstream-state.json', [json.dumps(state).encode('utf-8')])

    try:
        if not SHA_RE.fullmatch(installed):
            installed = git('rev-parse', 'HEAD').stdout.strip()
        state['installed'] = installed
        ref = 'refs/cvengine/upstream/' + branch
        if git('check-ref-format', ref).returncode != 0:
            return finish(error='that is not a usable branch name')
        remote = git('config', '--get', 'remote.origin.url').stdout.strip()
        if remote and same_repo(remote, repo):
            fetch = ['fetch', '--quiet', '--no-tags', '--no-recurse-submodules', 'origin']
        else:
            # not the repository this checkout was cloned from (a fork pulled from elsewhere): its public address, https only, objects checked
            fetch = ['-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'transfer.fsckObjects=true',
                     'fetch', '--quiet', '--no-tags', '--no-recurse-submodules', f'https://github.com/{repo}.git']
        done = git(*fetch, f'+refs/heads/{branch}:{ref}', timeout=FETCH_SECONDS, env={'GIT_TERMINAL_PROMPT': '0'})
        if done.returncode != 0:
            return finish(error='could not fetch ' + repo + ' ' + branch + ' (network, a private repository, or no such branch)')
        tip = git('rev-parse', ref).stdout.strip()
        if not SHA_RE.fullmatch(tip) or git('cat-file', '-e', installed + '^{commit}').returncode != 0:
            return finish(error='the build\'s commit is not in this checkout')
        base = git('merge-base', installed, tip)
        if base.returncode != 0 or not SHA_RE.fullmatch(base.stdout.strip()):
            return finish(error='the build shares no history with ' + repo + ' ' + branch)
        ahead = int(git('rev-list', '--count', f'{tip}..{installed}').stdout.strip())
        behind = int(git('rev-list', '--count', f'{installed}..{tip}').stdout.strip())
        finish(upstream=tip, base=base.stdout.strip(), ahead=ahead, behind=behind)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        finish(error='git could not answer: ' + str(exc)[:100])


def main():
    action = sys.argv[1]
    if action == 'directory':
        # root (cron, systemd) in a checkout owned by whoever cloned it: git refuses it ("dubious ownership") unless this one is named. Root
        # already runs this checkout's scripts, so naming it adds no trust.
        path = os.path.abspath(subprocess.check_output(
            ['git', '-c', 'safe.directory=' + os.getcwd(), 'rev-parse', '--git-path', 'cvengine-update'], text=True).strip())
        web = os.path.realpath('web')
        if os.path.commonpath([os.path.realpath(path), web]) == web:
            raise ValueError('host update state cannot be inside the web mount')
        os.makedirs(path, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.close(fd)
        print(path)
        return
    web_fd = os.open('web', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if action == 'migrate-log':
            # Preserve pre-upgrade history, but never dereference an unsafe shared
            # log. The private destination is created only once under the host lock.
            if os.path.exists(sys.argv[2]):
                return
            try:
                source_fd = regular_fd('.update-log', dir_fd=web_fd)
            except FileNotFoundError:
                return
            except (OSError, ValueError):
                print('Ignoring unsafe legacy UI log; starting a private update log', file=sys.stderr)
                return
            with os.fdopen(source_fd, 'rb') as source:
                # The shared file may grow while it is read. Import only a bounded
                # tail from the opened regular file, never stream until attacker EOF.
                size = os.fstat(source.fileno()).st_size
                source.seek(max(0, size - MAX_LEGACY_LOG_BYTES))
                remaining = min(size, MAX_LEGACY_LOG_BYTES)
                with open(sys.argv[2], 'xb') as destination:
                    while remaining:
                        chunk = source.read(min(65536, remaining))
                        if not chunk:
                            break
                        destination.write(chunk)
                        remaining -= len(chunk)
        elif action == 'migrate-requeue':
            if os.path.exists(sys.argv[2]):
                return
            try:
                source_fd = regular_fd('.update-requeue.json', dir_fd=web_fd)
            except FileNotFoundError:
                return
            with os.fdopen(source_fd, 'rb') as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError('legacy scan requeue file is too large')
            rows = json.loads(data)
            if not isinstance(rows, list) or any(
                not isinstance(row, dict) or
                type(row.get('domain')) is not int or row['domain'] <= 0 or
                type(row.get('scan')) is not int or row['scan'] <= 0 or
                row.get('mode') not in (None, 'standard', 'deep', 'passive')
                for row in rows
            ):
                raise ValueError('legacy scan requeue file has invalid entries')
            # The destination lives outside the web mount, under the host lock.
            fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as destination:
                destination.write(data)
                destination.flush()
                os.fsync(destination.fileno())
            os.unlink('.update-requeue.json', dir_fd=web_fd)
        elif action == 'approval':
            with os.fdopen(regular_fd('.update-approved', dir_fd=web_fd), 'rb') as source:
                value = source.read(256).strip()
            if not re.fullmatch(rb'[0-9a-f]{40}', value):
                raise ValueError('approval must contain exactly one commit id')
            print(value.decode('ascii'))
        elif action == 'mode':
            # "auto" only when the administrator chose Automatic in Settings > Updates; a missing, unreadable or odd file is Manual
            try:
                with os.fdopen(regular_fd('.update-mode', dir_fd=web_fd), 'rb') as source:
                    value = source.read(16).strip()
            except (FileNotFoundError, OSError, ValueError):
                value = b''
            print('auto' if value == b'auto' else 'manual')
        elif action == 'approval-branch':
            # the branch the administrator chose in Settings, or nothing when the file is missing or not a plain branch name
            try:
                with os.fdopen(regular_fd('.update-branch', dir_fd=web_fd), 'rb') as source:
                    value = source.read(128).strip()
            except FileNotFoundError:
                return
            if re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}', value) and b'..' not in value and not value.endswith((b'/', b'.lock')):
                print(value.decode('ascii'))
        elif action == 'commit':
            value = sys.argv[2]
            if not re.fullmatch(r'[0-9a-f]{40}', value):
                raise ValueError('invalid commit id')
            publish(web_fd, '.commit', [(value + '\n').encode('ascii')])
        elif action == 'upstream':
            upstream(web_fd)
        elif action == 'heartbeat':
            publish(web_fd, '.updater-heartbeat', [json.dumps({'at': time.time()}).encode('ascii')])
        elif action == 'log':
            with os.fdopen(regular_fd(sys.argv[2]), 'rb') as source:
                publish(web_fd, '.update-log', iter(lambda: source.read(65536), b''))
        elif action == 'openvas-wanted':
            # the OpenVAS switch the app asked for: "on" or "off", nothing else, read without following a link the container may have planted
            try:
                with os.fdopen(regular_fd('.openvas-wanted', dir_fd=web_fd), 'rb') as source:
                    value = source.read(8).strip()
            except (FileNotFoundError, OSError, ValueError):
                return
            if value in (b'on', b'off'):
                print(value.decode('ascii'))
        elif action == 'openvas-applied':
            # the answer scripts/openvas-sync.sh leaves for the app: one line of JSON, published like every other state file
            row = json.loads(sys.argv[2])
            if (not isinstance(row, dict) or row.get('want') not in ('on', 'off') or row.get('state') not in ('applying', 'ok', 'failed')
                    or not isinstance(row.get('ok'), bool) or not isinstance(row.get('error'), str) or len(row['error']) > 200
                    or not isinstance(row.get('at'), int)):
                raise ValueError('invalid OpenVAS answer')
            publish(web_fd, '.openvas-applied', [json.dumps(row).encode('utf-8') + b'\n'])
        elif action == 'openvas-log':
            # the tail of the host-private log of the OpenVAS switch, for the app's "see web/.openvas-log" hint
            with os.fdopen(regular_fd(sys.argv[2]), 'rb') as source:
                size = os.fstat(source.fileno()).st_size
                source.seek(max(0, size - 65536))
                publish(web_fd, '.openvas-log', [source.read(65536)])
        elif action == 'cert-status':
            # the outcome of scripts/renew-certs.sh for the app (Settings > Updates, get_system_status): result, the certificate's notAfter as
            # openssl prints it ("Nov 30 00:33:02 2027 GMT", empty when unknown: the earlier value is kept) and an error line. renewed_at
            # moves only when a certificate was issued.
            import ssl
            result = sys.argv[2]
            raw = sys.argv[3] if len(sys.argv) > 3 else ''
            error = sys.argv[4] if len(sys.argv) > 4 else ''
            if result not in ('kept', 'issued', 'external', 'failed') or len(error) > 200 or len(raw) > 64:
                raise ValueError('invalid certificate status')
            try:
                with os.fdopen(regular_fd('.cert-status.json', dir_fd=web_fd), 'rb') as source:
                    previous = json.loads(source.read(4096))
                if not isinstance(previous, dict):
                    previous = {}
            except (FileNotFoundError, OSError, ValueError):
                previous = {}
            now = time.time()
            not_after = ssl.cert_time_to_seconds(raw) if raw else previous.get('not_after')
            publish(web_fd, '.cert-status.json', [json.dumps({
                'checked_at': now, 'result': result, 'error': error, 'not_after': not_after,
                'renewed_at': now if result == 'issued' else previous.get('renewed_at'),
            }).encode('utf-8')])
        elif action == 'phase':
            value = sys.argv[2]
            if value not in PHASE_VALUES:
                raise ValueError('invalid phase')
            detail = sys.argv[3] if len(sys.argv) > 3 else ''
            if len(detail) > 200:
                raise ValueError('phase detail is too long')
            scans_running = None
            if len(sys.argv) > 4 and sys.argv[4] != '':
                scans_running = int(sys.argv[4])
                if scans_running < 0:
                    raise ValueError('scans_running must not be negative')
            payload = json.dumps({
                'phase': value, 'detail': detail, 'scans_running': scans_running, 'changed_at': time.time(),
            }).encode('utf-8')
            publish(web_fd, '.update-phase.json', [payload])
        else:
            raise ValueError('unknown update state action')
    finally:
        os.close(web_fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print('Unsafe or unavailable update state: ' + str(exc), file=sys.stderr)
        sys.exit(1)
