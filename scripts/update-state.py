#!/usr/bin/env python3
"""Host-side update state. Never follow paths supplied by the shared web mount."""
import os
import json
import re
import stat
import subprocess
import sys
import uuid

MAX_LEGACY_LOG_BYTES = 8 * 1024 * 1024


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


def main():
    action = sys.argv[1]
    if action == 'directory':
        path = os.path.abspath(subprocess.check_output(
            ['git', 'rev-parse', '--git-path', 'cvengine-update'], text=True).strip())
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
        elif action == 'commit':
            value = sys.argv[2]
            if not re.fullmatch(r'[0-9a-f]{40}', value):
                raise ValueError('invalid commit id')
            publish(web_fd, '.commit', [(value + '\n').encode('ascii')])
        elif action == 'log':
            with os.fdopen(regular_fd(sys.argv[2]), 'rb') as source:
                publish(web_fd, '.update-log', iter(lambda: source.read(65536), b''))
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
