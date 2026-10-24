import logging
import secrets
import os
import stat
import tempfile

logger = logging.getLogger(__name__)


'''
Based on
https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/MobSF/init.py
'''


def first_run(secret_file, base_dir):
    if 'RENGINE_SECRET_KEY' in os.environ:
        return os.environ['RENGINE_SECRET_KEY']
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(secret_file, flags)
    except FileNotFoundError:
        # Publish a complete key atomically. Two startup processes may race, but
        # both read the same winning key; no process can observe a half-written file.
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(secret_file), prefix='.secret-', delete=True) as pending:
                pending.write(get_random())
                pending.flush()
                os.fsync(pending.fileno())
                try:
                    os.link(pending.name, secret_file)
                except FileExistsError:
                    pass
            fd = os.open(secret_file, flags)
        except OSError as exc:
            raise RuntimeError(f'Secret file generation failed: {secret_file}') from exc
    with os.fdopen(fd) as secret:
        info = os.fstat(secret.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('Django secret path is not a regular file')
        if info.st_mode & 0o077:
            os.fchmod(secret.fileno(), 0o600)
        key = secret.read().strip()
    if not key:
        raise RuntimeError('Django secret file is empty')
    return key


def get_random():
    charlist = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join(secrets.choice(charlist) for _ in range(64))
