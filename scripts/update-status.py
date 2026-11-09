#!/usr/bin/env python3
"""Writes the status the maintenance page shows while an update runs (config/nginx/state/status.json).

The proxy serves that file as /maintenance-status.json to ANYONE who reaches the site while the maintenance flag exists, so it is public. Nothing
free-form goes in it: step names come from a fixed list, every sentence from the tables below, the commit is a 7 to 12 character hex string, times
are numbers. The only text taken from the host is the tail of the update log, shown only after a failure, and it is cut down line by line: a line
that mentions a secret-looking word is replaced by a marker, and addresses, URLs, paths, host names and long tokens are redacted in the rest.

  update-status.py begin SHA            the update started (state working, step checking)
  update-status.py step KEY             a new step: checking, stopping, build, backup, migrating, starting, verifying, scanner
  update-status.py tick                 still alive: refresh updated_at and when the log last grew (the page tells working from stalled)
  update-status.py fail REASON RESTORED why it ended (a key of FAILURES) and whether the previous version is running again: yes, no or unknown
  update-status.py done                 the update finished and was verified
  update-status.py clear                remove the file
Environment: CV_STATUS_FILE (default config/nginx/state/status.json), CV_STATUS_LOG (the host's update log, for tick and the failure tail).
"""
import json
import os
import re
import sys
import time

STEPS = ('checking', 'stopping', 'build', 'backup', 'migrating', 'starting', 'verifying', 'scanner')

# Plain-language text per step. The page adds the numbers (elapsed time, minutes without output).
DETAIL = {
    'checking': 'Checking the update and getting the files ready.',
    'stopping': 'Pausing background work so nothing runs on half-updated files.',
    'build': 'Building the new version. This is the longest step: a small server can take 10 to 25 minutes.',
    'backup': 'Starting the database and taking a backup before anything changes.',
    'migrating': 'Updating the database to the new version.',
    'starting': 'Starting the new version.',
    'verifying': 'Checking that the new version answers.',
    'scanner': 'Starting the built-in scanner.',
}

# reason -> (one plain sentence for what failed, what the administrator should do). `next` is the recovery the docs give (docs/UPDATES.md).
NEXT_HOST = 'On the server, read .git/cvengine-update/update.log in the cvENGINE folder, fix the cause, then approve the update again in Settings > Updates, or run make up.'
FAILURES = {
    'build_failed': ('The new version could not be built.', NEXT_HOST),
    'disk': ('There was not enough free disk space for the new version.', 'On the server, free some disk space (docker system prune removes unused images), then approve the update again in Settings > Updates.'),
    'migrate_failed': ('The database could not be updated to the new version.', NEXT_HOST),
    'restart_failed': ('The new version was installed but did not start.', NEXT_HOST),
    'previous_failed': ('The update failed and the previous version could not be started again.', NEXT_HOST),
    'flag': ('The updater could not show this page, so it changed nothing.', 'On the server, make the folder config/nginx/state writable by the updater, then approve the update again.'),
    'stopped': ('The update was stopped part way.', NEXT_HOST),
    'unknown': ('The update did not finish.', NEXT_HOST),
}

MAX_LINES = 20
MAX_LINE = 200

SENSITIVE = re.compile(r'(pass(word|wd)?|secret|token|api[_-]?key|apikey|authorization|bearer|credential|private|cookie|session|signature|\bkey\b|_key|-----BEGIN)', re.I)
REDACTIONS = (
    (re.compile(r'\x1b\[[0-9;?]*[A-Za-z]'), ''),  # terminal colours
    (re.compile(r'[a-z][a-z0-9+.-]*://\S+', re.I), '[link]'),  # any URL, credentials or not
    (re.compile(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b'), '[address]'),  # e-mail addresses
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'), '[address]'),  # IPv4
    (re.compile(r'(?<![\w:])(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?|\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b', re.I), '[address]'),  # IPv6 (a clock time is neither)
    (re.compile(r'\beyJ[\w.-]+'), '[id]'),  # JSON web tokens
    (re.compile(r'\b[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b'), '[id]'),  # three long dotted parts
    (re.compile(r'(?<![\w.])~?/(?:[\w.@+-]+/)*[\w.@+-]*'), '[path]'),  # absolute and home-relative paths
    (re.compile(r'\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|dev|app|local|lan|internal|example|invalid|co|uk|de|fr|nl|ru|cn|xyz|cloud)\b', re.I), '[host]'),
    (re.compile(r'\b[0-9a-f]{16,}\b', re.I), '[id]'),  # hashes, ids, hex tokens
    (re.compile(r'\b[A-Za-z0-9+/_=-]{32,}\b'), '[id]'),  # base64-looking tokens
    (re.compile(r'\b[A-Z][A-Z0-9_]{3,}=\S*'), '[setting]'),  # NAME=value environment assignments
)
TRACE = re.compile(r'^\s*(Traceback \(most recent call last\)|File "|During handling of the above exception|raise \w)')
PRINTABLE = re.compile(r'[^\x20-\x7e]')


def sanitize_line(line):
    """One log line made safe to show to anyone, or None when it is not worth showing."""
    text = line.rstrip('\n')
    if TRACE.search(text):
        return None  # a stack trace names files and code of the server: never shown
    if SENSITIVE.search(text):
        return '[line withheld: it may contain a secret]'
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    text = PRINTABLE.sub('', text).strip()
    text = re.sub(r'\s+', ' ', text)
    if len(text) < 3:
        return None
    return text[:MAX_LINE]


def sanitized_tail(log_path, lines=MAX_LINES):
    try:
        with open(log_path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 64 * 1024))
            raw = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return []
    out = []
    for line in raw[-(lines * 3):]:
        cleaned = sanitize_line(line)
        if cleaned and (not out or out[-1] != cleaned):
            out.append(cleaned)
    return out[-lines:]


def status_path():
    return os.environ.get('CV_STATUS_FILE') or os.path.join('config', 'nginx', 'state', 'status.json')


def log_path():
    return os.environ.get('CV_STATUS_LOG') or ''


def read():
    try:
        with open(status_path(), encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write(data):
    path = status_path()
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    try:
        os.chmod(directory, 0o755)
    except OSError:
        pass
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, separators=(',', ':'))
        handle.flush()
    os.chmod(temporary, 0o644)  # the proxy reads it as an unprivileged user, whatever the umask
    os.replace(temporary, path)


def last_output():
    path = log_path()
    try:
        return int(os.stat(path).st_mtime) if path else 0
    except OSError:
        return 0


def base(data):
    now = int(time.time())
    data.setdefault('v', 1)
    data['steps'] = list(STEPS)
    data['updated_at'] = now
    data['last_output_at'] = last_output() or data.get('last_output_at') or now
    return data


def short_sha(value):
    value = (value or '').strip().lower()
    return value[:12] if re.fullmatch(r'[0-9a-f]{7,40}', value) else ''


def begin(sha):
    now = int(time.time())
    write(base({'state': 'working', 'step': 'checking', 'detail': DETAIL['checking'], 'sha': short_sha(sha),
                'started_at': now, 'step_started_at': now}))


def step(key):
    if key not in STEPS:
        return  # a phase the page has no row for (merging, switching): the current step stays
    data = read()
    if data.get('state') == 'failed':
        return
    now = int(time.time())
    if data.get('step') == key and data.get('state') == 'working':
        return
    data.update({'state': 'working', 'step': key, 'detail': DETAIL[key], 'step_started_at': now})
    data.setdefault('started_at', now)
    write(base(data))


def tick():
    data = read()
    if data.get('state') != 'working':
        return
    write(base(data))


def fail(reason, restored):
    data = read()
    summary, nxt = FAILURES.get(reason, FAILURES['unknown'])
    now = int(time.time())
    data.update({'state': 'failed', 'detail': summary, 'error': {
        'summary': summary,
        'restored': {'yes': True, 'no': False}.get(restored),
        'next': nxt,
        'log': sanitized_tail(log_path()),
    }})
    data.setdefault('started_at', now)
    data.setdefault('step', 'checking')
    data.setdefault('step_started_at', now)
    write(base(data))


def done():
    data = read()
    data.update({'state': 'done', 'detail': 'The update is finished. The site is coming back.'})
    write(base(data))


def clear():
    for path in (status_path(), status_path() + '.tmp'):
        try:
            os.unlink(path)
        except OSError:
            pass


def main(argv):
    if len(argv) < 2:
        return 2
    action, args = argv[1], argv[2:]
    if action == 'begin' and len(args) >= 1:
        begin(args[0])
    elif action == 'step' and len(args) >= 1:
        step(args[0])
    elif action == 'tick':
        tick()
    elif action == 'fail' and len(args) >= 2:
        fail(args[0], args[1])
    elif action == 'done':
        done()
    elif action == 'clear':
        clear()
    else:
        return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as error:  # the status page is a courtesy: it must never fail an update
        print('update-status: %s' % type(error).__name__, file=sys.stderr)
        sys.exit(0)
