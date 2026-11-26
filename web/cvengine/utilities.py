"""Small helpers: duration text, Celery log formatting, NUL stripping and scope checks."""

import re

from celery._state import get_current_task
from celery.utils.log import ColorFormatter


def get_time_taken(latest, earlier):
    """Return a human readable duration between two datetimes, truncated to whole units."""
    total = int((latest - earlier).total_seconds())
    if total < 60:
        return f'{total} seconds'
    minutes_total = total // 60
    if minutes_total < 60:
        return f'{minutes_total} minutes'
    hours, minutes = divmod(minutes_total, 60)
    if minutes == 0:
        return f'{hours} hours'
    return f'{hours} hours {minutes} minutes'


class CVEngineTaskFormatter(ColorFormatter):
    """Celery log formatter that adds task_id and task_name to each record."""

    def format(self, record):
        task = get_current_task()
        if task is not None and getattr(task, 'request', None) is not None:
            record.__dict__['task_id'] = task.request.id
            record.__dict__['task_name'] = task.name.replace('tasks.', '').replace('.', '/')
        else:
            record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
            record.__dict__.setdefault('task_id', '')
        return super().format(record)


def replace_nulls(obj):
    """Return a copy of obj with NUL characters removed from all strings, recursing into lists and dict values."""
    if isinstance(obj, str):
        return obj.replace('\x00', '')
    if isinstance(obj, list):
        return [replace_nulls(item) for item in obj]
    if isinstance(obj, dict):
        return {key: replace_nulls(value) for key, value in obj.items()}
    return obj


class SubdomainScopeChecker:
    """Decide whether a host name is out of scope given regex or plain patterns."""

    def __init__(self, patterns):
        self.regex_patterns = set()
        self.plain_patterns = set()
        for pattern in patterns or ():
            if not pattern:
                continue
            try:
                self.regex_patterns.add(re.compile(pattern, re.IGNORECASE))
            except re.error:
                self.plain_patterns.add(pattern.lower())

    def is_out_of_scope(self, subdomain):
        """Return True if the host name matches a plain pattern or any regex."""
        host = subdomain.lower()
        if host in self.plain_patterns:
            return True
        return any(regex.search(host) for regex in self.regex_patterns)
