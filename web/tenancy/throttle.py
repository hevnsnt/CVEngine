"""Failure counters for password-guessing limits. They live in the shared Redis cache and count atomically, so several web
workers cannot undercount; a window starts at the first failure and is never extended by later ones."""
from django.core.cache import cache


def count(key, window):
    cache.add(key, 0, window)  # only when absent: sets the window, never extends it
    try:
        cache.incr(key)
    except ValueError:  # the key expired between the add and the incr
        cache.set(key, 1, window)


def exceeded(key, limit):
    return cache.get(key, 0) >= limit


def clear(key):
    cache.delete(key)
