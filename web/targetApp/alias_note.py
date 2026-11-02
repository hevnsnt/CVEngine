"""The alias and the note a person gives a target or a host.

An alias is a short display name for something that has only an address ("lab printer" for 10.0.0.5), a note is a few lines of free text.
Both are plain text typed by a person and shown in lists, search results, reports and graph tooltips, so they are cleaned once, here, on the
way in: stripped, kept under a bound, and refused when they carry control characters (an alias is one line, a note may have line breaks).
Markup is NOT removed: every place that shows them escapes them (the web pages build text nodes, the report templates autoescape), so ``<b>``
in an alias is displayed as ``<b>``, never rendered. The alias is for display only: the address and the names a scan discovers are never
replaced by it.
"""
import re

ALIAS_MAX, NOTE_MAX = 60, 1000

# control characters, line and paragraph separators and the bidirectional overrides and isolates that can make text read differently
_BAD = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]')
_BAD_LINE = re.compile(r'[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]')


def clean_alias(value):
    """The alias to store for ``value`` (``''`` clears it), or a ValueError saying what is wrong."""
    if not isinstance(value, str):
        raise ValueError('alias must be text')
    text = value.strip()
    if _BAD_LINE.search(text):
        raise ValueError('alias is one line of plain text (no line breaks or control characters)')
    if len(text) > ALIAS_MAX:
        raise ValueError(f'alias is at most {ALIAS_MAX} characters')
    return text


def clean_note(value):
    """The note to store for ``value`` (``''`` clears it), or a ValueError saying what is wrong."""
    if not isinstance(value, str):
        raise ValueError('note must be text')
    text = value.replace('\r\n', '\n').replace('\r', '\n').strip()
    if _BAD.search(text):
        raise ValueError('note is plain text (no control characters)')
    if len(text) > NOTE_MAX:
        raise ValueError(f'note is at most {NOTE_MAX} characters')
    return text
