"""Closing a finding: the remediation statuses that close one, and the note that says why.

One definition for CVE matches, scanner findings (startScan.models.Vulnerability) and hygiene findings, which share the remediation
fields (``remediation_status``, ``remediation_note``, ``remediation_by``, ``remediation_updated_at``), and for supplier findings, which
have their own statuses (``SUPPLIER_*`` below). A person closes a finding as fixed, an accepted risk or a false positive, with an optional
note on why (``clean_note``); the note is stored in the finding's own note field with who and when, and the change is written to the
finding's audit trail. The engine closes CVE matches on its own too (the AI or a correlation rule rules one out, a later scan no longer
reports a scanner finding, a hygiene check no longer finds one); those keep the reason they already store, and ``closure_of`` reads it
back as the closure note, marked ``closed_automatically``. An automatic closure is never labelled a false positive, with one exception: the AI
reviewer (cveFeed.reviewer) closes a finding it found to be one as ``false_positive`` with no user and a note that starts with ``AUTOMATIC``,
and only after the server's own checks (no hard evidence, nobody worked it); that reads back as automatic too.

Kept free of Django imports so every layer (models, counts, the API, reports) can import it.
"""
import re

STATUSES = ('open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive')
CLOSED = ('fixed', 'accepted_risk', 'false_positive')  # someone dealt with the finding, decided to live with it, or found it is not real
LABELS = {'open': 'Open', 'in_progress': 'In progress', 'fixed': 'Fixed', 'accepted_risk': 'Accepted risk', 'false_positive': 'False positive'}

# Supplier findings (cveFeed.models.SupplierFinding): open while the check finds it, resolved by a later check that no longer does, or set
# by a person to accepted (the project lives with it) or false_positive (the check got it wrong). Only those two are set by hand.
SUPPLIER_STATUSES = ('open', 'accepted', 'false_positive', 'resolved')
SUPPLIER_SETTABLE = ('open', 'accepted', 'false_positive')
SUPPLIER_CLOSED = ('accepted', 'false_positive', 'resolved')
SUPPLIER_LABELS = {'open': 'Open', 'accepted': 'Accepted', 'false_positive': 'False positive', 'resolved': 'Resolved'}

NOTE_MAX = 2000

# control characters (tab and newline kept), line and paragraph separators, zero-width characters and the bidirectional overrides and
# isolates that can make a note read differently from what it says
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]')

# what an automatic closure of a scanner or hygiene finding says when the pipeline itself stored no reason text
VULNERABILITY_GONE = 'Closed automatically: a later scan of this host no longer reports this finding.'
HYGIENE_RESOLVED = 'Resolved automatically: a later check no longer finds this.'
RULED_OUT_NO_REASON = 'Ruled out automatically by the AI review.'
# Every closure the engine writes into a finding's own note starts with this. A scanner finding a later scan read past its fixed version
# (remediation_status fixed with no remediation_by, cveFeed.finding_lifecycle) and a duplicate or redirect-alias copy the engine folded into
# another row (open_status False or hygiene status resolved) store their reason that way, so ``closure_of`` reads them as automatic.
AUTOMATIC = 'Closed automatically:'
SUPPLIER_RESOLVED = 'Resolved automatically: a later check no longer finds this.'


class NoteError(ValueError):
    """A note that cannot be stored: not text, or longer than NOTE_MAX after cleaning."""


def clean_note(value, limit=NOTE_MAX):
    """``value`` as a note to store: line endings made ``\\n``, control and invisible formatting characters removed, surrounding
    whitespace stripped. ``None`` stays ``None`` (the caller left the note out: keep the stored one). Raises NoteError for anything
    that is not text, or is longer than ``limit`` characters once cleaned."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise NoteError('note must be text')
    text = _CONTROL.sub('', value.replace('\r\n', '\n').replace('\r', '\n')).strip()
    if len(text) > limit:
        raise NoteError(f'note is too long (at most {limit} characters)')
    return text


def clip_note(value, limit=NOTE_MAX):
    """``value`` cleaned like ``clean_note`` but cut to ``limit`` instead of refused: for a note the server writes itself (an agent's
    report), where there is nobody to send a 400 to. ``None`` stays ``None``."""
    if value is None:
        return None
    return _CONTROL.sub('', str(value).replace('\r\n', '\n').replace('\r', '\n')).strip()[:limit].rstrip()


def is_closed(status):
    return status in CLOSED


def label(status):
    return LABELS.get(status, str(status or '').replace('_', ' '))


def _clip(text):
    text = _CONTROL.sub('', str(text or '')).strip()
    return text[:NOTE_MAX]


def closure_of(kind, obj):
    """``(note, user, when, automatic)`` for a closed finding, or ``(None, None, None, False)`` for one that is still open.

    ``kind`` is ``match``, ``vulnerability``, ``hygiene`` or ``supplier``. A person's closing status wins over the engine's: a match marked
    false positive by hand reads as that even when the AI also ruled it out. An automatic closure has no user; its note is the reason the
    engine stored when it closed the finding (a CVE match's ``ai_reason``), or a fixed sentence where the pipeline keeps none."""
    if kind == 'supplier':
        if obj.status in ('accepted', 'false_positive'):
            return obj.status_note or '', obj.status_by, getattr(obj, 'status_at', None), False
        if obj.status == 'resolved':
            return SUPPLIER_RESOLVED, None, obj.resolved_at, True
        return None, None, None, False
    if obj.remediation_status in CLOSED:
        note = obj.remediation_note or ''
        # the engine closed it (a later scan read a fixed version, or the AI reviewer found a false positive): nobody set it, and its note says why
        automatic = obj.remediation_by_id is None and note.startswith(AUTOMATIC)
        return note, obj.remediation_by, obj.remediation_updated_at, automatic
    if kind == 'match' and obj.ai_verdict == 'not_affected':
        return _clip(obj.ai_reason) or RULED_OUT_NO_REASON, None, getattr(obj, 'updated_at', None), True
    if kind == 'vulnerability' and obj.open_status is False:
        note = obj.remediation_note or ''
        return (_clip(note) if note.startswith(AUTOMATIC) else VULNERABILITY_GONE), None, None, True
    if kind == 'hygiene' and obj.status == 'resolved':
        note = obj.remediation_note or ''
        return (_clip(note) if note.startswith(AUTOMATIC) else HYGIENE_RESOLVED), None, obj.resolved_at, True
    return None, None, None, False
