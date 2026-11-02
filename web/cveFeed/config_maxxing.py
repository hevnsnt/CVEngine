"""Settings, configMaxxing: the home of the advanced tunables that used to be environment variables only.

Each card is a small registry entry (an id, a title and the module that owns its numbers), so another tunable is added by registering a card
here and in ``static/cve/config-maxxing.js``, not by redesigning the section. This module is only what the server must do for the section as a
whole: list the cards and put every one of them back to its defaults, as one audited action. Scan concurrency keeps its own storage, validation,
audit entries and API (``/cve/api/settings/scan_concurrency``). Every other card is a group of the generic tunable registry
(``cveFeed.tunables``: AI spend, Scan pacing ...): its numbers share one row and one API (``/cve/api/settings/tunables``), so a new tunable is
one line in that registry and a new group is one line there plus one in ``static/cve/tunables-card.js``. Auto-tuning (``cveFeed.autotune``) is the
first card: its mode, its history and the per-setting badges the other cards draw.
"""
from collections import namedtuple
from functools import partial

Card = namedtuple('Card', 'id title reset')


def _reset_autotune(user):
    from cveFeed import autotune
    return autotune.reset(user)


def _reset_scan_concurrency(user):
    from cveFeed import scan_concurrency
    return scan_concurrency.reset_all(user)


def _reset_tunable_group(group_id, user):
    from cveFeed import tunables
    return tunables.reset_group(user, group_id)


def _cards():
    from cveFeed import tunables
    # one card per group of the tunable registry (cveFeed.tunables): a new group needs no entry here
    return [Card('autotune', 'Auto-tuning', _reset_autotune), Card('scan_concurrency', 'Scan concurrency', _reset_scan_concurrency)] + [
        Card(group.id, group.title, partial(_reset_tunable_group, group.id)) for group in tunables.GROUPS]


CARDS = _cards()


def listing():
    return {'cards': [{'id': c.id, 'title': c.title} for c in CARDS]}


def reset_all(user):
    """Every card back to its defaults. Each card audits its own reset; this adds one entry for the whole action. Returns {card id: cleared keys}."""
    from cveFeed.admin_api import audit
    cleared = {card.id: card.reset(user) for card in CARDS}
    audit(user, 'config_maxxing.reset_all', 'all cards', cards=sorted(cleared), cleared={k: len(v) for k, v in cleared.items()})
    return cleared
