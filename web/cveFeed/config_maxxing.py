"""Settings, configMaxxing: the home of the advanced tunables that used to be environment variables only.

Each card is a small registry entry (an id, a title and the module that owns its numbers), so another tunable is added by registering a card
here and in ``static/cve/config-maxxing.js``, not by redesigning the section. This module is only what the server must do for the section as a
whole: list the cards and put every one of them back to its defaults, as one audited action. Each card keeps its own storage, validation,
audit entries and API (``/cve/api/settings/<card id>``).
"""
from collections import namedtuple

Card = namedtuple('Card', 'id title reset')


def _reset_scan_concurrency(user):
    from cveFeed import scan_concurrency
    return scan_concurrency.reset_all(user)


CARDS = [
    Card('scan_concurrency', 'Scan concurrency', _reset_scan_concurrency),
]


def listing():
    return {'cards': [{'id': c.id, 'title': c.title} for c in CARDS]}


def reset_all(user):
    """Every card back to its defaults. Each card audits its own reset; this adds one entry for the whole action. Returns {card id: cleared keys}."""
    from cveFeed.admin_api import audit
    cleared = {card.id: card.reset(user) for card in CARDS}
    audit(user, 'config_maxxing.reset_all', 'all cards', cards=sorted(cleared), cleared={k: len(v) for k, v in cleared.items()})
    return cleared
