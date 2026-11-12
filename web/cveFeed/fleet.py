"""What the install's Sentinels are right now, in the plain numbers an alert (and the AI that explains it) must not get wrong.

An alert once told an administrator that no Sentinel was online and to start the built-in Sentinel, on an install whose two remote Sentinels were live
the whole time and which has no built-in scanner at all. ``fleet_facts`` is the one place that says how many are live and whether there is a built-in
scanner; the alerts' texts, the facts handed to the AI, and the guard that drops advice contradicting them all read it."""
import re

from django.utils import timezone


def fleet_facts(now=None):
    """``{live_sentinels, live_remote, builtin_scanner, builtin_live, slots}``: the live, active Sentinels (heard from in the live window), how many are not the
    built-in scanner, whether this install has a built-in scanner at all (it enrolled one and it is not revoked) and whether it is live, and the slots
    (concurrent tasks) of the live ones."""
    from agentapi import sentinel_broker
    now = now or timezone.now()
    live = sentinel_broker._live_scanners(now)
    own = sentinel_broker.builtin_pk()
    return {'live_sentinels': len(live), 'live_remote': sum(1 for e in live if e.agent.pk != own), 'builtin_scanner': own is not None,
            'builtin_live': any(e.agent.pk == own for e in live), 'slots': sum(int(e.max_concurrent or 0) for e in live)}


def sentinels_text(count):
    return 'no live Sentinel' if not count else f"{count} live Sentinel{'s' if count != 1 else ''}"


_NONE_ONLINE = re.compile(r'\bno\s+(?:live\s+)?sentinels?\b(?:\s+(?:is|are))?(?:\s+(?:currently|right now|at the moment))?\s*(?:online|live|connected|reachable|available|running|heartbeating)'
                          r'|\bno\s+live\s+sentinels?\b|\bnone of (?:the|your) sentinels\s+(?:is|are)\s+(?:online|live|connected)', re.I)
_START_BUILTIN = re.compile(r'\b(?:start|enable|turn on|bring|restart|launch|run|update|fix|check)\b[^.;]{0,40}built-?in\s+(?:sentinel|scanner)'
                            r'|built-?in\s+(?:sentinel|scanner)[^.;]{0,30}\b(?:is|was|isn\'t|is not)\s+(?:down|offline|not running|stopped|not online)', re.I)


def contradicts_fleet(text, fleet):
    """Whether AI-written advice says what ``fleet`` shows is false: that no Sentinel is online while one is, or that a built-in Sentinel must be started
    (or is down) on an install that has none."""
    text = str(text or '')
    if fleet.get('live_sentinels') and _NONE_ONLINE.search(text):
        return True
    return not fleet.get('builtin_scanner') and bool(_START_BUILTIN.search(text))
