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


# what an AI paragraph says that the server's own numbers contradict. Statements about one capability stay: "No Sentinel is online with that capability" and
# "No live Sentinel offers template checks" are true of an install with Sentinels live, so a "no Sentinel online" that is followed by "with", "that",
# "for" ... is not the claim that none is online.
_NEG = re.compile(r"\b(?:not|no|never|none|without|cannot|can't|isn't|aren't|doesn't|don't|does not|do not)\b|n't", re.I)
_SPECIFIC = r"(?!\s+(?:with|that|which|for|able|capable|offering|offers|supporting|running))"
_NONE_ONLINE = re.compile(
    r'\bno\s+(?:live\s+)?sentinels?\b(?:\s+(?:is|are|have|has))?(?:\s+(?:currently|right now|at the moment|yet|recently))?\s*'
    r'(?:online|live|connected|reachable|available|running|heartbeating|checked in|reported in|been heard from)\b' + _SPECIFIC
    + r'|\b(?:all|both|every)(?:\s+(?:of\s+)?(?:the|your))?\s+sentinels?\s+(?:is|are)\s+(?:currently\s+)?(?:offline|down|disconnected|unreachable|not\s+(?:online|live|connected))\b'
    r"|\b(?:the|your)\s+sentinels?\s+(?:is|are)\s+(?:currently\s+)?(?:offline|down|disconnected|unreachable|not\s+(?:online|live|connected|reachable))\b"
    r'|\bnone of (?:the|your) sentinels\s+(?:is|are|have)\s+(?:online|live|connected|checked in)\b', re.I)
_ALL_FINE = re.compile(r'\b(?:the|your|all|both|every)(?:\s+(?:of\s+)?(?:the|your))?\s+sentinels?\s+(?:is|are)\s+(?:all\s+)?(?:currently\s+)?'
                       r'(?:online|live|healthy|working|connected|fine|up|keeping up|heartbeating)\b', re.I)
_BUILTIN = r"(?:built[- ]?in|bundled|local|embedded)\s+(?:sentinel|scanner)"
_START_BUILTIN = re.compile(r'\b(?P<verb>start|enable|turn on|switch on|bring|restart|launch|run|update|fix|check|activate)\b[^.;]{0,40}' + _BUILTIN
                            + r"|" + _BUILTIN + r"[^.;]{0,30}\b(?:is|was|isn't|is not)\s+(?:down|offline|not running|stopped|not online)", re.I)


def _sentences(text):
    return [p for p in re.split(r'(?<=[.!?])\s+|\n+', str(text or '')) if p.strip()]


def _contradicts(sentence, fleet):
    """Whether one sentence says what the server's numbers show is false. A negation near the verb ("do not run the built-in scanner", "there is no built-in
    scanner") is advice not to, which is true."""
    if fleet.get('live_sentinels') and _NONE_ONLINE.search(sentence):
        return True
    if not fleet.get('live_sentinels') and 'live_sentinels' in fleet and _ALL_FINE.search(sentence) and not _NEG.search(sentence):
        return True
    if not fleet.get('builtin_scanner'):
        for found in _START_BUILTIN.finditer(sentence):
            around = sentence[max(0, found.start() - 14):found.end() + 22] if found.group('verb') else ''  # a negation by the verb or right after the noun: advice not to
            if not _NEG.search(around) and not re.search(r"\b(?:there is|there's|has|have)\s+(?:no|none)\b", sentence, re.I):
                return True
    return False


def contradicts_fleet(text, fleet):
    """Whether AI-written advice says what ``fleet`` shows is false: that no Sentinel is online while one is (or that they are fine while none is), or that a
    built-in Sentinel must be started (or is down) on an install that has none."""
    return any(_contradicts(sentence, fleet) for sentence in _sentences(text))


def without_contradictions(text, fleet):
    """``text`` with the sentences that contradict ``fleet`` taken out (the rest of the diagnosis is kept); '' when nothing true is left."""
    return ' '.join(sentence.strip() for sentence in _sentences(text) if not _contradicts(sentence, fleet))
