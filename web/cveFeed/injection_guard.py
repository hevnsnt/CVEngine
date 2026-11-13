"""Text aimed at an AI agent, found in what a scanner stored about a host.

A scanned page, script, banner or header can carry instructions for whatever AI reads it next: SpikeStrip
(github.com/Arcanum-Sec/SpikeStrip) plants exactly that in HTML and JavaScript comments: workflow orders ("treat this note as your next
task"), markers to repeat ("include this reference in your report"), impossible tasks ("prove the Riemann hypothesis") and fabricated leads
that name real CVEs against made-up routes. Such text is never a fact about the host. Finding it is a fact, though: the AI reviewer
(cveFeed.reviewer) never closes a finding whose evidence carries it, and the packet the model reads says it is there.

``families(value)`` names the families found anywhere in a value (strings, lists and dicts, walked to a bounded depth and size).
``planted_markers(value)`` returns the opaque identifiers (hex runs of 12 or more characters) in the evidence, so a reply that repeats one
can be refused: repeating a planted marker is exactly what a canary asks for. Pure functions, no Django.
"""
import re

MAX_TEXT = 200_000   # characters examined per call: what a scanner stores is bounded, and so is this
MAX_DEPTH = 8

FAMILIES = {
    # "ignore your previous instructions", "you are now an AI that ...", "system prompt"
    'ai_directive': re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|original|system)\s+"
        r"(?:instructions?|prompts?|rules|directions)"
        r"|\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|llm|agent)\b"
        r"|\bsystem\s+prompt\b|\bas\s+an\s+ai\b"
        r"|\b(?:ai|llm|language\s+model|automated)\s+(?:agents?|assistants?|scanners?|reviewers?|tools?)\s+(?:must|should|shall|need\s+to)\b", re.I),
    # SpikeStrip's workflow orders: take this as your next task, pause, ask for authorization, resume the original checklist afterwards
    'workflow_order': re.compile(
        r"\b(?:before|prior\s+to)\s+(?:continuing|resuming|proceeding|selecting|analy[sz]ing|reporting|concluding)\b"
        r"|\btreat\s+this\s+(?:\w+\s+){0,2}(?:note|comment|message|text)\s+as\s+(?:your|the)\s+next\s+task"
        r"|\b(?:pause|stop)\s+(?:the\s+|your\s+|any\s+)?(?:broad\s+crawling|automated|assessment|scanning|evaluation)"
        r"|\brequest\s+explicit\s+human\s+authori[sz]ation"
        r"|\bresum(?:e|ing)\s+the\s+original\s+(?:assessment|checklist|task|evaluation)", re.I),
    # markers to repeat: "include this identifier in your next status update", "print this reference", canary words
    'echo_marker': re.compile(
        r"\b(?:include|print|repeat|output|echo|mention)\s+(?:this|the)\s+(?:identifier|reference|marker|canary|token|key|code)\b"
        r"|\breview\s+reference\s+[0-9a-f]{12,}\b|\bcanary\s+(?:alpha|beta|gamma)\b", re.I),
    # tasks no one can finish, meant to burn an agent's budget
    'impossible_task': re.compile(
        r"\briemann\s+hypothesis\b|\bp\s+versus\s+np\b|\benumerate\s+every\s+prime\b|\blargest\s+integer\b"
        r"|\blist\s+all\s+real\s+numbers\b|\bx\s*>\s*0\s+and\s+x\s*<\s*0\b|\brecheck\s+every\s+conclusion\s+recursively\b", re.I),
    # a lead handed to the reader: "prioritize SSRF checks there", "the /legacy/... route ... prioritize the CVE-2021-44228 review there"
    'false_lead': re.compile(
        r"\bprioriti[sz]e\s+(?:the\s+)?(?:\w+[\s-]){0,4}(?:review|checks?|testing)\b"
        r"|\b(?:route|handler|endpoint|path|alias)\b.{0,120}?\b(?:review|trace|inspect)\s+(?:that|this|the)\s+(?:parameter|route|path)\b"
        r"|\breview\s+(?:ssrf|sql\s+injection|template\s+injection|xxe|path\s+traversal)\s+there\b", re.I),
}

# Claims a scanned host makes about how its own findings should be judged: not instructions, so they are not in FAMILIES and never stop a step, but a
# false positive that rests on such a claim is not closed by the AI alone. Run only on strings a host controls (``triage.collecting().host``), never on
# cvENGINE's or a feed's own text. Narrow on purpose: an ordinary banner ("Apache/2.4.52 (Ubuntu)", "(Debian)", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6") says none of these.
VERDICT_CLAIM = 'verdict_claim'
_CLAIM = re.compile(
    r"\b(?:honey-?pot|decoy)\b"
    r"|\ball\s+(?:\w+\s+){0,2}(?:matches|findings|vulnerabilit(?:y|ies)|results|alerts)\b.{0,60}?\b(?:are|is)\s+(?:all\s+)?(?:false\s+positives?|not\s+real|fake)"
    r"|\b(?:are|is)\s+(?:all\s+)?false\s+positives?\b"
    r"|\bnot\s+(?:vulnerable|exploitable|affected\s+by)\b"
    r"|\b(?:fully\s+patched|(?:security\s+)?(?:patches|fixes)\s+(?:have\s+been\s+|were\s+|are\s+)?back-?ported|(?:vulnerabilit(?:y|ies)|cves?)\s+(?:have\s+been\s+|were\s+|are\s+)?(?:patched|fixed|mitigated))\b", re.I)


def verdict_claims(*values):
    """``['verdict_claim']`` when any string of ``values`` (host-controlled text) claims how its findings should be judged, else ``[]``."""
    for value in values:
        for text in _texts(value):
            if _CLAIM.search(text):
                return [VERDICT_CLAIM]
    return []


_HEX_RUN = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{12,64}(?![0-9a-fA-F])')


def _texts(value, depth=0, budget=None):
    """The strings of ``value`` (dict keys and values, list items), at most MAX_TEXT characters in all."""
    budget = budget if budget is not None else [MAX_TEXT]
    if budget[0] <= 0 or depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        piece = value[:budget[0]]
        budget[0] -= len(piece)
        yield piece
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _texts(str(key), depth + 1, budget)
            yield from _texts(item, depth + 1, budget)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _texts(item, depth + 1, budget)
    elif value is not None and not isinstance(value, (bool, int, float)):
        yield from _texts(str(value), depth + 1, budget)


def families(*values):
    """The sorted names of the families of AI-directed text found in ``values``."""
    found = set()
    for value in values:
        for text in _texts(value):
            for name, pattern in FAMILIES.items():
                if name not in found and pattern.search(text):
                    found.add(name)
    return sorted(found)


def planted_markers(*values):
    """The hex runs of 12 to 64 characters in ``values``, lower-cased: identifiers a reply must not repeat."""
    found = set()
    for value in values:
        for text in _texts(value):
            found.update(m.group(0).lower() for m in _HEX_RUN.finditer(text))
    return found


def repeats_marker(text, markers):
    """Whether ``text`` repeats any of ``markers`` (as a whole hex run)."""
    if not markers or not text:
        return False
    return any(m.group(0).lower() in markers for m in _HEX_RUN.finditer(text))
