"""What a discovery run reports, as the server holds it: the result a Sentinel's batches are folded into, the modes and their presets, and the rules
that turn a reported detection into a finding or a host label.

The discovery itself runs on a Sentinel (task kind ``bbot_discovery``, never on this server). This module is the part of that exchange the server
still needs: ``MODES`` names what a mode asks the scanner to run, ``BbotResult`` and ``Observed`` carry one batch into the database
(``cveFeed.discovery``, ``reNgine.tasks``), and ``short_title``, ``is_informational``, ``label_for`` and ``finding_key`` decide how a finding
is named, kept or shown as a label.
"""
import os
import re
from dataclasses import dataclass, field

# passive: only public data sources (CT logs, passive DNS, InternetDB...); nothing is sent to the target.
# standard (the default): subdomain enumeration plus the quick web preset, limited to modules flagged "safe" (no brute forcing, spidering or
# other loud modules). The preset's required flags are ANDed, so "passive,safe" would drop every active web module and leave nothing for it to do.
# The screenshot preset adds the front-page screenshot, so every web host gets one in the default mode, not only in deep.
# deep: the kitchen-sink preset (everything: subdomain, cloud, code and email enumeration, spidering, web probing, directory and parameter
# discovery, takeover checks...). It is active: it sends traffic to the target, so it is only for targets you are authorized to test. There is
# no "allow deadly modules" flag; --force only skips the scanner's own precondition warnings.
MODES = {
    'passive': {'presets': ('subdomain-enum',), 'args': ['-rf', 'passive']},
    'standard': {'presets': ('subdomain-enum', 'web', 'web-screenshots'), 'args': ['-rf', 'safe', '--force']},
    'deep': {'presets': ('kitchen-sink',), 'args': ['--force']},
}
DEFAULT_MODE = 'standard'
# The code-enum flag of the deep preset brings in a module that checks every secret it finds against the issuer's live API; it cannot be made to
# skip that verification from the module's options, so the module is excluded unless a person opted in with CVENGINE_BBOT_TRUFFLEHOG=1 and the
# project is not a bug bounty project (see trufflehog_allowed).
TRUFFLEHOG_ENV = 'CVENGINE_BBOT_TRUFFLEHOG'
TRUFFLEHOG_FLAG = '--cvengine-trufflehog'  # internal: run_discovery adds it for a project that may use trufflehog; the task target says so


def trufflehog_enabled():
    """True when CVENGINE_BBOT_TRUFFLEHOG is set to 1, true, yes or on. Off by default."""
    return os.environ.get(TRUFFLEHOG_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')


def trufflehog_allowed(project_id=None):
    """May the secret-verifying module run for this project: the setting is on and the project has no bug bounty engagement (a program's rules
    almost always forbid using a credential found on its assets, and cvENGINE cannot read a program's exceptions, so a bounty project is
    always off, whatever the setting)."""
    if not trufflehog_enabled():
        return False
    if project_id:
        from cveFeed.models import BountyEngagement
        if BountyEngagement._base_manager.filter(project_id=project_id).exists():
            return False
    return True


@dataclass
class BbotResult:
    subdomains: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    ports: set = field(default_factory=set)         # (host, port)
    urls: set = field(default_factory=set)          # (url, http status the scanner tagged it with; 0 when unknown)
    technologies: set = field(default_factory=set)  # (host, technology)
    resolutions: set = field(default_factory=set)   # (name, ip)
    edges: set = field(default_factory=set)         # (parent_host, child_host) for the spider graph
    findings: list = field(default_factory=list)    # dicts: name, severity (0-4), host, url, description
    http: list = field(default_factory=list)        # dicts from the HTTP responses of a batch: host, url, port, status, title, webserver, ...

@dataclass
class Observed:
    """One event as shown in the live feed."""
    type: str
    label: str
    host: str = ''
    parent_host: str = ''
    module: str = ''



TITLE_MAX = 80
_TITLE_BREAK = re.compile(r'\s[-\u2013\u2014]\s|:\s|:$|\.\s|\n')


def short_title(description):
    """A concise finding name from a detection's description, which runs on into confidence, signature, trigger and module lines:
    "No DMARC record found - domain has no protection ... Trigger: [...]" -> "No DMARC record found". The text before the first
    " - ", ": ", ". " or line break, capped at ``TITLE_MAX`` on a word boundary. The full text stays in the description."""
    text = str(description or '').strip()
    head = ' '.join(_TITLE_BREAK.split(text, 1)[0].split()).strip(' -:.') or ' '.join(text.split())[:TITLE_MAX]
    if len(head) > TITLE_MAX:
        head = head[:TITLE_MAX].rsplit(' ', 1)[0].rstrip(' ,;-:') + '\u2026'
    return (head[:1].upper() + head[1:]) or 'Finding'


# Informational detections ("WAF Detection", "Nginx version detect", "uses federated authentication") are host labels, not
# findings. The cutoff is conservative, because a real exposure dropped is a false negative:
#   * reported severity LOW or higher is always a finding, whatever the text;
#   * text that reads like an exposure (leak, takeover, missing SPF/DMARC, a bucket, a credential...) is always a finding, even at
#     info: it is hidden by the list's default severity filter but never lost;
#   * otherwise severity INFO that the scanner stated is a label, and so is a FINDING with no severity when its text reads like a
#     detection (detect, version, WAF, technology, federated, ...). Anything else with no severity stays a finding.
_EXPOSURE = re.compile(
    r'leak|disclos|credential|secret|passw|token|api[ _-]?key|takeover|vulnerab|misconfig|\bno (spf|dmarc|dkim|dnssec|caa|mx)\b|'
    r'\bmissing\b|default (login|cred|pass)|backup|\.git\b|\.env\b|directory listing|bucket|unauth|anonymous|admin(istrat\w+)? panel|'
    r'open redirect|inject|traversal|\bcve-\d|\bexploit|\bexpos(ed|ure)\b.*\b(database|admin|panel|file|key|config)|private key|sensitive',
    re.I)
_DETECTION = re.compile(
    r'detect|version|\bwaf\b|firewall|technolog|fingerprint|identified|federated|powered by|\buses\b|response \(body\)|\bcdn\b|banner', re.I)
_DETECTION_LABELS = (
    (re.compile(r'\bwaf\b|web application firewall', re.I), 'WAF'),
    (re.compile(r'federated auth', re.I), 'federated auth'),
    (re.compile(r'^http response \(body\)', re.I), 'response body match'),
)
_VERSION_DETECT = re.compile(r'^(.+?)\s+version\b', re.I)
_DETECT_TAIL = re.compile(r'\s*\b(detect(ed|ion|ed)?|identified)\b\s*$', re.I)
LABEL_MAX = 40


def is_informational(name, description, severity, severity_stated=True):
    """True for a detection that is a host label rather than a finding (see the cutoff above). Pure."""
    if severity and severity > 0:
        return False
    text = f'{name} {description}'
    if _EXPOSURE.search(text):
        return False
    return True if severity_stated else bool(_DETECTION.search(name or ''))


def label_for(name):
    """A short chip label for a detection name: "WAF Detection" -> "WAF", "Nginx version detect" -> "nginx version", a
    sensible fallback (the first four words without a trailing "detect") for the rest. Bounded to ``LABEL_MAX``. Pure."""
    title = short_title(name)
    for pattern, label in _DETECTION_LABELS:
        if pattern.search(title):
            return label
    m = _VERSION_DETECT.match(title)
    if m and len(m.group(1)) <= 24:
        product = m.group(1)
        return f'{product.lower() if product.istitle() else product} version'
    words = _DETECT_TAIL.sub('', title).split()
    return (' '.join(words[:4])[:LABEL_MAX].rstrip(' ,;-:') or 'detection')


def finding_key(description):
    """A short stable digest of a finding's full text. The short name no longer tells two findings apart ("Open S3 bucket: a" and
    "...: b" are both "Open S3 bucket"), so the digest goes in the finding's matcher key and neither is merged into the other."""
    import hashlib
    return hashlib.sha1(str(description or '').encode('utf-8', 'replace')).hexdigest()[:16]


