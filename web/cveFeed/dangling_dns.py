"""Rating the discovery's baddns dangling-DNS findings by what an outsider can actually claim.

baddns rates every dangling record medium, so cvENGINE showed them all as smoke: a claimable zone takeover and a stale CNAME no one else can
use looked the same. Each finding is checked again here when it is stored (``reNgine.tasks._persist_bbot_findings``) and by the
``rerate_dangling_dns`` command, and gets a severity (critical/high fire, medium smoke, low ice) and a note saying why:

* **Dangling NS** ("Dangling NS Records (NS records without SOA)"): the delegation is evaluated at the client's own zone cut, found by walking
  down from the registry (``find_cut``): each level is asked, non-recursively, for the next name's NS. A name of the client's that is a CNAME
  is not a delegation the client made: baddns followed the CNAME into the provider's zone (Railway, Marigold) and reported how the
  provider's name servers behave, so the finding is dropped. At the deepest cut, every delegated name server is asked for the zone's SOA with
  recursion off: when every one answers REFUSED or SERVFAIL the delegation is lame, and at a self-service DNS provider (Google Cloud DNS,
  Route 53, Azure DNS, ...; ``data/takeover_providers.json``) anyone with an account can create the zone there and answer for the name: high
  (fire). Lame elsewhere stays medium. A delegation one of whose servers answers for the zone is served: baddns misread it (low, ice).
* **Dangling CNAME, NXDOMAIN technique**: the target does not resolve. That is only a takeover when someone else can create the target: it is
  at a provider listed as claimable, or its registrable domain is not registered (anyone can buy it). Otherwise (a load balancer's random
  name, a tenant name the provider assigns, a registered domain, the client's own domain) the record is stale but not claimable: low (ice).
* **Dangling CNAME, HTTP String Match**: the provider's "not found" page matched. Some providers (Mailgun) answer every host name alike, claimed
  or not, so a control request is sent to the same addresses with a random host name: when it gets the same answer, the page says nothing
  about this host and the finding is dropped. A target at a provider listed as claimable is not controlled, because its "unclaimed" page is
  the same for every unknown host by design.

A check that gets no answer changes nothing: the finding keeps baddns's rating. ``CVENGINE_DANGLING_DNS_CHECKS=0`` turns the checks off.
"""
import functools
import json
import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'takeover_providers.json')
FIRE_SEVERITY, SMOKE_SEVERITY, ICE_SEVERITY = 3, 2, 1  # high, medium, low: cveFeed.threat.SEVERITY_HEAT
KIND_NS, KIND_NXDOMAIN, KIND_HTTP = 'ns', 'cname_nxdomain', 'cname_http'
NOTE_MARKER = '\n\ncvENGINE check: '  # what assess() adds to the stored description; parse() reads only what is before it
DNS_TIMEOUT = 3.0
HTTP_TIMEOUT = 8
MAX_BODY = 64 * 1024


def enabled():
    return os.environ.get('CVENGINE_DANGLING_DNS_CHECKS', '1').strip().lower() not in ('0', 'false', 'no', 'off')


# ----------------------------------------------------------------------------- the provider list

@functools.lru_cache(maxsize=1)
def providers():
    with open(DATA_FILE, encoding='utf-8') as handle:
        data = json.load(handle)
    cname = [(p['service'], tuple(s.lower() for s in p['suffixes'])) for p in data['cname']]
    nameservers = [(p['service'], tuple(re.compile(x, re.I) for x in p['patterns'])) for p in data['nameservers']]
    return cname, nameservers


def _clean(name):
    return (name or '').strip().lower().rstrip('.')


# ----------------------------------------------------------------------------- reading baddns's description

@dataclass
class Parsed:
    kind: str
    head: str
    confidence: str = ''
    signature: str = ''
    triggers: list = field(default_factory=list)


def _field(text, name, following):
    found = re.search(re.escape(name) + r': \[(.*?)\] ' + re.escape(following) + r': \[', text, re.S)
    return found.group(1).strip() if found else ''


def parse(description):
    """The parts of a baddns description that the rating reads, or None for a finding it does not rate (MX, TXT, a whois finding...).
    The discovery writes ``<description>. Confidence: [..] Signature: [..] Indicator: [..] Trigger: [a, b] baddns Module: [..]``."""
    text = str(description or '').split(NOTE_MARKER, 1)[0]
    head = text.split('. Confidence: [', 1)[0].strip()
    if head.startswith('Dangling NS Records'):
        kind = KIND_NS
    elif head.startswith('Dangling CNAME') and 'NXDOMAIN technique' in head:
        kind = KIND_NXDOMAIN
    elif head.startswith('Dangling CNAME') and 'HTTP String Match' in head:
        kind = KIND_HTTP
    else:
        return None
    trigger = _field(text, 'Trigger', 'baddns Module')
    return Parsed(kind, head, _field(text, 'Confidence', 'Signature'), _field(text, 'Signature', 'Indicator'),
                  [_clean(t) for t in trigger.split(',') if _clean(t)])


# ----------------------------------------------------------------------------- the network (replaced in tests)



# ----------------------------------------------------------------------------- the zone cut



# ----------------------------------------------------------------------------- the rating

@dataclass
class Rating:
    severity: int = None  # None: keep baddns's
    drop: bool = False
    note: str = ''
    zone: str = ''


def providers_doc():
    """The provider lists as a ``dangling_dns_check`` task carries them (the contract's ``providers``): this server's one copy, which a Sentinel applies."""
    with open(DATA_FILE, encoding='utf-8') as handle:
        data = json.load(handle)
    return {'cname': [{'service': p['service'], 'suffixes': list(p['suffixes'])} for p in data['cname']],
            'nameservers': [{'service': p['service'], 'patterns': list(p['patterns'])} for p in data['nameservers']]}


def _rating_from(row):
    """The ``Rating`` of a Sentinel's reported row (``probe_results.clean_dangling_dns_check``), or None when it had no usable answer."""
    if not isinstance(row, dict) or row.get('state') != 'rated':
        return None
    severity = row.get('severity')
    return Rating(severity=severity if severity in (ICE_SEVERITY, SMOKE_SEVERITY, FIRE_SEVERITY) else None, drop=bool(row.get('drop')),
                  note=row.get('note') or '', zone=row.get('zone') or '')


def assess_all(findings, project=None):
    """``[rating or None]`` for each of ``findings`` (``assess``'s dicts), in order: the same answer ``assess`` gives each, but the lookups run on a Sentinel
    when one can take ``dangling_dns_check`` (``agentapi.probe_dispatch``). A finding the Sentinel could not answer, or did not report, is None: baddns's
    own rating stands, never a drop or a lower severity. With no Sentinel able to take the work (``ScannerUnavailable``) every finding keeps baddns's
    rating, and ``rerate_dangling_dns`` rates them later: this server asks nothing itself."""
    findings = list(findings)
    out = [None] * len(findings)
    if not findings or not enabled():
        return out
    plan = []
    for index, finding in enumerate(findings):
        if (finding.get('module') or 'baddns') != 'baddns':
            continue
        parsed, host = parse(finding.get('description')), _clean(finding.get('host'))
        if parsed is not None and host:
            plan.append((index, {'id': str(index), 'host': host[:260], 'kind': parsed.kind, 'triggers': [t[:260] for t in parsed.triggers[:10]]}))
    if project is not None and plan:  # a finding of no project (a test, a stray row) keeps baddns's rating
        from agentapi import probe_dispatch
        from reNgine.resources import ScannerUnavailable
        try:
            answered = probe_dispatch.try_dangling(project, [check for _i, check in plan], providers_doc())
        except ScannerUnavailable as exc:
            logger.info('dangling DNS rating of project %s waits for a scanner: %s', project.pk, exc)
            return out
        for index, check in plan:
            out[index] = _rating_from(answered.get(check['id']))
    return out


def with_note(description, rating):
    """The stored description: baddns's text, then the check's note (an earlier note is replaced)."""
    text = str(description or '').split(NOTE_MARKER, 1)[0]
    return text + NOTE_MARKER + rating.note if rating and rating.note else text
