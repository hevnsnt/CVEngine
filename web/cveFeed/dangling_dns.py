"""Rating bbot's baddns dangling-DNS findings by what an outsider can actually claim.

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
import secrets
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'takeover_providers.json')
FIRE_SEVERITY, SMOKE_SEVERITY, ICE_SEVERITY = 3, 2, 1  # high, medium, low: cveFeed.threat.SEVERITY_HEAT
KIND_NS, KIND_NXDOMAIN, KIND_HTTP = 'ns', 'cname_nxdomain', 'cname_http'
NOTE_MARKER = '\n\ncvENGINE check: '  # what assess() adds to the stored description; parse() reads only what is before it
DNS_TIMEOUT = 3.0
HTTP_TIMEOUT = 8
MAX_BODY = 64 * 1024
MAX_SERVERS = 4  # name servers asked per level before the level counts as unanswered
LAME_RCODES = ('REFUSED', 'SERVFAIL')


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


def claimable_provider(target):
    """The listed provider a CNAME target is at (a suffix on a label boundary), or None."""
    name = _clean(target)
    for service, suffixes in providers()[0]:
        if any(name == s or name.endswith('.' + s) for s in suffixes):
            return service
    return None


def self_service_provider(nameservers):
    """The self-service DNS provider every one of ``nameservers`` belongs to, or None when any of them is not at a listed provider."""
    found = []
    for ns in nameservers:
        service = next((s for s, patterns in providers()[1] if any(p.match(_clean(ns)) for p in patterns)), None)
        if service is None:
            return None
        if service not in found:
            found.append(service)
    return ' and '.join(found) or None


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
    bbot writes ``<description>. Confidence: [..] Signature: [..] Indicator: [..] Trigger: [a, b] baddns Module: [..]``."""
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

@dataclass
class Reply:
    """One DNS answer: the rcode as text, the AA flag, and the answer and authority records as ``(owner, type, value)``, all lower case
    without the trailing dot."""
    rcode: str
    aa: bool = False
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)

    def values(self, owner, rtype, sections=('answer', 'authority')):
        owner = _clean(owner)
        return [v for s in sections for o, t, v in getattr(self, s) if o == owner and t == rtype]


class Net:
    """The lookups the rating makes. DNS questions go straight to the name servers being evaluated, recursion off; addresses that are
    loopback, private or otherwise not scannable are never asked. The HTTP control goes through ``cveFeed.pinned_transport`` (vetted
    addresses, Settings > Proxy)."""

    def __init__(self):
        self._addresses = {}

    def _resolver(self):
        from cveFeed.hygiene import _resolver
        return _resolver()

    def ns(self, name):
        """The NS host names of ``name`` from the recursive resolver ([] when there are none or DNS fails)."""
        from cveFeed.hygiene import fetch_records
        return [_clean(v) for v in fetch_records(name, 'NS', resolver=self._resolver())]

    def addresses(self, host):
        host = _clean(host)
        if host not in self._addresses:
            from cveFeed.hygiene import fetch_records
            from targetApp.target_types import is_scannable_ip
            self._addresses[host] = [ip for ip in fetch_records(host, 'A', resolver=self._resolver()) if is_scannable_ip(ip)]
        return self._addresses[host]

    def ask(self, server, qname, rdtype):
        """One non-recursive question to one server address, or None when it gave no answer."""
        import dns.exception
        import dns.flags
        import dns.message
        import dns.query
        from targetApp.target_types import is_scannable_ip
        if not is_scannable_ip(server):
            return None
        query = dns.message.make_query(qname, rdtype)
        query.flags &= ~dns.flags.RD
        try:
            response = dns.query.udp(query, server, timeout=DNS_TIMEOUT)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(query, server, timeout=DNS_TIMEOUT)
        except (dns.exception.DNSException, OSError, ValueError):
            return None
        return reply_from(response)

    def registered(self, domain):
        """True when ``domain`` is registered, False when its registry says it is not, None when that cannot be told. A domain with name
        servers is registered; only an NXDOMAIN is asked of the registry (RDAP), and only its explicit "not found" counts."""
        import dns.exception
        import dns.resolver
        try:
            self._resolver().resolve(domain, 'NS')
            return True
        except dns.resolver.NoAnswer:
            return True
        except dns.resolver.NXDOMAIN:
            from cveFeed.mailfail import rdap_registered
            return rdap_registered(domain)
        except (dns.exception.DNSException, OSError):
            return None

    def http_control(self, host):
        """``(real, control, control_name)``: the answer to ``GET /`` for ``host`` and for a random name sent to the same addresses, each
        ``(status, body)``; plain HTTP first, then HTTPS (certificate not checked: the provider's default certificate is the point). None when
        neither got an answer."""
        from cveFeed import pinned_transport
        control = f'cvengine-control-{secrets.token_hex(6)}.{_clean(host)}'
        for port, tls in ((80, False), (443, True)):
            try:
                addresses = pinned_transport.resolve(_clean(host), port)
            except (ValueError, OSError):
                return None
            real = self._get(_clean(host), port, addresses, tls)
            if real is None:
                continue
            other = self._get(control, port, addresses, tls)
            return (real, other, control) if other is not None else None
        return None

    def _get(self, name, port, addresses, tls):
        import http.client
        import ssl

        from cveFeed import pinned_transport
        context = None
        if tls:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        connection = pinned_transport.HTTPConnection(name, port, addresses, HTTP_TIMEOUT, context=context)
        try:
            connection.request('GET', '/', headers={'User-Agent': 'cvENGINE takeover check', 'Accept': '*/*', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            return response.status, pinned_transport.read_body(response, MAX_BODY)
        except (OSError, ValueError, http.client.HTTPException):
            return None
        finally:
            connection.close()


def reply_from(response):
    """A ``Reply`` from a dnspython message."""
    import dns.flags
    import dns.rcode
    import dns.rdatatype

    def records(section):
        return [(_clean(rrset.name.to_text()), dns.rdatatype.to_text(rrset.rdtype),
                 rd.to_text() if rrset.rdtype == dns.rdatatype.SOA else _clean(rd.to_text().split()[-1]))
                for rrset in section for rd in rrset]
    return Reply(dns.rcode.to_text(response.rcode()), bool(response.flags & dns.flags.AA), records(response.answer), records(response.authority))


def ask_any(net, servers, qname, rdtype):
    for server in list(servers)[:MAX_SERVERS]:
        reply = net.ask(server, qname, rdtype)
        if reply is not None:
            return reply
    return None


def _addresses(net, hosts):
    out = []
    for host in hosts:
        out += [a for a in net.addresses(host) if a not in out]
    return out


# ----------------------------------------------------------------------------- the zone cut

@dataclass
class Cut:
    kind: str  # 'zone' (a delegation), 'cname' (a name of the client's is a CNAME) or 'unknown'
    name: str = ''
    nameservers: list = field(default_factory=list)
    target: str = ''


def find_cut(name, net):
    """The deepest delegation on the way to ``name``, walking down from its registry: each level's servers are asked (recursion off) for
    the next name's NS, and a referral or an NS answer for that name is a cut. Stops at a CNAME (``kind='cname'``: whatever lies past it
    is the CNAME target's zone, not the client's), at a server that refuses (a lame delegation: the cut above is the one to evaluate) and at a
    name that does not exist."""
    from targetApp.target_types import apex_domain
    name = _clean(name)
    apex = apex_domain(name)
    if not apex or '.' not in apex:
        return Cut('unknown')
    labels = name[:-len(apex)].rstrip('.').split('.') if name != apex else []
    chain = [apex]
    for label in reversed([x for x in labels if x]):
        chain.append(f'{label}.{chain[-1]}')
    servers = _addresses(net, net.ns(apex.split('.', 1)[1]))
    cut = None
    for qname in chain:
        reply = ask_any(net, servers, qname, 'NS')
        if reply is not None and reply.rcode in LAME_RCODES and cut is not None:
            break  # the servers of the cut above refuse: that delegation is the one to evaluate
        if reply is None or reply.rcode not in ('NOERROR', 'NXDOMAIN'):
            return Cut('unknown')  # no answer: a shallower cut is not evaluated in place of one that may lie deeper
        target = reply.values(qname, 'CNAME', ('answer',))
        if target:
            return Cut('cname', qname, target=target[0])
        nameservers = reply.values(qname, 'NS')
        if nameservers:
            cut = Cut('zone', qname, sorted(set(nameservers)))
            servers = _addresses(net, cut.nameservers)
            if not servers:
                break
            continue
        if reply.rcode == 'NXDOMAIN':
            return Cut('unknown')  # the name does not exist where baddns saw a delegation: nothing to rate
    return cut or Cut('unknown')


def soa_state(zone, nameservers, net):
    """'lame' when every delegated name server answered a non-recursive SOA question for ``zone`` with REFUSED or SERVFAIL, 'served' when
    one answered for it, None otherwise (a server gave no answer, or answered something else)."""
    replies = []
    for ns in nameservers:
        reply = ask_any(net, net.addresses(ns), zone, 'SOA')
        if reply is None:
            return None
        replies.append(reply)
    if not replies:
        return None
    if any(r.rcode == 'NOERROR' and (r.aa or r.values(zone, 'SOA', ('answer',))) for r in replies):
        return 'served'
    if all(r.rcode in LAME_RCODES for r in replies):
        return 'lame'
    return None


# ----------------------------------------------------------------------------- the rating

@dataclass
class Rating:
    severity: int = None  # None: keep baddns's
    drop: bool = False
    note: str = ''
    zone: str = ''


def assess(finding, net=None):
    """The rating of one bbot finding (a dict with ``host``, ``description``, ``module``), or None when it is not a baddns finding this rates,
    the checks are off or the network gave no usable answer. Never raises."""
    if not enabled() or (finding.get('module') or 'baddns') != 'baddns':
        return None
    parsed = parse(finding.get('description'))
    host = _clean(finding.get('host'))
    if parsed is None or not host:
        return None
    net = net or Net()
    try:
        return {KIND_NS: _assess_ns, KIND_NXDOMAIN: _assess_nxdomain, KIND_HTTP: _assess_http}[parsed.kind](host, parsed, net)
    except Exception:  # noqa: BLE001 - a check that fails leaves baddns's rating, it never loses the finding
        logger.exception('dangling DNS check of %s failed', host)
        return None


def _assess_ns(host, parsed, net):
    cut = find_cut(host, net)
    if cut.kind == 'cname':
        return Rating(drop=True, zone=cut.name, note=(
            f'{cut.name} is a CNAME to {cut.target}. The name servers baddns reached serve the zone of the CNAME target (the provider), not '
            f'a delegation of this domain, so how they answer is the provider\'s DNS behaviour, not a dangling delegation.'))
    if cut.kind != 'zone':
        return None
    state = soa_state(cut.name, cut.nameservers, net)
    servers = ', '.join(cut.nameservers)
    if state == 'served':
        return Rating(severity=ICE_SEVERITY, zone=cut.name, note=(
            f'The delegation of {cut.name} ({servers}) is served: a delegated name server answers for the zone with its SOA. '
            f'baddns\'s reading is not reproduced.'))
    if state != 'lame':
        return None
    provider = self_service_provider(cut.nameservers)
    if provider:
        return Rating(severity=FIRE_SEVERITY, zone=cut.name, note=(
            f'{cut.name} is delegated to {provider} ({servers}) and every delegated name server answers a non-recursive SOA query for it '
            f'with REFUSED or SERVFAIL: no account there hosts the zone. {provider} lets any customer create a zone of any name, so anyone '
            f'can create {cut.name} there and answer for it (a zone takeover).'))
    return Rating(severity=SMOKE_SEVERITY, zone=cut.name, note=(
        f'{cut.name} is delegated to {servers} and every delegated name server refuses it, but that provider is not one where anyone can '
        f'create a zone of any name: the delegation is broken, a takeover is not shown.'))


def _assess_nxdomain(host, parsed, net):
    from targetApp.target_types import apex_domain
    target = parsed.triggers[-1] if parsed.triggers else ''
    if not target or target == 'self':
        return None
    provider = claimable_provider(target)
    if provider:
        return Rating(note=f'{target} is at {provider}, where a released name can be claimed by another customer.')
    domain = apex_domain(target)
    if not domain:
        return None
    registered = net.registered(domain)
    if registered is False:
        return Rating(note=f'{domain}, the registrable domain of {target}, is not registered: anyone can register it and answer for this name.')
    if registered is None:
        return None
    return Rating(severity=ICE_SEVERITY, note=(
        f'{target} does not resolve, but it is not at a provider where another customer can claim a name, and {domain} is registered, so '
        f'no outsider can create it: a stale record to remove, not a takeover.'))


def _normalised(answer, name):
    status, body = answer
    text = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body or '')
    return status, ' '.join(text.replace(name, '{host}').split())


def same_answer(real, control, host, control_name):
    """Whether the control request got the same status and body as the real one (each with its own host name blanked out)."""
    return _normalised(real, host) == _normalised(control, control_name)


def _assess_http(host, parsed, net):
    target = parsed.triggers[-1] if parsed.triggers else ''
    if target and target != 'self' and claimable_provider(target):
        return None
    pair = net.http_control(host)
    if pair is None:
        return None
    real, control, control_name = pair
    if same_answer(real, control, host, control_name):
        return Rating(drop=True, note=(
            f'A control request to the same addresses with a random host name ({control_name}) got the same answer (HTTP {real[0]}, same '
            f'body): the provider answers every host name this way, claimed or not, so the matched text says nothing about {host}.'))
    return None


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
    own rating stands, never a drop or a lower severity. With no Sentinel for the kind each finding is assessed here; with none able to take the work and
    the kind off ``CVENGINE_LOCAL_FALLBACK`` (``ScannerUnavailable``) every finding keeps baddns's rating, and ``rerate_dangling_dns`` rates them later."""
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
    if project is not None and plan:
        from agentapi import probe_dispatch
        from reNgine.resources import ScannerUnavailable
        try:
            answered = probe_dispatch.try_dangling(project, [check for _i, check in plan], providers_doc())
        except ScannerUnavailable as exc:
            logger.info('dangling DNS rating of project %s waits for a scanner: %s', project.pk, exc)
            return out
        if answered is not None:
            for index, check in plan:
                out[index] = _rating_from(answered.get(check['id']))
            return out
    for index, _check in plan:
        out[index] = assess(findings[index])
    return out


def with_note(description, rating):
    """The stored description: baddns's text, then the check's note (an earlier note is replaced)."""
    text = str(description or '').split(NOTE_MARKER, 1)[0]
    return text + NOTE_MARKER + rating.note if rating and rating.note else text
