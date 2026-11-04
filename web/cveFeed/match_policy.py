"""What counts as evidence for a CVE match, and what happens to a product seen without any.

A CVE match is a finding, so it needs hard evidence about *this host*, not a name that also appears in an advisory:

  * the product seen on the host is the same product the advisory names (``correlation.name_matches_token``) and its version is
    inside a bounded affected range of that advisory; or
  * a confirming check (a template hit), a distribution tracker listing the package as affected, a host-reported inventory
    (source ``host``) or a runZero report of the same CVE (those attach to a match that exists, they do not create one);
  * one exception, kept deliberately: a version of the same product against a CISA KEV advisory that gives no usable version bound
    (empty ranges, "unspecified"). Actively exploited and untestable by version, it is kept as a low-confidence match flagged
    ``evidence.unbounded``: a candidate that needs validation, never an "affected" verdict, and the host is template-tested too.
    It is a "version unknown" match (``is_version_unknown``): marked for review (the Needs validation list, with the reason below),
    very low priority (heat ice, a tiny capped share of the host score, no automatic AI triage or validation spend), and re-evaluated
    by the next correlation as soon as the CVE gains a version range.

A product seen *without a version* is not evidence of anything: "nginx" is in hundreds of advisories and most of them do not
apply to the version the host runs. It stays on the host as a technology or port (metadata is never dropped), and
``unversioned_products`` lists it as an unverified product, the lead for whatever finds its version (a banner, a version probe, a
host inventory). The same goes for an advisory that gives no usable version bound ("all versions", "unspecified"): there is
nothing to test the host's version against. An operating-system fingerprint ("Ubuntu", "Windows Server 2019") is decided by the
host's own report of its patch level, so it never matches by name either.

This module holds the pure rules and the maintenance step; ``correlation`` applies them while it correlates and ``tasks`` runs
``close_policy_matches`` after every update, so matches made before the policy existed close with a stored reason. A match someone took
a position on (remediation other than open, an assignee, a comment, a manual validation request, an AI "affected" verdict) or that
has a template hit, a distribution "vulnerable" verdict, a runZero report or a host-reported source is never closed by any
automatic sweep (``has_standing`` / ``closable``).
"""
import re

NO_EVIDENCE = 'Closed automatically: no version evidence'
REASON_NO_VERSION = (NO_EVIDENCE + '. The product was seen without a version, so cvENGINE cannot tell which '
                     'of its advisories apply; it is kept as a technology on the host (Unverified products) and is matched again '
                     'as soon as a version is identified.')
REASON_NO_BOUND = (NO_EVIDENCE + '. The advisory gives no version bound to test this version against, so '
                   'the product name alone is not evidence that the host is affected.')
REASON_OS = (NO_EVIDENCE + '. An operating-system fingerprint is not matched to CVEs by name from outside; '
             'only the host\'s own inventory report can place its kernel or patch level.')

REASON_VERSION_UNKNOWN = ('Version of the CVE is not known: review when the affected versions are published. The advisory gives no '
                          'usable affected version range, so this host cannot be tested by version. It is kept for review at very '
                          'low priority and is re-evaluated automatically when a range is published; until then only a person '
                          'can decide it.')

# an operating system named by a scanner, as a technology or an nmap product: never a CVE match by name
_OS_NAME = re.compile(
    r'^(?:(?:microsoft|canonical|gnu)\s+)?(?:windows(?:\s+(?:server|nt|\d[\w.]*|xp|vista|rt|ce|embedded)\b.*)?'
    r'|ubuntu(?:\s+linux)?|debian(?:\s+(?:gnu\s*/\s*)?linux)?|centos(?:\s+linux)?|(?:red\s*hat\s+)?(?:enterprise\s+)?linux(?:\s+kernel)?'
    r'|rhel|fedora|alpine(?:\s+linux)?|(?:open)?suse(?:\s+linux)?|rocky(?:\s+linux)?|almalinux|oracle\s+linux|amazon\s+linux'
    r'|freebsd|openbsd|netbsd|macos|mac\s+os(?:\s+x)?|os\s+x|unix|android|ios)$', re.I)
_OS_CPE = re.compile(r'^cpe:(?:/o:|2\.3:o:)', re.I)
# a product that is not software on its own: what a scanner calls a page it could not identify further
_NOT_A_LEAD = frozenset({'unknown', 'tcpwrapped'})


def is_os_sighting(name, cpe=''):
    """Whether a scanner's technology or product name (or CPE) names an operating system rather than an application. The CPE only
    speaks when the name says nothing: nmap gives "Microsoft HTTPAPI httpd" and "Linux telnetd" the CPE of the system they run on,
    but they are applications."""
    if _OS_NAME.match(re.sub(r'[_\-]+', ' ', (name or '').strip())):
        return True
    from cveFeed.correlation import GENERIC_PRODUCT_TOKENS, GENERIC_WORDS, _norm
    token = _norm(name)
    return bool(_OS_CPE.match((cpe or '').strip())) and (not token or token in GENERIC_PRODUCT_TOKENS | GENERIC_WORDS or token in _NOT_A_LEAD)


def hard_version_evidence(in_range, detail=None):
    """Whether a version result is evidence: inside a bounded range, or older than every branch an advisory fixes (an end-of-life
    release that never got a fix, which correlation records as ``branch_unlisted``). An unknown result is not."""
    return in_range is True or bool((detail or {}).get('branch_unlisted'))


# the JSON values Python reads as false (``bool(evidence.get(key))``): an evidence key holding one of them is no evidence at all
FALSY_JSON = (False, None, {}, [], '', 0)


def evidence_flag(evidence, key):
    """Whether ``evidence`` (a match's evidence dict) holds ``key`` with a true value: a key holding ``False``, ``None``, ``{}``, ``[]``, ``''`` or
    ``0`` is no evidence. ``evidence_flag_q`` is the database form, so the two never disagree."""
    return isinstance(evidence, dict) and bool(evidence.get(key))


def evidence_flag_q(key, prefix=''):
    """The database form of ``evidence_flag``: the key is present and its value is none of ``FALSY_JSON``."""
    from django.db.models import Q
    q = Q(**{prefix + 'evidence__has_key': key})
    for value in FALSY_JSON:
        q &= ~Q(**{f'{prefix}evidence__{key}': value})
    return q


def is_version_unknown(evidence, version_in_range, template_result='', distro_status=''):
    """Whether a match stands only on a name and an actively exploited advisory with no version bound (``evidence.unbounded``): kept
    for review, never a verdict. Hard evidence that does not depend on a version (a template hit, a distribution tracker, a runZero
    report) is not "unknown": that match is judged on it. A version inside a range cannot be unknown either."""
    return evidence_flag(evidence, 'unbounded') and version_in_range is None and template_result != 'vulnerable' \
        and distro_status != 'vulnerable' and not evidence_flag(evidence, 'runzero')


# ----------------------------------------------------------------------------- hard evidence: the one definition

def has_hard_evidence(source, evidence, template_result='', distro_status='', validation_status=''):
    """Whether a CVE match rests on evidence about *this host* beyond a version string. The one definition, used by triage's ceiling, the
    match heat (``threat.match_heat``) and its database form (``hard_evidence_q``). Hard evidence is any of:

      * a template hit (``template_result`` vulnerable: a nuclei CVE template that shows the flaw, or a confirmed OpenVAS test; a template
        that only matches a version string records ``version_only`` instead, ``templategen.template_evidence``, and is not one);
      * the distribution's tracker listing the host's package as vulnerable (``distro_status`` vulnerable);
      * the host's own inventory report: the match was made from it (source ``host``) or it confirmed an external match
        (``evidence.host_reported``);
      * a runZero report of the same CVE on the host (``evidence.runzero``);
      * a validation hit (the finding's Triage ``validation_status`` hit: one of cvENGINE's own read-only checks reproduced it).

    Everything else is *version-only* (for triage: an AI verdict on it stays needs validation): a version read by nmap or a banner, by
    technology detection (a script name, a page generator), by WPScan, an OpenVAS test below its quality bar, a template that matched a version
    string, or a CVE's version range read against any of those. An AI verdict is not evidence
    (text never confirms), and a version re-read by another tool is the same evidence again."""
    return (template_result == 'vulnerable' or distro_status == 'vulnerable' or source == 'host'
            or evidence_flag(evidence, 'host_reported') or evidence_flag(evidence, 'runzero') or validation_status == 'hit')


def hard_evidence_q(prefix=''):
    """The database form of ``has_hard_evidence`` over CVEMatch rows (``prefix`` reaches the match from another model). The validation hit is
    read through the match's Triage row (a one-to-one, so the join never multiplies rows)."""
    from django.db.models import Q
    p = prefix
    return (Q(**{p + 'template_result': 'vulnerable'}) | Q(**{p + 'distro_status': 'vulnerable'}) | Q(**{p + 'source': 'host'})
            | evidence_flag_q('host_reported', p) | evidence_flag_q('runzero', p) | Q(**{p + 'triage__validation_status': 'hit'}))


def _validation_status(match):
    """The validation status of a CVEMatch's Triage row ('' when it has none). Uses the row a ``select_related``/``prefetch_related`` of
    ``triage`` loaded; otherwise one query."""
    from django.core.exceptions import ObjectDoesNotExist
    try:
        row = match.triage
    except (ObjectDoesNotExist, AttributeError):
        return ''
    return getattr(row, 'validation_status', '') or ''


def is_version_only(match):
    """Whether a CVEMatch is *version-only*: it has no hard evidence (``has_hard_evidence``). Triage never rates such a match above needs
    validation (``triage.ceiling``). Heat reads ``version_proven`` under the ``kev`` heat policy (a version read from the component itself is
    proof there) and this under ``legacy`` (``threat.version_only_max_heat``)."""
    return not has_hard_evidence(getattr(match, 'source', ''), getattr(match, 'evidence', None), getattr(match, 'template_result', '') or '',
                                 getattr(match, 'distro_status', '') or '', _validation_status(match))


def version_only_q(prefix=''):
    """The database form of ``is_version_only``."""
    return ~hard_evidence_q(prefix)


# ----------------------------------------------------------------------------- proof: what turns a KEV match fire (the heat policy)

PROVEN_LIBRARY_CONFIDENCE = 0.8  # js_libraries.CONFIDENCE: a file's comment banner 0.9, a code signature 0.8; a file name 0.4
# the template_result a version-class template hit is recorded as (``templategen.VERSION_ONLY_RESULT``): a template that only reads a static
# page or a banner matched the version string on the host. It proves the version, not the flaw.
from cveFeed.templategen import VERSION_ONLY_RESULT as VERSION_TEMPLATE_RESULT  # noqa: E402

# The products whose service banner proves the version that runs (a positive list, so it fails safe: a product cvENGINE does not know is no
# proof). They are vendor-built and self-contained: an appliance's or a vendor's own server, shipped and updated as one build by its vendor, so
# the version it prints is the build that runs; that is where KEV entries concentrate (VPN gateways, firewalls, file-transfer servers,
# Jenkins, Confluence, ActiveMQ). Read as normalized prefixes of the scanner's product name ("Apache ActiveMQ" -> apacheactivemq). Everything
# else is no proof by its banner, in particular what a distribution packages and patches by backporting with the upstream version unchanged,
# often without printing a marker of itself (OpenSSH, Apache httpd, nginx, OpenSSL, MySQL, PHP, Exim, Postfix, BIND, Dovecot, PowerDNS,
# Asterisk, Kerberos, Erlang, libssh, Tomcat, Jetty, Traffic Server, ...), and what the operating system services (IIS, HTTP.sys, Microsoft
# ESMTP and ftpd): only the distribution's tracker or hard evidence proves those.
VENDOR_PRODUCT_PREFIXES = (
    # network appliances and remote access
    'fortigate', 'fortinet', 'fortios', 'fortiweb', 'fortimail', 'fortimanager', 'fortianalyzer', 'fortiproxy', 'fortisiem', 'forticlientems',
    'citrix', 'netscaler', 'ivanti', 'pulsesecure', 'pulseconnectsecure', 'paloalto', 'panos', 'globalprotect', 'sonicwall', 'f5bigip', 'bigip',
    'ciscoasa', 'ciscoadaptivesecurity', 'ciscoise', 'barracuda', 'zyxel', 'sophos', 'watchguard', 'checkpoint', 'mikrotik', 'ubiquiti',
    'qnap', 'synology', 'hikvision', 'dahua', 'mitel',
    # vendor servers shipped as one build
    'jenkins', 'atlassian', 'confluence', 'jira', 'bitbucket', 'bamboo', 'gitlab', 'teamcity', 'jetbrainsteamcity', 'zimbra', 'progressmoveit',
    'moveit', 'goanywhere', 'fortragoanywhere', 'crushftp', 'wingftp', 'servu', 'solarwinds', 'manageengine', 'zohomanageengine', 'veeam',
    'kaseya', 'screenconnect', 'connectwise', 'papercut', 'openfire', 'oracleweblogic', 'weblogic', 'coldfusion', 'adobecoldfusion',
    'vmwarevcenter', 'vmwareesxi', 'vmwarehorizon', 'vmwareworkspace', 'sapnetweaver', 'grafana', 'kibana', 'elasticsearch',
    # Apache projects shipped as the project's own build (not a distribution's)
    'apacheactivemq', 'activemq', 'apachesolr', 'solr', 'apachespark', 'apacheds', 'apacheofbiz', 'apacheairflow', 'apachesuperset',
    'apachedruid', 'apacheflink', 'apacheapisix', 'apacherocketmq', 'rocketmq', 'apachenifi', 'apachecouchdb', 'couchdb',
    'apacheopenmeetings', 'apacheunomi', 'apachehugegraph',
)


def vendor_built(product):
    """Whether a service banner of ``product`` (the scanner's product name) states the version that runs: a vendor-built product on
    ``VENDOR_PRODUCT_PREFIXES``. Anything else, an empty name included, is no proof by its banner (correlation records the answer as
    ``evidence.vendor_banner``)."""
    token = re.sub(r'[^a-z0-9]', '', (product or '').lower())
    return bool(token) and token.startswith(VENDOR_PRODUCT_PREFIXES)


def provenance_recorded(evidence):
    """Whether a match's evidence was written by the code that records everything ``version_read_from_component`` reads: a port row needs
    ``vendor_banner`` (recorded since the heat policy's review; a row from before reads as no proof until the next correlation writes it). The
    first correlation after the update therefore turns some old rows fire by recording what was already true, which is no news: it is not paged
    (``correlation.save_matches``, ``correlation._carry_remediation``)."""
    if not isinstance(evidence, dict) or evidence.get('source') != 'port':
        return True
    return 'vendor_banner' in evidence


def proof_only_unrecorded(old, new_evidence, new_version, validation_status=''):
    """Whether a match turns proven only because correlation now records a field it did not record before (``provenance_recorded``): the old
    row (``old``: a CVEMatch as it was, or anything with its ``source``, ``evidence``, ``template_result``, ``distro_status`` and
    ``matched_version``) at the same version, with that field filled in from the new evidence, was already proven. That is no news, so it is not
    paged. Anything else is new proof (nmap now probes the service instead of guessing from the port, the version moved) and is paged."""
    from types import SimpleNamespace
    old_evidence = getattr(old, 'evidence', None)
    if provenance_recorded(old_evidence) or (getattr(old, 'matched_version', '') or '') != (new_version or ''):
        return False
    filled = {**old_evidence, 'vendor_banner': bool((new_evidence or {}).get('vendor_banner'))}
    probe = SimpleNamespace(source=getattr(old, 'source', ''), evidence=filled, template_result=getattr(old, 'template_result', '') or '',
                            distro_status=getattr(old, 'distro_status', '') or '')
    return version_proven(probe, validation_status=validation_status or '')


_TYPEOF_REGISTERED = []


def _register_json_typeof():
    """Register ``jsontype`` (PostgreSQL ``jsonb_typeof``) on JSON key lookups once, so a database form can insist a value is a number: JSONB
    orders true, arrays and objects above every number, so ``value >= 0.8`` alone holds for them where Python's test does not."""
    if _TYPEOF_REGISTERED:
        return
    from django.db.models import CharField, Transform
    from django.db.models.fields.json import KeyTransform

    class JSONTypeof(Transform):
        lookup_name = 'jsontype'
        function = 'jsonb_typeof'
        output_field = CharField()

    KeyTransform.register_lookup(JSONTypeof)
    _TYPEOF_REGISTERED.append(True)


def version_read_from_component(evidence, distro_status='', template_result=''):
    """Whether a match's version was read from the component itself, at a confidence that proves it: "version proven", the second half of
    ``version_proven`` (the first, "vulnerability confirmed", is ``has_hard_evidence``). It proves the version is there, not that the flaw is,
    so it never lifts triage, creates a finding or counts as a validation hit; it is what the heat rule needs. Three readings qualify:

      * a version-class template hit on this host (``template_result`` version_only): a template that only reads a static page or a banner
        read the version from the service or the file itself and found it inside the range;
      * a JavaScript library whose OWN FILE states the version: ``evidence.source`` tech, ``version_source`` body (the file's comment banner
        or a code signature only the library's file has, ``cveFeed.js_libraries``), ``version_confidence`` at least
        ``PROVEN_LIBRARY_CONFIDENCE`` (0.8), and the copy that runs on the page (``copy_state`` effective, ``copies_unresolved`` not set),
        and that copy is the file that was read: the ``evidence.copies`` entry whose ``url`` is the ``script_url`` is itself ``source`` body
        and ``state`` effective (``script_copy_read``; ``copy_state`` is the best state of any copy of the version, so a read copy a later
        unread one shadows would pass on it alone);
      * a network service that answered nmap's version probe itself: ``evidence.source`` port, ``method`` probed (``table`` is nmap's
        guess from the port number), a vendor-built product (``evidence.vendor_banner``: ``vendor_built``, recorded by correlation)
        and NO distribution packaging read from the banner (``evidence.distro``). A distribution backports fixes without changing the
        upstream version it prints, and most print no marker of themselves, so the banner of any product not on the vendor list (OpenSSH,
        Apache httpd, nginx, OpenSSL, MySQL, PHP, Exim, BIND, Dovecot, IIS, an unknown product, ...) proves nothing until the distribution's own
        tracker gives a verdict (``distro_status`` vulnerable is hard evidence; patched is ice).

    Never proof: a version from a script's file name, CDN path or ``?ver=`` query (``version_source`` filename, 0.4), a copy a later one
    replaces, a fallback or a copy of an unresolved set (their caps, 0.4 and 0.5, are below the bar), a library version another tool read
    (``version_source`` other), technology detection (Wappalyzer, httpx, a page generator, a header), WPScan, an OpenVAS test below its
    quality bar, a version inherited from another host or a redirect (correlation records none of those as a file or probe reading), a
    nmap row from before the method was kept, and an AI verdict. To tighten it, drop a clause here (and in ``version_read_from_component_q``):
    the heat, lists, counts, scores, alerts and API all follow."""
    if distro_status == 'patched':
        return False
    if template_result == VERSION_TEMPLATE_RESULT:
        return True
    if not isinstance(evidence, dict):
        return False
    source = evidence.get('source')
    if source == 'tech':
        confidence = evidence.get('version_confidence')
        return (evidence.get('version_source') == 'body' and evidence.get('copy_state') == 'effective'
                and isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and confidence >= PROVEN_LIBRARY_CONFIDENCE
                and not evidence_flag(evidence, 'copies_unresolved') and script_copy_read(evidence))
    if source == 'port':
        return evidence.get('method') == 'probed' and evidence_flag(evidence, 'vendor_banner') and not evidence_flag(evidence, 'distro')
    return False


def script_copy_read(evidence):
    """Whether the copy at a library match's ``script_url`` is the file that was read and the one that runs: its ``evidence.copies`` entry
    (same ``url``) is ``source`` body and ``state`` effective. No such entry is no proof. ``script_copy_read_q`` is the database form."""
    url = evidence.get('script_url') if isinstance(evidence, dict) else None
    copies = evidence.get('copies') if isinstance(evidence, dict) else None
    return bool(isinstance(url, str) and url and isinstance(copies, list) and any(
        isinstance(c, dict) and c.get('url') == url and c.get('source') == 'body' and c.get('state') == 'effective' for c in copies))


_SCRIPT_COPY_PATH = '$.copies[*] ? (@.url == $u && $u != "" && @.source == "body" && @.state == "effective")'


def script_copy_read_q(prefix=''):
    """The database form of ``script_copy_read`` (PostgreSQL ``jsonb_path_exists``, the ``script_url`` passed in as ``$u``)."""
    from django.db.models import BooleanField, F, Func, Q

    class ScriptCopyRead(Func):
        output_field = BooleanField()
        conditional = True
        template = (f"jsonb_path_exists(%(expressions)s, '{_SCRIPT_COPY_PATH}'::jsonpath, "
                    "jsonb_build_object('u', (%(expressions)s) -> 'script_url'))")
    return Q(ScriptCopyRead(F(prefix + 'evidence')))


def library_read_q(prefix=''):
    """``version_read_from_component_q``'s library clause alone (a library's own file states the version, for the copy that runs)."""
    from django.db.models import Q
    _register_json_typeof()
    p = prefix
    return (Q(**{p + 'evidence__source': 'tech', p + 'evidence__version_source': 'body', p + 'evidence__copy_state': 'effective',
                 p + 'evidence__version_confidence__jsontype': 'number',
                 p + 'evidence__version_confidence__gte': PROVEN_LIBRARY_CONFIDENCE}) & ~evidence_flag_q('copies_unresolved', p)
            & script_copy_read_q(p))


def version_read_from_component_q(prefix=''):
    """The database form of ``version_read_from_component``. The confidence must be a JSON number (``jsonb_typeof``), as Python's
    ``isinstance`` test requires: JSONB orders true, arrays and objects above every number."""
    from django.db.models import Q
    p = prefix
    library = library_read_q(p)
    service = (Q(**{p + 'evidence__source': 'port', p + 'evidence__method': 'probed'}) & evidence_flag_q('vendor_banner', p)
               & ~evidence_flag_q('distro', p))
    template = Q(**{p + 'template_result': VERSION_TEMPLATE_RESULT})
    return (template | library | service) & ~Q(**{p + 'distro_status': 'patched'})


def version_proven(match, validation_status=None):
    """Whether a CVEMatch PROVES the version is on the host, in the sense of the owner's heat policy ("we can PROVE that version is in our
    environment": fire when its CVE is hot, ``threat.match_heat``). The one definition, with its database form ``version_proven_q``:

      * hard evidence about the host (``has_hard_evidence``): a template hit (nuclei, a confirmed OpenVAS test, testssl), the distribution
        tracker listing the package as vulnerable, the host's own inventory report, runZero reporting the CVE, a validation hit; or
      * the version read from the component itself at high confidence (``version_read_from_component``): a version-class template hit, a
        JavaScript library's own file (banner 0.9 or code signature 0.8, the copy that runs), or a service banner nmap's probe read from a
        service that is not distribution-packaged.

    Everything else (``version_read_from_component`` lists it) is a version we only THINK is there: smoke when hot. ``validation_status``
    overrides the Triage row's (``''``: as if no validation had hit yet)."""
    status = _validation_status(match) if validation_status is None else validation_status
    return (has_hard_evidence(getattr(match, 'source', ''), getattr(match, 'evidence', None), getattr(match, 'template_result', '') or '',
                              getattr(match, 'distro_status', '') or '', status)
            or version_read_from_component(getattr(match, 'evidence', None), getattr(match, 'distro_status', '') or '',
                                           getattr(match, 'template_result', '') or ''))


def version_proven_q(prefix=''):
    """The database form of ``version_proven``."""
    return hard_evidence_q(prefix) | version_read_from_component_q(prefix)


def proof_of(match):
    """What proves a CVEMatch's version, in a few words for the heat reason ("version proven: template hit"), or '' when nothing does."""
    evidence = getattr(match, 'evidence', None)
    evidence = evidence if isinstance(evidence, dict) else {}
    if (getattr(match, 'template_result', '') or '') == 'vulnerable':
        return 'version proven: template hit'
    if (getattr(match, 'distro_status', '') or '') == 'vulnerable':
        return "version proven: the distribution's tracker lists the package as vulnerable"
    if getattr(match, 'source', '') == 'host' or evidence_flag(evidence, 'host_reported'):
        return "version proven: the host's own inventory report"
    if evidence_flag(evidence, 'runzero'):
        return 'version proven: runZero reports it'
    if _validation_status(match) == 'hit':
        return 'version proven: a validation check reproduced it'
    if (getattr(match, 'template_result', '') or '') == VERSION_TEMPLATE_RESULT and getattr(match, 'distro_status', '') != 'patched':
        return 'version proven: a version check read it on the host'
    if version_read_from_component(evidence, getattr(match, 'distro_status', '') or ''):
        return ('version proven: read from the library file itself' if evidence.get('source') == 'tech'
                else 'version proven: read from the service banner by nmap')
    return ''


def version_only(source, evidence, version_in_range, template_result='', distro_status=''):
    """Whether a match stands on nothing but a version string inside an advisory's range (or older than every branch it fixes, which
    correlation records as ``branch_unlisted`` with no range result: the same string, read against the advisory's branches) and has no hard
    evidence (``has_hard_evidence``; a validation hit is weighed by the caller, on the Triage row). A banner version is the
    weakest evidence there is (a distribution backports fixes without changing it, a proxy answers for another server), so such a match
    is a lead to check, never a finding the AI can call affected (``triage.ceiling``)."""
    on_version = version_in_range is True or (version_in_range is None and evidence_flag(evidence, 'branch_unlisted'))
    return on_version and not has_hard_evidence(source, evidence, template_result, distro_status)


def version_unknown(match):
    """``is_version_unknown`` of a CVEMatch."""
    return is_version_unknown(match.evidence, match.version_in_range, getattr(match, 'template_result', ''), getattr(match, 'distro_status', ''))


def version_unknown_q(prefix=''):
    """The database form of ``is_version_unknown`` over CVEMatch rows (``prefix`` reaches the match from another model)."""
    from django.db.models import Q
    return (evidence_flag_q('unbounded', prefix) & Q(**{prefix + 'version_in_range__isnull': True})
            & ~Q(**{prefix + 'template_result': 'vulnerable'}) & ~Q(**{prefix + 'distro_status': 'vulnerable'})
            & ~evidence_flag_q('runzero', prefix))


def _has_other_evidence(match):
    """A match with hard evidence that does not depend on a version: it stays whatever the sighting says."""
    return (match.template_result == 'vulnerable' or match.distro_status == 'vulnerable'
            or evidence_flag(match.evidence, 'runzero'))


def sighting_of(match):
    """``(product name, cpe)`` of the technology or port a correlated match was made from, read from the evidence it stored. A sighting
    that is gone (a rescan replaced it) falls back to the matched product."""
    from startScan.models import Port, Technology
    from cveFeed.correlation import split_name_version
    evidence = match.evidence or {}
    source_id = evidence.get('source_id')
    if source_id and evidence.get('source') == 'tech':
        name = Technology.objects.filter(pk=source_id).values_list('name', flat=True).first()
        if name:
            return split_name_version(name)[0], ''
    if source_id and evidence.get('source') == 'port':
        row = Port.objects.filter(pk=source_id).values_list('product', 'cpe').first()
        if row and row[0]:
            return row[0].strip(), row[1] or evidence.get('cpe') or ''
    return match.matched_product, evidence.get('cpe') or ''


def has_standing(match):
    """Whether someone or something vouches for this match beyond the name it was made from, so no automatic sweep may close it: a
    person worked it (remediation other than open, an assignee, a comment, a manual validation request: not the one running right now,
    which is the very check that re-reads the product identity), the AI confirmed it, a
    template, a distribution tracker or runZero reported it, or the host reported it itself. (``unworked`` is the queryset form.)"""
    from cveFeed.models import FindingComment, OnDemandValidation
    if (match.remediation_status != 'open' or match.assignee_id or match.ai_verdict == 'affected' or match.source == 'host'
            or _has_other_evidence(match)):
        return True
    return (FindingComment.objects.filter(finding_kind='match', finding_id=match.pk).exists()
            or OnDemandValidation.objects.filter(match=match, source='manual').exclude(status='running').exists())


def unworked(qs):
    """The matches of ``qs`` that nobody vouches for (the queryset form of ``not has_standing``)."""
    from django.db.models import Exists, OuterRef

    from cveFeed.models import FindingComment, OnDemandValidation
    return (qs.filter(remediation_status='open', assignee__isnull=True).exclude(source='host')
            .exclude(template_result='vulnerable').exclude(distro_status='vulnerable').exclude(evidence_flag_q('runzero'))
            .exclude(ai_verdict='affected')
            .exclude(Exists(FindingComment.objects.filter(finding_kind='match', finding_id=OuterRef('pk'))))
            .exclude(Exists(OnDemandValidation.objects.filter(match=OuterRef('pk'), source='manual').exclude(status='running'))))


def no_evidence_reason(match, name, cpe=''):
    """The stored reason to close a correlated (tech or port) match that rests on a name alone, else ''."""
    if match.source not in ('tech', 'port') or has_standing(match):
        return ''
    if is_os_sighting(name, cpe):
        return REASON_OS
    evidence = match.evidence or {}
    if match.version_in_range is True or evidence.get('branch_unlisted') or evidence.get('unbounded'):
        return ''
    return REASON_NO_VERSION if not match.matched_version else REASON_NO_BOUND


def closable(qs):
    """Open, unworked, correlated matches that carry no evidence beyond a name (``unworked``, and not a branch-unlisted or unbounded KEV
    candidate, which are evidence by policy). A row already ruled out (by an earlier pass or by the AI) is left alone."""
    return (unworked(qs.filter(source__in=('tech', 'port')))
            .exclude(evidence_flag_q('branch_unlisted')).exclude(evidence_flag_q('unbounded'))
            .exclude(ai_verdict='not_affected'))


def settle_triage(match_ids, reason, now):
    """Give the triage rows of just-closed matches the classification the closure means. The closure writes the match's legacy verdict,
    which every list and count reads, but the triage list and its queues read the row: left alone it keeps saying needs_validation."""
    from cveFeed.models import Triage
    Triage.objects.filter(match_id__in=match_ids).update(classification='not_applicable', status='triaged', reason=reason, updated_at=now)


def close_policy_matches(limit=5000):
    """Close the open matches made before the evidence policy: a sighting with no version, or one whose advisory gave no version bound.
    Bounded (``limit`` matches per run, oldest first) and idempotent: a closed match is never picked again, so repeated runs finish
    the backlog. Rescores the hosts that lost a match. Returns how many were closed. (Wrong-product and operating-system matches need
    the sighting's name and are closed by ``correlation.invalid_identity_reason`` through ``reconcile_invalid_correlations``.)"""
    from django.db.models import Q
    from django.utils import timezone

    from cveFeed import scoring
    from cveFeed.models import CVEMatch
    from cveFeed.views import bump_stats_revision
    ids = list(closable(CVEMatch.objects.filter(version_in_range__isnull=True)).order_by('id').values_list('id', flat=True)[:limit])
    if not ids:
        return 0
    hosts = sorted({h for h in CVEMatch.objects.filter(id__in=ids).values_list('subdomain_id', flat=True) if h})
    now = timezone.now()
    closed = 0
    for reason, selector in ((REASON_NO_VERSION, Q(matched_version='')), (REASON_NO_BOUND, ~Q(matched_version=''))):
        # the guard is part of the UPDATE itself: a person or a template may have acted since the ids were read
        count = closable(CVEMatch.objects.filter(id__in=ids).filter(selector)).update(
            ai_verdict='not_affected', ai_model='deterministic-policy', confidence=0.0, updated_at=now, ai_reason=reason)
        if count:
            settle_triage(CVEMatch.objects.filter(id__in=ids, ai_reason=reason, updated_at=now).values('id'), reason, now)
        closed += count
    for start in range(0, len(hosts), scoring.CHUNK):
        scoring.rescore_subdomain_ids(hosts[start:start + scoring.CHUNK])
    if closed:
        bump_stats_revision()
    return closed


# ----------------------------------------------------------------------------- unversioned products (the leads)

def _lead(name, source, source_id, **extra):
    return {'name': name, 'source': source, 'source_id': source_id, **extra}


def unversioned_leads(technologies, ports):
    """The products a host runs that no version was found for, as ``{name, source, source_id, ...}``: from ``technologies`` (pairs of
    ``(id, stored name)``) and ``ports`` (pairs of ``(ip address, Port)``). One lead per product, and none for a product some other
    sighting on the same host did give a version, an operating system, or a generic label. Pure, so it is unit tested without a database."""
    from cveFeed.correlation import (_MIN_TOKEN, GENERIC_PRODUCT_TOKENS, _norm, name_matches_token, parse_cpe, parse_version,
                                     split_name_version)
    seen, candidates = [], []
    for source_id, stored in technologies:
        name, version = split_name_version(stored or '')
        candidates.append((name or (stored or '').strip(), parse_version(version) is not None, _lead(name or stored, 'tech', source_id)))
    for ip, port in ports:
        name = (port.product or '').strip()
        version = (port.version or '').strip() or (parse_cpe(port.cpe or '') or ('', '', ''))[2]
        candidates.append((name, parse_version(version) is not None,
                           _lead(name, 'port', port.id, ip=ip, port=port.number, protocol=port.protocol, cpe=(port.cpe or '')[:255],
                                 service=port.service_name or '')))
    versioned = [_norm(name) for name, has_version, _lead in candidates if has_version and name]
    leads, listed = [], set()
    for name, has_version, lead in candidates:
        token = _norm(name)
        if (has_version or len(token) < _MIN_TOKEN or token in GENERIC_PRODUCT_TOKENS or name.lower() in _NOT_A_LEAD
                or is_os_sighting(name, lead.get('cpe', ''))):
            continue
        key = (token, lead['source'], lead.get('ip'), lead.get('port'))
        if key in listed or any(name_matches_token(token, other) for other in versioned):
            continue
        listed.add(key)
        leads.append(lead)
    return leads


def unversioned_products(subdomain):
    """The unverified products of one host (a ``Subdomain``): see ``unversioned_leads``. This is what a version probe or an AI
    investigation starts from to find the missing version; the host page shows the same list."""
    from startScan.models import open_services
    technologies = [(t.id, t.name) for t in subdomain.technologies.all()]
    ports = [(ip.address, port) for ip in subdomain.ip_addresses.all() for port in open_services(ip)]
    return unversioned_leads(technologies, ports)
