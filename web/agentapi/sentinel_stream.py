"""Streamed Sentinel work: a task that posts partial results while it runs, then a final result that closes it (contract version 3).

The discovery (``bbot_discovery``) is the one streamed kind. It runs for up to six hours and finds hosts, ports, technologies, findings and screenshots
all along the way, so it does not fit "one result per task": the Sentinel posts numbered batches to ``POST sentinel/tasks/<id>/partial`` as it goes
(``report_partial``) and the usual ``POST sentinel/tasks/<id>/result`` at the end. Each batch is typed, clipped and held to the task's own scope here
(``clean_partial``), stored as one ``SentinelPartial`` row, and read in order by the stage that dispatched the task (``dispatch_stream``, running in the
discovery worker), which persists it through ``cveFeed.discovery`` and deletes the row. So the inventory, the live
feed and the scan's activity lines fill in as the run goes.

Ordering and idempotence. ``seq`` starts at 1 and grows by one. The task keeps the last one it took (``SentinelTask.partial_seq``): a batch at or below it
is a retry whose answer was lost, answered again as a duplicate and stored once; any other number than the next is refused (400). A final result names the
last ``seq`` it sent (``partials``) and is refused until the server has every batch. At most ``MAX_PENDING`` batches wait for the stage at once; past
that a batch is answered 429 and the Sentinel sends it again shortly (the stage has fallen behind or is gone).

Stopping. A task that is no longer the Sentinel's (a person cancelled it, the stage gave up or stopped with its scan, the lease ran out) answers a
batch with 409, and a batch of a task whose scan was stopped ends the task there and then, so a Sentinel learns of a stop at its next batch; when it
has nothing to send it asks ``GET sentinel/tasks/<id>`` and its heartbeat drops the lease too.

Leases. A batch counts as a sign of life: it extends the task's lease like a heartbeat, within the same ceiling (``sentinel_broker.max_runtime``, which
for a streamed task is the run's own time limit plus ``REPORT_GRACE`` and the broker's ``RUN_GRACE``), so a six hour run does not expire while it works.

Credentials. The API keys a project stored for the discovery's modules are never in a task: a task of a project that has some names them by reference
(``secret_ref`` ``bbotkeys:<project id>``), which keeps it to the built-in scanner, and the scanner reads them once through the secure read
(``sentinel_broker.read_secret``).
"""
import base64
import binascii
import ipaddress
import logging
import re
from urllib.parse import urlsplit

from django.db import IntegrityError, transaction
from django.utils import timezone

from agentapi import sentinel_contract
from agentapi import storage_safe
from agentapi.models import SentinelPartial, SentinelTask
from agentapi.services import ApiError

logger = logging.getLogger(__name__)

KIND = 'bbot_discovery'
STREAMED = sentinel_contract.STREAMED
MAX_SEQ = 1_000_000
MAX_PENDING = 40  # batches stored and not yet persisted by the stage, per task, before a new one is answered 429
REPORT_GRACE = 600  # seconds past a run's own time limit for its last batches and its final result
# The most of each list one batch may carry, equal to the contract's maxItems (tests.test_sentinel_stream holds them together).
LIMITS = {'subdomains': 1000, 'ips': 1000, 'ports': 2000, 'urls': 1000, 'technologies': 1000, 'resolutions': 2000, 'edges': 2000,
          'findings': 200, 'http': 500, 'events': 500, 'screenshots': 4}
MAX_PROBLEMS = 50
MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024
SCREENSHOT_TYPES = {'image/png': b'\x89PNG\r\n\x1a\n', 'image/jpeg': b'\xff\xd8\xff'}
EVENT_TYPES = ('DNS_NAME', 'IP_ADDRESS', 'OPEN_TCP_PORT', 'URL', 'TECHNOLOGY', 'WAF', 'FINDING', 'VULNERABILITY', 'STORAGE_BUCKET',
               'EMAIL_ADDRESS', 'ASN', 'SOCIAL', 'CODE_REPOSITORY', 'WEBSCREENSHOT', 'PROTOCOL')
MODES = ('passive', 'standard', 'deep')
KEYS_REF_PREFIX = 'bbotkeys:'  # ``SentinelTask.secret_ref`` of a discovery task whose project stored API keys: a reference, never a key
MAX_EXCLUSIONS = 2000
MAX_DENY_RANGES = 500
_NAME = re.compile(r'^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$')
_FILENAME = re.compile(r'^[A-Za-z0-9._-]{1,120}$')
_SCAN_NAME = re.compile(r'^[A-Za-z0-9_.-]{0,100}$')
_MODULE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


def _text(value, limit):
    from agentapi import agent_broker
    return agent_broker._text(value, limit)


def _int(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(value)
    return value


def _list(body, key):
    value = body.get(key, [])
    if not isinstance(value, list) or len(value) > LIMITS[key]:
        raise ApiError(400, f'{key} must be a list of at most {LIMITS[key]} entries')
    return value


# --- the scope a task carries, and the same rules held to what comes back ---------------------------------------------------------------

class Scope:
    """The scope policy of a task's target (``$defs/scope_policy``), as the server applies it to what a Sentinel reports: a name is kept when it is in
    or under an in-scope domain (only the domain itself for an exact host) and not excluded; an address when it is a plain address outside every denied
    range. The scanner applies the same policy on its side; this is the server not trusting that it did."""

    def __init__(self, policy):
        policy = policy if isinstance(policy, dict) else {}
        self.domains = [str(d).lower().rstrip('.') for d in policy.get('in_scope_domains') or [] if isinstance(d, str) and d]
        self.exact = bool(policy.get('exact_host'))
        rows = [r for r in policy.get('exclusions') or [] if isinstance(r, dict) and isinstance(r.get('host'), str)]
        self.excluded = {r['host'].lower().rstrip('.') for r in rows}
        self.excluded_trees = {r['host'].lower().rstrip('.') for r in rows if r.get('subtree')}
        self.denied = []
        for cidr in policy.get('deny_ranges') or []:
            try:
                self.denied.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError:
                continue

    def address(self, value):
        """The canonical text of ``value`` when it is an address outside every denied range, else ``None``."""
        try:
            ip = ipaddress.ip_address(str(value).strip().strip('[]'))
        except ValueError:
            return None
        if any(ip.version == net.version and ip in net for net in self.denied):
            return None
        return ip.compressed

    def name(self, value):
        """The lowercase name when ``value`` is a host name in scope, else ``None`` (an address is judged by ``address``)."""
        name = str(value or '').strip().lower().rstrip('.')
        if not name or len(name) > 253 or not _NAME.match(name):
            return None
        if not any(name == d or (not self.exact and name.endswith('.' + d)) for d in self.domains):
            return None
        if name in self.excluded or any(name.endswith('.' + t) for t in self.excluded_trees):
            return None
        return name

    def host(self, value):
        """A host a report names: an address outside the denied ranges, or a name in scope; ``None`` otherwise."""
        text = str(value or '').strip()
        return self.address(text) if text and (':' in text or text.replace('.', '').isdigit()) else self.name(text)

    def url(self, value):
        """An http or https URL whose host is in scope, clipped; ``None`` otherwise."""
        if not isinstance(value, str) or not value or len(value) > 2000:
            return None
        try:
            parts = urlsplit(value)
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme not in ('http', 'https') or not host or parts.username or parts.password or self.host(host) is None:
            return None
        return value


# --- what a Sentinel posts ----------------------------------------------------------------------------------------------------------------

def _screenshot(item, scope):
    """One screenshot, kept only when its host is in scope, its name is a plain file name and its bytes are the image type it says, at most
    ``MAX_SCREENSHOT_BYTES``. The bytes stay base64 in the batch; ``cveFeed.discovery.persist_screenshot_blobs`` writes them out."""
    if not isinstance(item, dict):
        return None
    host = scope.host(item.get('host'))
    filename, kind, data = item.get('filename'), item.get('content_type'), item.get('data')
    if host is None or not isinstance(filename, str) or not _FILENAME.match(filename) or filename.startswith('.') or kind not in SCREENSHOT_TYPES:
        return None
    if not isinstance(data, str) or len(data) > (MAX_SCREENSHOT_BYTES + 2) // 3 * 4:
        return None
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > MAX_SCREENSHOT_BYTES or not raw.startswith(SCREENSHOT_TYPES[kind]):
        return None
    return {'host': host, 'url': scope.url(item.get('url')) or '', 'filename': filename, 'content_type': kind, 'data': data}


def clean_partial(task, body):
    """The typed, clipped batch of ``task``'s report, held to the scope its target carries: anything out of scope, malformed or unexpected is
    dropped, every string clipped, every list capped. 400 when the body is not a batch at all (a list over its cap, a missing ``seq``)."""
    if not isinstance(body, dict):
        raise ApiError(400, 'body must be an object')
    try:
        seq = _int(body.get('seq'), 1, MAX_SEQ)
    except ValueError:
        raise ApiError(400, f'seq must be a whole number from 1 to {MAX_SEQ}') from None
    target = task.target if isinstance(task.target, dict) else {}
    scope = Scope(target.get('scope'))
    out = {'seq': seq}
    name = body.get('scan_name')
    if isinstance(name, str) and _SCAN_NAME.match(name) and name:
        out['scan_name'] = name
    try:
        out['subdomains'] = sorted({n for n in (scope.name(v) for v in _list(body, 'subdomains') if isinstance(v, str)) if n})
        out['ips'] = sorted({a for a in (scope.address(v) for v in _list(body, 'ips') if isinstance(v, str)) if a})
        ports = set()
        for item in _list(body, 'ports'):
            if isinstance(item, dict):
                host = scope.host(item.get('host'))
                port = item.get('port')
                if host and isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                    ports.add((host, port))
        out['ports'] = [{'host': h, 'port': p} for h, p in sorted(ports)]
        urls = {}
        for item in _list(body, 'urls'):
            if isinstance(item, dict) and scope.url(item.get('url')):
                status = item.get('status')
                urls[item['url']] = status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else 0
        out['urls'] = [{'url': u, 'status': s} for u, s in sorted(urls.items())]
        techs = set()
        for item in _list(body, 'technologies'):
            if isinstance(item, dict) and isinstance(item.get('technology'), str) and item['technology'].strip():
                host = scope.host(item.get('host'))
                if host:
                    techs.add((host, _text(item['technology'], 500)))
        out['technologies'] = [{'host': h, 'technology': t} for h, t in sorted(techs) if t]
        pairs = set()
        for item in _list(body, 'resolutions'):
            if isinstance(item, dict):
                name, ip = scope.name(item.get('name')), scope.address(item.get('ip'))
                if name and ip:
                    pairs.add((name, ip))
        out['resolutions'] = [{'name': n, 'ip': i} for n, i in sorted(pairs)]
        edges = set()
        for item in _list(body, 'edges'):
            if isinstance(item, dict):
                parent, child = scope.host(item.get('parent')), scope.host(item.get('child'))
                if parent and child and parent != child:
                    edges.add((parent, child))
        out['edges'] = [{'parent': p, 'child': c} for p, c in sorted(edges)]
        out['findings'] = [f for f in (_finding(item, scope) for item in _list(body, 'findings')) if f]
        out['http'] = [h for h in (_http(item, scope) for item in _list(body, 'http')) if h]
        out['events'] = [e for e in (_event(item, scope) for item in _list(body, 'events')) if e]
        out['screenshots'] = [s for s in (_screenshot(item, scope) for item in _list(body, 'screenshots')) if s]
    except (TypeError, AttributeError):
        raise ApiError(400, 'the batch does not match the expected shape for this task kind') from None
    return storage_safe.clean(out)  # a NUL or a lone surrogate from the host would make Postgres refuse the whole batch (agentapi/storage_safe.py)


def _finding(item, scope):
    if not isinstance(item, dict):
        return None
    host = item.get('host') or ''
    if host and scope.host(host) is None:
        return None
    url = item.get('url') or ''
    if url and scope.url(url) is None:
        return None
    severity = item.get('severity')
    name = _text(item.get('name'), 200)
    if not name:
        return None
    return {'name': name, 'informational': item.get('informational') is True,
            'severity': severity if isinstance(severity, int) and not isinstance(severity, bool) and 0 <= severity <= 4 else 0,
            'host': scope.host(host) if host else '', 'url': url, 'description': _text(item.get('description'), 4000),
            'module': _text(item.get('module'), 64)}


def _http(item, scope):
    if not isinstance(item, dict) or scope.url(item.get('url')) is None:
        return None
    host = scope.host(item.get('host') or urlsplit(item['url']).hostname)
    if host is None:
        return None

    def number(key, high):
        value = item.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= high else 0
    return {'host': host, 'url': item['url'], 'port': number('port', 65535), 'status': number('status', 999),
            'title': _text(item.get('title'), 500), 'webserver': _text(item.get('webserver'), 300),
            'content_type': _text(item.get('content_type'), 200), 'location': _text(item.get('location'), 500)}


def _event(item, scope):
    """One line of the live feed. Its host and its parent's are held to the scope (a module that reports a neighbour is not shown); the label is
    text a scanned host may have chosen, clipped and never interpreted."""
    if not isinstance(item, dict) or item.get('type') not in EVENT_TYPES:
        return None
    host = str(item.get('host') or '')
    parent = str(item.get('parent_host') or '')
    if (host and scope.host(host) is None) or (parent and scope.host(parent) is None):
        return None
    return {'type': item['type'], 'label': _text(item.get('label'), 500), 'host': host[:500].lower(), 'parent_host': parent[:500].lower(),
            'module': _text(item.get('module'), 64)}


def _module_reasons(value):
    out = []
    for item in value[:MAX_PROBLEMS] if isinstance(value, list) else []:
        if isinstance(item, dict) and isinstance(item.get('module'), str) and _MODULE.match(item['module']):
            out.append({'module': item['module'], 'reason': _text(item.get('reason'), 200)})
    return out


def clean_bbot_result(body):
    """The final result of a discovery task (the ``done`` half; ``clean_result`` handles ``error``): how many batches were sent, the mode the run
    finished in, why it stopped part way (empty for a whole run), the scanner's own scan name, how many web events it saw, and the modules that did not
    start. Nothing that was found: that came in the batches."""
    partials = body.get('partials')
    if isinstance(partials, bool) or not isinstance(partials, int) or not 0 <= partials <= MAX_SEQ:
        raise ApiError(400, f'partials must be a whole number from 0 to {MAX_SEQ}')
    if body.get('mode') not in MODES:
        raise ApiError(400, f'mode must be one of {", ".join(MODES)}')
    web = body.get('web_events') if isinstance(body.get('web_events'), dict) else {}
    name = body.get('scan_name')
    return {'partials': partials, 'mode': body['mode'], 'incomplete': _text(body.get('incomplete'), 300),
            'scan_name': name if isinstance(name, str) and _SCAN_NAME.match(name) else '',
            'web_events': {key: web[key] if isinstance(web.get(key), int) and not isinstance(web.get(key), bool) and web[key] >= 0 else 0
                           for key in ('URL', 'HTTP_RESPONSE')},
            'problems': _module_reasons(body.get('problems')), 'hard_failures': _module_reasons(body.get('hard_failures'))}


def check_final(task, result):
    """A final ``done`` result of a streamed task must come after every batch it sent: ``ApiError(400)`` when it names another count."""
    if task.kind in STREAMED and result.get('outcome') == 'done' and result.get('partials') != task.partial_seq:
        raise ApiError(400, f'the result says {result.get("partials")} batches were sent and the server has {task.partial_seq}')


def _scan_stopped(task):
    if not task.scan_id:
        return False
    from cveFeed.discovery import stopped
    return stopped(task.scan_id)


def report_partial(ctx, task_id, body):
    """``POST sentinel/tasks/<id>/partial``: store one batch of a streamed task this Sentinel is running. ``{accepted, duplicate, seq}``; a retry of a batch
    already taken answers ``duplicate`` and stores nothing. 409 when the task is no longer this Sentinel's to run (stop there), 429 when too many
    batches wait for the stage (send it again shortly), 400 for a batch that is not one (the task is then failed: it will not fit when sent again)."""
    from agentapi import agent_broker
    from agentapi import sentinel_broker as broker
    agent = broker._sentinel_agent(ctx)
    broker._limit(agent.token, 'partial')
    now = timezone.now()
    agent_broker._touch(agent, now)
    broker.reap_expired(now)
    task_id = broker._int(task_id)
    task = SentinelTask.objects.select_related('project').filter(pk=task_id, agent=agent).first()
    if task is None:
        ended = SentinelTask.objects.filter(pk=task_id, agent__isnull=True, status='expired').first()  # ``expire`` clears the agent
        if ended is not None and broker._held_before(ended, agent):
            raise ApiError(409, f'the task is no longer assigned to this Sentinel ({(ended.error or "it was ended")[:120]}): stop the run')
        raise ApiError(404, 'task not found')
    broker._ensure_eligible(agent, task)
    if task.kind not in STREAMED:
        raise ApiError(400, f'a {task.kind} task does not post partial results; report it once with POST sentinel/tasks/{task.pk}/result')
    if task.status != 'running' or not task.lease_expires_at or task.lease_expires_at < now:
        raise ApiError(409, 'the task is no longer assigned to this Sentinel (its lease expired, it was cancelled, or its scan stopped)')
    if _scan_stopped(task):
        broker.expire(task, 'the scan was stopped')
        raise ApiError(409, 'the scan was stopped: stop the run')
    seq = body.get('seq') if isinstance(body, dict) else None
    if isinstance(seq, int) and not isinstance(seq, bool) and 1 <= seq <= task.partial_seq:
        return {'accepted': False, 'duplicate': True, 'seq': task.partial_seq}
    if isinstance(seq, int) and not isinstance(seq, bool) and seq != task.partial_seq + 1:
        raise ApiError(400, f'batches must arrive in order: the next is {task.partial_seq + 1}')  # a client fault, never a reason to stop the run
    if SentinelPartial._base_manager.filter(task_id=task.pk).count() >= MAX_PENDING:
        raise ApiError(429, 'earlier batches are still being stored: send this one again shortly')
    try:
        batch = clean_partial(task, body)
    except ApiError as exc:
        if exc.status == 400:
            SentinelTask.objects.filter(pk=task.pk, status='running').update(status='failed', finished_at=now, lease_expires_at=None,
                                                                             error=f'a partial result was rejected: {exc.message}'[:300])
        raise
    from agentapi import address_guard
    refusal = address_guard.task_refusal(task, wait_for_unknown=False)
    if refusal and not getattr(refusal, 'unreadable', False):  # the domain itself now resolves into the do-not-scan list: the run ends here
        broker.expire(task, f'cancelled: {refusal}')
        raise ApiError(409, f'the task was cancelled ({refusal}): stop the run')
    batch, _ = address_guard.filter_batch(task, batch)  # a batch about an excluded address is not stored (the address list is read again for every batch)
    lease = min(now + broker.RUN_LEASE, (task.accepted_at or now) + broker.max_runtime(task))
    try:
        with transaction.atomic():
            won = SentinelTask.objects.filter(pk=task.pk, agent=agent, status='running', partial_seq=seq - 1).update(
                partial_seq=seq, lease_expires_at=lease)
            if not won:
                raise IntegrityError('lost the race')
            SentinelPartial.objects.create(task=task, seq=seq, body=batch)
    except IntegrityError:
        task.refresh_from_db()
        if task.partial_seq >= seq:  # the same batch, sent twice at once: the other one stored it
            return {'accepted': False, 'duplicate': True, 'seq': task.partial_seq}
        raise ApiError(409, 'the task is no longer assigned to this Sentinel') from None
    return {'accepted': True, 'duplicate': False, 'seq': seq}


# --- the API keys of a project, for the built-in scanner and the owner's own Sentinels the gate allows -----------------------------------------------------------------------------

def keys_ref(project_id):
    return f'{KEYS_REF_PREFIX}{int(project_id)}'


def keys_payload(task):
    """The project's discovery module keys as the nested config the scanner reads from a preset (``{modules: {shodan_dns: {api_key: ...}}}``), or ``None`` when the
    project has none any more. Called only by ``sentinel_broker.read_secret`` once it has won the single use."""
    from cveFeed.api_credentials import bbot_config_args
    from dashboard.models import Project
    project = Project.objects.filter(pk=task.project_id).first()
    args = bbot_config_args(project) if project else []
    config = {}
    for flag, pair in zip(args[::2], args[1::2]):
        path, _, value = pair.partition('=')
        keys = path.split('.')
        if flag != '-c' or len(keys) != 3 or keys[0] != 'modules' or not value:
            continue
        config.setdefault('modules', {}).setdefault(keys[1], {})[keys[2]] = value
    return config or None


def keys_ref_project(ref):
    tail = ref[len(KEYS_REF_PREFIX):] if isinstance(ref, str) and ref.startswith(KEYS_REF_PREFIX) else ''
    return int(tail) if tail.isdigit() and len(tail) <= 18 else None


KEYS_FEATURE = 'bbot_keys'  # ``info.features`` entry of a Sentinel client that handles a discovery's keys (sentinel_settings.FEATURES)
# Why a Sentinel is not sent a project's discovery keys, and the plain sentence for it (the Sentinel's name is added by the caller where it helps).
KEYS_REASONS = {
    'keys_setting_off': 'this project has discovery API keys, and your Sentinels are set not to receive them (Settings, Discovery API keys: \"Send discovery API keys to my Sentinels\" is off)',
    'keys_sentinel_opt_out': 'this project has discovery API keys, and the Sentinel is set not to receive them (its settings turn sending discovery API keys off)',
    'keys_client_outdated': 'this project has discovery API keys, and the Sentinel is too old to receive them safely (update it: it must report the bbot_keys feature)',
}


def keys_enabled():
    """The instance setting \"Send discovery API keys to my Sentinels\" (a tunable, on unless an App Admin or the environment turned it off)."""
    from cveFeed import tunables
    return bool(tunables.value('sentinel_bbot_keys', 1))


def key_delivery_decision(eff, kind, ref, project_id):
    """THE one gate for a discovery's key material, used wherever a task that carries a reference to it is offered, claimed or read (the claim, the refusal, the
    secure read, the capacity answer, the explanation). ``(True, '')`` when ``eff`` (the rights of one Sentinel, ``sentinel_broker.SentinelEff``) may be sent the
    keys ``ref`` names for a task of ``kind`` in project ``project_id``, else ``(False, reason)``. Key material goes only for a ``bbot_discovery`` task whose reference
    is ``bbotkeys:<its own project's id>``: any other kind, any other reference (a stored sign-in included) or another project's keys is refused here, for every
    Sentinel. Then the built-in scanner (its image reads secrets) is always fine; any other Sentinel needs, all of: an active, unrevoked Sentinel token (``eff.problem``
    empty), the project in its scope (checked by ``refusal`` first), ``info.features`` naming ``bbot_keys``, the instance setting on, and its own opt-out off."""
    if kind != KIND:
        return False, 'keys_wrong_kind'
    ref_project = keys_ref_project(ref)
    if ref_project is None or ref_project != project_id:
        return False, 'keys_wrong_project'
    if eff.problem:
        return False, 'keys_sentinel_unusable'
    if eff.builtin:
        return (True, '') if eff.reads_secrets else (False, 'keys_client_outdated')
    if not keys_enabled():
        return False, 'keys_setting_off'
    from agentapi import sentinel_settings
    if sentinel_settings.discovery_keys_opt_out(eff.agent):
        return False, 'keys_sentinel_opt_out'
    if KEYS_FEATURE not in ((eff.agent.info or {}).get('features') or []):
        return False, 'keys_client_outdated'  # an older client never says it: it is never sent a key
    token = eff.agent.token
    if token.revoked or token.read_only or token.scope != 'sentinel':
        return False, 'keys_sentinel_unusable'
    return True, ''


def provider_names(config):
    """The module (provider) names in a keys payload, never an option or a value: for the audit row."""
    return sorted(m for m in ((config or {}).get('modules') or {}) if isinstance(m, str))


# --- the stage side: build the target, dispatch it, consume the batches ---------------------------------------------------------------

def mode_options(mode):
    """The presets, required flags and ``--force`` of a discovery mode, read from the server's own table (``reNgine.discovery_events.MODES``), so the scanner runs the
    choices the server makes for a local run."""
    from reNgine import discovery_events as bbot_lib
    cfg = bbot_lib.MODES.get(mode) or bbot_lib.MODES['passive']
    args = list(cfg['args'])
    flags = [args[i + 1] for i, a in enumerate(args[:-1]) if a == '-rf']
    flags = [f for part in flags for f in part.split(',') if f]
    return {'presets': list(cfg['presets']), 'require_flags': flags, 'force': '--force' in args}


def _bounty_out_of_scope(project_id, name):
    """``(names, ranges)``: what the project's bug bounty programs list as out of scope that a discovery could reach from ``name``: names (each with whether
    the entry covers its subdomains) at or under it, and addresses and ranges."""
    from cveFeed import bounty_scope
    from cveFeed.models import BountyEngagement
    names, ranges = [], []
    for engagement in BountyEngagement._base_manager.filter(project_id=project_id).select_related('program'):
        index = bounty_scope.ScopeIndex(engagement.program.assets.filter(removed_at__isnull=True))
        for host in index.out_domains:
            names.append((host, False))
        for host in index.out_wild:
            names.append((host, True))
        ranges += [f'{ip}/{32 if ":" not in ip else 128}' for ip in index.out_ips]
        ranges += [str(net) for net, _ in index.out_nets]
    under = [(h.lower().rstrip('.'), sub) for h, sub in names if h and (h.lower().rstrip('.') == name or h.lower().rstrip('.').endswith('.' + name))]
    return under, ranges


def scope_policy(domain):
    """The scope policy (``$defs/scope_policy``) of a discovery of ``domain``: the target as the one in-scope domain, the organization's exclusions
    and the bug bounty program's out-of-scope names at or under it, the project's internal ranges and the program's out-of-scope addresses as ranges
    never touched, and whether it is a bug bounty project."""
    from cveFeed.exclusions import excluded_names
    from cveFeed.models import BountyEngagement
    from targetApp.target_types import internal_networks
    name = domain.name.strip().lower().rstrip('.')
    excluded = excluded_names(domain.project_id)
    subtrees = getattr(excluded, 'subtrees', frozenset())
    rows = {h: h in subtrees for h in set(excluded) | set(subtrees) if h == name or h.endswith('.' + name)}
    bounty = bool(domain.project_id) and BountyEngagement._base_manager.filter(project_id=domain.project_id).exists()
    ranges = [str(net) for net in internal_networks(domain.project_id)] + [str(net) for net in getattr(excluded, 'networks', ())]  # the do-not-scan networks are never touched
    if bounty:
        out_names, out_ranges = _bounty_out_of_scope(domain.project_id, name)
        for host, subtree in out_names:
            rows[host] = rows.get(host, False) or subtree
        ranges += out_ranges
    exclusions = [{'host': h, 'subtree': rows[h]} for h in sorted(rows) if 0 < len(h) <= 253][:MAX_EXCLUSIONS]
    return {'in_scope_domains': [name], 'exact_host': domain.exact_host_only(), 'exclusions': exclusions,
            'deny_ranges': list(dict.fromkeys(r for r in ranges if len(r) <= 50))[:MAX_DENY_RANGES], 'bounty': bounty}


def bbot_target(domain, mode, timeout, api_keys=False, trufflehog=False):
    """The ``target`` of a ``bbot_discovery`` task for ``domain`` (``$defs/targets/bbot_discovery``): what the mode runs (presets,
    required flags, ``--force``, trufflehog excluded unless it may run, ``--strict-scope`` for a host-scoped target) and the scope it must keep to."""
    options = mode_options(mode)
    return {'domain': domain.name.strip().lower().rstrip('.'), 'mode': mode if mode in MODES else 'passive', **options,
            'exclude_modules': [] if trufflehog else ['trufflehog'], 'strict_scope': bool(domain.is_host_scoped()),
            'timeout_seconds': max(60, min(86400, int(timeout))), 'api_keys': bool(api_keys), 'trufflehog': bool(trufflehog),
            'scope': scope_policy(domain)}


POLL_SECONDS = 2.0  # between looks at a running stream: its batches come every few seconds, and a six hour run must not hammer the database


def _drain(task_id, consumed, on_partial):
    """Hand the stored batches after ``consumed`` to ``on_partial`` in order, deleting each once it is stored. Returns the last ``seq`` handed over."""
    while True:
        rows = list(SentinelPartial._base_manager.filter(task_id=task_id, seq__gt=consumed).order_by('seq')[:10])
        if not rows:
            return consumed
        for row in rows:
            if row.seq != consumed + 1:  # never happens: the broker takes them only in order
                logger.warning('sentinel task %s: batch %s arrived after %s; waiting for the missing one', task_id, row.seq, consumed)
                return consumed
            on_partial(row.body)
            consumed = row.seq
            SentinelPartial._base_manager.filter(pk=row.pk).delete()


def dispatch_stream(project, kind, target, scan, on_partial, label='', secret_ref=None, builtin_only=False, bbot_keys=False):
    """Send one streamed task to a Sentinel and consume its batches as they arrive, through ``on_partial(batch)``, until its final result.

    Returns ``{'result': <the final result>, 'consumed': n}`` when the task ended ``done``; ``{'result': None, 'consumed': n, 'error': why}`` when it ended
    otherwise after ``n`` > 0 batches (what they carried is real and was stored: the caller keeps it, as for a local run that stopped part way);
    ``ScannerUnavailable`` when no Sentinel did any of it (``sentinel_dispatch._no_local``: the kind never runs here, so the caller waits); ``None``
    only for internal work, which has no stage that waits. A stop of the scan, or a global pause,
    cancels the task and raises ``ScanAborted``; any error of ``on_partial`` cancels it too and is raised.

    ``bbot_keys``: the task carries a project's discovery API keys by reference (``secret_ref``): it goes to the built-in scanner or to a Sentinel the one gate
    (``key_delivery_decision``) allows, and with none the stage waits for a scanner with the plain reason.

    The waits are ``sentinel_dispatch``'s (claim, queue), and the run's own: its target's ``timeout_seconds`` plus ``REPORT_GRACE`` from the claim.
    A task of the same kind and scan that is still active (the queue gave a lost worker's pipeline to a new one) is ended first."""
    from agentapi import sentinel_broker, sentinel_dispatch
    from reNgine import resources
    if scan is not None:
        for old in SentinelTask._base_manager.filter(scan=scan, kind=kind, status__in=('queued', 'claimed', 'running')).select_related('project'):
            sentinel_broker.expire(old, 'a new run of the same scan took the work over')
    capacity = sentinel_broker.capacity_state(project, kind, why=True, builtin_only=builtin_only, bbot_keys=bbot_keys)
    if capacity['state'] == 'none':
        sentinel_dispatch._no_scanner(kind, project, capacity=capacity)
        return None
    timeout = int((target or {}).get('timeout_seconds') or sentinel_dispatch.COMPLETION_CEILING[kind]) + REPORT_GRACE
    work = sentinel_dispatch._Dispatch(project, kind, target, (target or {}).get('domain', ''), None, scan, timeout, None, 1, False, capacity,
                                       label=label or None, secret_ref=secret_ref)
    consumed = 0
    clock = sentinel_dispatch.time
    last_reap = last_stop = work.started
    try:
        while True:
            work.task.refresh_from_db()
            consumed = _drain(work.task.pk, consumed, on_partial)
            if work.finished:
                break
            now = clock.monotonic()
            if scan is not None and now - last_stop >= sentinel_dispatch.STOP_CHECK_EVERY:
                last_stop = now
                if sentinel_dispatch._stopped(scan):
                    raise resources.ScanAborted(f'{kind} was stopped with its scan')
            none_left = False
            if now - last_reap >= sentinel_dispatch.REAP_EVERY:
                sentinel_broker.reap_expired()
                last_reap = now
                none_left = work.task.status == 'queued' and sentinel_broker.capacity_state(
                    project, kind, builtin_only=builtin_only, bbot_keys=bbot_keys)['state'] == 'none'
            if work.step(now, none_left):
                break
            pause = work.pause(now) if work.run_deadline is None else min(POLL_SECONDS, max(0.0, work.run_deadline - now))
            clock.sleep(pause)
        work.task.refresh_from_db()
        consumed = _drain(work.task.pk, consumed, on_partial)  # what was posted before the end
        if work.task.status != 'done' and scan is not None and sentinel_dispatch._stopped(scan):
            raise resources.ScanAborted(f'{kind} was stopped with its scan')  # the broker ended it at a batch: a stop, not a Sentinel's failure
    except BaseException:
        work.cancel('the stage stopped before the task finished')
        raise
    work.settle()
    task = work.task
    if task.status == 'done':
        return {'result': task.result, 'consumed': consumed}
    if consumed:
        return {'result': None, 'consumed': consumed, 'error': (task.error or 'the Sentinel did not finish the run')[:290]}
    work.no_local()
    return None
