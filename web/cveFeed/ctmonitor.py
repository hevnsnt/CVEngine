"""Certificate Transparency monitoring: every target domain is "subscribed" to crt.sh so a certificate
issued for a new subdomain shows up here on its own, without waiting for the next active discovery pass.

This is purely passive: one read-only HTTPS GET to a public CT log aggregator per check, the same source
the discovery's own ``crt`` module uses. Nothing is sent to the target itself.

crt.sh is often slow or answers 502 and 429. When it cannot be reached after its polite attempts, or its shared pacing has kept every
lookup waiting for ``BUSY_FALLBACK_SECONDS``, the lookup asks Cert Spotter instead (``api.certspotter.com``, the source of the
discovery's ``certspotter`` module), under its own pacing, an hourly budget below its unauthenticated limit and a per-source circuit
(``CIRCUIT_FAILURES`` failed lookups in a row and a source is left alone for ``CIRCUIT_SECONDS``). The fallback is on by default;
Settings, Timings switches it off, and ``CVENGINE_CT_FALLBACK=0`` turns it off whatever the page says. A host the fallback found is
recorded with the module ``ct-monitor:certspotter``; a crt.sh find keeps ``ct-monitor``.
"""
import json
import logging
import os
import random
import re
import threading
import time

import requests

logger = logging.getLogger(__name__)

CRT_SH_URL = 'https://crt.sh/'
REQUEST_TIMEOUT = 45          # crt.sh is slow on big domains
MIN_GAP = (1.5, 2.5)          # seconds between lookups, across every worker: crt.sh blocks bursts
MAX_ATTEMPTS = 4
MAX_BYTES = 32 * 1024 * 1024  # a reply larger than this is refused unread: %.domain of a big target can be hundreds of MB
MAX_BACKOFF = 120             # never wait longer than this on one retry, whatever Retry-After says
MAX_NEW_PER_RUN = 200  # a cap, not a truncation of what gets recorded over time: the rest show up next run

CRTSH, CERTSPOTTER = 'crt.sh', 'certspotter'
EVENT_MODULE = {CRTSH: 'ct-monitor', CERTSPOTTER: 'ct-monitor:certspotter'}  # DiscoveryEvent.module of a host each source found
EVENT_MODULES = tuple(EVENT_MODULE.values())
CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances'
CERTSPOTTER_TIMEOUT = 30
CERTSPOTTER_GAP = (20.0, 30.0)  # seconds between Cert Spotter lookups, across every worker
CERTSPOTTER_MAX_IN_FLIGHT = 1
CERTSPOTTER_ATTEMPTS = 2
CERTSPOTTER_PER_HOUR = 8        # lookups an hour, across every worker: it answers X-RateLimit-Limit 10 an hour without an API key
BUSY_FALLBACK_SECONDS = 900     # crt.sh's pacing has held lookups this long with no success in between: ask the fallback instead of waiting more
CIRCUIT_FAILURES = 3            # failed lookups in a row after which a source is skipped ...
CIRCUIT_SECONDS = 600           # ... for this long
_LABEL = r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
_HOSTNAME_RE = re.compile(rf'^(\*\.)?({_LABEL}\.)+[a-z]{{2,63}}$')


def _clean_name(raw, domain):
    """One line of crt.sh's name_value -> a lowercase hostname under ``domain``, or None if unusable."""
    name = raw.strip().lower().rstrip('.')
    if name.startswith('*.'):
        name = name[2:]
    if not name or not _HOSTNAME_RE.match(name) and name != domain:
        return None
    if name != domain and not name.endswith(f'.{domain}'):
        return None  # crt.sh substring search can surface unrelated certs; keep only this domain's own tree
    return name


def parse_certspotter(issuances, domain):
    """``issuances`` is Cert Spotter's decoded JSON (a list of issuances, each with a ``dns_names`` list when asked with
    ``expand=dns_names``). Returns the deduplicated, in-scope hostnames, read exactly like crt.sh's."""
    names = set()
    for issuance in issuances if isinstance(issuances, list) else ():
        raw_names = issuance.get('dns_names') if isinstance(issuance, dict) else None
        for raw in raw_names if isinstance(raw_names, list) else ():
            name = _clean_name(str(raw), domain)
            if name:
                names.add(name)
    return names


def parse_ct_entries(entries, domain):
    """``entries`` is crt.sh's decoded JSON (a list of certs, each with a ``name_value`` of one or more
    newline-separated names). Returns the deduplicated, in-scope hostnames."""
    names = set()
    for entry in entries:
        for raw in str(entry.get('name_value', '')).splitlines():
            name = _clean_name(raw, domain)
            if name:
                names.add(name)
    return names


# --- politeness: one lookup at a time, spaced out, backing off when crt.sh says so ------------------------------------

_SLOT_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
local at = math.max(tonumber(ARGV[1]), nxt)
redis.call('SET', KEYS[1], at + tonumber(ARGV[2]), 'EX', 900)
return tostring(at)
"""
_PUSH_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
redis.call('SET', KEYS[1], math.max(nxt, tonumber(ARGV[1])), 'EX', 900)
return 1
"""
MAX_INLINE_WAIT = 30          # seconds a lookup may sleep inside a worker slot; a longer wait goes back to the queue (see ``CtBusy``)
MAX_IN_FLIGHT = 2             # requests to crt.sh under way at once, across every worker. The spacing above only spaces out the STARTS: with replies taking up to
#                               REQUEST_TIMEOUT seconds a dozen overlapped, crt.sh answered 429 or timed out, and every miss became a retry (an exception
#                               record built inside a greenlet: the classic lane crashed in the garbage collector doing exactly that, three times on 11/9 to 11/10)
_FLIGHT_KEY = 'cvengine:crtsh:inflight'
_FLIGHT_LUA = """
local n = tonumber(redis.call('GET', KEYS[1]) or '0')
if n >= tonumber(ARGV[1]) then return 0 end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return 1
"""
_LEAVE_LUA = """
local n = tonumber(redis.call('GET', KEYS[1]) or '0')
if n > 0 then redis.call('DECR', KEYS[1]) end
return 1
"""
_flight_local = {'n': 0}
_local = {'next': 0.0}
_local_lock = threading.Lock()
_SLOT_KEY = 'cvengine:crtsh:next'
# each source has its own shared pacing and in-flight count: a slow crt.sh never holds the fallback back, nor the other way round
_PACING = {CRTSH: {'slot': _SLOT_KEY, 'flight': _FLIGHT_KEY, 'local': _local, 'flight_local': _flight_local},
           CERTSPOTTER: {'slot': 'cvengine:certspotter:next', 'flight': 'cvengine:certspotter:inflight', 'local': {'next': 0.0},
                         'flight_local': {'n': 0}}}


def _max_in_flight(source):
    return MAX_IN_FLIGHT if source == CRTSH else CERTSPOTTER_MAX_IN_FLIGHT


def _redis():
    from reNgine import resources
    return getattr(resources.get_store(), 'r', None)


def reserve_slot(gap, now=time.time, source=CRTSH):
    """Seconds to wait before this lookup may go. Slots are handed out in order and ``gap`` apart, shared by every worker
    process when Redis is there, else per process."""
    pacing = _PACING[source]
    client = _redis()
    if client is not None:
        try:
            at = float(client.eval(_SLOT_LUA, 1, pacing['slot'], now(), gap))
            return max(0.0, at - now())
        except Exception:  # noqa: BLE001 - a Redis hiccup must not stop the monitor
            pass
    with _local_lock:
        local = pacing['local']
        at = max(now(), local['next'])
        local['next'] = at + gap
        return max(0.0, at - now())


class CtBusy(Exception):
    """crt.sh's shared pacing says every lookup must wait ``wait`` seconds. Sleeping that long inside a worker slot would hold the slot (hundreds
    of new targets queue hundreds of lookups behind one rate limit), so the lookup is put back on the queue for that long instead."""

    def __init__(self, wait, source=CRTSH):
        super().__init__(f'{source} pacing: next free slot in {wait:.0f}s')
        self.wait, self.source = wait, source


def wait_for_slot(now=time.time, source=CRTSH):
    """Seconds until the shared pacing would let another lookup go, without taking a slot."""
    pacing = _PACING[source]
    client = _redis()
    if client is not None:
        try:
            return max(0.0, float(client.get(pacing['slot']) or 0) - now())
        except Exception:  # noqa: BLE001 - a Redis hiccup must not stop the monitor
            pass
    with _local_lock:
        return max(0.0, pacing['local']['next'] - now())


def push_back(seconds, now=time.time, source=CRTSH):
    """Everyone waits at least this long before the next lookup (the source asked us to slow down)."""
    pacing = _PACING[source]
    until = now() + seconds
    client = _redis()
    if client is not None:
        try:
            client.eval(_PUSH_LUA, 1, pacing['slot'], until)
            return
        except Exception:  # noqa: BLE001
            pass
    with _local_lock:
        pacing['local']['next'] = max(pacing['local']['next'], until)


def _enter_flight(source=CRTSH):
    """True when a request may go now (fewer than ``MAX_IN_FLIGHT`` are under way). The count lives in Redis for every worker, and expires on its own so a
    worker that dies mid-request cannot hold a place for ever; without Redis it is counted per process."""
    pacing, limit = _PACING[source], _max_in_flight(source)
    client = _redis()
    if client is not None:
        try:
            return bool(client.eval(_FLIGHT_LUA, 1, pacing['flight'], limit, 2 * REQUEST_TIMEOUT))
        except Exception:  # noqa: BLE001 - a Redis hiccup must not stop the monitor
            pass
    with _local_lock:
        if pacing['flight_local']['n'] >= limit:
            return False
        pacing['flight_local']['n'] += 1
        return True


def _leave_flight(source=CRTSH):
    pacing = _PACING[source]
    client = _redis()
    if client is not None:
        try:
            client.eval(_LEAVE_LUA, 1, pacing['flight'])
            return
        except Exception:  # noqa: BLE001
            pass
    with _local_lock:
        pacing['flight_local']['n'] = max(0, pacing['flight_local']['n'] - 1)


class _Flight:
    """``with _Flight(sleep):`` holds one of the ``MAX_IN_FLIGHT`` places for the body, waiting up to ``MAX_INLINE_WAIT`` seconds for one; ``CtBusy`` when none
    came free (the lookup goes back to the queue and no worker slot is held meanwhile)."""

    def __init__(self, sleep, source=CRTSH):
        self.sleep, self.held, self.source = sleep, False, source

    def __enter__(self):
        for _ in range(int(MAX_INLINE_WAIT)):
            if _enter_flight(self.source):
                self.held = True
                return self
            self.sleep(1)
        raise CtBusy(10, self.source)

    def __exit__(self, *exc):
        if self.held:
            _leave_flight(self.source)
        return False


def _retry_after(resp):
    try:
        return min(float(resp.headers.get('Retry-After')), MAX_BACKOFF)
    except (TypeError, ValueError, AttributeError):
        return None


def _read_json(resp):
    """The decoded JSON of a streamed reply, read at most MAX_BYTES (ValueError above that or when it is not JSON)."""
    body, size = [], 0
    try:
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError(f'the reply is larger than {MAX_BYTES // (1024 * 1024)} MB')
            body.append(chunk)
    finally:
        resp.close()
    return json.loads(b''.join(body).decode('utf-8', 'replace') or '[]')


_why = threading.local()  # the reason of the last failed lookup in this thread (greenlet under gevent), for the health record


def _failed(reason):
    _why.text = str(reason)[:300]
    return None


def last_failure():
    return getattr(_why, 'text', '') or 'failed'


def _fetch(domain, timeout=REQUEST_TIMEOUT, sleep=time.sleep):
    """Entries for ``domain`` from crt.sh, or None when it could not be reached after several polite attempts. A shared provider
    domain (``jfrog.com``) is never queried: ``%.jfrog.com`` is every customer of the provider, not this target's tree."""
    from targetApp.shared_domains import is_provider_domain
    if is_provider_domain(domain):
        logger.info('crt.sh lookup for %s skipped: a shared provider domain, not an owned scope', domain)
        return []
    for attempt in range(MAX_ATTEMPTS):
        waiting = wait_for_slot()
        if waiting > MAX_INLINE_WAIT:  # before a slot is taken, so no reservation is left unused
            raise CtBusy(waiting)
        sleep(reserve_slot(random.uniform(*MIN_GAP)))
        last = attempt + 1 == MAX_ATTEMPTS
        with _Flight(sleep):
            try:
                resp = requests.get(CRT_SH_URL, params={'q': f'%.{domain}', 'output': 'json'}, timeout=timeout, stream=True)
            except requests.Timeout as exc:
                logger.warning('crt.sh lookup for %s timed out (attempt %s of %s): %s', domain, attempt + 1, MAX_ATTEMPTS, exc)
                if last:
                    return _failed(f'timed out after {MAX_ATTEMPTS} attempts')
                push_back(min(2 ** attempt * 5, MAX_BACKOFF))
                continue
            except requests.RequestException as exc:
                logger.warning('crt.sh lookup failed for %s: %s', domain, exc)
                return _failed(type(exc).__name__)
            status = resp.status_code if isinstance(getattr(resp, 'status_code', None), int) else 200
            if status == 429 or status >= 500:
                wait = _retry_after(resp) or min(2 ** attempt * 10, MAX_BACKOFF)
                logger.info('crt.sh answered %s for %s; backing off %.0fs (attempt %s of %s)', status, domain, wait, attempt + 1, MAX_ATTEMPTS)
                if last:
                    logger.warning('crt.sh lookup failed for %s: HTTP %s after %s attempts', domain, status, MAX_ATTEMPTS)
                    return _failed(f'HTTP {status} after {MAX_ATTEMPTS} attempts')
                push_back(wait)
                continue
            try:
                resp.raise_for_status()
                entries = _read_json(resp)
            except (requests.RequestException, ValueError, RecursionError) as exc:
                logger.warning('crt.sh lookup failed for %s: %s', domain, exc)
                return _failed(str(exc) or type(exc).__name__)
            return entries if isinstance(entries, list) else []
    return _failed('no attempt left')


def fetch_ct_names(domain, timeout=REQUEST_TIMEOUT):
    """Every hostname crt.sh has a certificate for under ``domain``. An empty set when crt.sh cannot be reached: a watcher
    that cannot reach it must not fail the discovery it is layered on top of."""
    entries = _fetch(domain, timeout)
    return set() if entries is None else parse_ct_entries(entries, domain)


# --- the fallback source and the per-source circuit -------------------------------------------------------------------------

def _cache():
    from django.core.cache import cache
    return cache


def fallback_enabled():
    """Whether a lookup crt.sh could not answer may ask Cert Spotter: ``CVENGINE_CT_FALLBACK`` off (``0``, ``false``, ``no``, ``off``) turns it off
    whatever the page says; else Settings, Timings (on by default)."""
    if os.environ.get('CVENGINE_CT_FALLBACK', '').strip().lower() in ('0', 'false', 'no', 'off'):
        return False
    try:
        from dashboard.models import SystemTimings
        return bool(SystemTimings.current().ct_fallback_source)
    except Exception:  # noqa: BLE001 - a settings read problem keeps the default
        return True


def circuit_open(source):
    """True while ``source`` is skipped after ``CIRCUIT_FAILURES`` failed lookups in a row (shared by every worker through the cache)."""
    try:
        return bool(_cache().get(f'cvengine:ct:circuit:{source}:open'))
    except Exception:  # noqa: BLE001
        return False


def _circuit_result(source, ok):
    """Count a lookup of ``source``: a success closes the circuit, the ``CIRCUIT_FAILURES``th failure in a row opens it for ``CIRCUIT_SECONDS``."""
    cache, fails = _cache(), f'cvengine:ct:circuit:{source}:fails'
    try:
        if ok:
            cache.delete_many([fails, f'cvengine:ct:circuit:{source}:open'])
            return
        cache.add(fails, 0, 3600)
        if cache.incr(fails) >= CIRCUIT_FAILURES:
            cache.set(f'cvengine:ct:circuit:{source}:open', time.time() + CIRCUIT_SECONDS, CIRCUIT_SECONDS)
            cache.delete(fails)
            logger.warning('ct watch: %s failed %s lookups in a row; it is skipped for %s seconds', source, CIRCUIT_FAILURES, CIRCUIT_SECONDS)
    except Exception:  # noqa: BLE001 - the circuit is an optimisation, never a reason to fail a lookup
        pass


_BUSY_KEY = 'cvengine:ct:busy-since:'


def _busy_too_long(source, now=time.time):
    """Note that ``source``'s pacing held a lookup back; True when it has done so for ``BUSY_FALLBACK_SECONDS`` with no success in between."""
    try:
        cache = _cache()
        cache.add(_BUSY_KEY + source, now(), 2 * BUSY_FALLBACK_SECONDS)
        since = float(cache.get(_BUSY_KEY + source) or now())
        return now() - since >= BUSY_FALLBACK_SECONDS
    except Exception:  # noqa: BLE001
        return False


def _not_busy(source):
    try:
        _cache().delete(_BUSY_KEY + source)
    except Exception:  # noqa: BLE001
        pass


def _take_certspotter_budget(now=time.time):
    """Seconds to wait when this hour's Cert Spotter budget (``CERTSPOTTER_PER_HOUR``, every worker together) is used up, else 0 and one is taken."""
    hour = int(now() // 3600)
    key = f'cvengine:certspotter:hour:{hour}'
    try:
        cache = _cache()
        cache.add(key, 0, 3700)
        if cache.incr(key) <= CERTSPOTTER_PER_HOUR:
            return 0
    except Exception:  # noqa: BLE001 - without the cache the pacing alone keeps it polite
        return 0
    return (hour + 1) * 3600 - now()


def _spend_certspotter_budget(now=time.time):
    """Cert Spotter said this hour's limit is used up (``X-RateLimit-Remaining: 0``): no more lookups this hour, from any worker."""
    try:
        _cache().set(f'cvengine:certspotter:hour:{int(now() // 3600)}', CERTSPOTTER_PER_HOUR + 1, 3700)
    except Exception:  # noqa: BLE001
        pass


def _fetch_certspotter(domain, timeout=CERTSPOTTER_TIMEOUT, sleep=time.sleep):
    """In-scope names Cert Spotter has a certificate for under ``domain`` (its newest page of issuances: every page is one query of a small
    hourly budget), or None when it could not be reached. ``CtBusy`` when its pacing or this hour's budget says wait. A shared provider domain
    is never queried. Nothing is sent to the target."""
    from targetApp.shared_domains import is_provider_domain
    if is_provider_domain(domain):
        return set()
    for attempt in range(CERTSPOTTER_ATTEMPTS):
        waiting = wait_for_slot(source=CERTSPOTTER)
        if waiting > MAX_INLINE_WAIT:
            raise CtBusy(waiting, CERTSPOTTER)
        budget_wait = _take_certspotter_budget()
        if budget_wait:
            raise CtBusy(budget_wait, CERTSPOTTER)
        sleep(reserve_slot(random.uniform(*CERTSPOTTER_GAP), source=CERTSPOTTER))
        last = attempt + 1 == CERTSPOTTER_ATTEMPTS
        with _Flight(sleep, CERTSPOTTER):
            try:
                resp = requests.get(CERTSPOTTER_URL, params={'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'},
                                    timeout=timeout, stream=True)
            except requests.Timeout:
                logger.warning('Cert Spotter lookup for %s timed out (attempt %s of %s)', domain, attempt + 1, CERTSPOTTER_ATTEMPTS)
                if last:
                    return _failed(f'timed out after {CERTSPOTTER_ATTEMPTS} attempts')
                push_back(30, source=CERTSPOTTER)
                continue
            except requests.RequestException as exc:
                logger.warning('Cert Spotter lookup failed for %s: %s', domain, exc)
                return _failed(type(exc).__name__)
            status = resp.status_code if isinstance(getattr(resp, 'status_code', None), int) else 200
            headers = getattr(resp, 'headers', None) or {}
            if str(headers.get('X-RateLimit-Remaining', '')).strip() == '0':
                _spend_certspotter_budget()
            if status == 429:  # its hourly limit: no retry, everyone waits it out
                wait = _retry_after(resp) or MAX_BACKOFF
                push_back(wait, source=CERTSPOTTER)
                _spend_certspotter_budget()
                resp.close()
                logger.warning('Cert Spotter answered 429 for %s; backing off %.0fs', domain, wait)
                return _failed('HTTP 429 (rate limited)')
            if status >= 500:
                wait = _retry_after(resp) or min(2 ** attempt * 10, MAX_BACKOFF)
                resp.close()
                logger.info('Cert Spotter answered %s for %s; backing off %.0fs (attempt %s of %s)', status, domain, wait, attempt + 1, CERTSPOTTER_ATTEMPTS)
                if last:
                    return _failed(f'HTTP {status} after {CERTSPOTTER_ATTEMPTS} attempts')
                push_back(wait, source=CERTSPOTTER)
                continue
            try:
                resp.raise_for_status()
                issuances = _read_json(resp)
            except (requests.RequestException, ValueError, RecursionError) as exc:
                logger.warning('Cert Spotter lookup failed for %s: %s', domain, exc)
                return _failed(str(exc) or type(exc).__name__)
            return parse_certspotter(issuances, domain)
    return _failed('no attempt left')


def _note(source, outcome, domain, names=0, new=0, error=''):
    """One lookup outcome of one source: ``ok`` (with the names it gave and the hosts that were new), ``failed`` or ``busy``. Logged, so a
    working monitor is visible in the worker log too."""
    if outcome == 'ok':
        logger.info('ct watch: %s answered for %s: %s name(s), %s new host(s)', source, domain, names, new)
    elif outcome == 'failed':
        logger.info('ct watch: %s lookup for %s failed: %s', source, domain, error)


def lookup(domain, sleep=None):
    """``(names, source)`` for ``domain``: crt.sh first, Cert Spotter when crt.sh could not answer (and the fallback is on), or None when no
    source could (a failure, as before the fallback). ``CtBusy`` when the lookup should be asked again later with no worker slot held."""
    sleep = sleep or time.sleep
    use_fallback = fallback_enabled()
    crt_busy = None
    # a crt.sh whose circuit is open is skipped only when the fallback can take the lookup; otherwise it is asked as always
    if use_fallback and circuit_open(CRTSH) and not circuit_open(CERTSPOTTER):
        crt_state = 'skipped'
    else:
        try:
            entries = _fetch(domain, sleep=sleep)
        except CtBusy as busy:
            _note(CRTSH, 'busy', domain)
            if not (use_fallback and _busy_too_long(CRTSH)) or circuit_open(CERTSPOTTER):
                raise
            crt_busy, crt_state = busy, 'busy'
        else:
            if entries is not None:
                _circuit_result(CRTSH, True)
                _not_busy(CRTSH)
                return parse_ct_entries(entries, domain), CRTSH
            _circuit_result(CRTSH, False)
            _note(CRTSH, 'failed', domain, error=last_failure())
            if not use_fallback or circuit_open(CERTSPOTTER):
                return None
            crt_state = 'failed'
    try:
        names = _fetch_certspotter(domain, sleep=sleep)
    except CtBusy as busy:
        _note(CERTSPOTTER, 'busy', domain)
        if crt_state == 'failed':
            return None  # crt.sh really failed and the fallback cannot be asked now: a failure, exactly as without it
        raise crt_busy or busy
    if names is None:
        _circuit_result(CERTSPOTTER, False)
        _note(CERTSPOTTER, 'failed', domain, error=last_failure())
        if crt_busy is not None:
            raise crt_busy  # crt.sh was only busy: it is asked again when its slot is due, as without the fallback
        return None
    _circuit_result(CERTSPOTTER, True)
    return names, CERTSPOTTER


def run_ct_watch(domain_id, fetch=fetch_ct_names):
    """Check one target's certificate history for hosts CVEngine does not already know about."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    if domain.exact_host_only():  # added as exactly this host (=example.com): no name under it would be taken, so crt.sh is not asked
        return {'checked': 0, 'new': 0, 'skipped': 'exact host'}
    known = set(Subdomain.objects.filter(target_domain=domain).values_list('name', flat=True))
    source = CRTSH
    if fetch is fetch_ct_names:  # the real lookup: tell "unreachable" apart from "nothing found" so the task can try again later
        answer = lookup(domain.name)
        if answer is None:
            return {'checked': 0, 'new': 0, 'failed': True}
        found, source = answer
    else:
        found = fetch(domain.name)
    out = _store(domain, found, known, source)
    if fetch is fetch_ct_names:
        _note(source, 'ok', domain.name, names=out['checked'], new=out['new'])
    if source != CRTSH:
        out['source'] = source
    return out


def _store(domain, found, known, source):
    """Record the names of ``found`` not already ``known`` as hosts of ``domain``, with a discovery event naming ``source``."""
    from django.utils import timezone

    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Subdomain
    from targetApp.models import Domain

    from cveFeed import ledger
    ledger.record('ct-watch', [domain.name], domain.project_id)  # the sweep skips targets checked in the last 24 hours
    from cveFeed.exclusions import drop_excluded
    new_names = drop_excluded(domain.project_id, sorted(found - known), names_only=True)[:MAX_NEW_PER_RUN]  # an excluded host is never re-created
    if not new_names:
        return {'checked': len(found), 'new': 0}
    created = []
    for name in new_names:
        sub, was_created = get_or_create_first(
            Subdomain, target_domain=domain, name=name,
            defaults={'is_imported_subdomain': True, 'discovered_date': timezone.now()})
        if was_created:
            created.append(sub)
            DiscoveryEvent.objects.create(scan=None, domain=domain, type='DNS_NAME', label=name, host=name,
                                          parent_host=domain.name, module=EVENT_MODULE[source])
    if created:
        from cveFeed.bounty_gate import Gate
        gate = Gate()  # a bug bounty project is recorded but not scanned on its own: not before its owner confirmed automated testing, not outside the program's scope
        to_scan = [s.name for s in created if gate.allows(domain.project_id, s.name)]
        if domain.discovery_mode in (Domain.DISCOVERY_MANUAL, Domain.DISCOVERY_PASSIVE):  # "just add it, do not scan yet" or public sources only: the names are recorded, nothing connects to them
            to_scan = []
        try:  # the new hosts get fingerprinted and checked now, not at the next full discovery
            from cveFeed.tasks import host_pipeline
            if to_scan:
                host_pipeline.delay(domain.id, to_scan)
        except Exception:  # noqa: BLE001 - a queue problem must not lose the finds, which are already recorded
            logger.exception('could not queue the pipeline for %s new host(s) of %s', len(created), domain.name)
        activity.log('discovery', (
            f'Certificate transparency: {len(created)} new host{"s" if len(created) != 1 else ""} for {domain.name} '
            f'({", ".join(s.name for s in created[:3])}{", ..." if len(created) > 3 else ""})'
            + ('' if source == CRTSH else f' (found by {source}, crt.sh could not answer)')),
            project=domain.project_id)
    return {'checked': len(found), 'new': len(created)}
