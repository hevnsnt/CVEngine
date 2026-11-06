"""Outbound connections from THIS server's own probes: count them, pace the ports a hosting provider watches, and say so.

A cloud VPS provider (Contabo, AWS, GCP, Azure, DigitalOcean, Hetzner and others) watches the outbound connections of a server, port 25 above
all: a burst of SYNs to port 25 on many addresses looks like a spam bot, and the provider warns, throttles or blocks the port. cvENGINE's
port and TLS scanners run on Sentinels, which this module never changes (they run on other networks, and the dispatch payloads they receive are
untouched); what still leaves this server directly is its own in-process probes and the few tools that have no scanner kind yet. This module is the
server-side safeguard for those.

Four parts, all state in Redis (no table, no migration):

* **The egress ledger** (``record``, ``snapshot``): new outbound TCP connection attempts from this server, per hour, kept for seven days.
  Counted per watched port (``CVENGINE_LOCAL_WATCH_PORTS``, default 25, 465, 587, 23, 3389) and in total for every port, and per source (the
  scan kind and the project) for the watched ports. In-process probes (``cveFeed.pinned_transport``, the database checks) are counted exactly,
  one per connection attempt. The external scanners are black boxes: they are counted from their probe plan (one attempt per
  address and port in the plan, before retries), so those numbers are an estimate, said so on every surface that shows them.
* **The connection log** (``log_connections``, ``connection_log``, ``connection_log_csv``): one record per outbound connection this server
  opens (or holds back) to a logged port (the app's own mail through Settings, Email is not a scan and is not logged) (``CVENGINE_EGRESS_LOG_PORTS``,
  default 25, 465, 587): time, destination address and port, sent, paced or skipped, the tool, project and scan, and whether the record is exact (this
  process opened, or refused to open, that very connection) or estimated (an external tool was handed that address and port). A Redis stream, kept
  14 days and at most 200,000 records (``CVENGINE_EGRESS_LOG_DAYS``, ``CVENGINE_EGRESS_LOG_MAX``), the oldest dropped first; App Admins read it
  over REST and MCP (``agentapi.egress``) or as CSV.
* **The governor** (``take``, ``admit_one``): a shared sliding window per budgeted port (``CVENGINE_LOCAL_PORT_BUDGETS``,
  default ``25:400/hour``; the port-25 number is also on Settings, configMaxxing): never more than the budget granted in any 60 minutes, and
  never more than a quarter of it in any 15, or a single whole run larger than that quarter and nothing else (such a run is granted only into 15
  minutes that hold nothing else, and nothing else is granted in the 15 after it; one that has waited ALONE_PRIORITY_AFTER gets priority over
  ordinary grants). Single targets that share a run are admitted least recently admitted first (``last_admitted``). One window on the Redis server's clock, shared
  by every worker. A connection the window has no room for is not made.
* **The fallback cap** (``admit_fallback``, ``note_fallback``): how many stage runs in each UTC clock hour may fall back from a Sentinel to local
  execution. A warning in the activity log and a problem in ``get_system_status`` say when tasks keep falling back, and name the Sentinels that
  are offline or full.
* **The opt-in skip list** (``CVENGINE_LOCAL_SKIP_PORTS``, default empty): ports this server never connects to at all. The version probes and
  validation checks on them are not run here, and in-process connections to them are refused. A Sentinel still scans them.

Every function here fails open: when Redis cannot be read, the scan runs as it did before this module existed (a server whose Redis is down has
no broker either, so nothing is being dispatched).
"""
import contextlib
import contextvars
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

DEFAULT_WATCH = '25,465,587,23,3389'
DEFAULT_BUDGETS = '25:400/hour'
DEFAULT_PORT25_PER_HOUR = 400  # the configMaxxing tunable's default; equal to the 25 entry of DEFAULT_BUDGETS
DEFAULT_FALLBACK_NMAP_PER_HOUR = 30
DEFAULT_FALLBACK_NAABU_PER_HOUR = 10
HOUR = 3600
KEEP_HOURS = 7 * 24  # the ledger's window
BUCKET_TTL = (KEEP_HOURS + 2) * HOUR
BURST_SHARE = 4  # at most a quarter of an hour's budget in any 15 minutes: an hour's allowance is never spent in one burst
# A whole run on port 25 larger than the 15-minute quarter needs 15 minutes with no other port-25 start. One that has waited this long
# for them gets priority: ordinary port-25 grants are held (paced: owed or due) until it starts, which the window then allows within another
# 61 minutes at most. The mark lapses ALONE_WAIT_TTL seconds after the run last asked.
ALONE_PRIORITY_AFTER = 60 * 60
ALONE_WAIT_TTL = 10 * 60
ALERT_STEPS = (50, 80, 100)  # percent of a port's hourly budget at which the activity log says so, once per hour
FALLBACK_WARN_AT = 5  # Sentinel tasks falling back to local execution in one hour before the warning and the system problem
PREFIX = 'cvengine:egress'
SKIP_REASON = 'CVENGINE_LOCAL_SKIP_PORTS'

_context = contextvars.ContextVar('cvengine_local_egress', default=None)


class PortHeld(OSError):
    """A local connection to ``port`` was not made: it is on the skip list (``reason='skipped'``) or its budget is used up this hour
    (``reason='paced'``). An OSError, so every caller that treats a refused connection as "not reachable this time" already handles it."""

    def __init__(self, port, reason):
        self.port, self.reason = int(port), reason
        super().__init__(held_text(self.port, reason))


def held_text(port, reason):
    if reason == 'skipped':
        return f'skipped on the server: port {port} ({SKIP_REASON}); a Sentinel does this'
    return f'port {port} paced on the server: its hourly budget is used up; it is probed later'


# --- settings ---------------------------------------------------------------------------------------------------------

def parse_ports(text):
    """``"25, 465-466, junk"`` -> ``frozenset({25, 465, 466})``. Whitespace is ignored, a range may be written either way round, anything that is
    not a port or a range of ports is skipped (never an error: this guards a scan, it must not stop one). Empty -> nothing."""
    out = set()
    for part in str(text or '').replace(';', ',').split(','):
        part = part.strip()
        match = re.fullmatch(r'(\d{1,5})\s*(?:-\s*(\d{1,5}))?', part)
        if not match:
            continue
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        low, high = min(low, high), max(low, high)
        if low < 1 or high > 65535:
            continue
        out.update(range(low, high + 1))
    return frozenset(out)


def parse_budgets(text):
    """``"25:400/hour, 587:100/h, 465:50"`` -> ``{25: 400, 587: 100, 465: 50}`` (new connections per hour). ``0``, an empty value or a port with
    budget 0 means no budget (that port is not paced). Anything else that does not parse is skipped."""
    out = {}
    for part in str(text or '').replace(';', ',').split(','):
        match = re.fullmatch(r'\s*(\d{1,5})\s*:\s*(\d{1,9})\s*(?:/\s*(?:h|hr|hour)s?)?\s*', part, re.IGNORECASE)
        if not match:
            continue
        port, per_hour = int(match.group(1)), int(match.group(2))
        if 1 <= port <= 65535 and per_hour > 0:
            out[port] = per_hour
    return out


def skipped_ports(environ=None):
    """The opt-in skip list (``CVENGINE_LOCAL_SKIP_PORTS``): empty by default, so every local run is exactly as before."""
    return parse_ports((environ if environ is not None else os.environ).get('CVENGINE_LOCAL_SKIP_PORTS', ''))


def budgets(environ=None):
    """``{port: connections per hour}`` the governor paces. ``CVENGINE_LOCAL_PORT_BUDGETS`` (default ``25:400/hour``; empty or ``0`` turns
    pacing off), with the port-25 number taken from Settings, configMaxxing (tunable ``egress_port25_per_hour``, or
    ``CVENGINE_LOCAL_PORT25_PER_HOUR``) when one was set there (0 turns port 25's pacing off). A skipped port is not paced: it is not probed."""
    env = environ if environ is not None else os.environ
    raw = env.get('CVENGINE_LOCAL_PORT_BUDGETS')
    out = parse_budgets(DEFAULT_BUDGETS if raw is None else raw)
    try:
        from cveFeed import tunables
        got = tunables.resolve('egress_port25_per_hour') if environ is None else {'source': 'default'}
    except Exception:  # noqa: BLE001 - the saved copy cannot be read: the environment decides
        got = {'source': 'default'}
    if got['source'] in ('admin', 'environment', 'auto'):
        if got['value'] > 0:
            out[25] = int(got['value'])
        else:
            out.pop(25, None)
    skip = skipped_ports(env)
    return {port: n for port, n in out.items() if port not in skip}


def watched_ports(environ=None):
    """The ports the ledger counts one by one (and the system status shows): ``CVENGINE_LOCAL_WATCH_PORTS`` (default 25, 465, 587, 23, 3389),
    plus every budgeted and skipped port."""
    env = environ if environ is not None else os.environ
    raw = env.get('CVENGINE_LOCAL_WATCH_PORTS')
    return tuple(sorted(parse_ports(DEFAULT_WATCH if raw is None else raw) | set(budgets(environ)) | skipped_ports(env)))


def fallback_cap(kind):
    """Local fallback stage runs per hour for ``kind`` (nmap 30, naabu 10 by default; Settings, configMaxxing); 0 or None: unlimited."""
    defaults = {'nmap': ('fallback_nmap_per_hour', DEFAULT_FALLBACK_NMAP_PER_HOUR), 'naabu': ('fallback_naabu_per_hour', DEFAULT_FALLBACK_NAABU_PER_HOUR)}
    if kind not in defaults:
        return 0
    from cveFeed import tunables
    key, default = defaults[kind]
    return int(tunables.value(key, default))


# --- port lists on command lines --------------------------------------------------------------------------------------

# --- the run's context: who is scanning, for the ledger and for owed ports ------------------------------------------------

@contextlib.contextmanager
def context(kind=None, project=None, org_id=None, scan_id=None):
    """Name the stage that runs local tools inside this block, so their connections are counted against it and an owed port is probed later
    for the right organization. Nested blocks inherit what they do not name."""
    outer = _context.get() or {}
    project_id = getattr(project, 'pk', project)
    token = _context.set({'kind': kind or outer.get('kind'), 'project': project_id if project_id is not None else outer.get('project'),
                          'org_id': org_id if org_id is not None else outer.get('org_id'),
                          'scan_id': scan_id if scan_id is not None else outer.get('scan_id')})
    try:
        yield
    finally:
        _context.reset(token)


def current():
    return dict(_context.get() or {})


# --- Redis ------------------------------------------------------------------------------------------------------------

def _client():
    try:
        from reNgine import resources
        return resources.redis_client()
    except Exception:  # noqa: BLE001
        return None


def _hour(now=None):
    return int((time.time() if now is None else now) // HOUR)


# --- the ledger ---------------------------------------------------------------------------------------------------------

def record(kind, total, per_port=None, project=None, now=None):
    """Count ``total`` new outbound TCP connection attempts by ``kind`` (``per_port``: ``{port: n}`` of them, kept for the watched ports).
    Never raises."""
    total = int(total or 0)
    if total <= 0:
        return
    ctx = current()
    kind = kind or ctx.get('kind') or 'local'
    project = project if project is not None else ctx.get('project')
    watch = set(watched_ports())
    hour = _hour(now)
    try:
        client = _client()
        if client is None:
            return
        pipe = client.pipeline()
        conn, src = f'{PREFIX}:conn:{hour}', f'{PREFIX}:src:{hour}'
        pipe.hincrby(conn, 'all', total)
        pipe.hincrby(src, f'{kind}|{project or "-"}|all', total)
        for port, n in (per_port or {}).items():
            if int(port) in watch and int(n) > 0:
                pipe.hincrby(conn, f'p{int(port)}', int(n))
                pipe.hincrby(src, f'{kind}|{project or "-"}|{int(port)}', int(n))
        pipe.expire(conn, BUCKET_TTL)
        pipe.expire(src, BUCKET_TTL)
        pipe.execute()
    except Exception:  # noqa: BLE001 - counting must never stop a scan
        logger.debug('egress ledger: could not count %s connections', kind, exc_info=False)


def record_one(port, kind=None, project=None, address=None):
    """One in-process connection attempt to ``port`` (logged exactly, with ``address``, when the port is a logged one)."""
    kind = kind or current().get('kind') or 'in-process'
    record(kind, 1, {int(port): 1}, project=project)
    if address:
        log_connections([address], [port], kind, mode=EXACT, project=project)


# --- the connection log: one record per connection (or planned probe) to a logged port --------------------------------------

EXACT, ESTIMATED = 'exact', 'estimated'
SENT, PACED, SKIPPED = 'sent', 'paced', 'skipped'
DEFAULT_LOG_PORTS = '25,465,587'
DEFAULT_LOG_DAYS = 14
DEFAULT_LOG_MAX = 200_000
LOG_KEY = f'{PREFIX}:log'
LOG_FIELDS = ('at', 'address', 'port', 'mode', 'outcome', 'kind', 'project', 'scan_id')


def log_ports(environ=None):
    """The ports every local connection to is logged one by one (``CVENGINE_EGRESS_LOG_PORTS``, default 25, 465, 587)."""
    env = environ if environ is not None else os.environ
    raw = env.get('CVENGINE_EGRESS_LOG_PORTS')
    return parse_ports(DEFAULT_LOG_PORTS if raw is None else raw)


def _env_int(name, default, low, high):
    try:
        return min(high, max(low, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def log_days():
    """Days a record is kept (``CVENGINE_EGRESS_LOG_DAYS``, default 14, 1 to 365)."""
    return _env_int('CVENGINE_EGRESS_LOG_DAYS', DEFAULT_LOG_DAYS, 1, 365)


def log_max():
    """Most records kept, the oldest dropped first (``CVENGINE_EGRESS_LOG_MAX``, default 200,000, 100 to 5,000,000)."""
    return _env_int('CVENGINE_EGRESS_LOG_MAX', DEFAULT_LOG_MAX, 100, 5_000_000)


def log_connections(addresses, ports, kind=None, mode=EXACT, outcome=SENT, project=None, scan_id=None, now=None):
    """One record per address and logged port: when, where to, which port, ``mode`` (``exact``: this process opened, or decided not to open,
    that very connection; ``estimated``: an external tool's probe plan named it, the tool itself is not watched), ``outcome`` (``sent``,
    ``paced``: held back by the budget and probed later, ``skipped``: on the opt-in skip list) and the source (scan kind, project, scan). Kept in a
    Redis stream, at most ``log_max()`` records and ``log_days()`` days, the oldest dropped first. Never raises."""
    ports = sorted({int(p) for p in ports or ()} & log_ports())
    addresses = [a for a in dict.fromkeys(addresses or ()) if a]
    if not ports or not addresses:
        return 0
    ctx = current()
    project = project if project is not None else ctx.get('project')
    scan_id = scan_id if scan_id is not None else ctx.get('scan_id')
    kind = kind or ctx.get('kind') or 'local'
    client = _client()
    if client is None:
        return 0
    entry_id = '*' if now is None else f'{int(now * 1000)}-*'  # the Redis server's clock, so workers whose clocks differ never collide
    now = time.time() if now is None else now
    try:
        pipe = client.pipeline()
        n = 0
        for address in addresses:
            for port in ports:
                fields = {'address': str(address)[:255], 'port': port, 'mode': mode, 'outcome': outcome, 'kind': str(kind)[:40],
                          'project': '' if project is None else str(project), 'scan_id': '' if scan_id is None else str(scan_id)}
                pipe.xadd(LOG_KEY, fields, id=entry_id, maxlen=log_max(), approximate=False)
                n += 1
        pipe.xtrim(LOG_KEY, minid=str(int((now - log_days() * 86400) * 1000)), approximate=False)
        pipe.execute()
        return n
    except Exception:  # noqa: BLE001 - the log must never stop a scan
        logger.debug('egress log: could not write %s record(s)', len(addresses) * len(ports), exc_info=False)
        return 0


def _record_of(entry_id, fields):
    from datetime import datetime
    from datetime import timezone as tz
    millis = int(str(entry_id).split('-')[0])
    return {'id': entry_id, 'at': datetime.fromtimestamp(millis / 1000, tz.utc).isoformat().replace('+00:00', 'Z'),
            'address': fields.get('address', ''), 'port': int(fields.get('port') or 0), 'mode': fields.get('mode', ''),
            'outcome': fields.get('outcome', ''), 'kind': fields.get('kind', ''),
            'project': int(fields['project']) if str(fields.get('project') or '').isdigit() else None,
            'scan_id': int(fields['scan_id']) if str(fields.get('scan_id') or '').isdigit() else None}


def connection_log(port=None, project=None, since=None, until=None, limit=100, cursor=None, scan_cap=50_000):
    """A page of the connection log, newest first: ``{'records': [...], 'next': cursor or None, 'kept_days', 'kept_max'}``. Filters: ``port``,
    ``project`` (id), ``since`` / ``until`` (epoch seconds). ``cursor`` is the ``next`` of the previous page. At most ``scan_cap`` records are
    read for one page, so a filter that matches little cannot make one call read the whole log (``next`` then continues from there)."""
    limit = max(1, min(int(limit or 100), 1000))
    client = _client()
    out = {'records': [], 'next': None, 'kept_days': log_days(), 'kept_max': log_max()}
    if client is None:
        return out
    high = f'({cursor}' if cursor else (str(int(until * 1000)) if until is not None else '+')
    low = str(int(since * 1000)) if since is not None else '-'
    read = 0
    try:
        while len(out['records']) < limit and read < scan_cap:
            batch = client.xrevrange(LOG_KEY, max=high, min=low, count=min(1000, scan_cap - read))
            if not batch:
                return out
            read += len(batch)
            for entry_id, fields in batch:
                high = f'({entry_id}'
                record = _record_of(entry_id, fields)
                if (port is None or record['port'] == int(port)) and (project is None or record['project'] == int(project)):
                    out['records'].append(record)
                    if len(out['records']) >= limit:
                        out['next'] = entry_id
                        return out
        out['next'] = high[1:] if read >= scan_cap and high.startswith('(') else None
    except Exception:  # noqa: BLE001
        logger.warning('egress log: could not be read', exc_info=False)
    return out


def connection_log_csv(port=None, project=None, since=None, until=None, project_names=None):
    """Every matching record (newest first) as CSV text, for a person to hand to a hosting provider. ``project_names`` maps ids to slugs."""
    import csv
    import io
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['time_utc', 'destination_address', 'destination_port', 'outcome', 'exact_or_estimated', 'tool', 'project', 'scan_id'])
    cursor = None
    while True:
        page = connection_log(port=port, project=project, since=since, until=until, limit=1000, cursor=cursor, scan_cap=log_max())
        for r in page['records']:
            name = (project_names or {}).get(r['project'], r['project'] if r['project'] is not None else '')
            writer.writerow([r['at'], r['address'], r['port'], r['outcome'], r['mode'], r['kind'], name, r['scan_id'] or ''])
        if not page['next']:
            return buffer.getvalue()
        cursor = page['next']


def snapshot(now=None, hours=24):
    """``{'hour': {...}, 'day': {...}, 'week': {...}}`` counts (``all`` and ``p<port>``) for the last hour, the last ``hours`` and seven days, and
    the top sources of the last 24 hours. Never raises (an unreadable ledger is ``None``)."""
    client = _client()
    if client is None:
        return None
    hour = _hour(now)
    try:
        pipe = client.pipeline()
        for h in range(hour - KEEP_HOURS + 1, hour + 1):
            pipe.hgetall(f'{PREFIX}:conn:{h}')
        rows = pipe.execute()
        pipe = client.pipeline()
        for h in range(hour - hours + 1, hour + 1):
            pipe.hgetall(f'{PREFIX}:src:{h}')
        sources = pipe.execute()
    except Exception:  # noqa: BLE001
        return None

    def add(rows_):
        out = {}
        for row in rows_:
            for key, value in (row or {}).items():
                out[key] = out.get(key, 0) + int(value)
        return out
    top = {}
    for row in sources:
        for key, value in (row or {}).items():
            top[key] = top.get(key, 0) + int(value)
    return {'hour': add(rows[-1:]), 'day': add(rows[-hours:]), 'week': add(rows), 'sources': top}


# --- the governor -------------------------------------------------------------------------------------------------------

# A sliding window over minute buckets: what was granted in the current minute and the 60 before it may never exceed the hourly budget, and
# what was granted in the current minute and the 15 before it never a quarter of it. Any 3600 seconds span at most 61 minute buckets (any 900
# seconds at most 16), so "never more than N in any hour, never more than N/4 in any 15 minutes" holds exactly, not just on average, and the
# whole budget stays usable hour after hour. ``whole`` grants all of ``want`` or nothing (one run can be many connections, not a few).
# ``alone`` (ARGV[7] = 0) is the one exception to the quarter: a whole run larger than the quarter (240 of 400, say) is granted
# only when nothing was granted in the current minute and the 15 before it, and then fills that quarter by itself, so nothing else is granted
# in the 15 minutes after it either: any 15 minutes hold at most a quarter of the budget, or that one run and nothing else.
_TAKE = """
local now = tonumber(ARGV[1])
if now < 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1])
end
local want = tonumber(ARGV[2])
local cap_hour = tonumber(ARGV[3])
local cap_burst = tonumber(ARGV[4])
local whole = tonumber(ARGV[5])
local use_burst = tonumber(ARGV[7])
local m = math.floor(now / 60)
local wait_key = ARGV[9]  -- a whole run waiting for its quiet 15 minutes: the time it first asked (see ALONE_PRIORITY_AFTER)
local dry = tonumber(ARGV[12])  -- 1: only say whether it would be granted (and keep the waiting mark), take nothing
-- refunds (ARGV[13] pairs of minute, count from ARGV[14]): grants made when a pass was planned, moved now to the minute its process starts
local nref = tonumber(ARGV[13] or '0')
for j = 0, nref - 1 do
  local rm = ARGV[14 + 2 * j]
  local cur = tonumber(redis.call('HGET', KEYS[1], rm) or '0')
  local back = math.min(cur, tonumber(ARGV[15 + 2 * j]))
  if back > 0 then
    if back == cur then redis.call('HDEL', KEYS[1], rm) else redis.call('HINCRBY', KEYS[1], rm, -back) end
    local uk = ARGV[8] .. tostring(math.floor(tonumber(rm) / 60))
    local u = tonumber(redis.call('GET', uk) or '0')
    if u > 0 then redis.call('DECRBY', uk, math.min(u, back)) end
  end
end
local rows = redis.call('HGETALL', KEYS[1])
local hour, burst = 0, 0
for i = 1, #rows, 2 do
  local k = tonumber(rows[i])
  local v = tonumber(rows[i + 1])
  if k <= m - 61 then
    redis.call('HDEL', KEYS[1], rows[i])
  elseif k <= m then
    hour = hour + v
    if k > m - 16 then burst = burst + v end
  end
end
local alone = use_burst == 0 and want > cap_burst
local grant = math.min(want, cap_hour - hour)
if not alone then
  grant = math.min(grant, cap_burst - burst)
  local since = redis.call('GET', wait_key)
  if since and now - tonumber(since) >= tonumber(ARGV[10]) then grant = 0 end  -- a run waiting that long has priority: held
elseif burst > 0 then
  grant = 0
end
if grant < 0 then grant = 0 end
if whole == 1 and grant < want then grant = 0 end
if alone then
  if grant > 0 then
    if dry == 0 then redis.call('DEL', wait_key) end
  else
    redis.call('SET', wait_key, tostring(now), 'NX')
    redis.call('EXPIRE', wait_key, tonumber(ARGV[11]))  -- lapses unless the run keeps asking
  end
end
local used_key = ARGV[8] .. tostring(math.floor(now / 3600))
if dry == 1 then
  return {grant, tonumber(redis.call('GET', used_key) or '0'), m}
end
if grant > 0 then
  redis.call('HINCRBY', KEYS[1], tostring(m), grant)
  redis.call('INCRBY', used_key, grant)
  redis.call('EXPIRE', used_key, tonumber(ARGV[6]))
end
redis.call('EXPIRE', KEYS[1], 7300)
return {grant, tonumber(redis.call('GET', used_key) or '0'), m}
"""


def bucket_size(per_hour):
    """The most new connections granted in any 15 minutes: a quarter of the hourly budget (at least one)."""
    return max(1, int(per_hour) // BURST_SHARE)


def take(port, want, now=None, whole=False, burst=True):
    return _take(port, want, now=now, whole=whole, burst=burst)[0]


def _take(port, want, now=None, whole=False, burst=True, refund=None, dry=False):
    """Up to ``want`` new connections to ``port`` (all or none with ``whole``): never more than the port's hourly budget in any 60 minutes, and
    never more than a quarter of it in any 15. ``burst=False`` (a whole run larger than the quarter, with ``whole``) lets a run larger than the quarter go, but
    only alone: when nothing was granted in its 15 minutes, and nothing else is then granted in the 15 after it. The window runs on the Redis
    server's clock (``now`` replaces it in tests), so workers whose clocks differ share one window. Returns how many were granted: ``want``
    for a port with no budget, and when Redis cannot be read (fail open).

    ``_take`` returns ``(granted, minute)``, the minute (on the window's clock) the grant was counted in, or None when nothing was counted.
    ``refund`` (``{minute: n}``) first takes back grants made earlier that were never used, in the same atomic step (see ``launch``)."""
    want = int(want)
    per_hour = budgets().get(int(port))
    if not per_hour or want <= 0:
        return max(0, want), None
    client = _client()
    if client is None:
        return want, None
    pairs = [x for minute, n in sorted((refund or {}).items()) if n > 0 for x in (int(minute), int(n))]
    try:
        grant, used, minute = client.eval(_TAKE, 1, f'{PREFIX}:window:{int(port)}', -1 if now is None else now, want, per_hour,
                                          bucket_size(per_hour), 1 if whole else 0, BUCKET_TTL, 1 if burst else 0,
                                          f'{PREFIX}:used:{int(port)}:', f'{PREFIX}:alone-waiting:{int(port)}', ALONE_PRIORITY_AFTER,
                                          ALONE_WAIT_TTL, 1 if dry else 0, len(pairs) // 2, *pairs)
    except Exception:  # noqa: BLE001 - a governor that cannot be read must not stop a scan: the run goes ahead as before
        logger.warning('egress governor: Redis could not be read; port %s is not paced for this run', port)
        return want, None
    if not dry:
        _alert(int(port), int(used), per_hour, int(grant), time.time() if now is None else now)
    return int(grant), int(minute)


def used_this_hour(port, now=None):
    client = _client()
    if client is None:
        return None
    try:
        return int(client.get(f'{PREFIX}:used:{int(port)}:{_hour(now)}') or 0)
    except Exception:  # noqa: BLE001
        return None


def _alert(port, used, per_hour, granted, now):
    """One activity line per hour as port ``port``'s use crosses 50, 80 and 100 percent of its budget."""
    if not granted and used < per_hour:
        return
    share = used * 100 // max(1, per_hour)
    client = _client()
    for step in ALERT_STEPS:
        if share < step:
            break
        try:
            if not client.set(f'{PREFIX}:alert:{port}:{_hour(now)}:{step}', '1', nx=True, ex=2 * HOUR):
                continue
        except Exception:  # noqa: BLE001
            return
        from cveFeed import activity
        activity.log('run_check', f'port {port}: {used} of its {per_hour} local connections this hour are used ({step}%)'
                     + ('; the rest are paced to the next hour' if step >= 100 else ''), project=current().get('project'))


ROTATION_DAYS = 30


def last_admitted(kind, targets):
    """``{target: time it was last admitted}`` for ``targets`` of ``kind`` (absent: never). Single targets that share a run
    are admitted oldest first by it, so none waits behind the same others run after run."""
    client = _client()
    targets = list(targets or ())
    if client is None or not targets:
        return {}
    try:
        values = client.hmget(f'{PREFIX}:rotation:{kind}', targets)
    except Exception:  # noqa: BLE001
        return {}
    return {t: float(v) for t, v in zip(targets, values) if v is not None}


def note_admitted(kind, targets):
    client = _client()
    targets = list(targets or ())
    if client is None or not targets:
        return
    at = launch_now()
    try:
        if at is None:
            seconds, micro = client.time()
            at = seconds + micro / 1e6
        key = f'{PREFIX}:rotation:{kind}'
        client.hset(key, mapping={t: at for t in targets})
        client.expire(key, ROTATION_DAYS * 86400)
    except Exception:  # noqa: BLE001
        pass


def launch_now():
    """The window's clock at a process start: None, the Redis server's clock (tests replace it)."""
    return None


def admit_one(port, kind=None, address=None, weight=1, now=None, burst=True):
    """For a single connection, or one run of a tool against one host and port (a probe, a validation check, a tool that counts as
    ``weight`` connections, all granted or none): ``None`` when it may go ahead, else the reason it is held (``'skipped'`` or ``'paced'``,
    logged with ``address`` when given). The caller counts what it then sends."""
    port = int(port)
    reason = None
    if port in skipped_ports():
        reason = SKIPPED
    elif port in budgets() and take(port, max(1, int(weight)), now=now, whole=True, burst=burst) < 1:
        reason = PACED
    if reason and address:
        log_connections([address], [port], kind, mode=EXACT, outcome=reason)
    return reason


def check_connect(port, kind=None, address=None):
    """The gate of an in-process connection: raises ``PortHeld`` for a skipped or paced port, otherwise counts (and logs) the attempt."""
    reason = admit_one(port, kind, address)
    if reason:
        raise PortHeld(port, reason)
    record_one(port, kind, address=address)


# --- the local fallback cap and its warning --------------------------------------------------------------------------------

def admit_fallback(kind, project=None, now=None):
    """Whether one more stage run of ``kind`` may fall back to local execution this hour (``fallback_cap``; 0 is unlimited). Over the cap the
    caller defers the work: the addresses stay due for the next run. Logs one line when it defers. Fails open."""
    cap = fallback_cap(kind)
    client = _client()
    if not cap or client is None:
        return True
    key = f'{PREFIX}:fallback-runs:{kind}:{_hour(now)}'
    try:
        n = client.incr(key)
        client.expire(key, 2 * HOUR)
    except Exception:  # noqa: BLE001
        return True
    if n <= cap:
        return True
    try:
        client.decr(key)
    except Exception:  # noqa: BLE001
        pass
    from cveFeed import activity
    activity.log('run_check', f'{kind} did not fall back to local execution: {cap} local fallback runs of {kind} this hour is the cap; '
                 'the addresses stay due for the next run. Check your Sentinels', project=project)
    return False


def fallback_runs_this_hour(kind, now=None):
    client = _client()
    if client is None:
        return None
    try:
        return int(client.get(f'{PREFIX}:fallback-runs:{kind}:{_hour(now)}') or 0)
    except Exception:  # noqa: BLE001
        return None


def note_fallback(kind, project=None, now=None):
    """Count one Sentinel task that fell back to local execution; at FALLBACK_WARN_AT in an hour, one warning names the Sentinels that are
    offline or full."""
    client = _client()
    if client is None:
        return
    minute = int((time.time() if now is None else now) // 60)
    try:
        pipe = client.pipeline()
        pipe.hincrby(FALLBACK_KEY, str(minute), 1)
        pipe.expire(FALLBACK_KEY, 2 * HOUR)
        pipe.execute()
        total = fallbacks_last_hour(now)
        # once per 60 minutes, however the clock hours fall
        if total < FALLBACK_WARN_AT or not client.set(f'{PREFIX}:fallback-warned', '1', nx=True, ex=HOUR):
            return
    except Exception:  # noqa: BLE001
        return
    from cveFeed import activity
    activity.log('run_check', fallback_warning(total), project=project, status='failed')


FALLBACK_KEY = f'{PREFIX}:fallbacks'  # minute -> stages or tasks that fell back to local execution in it


def fallbacks_last_hour(now=None):
    """Stages or Sentinel tasks that fell back to local execution in the last 60 minutes (a sliding window over minute buckets)."""
    client = _client()
    if client is None:
        return 0
    minute = int((time.time() if now is None else now) // 60)
    try:
        rows = client.hgetall(FALLBACK_KEY) or {}
    except Exception:  # noqa: BLE001
        return 0
    old = [k for k in rows if not str(k).lstrip('-').isdigit() or int(k) <= minute - 120]
    if old:
        try:
            client.hdel(FALLBACK_KEY, *old)
        except Exception:  # noqa: BLE001
            pass
    return sum(int(v) for k, v in rows.items() if k not in old and minute - 60 < int(k) <= minute)


def sentinel_trouble():
    """``{'offline': [names], 'full': [names]}``: the active Sentinels that are not heartbeating, and the live ones at their concurrency limit."""
    from agentapi.models import SENTINEL_ACTIVE_STATUSES, Agent, SentinelTask
    from agentapi.sentinel_broker import LIVE_WINDOW
    from django.db.models import Count
    from django.utils import timezone
    now = timezone.now()
    agents = list(Agent.objects.filter(kind='scanner', status='active').values('id', 'name', 'last_seen', 'max_concurrent')[:200])
    held = dict(SentinelTask.objects.filter(agent_id__in=[a['id'] for a in agents], status__in=SENTINEL_ACTIVE_STATUSES)
                .values_list('agent_id').annotate(n=Count('id')))
    offline = sorted(a['name'] for a in agents if not a['last_seen'] or a['last_seen'] < now - LIVE_WINDOW)
    full = sorted(a['name'] for a in agents if a['name'] not in offline and held.get(a['id'], 0) >= (a['max_concurrent'] or 1))
    return {'offline': offline, 'full': full}


def fallback_warning(total):
    try:
        trouble = sentinel_trouble()
    except Exception:  # noqa: BLE001
        trouble = {'offline': [], 'full': []}
    parts = []
    if trouble['offline']:
        parts.append('offline: ' + ', '.join(trouble['offline'][:10]))
    if trouble['full']:
        parts.append('at capacity: ' + ', '.join(trouble['full'][:10]))
    if not parts:
        parts.append('no registered Sentinel is offline or full; check their capabilities and scope')
    return f'{total} stages fell back to local execution in the last hour: check your Sentinels ({"; ".join(parts)})'


# --- the opt-in skip list, applied where a local tool starts ---------------------------------------------------------

def note_skipped(tool, ports, addresses=()):
    """The one activity line a local run that left skipped ports out writes (and a log record per address and logged port)."""
    if not ports:
        return
    log_connections(addresses, ports, tool, mode=EXACT, outcome=SKIPPED)
    from cveFeed import activity
    ctx = current()
    names = ', '.join(str(p) for p in sorted(ports))
    activity.log('run_check', f'{tool}: port {names} not scanned from this server: {SKIP_REASON}; a Sentinel does this',
                 project=ctx.get('project'), scan_id=ctx.get('scan_id'))


def coverage_note():
    """The sentence the host check coverage adds to a port-scanning check while the skip list is set, or ''."""
    skip = skipped_ports()
    return f'skipped on the server: port {", ".join(str(p) for p in sorted(skip))}' if skip else ''


# --- what get_system_status and the configMaxxing card show -------------------------------------------------------------

def status(problems=None, now=None):
    """The egress section of ``get_system_status``: counts by watched port for the last hour and 24 hours, the budgets and their use this
    hour, owed ports, local fallbacks, and the top sources. A problem is added while tasks keep falling back to local execution."""
    snap = snapshot(now) or {'hour': {}, 'day': {}, 'week': {}, 'sources': {}}
    watch = watched_ports()
    rules = budgets()
    ports = []
    for port in watch:
        ports.append({'port': port, 'last_hour': snap['hour'].get(f'p{port}', 0), 'last_24h': snap['day'].get(f'p{port}', 0),
                      'last_7d': snap['week'].get(f'p{port}', 0), 'budget_per_hour': rules.get(port),
                      'used_this_hour': used_this_hour(port, now) if port in rules else None,
                      'skipped': port in skipped_ports()})
    sources = sorted(((k, v) for k, v in snap['sources'].items() if not k.endswith('|all')), key=lambda kv: -kv[1])[:10]
    fallbacks = fallbacks_last_hour(now)
    if problems is not None and fallbacks >= FALLBACK_WARN_AT:
        problems.append(f'egress: {fallback_warning(fallbacks)}')
    return {'estimate_note': 'nmap and naabu are counted from their probe plan (addresses x ports, before retries): an '
                             'estimate; in-process probes are counted exactly',
            'all_ports': {'last_hour': snap['hour'].get('all', 0), 'last_24h': snap['day'].get('all', 0), 'last_7d': snap['week'].get('all', 0)},
            'watched': ports, 'skip_ports': sorted(skipped_ports()),
            'top_sources_24h': [{'kind': k.split('|')[0], 'project': k.split('|')[1], 'port': int(k.split('|')[2]), 'connections': v}
                                for k, v in sources],
            'fallbacks_last_hour': fallbacks,
            'fallback_caps_per_hour': {kind: fallback_cap(kind) for kind in ('nmap', 'naabu')}}
