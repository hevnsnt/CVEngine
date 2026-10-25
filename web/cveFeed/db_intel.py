"""Richer metadata from the database NSE scripts in cveFeed.nmap_scan.NSE_SCRIPTS: each one's pre-authentication
greeting, parsed into ``Port.extra['db']`` and used to fill ``Port.version``/``Port.product`` when nmap's own
``-sV`` probe came back empty. This is metadata only, same as cveFeed.service_intel's RDP and SMB facts: whether
a database is reachable with NO authentication at all is a separate question, answered by cveFeed.db_exposure's
real connection attempts, not by anything parsed here.

Everything here reads output already stored by the nmap stage; nothing connects to a host.
"""
import re

LINE = re.compile(r'^\s*([A-Za-z0-9_ ]+?):\s*(.*?)\s*$')


def _field_lines(text):
    for raw in str(text or '').splitlines():
        match = LINE.match(raw)
        if match:
            yield match.group(1).strip(), match.group(2).strip()


def parse_mysql_info(text):
    """``{version, protocol}`` from mysql-info output. Every MySQL server sends this greeting before any
    authentication, so answering at all says nothing about whether a credential is required."""
    facts = {}
    for key, value in _field_lines(text):
        if key == 'Version' and value:
            facts['version'] = value[:120]
        elif key == 'Protocol' and value:
            facts['protocol'] = value[:20]
    return facts


def parse_mongodb_info(text):
    """``{version}`` from mongodb-info's Build info section. The script's output nests ``Server status`` fields
    under it too, but ``version`` only ever appears once, so a flat ``key = value`` scan is enough."""
    facts = {}
    for raw in str(text or '').splitlines():
        stripped = raw.strip()
        if '=' not in stripped:
            continue
        key, _, value = stripped.partition('=')
        key, value = key.strip(), value.strip()
        if key == 'version' and value:
            facts['version'] = value[:60]
    return facts


def parse_redis_info(text):
    """``{version, role, architecture}`` from redis-info output. Its fields are column-aligned, not
    colon-separated, and the bind address, channel and client lists that follow are left out on purpose:
    they are not metadata, and keeping them would mean storing who else talks to this server."""
    facts = {}
    for raw in str(text or '').splitlines():
        if not raw or raw[0] in (' ', '\t'):
            continue  # a nested list item (an address, a channel): not a field
        stripped = raw.strip()
        if not stripped or stripped.endswith(':'):
            continue  # a list header with no value of its own
        parts = re.split(r' {2,}', stripped, maxsplit=1)
        if len(parts) != 2:
            continue
        key, value = parts[0].strip(), parts[1].strip()
        if key == 'Version':
            facts['version'] = value[:60]
        elif key == 'Role':
            facts['role'] = value[:40]
        elif key == 'Architecture':
            facts['architecture'] = value[:40]
    return facts


def parse_memcached_info(text):
    """``{uptime, architecture, authentication}`` from memcached-info output."""
    facts = {}
    for key, value in _field_lines(text):
        if key == 'Uptime' and value:
            facts['uptime'] = value[:60]
        elif key == 'Architecture' and value:
            facts['architecture'] = value[:40]
        elif key == 'Authentication' and value:
            facts['authentication'] = value[:20]
    return facts


def parse_couchdb_stats(text):
    """``{auth, admin_party}`` from couchdb-stats' trailing authentication line. The request-count tables above it
    are runtime statistics, not metadata, and are left out."""
    facts = {}
    match = re.search(r'Authentication\s*:\s*(.+)', text or '')
    if match:
        value = match.group(1).strip()[:80]
        facts['auth'] = value
        facts['admin_party'] = 'admin party' in value.lower()
    return facts


def parse_ms_sql_ntlm(text):
    """``{computer_name, domain, fqdn, dns_domain, build, os}`` from ms-sql-ntlm-info: the exact same NTLM
    challenge fields rdp-ntlm-info reads, negotiated over SQL Server's own protocol instead of RDP's. The build
    disclosed is the host's real Windows version either way, so the same lookup table applies."""
    from cveFeed.service_intel import parse_rdp_ntlm
    return parse_rdp_ntlm(text)


def parse_ms_sql_info(text):
    """``{windows_server, version, version_number}`` from ms-sql-info's host-wide instance enumeration. A host can
    run several SQL Server instances; this keeps the first one's version, which covers the common case of one."""
    facts = {}
    for key, value in _field_lines(text):
        if key == 'Windows server name' and value:
            facts.setdefault('windows_server', value[:120])
        elif key == 'name' and value and 'sql server' in value.lower():
            facts.setdefault('version', value[:120])
        elif key == 'number' and value:
            facts.setdefault('version_number', value[:40])
    return facts


# Port-level scripts: {NSE script id: (database label, parser)}. ms-sql-info is handled separately in
# apply_mssql_host_facts because it is a HOST script (it asks the SQL Server Browser service once per host, not
# once per port); every other script here answers one specific port.
PARSERS = {
    'mysql-info': ('MySQL', parse_mysql_info),
    'mongodb-info': ('MongoDB', parse_mongodb_info),
    'redis-info': ('Redis', parse_redis_info),
    'memcached-info': ('Memcached', parse_memcached_info),
    'couchdb-stats': ('CouchDB', parse_couchdb_stats),
    'ms-sql-ntlm-info': ('Microsoft SQL Server', parse_ms_sql_ntlm),
}


def apply_db_facts(port):
    """Store this port's parsed database script output on ``port.extra['db']``, and fill ``version``/``product``
    when nmap's own ``-sV`` probe came back empty. Never overrides what ``-sV`` already found: these scripts read
    the same pre-authentication greeting ``-sV`` does, just in a different shape. True when anything changed."""
    scripts = (port.extra or {}).get('scripts') or {}
    facts, label = {}, None
    for script_id, (db_label, parser) in PARSERS.items():
        text = scripts.get(script_id)
        if not text:
            continue
        parsed = parser(text)
        if parsed:
            facts[script_id] = parsed
            label = label or db_label
    if not facts:
        return False
    changed = []
    extra = dict(port.extra or {})
    if extra.get('db') != facts:
        extra['db'] = facts
        port.extra = extra
        changed.append('extra')
    version = next((f.get('version') for f in facts.values() if f.get('version')), None)
    if version and not port.version:
        port.version = version
        changed.append('version')
    if label and not port.product:
        port.product = label
        changed.append('product')
    if changed:
        port.save(update_fields=changed)
    return bool(changed)


def apply_mssql_host_facts(ip_obj):
    """ms-sql-info's version, applied to whichever open port on this address looks like SQL Server: the script
    itself is host-wide (it queries the SQL Server Browser service once, not once per port), so there is no port
    of its own to key the result to. True when anything changed."""
    text = ((ip_obj.fingerprint or {}).get('scripts') or {}).get('ms-sql-info')
    if not text:
        return False
    facts = parse_ms_sql_info(text)
    if not facts:
        return False
    changed_any = False
    for port in ip_obj.ports.all():
        if port.number != 1433 and 'ms-sql' not in (port.service_name or ''):
            continue
        extra = dict(port.extra or {})
        db = dict(extra.get('db') or {})
        if db.get('ms-sql-info') == facts:
            continue
        db['ms-sql-info'] = facts
        extra['db'] = db
        port.extra = extra
        changed = ['extra']
        if facts.get('version') and not port.version:
            port.version = facts['version']
            changed.append('version')
        if not port.product:
            port.product = 'Microsoft SQL Server'
            changed.append('product')
        port.save(update_fields=changed)
        changed_any = True
    return changed_any
