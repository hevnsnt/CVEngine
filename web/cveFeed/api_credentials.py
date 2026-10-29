"""Org- and project-level API keys for external OSINT services (Shodan, Censys, ...), and turning them
into the bbot module config that actually uses them. A project's own key for a service overrides its
organization's; with neither set, bbot just runs that module unauthenticated (most soft-fail cleanly,
per the "Setup soft-failed: No API key set" lines bbot already logs).
"""

# service slug -> (label, [(field, description, is_secret)], [(bbot config path, field)])
# The bbot config paths are what bbot_config_args turns into `-c path=value` flags. They must name real bbot modules and
# options (checked against bbot 3.x: an unknown module or option makes bbot print a preset error). A field given as a
# tuple is joined with ':' into one value, which is how bbot's Censys modules take "id:secret".
SERVICES = {
    'shodan': ('Shodan', [('api_key', 'API key', True)],
               [('modules.shodan_dns.api_key', 'api_key')]),  # shodan_idb is the free InternetDB: it has no key option
    # bbot's Censys module talks to the legacy Search API (search.censys.io) with the API ID and secret. censys_ip is not mapped:
    # none of the scan modes enables it, so a key for it would be stored and never used.
    'censys': ('Censys (legacy Search API: API ID and secret; Censys is retiring that API)', [('api_id', 'API ID', False), ('api_secret', 'API secret', True)],
               [('modules.censys_dns.api_key', ('api_id', 'api_secret'))]),
    'virustotal': ('VirusTotal', [('api_key', 'API key', True)], [('modules.virustotal.api_key', 'api_key')]),
    'securitytrails': ('SecurityTrails', [('api_key', 'API key', True)], [('modules.securitytrails.api_key', 'api_key')]),
    'fullhunt': ('FullHunt', [('api_key', 'API key', True)], [('modules.fullhunt.api_key', 'api_key')]),
    'leakix': ('LeakIX', [('api_key', 'API key', True)], [('modules.leakix.api_key', 'api_key')]),
    'hunterio': ('Hunter.io', [('api_key', 'API key', True)], [('modules.hunterio.api_key', 'api_key')]),
    'chaos': ('Chaos (ProjectDiscovery)', [('api_key', 'API key', True)], [('modules.chaos.api_key', 'api_key')]),
    'github': ('GitHub (code search)', [('api_key', 'Personal access token', True)],
               [('modules.github_codesearch.api_key', 'api_key'), ('modules.github_org.api_key', 'api_key')]),
    'otx': ('AlienVault OTX', [('api_key', 'API key', True)], [('modules.otx.api_key', 'api_key')]),
    'c99': ('C99', [('api_key', 'API key', True)], [('modules.c99.api_key', 'api_key')]),
    'bevigil': ('BeVigil', [('api_key', 'API key', True)], [('modules.bevigil.api_key', 'api_key')]),
    'builtwith': ('BuiltWith', [('api_key', 'API key', True)], [('modules.builtwith.api_key', 'api_key')]),
    'bufferoverrun': ('BufferOver.run', [('api_key', 'API key', True)], [('modules.bufferoverrun.api_key', 'api_key')]),
    # WPScan is run by CVEngine itself against WordPress sites it found (see cveFeed.wpscan_scan), not through bbot.
    'wpscan': ('WPScan (WordPress vulnerability data)', [('api_key', 'API token from wpscan.com', True)], []),
    # Retired, see RETIRED: kept only so a key someone already saved stays visible and removable.
    'binaryedge': ('BinaryEdge', [('api_key', 'API key', True)], []),
    # runZero is an asset-inventory platform, not a bbot module: its key is used by cveFeed.runzero_sync, which reads the
    # inventory on a schedule (see SYNC_SERVICES), so it has no bbot mapping.
    'runzero': ('runZero', [('api_key', 'Export API token', True)], []),
}

# Services that no longer exist. Their rows are kept (a stored key is user data and removing it is the user's call) but no new key is
# accepted, nothing reads them, and the pages say why.
RETIRED = {
    'binaryedge': 'BinaryEdge was shut down as a standalone service on 31 March 2025 (Coalition retired the platform, its accounts and '
                  'its API), so there is nothing to connect to. Remove the key; it is not used.',
}


def credential_summary(cred):
    """Which fields are set, without ever returning the secret values themselves."""
    _, fields, _ = SERVICES[cred.service]
    return {name: bool(cred.value.get(name)) for name, _, _ in fields}


def resolve_for_project(project):
    """{service: {field: value}} for one project: its own keys, falling back to its organization's."""
    from dashboard.models import ApiCredential
    merged = {}
    if project.org_id:
        for cred in ApiCredential.objects.filter(org_id=project.org_id):
            merged[cred.service] = dict(cred.value)
    for cred in ApiCredential.objects.filter(project=project):
        # the project's own key wins over its org's, field by field: a project row holding only part of a pair (Censys's ID without
        # its secret) must not blank what the organization set
        merged[cred.service] = {**merged.get(cred.service, {}), **{k: v for k, v in cred.value.items() if v}}
    return merged


def _global_chaos_key():
    """The Chaos key saved once for the whole install (Settings > API vault), used where no organization or project has its own."""
    from dashboard.models import ChaosAPIKey
    row = ChaosAPIKey.objects.exclude(key='').first()
    return (row.key or '').strip() if row else ''


def service_for_module(module):
    """The service whose key feeds a bbot module, for naming a rejected key: ``('virustotal', 'VirusTotal')`` or ``None``."""
    for service, (label, _fields, mapping) in SERVICES.items():
        if any(path.split('.')[1] == module for path, _ in mapping):
            return service, label
    return None


def bbot_config_args(project):
    """``-c path=value`` flags for every configured service, ready to append to a bbot command line."""
    args = []
    resolved = resolve_for_project(project)
    if not any(resolved.get('chaos', {}).values()) and _global_chaos_key():
        resolved['chaos'] = {'api_key': _global_chaos_key()}
    for service, fields in resolved.items():
        _, _, mapping = SERVICES.get(service, (None, None, []))
        for path, field in mapping:
            names = field if isinstance(field, tuple) else (field,)
            parts = [fields.get(n) for n in names]
            if all(parts):  # a pair like Censys's id and secret is only usable whole
                args += ['-c', f'{path}={":".join(parts)}']
    return args


SCAN_STAGES = frozenset({'wpscan'})  # keys a pipeline stage uses directly rather than through a bbot module
SYNC_SERVICES = frozenset({'runzero'})  # keys a scheduled job uses to read the service (not during a scan)


def used_in_scans(service):
    """Whether a scan can actually use this service's key (it maps to a bbot module or a pipeline stage)."""
    return service not in RETIRED and (bool(SERVICES[service][2]) or service in SCAN_STAGES)


def service_entry(service, label, fields, cred=None):
    """The part of a service's API payload that is the same for a project and an organization listing."""
    return {'service': service, 'label': label, 'fields': [{'name': n, 'label': d, 'secret': s} for n, d, s in fields],
            'configured': bool(cred), 'used_in_scans': used_in_scans(service), 'used_by_sync': service in SYNC_SERVICES,
            'retired': RETIRED.get(service), 'set': credential_summary(cred) if cred else {}}
