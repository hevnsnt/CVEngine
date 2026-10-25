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
    'censys': ('Censys', [('api_id', 'API ID', False), ('api_secret', 'API secret', True)],
               [('modules.censys_dns.api_key', ('api_id', 'api_secret')), ('modules.censys_ip.api_key', ('api_id', 'api_secret'))]),
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
    # bbot has no BinaryEdge module (3.x), so like runZero this key is storable but has nothing to feed yet.
    'binaryedge': ('BinaryEdge', [('api_key', 'API key', True)], []),
    # runZero is an asset-inventory platform, not a bbot module: there is nothing to feed it into during a
    # scan. The key is still storable here so it is ready for a future "pull runZero's own inventory in as
    # a source of hosts" integration; it has no bbot_config_args mapping until that import job exists.
    'runzero': ('runZero', [('api_key', 'Export API token', True)], []),
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
        merged[cred.service] = dict(cred.value)  # the project's own key wins over its org's
    return merged


def bbot_config_args(project):
    """``-c path=value`` flags for every configured service, ready to append to a bbot command line."""
    args = []
    for service, fields in resolve_for_project(project).items():
        _, _, mapping = SERVICES.get(service, (None, None, []))
        for path, field in mapping:
            names = field if isinstance(field, tuple) else (field,)
            parts = [fields.get(n) for n in names]
            if all(parts):  # a pair like Censys's id and secret is only usable whole
                args += ['-c', f'{path}={":".join(parts)}']
    return args


SCAN_STAGES = frozenset({'wpscan'})  # keys a pipeline stage uses directly rather than through a bbot module


def used_in_scans(service):
    """Whether a scan can actually use this service's key (it maps to a bbot module or a pipeline stage)."""
    return bool(SERVICES[service][2]) or service in SCAN_STAGES
