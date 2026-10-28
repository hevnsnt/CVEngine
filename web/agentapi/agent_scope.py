"""What an agent may say about itself, and what it may be responsible for.

Pure parsing and matching (no queries except ``authorise``): the registration body is cleaned here into a small typed record, a
host pattern is one of the shapes the remediation work list already understands (``services.AssetFilter``), and the scope an agent
asked for is cut down to what its token's user can reach before any work is handed out.
"""
import ipaddress
import re

from tenancy import roles

MAX_HOST_PATTERNS = 200
MAX_CAPABILITIES = 40
MAX_TOOLS = 30
MAX_SCOPE_NAMES = 100

KINDS = ('remediation', 'validation', 'scanner', 'reporter', 'human')
OS_FAMILIES = ('linux', 'windows', 'macos', 'bsd')
# The capabilities the broker itself asks for. Others are accepted (an agent may offer more than the broker knows) but never matched.
KNOWN_CAPABILITIES = ('validate:network', 'validate:local', 'validate:local-ssh', 'validate:guided', 'remediate:linux', 'remediate:windows',
                      'remediate:web-config', 'report:inventory', 'shell', 'ssh', 'can-restart-services',
                      'nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan', 'openvas')  # the Sentinel (kind='scanner') scan-stage capabilities
# Underscores are allowed alongside hyphens so a Sentinel's capabilities can name a SentinelTask kind verbatim (nuclei_light, ...).
_CAPABILITY = re.compile(r'^[a-z][a-z0-9_-]{0,30}(?::[a-z][a-z0-9_-]{0,30})?$')
_TOOL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$')
_SLUG = re.compile(r'^[-\w]{1,100}$')
_NAME_CLEAN = re.compile(r'[\x00-\x1f\x7f]')


class ScopeError(ValueError):
    """A registration field the caller got wrong; the message says which."""


def _string_list(value, label, limit):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f'{label} must be a list of strings')
    if len(value) > limit:
        raise ScopeError(f'{label} may list at most {limit} entries')
    return value


def clean_name(value, label='name'):
    text = _NAME_CLEAN.sub('', value).strip() if isinstance(value, str) else ''
    if not text:
        raise ScopeError(f'{label} must be a non-empty string')
    return text[:100]


def clean_kind(value):
    if value not in KINDS:
        raise ScopeError(f'kind must be one of {", ".join(KINDS)}')
    return value


def clean_capabilities(value):
    out = []
    for item in _string_list(value, 'capabilities', MAX_CAPABILITIES):
        cap = item.strip().lower()
        if not _CAPABILITY.match(cap):
            raise ScopeError(f'capability {item[:40]!r} is not a lowercase name such as validate:network')
        if cap not in out:
            out.append(cap)
    return out


def clean_os(value):
    out = []
    for item in _string_list(value, 'os', len(OS_FAMILIES)):
        fam = item.strip().lower()
        if fam not in OS_FAMILIES:
            raise ScopeError(f'os entries must be among {", ".join(OS_FAMILIES)}')
        if fam not in out:
            out.append(fam)
    return out


def clean_tools(value):
    out = []
    for item in _string_list(value, 'tools', MAX_TOOLS):
        tool = item.strip()
        if not _TOOL.match(tool):
            raise ScopeError(f'tool {item[:40]!r} is not a plain tool name')
        if tool not in out:
            out.append(tool)
    return out


def clean_host_pattern(raw):
    """One host the agent is responsible for, in the form ``services.AssetFilter`` matches: a host name (which also covers every name under
    it, so ``*.example.test`` is stored as ``example.test``), an IP address, or a CIDR. Anything else, a regular expression included, is
    refused: a pattern language is a place for a slow or surprising match."""
    from targetApp.target_types import CIDR, DOMAIN, IP, classify_target
    text = raw.strip().lower().rstrip('.')
    if text.startswith('*.'):
        text = text[2:]
    kind = classify_target(text)
    if kind == CIDR:
        return str(ipaddress.ip_network(text, strict=False))
    if kind == IP:
        return str(ipaddress.ip_address(text))
    if kind == DOMAIN:
        return text
    raise ScopeError(f'host {raw[:60]!r} is not a host name, wildcard such as *.example.test, IP address or CIDR')


def clean_scope(value):
    """``{orgs, projects, hosts, instance}`` from a registration body, the lists de-duplicated. Unknown keys are an error, so a
    typo does not quietly widen or narrow what an agent covers. ``instance`` (a bool, default ``False``) means every
    organization and project on this server, present and future; ``authorise`` below only ever lets a superuser keep it set."""
    if value is None:
        return {'orgs': [], 'projects': [], 'hosts': [], 'instance': False}
    if not isinstance(value, dict):
        raise ScopeError('scope must be an object with orgs, projects, hosts and instance')
    extra = set(value) - {'orgs', 'projects', 'hosts', 'instance'}
    if extra:
        raise ScopeError(f'unknown scope key(s): {", ".join(sorted(str(k)[:20] for k in extra))}')
    out = {}
    for key in ('orgs', 'projects'):
        names = []
        for item in _string_list(value.get(key), f'scope.{key}', MAX_SCOPE_NAMES):
            slug = item.strip()
            if not _SLUG.match(slug):
                raise ScopeError(f'scope.{key} entries are slugs: {item[:40]!r} is not one')
            if slug not in names:
                names.append(slug)
        out[key] = names
    hosts = []
    for item in _string_list(value.get('hosts'), 'scope.hosts', MAX_HOST_PATTERNS):
        pattern = clean_host_pattern(item)
        if pattern not in hosts:
            hosts.append(pattern)
    out['hosts'] = hosts
    if 'instance' in value and not isinstance(value['instance'], bool):
        raise ScopeError('scope.instance must be true or false')
    out['instance'] = bool(value.get('instance', False))
    return out


def authorise(user, scope):
    """The organizations and projects of ``scope`` that ``user`` may not claim, as ``(orgs, projects, bad_instance)``: the first two
    are name lists, the third is ``True`` only when ``scope.instance`` is set and ``user`` is not a superuser. An unknown name and
    one the user cannot reach look the same, so a registration never reveals what another tenant has; ``scope.instance`` is the
    one exception that must say plainly who may hold it, since it is not a name to hide but the whole server."""
    from dashboard.models import Org, Project
    allowed_projects = roles.allowed_project_ids(user)
    org_ids = None if user.is_superuser else roles.user_org_ids(user)
    bad_orgs = []
    for slug in scope['orgs']:
        org = Org.objects.filter(slug=slug).first()
        if not org or (org_ids is not None and org.pk not in org_ids):
            bad_orgs.append(slug)
    bad_projects = []
    for slug in scope['projects']:
        project = Project.objects.filter(slug=slug).first()
        if not project or (allowed_projects is not None and project.pk not in allowed_projects):
            bad_projects.append(slug)
    bad_instance = bool(scope.get('instance')) and not user.is_superuser
    return bad_orgs, bad_projects, bad_instance


def project_slugs_in_scope(user, scope, limit_projects=None):
    """The slugs of the projects the agent may work in: every project ``user`` can reach when ``scope.instance`` is set, else the
    projects of its organizations plus the ones it names, kept to what ``user`` can reach now, and to the administrator's project
    limit when there is one. An agent that names no organization or project and holds no instance scope covers none: a host list
    alone narrows where it may act, it does not pick a project."""
    from dashboard.models import Project
    allowed = roles.allowed_project_ids(user)
    if scope.get('instance'):
        slugs = set((Project.objects.all() if allowed is None else Project.objects.filter(pk__in=allowed)).values_list('slug', flat=True))
        return slugs & set(limit_projects) if limit_projects is not None else slugs
    if not scope.get('orgs') and not scope.get('projects'):
        return set()
    qs = Project.objects.all() if allowed is None else Project.objects.filter(pk__in=allowed)
    wanted = Project.objects.none()
    if scope.get('orgs'):
        wanted = wanted | qs.filter(org__slug__in=scope['orgs'])
    if scope.get('projects'):
        wanted = wanted | qs.filter(slug__in=scope['projects'])
    slugs = set(wanted.values_list('slug', flat=True))
    return slugs & set(limit_projects) if limit_projects is not None else slugs


def requirement_met(requirement, have):
    """A requirement is a capability, or capabilities joined by ``|`` of which one is enough."""
    return any(part in have for part in requirement.split('|'))


def missing_requirements(required, have):
    return [r for r in required if not requirement_met(r, have)]
