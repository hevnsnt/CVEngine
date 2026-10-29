"""Hosts an organization has excluded for good ("Remove & exclude"), and the checks every discovery and scan path shares.

A host is excluded for a project when its organization holds a HostExclusion with the SAME name. The match is the whole
name, lowercase: excluding ``provider.example`` does not touch ``notprovider.example`` (never a substring or a bare suffix).
An exclusion made with ``include_subdomains`` (``-provider.example`` in Add targets) also covers every name under it, on a dot
boundary: ``www.provider.example`` and ``a.b.provider.example``, still never ``notprovider.example``.

Everything here is read through the project's own org, so one org's list never reaches another's scans. A project without
an org has no exclusions. All the checks are non-fatal: if the lookup fails, nothing is excluded (the owner's explicit
deletion has already removed the data; the lookup only prevents it from coming back).
"""
import logging

logger = logging.getLogger(__name__)

MAX_HOST_LENGTH = 500


def normalize(value):
    """The comparable form of a host: a bare lowercase name, without scheme, port, path or trailing dot. '' if empty."""
    from targetApp.target_types import bare_host
    return bare_host(value).strip().rstrip('.')[:MAX_HOST_LENGTH]


class ExclusionSet(frozenset):
    """The names an organization excluded: ``name in excluded`` is true for an excluded name and for any name under an excluded
    domain (one made with ``include_subdomains``). A frozenset of the exact names, so every existing ``in`` check keeps working;
    ``|`` keeps the subdomain rules."""

    def __new__(cls, names=(), subtrees=()):
        self = super().__new__(cls, names)
        self.subtrees = frozenset(subtrees)
        return self

    def __contains__(self, name):
        if super().__contains__(name):
            return True
        if not self.subtrees or not isinstance(name, str):
            return False
        name = name.strip().lower().rstrip('.')
        while '.' in name:
            name = name.split('.', 1)[1]
            if name in self.subtrees:
                return True
        return False

    def __or__(self, other):
        return ExclusionSet(frozenset(self) | frozenset(other), self.subtrees | getattr(other, 'subtrees', frozenset()))

    def __ror__(self, other):
        return self.__or__(other)


def excluded_names(project_id, strict=False):
    """The ExclusionSet of lowercase names excluded for ``project_id`` (its org's list, plus the hosts moved out of the project). Empty for no project or no org. ``strict``
    lets a failed lookup raise (an authorization check must stop, not carry on with nothing excluded)."""
    if not project_id:
        return ExclusionSet()
    from cveFeed.models import HostExclusion, HostMove
    try:
        rows = list(HostExclusion.objects.filter(org__projects__id=project_id).values_list('host', 'include_subdomains'))
        # a host moved out of this project into another stays out of this one (exact name), whatever its org's list says
        rows += [(host, False) for host in HostMove.objects.filter(project_id=project_id).values_list('host', flat=True)]
    except Exception:  # noqa: BLE001 - never let a lookup problem stop discovery
        if strict:
            raise
        logger.warning('could not read the host exclusions for project %s', project_id, exc_info=True)
        return ExclusionSet()
    return ExclusionSet((host for host, _ in rows), (host for host, subtree in rows if subtree))


def covers(pattern, name, subtree):
    """Whether the exclusion ``pattern`` (made with or without ``include_subdomains``) covers ``name``."""
    name = normalize(name)
    return name == pattern or bool(subtree and name.endswith('.' + pattern))


def is_excluded(project_id, host):
    """Whether ``host`` (any case; a URL or host:port is reduced to its name) is excluded for the project's org."""
    name = normalize(host)
    return bool(name) and name in excluded_names(project_id)


def drop_excluded(project_id, names):
    """``names`` (a list, in order) without the excluded ones. One query."""
    names = list(names)
    banned = excluded_names(project_id)
    if not banned:
        return names
    return [n for n in names if normalize(n) not in banned]


def org_id_of(project_id):
    from dashboard.models import Project
    return Project._base_manager.filter(pk=project_id).values_list('org_id', flat=True).first()
