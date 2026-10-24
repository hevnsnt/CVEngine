"""Hosts an organization has excluded for good ("Remove & exclude"), and the checks every discovery and scan path shares.

A host is excluded for a project when its organization holds a HostExclusion with the SAME name. The match is the whole
name, lowercase, and nothing else: no suffix, no substring, no parent domain. Excluding ``provider.example`` does
not touch ``notprovider.example`` or ``www.provider.example`` (that one needs its own exclusion).

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


def excluded_names(project_id):
    """The frozenset of lowercase names excluded for ``project_id`` (its org's list). Empty for no project or no org."""
    if not project_id:
        return frozenset()
    from cveFeed.models import HostExclusion
    try:
        return frozenset(HostExclusion.objects.filter(org__projects__id=project_id).values_list('host', flat=True))
    except Exception:  # noqa: BLE001 - never let a lookup problem stop discovery
        logger.warning('could not read the host exclusions for project %s', project_id, exc_info=True)
        return frozenset()


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
