"""User roles and their permissions for CVEngine, for django-role-permissions."""

from rolepermissions.roles import AbstractUserRole

from cvengine.definitions import (
    PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_INTERESTING_LOOKUP,
    PERM_MODIFY_SCAN_CONFIGURATIONS,
    PERM_MODIFY_SCAN_REPORT,
    PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    PERM_MODIFY_TARGETS,
    PERM_MODIFY_WORDLISTS,
)

_ALL_PERMISSIONS = (
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    PERM_MODIFY_SCAN_CONFIGURATIONS,
    PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_WORDLISTS,
    PERM_MODIFY_INTERESTING_LOOKUP,
    PERM_MODIFY_SCAN_REPORT,
    PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_TARGETS,
)


def _build(granted):
    """Return a dict with every permission name mapped to whether it is granted."""
    return {name: name in granted for name in _ALL_PERMISSIONS}


class SysAdmin(AbstractUserRole):
    """Full access to every permission."""

    available_permissions = _build(set(_ALL_PERMISSIONS))


class PenetrationTester(AbstractUserRole):
    """Everything except system configurations."""

    available_permissions = _build(set(_ALL_PERMISSIONS) - {PERM_MODIFY_SYSTEM_CONFIGURATIONS})


class Auditor(AbstractUserRole):
    """Read oriented access to results, lookups and reports."""

    available_permissions = _build({
        PERM_MODIFY_SCAN_RESULTS,
        PERM_MODIFY_INTERESTING_LOOKUP,
        PERM_MODIFY_SCAN_REPORT,
    })
