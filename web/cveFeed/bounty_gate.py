"""The one admission check every unattended scan entry point asks before it touches a bug bounty project.

Two questions, answered once so no sweep invents its own:

  project   Has the person confirmed the program's policy allows automated scanning (``conductor.bounty_blocked_projects``: policy
            acknowledged, automated testing allowed, engagement still being worked, and the program's scope unchanged since the
            acknowledgement)? Asked by every sweep and queue that starts work on its own. A scan a person starts is a decision of
            theirs and is not held to it.
  host      Does the program's scope name this host (``bounty_scope.ScopeIndex``)? Asked for every host a scanner is aimed at, whoever
            started the scan, because a program refuses the report and may ban the researcher for testing what its scope does not name.
            ``out_of_scope`` and ``not_listed`` hosts are never scanned. An ``ambiguous`` host (the apex of an in-scope wildcard, a
            path-only entry, a pattern, a program whose scope is prose) is scanned only after a person confirmed it, and adding or
            importing it as a target of the project is that confirmation. A host reached through an in-scope name (an address behind it)
            is judged only against the out-of-scope entries.

A project with no bug bounty engagement is never affected: ``refusal`` costs it one query. Build one ``Gate`` per sweep (it caches what it
reads) and call ``refusal(project_id, host)``; an empty string means go ahead, anything else is the reason to log or show.
"""
from cveFeed import bounty_scope

PROJECT_REASON = 'the bug bounty engagement has not confirmed automated testing, or the program\'s scope changed since it was acknowledged'


class _ProjectScope:
    """One project's scope: the indexes of the programs it works and the names a person added as targets. No engagements means no rules."""

    def __init__(self, project_id):
        from cveFeed.models import BountyEngagement
        from targetApp.models import Domain
        rows = list(BountyEngagement._base_manager.filter(project_id=project_id).select_related('program'))
        self.bounty = bool(rows)
        self.indexes, self.targets = [], set()
        if not rows:
            return
        for engagement in rows:
            self.indexes.append(bounty_scope.ScopeIndex(engagement.program.assets.filter(removed_at__isnull=True)))
        self.targets = {name.lower().rstrip('.') for name in Domain._base_manager.filter(project_id=project_id).values_list('name', flat=True)}

    def refusal(self, host, derived=False):
        if not self.bounty:
            return ''
        from cveFeed.exclusions import normalize
        name = normalize(host)
        verdicts = [index.check(name) for index in self.indexes]
        states = {v.state for v in verdicts}
        if bounty_scope.OUT in states:
            return next(v.reason for v in verdicts if v.state == bounty_scope.OUT)
        parsed = bounty_scope.parse_host(name)
        if derived and parsed and parsed[0] == 'ip':
            return ''  # an address behind a name the scope allows: only an out-of-scope entry can refuse it
        if bounty_scope.IN in states:
            return ''
        if bounty_scope.AMBIGUOUS in states and name in self.targets:
            return ''  # a person added it as a target: that is the confirmation the scope check asks for
        verdict = next((v for v in verdicts if v.state == bounty_scope.AMBIGUOUS), verdicts[0] if verdicts else None)
        if verdict is None:
            return 'the program lists no scope'
        if verdict.state == bounty_scope.AMBIGUOUS:
            return f'{verdict.reason}; add it as a target of the project to confirm it'
        return verdict.reason


class Gate:
    """``refusal(project_id, host=None)`` for any number of projects and hosts; the blocked-project set and each project's scope are
    read once. ``blocked`` lets a caller that already has the set pass it."""

    def __init__(self, blocked=None):
        from cveFeed.conductor import bounty_blocked_projects
        self.blocked = set(blocked) if blocked is not None else bounty_blocked_projects()
        self._scopes = {}

    def project_blocked(self, project_id):
        return project_id in self.blocked

    def refusal(self, project_id, host=None, *, unattended=True, derived=False):
        """Why a scanner may not be aimed at ``host`` of ``project_id`` (or, with no host, at the project at all) - ``''`` when it may.
        ``unattended`` is True for anything the system starts on its own (the project confirmation applies); a scan a person started
        passes False and is held only to the host scope. ``derived`` marks an address found behind a name, not a target itself."""
        if not project_id:
            return ''
        if unattended and project_id in self.blocked:
            return PROJECT_REASON
        if host is None:
            return ''
        if project_id not in self._scopes:
            self._scopes[project_id] = _ProjectScope(project_id)
        return self._scopes[project_id].refusal(host, derived=derived)

    def allows(self, project_id, host=None, **kwargs):
        return not self.refusal(project_id, host, **kwargs)
