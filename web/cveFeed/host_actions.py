"""The fixed list of next steps the AI host review may choose for a host (``cveFeed.host_review``), and the one place that runs them.

The model never names a function, a host or an address. It names an ACTION from ``ACTIONS`` and, for an action that is about one finding, a
TARGET: the short ref (``f3``) of a finding in the packet it was shown. This module decides what it may choose and what happens then:

* ``offered(project, sub, rows)`` is the list of actions allowed NOW for this host, each with the refs it may name and its class: ``auto``
  (read-only, or no contact with the host at all, so the project's mode ``auto`` may start it on its own) or ``recommend`` (a broader
  scan: always for a person to start). It is computed from the stored host and findings, never from anything the model said.
* ``run(action, target, project, sub, by)`` computes ``offered`` again, refuses anything that is not in it (and anything that is not a
  registered action at all), then calls the one existing function the action maps to, which applies its own gates: scope, exclusions, the
  archive, the bug bounty confirmation, the pause, and the project's caps. ``by`` is the person who pressed Start, or None for a step the
  review started itself; a step with no person behind it passes the unattended gates (a bug bounty project that has not confirmed automated
  testing, a target set to manual only).

Every validation this module queues carries ``source='host_review'``. It is not ``manual``, so it never counts as a person's work
(``reviewer.worked_by_person``), and the workers treat it as unattended. Deliberately NOT here: validating a secret (it contacts a third party
with the secret), marking a finding fixed or accepted, changing a heat, retesting a fixed finding, and closing a false positive (a verdict on
a finding, through ``reviewer.close_gate``, never a step).
"""
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)

AUTO, RECOMMEND = 'auto', 'recommend'
SOURCE = 'host_review'
MAX_DRAFTS = 10  # CVEs one review may name for a written check

# action: (class, what it does to the host, the existing function it calls). The class decides who may start it. The text is for the person.
ACTIONS = {
    'none': (AUTO, 'nothing', 'nothing is started', 'Nothing more is needed for this host now.'),
    'validate_match': (AUTO, 'read-only checks on a Sentinel', 'cveFeed.hot_validation.enqueue (source host_review)',
                       'Run the read-only validation of one CVE match.'),
    'revalidate_finding': (AUTO, 'read-only checks on a Sentinel', 'AutomaticValidation + cveFeed.tasks.automatic_validate_finding (source host_review)',
                           'Validate one scanner or hygiene finding again.'),
    'screenshot': (AUTO, 'page requests', 'cveFeed.web_shot.queue_host', 'Take fresh screenshots of the web pages of the host.'),
    'draft_check': (AUTO, 'none: a draft is written and gated, never run on a host', 'cveFeed.templategen.generate_template',
                    'Ask the AI to draft a detection check for a CVE that has none.'),
    'ask_person': (AUTO, 'none', 'cveFeed.notify.host_needs_person', 'Ask a person to look at the host.'),
    'rescan_host': (RECOMMEND, 'port and template scans', 'cveFeed.tasks.host_pipeline', 'Scan the host again (ports and templates).'),
    'assess_host': (RECOMMEND, 'the full assessment pipeline', 'cveFeed.host_assessment.enqueue (source host_review)', 'Run a full assessment of the host.'),
    'run_hygiene': (RECOMMEND, 'DNS and mail reads for the whole target', 'cveFeed.tasks.run_hygiene_task', 'Run the hygiene checks of the host\'s target.'),
}
TARGETED = ('validate_match', 'revalidate_finding', 'draft_check')  # actions that are about one finding: they name a ref
AUTO_ACTIONS = tuple(a for a, spec in ACTIONS.items() if spec[0] == AUTO)
RECOMMEND_ACTIONS = tuple(a for a, spec in ACTIONS.items() if spec[0] == RECOMMEND)
NO_CONTACT = ('none', 'ask_person')  # offered even while scanning is paused or the host is out of reach: they start nothing


class Refused(Exception):
    """An action that may not run now, with the reason a person reads."""


# ------------------------------------------------------------------------------------------------------------------------ the context

class _Ctx:
    """What ``offered`` and ``run`` read, once: the project, the host, the findings (loaded with what the checks read), the person (or None)."""

    def __init__(self, project, sub, rows, by=None, unattended=None, agent=False):
        from cveFeed.models import Triage
        self.project, self.sub, self.by, self.agent = project, sub, by, agent  # agent: an API key or an agent started it (HS-5): it keeps the requester for the record but gets no person's authority
        self.unattended = ((by is None) or agent) if unattended is None else unattended
        self.now = timezone.now()
        self.host = sub.name.lower().rstrip('.') if sub is not None else ''
        wanted = [(ref, t) for ref, t in (rows or []) if getattr(t, 'project_id', None) == project.pk]
        loaded = Triage.objects.select_related('match__cve_entry', 'match__subdomain__target_domain', 'vulnerability__target_domain',
                                               'vulnerability__subdomain', 'hygiene__domain').in_bulk([t.pk for _, t in wanted])
        # only this project's own findings on this host: a ref can never reach another project's or another host's row
        self.pairs = [(ref, loaded[t.pk]) for ref, t in wanted
                      if t.pk in loaded and (not self.host or (loaded[t.pk].host or '').lower().rstrip('.') == self.host)]
        self._gate = None
        self._paused = None

    @property
    def paused(self):
        if self._paused is None:
            from cveFeed.scan_control import pause_requested
            self._paused = bool(pause_requested())
        return self._paused

    def gate(self):
        """``(target domain, host name)`` of the host when the scan admission gates let it be touched, else raises ``Refused`` with why: the host's
        scope, an internal range (an internal Sentinel scans those), a manual only target and a bug bounty project that has not confirmed automated
        testing (both only for a step with no person behind it), the exclusion list and the archive."""
        if self._gate is None:
            self._gate = self._read_gate()
        if isinstance(self._gate, str):
            raise Refused(self._gate)
        return self._gate

    def _read_gate(self):
        from cveFeed.host_assessment import _admit
        if self.sub is None:
            return 'the host has no inventory record'
        if self.paused:
            return 'scanning is paused'
        try:
            return _admit(self.project, self.sub, unattended=self.unattended)
        except ValueError as exc:
            return str(exc)

    def open(self):
        """The gate as a boolean, for ``offered``."""
        try:
            self.gate()
            return True
        except Refused:
            return False

    def check_not_excluded(self):
        """The lighter gate of a validation (its worker re-checks scope and the bug bounty confirmation itself): the host is known, not excluded,
        not archived, and scanning is not paused."""
        from cveFeed.exclusions import is_excluded
        from cveFeed.models import HostState
        if self.sub is None:
            raise Refused('the host has no inventory record')
        if self.paused:
            raise Refused('scanning is paused')
        if is_excluded(self.project.pk, self.host):
            raise Refused('host is excluded')
        if self.unattended:
            from cveFeed.conductor import bounty_blocked_projects
            if self.project.pk in bounty_blocked_projects():
                raise Refused('the bug bounty engagement has not confirmed automated testing')
        if HostState.objects.filter(project=self.project, host=self.host, archived_at__isnull=False).exists():
            raise Refused('host is archived; restore it before scanning')

    def lenient(self):
        try:
            self.check_not_excluded()
            return True
        except Refused:
            return False

    def row_for(self, target):
        found = dict(self.pairs).get(target)
        if found is None:
            raise Refused('that finding is not on this host')
        return found


# ------------------------------------------------------------------------------------------------------------------------ what is offered

def _validate_targets(ctx):
    from cveFeed import hot_validation, match_policy
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    rows = [(ref, row) for ref, row in ctx.pairs if row.kind == 'cve_match' and row.match_id]
    if not rows or not ctx.lenient():
        return []
    current = set(CVEMatch.objects.filter(pk__in=[r.match_id for _, r in rows]).filter(latest_scan_q('subdomain__')).values_list('pk', flat=True))
    jobs = hot_validation._latest_jobs([r for _, r in rows])
    active = {ctx.project.pk: hot_validation._active_count(ctx.project.pk)}
    out = []
    for ref, row in rows:
        match = row.match
        evidence = match.evidence or {}
        if (row.match_id not in current or match.source == hot_validation.HOST_REPORTED
                or match_policy.is_version_unknown(evidence, match.version_in_range, match.template_result or '', match.distro_status or '')):
            continue  # a replaced match, one only the host can speak for, one that waits for a person or a published range: the sweep skips them too
        lane = hot_validation.tier_for(row)
        if lane is None or hot_validation._settled(row, lane, jobs, active, ctx.now):
            continue  # not current, already running, already answered for this evidence, or the project is at its cap
        out.append(ref)
    return out


def _revalidate_targets(ctx):
    from cveFeed import hot_validation, reviewer
    scanner_kinds = [kind for kind in reviewer.KIND_ORDER if kind != 'cve_match']  # a scanner finding or a hygiene finding: every kind the review reads but a CVE match
    rows = [(ref, row) for ref, row in ctx.pairs if row.kind in scanner_kinds and hot_validation.manual_eligible(row)]
    if not rows or not ctx.lenient():
        return []
    jobs = hot_validation._latest_jobs([r for _, r in rows])
    if hot_validation._active_count(ctx.project.pk) >= hot_validation.PROJECT_ACTIVE_CAP:
        return []
    out = []
    for ref, row in rows:
        job = jobs.get(row.pk)
        if job is not None and (job.status in ('queued', 'running') or hot_validation._recently_handled(job, row.signature, ctx.now)):
            continue  # in flight, or already answered for this very evidence
        out.append(ref)
    return out


def _draft_targets(ctx):
    import datetime
    from cveFeed import ai_jobs, templategen, validation
    from cveFeed.models import AIJob, GeneratedTemplate
    rows = [(ref, row) for ref, row in ctx.pairs if row.kind == 'cve_match' and row.match_id]
    if not rows or ctx.paused or not ai_jobs.provider_row():
        return []
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    try:
        sentinel_dispatch.nuclei_validate_ready(ctx.project.pk)  # no scanner could check a draft: the AI is not asked for one
    except ScannerUnavailable:
        return []
    cve_ids = {row.match.cve_entry_id for _, row in rows}
    days = datetime.timedelta(days=templategen.generation_limit('TEMPLATE_GEN_CVE_DAYS'))
    tried = set(GeneratedTemplate.objects.filter(cve_entry_id__in=cve_ids, created_at__gte=ctx.now - days).values_list('cve_entry_id', flat=True))
    asking = set(AIJob.objects.filter(kind='template_generation', status__in=AIJob.OPEN).values_list('dedupe', flat=True))
    out, seen = [], set()
    for ref, row in rows:
        entry = row.match.cve_entry
        if entry.pk in seen or entry.pk in tried or f'template:{entry.pk}' in asking:
            continue
        seen.add(entry.pk)
        if validation.resolve_template(entry.cve_id)[0]:
            continue  # a template already covers it
        out.append(ref)
        if len(out) >= MAX_DRAFTS:
            break
    return out


def _screenshot_offer(ctx):
    from cveFeed import web_shot
    return bool(ctx.open() and not web_shot.unavailable_reason() and web_shot.web_targets(ctx.sub))


def _rescan_offer(ctx):
    return ctx.open()


def _assess_offer(ctx):
    from cveFeed import host_assessment
    from cveFeed.models import HostAssessment
    if not ctx.open():
        return False
    if HostAssessment.objects.filter(project=ctx.project, host=ctx.host, status__in=host_assessment.ACTIVE).exists():
        return False
    try:
        host_assessment._require_capacity(ctx.project)
    except RuntimeError:
        return False
    return True


def offered(project, sub, rows, by=None, unattended=None):
    """``{action: {'class', 'targets', 'touches_host', 'summary'}}``: the actions allowed now for this host. ``rows`` is ``[(ref, Triage)]``, the findings
    the model is shown (only this project's findings on this host are used, whatever is passed). ``none`` and ``ask_person`` are always there; the
    rest only while scanning is not paused, the host is in the inventory and its gates pass (``unattended`` defaults to "no person" unless ``by``
    is given: a person may be offered what an unattended step may not, a bug bounty project that has not confirmed automated testing).
    ``targets`` is the list of refs a targeted action may name."""
    ctx = _Ctx(project, sub, rows, by=by, unattended=unattended)
    found = {'none': [], 'ask_person': []}
    if ctx.sub is not None and not ctx.paused:
        targeted = {'validate_match': _validate_targets, 'revalidate_finding': _revalidate_targets, 'draft_check': _draft_targets}
        for action, read in targeted.items():
            refs = read(ctx)
            if refs:
                found[action] = refs
        for action, read in (('screenshot', _screenshot_offer), ('rescan_host', _rescan_offer), ('assess_host', _assess_offer), ('run_hygiene', _rescan_offer)):
            if read(ctx):
                found[action] = []
    return {action: {'class': ACTIONS[action][0], 'targets': refs, 'touches_host': action not in NO_CONTACT and action != 'draft_check',
                     'summary': ACTIONS[action][3]} for action, refs in found.items()}


# ------------------------------------------------------------------------------------------------------------------------ running one

def _start_validate(ctx, target):
    from cveFeed import hot_validation
    row = ctx.row_for(target)
    ctx.check_not_excluded()
    lane = hot_validation.tier_for(row)
    if lane is None:
        raise Refused('this finding is no longer current')
    result = hot_validation.enqueue(row, lane, source=SOURCE)
    if result in ('queued', 'promoted'):
        return 'started', f'validation of finding #{row.pk} queued ({lane})'
    raise Refused({'inflight': 'a validation of it is already running', 'fresh': 'it was validated for this very evidence a short while ago',
                   'project_cap': 'this project already has too many validations in progress', 'min_gap': 'it was validated a few hours ago',
                   'stale': 'this finding is no longer current', 'failed': 'the validation queue is unavailable'}.get(result, result))


def _start_revalidate(ctx, target):
    from django.db import transaction
    from cveFeed import activity, hot_validation, triage as triage_lib
    from cveFeed.models import AutomaticValidation, Triage
    from cveFeed.tasks import automatic_validate_finding
    from dashboard.models import Project
    row = ctx.row_for(target)
    ctx.check_not_excluded()
    if not hot_validation.manual_eligible(row):
        raise Refused('this finding is closed or no longer in project scope')
    pairs = triage_lib.track([row.finding])
    if not pairs:
        raise Refused('this finding has no owning project to triage it under')
    row = pairs[0][0]
    with transaction.atomic():
        Project.objects.select_for_update().get(pk=ctx.project.pk)  # the project's cap and the duplicate check are one step
        row = Triage.objects.select_for_update().get(pk=row.pk, project=ctx.project)
        previous = AutomaticValidation.objects.filter(triage=row).order_by('-id').first()
        if previous is not None and (previous.status in ('queued', 'running') or hot_validation._recently_handled(previous, row.signature, ctx.now)):
            raise Refused('it is already being validated, or was validated for this very evidence a short while ago')
        if hot_validation._active_count(ctx.project.pk) >= hot_validation.PROJECT_ACTIVE_CAP:
            raise Refused('this project already has too many validations in progress')
        job = AutomaticValidation.objects.create(triage=row, project=ctx.project, signature=row.signature, priority=6, source=SOURCE, attempts=1,
                                                 requested_by=None)
    try:
        automatic_validate_finding.apply_async(args=[job.pk], priority=6)
    except Exception as exc:  # noqa: BLE001 - the broker is down: the row must not stay queued for ever
        AutomaticValidation.objects.filter(pk=job.pk, status='queued').update(status='failed', error='validation broker rejected the request',
                                                                              finished_at=timezone.now())
        raise Refused('the validation queue is unavailable') from exc
    activity.log('validate', f'AI host review: validation #{job.pk} queued for finding #{row.pk}', project=ctx.project, job_id=job.pk, finding_id=row.pk)
    return 'started', f'validation #{job.pk} of finding #{row.pk} queued'


def _start_screenshot(ctx, target):
    from cveFeed import web_shot
    ctx.gate()
    why = web_shot.unavailable_reason()
    if why:
        raise Refused(why)
    summary = web_shot.queue_host(ctx.project, ctx.sub, by_person=ctx.by is not None and not ctx.agent)
    if summary['blocked'] and not summary['queued']:
        raise Refused('this host cannot be photographed')
    return ('started', f'{summary["queued"]} page(s) queued') if summary['queued'] or summary['kept'] else ('done', 'there is no page to capture')


def _start_draft(ctx, target):
    from cveFeed import templategen
    from reNgine.resources import ScannerUnavailable
    row = ctx.row_for(target)
    if row.kind != 'cve_match' or not row.match_id:
        raise Refused('a check is written for a CVE match')
    if ctx.paused:
        raise Refused('scanning is paused')
    try:
        job = templategen.generate_template(row.match.cve_entry, project=ctx.project.pk, candidate_only=True)
    except templategen.TemplateBudgetExceeded as exc:
        raise Refused(str(exc)) from exc
    except ScannerUnavailable as exc:
        raise Refused('no scanner could check a draft now') from exc
    return 'started', f'AI job #{job.pk} writes a draft check (never run on a host until it has passed every gate)'


def _start_ask(ctx, target):
    from cveFeed import notify
    notify.host_needs_person(ctx.host)
    return 'done', 'a person is asked to look at the host'


def _start_none(ctx, target):
    return 'done', 'nothing to do'


def _start_rescan(ctx, target):
    from cveFeed.tasks import host_pipeline
    domain, host = ctx.gate()
    host_pipeline.delay(domain.id, [host], by_person=ctx.by is not None and not ctx.agent)
    return 'started', 'a rescan of the host is queued'


def _start_assess(ctx, target):
    from cveFeed import host_assessment
    ctx.gate()
    try:
        job, created = host_assessment.enqueue(ctx.project, ctx.sub, source=SOURCE, user=ctx.by, unattended=True if ctx.unattended else None)
    except ValueError as exc:
        raise Refused(str(exc)) from exc
    except RuntimeError as exc:
        raise Refused(str(exc)) from exc
    if not created:
        raise Refused('an assessment of this host is already queued or running')
    if job.status == 'failed':
        raise Refused(job.error or 'the assessment could not be queued')
    return 'started', f'host assessment #{job.pk} queued'


def _start_hygiene(ctx, target):
    from cveFeed.tasks import run_hygiene_task
    domain, _host = ctx.gate()
    run_hygiene_task.delay(domain.id)
    return 'started', 'the hygiene checks of the target are queued'


_RUN = {'none': _start_none, 'validate_match': _start_validate, 'revalidate_finding': _start_revalidate, 'screenshot': _start_screenshot,
        'draft_check': _start_draft, 'ask_person': _start_ask, 'rescan_host': _start_rescan, 'assess_host': _start_assess, 'run_hygiene': _start_hygiene}


def run(action, target, project, sub, by=None, rows=None, agent=False):
    """Start one action for one host and say what happened: ``{'action', 'target', 'state', 'detail'}`` with ``state`` ``started`` (queued, running on
    its own), ``done`` (finished at once) or ``refused`` (and why: nothing was started). Never raises. Anything that is not a registered action is
    refused; so is a registered one that is not in ``offered`` now for this host, or a target that is not one of its refs. Each action then passes
    its own function's gates. ``by`` is the person who started it (None: the review itself); ``agent`` says an API key or an agent pressed Start for that user: the user is kept
    for the record, but every gate is the unattended one (a bug bounty project that has not confirmed automated testing, a manual-only target). ``rows`` is ``[(ref, Triage)]``, the findings the
    refs name (``host_review.pairs_from_refs`` for a stored review); without it the host's open findings are read in packet order."""
    result = {'action': str(action)[:24], 'target': str(target or '')[:12], 'state': 'refused', 'detail': ''}
    try:
        if action not in ACTIONS:
            result['detail'] = 'not an action the review may take'
            return result
        if rows is None:
            from cveFeed import host_review
            rows = host_review.pairs(project, sub.name.lower()) if sub is not None else []
        ctx = _Ctx(project, sub, rows, by=by, agent=agent)
        found = offered(project, sub, ctx.pairs, by=by, unattended=ctx.unattended).get(action)
        if found is None:
            result['detail'] = 'not offered for this host now'
            return result
        target = str(target or '')
        if action in TARGETED:
            if target not in found['targets']:
                result['detail'] = 'that finding is not offered for this action'
                return result
        elif target:
            result['detail'] = 'this action takes no target'
            return result
        state, detail = _RUN[action](ctx, target)
        result.update(state=state, detail=str(detail)[:300])
    except Refused as exc:
        result['detail'] = str(exc)[:300]
    except Exception as exc:  # noqa: BLE001 - an action that breaks is refused, never raised into the review
        logger.exception('host review action %s failed', action)
        result['detail'] = f'could not be started ({type(exc).__name__})'
    return result
