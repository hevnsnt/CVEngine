"""The first-run setup wizard (/cve/welcome/, API /cve/api/welcome/): what the server keeps, decides and does for each step.

The wizard is meant to be the way an install is set up: the installer only starts the stack and prints a URL. It asks for what a discovery
needs first (organization, project, ONE seed domain) and starts a bbot discovery of that domain at once, in the background, then asks the
setup questions while it runs, so the dashboard already has findings the first time it opens.

Steps, in order (``STEPS``): ``seed`` (organization, project, seed domain; starts discovery), ``plan`` (internal scanner, internal plus external
Sentinels, or external only), ``scanners`` (which scanner kinds run, OpenVAS in its own group, off unless asked for), ``extras`` (AI model,
notifications, time zone, your password: each skippable) and ``build`` (the transparent "building" screen, then the dashboard).

Everything is stored on the server (``dashboard.SetupWizard``), so the wizard resumes from any browser, every step can be run again, and nothing
a person saved is lost. Nothing secret is kept here: a key or webhook goes into its own settings row when entered and is never sent back.
Writes are App Admin only, CSRF-protected by Django's middleware like every other POST, and rate limited per user.

Scanner settings use what already exists: the instance defaults of ``agentapi.sentinel_settings`` (``builtin_kinds`` for the install's own
scanner, ``external_kinds`` for every other Sentinel) and, for OpenVAS, ``cveFeed.openvas_admin``'s switch. Nothing here runs a scan itself.
"""
import logging
import os
from datetime import timedelta
from urllib.parse import urlparse

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

STEPS = ('seed', 'plan', 'scanners', 'extras', 'build')
PLANS = ('internal', 'both', 'external')
WHERES = ('internal', 'external', 'both')
EXTRAS = ('ai', 'notify', 'timezone', 'password')
DEFAULT_DWELL_SECONDS = 90
ENOUGH_HOSTS = 10  # findings that end the wait early: the dashboard already has something to show
LIVE_WINDOW = timedelta(minutes=3)  # a Sentinel heard from this recently is live (the broker's own window)
REQUEUE_EVERY = 30  # seconds between two tries to start a discovery that found no scanner
MAX_ENROLLMENTS_SHOWN = 5


class WizardError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


# --- the plain-language families of scanner kinds -----------------------------------------------------------------------------------------------

# (family id, title, what it does, kinds). A kind in no family is not asked about and keeps whatever the capability policy says (the default: on).
FAMILIES = (
    ('discovery', 'Finding hosts', 'Subdomains, addresses and certificates: how cvENGINE learns what you own. Always on.',
     ('bbot_discovery', 'discover', 'dns_resolve', 'alive_check', 'identity_check', 'dangling_dns_check')),
    ('web', 'Websites', 'Web fingerprints, hidden routes, virtual hosts, cloud storage and supplier checks.',
     ('http_probe', 'waf', 'vhost_probe', 'subdir_probe', 'route_probe', 'route_probe_signed', 'page_read', 'path_probe', 'bucket_check', 'supplier_check')),
    ('network', 'Open ports and services', 'Which ports answer and which service and version is behind them. Includes the heavy full-port and UDP sweeps.',
     ('nmap', 'naabu', 'nmap_full', 'nmap_verify', 'nmap_udp', 'db_probe')),
    ('tls_mail', 'Certificates and email', 'TLS configuration, expiring certificates, SPF, DKIM and DMARC.', ('testssl', 'hygiene_check')),
    ('ssh', 'SSH', 'A read-only look at the SSH services that answer: their software version, key types and sizes, and whether a host key is on the list of compromised keys. No login is ever attempted.',
     ('ssh_probe',)),
    ('secrets', 'Exposed secrets (Kingfisher)', 'Looks for keys and tokens left in public files and repositories.', ('secrets_scan',)),
    ('screenshots', 'Screenshots', 'A picture of each web page and remote desktop login. Needs a browser, so it is the hungriest of the light checks.',
     ('web_screenshot', 'rdp_shot')),
    ('wordpress', 'WordPress', 'WordPress core, plugin and theme checks. The thorough pass takes much longer.', ('wpscan', 'wpscan_thorough')),
    ('nuclei', 'Known-issue templates (nuclei)', 'Thousands of fast checks for known misconfigurations and CVEs. The deep pass runs them all.',
     ('nuclei_light', 'nuclei_targeted', 'nuclei_validate', 'nuclei_deep')),
)
LOCKED_ON = ('bbot_discovery', 'discover')  # without them nothing is ever found: not offered as a choice
HEAVY = ('nmap_full', 'nmap_udp', 'nuclei_deep', 'wpscan_thorough', 'web_screenshot', 'rdp_shot')  # off by default on a small machine
SMALL_MEMORY_GB = 6
OPENVAS_COST = ('OpenVAS is a second, much heavier scanner: it needs about 4 GB of memory, 2 CPUs and 60 GB of disk on the machine that runs it, '
                'and its first feed download takes hours. It is off unless you turn it on.')


def family_kinds():
    return [k for _, _, _, kinds in FAMILIES for k in kinds]


def memory_gb():
    """Total memory of this machine in GB (the scanner shares the host with this server on a single machine), or ``None`` when it cannot be read."""
    try:
        with open('/proc/meminfo') as handle:
            for line in handle:
                if line.startswith('MemTotal:'):
                    return round(int(line.split()[1]) / 1024 / 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    return None


def suggested_off(memory=None):
    """The kinds switched off by default: none on a machine with enough memory, the heavy ones on a small VPS (``None`` memory counts as small)."""
    memory = memory_gb() if memory is None else memory
    return [] if memory is not None and memory >= SMALL_MEMORY_GB else sorted(HEAVY)


def families_payload(off):
    from agentapi.sentinel_policy import label
    off = set(off)
    return [{'id': fid, 'title': title, 'about': about,
             'kinds': [{'kind': k, 'label': label(k), 'on': k not in off, 'locked': k in LOCKED_ON, 'heavy': k in HEAVY} for k in kinds]}
            for fid, title, about, kinds in FAMILIES]


# --- state ---------------------------------------------------------------------------------------------------------------------------------

def wizard_row():
    from dashboard.models import SetupWizard
    row = SetupWizard.objects.order_by('id').first()
    if row is None:
        row = SetupWizard.objects.create()
    return row


def _store(row, **changes):
    data = dict(row.data or {})
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    row.data = data
    row.save(update_fields=['data'])
    return data


def _mark(row, step, how):
    steps = dict((row.data or {}).get('steps') or {})
    steps[step] = how
    _store(row, steps=steps)


def _started(row):
    if row.started_at is None:
        row.started_at = timezone.now()
        row.save(update_fields=['started_at'])


def needs_wizard(user):
    """Whether this person is sent to the wizard: an App Admin, until it is completed. A wizard somebody has started always resumes. An install that
    already holds targets (an upgrade, or one set up by hand) is never taken to it; ``?skip=1`` on the dashboard also leaves it."""
    if not (user.is_authenticated and user.is_superuser):
        return False
    from dashboard.models import Project, SetupWizard
    row = SetupWizard.objects.order_by('id').first()
    if row is not None and row.completed_at:
        return False
    if row is not None and row.started_at:
        return True
    from targetApp.models import Domain
    if Domain._base_manager.exists():
        return False
    from dashboard.models import UserProfile
    if UserProfile.objects.filter(user=user, onboarded=True).exists() and Project.objects.exists():
        return False
    return True


def next_step(data):
    steps = (data or {}).get('steps') or {}
    return next((s for s in STEPS[:-1] if s not in steps), 'build')


# --- limits --------------------------------------------------------------------------------------------------------------------------------

LIMITS = {'write': (60, 600), 'seed': (12, 600), 'provision': (8, 600), 'progress': (120, 60)}


def limit(user, bucket):
    """A fixed window per user and kind of request: the wizard is a handful of clicks, so these are generous for a person and short for a script."""
    count, window = LIMITS[bucket]
    key = f'wizard-limit:{bucket}:{user.pk}'
    cache.add(key, 0, window)
    try:
        used = cache.incr(key)
    except ValueError:  # the key expired between add and incr
        cache.set(key, 1, window)
        used = 1
    if used > count:
        raise WizardError(429, 'Too many requests from this account just now; wait a minute and try again.')


# --- the seed step -------------------------------------------------------------------------------------------------------------------------

def clean_domain(value):
    """The one seed domain, lower case, or ``WizardError``. A domain only (no address, range, URL or wildcard), and one the existing target rules
    allow: nothing that resolves to a loopback, link-local or internal address (``targetApp.target_types``)."""
    from targetApp import target_types
    text = str(value or '').strip().lower()
    for prefix in ('https://', 'http://'):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.split('/')[0].strip().rstrip('.')
    if not text:
        raise WizardError(400, 'Enter the domain you want to start with, for example example.com.')
    if text.startswith('*.'):
        text = text[2:]
    if target_types.classify_target(text) != target_types.DOMAIN:
        raise WizardError(400, f'"{text[:80]}" is not a domain name. Enter one domain such as example.com (an address or range can be added later in Targets).')
    if target_types.resolves_to_blocked(text):
        raise WizardError(400, f'{text} points at a loopback, link-local or internal address, which cannot be scanned from here '
                               '(an operator can allow internal ranges with CVENGINE_ALLOW_PRIVATE_TARGETS=1).')
    return text


def _clean_name(value, what):
    name = ' '.join(str(value or '').split())[:100]
    if len(name) < 2:
        raise WizardError(400, f'Give your {what} a name (2 or more characters).')
    return name


def save_seed(request):
    """Organization, project and the seed domain in one step: create or rename them, add the target and start its discovery. Safe to send again:
    the same values change nothing and start nothing a second time; another name renames; another domain is added beside the first."""
    from agentapi import services
    from cveFeed import discovery, welcome
    from tenancy import roles
    body = welcome._body(request)
    org_name, project_name = _clean_name(body.get('org'), 'organization'), _clean_name(body.get('project'), 'project')
    if roles.is_reserved_project(project_name):
        raise WizardError(400, f'"{roles.ALL_PROJECTS}" is reserved for the all-projects view; choose another project name.')
    domain = clean_domain(body.get('domain'))
    if not body.get('authorized'):
        raise WizardError(400, 'Confirm you are authorized to test this domain.')
    limit(request.user, 'seed')
    with transaction.atomic():
        row = wizard_row()
        _started(row)
        kick_builtin_scanner()
        org, project = _own_org_and_project(row, request.user, org_name, project_name)
        ctx = services.Ctx(user=request.user)
        try:
            result = services.add_target(ctx, project.slug, domain)
        except services.ApiError as exc:
            raise WizardError(exc.status, exc.message)
        _store(row, org={'name': org.name, 'slug': org.slug}, project={'name': project.name, 'slug': project.slug}, domain=domain)
        _mark(row, 'seed', 'done')
    started = start_discovery(row, project, domain)
    out = view(request)
    out['discovery_started'] = started
    out['added'] = [d['name'] for d in result['created']]
    return out


def _own_org_and_project(row, user, org_name, project_name):
    """The organization and project this wizard made, renamed in place when the step is sent again with other names (so the seed domain is not
    added to a second project); the first time, or when they are gone, they are created."""
    from dashboard.models import Org, Project
    data = row.data or {}
    org = Org.objects.filter(slug=(data.get('org') or {}).get('slug')).first() if data.get('org') else None
    project = Project.objects.filter(slug=(data.get('project') or {}).get('slug'), org=org).first() if org and data.get('project') else None
    if org is None or project is None:
        from cveFeed import welcome
        welcome.ensure_org(user, org_name)
        welcome.ensure_project(user, project_name)
        return welcome.wizard_org(user), welcome.wizard_project(user)
    if org.name != org_name:
        org.name = org_name
        org.save(update_fields=['name'])
    if project.name != project_name:
        project.name = project_name
        project.save(update_fields=['name'])
    return org, project


def start_discovery(row, project, domain):
    """Queue the seed domain's bbot discovery once. Returns whether a new one was queued. A discovery already queued, running or finished for this
    domain is left alone; one that ended because no scanner was there is queued again (``resume_discovery``) as soon as a scanner is live."""
    from cveFeed import discovery
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    target = Domain._base_manager.filter(name=domain, project=project).order_by('id').first()
    if target is None:
        return False
    disc = (row.data or {}).get('discovery') or {}
    if disc.get('domain') == domain and disc.get('scan_id'):
        previous = ScanHistory._base_manager.filter(pk=disc['scan_id'], domain=target).only('scan_status').first()
        if previous is not None and not _produced_nothing(previous):
            return False
        # the same step sent again after a discovery that ended with no host (refused, failed, stopped, or finished empty): it starts again, with a
        # fresh wait, instead of leaving the person on a screen that can only say it found nothing
        disc = {**disc, 'started_at': None, 'tries': 0}
    if not live_sentinels()['live']:
        # No scanner is live yet (a fresh install: the built-in one enrols within a minute of the installer finishing). A scan made now would be refused
        # at once and show as a failed scan in the list on a clean install, so it is not made: the wizard holds the discovery and ``resume_discovery`` starts
        # it, as one scan, the moment a scanner is live.
        now = timezone.now().isoformat()
        _store(row, discovery={'domain': domain, 'scan_id': None, 'pending': True, 'started_at': now, 'tries': 0, 'last_try': None})
        return True
    try:
        scans = discovery.start_in_stored_modes([target])  # the mode stored on the target; the same call the dashboard's own discovery uses
    except RuntimeError:  # no scan engine yet: a fresh install is still finishing its first start
        raise WizardError(503, 'cvENGINE is still finishing its first start. Your answers are saved; press Continue again in a few seconds.')
    scan = scans[0] if scans else None
    if scan is None:
        return False
    now = timezone.now().isoformat()
    _store(row, discovery={'domain': domain, 'scan_id': scan.id, 'started_at': disc.get('started_at') if disc.get('domain') == domain and disc.get('started_at') else now,
                           'tries': int(disc.get('tries') or 0) if disc.get('domain') == domain else 0, 'last_try': now})
    return True


def _produced_nothing(scan):
    """Whether a seed discovery has ended and found no host: nothing is running or queued for it and no name was stored under it."""
    from cveFeed import discovery
    from startScan.models import Subdomain
    if scan.scan_status in (discovery.QUEUED, discovery.RUNNING):
        return False
    return not Subdomain.objects.filter(scan_history_id=scan.pk).exists()


def resume_discovery(row, now=None):
    """A discovery that ended with \"waiting for a scanner\" (no Sentinel took it in the queue window) is queued again once one is live, at most every
    ``REQUEUE_EVERY`` seconds. Returns True when it was."""
    from cveFeed import discovery
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    data = row.data or {}
    disc = data.get('discovery') or {}
    now = now or timezone.now()
    if disc.get('pending') and not disc.get('scan_id'):  # held until a scanner is live (start_discovery): start it now, once
        if not live_sentinels(now)['live']:
            return False
        target = Domain._base_manager.filter(name=disc.get('domain')).order_by('id').first()
        scans = discovery.start_in_stored_modes([target]) if target is not None else []
        if not scans:
            return False
        _store(row, discovery={**disc, 'scan_id': scans[0].id, 'pending': False, 'tries': 0, 'last_try': now.isoformat()})
        return True
    if not disc.get('scan_id') or int(disc.get('tries') or 0) >= 20:
        return False
    last = _parse(disc.get('last_try'))
    if last and (now - last).total_seconds() < REQUEUE_EVERY:
        return False
    scan = ScanHistory._base_manager.filter(pk=disc['scan_id']).only('scan_status', 'error_message', 'domain_id').first()
    if scan is None or scan.scan_status != discovery.FAILED or 'waiting for a scanner' not in (scan.error_message or ''):
        return False
    if not live_sentinels(now)['live']:
        return False
    target = Domain._base_manager.filter(pk=scan.domain_id).first()
    if target is None:
        return False
    scans = discovery.start_in_stored_modes([target])
    if not scans:
        return False
    disc = {**disc, 'scan_id': scans[0].id, 'tries': int(disc.get('tries') or 0) + 1, 'last_try': now.isoformat()}
    _store(row, discovery=disc)
    return True


def _parse(text):
    from django.utils.dateparse import parse_datetime
    return parse_datetime(text) if text else None


# --- the plan and the scanner kinds --------------------------------------------------------------------------------------------------------

def builtin_state():
    """The built-in scanner as the wizard words it: whether this install runs it at all (CVENGINE_BUILTIN_SCANNER, set by the installer) and where
    it stands."""
    from agentapi import builtin_scanner
    out = builtin_scanner.status()
    if not out.get('enabled'):
        return {'enabled': False, 'enrolled': False, 'live': False, 'text': 'The built-in scanner is switched off on this install (the installer was told '
                                                                              '"external Sentinels only").'}
    if not out.get('enrolled'):
        return {'enabled': True, 'enrolled': False, 'live': False, 'text': 'The built-in scanner is starting: it is being pulled and is about to enrol.'}
    if not out.get('live'):
        return {'enabled': True, 'enrolled': True, 'live': False, 'text': 'The built-in scanner is enrolled but has not reported in for a few minutes.'}
    return {'enabled': True, 'enrolled': True, 'live': True, 'text': 'The built-in scanner is ready.'}


KICK_EVERY = 20  # seconds between two requests to the worker to ready the built-in scanner's enrollment


def kick_builtin_scanner():
    """Ask the worker to ready the built-in scanner's enrollment now instead of at its next five-minute beat: the App Admin only just came into being, and
    the scanner container waits for the enrollment the server writes for it (the worker owns that volume). At most every ``KICK_EVERY`` seconds, and only
    while the built-in scanner is on and not yet live. Returns whether a request was sent."""
    from agentapi import builtin_scanner
    status = builtin_scanner.status()
    if not status.get('enabled') or status.get('live') or not cache.add('wizard-kick-builtin', 1, KICK_EVERY):
        return False
    try:
        from cveFeed.tasks import ensure_builtin_scanner
        ensure_builtin_scanner.delay()
    except Exception:  # the broker is not up yet: the beat does it within five minutes, and the next poll asks again
        logger.warning('setup wizard: could not ask the worker to enrol the built-in scanner', exc_info=True)
        return False
    return True


def live_sentinels(now=None):
    """``{live, builtin, external}``: Sentinels heard from in the last three minutes that may take work, from two bounded queries (the built-in scanner is
    the one the server's own enrollment made, never what a Sentinel says about itself)."""
    from agentapi import builtin_scanner
    from agentapi.models import Agent
    now = now or timezone.now()
    ids = set(Agent.objects.filter(kind='scanner', status='active', last_seen__gte=now - LIVE_WINDOW).values_list('id', flat=True)[:200])
    own = builtin_scanner.builtin_agent()
    builtin = 1 if own is not None and own.pk in ids else 0
    return {'live': len(ids), 'builtin': builtin, 'external': len(ids) - builtin}


def save_plan(request):
    from cveFeed import welcome
    plan = str(welcome._body(request).get('plan') or '')
    if plan not in PLANS:
        raise WizardError(400, f'Choose one of: {", ".join(PLANS)}.')
    if plan != 'external' and not builtin_state()['enabled']:
        raise WizardError(409, 'The built-in scanner is switched off on this install, so "internal" and "both" are not available here. Choose external '
                               'Sentinels only, or ask whoever installed cvENGINE to switch the built-in scanner on (CVENGINE_BUILTIN_SCANNER).')
    limit(request.user, 'write')
    row = wizard_row()
    _started(row)
    _store(row, plan=plan)
    _mark(row, 'plan', 'done')
    apply_scanner_policy(row, request.user)
    return view(request)


def _openvas_choice(data):
    choice = data.get('openvas') or {}
    plan = data.get('plan') or 'internal'
    where = choice.get('where') if choice.get('where') in WHERES else {'internal': 'internal', 'external': 'external', 'both': 'both'}[plan]
    if plan == 'internal':
        where = 'internal'
    elif plan == 'external':
        where = 'external'
    return bool(choice.get('enabled')), where


def build_policy(data, final=False):
    """``(builtin_kinds, external_kinds)`` the wizard stores as the instance defaults: kinds the person switched off are denied for both classes,
    OpenVAS is denied wherever it was not asked for, and external only denies the built-in scanner every kind (but the seed discovery, until the wizard
    is finished, so the first discovery is not stranded)."""
    from agentapi.models import SentinelTask
    off = set(data.get('off_kinds') if data.get('off_kinds') is not None else suggested_off()) - set(LOCKED_ON)
    enabled, where = _openvas_choice(data)
    builtin, external = {}, {}
    for kind in sorted(off):
        builtin[kind] = external[kind] = {'mode': 'deny', 'max_concurrent': None}
    if not (enabled and where in ('internal', 'both')):
        builtin['openvas'] = {'mode': 'deny', 'max_concurrent': None}
    if not (enabled and where in ('external', 'both')):
        external['openvas'] = {'mode': 'deny', 'max_concurrent': None}
    if (data.get('plan') or 'internal') == 'external':
        for kind in SentinelTask.KINDS:
            if kind == 'bbot_discovery' and not final:
                continue
            builtin[kind] = {'mode': 'deny', 'max_concurrent': None}
    return builtin, external


def apply_scanner_policy(row, actor, final=False):
    """Write the plan and the kind choices to the existing instance defaults, and the OpenVAS switch. Idempotent: the same choices write the same maps."""
    from agentapi import sentinel_settings
    builtin, external = build_policy(row.data or {}, final=final)
    sentinel_settings.set_defaults(actor, {'builtin_kinds': builtin, 'external_kinds': external})
    apply_openvas(row, actor)


def apply_openvas(row, actor):
    """Switch the OpenVAS add-on to what the wizard recorded. Off is the default and is only written when the wizard itself switched it on before; it
    never turns off a switch an administrator set."""
    from cveFeed import openvas_admin
    from cveFeed.models import OpenvasOrg, OpenvasSettings
    from dashboard.models import Org
    data = row.data or {}
    enabled, _ = _openvas_choice(data)
    settings_row = OpenvasSettings.current()
    if enabled:
        if not settings_row.enabled:
            settings_row.enabled, settings_row.updated_by = True, actor
            settings_row.save()
            openvas_admin.set_schedule(True)
            _store(row, openvas_switched_on_by_wizard=True)
        org = Org.objects.filter(slug=(data.get('org') or {}).get('slug')).first()
        if org is not None:
            link = OpenvasOrg.objects.filter(org=org).first() or OpenvasOrg(org=org)
            if not link.enabled:
                link.enabled, link.updated_by = True, actor
                link.save()
    elif data.get('openvas_switched_on_by_wizard') and settings_row.enabled:
        settings_row.enabled, settings_row.updated_by = False, actor
        settings_row.save()
        openvas_admin.set_schedule(False)
        _store(row, openvas_switched_on_by_wizard=None)


def save_scanners(request):
    from cveFeed import welcome
    body = welcome._body(request)
    limit(request.user, 'write')
    row = wizard_row()
    known = set(family_kinds())
    wanted = body.get('kinds')
    if wanted is not None:
        if not isinstance(wanted, dict) or any(k not in known for k in wanted) or any(not isinstance(v, bool) for v in wanted.values()):
            raise WizardError(400, 'kinds must say true or false for each scanner type in the list.')
        current = set((row.data or {}).get('off_kinds') if (row.data or {}).get('off_kinds') is not None else suggested_off())
        for kind, on in wanted.items():
            (current.discard if on or kind in LOCKED_ON else current.add)(kind)
        _store(row, off_kinds=sorted(current))
    ov = body.get('openvas')
    if ov is not None:
        if not isinstance(ov, dict) or not isinstance(ov.get('enabled', False), bool) or ov.get('where', 'internal') not in WHERES:
            raise WizardError(400, 'openvas must be {enabled: true or false, where: internal, external or both}.')
        plan = (row.data or {}).get('plan') or 'internal'
        if ov.get('enabled') and ov.get('where') == 'external' and plan == 'internal':
            raise WizardError(400, 'You chose the internal scanner only, so OpenVAS can only run there. Go back and add external Sentinels, or choose internal.')
        if ov.get('enabled') and ov.get('where') == 'internal' and plan == 'external':
            raise WizardError(400, 'You chose external Sentinels only, so OpenVAS can only run on one of them.')
        _store(row, openvas={'enabled': bool(ov.get('enabled')), 'where': ov.get('where') or ('external' if plan == 'external' else 'internal')})
    _started(row)
    _mark(row, 'scanners', 'done')
    apply_scanner_policy(row, request.user)
    return view(request)


# --- external Sentinels: the real enrollment, inside the wizard ---------------------------------------------------------------------

def provision(request):
    """Generate a one-time enrollment for an external Sentinel scoped to the wizard's organization and return the install command. The secret is shown
    once, in this response; only the enrollment's id is kept, to poll whether it was used."""
    from agentapi import sentinel_broker
    from agentapi import services
    from cveFeed import welcome
    body = welcome._body(request)
    profile = 'full' if body.get('profile') == 'full' else 'light'
    network = 'internal' if body.get('network') == 'internal' else 'external'
    limit(request.user, 'provision')
    row = wizard_row()
    org = (row.data or {}).get('org') or {}
    if not org.get('slug'):
        raise WizardError(409, 'Name your organization first (step 1): a Sentinel is enrolled for it.')
    try:
        out = sentinel_broker.generate_org_enrollment_blob(services.Ctx(user=request.user), org['slug'], network, profile)
    except services.ApiError as exc:
        raise WizardError(exc.status, exc.message)
    from agentapi.models import SentinelEnrollment
    enrollment = SentinelEnrollment.objects.filter(token_hash=sentinel_broker._hash_enrollment(out['enrollment_token'])).first()
    ids = [i for i in ((row.data or {}).get('enrollments') or [])][-(MAX_ENROLLMENTS_SHOWN - 1):]
    if enrollment is not None:
        ids.append(enrollment.pk)
    _store(row, enrollments=ids)
    return {'command': out['setup']['one_liner'], 'expires_at': out['expires_at'], 'profile': profile, 'network': network,
            'note': out['setup']['note'], 'enrollment_id': enrollment.pk if enrollment else None}


def enrollments_state(row, now=None):
    """The wizard's enrollments with the Sentinel each became, if any, for the live connection status: bounded to the last few."""
    from agentapi.models import SentinelEnrollment
    now = now or timezone.now()
    ids = ((row.data or {}).get('enrollments') or [])[-MAX_ENROLLMENTS_SHOWN:]
    out = []
    for e in SentinelEnrollment.objects.filter(pk__in=ids).select_related('used_by_agent').order_by('id'):
        agent = e.used_by_agent
        item = {'id': e.pk, 'expires_at': e.expires_at.isoformat(), 'expired': e.used_at is None and e.expires_at <= now, 'used': bool(e.used_at)}
        if agent is not None:
            item['agent'] = {'name': agent.name, 'status': agent.status,
                             'live': bool(agent.last_seen and now - agent.last_seen <= LIVE_WINDOW)}
        out.append(item)
    return out


# --- the optional extras -------------------------------------------------------------------------------------------------------------------

HOOKS = {'slack': ('slack_hook_url', 'send_to_slack', ('hooks.slack.com',)),
         'discord': ('discord_hook_url', 'send_to_discord', ('discord.com', 'discordapp.com'))}


def save_notify(request):
    """One Slack or Discord webhook for scan and finding notifications. The URL is a secret: stored encrypted, never returned (only whether it is set)."""
    from cveFeed import welcome
    from scanEngine.models import Notification
    body = welcome._body(request)
    kind = str(body.get('service') or '')
    if kind not in HOOKS:
        raise WizardError(400, 'Choose Slack or Discord. Telegram and the rest are in Settings > Notifications.')
    field, flag, hosts = HOOKS[kind]
    url = str(body.get('url') or '').strip()
    parsed = urlparse(url)
    if parsed.scheme != 'https' or (parsed.hostname or '') not in hosts or not parsed.path.strip('/'):
        raise WizardError(400, f'That does not look like a {kind.title()} webhook address (https://{hosts[0]}/...).')
    limit(request.user, 'write')
    row = Notification.objects.first() or Notification()
    setattr(row, field, url)
    setattr(row, flag, True)
    row.save()
    wiz = wizard_row()
    _started(wiz)
    _mark_extra(wiz, 'notify', 'done')
    return view(request)


def _mark_extra(row, name, how):
    extras = dict((row.data or {}).get('extras') or {})
    extras[name] = how
    _store(row, extras=extras)


def save_password(request):
    """The App Admin's own password, from the wizard: the Account page's change (current password required, the same strength rules, the same lockout),
    except that the built-in scanner's token, which belongs to this user, is not revoked while a discovery runs on it."""
    from cveFeed import account_api
    limit(request.user, 'write')
    try:
        account_api.change_password(request, keep_machine_tokens=True)
    except account_api.AccountError as exc:
        raise WizardError(exc.status, exc.message)
    row = wizard_row()
    _started(row)
    _mark_extra(row, 'password', 'done')
    return view(request)


def mark_extra(request):
    from cveFeed import welcome
    body = welcome._body(request)
    name, how = str(body.get('name') or ''), str(body.get('how') or '')
    if name not in EXTRAS or how not in ('done', 'skipped'):
        raise WizardError(400, f'name must be one of {", ".join(EXTRAS)} and how done or skipped.')
    limit(request.user, 'write')
    row = wizard_row()
    _started(row)
    _mark_extra(row, name, how)
    if all(e in ((row.data or {}).get('extras') or {}) for e in EXTRAS):
        _mark(row, 'extras', 'done')
    return view(request)


def skip_step(request):
    """Skip a whole step. Skipping the seed step is refused (nothing else can work without a project); the others keep their defaults: skipping
    ``plan`` keeps the built-in scanner, skipping ``scanners`` takes the suggested kinds with OpenVAS off."""
    from cveFeed import welcome
    step = str(welcome._body(request).get('step') or '')
    if step not in STEPS[1:-1]:
        raise WizardError(400, f'Only these steps can be skipped: {", ".join(STEPS[1:-1])}.')
    limit(request.user, 'write')
    row = wizard_row()
    _started(row)
    _mark(row, step, 'skipped')
    if step in ('plan', 'scanners'):
        apply_scanner_policy(row, request.user)
    return view(request)


# --- the building screen -------------------------------------------------------------------------------------------------------------------

def dwell_seconds():
    """How long a discovery is given before the dashboard opens with nothing found yet (``CVENGINE_SETUP_DWELL_SECONDS``, default 90, 0 turns the wait off)."""
    try:
        return max(0, min(900, int(os.environ.get('CVENGINE_SETUP_DWELL_SECONDS', DEFAULT_DWELL_SECONDS))))
    except ValueError:
        return DEFAULT_DWELL_SECONDS


def progress(request, now=None):
    """What the building screen shows, from a few bounded queries: whether a Sentinel is ready, whether the discovery is queued, running or done,
    how many hosts it has found, and whether the wait is over. Also requeues a discovery that found no scanner, once one is live."""
    from cveFeed import discovery
    from cveFeed.models import DiscoveryEvent
    from startScan.models import ScanHistory, Subdomain
    limit(request.user, 'progress')
    now = now or timezone.now()
    row = wizard_row()
    data = row.data or {}
    resume_discovery(row, now)
    data = row.data or {}
    disc = data.get('discovery') or {}
    live = live_sentinels(now)
    if not live['builtin']:
        kick_builtin_scanner()
    out = {'sentinel': {**live, 'builtin_state': builtin_state()}, 'discovery': None, 'dwell': {'min_seconds': dwell_seconds()}}
    started = _parse(disc.get('started_at'))
    elapsed = int((now - started).total_seconds()) if started else None
    found = 0
    if disc.get('scan_id'):
        scan = ScanHistory._base_manager.filter(pk=disc['scan_id']).select_related('domain').only(
            'scan_status', 'error_message', 'domain__name').first()
        if scan is not None:
            found = Subdomain.objects.filter(scan_history_id=scan.pk).count()
            recent = list(DiscoveryEvent.objects.filter(scan_id=scan.pk, type='DNS_NAME').order_by('-id').values_list('host', flat=True)[:6])
            waiting = scan.scan_status == discovery.FAILED and 'waiting for a scanner' in (scan.error_message or '')
            state = ('queued' if scan.scan_status == discovery.QUEUED else 'running' if scan.scan_status == discovery.RUNNING
                     else 'done' if scan.scan_status == discovery.SUCCESS else 'waiting' if waiting else 'ended')
            out['discovery'] = {'scan_id': scan.pk, 'domain': scan.domain.name, 'state': state, 'hosts': found, 'recent': [h for h in recent if h],
                                'queue_position': discovery.queue_position(scan.pk) if state == 'queued' else None,
                                'error': (scan.error_message or '')[:290] if state == 'ended' else '',
                                'text': discovery_text(state, scan.domain.name, found, live['live'], scan.error_message if state == 'ended' else '')}
    if disc.get('pending') and not disc.get('scan_id'):  # held until a scanner is live: shown as queued, with no scan in the list yet
        out['discovery'] = {'scan_id': None, 'domain': disc.get('domain'), 'state': 'queued', 'hosts': 0, 'recent': [], 'queue_position': None, 'error': '',
                            'text': discovery_text('queued', disc.get('domain'), 0, False)}
    over = elapsed is None or elapsed >= out['dwell']['min_seconds']
    finished = bool(out['discovery'] and out['discovery']['state'] in ('done', 'ended'))
    ready = over or found >= ENOUGH_HOSTS or finished
    out['dwell'].update(elapsed=elapsed, ready=bool(ready), hold=not ready,
                        reason=('' if ready else 'Discovery found nothing yet, so the dashboard would open empty: giving it a little longer.' if not found
                                else f'Discovery has found {found} so far: giving it a little longer so the dashboard opens with more in it.'))
    out['next'] = next_step(data)
    out['completed'] = bool(row.completed_at)
    return out


def discovery_text(state, domain, found, live, reason=''):
    hosts = f'{found} host{"s" if found != 1 else ""}'
    if state == 'queued':
        return (f'Discovery of {domain} is queued and starts the moment a Sentinel takes it.' if live
                else f'Discovery of {domain} is queued. No Sentinel is connected yet, so it starts as soon as one is.')
    if state == 'running':
        return f'Discovering {domain}: {hosts} found so far.'
    if state == 'done':
        return f'Discovery of {domain} finished: {hosts} found.'
    if state == 'waiting':
        return (f'No Sentinel took the discovery of {domain} in time. It is queued again as soon as one is connected.' if not live
                else f'Queueing the discovery of {domain} again now that a Sentinel is connected.')
    reason = ' '.join(str(reason or '').split()).rstrip('. ')[:290]
    if reason:  # what the scanner or the server's own check said (for example that the name resolves to an internal address): shown, not guessed at
        return f'Discovery of {domain} ended early with {hosts} found: {reason}. You can start it again from Targets.'
    return f'Discovery of {domain} ended early with {hosts} found. You can start it again from Targets.'


def finish(request):
    """Complete the wizard: apply the final scanner policy (external only now denies the built-in scanner everything), mark the person onboarded, and
    store the completion so no admin is sent back. Safe to call again."""
    from cveFeed import welcome
    from dashboard.models import UserProfile
    limit(request.user, 'write')
    row = wizard_row()
    steps = (row.data or {}).get('steps') or {}
    for step in STEPS[1:-1]:
        steps.setdefault(step, 'skipped')
    _store(row, steps=steps)
    apply_scanner_policy(row, request.user, final=True)
    if not row.completed_at:
        row.completed_at, row.completed_by = timezone.now(), request.user.username
        row.save(update_fields=['completed_at', 'completed_by'])
        from tenancy import audit
        audit.record(request.user, 'setup.complete', 'setup wizard', plan=(row.data or {}).get('plan') or 'internal')
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    if not profile.onboarded:
        profile.onboarded = True
        profile.save(update_fields=['onboarded'])
    out = welcome.state(request)
    disc = (row.data or {}).get('discovery') or {}
    out['follow'] = disc.get('scan_id')
    out['project'] = ((row.data or {}).get('project') or {}).get('slug')
    return out


# --- the whole state -----------------------------------------------------------------------------------------------------------------------

def state_view(request):
    limit(request.user, 'progress')
    return view(request)


def view(request):
    """Everything the wizard page draws from: saved values (never a secret), step status and the step to resume at."""
    from cveFeed import welcome
    from dashboard.models import AIProviderSettings
    from scanEngine.models import Notification
    row = wizard_row()
    data = row.data or {}
    base = welcome.state(request)
    off = data.get('off_kinds') if data.get('off_kinds') is not None else suggested_off()
    ov_enabled, ov_where = _openvas_choice(data)
    plan = data.get('plan') or ('external' if not builtin_state()['enabled'] else 'internal')
    note = Notification.objects.first()
    ai = AIProviderSettings.objects.first()
    return {
        **base,
        'steps': data.get('steps') or {}, 'next': next_step(data), 'extras': data.get('extras') or {}, 'completed': bool(row.completed_at),
        'seed': {'org': (data.get('org') or {}).get('name') or '', 'project': (data.get('project') or {}).get('name') or '', 'domain': data.get('domain') or ''},
        'plan': plan, 'plan_chosen': 'plan' in (data.get('steps') or {}),
        'builtin': builtin_state(),
        'families': families_payload(off), 'suggested_off': suggested_off(), 'memory_gb': memory_gb(),
        'openvas': {'enabled': ov_enabled, 'where': ov_where, 'cost': OPENVAS_COST},
        'enrollments': enrollments_state(row),
        'notify': {'slack': bool(note and note.slack_hook_url), 'discord': bool(note and note.discord_hook_url)},
        'ai': {'connected': bool(ai and ai.enabled), 'provider': ai.provider if ai and ai.enabled else ''},
        'dwell_seconds': dwell_seconds(),
    }
