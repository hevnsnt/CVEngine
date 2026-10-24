"""Factory reset: put the instance back to a fresh install and send the administrator through onboarding again.

Superuser only (the settings API enforces it, and asks for a typed phrase plus the administrator's password).

Removed: every organization, project, target, host and scan with everything under them (IPs, ports, findings,
screenshots, reports, notes), every user except the administrator who runs the reset, memberships, API tokens, the AI
settings, API vault, notification/proxy/report settings, IP allowlist, bans and strikes, the audit log, the CVE feed and
matches, generated templates, AI activity, update settings, scheduled scans, other sessions, and the files under the
scan-results directory.

Kept: the administrator's own account (password and two-step sign-in untouched, so they can still sign in; only the
"finished onboarding" flag is cleared), scan engines, wordlists and the installed tools, and the system schedules.
Afterwards the instance has the untouched "Default" organization and project of a new install, and the first-run wizard
starts again.
"""
import logging
import os

from django.apps import apps
from django.core.cache import cache
from django.db import transaction
from django.db.models import ProtectedError
from django.utils import timezone

logger = logging.getLogger(__name__)

CONFIRM_PHRASE = 'FACTORY RESET'
WIPE_APPS = ('startScan', 'targetApp', 'recon_note', 'cveFeed', 'dashboard')
# The acting administrator's own rows survive (the other users' cascade away with them).
KEEP_MODELS = {'dashboard.userprofile', 'dashboard.userpreferences'}
WIPE_SCAN_MODELS = ('scanEngine.notification', 'scanEngine.proxy', 'scanEngine.vulnerabilityreportsetting')
RUNNING_STATUSES = (-1, 1)  # initiated, running


def running_scans():
    from startScan.models import ScanHistory
    return ScanHistory._base_manager.filter(scan_status__in=RUNNING_STATUSES).count()


def plan(actor):
    """What a reset would remove, for the confirmation screen."""
    from django.contrib.auth.models import User
    from dashboard.models import Org, Project
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    return {
        'organizations': Org._base_manager.count(), 'projects': Project._base_manager.count(),
        'targets': Domain._base_manager.count(), 'hosts': Subdomain._base_manager.count(),
        'scans': ScanHistory._base_manager.count(), 'users': User.objects.exclude(pk=actor.pk).count(),
        'running_scans': running_scans(),
    }


def _models_to_wipe():
    models = []
    for label in WIPE_APPS:
        for model in apps.get_app_config(label).get_models():
            if model._meta.managed and not model._meta.proxy and model._meta.label_lower not in KEEP_MODELS:
                models.append(model)
    for label in WIPE_SCAN_MODELS:
        try:
            models.append(apps.get_model(label))
        except LookupError:
            pass
    return models


def _wipe(models):
    """Delete every row, unscoped. Cascades take most of it; a model blocked by PROTECT is retried after the rest."""
    pending = list(models)
    for _ in range(4):
        blocked = []
        for model in pending:
            try:
                model._base_manager.all().delete()
            except ProtectedError:
                blocked.append(model)
        if not blocked:
            return
        pending = blocked
    raise RuntimeError('could not delete: ' + ', '.join(m._meta.label for m in pending))


def _clear_files():
    from cveFeed import templategen, updater
    from reNgine.common_func import SCAN_RESULTS_ROOT, safe_remove_path
    for root in (SCAN_RESULTS_ROOT, templategen.GENERATED_DIR):
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for entry in entries:
            safe_remove_path(os.path.join(root, entry), root)
    updater._remove_flag()


def reset(actor, keep_session_key=None):
    """Do the reset. Returns the counts that were removed. The caller has already verified the administrator."""
    from django.contrib.auth.models import User
    from django.contrib.sessions.models import Session
    from django_celery_beat.models import PeriodicTask
    from dashboard.models import AuditLog, Org, Project, SystemTimings, UserProfile
    removed = plan(actor)
    with transaction.atomic():
        _wipe(_models_to_wipe())
        User.objects.exclude(pk=actor.pk).delete()
        sessions = Session.objects.all()
        if keep_session_key:
            sessions = sessions.exclude(session_key=keep_session_key)
        sessions.delete()
        PeriodicTask.objects.exclude(name__startswith='cvengine-').exclude(name='celery.backend_cleanup').delete()
        org = Org.objects.create(name='Default', slug='default')
        Project.objects.create(name='Default', slug='default', insert_date=timezone.now(), org=org)
        UserProfile.objects.update_or_create(user=actor, defaults={'onboarded': False, 'must_change_password': False})
    cache.clear()
    try:
        from cveFeed.admin_api import apply_timings
        apply_timings(SystemTimings())  # schedules back to the shipped defaults
    except Exception:  # noqa: BLE001 - a reset that worked must not report failure over a schedule tweak
        logger.exception('could not restore the default schedules after a factory reset')
    _clear_files()
    AuditLog.objects.create(actor=actor, actor_name=actor.username, action='system.factory_reset', target='instance', detail=removed)
    logger.warning('factory reset performed by %s: %s', actor.username, removed)
    return removed
