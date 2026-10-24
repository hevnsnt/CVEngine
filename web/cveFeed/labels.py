"""Host labels: short informational chips ("WAF", "nginx version") for what a scanner detected that is not a finding."""
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)


def record_label(project_id, domain_id, host, label, detail='', source='bbot', kind='detection'):
    """Add a label to a host, or move its ``last_seen`` when it is already there. Bounded (``HostLabel.MAX_PER_HOST`` per host), lowercase
    host, never raises: a label is decoration, so a failure must not cost the scan its findings. Returns the row or None."""
    from cveFeed.models import HostLabel
    host, label = (host or '').strip().lower(), (label or '').strip()[:64]
    if not (project_id and domain_id and host and label):
        return None
    try:
        now = timezone.now()
        row = HostLabel.objects.filter(project_id=project_id, host=host, label=label).first()
        if row:
            HostLabel.objects.filter(pk=row.pk).update(last_seen=now)
            return row
        if HostLabel.objects.filter(project_id=project_id, host=host).count() >= HostLabel.MAX_PER_HOST:
            return None
        row, _ = HostLabel.objects.get_or_create(project_id=project_id, host=host, label=label, defaults={
            'domain_id': domain_id, 'kind': kind, 'source': source, 'detail': (detail or '')[:300], 'first_seen': now, 'last_seen': now})
        return row
    except Exception:  # noqa: BLE001
        logger.exception('could not record host label %s on %s', label, host)
        return None
