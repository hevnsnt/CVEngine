from django.apps import AppConfig


class AgentapiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'agentapi'

    def ready(self):
        from django.db.models.signals import post_save
        from agentapi.models import SentinelTask
        post_save.connect(_sentinel_task_saved, sender=SentinelTask, dispatch_uid='agentapi.sentinel_task_queued')


def _sentinel_task_saved(sender, instance, created, **kwargs):
    """A SentinelTask was queued, by whatever made it (a stage, the OpenVAS sweep, a kind added later): wake the long polls of the Sentinels that
    could take it (``sentinel_notify.task_queued``, after the transaction commits)."""
    if created and instance.status == 'queued':
        from agentapi import sentinel_notify
        sentinel_notify.task_queued(instance)
