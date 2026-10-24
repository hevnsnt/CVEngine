from django.db import migrations, models
from django.utils import timezone


def expire_unbound_requests(apps, schema_editor):
    OnDemand = apps.get_model('cveFeed', 'OnDemandValidation')
    Automatic = apps.get_model('cveFeed', 'AutomaticValidation')
    # Earlier jobs did not retain their bearer identity. Never silently treat
    # an unknown manual request (including a deleted user) as automatic work.
    OnDemand.objects.all().update(source='legacy')
    values = dict(status='failed', finished_at=timezone.now(), next_attempt_at=None,
                  error='request authority predates this upgrade; submit a new request')
    OnDemand.objects.filter(status__in=['queued', 'running']).update(**values)
    Automatic.objects.filter(source='manual', status__in=['queued', 'running']).update(**values)


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0059_validationbudget')]
    operations = [
        migrations.AddField(model_name='ondemandvalidation', name='source',
                            field=models.CharField(default='automatic', max_length=12)),
        migrations.AddField(model_name='ondemandvalidation', name='requested_token_id',
                            field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name='automaticvalidation', name='requested_token_id',
                            field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.RunPython(expire_unbound_requests, migrations.RunPython.noop),
    ]
