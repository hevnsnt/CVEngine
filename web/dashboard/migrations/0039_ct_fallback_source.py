from django.db import migrations, models


class Migration(migrations.Migration):
    """The switch of the certificate transparency watch's second source (Cert Spotter, asked when crt.sh cannot answer): on, with a
    database default, so code of the version before can still save the timings row during an update or after a rollback."""

    dependencies = [('dashboard', '0038_auditlog_action_id_idx')]

    operations = [
        migrations.AddField(model_name='systemtimings', name='ct_fallback_source',
                            field=models.BooleanField(default=True, db_default=True)),
    ]
