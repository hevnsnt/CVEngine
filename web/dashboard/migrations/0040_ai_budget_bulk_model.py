from django.db import migrations, models


class Migration(migrations.Migration):
    """The AI money budget (a monthly and a daily limit in USD, both unset) and the bulk model of the high-volume AI stages (empty: the
    provider's cheapest current model; the switch on). Every column is nullable or has a database default, so code of the version before can
    still save the AI settings row during an update or after a rollback."""

    dependencies = [('dashboard', '0039_ct_fallback_source')]

    operations = [
        migrations.AddField(model_name='aiprovidersettings', name='bulk_model',
                            field=models.CharField(blank=True, default='', db_default='', max_length=200)),
        migrations.AddField(model_name='aiprovidersettings', name='use_bulk_model',
                            field=models.BooleanField(default=True, db_default=True)),
        migrations.AddField(model_name='aiprovidersettings', name='monthly_budget_usd',
                            field=models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
        migrations.AddField(model_name='aiprovidersettings', name='daily_budget_usd',
                            field=models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
    ]
