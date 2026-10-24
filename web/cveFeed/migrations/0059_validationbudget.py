from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0058_ondemand_retry_backoff')]
    operations = [
        migrations.CreateModel(
            name='ValidationBudget',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.DateField()),
                ('scope', models.CharField(max_length=64)),
                ('reserved', models.PositiveIntegerField(default=0)),
            ],
            options={'constraints': [models.UniqueConstraint(fields=('day', 'scope'), name='uniq_validation_budget_day_scope')]},
        ),
    ]
