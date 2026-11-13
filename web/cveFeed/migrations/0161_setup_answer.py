"""1.4.0 questions about an update (``cveFeed.setup_questions``): the table that records what an administrator answered, and the AI reviewer's two
switches shipping off.

This migration creates the table and answers nothing: it writes no row. ``ReviewerSettings.enabled`` and ``auto_close`` change their Python default
from true to false (the row is created on first use, so a new install and an upgrade both get it off); no column changes, so nothing is rewritten.
0162 turns off the rows that already exist and that no person has touched.
"""
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0160_fix_retest'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SetupAnswer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=60, unique=True)),
                ('answer', models.CharField(max_length=60)),
                ('answered_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('answered_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterField(
            model_name='reviewersettings',
            name='enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='reviewersettings',
            name='auto_close',
            field=models.BooleanField(default=False),
        ),
    ]
