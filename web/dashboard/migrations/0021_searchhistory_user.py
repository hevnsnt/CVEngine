from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('dashboard', '0020_aiprovidersettings_verified_at_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.AddField(
            model_name='searchhistory',
            name='user',
            field=models.ForeignKey(
                null=True, blank=True, on_delete=django.db.models.deletion.CASCADE,
                related_name='search_history', to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
