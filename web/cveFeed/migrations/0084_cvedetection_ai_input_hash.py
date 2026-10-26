from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0083_cveentry_local_only')]
    operations = [
        migrations.AddField(model_name='cvedetection', name='ai_input_hash', field=models.CharField(blank=True, default='', max_length=16)),
    ]
