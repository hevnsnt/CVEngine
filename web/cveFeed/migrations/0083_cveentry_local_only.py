from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0082_hostexclusion_include_subdomains')]
    operations = [
        migrations.AddField(model_name='cveentry', name='local_only', field=models.BooleanField(db_index=True, default=False)),
        migrations.AddField(model_name='cveentry', name='locality_at', field=models.DateTimeField(blank=True, null=True)),
    ]
