from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0081_work_conductor_schedule')]
    operations = [
        migrations.AddField(model_name='hostexclusion', name='include_subdomains', field=models.BooleanField(default=False)),
    ]
