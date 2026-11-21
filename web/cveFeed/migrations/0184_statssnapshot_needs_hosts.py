from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0183_zero_wire_schedule')]
    operations = [migrations.AddField(model_name='statssnapshot', name='needs_hosts', field=models.IntegerField(blank=True, null=True))]
