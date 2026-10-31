from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0007_sentinel_network")]
    operations = [
        migrations.AddField(model_name="sentinelenrollment", name="builtin", field=models.BooleanField(default=False, db_default=False)),
    ]
