from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0024_ai_plan_budget')]
    operations = [
        migrations.CreateModel(name='ScanPolicy', fields=[
            ('id', models.AutoField(primary_key=True, serialize=False)),
            ('nuclei_all_templates', models.BooleanField(default=False)),
        ]),
    ]
