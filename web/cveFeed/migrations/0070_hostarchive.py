import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0069_routeauth_fingerprint_names'),
        ('dashboard', '0019_encrypt_existing_secrets'),
        ('targetApp', '0001_initial'),
    ]
    operations = [
        migrations.CreateModel(
            name='HostArchive',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=500)),
                ('technologies', models.JSONField(blank=True, default=dict)),
                ('tech_text', models.TextField(blank=True, default='')),
                ('url_count', models.PositiveIntegerField(default=0)),
                ('checked_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='targetApp.domain')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
            ],
        ),
        migrations.AddConstraint(
            model_name='hostarchive',
            constraint=models.UniqueConstraint(fields=('project', 'host'), name='uniq_hostarchive_project_host'),
        ),
    ]
