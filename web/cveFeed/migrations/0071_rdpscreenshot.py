import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0070_hostarchive'),
        ('dashboard', '0019_encrypt_existing_secrets'),
        ('targetApp', '0001_initial'),
    ]
    operations = [
        migrations.CreateModel(
            name='RdpScreenshot',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=500)),
                ('address', models.CharField(max_length=64)),
                ('port', models.PositiveIntegerField(default=3389)),
                ('image_path', models.CharField(blank=True, default='', max_length=1000)),
                ('image_hash', models.CharField(blank=True, default='', max_length=16)),
                ('logged_in_user', models.CharField(blank=True, default='', max_length=300)),
                ('ai_summary', models.TextField(blank=True, default='')),
                ('ai_error', models.CharField(blank=True, default='', max_length=300)),
                ('captured_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='targetApp.domain')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
            ],
        ),
        migrations.AddConstraint(
            model_name='rdpscreenshot',
            constraint=models.UniqueConstraint(fields=('project', 'host', 'port'), name='uniq_rdpshot_project_host_port'),
        ),
    ]
