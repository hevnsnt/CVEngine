"""Service features: what a Sentinel read about one feature of the service on a host and port (``cveFeed.service_features``).

The first feature is ``http2``: whether a TLS service offers HTTP/2, from the ALPN protocol the server chose in the hygiene check's certificate
handshake. Correlation and triage read it for the CVEs whose advisory needs the feature (the nginx HTTP/2 module flaws). The table starts empty:
readings arrive with the next hygiene check of each target by a Sentinel that reads ALPN.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0175_drop_nuclei_template_refresh'), ('targetApp', '0008_domain_expect_private_ca')]
    operations = [
        migrations.CreateModel(
            name='ServiceFeature',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=500)),
                ('port', models.IntegerField()),
                ('transport', models.CharField(default='tls', max_length=8)),
                ('feature', models.CharField(max_length=24)),
                ('value', models.CharField(max_length=24)),
                ('detail', models.CharField(blank=True, default='', max_length=120)),
                ('source', models.CharField(max_length=24)),
                ('observed_at', models.DateTimeField()),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='targetApp.domain')),
            ],
            options={
                'indexes': [models.Index(fields=['host', 'feature'], name='servicefeature_host_idx')],
                'constraints': [models.UniqueConstraint(fields=('domain', 'host', 'port', 'feature'), name='servicefeature_unique')],
            },
        ),
    ]
