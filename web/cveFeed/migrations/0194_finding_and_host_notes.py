import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

OBSERVATIONS = [('confirmed', 'confirmed'), ('not_reproduced', 'not_reproduced'), ('false_positive', 'false_positive'),
                ('fixed_verified', 'fixed_verified'), ('needs_more_info', 'needs_more_info'), ('info', 'info')]
SOURCES = [('ui', 'ui'), ('mcp', 'mcp'), ('rest', 'rest')]


class Migration(migrations.Migration):
    """Structured operator notes. A finding's comment gains an optional observation, the evidence behind it, where it came from (web, MCP or
    REST) and the API token's name; the new ``HostNote`` table holds the same notes about a whole host; the triage row gains ``notes_mark``,
    the newest note that queued the finding for a fresh AI review. Every new column carries a database default, so the code of the version
    before can still insert comments and triage rows during the update and after a rollback. The new table starts empty; nothing is backfilled."""

    dependencies = [
        ('cveFeed', '0193_hostassessment_front_db_default'),
        ('dashboard', '0039_ct_fallback_source'),
        ('startScan', '0037_subdomain_lower_name_idx'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='findingcomment',
            name='evidence',
            field=models.TextField(blank=True, db_default='', default='', max_length=4000),
        ),
        migrations.AddField(
            model_name='findingcomment',
            name='observation',
            field=models.CharField(blank=True, choices=OBSERVATIONS, db_default='', default='', max_length=20),
        ),
        migrations.AddField(
            model_name='findingcomment',
            name='source',
            field=models.CharField(choices=SOURCES, db_default='ui', default='ui', max_length=8),
        ),
        migrations.AddField(
            model_name='findingcomment',
            name='via',
            field=models.CharField(blank=True, db_default='', default='', max_length=100),
        ),
        migrations.AddField(
            model_name='triage',
            name='notes_mark',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.CreateModel(
            name='HostNote',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=500)),
                ('observation', models.CharField(blank=True, choices=OBSERVATIONS, db_default='', default='', max_length=20)),
                ('text', models.TextField(max_length=4000)),
                ('evidence', models.TextField(blank=True, db_default='', default='', max_length=4000)),
                ('source', models.CharField(choices=SOURCES, db_default='ui', default='ui', max_length=8)),
                ('via', models.CharField(blank=True, db_default='', default='', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('author', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
                ('subdomain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='startScan.subdomain')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'indexes': [models.Index(fields=['project', 'host', '-created_at'], name='hostnote_host_idx')],
            },
        ),
    ]
