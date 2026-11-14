"""1.4.0 retest on fix: what happened when a finding marked fixed was checked again (``cveFeed.retest``).

Four columns on Triage (the row every list already joins) hold the newest result, and ``FixRetest`` holds each try with its Sentinel, time and
evidence. Every NOT NULL column has a database default, so the previous release's code, which keeps running until the workers restart and
inserts Triage rows without them, can still insert. Catalog-only on PostgreSQL 11 and later: no rewrite, nothing backfilled (a finding marked
fixed before this release reads as fixed, not verified, until it is retested). The audit trail gains the ``retest`` event (choices only).
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0159_cvedetection_source_filled_idx'),
        ('dashboard', '0035_apitoken_suffix_db_default'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='triage',
            name='retest_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='triage',
            name='retest_reason',
            field=models.CharField(blank=True, db_default='', default='', max_length=300),
        ),
        migrations.AddField(
            model_name='triage',
            name='retest_sentinel',
            field=models.CharField(blank=True, db_default='', default='', max_length=120),
        ),
        migrations.AddField(
            model_name='triage',
            name='retest_state',
            field=models.CharField(blank=True, db_default='', default='', max_length=16),
        ),
        migrations.AlterField(
            model_name='findingauditevent',
            name='event',
            field=models.CharField(choices=[('status', 'status'), ('assignee', 'assignee'), ('comment', 'comment'), ('heat', 'heat'), ('retest', 'retest')], max_length=16),
        ),
        migrations.CreateModel(
            name='FixRetest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.CharField(db_default='automatic', default='automatic', max_length=12)),
                ('status', models.CharField(db_default='queued', default='queued', max_length=12)),
                ('outcome', models.CharField(blank=True, db_default='', default='', max_length=16)),
                ('reason', models.CharField(blank=True, db_default='', default='', max_length=300)),
                ('check_run', models.JSONField(blank=True, default=dict)),
                ('sentinel', models.CharField(blank=True, db_default='', default='', max_length=120)),
                ('evidence', models.JSONField(blank=True, default=dict)),
                ('attempts', models.PositiveSmallIntegerField(db_default=1, default=1)),
                ('next_attempt_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='dashboard.project')),
                ('requested_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('triage', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='fix_retests', to='cveFeed.triage')),
            ],
            options={
                'indexes': [models.Index(fields=['project', 'status', 'created_at'], name='fixretest_proj_status_idx'), models.Index(fields=['outcome', 'next_attempt_at'], name='fixretest_due_idx')],
                'constraints': [models.UniqueConstraint(condition=models.Q(('status__in', ['queued', 'running'])), fields=('triage',), name='one_active_fixretest_per_finding')],
            },
        ),
    ]
