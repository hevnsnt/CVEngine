import django.db.models.deletion
from django.db import migrations, models
from django.db.models import OuterRef, Subquery


def backfill_org(apps, schema_editor):
    Domain = apps.get_model('targetApp', 'Domain')
    Project = apps.get_model('dashboard', 'Project')
    Domain.objects.filter(project__isnull=False).update(
        org=Subquery(Project.objects.filter(pk=OuterRef('project_id')).values('org_id')[:1]))


class Migration(migrations.Migration):
    dependencies = [('targetApp', '0003_remove_shared_provider_apexes'), ('dashboard', '0022_mfa_secret_encrypted')]
    operations = [
        migrations.AddField(model_name='domain', name='org',
                            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.CASCADE,
                                                    related_name='+', to='dashboard.org')),
        migrations.RunPython(backfill_org, migrations.RunPython.noop),
        # names were unique across the instance, so no (organization, name) pair can collide
        migrations.AlterField(model_name='domain', name='name', field=models.CharField(db_index=True, max_length=300)),
        migrations.AddConstraint(model_name='domain', constraint=models.UniqueConstraint(
            condition=models.Q(('org__isnull', False)), fields=('org', 'name'), name='uniq_domain_org_name')),
        migrations.AddConstraint(model_name='domain', constraint=models.UniqueConstraint(
            condition=models.Q(('org__isnull', True)), fields=('project', 'name'), name='uniq_domain_project_name')),
    ]
