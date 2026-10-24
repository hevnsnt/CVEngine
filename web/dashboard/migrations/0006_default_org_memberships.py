from django.db import migrations

LEGACY_TO_TENANCY = {'sys_admin': 'admin', 'penetration_tester': 'user', 'auditor': 'audit'}


def create_default_org(apps, schema_editor):
    """Everything existing lands in one 'Default' org; users keep the access their legacy role gave."""
    Org = apps.get_model('dashboard', 'Org')
    Project = apps.get_model('dashboard', 'Project')
    OrgMembership = apps.get_model('dashboard', 'OrgMembership')
    User = apps.get_model('auth', 'User')
    org, _ = Org.objects.get_or_create(slug='default', defaults={'name': 'Default'})
    Project.objects.filter(org__isnull=True).update(org=org)
    for user in User.objects.all():
        if user.is_superuser:
            role = 'admin'
        else:
            names = list(user.groups.values_list('name', flat=True))
            role = next((LEGACY_TO_TENANCY[n] for n in ('sys_admin', 'penetration_tester', 'auditor') if n in names), 'audit')
        OrgMembership.objects.get_or_create(user=user, org=org, defaults={'role': role})


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0005_tenancy'), ('auth', '0012_alter_user_first_name_max_length')]
    operations = [migrations.RunPython(create_default_org, migrations.RunPython.noop)]
