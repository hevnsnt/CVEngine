from django.db import migrations


class Migration(migrations.Migration):
    """The reNgine external tool registry (InstalledExternalTool: install, update and version commands for tools such as nuclei and naabu) is gone.
    Nothing read it: every scan tool runs on a Sentinel, which installs and pins its own. Its rows (the three defaults and any an administrator added)
    are dropped with the table."""

    dependencies = [('scanEngine', '0006_encrypt_proxy_list')]
    operations = [migrations.DeleteModel(name='InstalledExternalTool')]
