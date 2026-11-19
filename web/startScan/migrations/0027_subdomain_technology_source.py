import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    """A host's technology links say where each technology came from (``startScan.models.SubdomainTechnology``): the plain many-to-many table
    ``startScan_subdomain_technologies`` becomes the table of an explicit through model and gains ``source``, ``cpe`` and ``observed_at``. The
    table is kept as it is (no row is copied or rewritten): three columns are added, ``source`` and ``cpe`` empty and ``observed_at`` NULL on every
    link stored before (not known), and the model is declared over it. Adding a column with a constant default and a nullable one is a metadata
    change in PostgreSQL 11 and later, so the table is not rewritten. The update step ``backfill_template_identities`` fills them from the
    stored template findings that name the template."""

    dependencies = [
        ('startScan', '0026_vulnerability_severity_id_idx'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=[
                        'ALTER TABLE "startScan_subdomain_technologies" ADD COLUMN "source" varchar(32) NOT NULL DEFAULT \'\'',
                        'ALTER TABLE "startScan_subdomain_technologies" ADD COLUMN "cpe" varchar(255) NOT NULL DEFAULT \'\'',
                        'ALTER TABLE "startScan_subdomain_technologies" ADD COLUMN "observed_at" timestamp with time zone NULL',
                    ],
                    reverse_sql=[
                        'ALTER TABLE "startScan_subdomain_technologies" DROP COLUMN "observed_at"',
                        'ALTER TABLE "startScan_subdomain_technologies" DROP COLUMN "cpe"',
                        'ALTER TABLE "startScan_subdomain_technologies" DROP COLUMN "source"',
                    ],
                ),
            ],
            state_operations=[
                migrations.CreateModel(
                    name='SubdomainTechnology',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('source', models.CharField(blank=True, default='', max_length=32)),
                        ('cpe', models.CharField(blank=True, default='', max_length=255)),
                        ('observed_at', models.DateTimeField(blank=True, default=django.utils.timezone.now, null=True)),
                        ('subdomain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.subdomain')),
                        ('technology', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.technology')),
                    ],
                    options={
                        'db_table': 'startScan_subdomain_technologies',
                        'unique_together': {('subdomain', 'technology')},
                    },
                ),
                migrations.AlterField(
                    model_name='subdomain',
                    name='technologies',
                    field=models.ManyToManyField(blank=True, related_name='technologies', through='startScan.SubdomainTechnology',
                                                 to='startScan.technology'),
                ),
            ],
        ),
    ]
