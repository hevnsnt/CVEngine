"""1.3.3: the false_positive closure status and the closure note.

CVE matches, scanner findings and hygiene findings need no schema change: their remediation_status is a free 16-character column
(``false_positive`` fits) and remediation_note already holds the note. Supplier findings need room for the new status and a 2000-character
note, and a time for when a person set the status. Each step only widens a varchar or adds a nullable column: metadata-only in PostgreSQL,
no table rewrite, nothing backfilled; existing rows keep their status and note.

Reversible: going back first turns every ``false_positive`` into the closest status the older code knows (accepted_risk on CVE matches,
scanner and hygiene findings, accepted on supplier findings), so a rolled-back release still counts them as closed, and clips supplier
notes to the older 500 characters; then the columns narrow again.

Numbered 0138 because PR #386 adds 0137_heat_policy_baseline: whichever of the two merges second points this dependency at the other.
"""
from django.db import migrations, models
from django.db.models.functions import Length


def to_older_statuses(apps, schema_editor):
    # check foreign keys as each statement ends, so no trigger event is still pending when the columns narrow next (as in agentapi 0009)
    if schema_editor.connection.vendor == 'postgresql':
        schema_editor.execute('SET CONSTRAINTS ALL IMMEDIATE')
    for app, model in (('cveFeed', 'CVEMatch'), ('cveFeed', 'HygieneFinding'), ('startScan', 'Vulnerability')):
        apps.get_model(app, model).objects.filter(remediation_status='false_positive').update(remediation_status='accepted_risk')
    SupplierFinding = apps.get_model('cveFeed', 'SupplierFinding')
    SupplierFinding.objects.filter(status='false_positive').update(status='accepted')
    for row in SupplierFinding.objects.annotate(n=Length('status_note')).filter(n__gt=500).only('pk', 'status_note'):
        SupplierFinding.objects.filter(pk=row.pk).update(status_note=row.status_note[:500])


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0136_cvematch_fire_notified"),
        ("startScan", "0025_scanhistory_discovery_mode"),
    ]

    operations = [
        migrations.AlterField(
            model_name="supplierfinding",
            name="status",
            field=models.CharField(default="open", max_length=16),
        ),
        migrations.AlterField(
            model_name="supplierfinding",
            name="status_note",
            field=models.CharField(blank=True, default="", max_length=2000),
        ),
        migrations.AddField(
            model_name="supplierfinding",
            name="status_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        # last, so that going back runs it first: the rows fit the narrower columns before they narrow
        migrations.RunPython(migrations.RunPython.noop, to_older_statuses),
    ]
