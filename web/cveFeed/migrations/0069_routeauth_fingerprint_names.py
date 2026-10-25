from django.db import migrations


def add_fingerprint_names(apps, schema_editor):
    """Search reads ``evidence['fingerprint_names']``; routes checked before it existed get it from their fingerprints."""
    RouteAuth = apps.get_model('cveFeed', 'RouteAuth')
    batch = []
    for route in RouteAuth.objects.filter(evidence__has_key='fingerprints').only('id', 'evidence').iterator(chunk_size=500):
        names = [f.get('name', '') for f in route.evidence.get('fingerprints') or [] if isinstance(f, dict)]
        route.evidence = {**route.evidence, 'fingerprint_names': names}
        batch.append(route)
        if len(batch) >= 500:
            RouteAuth.objects.bulk_update(batch, ['evidence'])
            batch = []
    if batch:
        RouteAuth.objects.bulk_update(batch, ['evidence'])


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0068_threat_intel')]
    operations = [migrations.RunPython(add_fingerprint_names, migrations.RunPython.noop)]
