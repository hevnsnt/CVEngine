from django.db import migrations, models
import django.db.models.deletion

CLOSING = ('likely_false_positive', 'not_applicable')


def neutralise_shared_closures(apps, schema_editor):
    """Give the closing answers already stored the origin they can be proven from, so only that tenant keeps reusing them (task 256).

    The origin of a model's answer is the project that reserved the provider call for its signature (TriageCall, kept for the daily caps):
    a closing TriageVerdict (likely_false_positive, not_applicable) asked for by exactly one project gets that project, and the host when
    that project's findings holding it are all on one host. For the kinds whose prompt shows host text the signature does not carry (every
    kind but a CVE match), only a one-host answer gets an origin. Every other closing answer (asked by several projects, by none on record,
    or written by a deterministic closure) keeps none, so it closes nothing more. The findings that already hold one keep their
    classification until ``manage.py release_shared_closures --apply`` reviews them, and the not_affected rows of MatchVerdict, which
    correlation no longer seeds (``correlation._seedable``), are left for that command to find the matches they closed. Reads in chunks
    of 1000 answers; nothing is reopened here.
    """
    TriageVerdict = apps.get_model('cveFeed', 'TriageVerdict')
    TriageCall = apps.get_model('cveFeed', 'TriageCall')
    Triage = apps.get_model('cveFeed', 'Triage')
    from django.db.models import Max, Min
    last = 0
    while True:
        chunk = list(TriageVerdict.objects.filter(classification__in=CLOSING, project__isnull=True, pk__gt=last)
                     .order_by('pk').values_list('pk', 'kind', 'signature')[:1000])
        if not chunk:
            break
        last = chunk[-1][0]
        asked = {}
        for kind, signature, project_id in (TriageCall.objects.filter(status='succeeded', signature__in=[c[2] for c in chunk])
                                            .values_list('kind', 'signature', 'project_id').distinct()):
            asked.setdefault((kind, signature), set()).add(project_id)
        hosts = {(row['verdict_id'], row['project_id']): (row['first_host'], row['last_host']) for row in
                 Triage.objects.filter(verdict_id__in=[c[0] for c in chunk]).values('verdict_id', 'project_id')
                 .annotate(first_host=Min('host'), last_host=Max('host')).order_by()}
        for pk, kind, signature in chunk:
            projects = asked.get((kind, signature), set())
            if len(projects) != 1:
                continue
            project_id = next(iter(projects))
            first, final = hosts.get((pk, project_id), ('', ''))
            one_host = first if first and first == final else ''
            if kind != 'cve_match' and not one_host:
                continue
            TriageVerdict.objects.filter(pk=pk, project__isnull=True).update(project_id=project_id, host=one_host[:500])


class Migration(migrations.Migration):
    """Where a stored triage answer was reached (task 256): two nullable or defaulted columns, so adding them rewrites nothing; then the
    closing answers already stored get the origin they can be told from (see ``neutralise_shared_closures``). Reversing drops the columns.""" 

    dependencies = [
        ("dashboard", "0031_ai_provider_request_settings"),
        ("cveFeed", "0136_cvematch_fire_notified"),
    ]

    operations = [
        migrations.AddField(
            model_name="triageverdict",
            name="project",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+",
                                    to="dashboard.project"),
        ),
        migrations.AddField(
            model_name="triageverdict",
            name="host",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
        migrations.RunPython(neutralise_shared_closures, migrations.RunPython.noop),
    ]
