from django.db import migrations, models
import django.db.models.deletion

# cveFeed.triage.SHARED_REASON at the time of writing (a migration does not import app code that may change)
SHARED_REASON = 'Assessed from a matching finding elsewhere (the same evidence on another host); no host-specific notes.'


def record_origins(apps, schema_editor):
    """Give the answers already stored the origin they can be proven from, so a closing one closes only that tenant's findings and its
    words are shown only there (task 256).

    The origin of a model's answer is the project that reserved the provider call for its signature (TriageCall, kept for the daily caps):
    an answer asked for by exactly one project gets that project. One with no call on record (written before the ledger, or by a deterministic
    rule) gets the project of its findings when they are all in one project. The host is set when that project's findings holding the answer
    are all on one host. Every other answer (asked by several projects, or held by several with no call on record) keeps none: it closes
    nothing more and its words are shown nowhere; the findings it already closed are reviewed by ``cveFeed.verdict_tenancy`` (run once by the
    first correlation after the upgrade). Reads in chunks of 1000 answers; nothing is reopened here.
    """
    TriageVerdict = apps.get_model('cveFeed', 'TriageVerdict')
    TriageCall = apps.get_model('cveFeed', 'TriageCall')
    Triage = apps.get_model('cveFeed', 'Triage')
    from django.db.models import Max, Min
    last = 0
    while True:
        chunk = list(TriageVerdict.objects.filter(project__isnull=True, pk__gt=last).order_by('pk').values_list('pk', 'kind', 'signature')[:1000])
        if not chunk:
            break
        last = chunk[-1][0]
        asked = {}
        for kind, signature, project_id in (TriageCall.objects.filter(signature__in=[c[2] for c in chunk], status='succeeded')
                                            .values_list('kind', 'signature', 'project_id').distinct()):
            asked.setdefault((kind, signature), set()).add(project_id)
        held = {}
        for row in (Triage.objects.filter(verdict_id__in=[c[0] for c in chunk]).values('verdict_id', 'project_id')
                    .annotate(first_host=Min('host'), last_host=Max('host')).order_by()):
            held.setdefault(row['verdict_id'], {})[row['project_id']] = (row['first_host'], row['last_host'])
        for pk, kind, signature in chunk:
            projects = asked.get((kind, signature)) or (set(held.get(pk, {})) if (kind, signature) not in asked else set())
            if len(projects) != 1:
                continue
            project_id = next(iter(projects))
            first, final = held.get(pk, {}).get(project_id, ('', ''))
            TriageVerdict.objects.filter(pk=pk, project__isnull=True).update(project_id=project_id, host=(first if first and first == final else '')[:500])


def drop_shared_words(apps, schema_editor):
    """The shared correlation table (MatchVerdict) has no tenant, yet it kept the model's words about the host an answer was reached on, and
    correlation copied them onto every new match it seeded, in any organization (task 256). Every non-closing row gets the fixed sentence, and
    so does every match still holding words it was seeded with (same key, verdict and words, and no Triage row of its own with those words:
    a match whose own review wrote them keeps them). Unconditional, and before any organization is added: the table has no tenant. The
    not_affected rows keep their words until ``cveFeed.verdict_tenancy`` has found the matches they seeded closed, then they are deleted
    (nothing seeds from them any more). Two UPDATE statements per kind of range result, whatever the size of the tables."""
    from django.db.models import Exists, OuterRef
    MatchVerdict = apps.get_model('cveFeed', 'MatchVerdict')
    CVEMatch = apps.get_model('cveFeed', 'CVEMatch')
    Triage = apps.get_model('cveFeed', 'Triage')
    worded = MatchVerdict.objects.exclude(ai_verdict='not_affected').exclude(ai_reason=SHARED_REASON)
    own = Triage.objects.filter(match=OuterRef('pk'), reason=OuterRef('ai_reason'))
    for unknown in (True, False):
        same = worded.filter(cve_entry_id=OuterRef('cve_entry_id'), matched_product=OuterRef('matched_product'),
                             matched_version=OuterRef('matched_version'), source=OuterRef('source'), ai_verdict=OuterRef('ai_verdict'),
                             ai_reason=OuterRef('ai_reason'),
                             **({'version_in_range__isnull': True} if unknown else {'version_in_range': OuterRef('version_in_range')}))
        (CVEMatch.objects.filter(version_in_range__isnull=unknown).exclude(ai_reason=SHARED_REASON).filter(Exists(same)).exclude(Exists(own))
         .update(ai_reason=SHARED_REASON))
    worded.update(ai_reason=SHARED_REASON)


class Migration(migrations.Migration):
    """Where a stored triage answer was reached (task 256): two nullable or defaulted columns, so adding them rewrites nothing, and an index
    on the provider-call ledger by signature; then the answers already stored get the origin they can be told from (``record_origins``), and
    the shared correlation table gives up the model's words (``drop_shared_words``). Reversing drops the columns and the index (the words are
    not put back).

    Numbered 0140, after develop's 0139 (#386, heat policy), which follows 0138 (#390)."""

    dependencies = [
        ("dashboard", "0031_ai_provider_request_settings"),
        ("cveFeed", "0139_heat_policy_baseline"),
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
        migrations.AddIndex(
            model_name="triagecall",
            index=models.Index(fields=["signature", "status"], name="triagecall_signature_idx"),
        ),
        migrations.RunPython(record_origins, migrations.RunPython.noop),
        migrations.RunPython(drop_shared_words, migrations.RunPython.noop),
    ]
