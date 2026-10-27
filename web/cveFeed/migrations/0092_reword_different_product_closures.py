from django.db import migrations
from django.db.models import F, Value
from django.db.models.functions import Replace

# "invalid product correlation" read as if the data had failed to parse; the closure is a different product being linked. The stored
# reasons of the rows closed under the first wording are rewritten so the lists and the detail pages do not keep both.
REWORDS = (
    ('invalid product correlation; the recorded product identity does not match an affected product in the advisory',
     'different product; the recorded product is not one the advisory covers'),
    ('invalid product correlation; the recorded fingerprint is a generic cloud or service label, not the affected product',
     'different product; the recorded fingerprint is a generic cloud or service label, not the affected software'),
)
TARGETS = (('CVEMatch', 'ai_reason'), ('MatchVerdict', 'ai_reason'), ('TriageVerdict', 'reason'), ('Triage', 'reason'))


def reword(apps, schema_editor):
    for model_name, field in TARGETS:
        model = apps.get_model('cveFeed', model_name)
        for old, new in REWORDS:
            model.objects.filter(**{field + '__contains': old}).update(**{field: Replace(F(field), Value(old), Value(new))})


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0091_probe_observation')]
    operations = [migrations.RunPython(reword, migrations.RunPython.noop)]
