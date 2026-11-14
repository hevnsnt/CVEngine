"""File the secrets that stored scanner findings still carry in the secrets inventory, and mask them in the findings (docs/SECRETS-PLAN.md 8.3).

Before 1.4 a nuclei token template stored the key it extracted (``extracted_results``) and the whole response that served it, and a bbot badsecrets
or trufflehog finding printed the secret in its description. Each such finding is read once: the value is fingerprinted into the inventory (linked
to the finding, whose severity then follows the inventory row), the finding keeps the mask, and a token template's response keeps its status line
and headers only. Masking cannot be undone, so this is a dry run unless ``--apply``; it is listed in ``cveFeed.upgrade_backfills.BACKFILLS`` and
applied once by itself after the update. Running it again finds nothing to change (a mask is never filed again). The route check's own samples
were never values, so routes join the inventory at their next check.

    python3 manage.py backfill_secrets_inventory
    python3 manage.py backfill_secrets_inventory --apply [--project slug]
"""
from django.core.management.base import BaseCommand
from django.db.models import Q

from ._finding_backfill import add_arguments, line, projects

CHUNK = 200
FIELDS = ('source', 'template', 'template_url', 'template_id', 'extracted_results', 'response', 'description')


def candidates(project):
    from startScan.models import Vulnerability
    from cveFeed import secrets_inventory
    nuclei = Q(source__iexact='nuclei') & (Q(tags__name__in=sorted(secrets_inventory.TOKEN_TAGS)) | Q(template__icontains='exposures/tokens/')
                                           | Q(template_url__icontains='exposures/tokens/'))
    bbot = Q(source__iexact='bbot', template_id__in=secrets_inventory.BBOT_SECRET_MODULES)
    return (Vulnerability.objects.filter(target_domain__project=project).filter(nuclei | bbot).distinct().order_by('id')
            .select_related('target_domain', 'subdomain').prefetch_related('tags'))


class Command(BaseCommand):
    help = 'File the secrets stored scanner findings carry in the secrets inventory and mask them (a dry run unless --apply).'

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        from cveFeed import secrets_inventory
        total = {'findings': 0, 'secrets': 0}
        for project in projects(opts):
            counts = {'findings': 0, 'secrets': 0}
            last = 0
            while True:
                chunk = list(candidates(project).filter(id__gt=last)[:CHUNK])
                if not chunk:
                    break
                last = chunk[-1].id
                for vuln in chunk:
                    data = {name: getattr(vuln, name) for name in FIELDS}
                    found = secrets_inventory.take_from_finding(data, [t.name for t in vuln.tags.all()])
                    if not found:
                        continue
                    counts['findings'] += 1
                    counts['secrets'] += len(found)
                    if opts['apply']:
                        changed = [name for name in FIELDS if data[name] != getattr(vuln, name)]
                        for name in changed:
                            setattr(vuln, name, data[name])
                        if changed:
                            vuln.save(update_fields=changed)
                        secrets_inventory.feed_finding(vuln, found)
            total['findings'] += counts['findings']
            total['secrets'] += counts['secrets']
            if counts['findings']:
                self.stdout.write(line(project, counts))
        verb = 'filed and masked' if opts['apply'] else 'would file and mask'
        self.stdout.write(self.style.SUCCESS(f"{verb} {total['secrets']} secret(s) from {total['findings']} finding(s)"))
