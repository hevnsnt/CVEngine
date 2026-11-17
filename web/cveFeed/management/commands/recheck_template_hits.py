"""Read again the confirmations an AI-written check recorded, and correct the ones that only read a version string (cveFeed.templategen).

An AI-written nuclei check (``GeneratedTemplate``) whose matchers only read a version string, in a shape the static classifier
(``templategen.template_evidence``) does not list, had its hits recorded as ``template_result='vulnerable'``: a confirmation. Triage read that
as proof, the heat went to fire and a confirmed nuclei-cve finding was filed. Every hit is now read for what it showed
(``templategen.hit_evidence``); this command does the same for the matches already stored, from the hit's own response kept on the nuclei-cve
finding (``Vulnerability.response``) or on the validation step (``Triage.validation_evidence['nuclei_template']``). A hit that only read the
version string is recorded as ``version_only``, the finding that check filed is closed automatically as a false positive (one a person
changed is left alone) and the match's triage starts over (``templategen.version_hit_corrected``). A match's remediation status is never
touched. A hit whose response was not stored, a template no longer stored, or anything the evaluator cannot decide stays as it is. A dry run by
default; run once by itself after the update (``cveFeed.upgrade_backfills``).

    python3 manage.py recheck_template_hits
    python3 manage.py recheck_template_hits --apply [--project slug]
"""
from django.core.management.base import BaseCommand

from cveFeed.templategen import stored_hit  # noqa: F401 - read here, and kept importable from this command

from ._finding_backfill import add_arguments, line, projects


def recheck(project, apply=False):
    """The counts for one project, correcting the version hits when ``apply``."""
    from cveFeed import templategen
    from cveFeed.models import CVEEntry, CVEMatch, GeneratedTemplate
    counts = {'checked': 0, 'version_only': 0, 'behaviour': 0, 'no_response': 0, 'no_template': 0, 'findings_closed': 0}
    groups = {}
    for pk, cve_pk, host, template_id in (CVEMatch.objects.filter(subdomain__target_domain__project=project, template_result='vulnerable')
                                          .exclude(template_id='').values_list('pk', 'cve_entry_id', 'subdomain__name', 'template_id')):
        groups.setdefault((cve_pk, host, template_id), []).append(pk)
    texts = {}
    for (cve_pk, host, template_id), ids in sorted(groups.items()):
        key = (cve_pk, template_id)
        if key not in texts:  # only an AI-written check is looked at: the one text that was approved and run under that id
            found = set(GeneratedTemplate.objects.filter(cve_entry_id=cve_pk, template_id=template_id).exclude(path='')
                        .values_list('yaml', flat=True))
            texts[key] = found.pop() if len(found) == 1 else None
        text = texts[key]
        if text is None:
            continue
        counts['checked'] += 1
        cve = CVEEntry.objects.only('id', 'cve_id').get(pk=cve_pk)
        try:
            yaml_id = str((templategen.load_template(text) or {}).get('id') or '')[:200]
        except Exception:  # noqa: BLE001 - an unreadable template is judged behaviour below
            yaml_id = ''
        ids_of_template = {template_id, yaml_id}
        hit = stored_hit(project.pk, host, cve.cve_id, ids_of_template, ids)
        if hit is None:
            counts['no_response'] += 1
            continue
        outcome = {'host': host, 'vulnerable': True, 'hit': {**hit, 'template-id': yaml_id}}
        if templategen.hit_evidence(text, outcome) != templategen.VERSION_EVIDENCE:
            counts['behaviour'] += 1
            continue
        counts['version_only'] += 1
        if apply:
            moved = list(CVEMatch.objects.filter(pk__in=ids, template_result='vulnerable', template_id=template_id).values_list('pk', flat=True))
            CVEMatch.objects.filter(pk__in=moved).update(template_result=templategen.VERSION_ONLY_RESULT)
            if moved:
                counts['findings_closed'] += len(templategen.version_hit_corrected(cve, host, project.pk, ids_of_template, moved))
    return counts


class Command(BaseCommand):
    help = ('Read again the confirmations AI-written checks recorded and correct the ones that only read a version string '
            '(a dry run unless --apply).')

    def add_arguments(self, parser):
        add_arguments(parser)

    def handle(self, *args, **opts):
        total = {'version_only': 0, 'findings_closed': 0}
        for project in projects(opts):
            counts = recheck(project, apply=opts['apply'])
            total['version_only'] += counts['version_only']
            total['findings_closed'] += counts['findings_closed']
            if counts['checked']:
                self.stdout.write(line(project, counts))
        verb = 'corrected' if opts['apply'] else 'would correct'
        self.stdout.write(self.style.SUCCESS(f"{verb} {total['version_only']} template confirmation(s) that only read a version string"
                                             + (f", closed {total['findings_closed']} finding(s)" if opts['apply'] else '')))
