"""Re-rate the open baddns dangling-DNS findings already stored, the way a new scan now rates them (cveFeed.dangling_dns), and give a
finding with no host the host it was matched at.

A dry run by default: it asks a Sentinel to run the same DNS and HTTP checks a scan runs (``dangling_dns_check``; this server sends nothing to a host
itself) and reports, per project, how many findings would change. Nothing is written without --apply. With no scanner able to take the work a project's
findings are reported as ``waiting for a scanner`` and left alone.

    python3 manage.py rerate_dangling_dns                 # dry run, every project
    python3 manage.py rerate_dangling_dns --project acme  # dry run, one project
    python3 manage.py rerate_dangling_dns --apply         # write the new severities and hosts

With --apply: a finding the check re-rates gets the new severity and the check's note in its description; a finding the check would no longer
record (a provider's zone reached through a CNAME, a "not found" page the provider shows for every host) is set to informational (no heat)
with the note, not deleted or closed; a finding with no host gets the host row of its "Matched at" name. Findings that are closed, and
findings whose check got no answer, are left alone.
"""
from collections import defaultdict

from django.core.management.base import BaseCommand

SEVERITY_NAMES = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


def candidates(project=None):
    from startScan.models import Vulnerability
    rows = (Vulnerability.objects.filter(source='bbot', template_id='baddns', open_status=True,
                                                remediation_status__in=('open', 'in_progress'))
            .select_related('subdomain', 'target_domain__project', 'scan_history').order_by('id'))
    if project:
        rows = rows.filter(target_domain__project__slug=project)
    return rows


def plan(vuln, rating):
    """``(new_severity, new_description, host_name)`` for one stored finding and its ``rating`` (``dangling_dns.Rating`` or None); each part None when it
    does not change."""
    from cveFeed import dangling_dns
    host = _host_of(vuln)
    severity = description = None
    if rating is not None:
        target = 0 if rating.drop else (rating.severity if rating.severity is not None else vuln.severity)
        severity = target if target != vuln.severity else None
        text = dangling_dns.with_note(vuln.description, rating)
        description = text if text != vuln.description else None
    return severity, description, (host if host and not vuln.subdomain_id else None)


def _host_of(vuln):
    host = (vuln.subdomain.name if vuln.subdomain_id else '') or (vuln.http_url or '').strip().lower()
    return host if host and '/' not in host else ''


def apply(vuln, severity, description, host):
    from startScan.models import Subdomain
    fields = []
    if severity is not None:
        vuln.severity = severity
        fields.append('severity')
    if description is not None:
        vuln.description = description
        fields.append('description')
    if host and vuln.target_domain_id:
        domain = vuln.target_domain
        if host == domain.name or host.endswith('.' + domain.name):
            sub = (Subdomain.objects.filter(scan_history=vuln.scan_history, target_domain=domain, name=host).first()
                   or Subdomain.objects.create(scan_history=vuln.scan_history, target_domain=domain, name=host))
            vuln.subdomain = sub
            fields.append('subdomain')
    if fields:
        vuln.save(update_fields=fields)
    return bool(fields)


class Command(BaseCommand):
    help = "Re-rate stored baddns dangling-DNS findings by what an outsider can claim (dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument('--project', help='Only this project (its slug).')
        parser.add_argument('--apply', action='store_true', help='Write the changes. Without it nothing is written.')

    def handle(self, *args, **opts):
        from cveFeed import dangling_dns
        counts = defaultdict(lambda: defaultdict(int))
        by_project = defaultdict(list)
        for vuln in candidates(opts.get('project')).iterator():
            by_project[vuln.target_domain.project if vuln.target_domain_id and vuln.target_domain.project_id else None].append(vuln)
        for project, vulns in by_project.items():  # one batch per project, rated by a Sentinel of it
            ratings = dangling_dns.assess_all([{'host': _host_of(v), 'description': v.description, 'module': 'baddns'} for v in vulns], project=project)
            self._report(counts, project, vulns, ratings, opts['apply'])
        mode = 'applied' if opts['apply'] else 'dry run (nothing written; --apply writes)'
        self.stdout.write(f'rerate_dangling_dns: {mode}')
        for slug in sorted(counts):
            parts = ', '.join(f'{k}: {v}' for k, v in sorted(counts[slug].items()))
            self.stdout.write(f'  {slug}: {parts}')
        if not counts:
            self.stdout.write('  no open baddns findings')

    def _report(self, counts, project, vulns, ratings, apply_changes):
        slug = project.slug if project is not None else '-'
        for vuln, rating in zip(vulns, ratings):
            counts[slug]['examined'] += 1
            if rating is None and project is not None and _host_of(vuln):
                counts[slug]['waiting for a scanner or unanswered'] += 1
            severity, description, host = plan(vuln, rating)
            if severity is not None:
                counts[slug][f'{SEVERITY_NAMES.get(vuln.severity, vuln.severity)} -> {SEVERITY_NAMES.get(severity, severity)}'] += 1
            if host:
                counts[slug]['host filled'] += 1
            if apply_changes and apply(vuln, severity, description, host):
                counts[slug]['written'] += 1
