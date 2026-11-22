"""Report, per project, whether the open findings point at hosts of the current inventory, and close those whose host is gone or archived
(cveFeed.finding_hosts).

Classes: ok; port (A: a certificate or TLS finding names name:port); alias (B: the name is a host only through the collapse, an alias or a name
with several current rows); gone (C: no longer in the current inventory); archived; not_a_host (a DNS or mail name that never was a host row).
Every page reads ok, port and alias through cveFeed.host_resolver, so only gone and archived change with --apply: they are closed as fixed with a
note that says why, and reopen when the host is back. A dry run by default.

    python3 manage.py audit_finding_hosts [--project slug]
    python3 manage.py audit_finding_hosts --apply
"""
from django.core.management.base import BaseCommand

from cveFeed import finding_hosts

from ._finding_backfill import projects


class Command(BaseCommand):
    help = 'Count open findings by whether their host is in the current inventory; --apply closes those of gone and archived hosts.'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Close the findings of gone and archived hosts. Without it the command only counts.')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')
        parser.add_argument('--project', action='append', default=[], help='Project slug (repeatable). Every project when left out.')

    def handle(self, *args, **opts):
        apply = bool(opts['apply']) and not opts['dry_run']
        chosen = projects(opts)
        ids = [p.pk for p in chosen] if opts['project'] else None
        slugs = {p.pk: p.slug for p in chosen}
        result = finding_hosts.audit(ids)
        for pid, per in sorted(result['projects'].items(), key=lambda kv: slugs.get(kv[0], '')):
            if any(per[c] for c in finding_hosts.CLASSES if c != 'ok'):
                self.stdout.write(f"{slugs.get(pid, pid)}: " + ', '.join(f'{c} {per[c]}' for c in finding_hosts.CLASSES))
        totals = result['totals']
        summary = ', '.join(f'{c} {totals[c]}' for c in finding_hosts.CLASSES)
        if not apply:
            self.stdout.write(f"Dry run: open findings by host: {summary}. --apply would close {totals['gone']} (gone) and {totals['archived']} (archived).")
            return
        done = finding_hosts.fix(ids)
        gone, archived = done['gone'], done['archived']
        closed_gone = gone['match'] + gone['vulnerability'] + gone['hygiene']
        closed_archived = sum(archived.get(k, 0) for k in ('match', 'vulnerability', 'hygiene'))
        self.stdout.write(f"Applied: open findings by host were {summary}; closed {closed_gone} on {gone['hosts']} hosts gone from the inventory "
                          f"and {closed_archived} on {archived.get('hosts', 0)} archived hosts.")
