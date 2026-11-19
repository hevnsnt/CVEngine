from django.core.management.base import BaseCommand
from django.db.models import Q


class Command(BaseCommand):
    help = ('Fold the technology rows whose names differ only in case and read as the same product and version ("Caddy" and "caddy", '
            '"PHP:8.1.2" and "php:8.1.2") onto one row (cveFeed.tech_rows.merge_duplicates), take MariaDB\'s "5.5.5-" handshake prefix off the '
            'stored port versions and CPEs (cveFeed.port_inventory.mariadb_version), and correlate the current hosts that moved. '
            'A dry run by default: --apply writes.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='write the changes and the matches (default: dry run, nothing written)')
        parser.add_argument('--dry-run', action='store_true', help='the default; accepted for clarity')

    def handle(self, *args, **options):
        from cveFeed import correlation, tech_rows
        from cveFeed.port_inventory import mariadb_version
        from startScan.models import Port, Subdomain
        apply = bool(options['apply']) and not options['dry_run']
        merged = tech_rows.merge_duplicates(apply=apply)
        ports = list(Port.objects.filter(Q(version__startswith='5.5.5-') | Q(cpe__istartswith='cpe:/a:mariadb:mariadb:5.5.5-'))
                     .filter(Q(product__icontains='mariadb') | Q(version__icontains='mariadb') | Q(cpe__icontains='mariadb')))
        if not apply:
            self.stdout.write(f'Dry run: {merged["rows"]} technology rows in {merged["groups"]} groups would be folded onto one spelling '
                              f'({len(merged["hosts"])} host rows), {len(ports)} MariaDB port versions would lose the "5.5.5-" prefix.')
            return
        for port in ports:
            extra = port.extra if isinstance(port.extra, dict) else {}
            rec = mariadb_version({'product': port.product, 'version': port.version, 'cpe': port.cpe, 'cpes': extra.get('cpes') or []})
            port.version, port.cpe = rec['version'][:100], rec.get('cpe') or ''
            if extra.get('cpes'):
                port.extra = {**extra, 'cpes': rec['cpes']}
            port.save(update_fields=['version', 'cpe', 'extra'])
        hosts = set(merged['hosts'])
        hosts |= set(Subdomain.objects.filter(ip_addresses__ports__in=[p.pk for p in ports]).values_list('pk', flat=True))
        current = list(Subdomain.objects.filter(correlation.latest_scan_q()).filter(pk__in=hosts).values_list('pk', flat=True))
        matches = 0
        if current:
            cve_by_id, index = correlation.cve_pool()
            for start in range(0, len(current), 200):
                subs = list(Subdomain.objects.filter(pk__in=current[start:start + 200]).select_related('target_domain', 'scan_history')
                            .prefetch_related('technologies', 'ip_addresses__ports'))
                matches += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
        self.stdout.write(f'Applied: {merged["rows"]} technology rows folded in {merged["groups"]} groups, {len(ports)} MariaDB port versions '
                          f'read without the "5.5.5-" prefix; {len(current)} current hosts correlated, {matches} CVE matches.')
