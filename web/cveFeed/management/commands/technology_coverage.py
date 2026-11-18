"""Report which detected technology names connect to a CVE record (cveFeed.tech_coverage). Read-only: nothing is written.

By default it reads the current hosts' technologies and port products and the stored CVE catalogue. ``--seed`` reads a CVE seed file
instead of the catalogue (the published one: https://github.com/hevnsnt/CVEngine/releases/download/cve-seed/cve-seed.jsonl.gz), and
``--names`` a JSON list of names (or of ``{"name", "version", "source", "cpe", "hosts"}``) instead of the hosts, so the naming gaps of a
release can be measured without an inventory.

    python3 manage.py technology_coverage
    python3 manage.py technology_coverage --project acme --limit 100
    python3 manage.py technology_coverage --seed cve-seed.jsonl.gz --names names.json --json
"""
import json

from django.core.management.base import BaseCommand, CommandError

from cveFeed import correlation, tech_coverage


class Command(BaseCommand):
    help = ("Report the technology names that connect to no CVE record, the unversioned ones with the most CVEs, and the names that reach more "
            "than one vendor's products (read-only).")

    def add_arguments(self, parser):
        parser.add_argument("--seed", help="a CVE seed file (.jsonl.gz) to read instead of the stored catalogue")
        parser.add_argument("--names", help="a JSON file of technology names to read instead of the current hosts")
        parser.add_argument("--project", help="only this project's hosts (a slug)")
        parser.add_argument("--limit", type=int, default=tech_coverage.DEFAULT_LIMIT, help="rows per list (default 50, at most 500)")
        parser.add_argument("--json", action="store_true", help="print the report as JSON")

    def handle(self, *args, **opts):
        if opts["seed"]:
            try:
                cve_by_id, index = tech_coverage.pool_from_seed(opts["seed"])
            except (OSError, ValueError) as exc:
                raise CommandError(f"could not read the seed: {exc}")
        else:
            cve_by_id, index = correlation.cve_pool()
        if opts["names"]:
            try:
                sightings = tech_coverage.sightings_from_file(opts["names"])
            except (OSError, ValueError) as exc:
                raise CommandError(f"could not read the names: {exc}")
        else:
            project = None
            if opts["project"]:
                from dashboard.models import Project
                project = Project.objects.filter(slug=opts["project"]).first()
                if project is None:
                    raise CommandError(f"no project {opts['project']!r}")
            sightings = tech_coverage.sightings_from_db(project)
        report = tech_coverage.report(sightings, cve_by_id, index, opts["limit"])
        if opts["json"]:
            self.stdout.write(json.dumps(report, indent=1, sort_keys=True))
            return
        self._text(report)

    def _text(self, r):
        w = self.stdout.write
        cat = r["catalogue"]
        w(f"catalogue: {cat['cves']} CVEs, {cat['affected_entries']} affected entries, {cat['vendor_products']} vendor:product pairs")
        w(f"names: {r['names']} ({r['host_sightings']} host sightings); connected {r['connected_names']} "
          f"({r['connected_host_sightings']} host sightings); operating systems left to the host's own report: {r['os_sightings']}")
        w(f"\nUnmatched ({r['unmatched_count']}): names that reach no CVE record")
        for row in r["unmatched"]:
            near = "; ".join(f"{n['product']} ({n['cves']})" for n in row["near"])
            w(f"  {row['hosts']:>5}  {row['name']}  [{','.join(row['sources'])}]" + (f"  near: {near}" if near else ""))
        w(f"\nUnversioned ({r['unversioned_count']}): seen without a version, most CVEs first")
        for row in r["unversioned"]:
            w(f"  {row['cves']:>5} CVEs ({row['kev']} KEV)  {row['unversioned_hosts']:>4} hosts  {row['name']}  -> {', '.join(row['products'][:3])}")
        w(f"\nAmbiguous ({r['ambiguous_count']}): names that reach more than one vendor's products")
        for row in r["ambiguous"]:
            w(f"  {row['name']}: " + "; ".join(f"{v['vendor']} ({v['cves']})" for v in row["vendors"]))
        self.stdout.write(self.style.SUCCESS(
            f"\n{r['unmatched_count']} unmatched, {r['unversioned_count']} unversioned leads, {r['ambiguous_count']} ambiguous"))
