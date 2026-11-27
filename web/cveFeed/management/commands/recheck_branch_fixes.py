"""Re-correlate the CVEs whose stored matches a branch fix of their own advisory now closes (cveFeed.correlation.branch_fixed).

F5 writes nginx's two lines in one CVE record as ``1.13.10`` up to ``1.31.2`` plus ``1.30.2`` up to ``1.30.3`` (CVE-2026-42055), and others
as ``0.6.18`` with no upper bound plus ``1.31.0`` up to ``1.31.9`` and ``1.30.0`` up to ``1.30.7`` (CVE-2026-123634). The stored ranges are
the record as written; read literally, a patched 1.30.5 or 1.31.9 sat inside the wide range. Correlation now reads a version at or past
its own line's stated fix as outside every range that runs past that line. This command finds the CVEs with a stored in-range match that
the new reading leaves outside, and marks them for re-correlation (``correlate_refreshed_cves`` closes those matches as it closes any match
a range no longer holds). No range is rewritten and no match row is written here.

Cost: one read of the version-in-range matches (their CVE, version and the index of the entry they were matched on) and one read of the
affected data of their CVEs, compared in memory; then the marked CVEs are re-correlated in batches of 100 per walk of the inventory.

    python3 manage.py recheck_branch_fixes
    python3 manage.py recheck_branch_fixes --apply
"""
from django.core.management.base import BaseCommand
from django.utils import timezone


def stale_cves():
    """``{cve entry id: (cve id, matches the new reading closes)}``: the CVEs with a match stored in range whose entry holds its version when read
    literally and leaves it outside once the entry's own branch fix is read (``correlation.item_verdict`` with and without ``branch_rule``)."""
    from cveFeed.correlation import branch_fixes, item_verdict, parse_version, prepared_ranges
    from cveFeed.models import CVEEntry, CVEMatch
    rows = {}
    for cve_pk, version, index in (CVEMatch.objects.filter(version_in_range=True).exclude(matched_version='')
                                   .values_list('cve_entry_id', 'matched_version', 'evidence__affected_index').distinct()):
        if isinstance(index, int) and not isinstance(index, bool):
            rows.setdefault(cve_pk, set()).add((version, index))
    out = {}
    entries = CVEEntry.objects.filter(pk__in=list(rows)).values_list('pk', 'cve_id', 'affected')
    for pk, cve_id, affected in entries.iterator(chunk_size=500):
        affected = affected if isinstance(affected, list) else []
        for version, index in rows[pk]:
            item = affected[index] if 0 <= index < len(affected) and isinstance(affected[index], dict) else None
            if item is None or not branch_fixes(prepared_ranges(item.get('ranges'))):
                continue  # only an entry that states a branch fix reads differently now
            parsed = parse_version(version)
            # only what the rule changes: in range read literally, outside once the branch fix is read (a match stale for another reason is
            # left to the next scan's correlation, as before)
            if (parsed is not None and item_verdict(parsed, item, version, branch_rule=False)[0] is True
                    and item_verdict(parsed, item, version)[0] is not True):
                out.setdefault(pk, [cve_id, 0])
                out[pk][1] += CVEMatch.objects.filter(cve_entry_id=pk, matched_version=version, version_in_range=True,
                                                      evidence__affected_index=index).count()
    return {pk: tuple(value) for pk, value in out.items()}


class Command(BaseCommand):
    help = "Re-correlate the CVEs whose matches a branch fix stated in the same advisory now closes (a dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Mark the CVEs for re-correlation. Without it the command only reports.")

    def handle(self, *args, **opts):
        from cveFeed.models import CVEEntry
        found = stale_cves()
        if not found:
            self.stdout.write(self.style.SUCCESS("nothing to recheck: no stored match sits past a fix its own advisory states for its line"))
            return
        for _pk, (cve_id, matches) in sorted(found.items(), key=lambda pair: pair[1][0]):
            self.stdout.write(f"{cve_id}: {matches} match(es) past the advisory's own branch fix")
        total = sum(matches for _cve, matches in found.values())
        if not opts["apply"]:
            self.stdout.write(self.style.SUCCESS(f"dry run: {len(found)} CVEs, {total} matches would be re-correlated (run again with --apply)"))
            return
        # synced_at moves so the per-process correlation index is built again, as for any CVE marked for re-correlation
        CVEEntry.objects.filter(pk__in=list(found)).update(needs_recorrelation=True, synced_at=timezone.now())
        self.stdout.write(self.style.SUCCESS(f"{len(found)} CVEs ({total} matches) marked for re-correlation; the next "
                                             "correlate_refreshed_cves run (queued by the 30 minute feed sync) closes the matches past the fix"))
