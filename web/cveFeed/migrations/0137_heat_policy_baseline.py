"""The KEV heat policy's update: record under which heat rule a CVE match was announced, and announce nothing by itself.

Self-contained on purpose: the rule it applies is written out here in SQL, as it stands at this migration, so later changes to the code (new
evidence fields, a tightened proof) can never change what this migration did or break it on a fresh install.

1. ``fire_notified_rule``: the heat rule a page or a quiet mark was made under (``threat.heat_signature``). The pages made before the update were
   made under the rule then in force, the legacy one with its version-only cap (``CVENGINE_VERSION_ONLY_MAX_HEAT``, smoke by default).
2. Unless ``CVENGINE_HEAT_POLICY`` says legacy, every match that is fire under the KEV rule and was not announced under it is marked as announced
   under it, without a message, and the rule is recorded as baselined (BackgroundCursor lane ``heat_baseline``, 1 = kev), so the update pages none
   of the backlog. Matches still waiting for their page are left to it: those of a scan that has not finished, and those made in the last six
   hours. Under legacy the workers baseline at start (``cveFeed.notify.baseline_heat_policy``).

Cost: one UPDATE over the matches joined to their CVE (about 4 s at 400k matches; it holds row locks on the rows it marks only). No schema
change but the new nullable column with a constant default (no table rewrite).
"""
import os

from django.db import connection as default_connection
from django.db import migrations, models

GRACE_HOURS = 6
WAITING_SCAN_STATUSES = (-1, 1)  # initiated, running


def _flag(key):
    """SQL: the evidence key is present and holds none of the values Python reads as false."""
    return (f"(m.evidence ? '{key}' AND (m.evidence -> '{key}') NOT IN "
            "('false'::jsonb, 'null'::jsonb, '{}'::jsonb, '[]'::jsonb, '\"\"'::jsonb, '0'::jsonb))")


# the KEV rule as it stands at this migration: hot, and the version proven, and not patched or of an unknown version range
KEV_FIRE = f"""
    (c.kev IS TRUE OR c.exploit_db IS TRUE)
    AND m.distro_status <> 'patched'
    AND NOT ({_flag('unbounded')} AND m.version_in_range IS NULL AND m.template_result <> 'vulnerable'
             AND m.distro_status <> 'vulnerable' AND NOT {_flag('runzero')})
    AND (
        m.template_result IN ('vulnerable', 'version_only') OR m.distro_status = 'vulnerable' OR m.source = 'host'
        OR {_flag('host_reported')} OR {_flag('runzero')}
        OR EXISTS (SELECT 1 FROM "cveFeed_triage" t WHERE t.match_id = m.id AND t.validation_status = 'hit')
        OR (m.evidence ->> 'source' = 'tech' AND m.evidence ->> 'version_source' = 'body' AND m.evidence ->> 'copy_state' = 'effective'
            AND jsonb_typeof(m.evidence -> 'version_confidence') = 'number' AND (m.evidence ->> 'version_confidence')::numeric >= 0.8
            AND NOT {_flag('copies_unresolved')})
        OR (m.evidence ->> 'source' = 'port' AND m.evidence ->> 'method' = 'probed' AND {_flag('vendor_banner')} AND NOT {_flag('distro')})
    )
"""


def _legacy(value):
    return (value or '').strip().lower() in ('legacy', '0')


def baseline(apps, schema_editor):
    connection = schema_editor.connection if schema_editor is not None else default_connection
    cap = (os.environ.get('CVENGINE_VERSION_ONLY_MAX_HEAT') or '').strip().lower()
    cap = cap if cap in ('fire', 'smoke', 'ice') else 'smoke'
    with connection.cursor() as cursor:
        cursor.execute("""UPDATE "cveFeed_cvematch" SET fire_notified_rule = %s
                          WHERE fire_notified_at IS NOT NULL AND fire_notified_rule = ''""", [f'legacy:{cap}'])
        if _legacy(os.environ.get('CVENGINE_HEAT_POLICY')):
            return  # the legacy rule stays: the workers baseline it at start, with the code in force
        cursor.execute(f"""
            UPDATE "cveFeed_cvematch" AS m SET fire_notified_at = now(), fire_notified_rule = 'kev'
            FROM "cveFeed_cveentry" AS c
            WHERE c.id = m.cve_entry_id
              AND (m.fire_notified_at IS NULL OR m.fire_notified_rule <> 'kev')
              AND m.created_at < now() - interval '{GRACE_HOURS} hours'
              AND NOT EXISTS (SELECT 1 FROM "startScan_scanhistory" s WHERE s.id = m.scan_history_id
                              AND s.scan_status IN ({', '.join(str(v) for v in WAITING_SCAN_STATUSES)}))
              AND {KEV_FIRE}""")
        cursor.execute("""INSERT INTO "cveFeed_backgroundcursor" (lane, last_pk, updated_at) VALUES ('heat_baseline', 1, now())
                          ON CONFLICT (lane) DO UPDATE SET last_pk = 1, updated_at = now()""")


class Migration(migrations.Migration):
    dependencies = [
        ("cveFeed", "0136_cvematch_fire_notified"),
    ]

    operations = [
        migrations.AddField(
            model_name="cvematch",
            name="fire_notified_rule",
            field=models.CharField(blank=True, default="", max_length=24),
        ),
        migrations.RunPython(baseline, migrations.RunPython.noop),
    ]
