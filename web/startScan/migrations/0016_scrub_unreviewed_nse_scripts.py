from django.db import migrations

# A frozen copy of cveFeed.nmap_scan.NSE_SCRIPTS at the time this migration was written. Never import the live
# constant into a migration: a later change to that list must not silently change what an old migration does, on a
# fresh install replaying every migration in order or a reinstall replaying this one again.
REVIEWED_SCRIPTS = frozenset((
    'banner', 'ssh-hostkey', 'ssh2-enum-algos', 'ssl-cert', 'http-headers', 'http-title', 'ftp-anon',
    'rdp-ntlm-info', 'rdp-enum-encryption', 'smb-os-discovery', 'nbstat', 'mysql-info', 'ms-sql-info',
    'ms-sql-ntlm-info', 'mongodb-info', 'redis-info', 'memcached-info', 'couchdb-stats',
))


def scrub(apps, schema_editor):
    """nmap's -sV silently runs its whole "version" NSE category (rpcinfo, hnap-info, vmware-version, and more)
    on top of whatever --script asked for, and writes their output to the XML this project parses, regardless of
    version. CVEngine now drops anything outside REVIEWED_SCRIPTS before it is ever stored (see
    cveFeed.nmap_scan._reviewed_scripts), but an install that scanned before that fix, or before NSE_SCRIPTS was
    first narrowed down from nmap's broader defaults, still has the old, unreviewed script output sitting on its
    Port and IpAddress rows. One pass strips it so an upgrade does not leave days of stale noise on the host page."""
    Port = apps.get_model('startScan', 'Port')
    IpAddress = apps.get_model('startScan', 'IpAddress')

    batch = []
    for port in Port.objects.all().iterator(chunk_size=2000):
        scripts = (port.extra or {}).get('scripts')
        if not isinstance(scripts, dict):
            continue
        kept = {sid: text for sid, text in scripts.items() if sid in REVIEWED_SCRIPTS}
        if kept == scripts:
            continue
        extra = dict(port.extra)
        if kept:
            extra['scripts'] = kept
            extra['script_text'] = '\n'.join(kept.values())
        else:
            extra.pop('scripts', None)
            extra.pop('script_text', None)
        port.extra = extra
        batch.append(port)
        if len(batch) >= 2000:
            Port.objects.bulk_update(batch, ['extra'])
            batch = []
    if batch:
        Port.objects.bulk_update(batch, ['extra'])

    batch = []
    for ip in IpAddress.objects.all().iterator(chunk_size=2000):
        scripts = (ip.fingerprint or {}).get('scripts')
        if not isinstance(scripts, dict):
            continue
        kept = {sid: text for sid, text in scripts.items() if sid in REVIEWED_SCRIPTS}
        if kept == scripts:
            continue
        fingerprint = dict(ip.fingerprint)
        if kept:
            fingerprint['scripts'] = kept
        else:
            fingerprint.pop('scripts', None)
        ip.fingerprint = fingerprint
        batch.append(ip)
        if len(batch) >= 2000:
            IpAddress.objects.bulk_update(batch, ['fingerprint'])
            batch = []
    if batch:
        IpAddress.objects.bulk_update(batch, ['fingerprint'])


class Migration(migrations.Migration):
    dependencies = [('startScan', '0015_technology_version_category')]
    operations = [
        migrations.RunPython(scrub, migrations.RunPython.noop),
    ]
