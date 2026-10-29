"""Clean up targets the weekly apex sweep created for shared provider domains.

Earlier releases promoted ``acme.jfrog.com`` to its registrable apex ``jfrog.com`` and deep-scanned all of it (likewise
``atlassian.net``). Those rows were created by the sweep with a fixed description. This migration:

- deletes a shared-provider domain whose description is that marker (the sweep made it; its scans and findings were out of scope,
  and the foreign keys cascade);
- leaves a shared-provider domain the user added themselves in place but sets scope_mode='host' so it stops enumerating the provider.

Reverse is a no-op: deleted rows are not recreated.
"""
import logging

from django.db import migrations

logger = logging.getLogger(__name__)

AUTO_MARKER = "Added for the weekly deep discovery of its subdomains"

# Frozen copy of targetApp.shared_domains (SHARED_DOMAINS, shared_domain_of) as of this migration.
# Never import the live code into a migration: a later change to it must not alter (or break at import)
# what this migration does when a fresh install replays them all.
# An entry covers itself and everything under it.
SHARED_DOMAINS = frozenset({
    # artifact, issue tracking, support, status and docs SaaS
    'jfrog.com', 'jfrog.io', 'atlassian.net', 'atlassian.com', 'jira.com', 'zendesk.com', 'freshdesk.com',
    'statuspage.io', 'readthedocs.io', 'readthedocs.org', 'surge.sh', 'myshopify.com', 'wpengine.com',
    'service-now.com', 'salesforce.com', 'force.com', 'okta.com', 'oktapreview.com', 'okta-emea.com',
    'cloudflareaccess.com', 'onmicrosoft.com', 'sharepoint.com',
    # source hosting and static pages
    'github.io', 'gitlab.io', 'netlify.app', 'netlify.com', 'vercel.app', 'pages.dev', 'workers.dev',
    'herokuapp.com', 'herokudns.com', 'web.app', 'firebaseapp.com',
    # Amazon Web Services (covers s3.amazonaws.com, s3.<region>.amazonaws.com, elb, elasticbeanstalk and compute hosts)
    'amazonaws.com', 's3.amazonaws.com', 'elasticbeanstalk.com', 'cloudfront.net', 'awsapprunner.com',
    # Microsoft Azure
    'azurewebsites.net', 'cloudapp.azure.com', 'cloudapp.net', 'azureedge.net', 'azurefd.net', 'trafficmanager.net',
    'windows.net', 'blob.core.windows.net',
    # Google Cloud
    'appspot.com', 'cloudfunctions.net', 'run.app', 'googleusercontent.com',
    # CDNs
    'fastly.net', 'akamaihd.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net',
})


def _clean(name):
    return (name or '').strip().lower().rstrip('.')


def shared_domain_of(name):
    """The SHARED_DOMAINS entry that ``name`` is or sits under (the longest), or None."""
    labels = _clean(name).split('.')
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in SHARED_DOMAINS:
            return candidate
    return None


def remove_shared_apexes(apps, schema_editor):
    Domain = apps.get_model('targetApp', 'Domain')
    deleted, host_scoped = [], []
    for row in Domain.objects.all().order_by('id'):
        if shared_domain_of(row.name) != (row.name or "").strip().lower().rstrip("."):
            continue
        # only a bare provider domain (jfrog.com), not a tenant under it (acme.jfrog.com), is the sweep's doing
        if (row.description or '').strip() == AUTO_MARKER:
            deleted.append(row)
        elif row.scope_mode != 'host':
            host_scoped.append(row.id)
    for row in deleted:
        row.delete()
    if host_scoped:
        Domain.objects.filter(id__in=host_scoped).update(scope_mode='host')
    if deleted or host_scoped:
        logger.warning('shared-domain scope cleanup: removed %d auto-created provider domain(s) (%s); set %d user-added shared domain(s) to host scope',
                       len(deleted), ', '.join(r.name for r in deleted[:20]), len(host_scoped))


class Migration(migrations.Migration):

    dependencies = [
        ('targetApp', '0002_domain_scope_mode'),
        ('startScan', '0010_ip_full_scan'),  # the foreign keys that cascade from a Domain must be in the migration state
        ('cveFeed', '0039_full_scan_schedule'),
    ]

    operations = [
        migrations.RunPython(remove_shared_apexes, migrations.RunPython.noop),
    ]
