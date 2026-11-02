"""Shared (multi-tenant) domains and the scope of a target that sits under one.

A tenant of a SaaS, cloud, CDN, source-hosting or pages provider owns only its own subdomain
(``acme.jfrog.com``), never the registrable domain the provider runs (``jfrog.com``). Promoting such a target to
its registrable apex and enumerating it would scan the provider and every other customer, so a target under a
shared domain is *host scoped*: the ownable scope is the host itself.

Pure Python (no Django) so it is unit testable on its own.
"""
from targetApp.target_types import apex_domain

# NON-EXHAUSTIVE and EDITABLE: add a provider here when you find a tenant domain that is missing. Many of these are NOT
# Public Suffix List entries (the PSL's private section lists some, such as github.io and herokuapp.com, and
# tldextract ignores that section by default), so ``apex_domain`` alone cannot tell ``acme.jfrog.com`` from
# ``acme-example.ai``; that is exactly why CVEngine keeps its own list. An entry covers itself and everything under it, so
# ``amazonaws.com`` also covers ``s3.us-east-1.amazonaws.com`` and every elb or compute host, and ``windows.net``
# covers ``blob.core.windows.net``. A target the user really owns can opt out per domain (Domain.scope_mode = 'parent').
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
    'fastly.net', 'akamaihd.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net', 'b-cdn.net',
    # app, blog and site hosts, tunnels and object storage whose customers each get a name under the provider's
    'onrender.com', 'blogspot.com', 'fly.dev', 'railway.app', 'deno.dev', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev',
    'wixsite.com', 'squarespace.com', 'webflow.io', 'ondigitalocean.app', 'digitaloceanspaces.com', 'r2.dev',
    'storage.googleapis.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt',
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


def is_shared_apex(apex):
    """True when ``apex`` is a shared (multi-tenant) domain, or a name under one: nobody owns it as a whole."""
    return shared_domain_of(apex) is not None


def is_provider_domain(name):
    """True when ``name`` IS a shared domain (``jfrog.com``), not a tenant under one: a name no certificate-transparency query or
    enumeration may ever be run against."""
    return shared_domain_of(name) == _clean(name)


def effective_apex(name):
    """``(scope, host_scoped)`` for a domain target.

    - a tenant under a shared domain (``acme.jfrog.com``) -> ``(name, True)``: the host is the ownable scope, never the
      provider's apex;
    - a shared domain itself, added directly (``jfrog.com``) -> ``(name, True)``: never promoted or used to enumerate;
    - an owned name (``hr.clouds.acme-example.ai``) -> ``(registrable domain, False)``;
    - anything that is not a domain name (an IP, junk) -> ``(None, False)``.
    """
    name = _clean(name)
    registrable = apex_domain(name)
    if registrable is None:
        return None, False
    if is_shared_apex(registrable) or is_shared_apex(name):
        return name, True
    return registrable, False
