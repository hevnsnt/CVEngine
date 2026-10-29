import re

from django.db import migrations, models

# Frozen copy of cveFeed.correlation.split_name_version and cveFeed.fingerprint.categorize as of this migration.
# Never import the live code into a migration: a later change to it must not alter (or break at import)
# what this migration does when a fresh install replays them all.
# A technology some scanner stored as a CPE ("cpe:/a:openbsd:openssh:7.2p2") or as a banner token ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"):
# the product and version are in there, not in a name that happens to contain colons or an underscore.
_CPE_TECH_RE = re.compile(r"^cpe:(?:/a:|2\.3:a:)([^:\s]*):([^:\s]+)(?::([^:\s]+))?", re.IGNORECASE)
_BANNER_TECH_RE = re.compile(r"^([A-Za-z][\w.+-]*?)_(\d[\w.+~-]*)(?:\s|$)")


def split_name_version(tech_name):
    """reNgine stores tech as 'Name' or 'Name:version' (httpx tech-detect); a scanner may also store a CPE or a 'Name_version' banner."""
    if not tech_name:
        return "", ""
    name = tech_name.strip()
    cpe = _CPE_TECH_RE.match(name)
    if cpe:
        version = cpe.group(3) or ""
        return cpe.group(2).replace("_", " "), version if version[:1].isdigit() else ""
    banner = _BANNER_TECH_RE.match(name)
    if banner:
        return banner.group(1).replace("_", " "), banner.group(2)
    if ":" in name:
        base, _, ver = name.rpartition(":")
        if ver and ver[0].isdigit():
            return base.strip(), ver.strip()
    return name, ""


CATEGORIES = {
    "language": ("php", "python", "ruby", "java", "node.js", "asp.net", "perl"),
    "web server": ("nginx", "apache http server", "apache", "microsoft iis", "openresty", "litespeed", "caddy", "gunicorn", "kestrel",
                   "apache tomcat", "jetty", "lighttpd", "envoy", "traefik", "haproxy", "google web server", "varnish"),
    "cdn": ("cloudflare", "amazon cloudfront", "akamai", "fastly"),
    "hosting": ("netlify", "vercel", "github pages", "heroku", "amazon s3", "aws elastic load balancing", "wp engine", "servd",
                "firebase hosting", "render"),
    "cms": ("wordpress", "drupal", "craft cms", "joomla", "shopify", "datocms", "ghost", "contentful", "strapi", "typo3"),
    "javascript library": ("jquery", "bootstrap", "angularjs", "lodash", "moment.js", "underscore.js", "datatables", "swiper"),
    "framework": ("next.js", "nuxt.js", "django", "laravel", "express", "react", "vue.js", "angular", "svelte", "symfony", "rails"),
    "analytics": ("google tag manager", "google analytics", "hotjar", "segment"),
}
_CATEGORY_OF = {name: category for category, names in CATEGORIES.items() for name in names}


def categorize(name):
    """The kind of technology a stored name is ('web server', 'language', 'cms', 'cdn', 'hosting', 'framework', 'analytics'),
    or '' for one that is not in the table."""
    base = re.sub(r"[-_]+", " ", (name or "").split(":")[0].strip().lower())
    return _CATEGORY_OF.get(base, "")


def fill(apps, schema_editor):
    Technology = apps.get_model('startScan', 'Technology')
    batch = []
    for tech in Technology.objects.all().iterator(chunk_size=2000):
        _base, version = split_name_version(tech.name or '')
        category = categorize(tech.name or '')
        if (tech.version, tech.category) != (version, category):
            tech.version, tech.category = version, category
            batch.append(tech)
        if len(batch) >= 2000:
            Technology.objects.bulk_update(batch, ['version', 'category'])
            batch = []
    if batch:
        Technology.objects.bulk_update(batch, ['version', 'category'])


class Migration(migrations.Migration):
    dependencies = [('startScan', '0014_ip_fingerprint')]
    operations = [
        migrations.AddField('technology', 'version', models.CharField(blank=True, default='', max_length=200)),
        migrations.AddField('technology', 'category', models.CharField(blank=True, db_index=True, default='', max_length=40)),
        migrations.RunPython(fill, migrations.RunPython.noop),
    ]
