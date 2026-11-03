"""What kind of thing each product a CVE names is, so the checks and the guidance fit it (cveFeed.detection).

An advisory's ``affected`` list mixes very different things under one CVE: the jQuery library itself, its npm, Composer, Maven (WebJars),
NuGet and RubyGems packagings, an OS distribution's package of a daemon (Red Hat's ``openssh``), the distribution release itself (``Red Hat
Enterprise Linux 9``), a container image (``openshift/ose-rhel-coreos-9``), a CMS extension, or a network product named by its vendor. A check
that fits one is nonsense for another: nmap cannot read a JavaScript file, ``dpkg-query`` knows no npm package, and a RHEL release name is not a
banner. This module sorts each entry into one class, and folds the entries that are the same library under different ecosystem names into one
component that lists its coordinates.

Classes:
  client_library    a JavaScript library cvENGINE reads from the script files a page loads (``js_libraries.LIBRARIES``), with every packaging
                    of it as a coordinate (``npm jquery``, ``composer components/jquery``, ``maven org.webjars.npm:jquery``, ``gem jquery-rails``)
  language_package  a package of a language ecosystem (npm, PyPI, Maven, RubyGems, Packagist, NuGet, Go, crates.io): checked in the
                    application's dependency tree (its lockfile or package manager), never with dpkg, rpm or apk
  os_package        a package of an operating-system distribution (Debian, Ubuntu, Red Hat and its rebuilds, SUSE, Alpine): checked with that
                    distribution's own package manager only
  os_platform       a distribution release or platform the advisory names as the product (``Red Hat Enterprise Linux 9``): never a banner
  cms_component     a WordPress or Drupal plugin, theme or module: read from its readme or the CMS, never a JavaScript library of the same name
  network_product   anything else named by vendor and product (OpenSSH, nginx, Tomcat): its banner, header or the host's package
  other             a container image or an ecosystem cvENGINE cannot check (Bitnami images): named, never checked

Everything here is pure and reads only the CVE's own fields."""
import re

# OSV ecosystem names (lowercase, before any ":release" suffix) -> the package_version ecosystem a check uses
LANGUAGE_ECOSYSTEMS = {'npm': 'npm', 'pypi': 'pip', 'maven': 'maven', 'rubygems': 'gem', 'packagist': 'composer', 'nuget': 'nuget',
                       'go': 'go', 'crates.io': 'cargo'}
DISTRO_ECOSYSTEMS = {'debian': 'dpkg', 'ubuntu': 'dpkg', 'alpine': 'apk', 'red hat': 'rpm', 'redhat': 'rpm', 'rhel': 'rpm',
                     'rocky linux': 'rpm', 'almalinux': 'rpm', 'suse': 'rpm', 'opensuse': 'rpm', 'suse linux enterprise': 'rpm',
                     'oracle linux': 'rpm', 'fedora': 'rpm', 'centos': 'rpm', 'amazon linux': 'rpm', 'mageia': 'rpm', 'wolfi': 'apk',
                     'chainguard': 'apk'}
LANGUAGE = frozenset(LANGUAGE_ECOSYSTEMS.values())
DISTRO = frozenset(('dpkg', 'rpm', 'apk'))
# what a person calls each ecosystem
ECOSYSTEM_LABELS = {'npm': 'npm', 'pip': 'PyPI', 'maven': 'Maven', 'gem': 'RubyGems', 'composer': 'Composer (Packagist)', 'nuget': 'NuGet',
                    'go': 'Go modules', 'cargo': 'Cargo (crates.io)', 'dpkg': 'Debian / Ubuntu package', 'rpm': 'RPM package (Red Hat, SUSE)',
                    'apk': 'Alpine package', 'any': 'package'}
# vendors that publish OS packages: their advisory entries name a distribution package and, as the product, a release of the distribution
DISTRO_VENDORS = {'red hat': 'rpm', 'redhat': 'rpm', 'suse': 'rpm', 'canonical': 'dpkg', 'debian': 'dpkg', 'ubuntu': 'dpkg', 'alpine': 'apk',
                  'oracle linux': 'rpm', 'rocky': 'rpm', 'almalinux': 'rpm', 'amazon linux': 'rpm'}
_PLATFORM = re.compile(r'^(?:red hat (?:enterprise linux|openshift|ceph storage|satellite|jboss|software collections|virtualization|ansible)'
                       r'|rhel\b|enterprise linux\b|ubuntu\b|debian\b|suse linux|opensuse\b|sles\b|alpine linux|amazon linux|oracle linux|'
                       r'rocky linux|almalinux|centos\b|fedora\b)', re.IGNORECASE)
# a version string that is a distribution's own package build: el9, el8_4, fc39, deb12u1, ubuntu0.13, +deb, -r0 (Alpine), .sles
_DISTRO_BUILD = re.compile(r'(?:\.el\d|\.fc\d|\+deb\d|deb\d+u\d|ubuntu\d|\.amzn\d|-r\d+$|\.sles|\.mga\d)', re.IGNORECASE)
_DISTRO_BUILD_ECOSYSTEM = ((re.compile(r'\.el\d|\.fc\d|\.amzn\d|\.sles|\.mga\d', re.IGNORECASE), 'rpm'),
                           (re.compile(r'\+deb\d|deb\d+u\d|ubuntu\d', re.IGNORECASE), 'dpkg'), (re.compile(r'-r\d+$'), 'apk'))
_CMS_WORDS = re.compile(r'\b(?:WordPress (?:plugin|theme)|plugin for WordPress|theme for WordPress|SA-CONTRIB-\d|Drupal (?:module|theme|contrib)'
                        r'|Joomla! ?(?:extension|component|module))', re.IGNORECASE)
_CMS_PACKAGE = re.compile(r'^(?:drupal/(?!core$)|wpackagist-(?:plugin|theme)/|joomla/)', re.IGNORECASE)
# web servers and runtimes whose version a response header states (Server, X-Powered-By, X-AspNet-Version): read with curl, not nmap
WEB_SERVER_WORDS = re.compile(r'\b(?:nginx|openresty|apache http server|apache httpd|httpd|internet information services|\biis\b|'
                              r'microsoft-iis|tomcat|jetty|lighttpd|caddy|litespeed|tengine|php|asp\.net|express)\b', re.IGNORECASE)
# the binary package an OS ships a network product as, where it is not the product's own lowercase name (dpkg, rpm, apk)
OS_PACKAGE_NAMES = {
    'openssh': {'dpkg': 'openssh-server', 'rpm': 'openssh-server', 'apk': 'openssh-server'},
    'apache http server': {'dpkg': 'apache2', 'rpm': 'httpd', 'apk': 'apache2'},
    'apache httpd': {'dpkg': 'apache2', 'rpm': 'httpd', 'apk': 'apache2'},
    'httpd': {'dpkg': 'apache2', 'rpm': 'httpd', 'apk': 'apache2'},
    'bind': {'dpkg': 'bind9', 'rpm': 'bind', 'apk': 'bind'},
    'isc bind': {'dpkg': 'bind9', 'rpm': 'bind', 'apk': 'bind'},
    'nginx open source': {'dpkg': 'nginx', 'rpm': 'nginx', 'apk': 'nginx'},
    'postgresql': {'dpkg': 'postgresql', 'rpm': 'postgresql-server', 'apk': 'postgresql'},
    'mysql': {'dpkg': 'mysql-server', 'rpm': 'mysql-server', 'apk': 'mysql'},
    'mysql server': {'dpkg': 'mysql-server', 'rpm': 'mysql-server', 'apk': 'mysql'},
    'samba': {'dpkg': 'samba', 'rpm': 'samba', 'apk': 'samba'},
    'exim': {'dpkg': 'exim4-daemon-light', 'rpm': 'exim', 'apk': 'exim'},
    'openssl': {'dpkg': 'openssl', 'rpm': 'openssl', 'apk': 'openssl'},
}
_PLAIN_PACKAGE = re.compile(r'^[a-z0-9][a-z0-9.+_-]{0,99}\Z')  # what an OS package name looks like: lowercase, no scope, no group, no path


def _lower(value):
    return str(value or '').strip().lower()


# packagings that publish a library under a name of their own (NuGet): the library they are, when the advisory names that library
PACKAGING_ALIASES = {'jquery.ui.combined': 'jquery-ui', 'angularjs.core': 'angularjs', 'jquery.ui': 'jquery-ui', 'twitter.bootstrap': 'bootstrap',
                     'underscore.js': 'underscore', 'lodash.js': 'lodash'}


def library_of(name, libraries=()):
    """The client-side library key ``name`` is (``detection.library_key``, or a packaging alias of one of ``libraries``), or ''."""
    from cveFeed.detection import library_key
    key = library_key(name)
    if key:
        return key
    alias = PACKAGING_ALIASES.get(_lower(name), '')
    return alias if alias in libraries else ''


def stated_ecosystem(item):
    """The package_version ecosystem an advisory entry states (OSV ``ecosystem``, ``Debian:12`` read as its distribution), '' when it states
    none, or 'other' for one cvENGINE cannot check (Bitnami, Hex, Pub, a container registry)."""
    raw = _lower(item.get('ecosystem'))
    if not raw:
        return ''
    base = raw.split(':')[0].strip()
    if base in LANGUAGE_ECOSYSTEMS:
        return LANGUAGE_ECOSYSTEMS[base]
    for name, eco in DISTRO_ECOSYSTEMS.items():
        if base == name or base.startswith(name + ' '):
            return eco
    return 'other'


def inferred_ecosystem(item, library=''):
    """The ecosystem an entry with no stated one most likely belongs to, from its own shape, or ''. Conservative: a guess is made only where the
    name cannot be anything else (a Maven ``group:artifact``, an npm ``@scope/name``, a Composer ``vendor/name`` of a library, a RubyGems
    ``*-rails`` that vendors a library, a distribution vendor's package)."""
    from cveFeed.detection import BUNDLED_BY
    package = str(item.get('package') or '').strip()
    vendor = _lower(item.get('vendor'))
    low = package.lower()
    if not package:
        return ''
    if re.match(r'^[a-z0-9_.-]+\.[a-z0-9_.-]+:[a-z0-9_.-]+\Z', low):
        return 'maven'
    if low.startswith('@') and '/' in low:
        return 'npm'
    if any(low in names for names in BUNDLED_BY.values()) or low.endswith('-rails'):
        return 'gem'
    if '/' in low:
        if re.match(r'^(?:github\.com|gitlab\.com|golang\.org|go\.[a-z0-9.-]+|gopkg\.in|k8s\.io|sigs\.k8s\.io)/', low):
            return 'go'
        if vendor in DISTRO_VENDORS:
            return 'other'  # a distribution vendor's name with a path is a container image (openshift/ose-rhel-coreos-9), not a package
        return 'composer' if library else ''
    if vendor in DISTRO_VENDORS and _PLAIN_PACKAGE.match(low):
        return DISTRO_VENDORS[vendor]
    if library and low == library:
        return 'npm'  # the library's own lowercase name as a package: npm, where every one of these libraries is published
    fixes = [str(r.get('fixed') or r.get('lastAffected') or r.get('last_affected') or '') for r in item.get('ranges') or [] if isinstance(r, dict)]
    for pattern, eco in _DISTRO_BUILD_ECOSYSTEM:
        if any(pattern.search(f) for f in fixes) and _PLAIN_PACKAGE.match(low):
            return eco
    return ''


def is_cms_component(item, text=''):
    """Whether an advisory is about a CMS extension (a WordPress plugin or theme, a Drupal module): its words say so, or a package is one."""
    package = str(item.get('package') or '')
    if _CMS_PACKAGE.match(package) or _CMS_WORDS.search(text or ''):
        return True
    return _lower(item.get('vendor')) == 'drupal' and _lower(item.get('product')) not in ('drupal', 'drupal core', '')


def classify(item, text='', libraries=()):
    """``(class, ecosystem)`` for one advisory entry (see the module docstring). ``libraries`` are the client-side library keys the CVE names
    (``detection.cve_libraries``): a packaging that vendors one of them is a coordinate of that library."""
    from cveFeed.detection import _bundles
    product, package = str(item.get('product') or ''), str(item.get('package') or '')
    stated = stated_ecosystem(item)
    if is_cms_component(item, text) and stated not in DISTRO:
        return 'cms_component', stated if stated in LANGUAGE else ''
    key = next((library_of(n, libraries) for n in (product, package) if library_of(n, libraries)), '')
    if key and key in libraries:
        eco = stated or inferred_ecosystem(item, key)
        return 'client_library', eco if eco in LANGUAGE else ''
    if libraries and any(_bundles(n, libraries) for n in (product, package) if n):
        eco = stated or inferred_ecosystem(item, '')
        return 'client_library', eco if eco in LANGUAGE else ''
    eco = stated or inferred_ecosystem(item)
    if eco == 'other':
        return 'other', ''
    if eco in LANGUAGE:
        return 'language_package', eco
    if product and _PLATFORM.match(product.strip()):
        return ('os_platform', eco or DISTRO_VENDORS.get(_lower(item.get('vendor')), '')) if not package else (
            'os_package', eco or DISTRO_VENDORS.get(_lower(item.get('vendor')), ''))
    if eco in DISTRO:
        return 'os_package', eco
    return 'network_product', ''


def os_package_name(product, ecosystem):
    """The binary package an OS ships ``product`` as for ``ecosystem`` (dpkg, rpm, apk), or the product's lowercase name, or '' when that is
    not a package name at all (a name with spaces, a scope or a path)."""
    low = _lower(product)
    mapped = OS_PACKAGE_NAMES.get(low, {}).get(ecosystem) if ecosystem in DISTRO else None
    if mapped:
        return mapped
    if ecosystem == 'any':
        mapped = OS_PACKAGE_NAMES.get(low, {}).get('dpkg')
        if mapped:
            return mapped
    return low if _PLAIN_PACKAGE.match(low) else ''


def is_distro_build(version):
    """Whether a version is a distribution's own package build (``8.7p1-38.el9_4.4``, ``1:9.6p1-3ubuntu13.5``): it means nothing to another
    distribution or to the upstream version a banner states."""
    return bool(_DISTRO_BUILD.search(str(version or '')))


def components(affected, text='', libraries=()):
    """The advisory's entries folded into components: ``[{'name', 'class', 'library', 'coordinates': [{'ecosystem', 'package'}], 'entries':
    [indexes]}]`` in the order the advisory names them. Every entry of one client-side library (its own name, each packaging, a package that
    vendors it) is one component; an OS package and the releases that ship it are one component per package name; anything else is one
    component per product name. ``libraries`` as in ``classify``."""
    from cveFeed.correlation import clean_affected
    from cveFeed.detection import _PACKAGE, _bundles, _libraries as library_table
    out, index = [], {}
    for position, item in enumerate(clean_affected(affected)):
        cls, eco = classify(item, text, libraries)
        product, package = str(item.get('product') or '').strip(), str(item.get('package') or '').strip()
        if product.lower() in ('n/a', 'unknown', '*'):
            product = ''
        if cls == 'client_library':
            key = next((library_of(n, libraries) for n in (product, package) if library_of(n, libraries)), '') or next(
                (k for k in libraries if any(_bundles(n, (k,)) for n in (product, package) if n)), '')
            group, name = ('lib', key), library_table()[key][0] if key in library_table() else (product or package)
        elif cls == 'os_package':
            group, name = ('os', (package or product).lower()), package or product
        else:
            group, name = (cls, (product or package).lower()), product or package
        if not name:
            continue
        comp = index.get(group)
        if comp is None:
            comp = {'name': name, 'class': cls, 'library': group[1] if cls == 'client_library' else '', 'coordinates': [], 'entries': [],
                    'vendor': str(item.get('vendor') or '')[:60]}
            index[group] = comp
            out.append(comp)
        comp['entries'].append(position)
        if cls == 'os_package' and not comp.get('platforms') and product and product != package:
            comp['platforms'] = []
        if cls == 'os_package' and product and product != package and product not in comp.get('platforms', []):
            comp.setdefault('platforms', []).append(product[:100])
        coordinate_eco = eco or ('any' if cls == 'network_product' else '')
        if package and coordinate_eco and _PACKAGE.match(package):
            coordinate = {'ecosystem': coordinate_eco, 'package': package}
            if coordinate not in comp['coordinates']:
                comp['coordinates'].append(coordinate)
    return out


# --- what a person reads to tell a library's version, per library (curated, reviewed constants; never taken from a scan or a feed) ------
# console: an expression typed into the browser's developer console on the page, which prints the version of the copy that runs (each
#          verified against the library's own source: jQuery.fn.jquery, jQuery.ui.version, jQuery.migrateVersion, angular.version.full,
#          React.version, Vue.version, _.VERSION, moment.version, jQuery.fn.dataTable.version; Bootstrap 3 and 4 set VERSION on each jQuery
#          plugin's Constructor, Bootstrap 5 on the bootstrap global). '' where the library exposes none.
# banner:  the first line of the library's own file, with {version} filled in (what the html-libraries read looks for).
# grep:    an extended regular expression that finds that banner line in a bundled copy on disk.
LIBRARY_FACTS = {
    'jquery': {'console': 'jQuery.fn.jquery', 'banner': '/*! jQuery v{version} | (c) ... | jquery.org/license */',
               'grep': 'jQuery (JavaScript Library )?v[0-9][0-9.]*'},
    'jquery-ui': {'console': 'jQuery.ui.version', 'banner': '/*! jQuery UI - v{version} - ...', 'grep': 'jQuery UI - v[0-9][0-9.]*'},
    'jquery-migrate': {'console': 'jQuery.migrateVersion', 'banner': '/*! jQuery Migrate v{version} | (c) ... | jquery.org/license */',
                       'grep': 'jQuery Migrate (- )?v[0-9][0-9.]*'},
    'bootstrap': {'console': '', 'banner': '/*! Bootstrap v{version} (https://getbootstrap.com/) ...', 'grep': 'Bootstrap v[0-9][0-9.]*'},
    'angularjs': {'console': 'angular.version.full', 'banner': '/** @license AngularJS v{version} ...', 'grep': '@license AngularJS v[0-9][0-9.]*'},
    'react': {'console': 'React.version', 'banner': '/** @license React v{version} ...', 'grep': '@license React v[0-9][0-9.]*'},
    'vue': {'console': 'Vue.version', 'banner': '/*! Vue.js v{version} ...', 'grep': 'Vue\\.js v[0-9][0-9.]*'},
    'lodash': {'console': '_.VERSION', 'banner': '/** @license Lodash ... lodash {version} ...', 'grep': '[Ll]odash [0-9][0-9.]*'},
    'moment': {'console': 'moment.version', 'banner': '//! moment.js\n//! version : {version}', 'grep': '//! version : [0-9][0-9.]*'},
    'underscore': {'console': '_.VERSION', 'banner': '//     Underscore.js {version}', 'grep': 'Underscore\\.js [0-9][0-9.]*'},
    'swiper': {'console': '', 'banner': '/** Swiper {version} ...', 'grep': 'Swiper [0-9][0-9.]*'},
    'datatables': {'console': 'jQuery.fn.dataTable.version', 'banner': '/*! DataTables {version} ...', 'grep': 'DataTables [0-9][0-9.]*'},
}


def console_expression(key, version=''):
    """The console expression that prints ``key``'s running version, chosen for the major release ``version`` names where the library
    changed where it keeps it (Bootstrap 3 and 4 against 5). '' when the library exposes none."""
    if key == 'bootstrap':
        major = re.match(r'(\d+)', str(version or ''))
        if major and int(major.group(1)) >= 5:
            return 'bootstrap.Tooltip.VERSION'
        if major and int(major.group(1)) in (3, 4):
            return 'jQuery.fn.tooltip.Constructor.VERSION'
        return ''
    return LIBRARY_FACTS.get(key, {}).get('console', '')


# --- the condition the advisory states for the flaw to be usable (by rules, from its own words: quoted, never a payload) --------------------
_STRONG = re.compile(r'\b(?:untrusted|attacker[- ]controlled|user[- ]controlled|user[- ]supplied|user[- ]provided|crafted|only (?:when|if)|'
                     r'requires?|must (?:be|have)|(?:is|are) enabled|when (?:the|a|an) [a-z0-9 _.-]{1,40} (?:is|are) (?:enabled|used|configured|set))\b',
                     re.IGNORECASE)
_WEAK = re.compile(r'\b(?:when|if|via|through|by (?:passing|sending|using))\b', re.IGNORECASE)


def exploit_precondition(description):
    """The sentence of an advisory's description that says what must hold for the flaw to be used (untrusted input reaching a function, a
    feature turned on), trimmed to 300 characters; '' when no sentence says so. Plain text from a third-party feed: shown quoted, as the
    advisory's words, never run and never turned into a test."""
    from reNgine.ai_providers import clean_text
    text = clean_text(str(description or ''), 2500) or ''
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+(?=[A-Z])', text) if 20 <= len(s.strip())]
    for pattern in (_STRONG, _WEAK):
        for sentence in sentences:
            if pattern.search(sentence):
                return sentence if len(sentence) <= 300 else sentence[:297].rsplit(' ', 1)[0] + '...'
    return ''


def language_ecosystem_of(package):
    """The language ecosystem a package name can only belong to (a Maven ``group:artifact``, an npm ``@scope/name``, a Composer or Go
    ``path/name``), or ''. For a check written with ecosystem ``any``: such a name is never an OS package, so dpkg, rpm and apk are never
    run for it."""
    low = str(package or '').strip().lower()
    if re.match(r'^[a-z0-9_.-]+\.[a-z0-9_.-]+:[a-z0-9_.-]+\Z', low):
        return 'maven'
    if low.startswith('@') and '/' in low:
        return 'npm'
    if re.match(r'^(?:github\.com|gitlab\.com|golang\.org|go\.[a-z0-9.-]+|gopkg\.in|k8s\.io|sigs\.k8s\.io)/', low):
        return 'go'
    if re.match(r'^[a-z0-9_.-]+/[a-z0-9_.-]+\Z', low):
        return 'composer'
    return ''
