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
    from cvengine.ai_providers import clean_text
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


# --- the service features an advisory says the flaw needs (by rules, from its own words) --------------------------------------------------
# One rule table: each rule is a CVE predicate (the advisory's wording, read from its title and description: ``needs``, unless ``not_needed``
# says the flaw is reached without the feature) and what it means for a reading of one service feature (``cvengine_scanner.features``): the
# reading values that make the host exposed (``exposed``, any of a reading's comma-joined tokens) and the values that rule it out (``rule_out``,
# every token; None: every reading that is not exposed). ``unread`` names a way to the feature that no Sentinel reads (cleartext HTTP/2, h2c,
# is never probed): the precondition stays, but its absence never rules a match out. Evaluated in one place (cveFeed.service_features); a new
# feature is a new rule here and a vocabulary entry, never new correlation code.
#
# HTTP/2. A feature named only as the flaw's protocol ("a crafted HTTP/2 request", "the HTTP/2 implementation") is NOT a precondition: such an
# advisory says nothing of whether HTTP/2 has to be turned on, and a stated precondition is all this rule reads.
_HTTP2 = r'HTTP/?2(?:\.0)?'
_NEVER = re.compile(r'(?!)')  # a rule part that never holds
# An advisory that names no mail server or SMTP at all is not an SMTP advisory: an SMTP reading says nothing of it (an NTLM or STARTTLS flaw of
# another protocol). Used as ``not_needed`` of the SMTP rules.
_NOT_SMTP = re.compile(r'\A(?![\s\S]*\b(?:SMTP|ESMTP|Exim|Postfix|Sendmail|OpenSMTPD|qmail|MTA)\b)', re.IGNORECASE)
FEATURE_RULES = (
    {'id': 'http2_enabled', 'feature': 'http2', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(
         r'\bngx_http_v2_module\b|\bmod_http2\b|\b' + _HTTP2 + r' (?:protocol )?module\b'
         r'|\b(?:configurations?|configured|deployments?|instances?|servers?|sites?|virtual hosts?)\s+(?:that\s+|which\s+|to\s+)?'
         r'(?:use|uses|using|enable|enables|serve|serves|support|supports|have)\s+' + _HTTP2 + r'\b'
         r'|\bwhen (?:they |it )?(?:use|uses|using|serves?|serving) ' + _HTTP2 + r'\b'
         r'|\b(?:when|if|where|with|while|only (?:when|if))\s+(?:the\s+)?' + _HTTP2 + r'(?:\s+(?:support|protocol|module))?\s+'
         r'(?:is|was|are|has been|have been)\s+(?:enabled|configured|turned on|in use|used|active|negotiated)\b'
         r'|\bwith ' + _HTTP2 + r' (?:support )?(?:enabled|turned on|configured)\b'
         r'|\bhttp2 (?:option|parameter|directive)\b|[\'"]http2[\'"] (?:option|parameter|directive)|\blisten\b[^.]{0,60}\bhttp2\b|\bhttp2 on\b'
         r'|\bProtocols\b[^.]{0,40}\bh2\b',
         re.IGNORECASE),
     'not_needed': re.compile(
         r'\bHTTP/1(?:\.[01x])?\s*(?:,|and|or|/)\s*(?:HTTP/)?2\b|\b' + _HTTP2 + r'\s*(?:,|and|or|/)\s*HTTP/(?:1|3)\b'
         r'|\bregardless of (?:the )?(?:HTTP )?protocol|\b(?:does not|doesn\'t|do not) (?:require|need) ' + _HTTP2 + r'\b'
         r'|\bnot (?:limited|specific|restricted) to ' + _HTTP2 + r'\b',
         re.IGNORECASE),
     'unread': re.compile(r'\bh2c\b|\bcleartext ' + _HTTP2 + r'|' + _HTTP2 + r' over (?:cleartext|plain ?text|TCP)\b|\bprior knowledge\b',
                          re.IGNORECASE)},
    # --- SSH, read from the server's KEXINIT (nmap's ssh2-enum-algos in the fingerprint pass, the ssh_probe kind) -------------------------------
    # Terrapin (CVE-2023-48795): "... aka a Terrapin attack". The prefix truncation needs ChaCha20-Poly1305 or a CBC cipher with an EtM MAC, and
    # strict key exchange (kex-strict-*-v00@openssh.com) is the fix: a server that offers it, or neither affected mode, rules the match out.
    {'id': 'ssh_terrapin', 'feature': 'ssh_terrapin', 'exposed': ('exposed',), 'rule_out': ('strict_kex', 'no_affected_mode'),
     'needs': re.compile(r'\bTerrapin\b|\bprefix truncation attack', re.IGNORECASE), 'not_needed': _NEVER, 'unread': _NEVER},
    # CVE-2008-5161: "Error handling in the SSH protocol in ... OpenSSH 4.7p1 ..., when using a block cipher algorithm in Cipher Block Chaining
    # (CBC) mode, makes it easier ... to recover certain plaintext data". The SSH product and the CBC condition in one sentence; a TLS or SSL
    # advisory is not this rule's (its CBC is a TLS cipher suite, which the SSH reading says nothing of).
    {'id': 'ssh_cbc_mode', 'feature': 'ssh_cbc', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\b(?:SSH|sshd|OpenSSH)\b.{0,600}?\b(?:Cipher Block Chaining|CBC)\b(?:\s*\(CBC\))?\s+mode\b', re.IGNORECASE | re.DOTALL),
     'not_needed': re.compile(r'\b(?:TLS|SSLv?[23]?|DTLS|HTTPS)\b'), 'unread': _NEVER},
    # CVE-2013-4548: "The mm_newkeys_from_blob function in monitor_wrap.c in sshd in OpenSSH 6.2 and 6.3, when an AES-GCM cipher is used, ..."
    {'id': 'ssh_aes_gcm', 'feature': 'ssh_aes_gcm', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\b(?:sshd|OpenSSH|SSH)\b.{0,400}?\bwhen an? AES-GCM cipher is (?:used|negotiated|in use)\b', re.IGNORECASE | re.DOTALL),
     'not_needed': re.compile(r'\b(?:TLS|SSLv?[23]?|DTLS|HTTPS)\b'), 'unread': _NEVER},
    # --- SMTP, read from one cleartext EHLO (the nmap fingerprint pass's follow-up) ------------------------------------------------------------
    # CVE-2017-16943, CVE-2017-16944: "The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows ... via vectors
    # involving BDAT commands". BDAT exists only when the server lists CHUNKING (RFC 3030); Exim's own workaround was chunking_advertise_hosts =.
    # Only for an advisory about a mail server (``_NOT_SMTP``).
    {'id': 'smtp_bdat', 'feature': 'smtp_chunking', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bBDAT\b|\bCHUNKING (?:extension|command|support)\b'), 'not_needed': _NOT_SMTP, 'unread': _NEVER},
    # CVE-2023-42114, CVE-2023-42116 ("... the handling of NTLM challenge requests", Exim), CVE-2020-12783 ("an out-of-bounds read in the SPA
    # authenticator that could result in SPA/NTLM authentication bypass", Exim): reached through AUTH NTLM, which the server lists only when the
    # SPA authenticator is configured (Exim's advisory: "Do not use SPA (NTLM) authentication"). A list read before STARTTLS that may grow after
    # it (``tls_unread``) shows NTLM but never clears it.
    {'id': 'smtp_auth_ntlm', 'feature': 'smtp_auth', 'exposed': ('ntlm',),
     'rule_out': ('external', 'gssapi', 'cram-md5', 'digest-md5', 'plain', 'login', 'xoauth2', 'oauthbearer', 'scram-sha-1', 'scram-sha-256',
                  'other', 'none'),
     'needs': re.compile(r'\bNTLM challenge\b|\bSPA authenticator\b|\bSPA/NTLM\b|\bAUTH NTLM\b', re.IGNORECASE),
     'not_needed': _NOT_SMTP, 'unread': _NEVER},
    # CVE-2011-0411: "The STARTTLS implementation in Postfix ... allows man-in-the-middle attackers to insert commands into encrypted SMTP
    # sessions", CVE-2021-33515 (Dovecot submission: "allows STARTTLS command injection in lib-smtp"): a server that does not list STARTTLS has
    # no such implementation in reach. Never an IMAP, POP3 or other protocol's STARTTLS, and never the sending side (Exim's CVE-2021-38371,
    # "during MTA SMTP sending"), which no listening port shows.
    {'id': 'smtp_starttls_injection', 'feature': 'smtp_starttls', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bSTARTTLS\b.{0,400}?\b(?:insert|inject)\w*\b.{0,60}?\bcommands?\b|\bSTARTTLS command injection\b',
                         re.IGNORECASE | re.DOTALL),
     'not_needed': re.compile(_NOT_SMTP.pattern + r'|\b(?:IMAP|POP3|LMTP|NNTP|XMPP|FTP)\b|\bSMTP (?:client|sending)\b|\bMTA SMTP sending\b',
                              re.IGNORECASE | re.DOTALL),
     'unread': _NEVER},
    # --- SMB, read from one SMB2 and one SMB1 NEGOTIATE on port 445 ----------------------------------------------------------------------------
    # MS17-010 (CVE-2017-0143 to CVE-2017-0148: "The SMBv1 server in Microsoft Windows ..."), CVE-2017-11780 ("The Server Message Block 1.0
    # (SMBv1) on ..."), CVE-2020-1301 ("... the Microsoft Server Message Block 1.0 (SMBv1) server handles certain requests"): a server that refuses
    # SMBv1 rules the match out. Not when the advisory names a later SMB version beside it, nor the SMBv1 client.
    {'id': 'smbv1_server', 'feature': 'smbv1', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\b(?:SMBv1|SMB ?1(?:\.0)?|Server Message Block (?:version )?1(?:\.0)?)\b(?:\s*\(SMBv1\))?\s+(?:server|protocol)\b'
                         r'|\bThe Server Message Block 1\.0 \(SMBv1\)', re.IGNORECASE),
     'not_needed': re.compile(r'\bSMBv1\b[^.]{0,30}\b(?:and|or)\b[^.]{0,10}\bSMBv?[23]|\bSMBv?[23](?:\.\d+)*\b[^.]{0,30}\b(?:and|or)\b[^.]{0,10}\bSMBv1\b'
                              r'|\bSMBv1 client\b', re.IGNORECASE),
     'unread': _NEVER},
    # SMBGhost and SMBleed (CVE-2020-0796, CVE-2020-1206): "... the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles
    # certain requests". Microsoft's advisory (ADV200005, and the FAQ of both CVEs) places the flaw in SMB 3.1.1 compression and gives disabling
    # compression as the workaround, so the reading that rules them out is no 3.1.1 compression. That exact wording, or an advisory that names
    # SMB compression itself.
    {'id': 'smb_compression', 'feature': 'smb_compression', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bServer Message Block 3\.1\.1 \(SMBv3\) protocol handles certain requests\b|\bSMB(?:v?3(?:\.1\.1)?)? compression\b'
                         r'|\bcompress(?:ed|ion) (?:header|transform|request|message)s?\b[^.]{0,60}\bSMB', re.IGNORECASE),
     'not_needed': _NEVER, 'unread': _NEVER},
    # --- RDP, read from nmap's rdp-enum-encryption in the fingerprint pass ---------------------------------------------------------------------
    # BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1181, CVE-2019-1182, CVE-2019-1222, CVE-2019-1226): "... when an unauthenticated attacker
    # connects to the target system using RDP and sends specially crafted requests". With Network Level Authentication required, a client must
    # authenticate (CredSSP) before the vulnerable code is reached, Microsoft's stated mitigation: such a host closes the match as the precondition
    # not being met (an authenticated attacker is a different finding). Never the RD Gateway (CVE-2020-0609, CVE-2020-0610: the same words, but
    # the gateway's own UDP and HTTPS transport) or the client.
    {'id': 'rdp_unauthenticated', 'feature': 'rdp_nla', 'exposed': ('not_required',), 'rule_out': ('required',),
     'needs': re.compile(r'\bunauthenticated attacker connects to the target (?:system|server|host) using RDP\b', re.IGNORECASE),
     'not_needed': re.compile(r'\bRD Gateway\b|\bRemote Desktop Gateway\b|\bRemote Desktop (?:Connection )?Client\b|\bRD Web\b', re.IGNORECASE),
     'unread': _NEVER},
)
# what a database prefilter for ``feature_preconditions`` looks for (PostgreSQL ``~*``): every ``needs`` wording above names one of these. A new
# rule adds its own words here.
FEATURE_PREFILTER = (r'http/?2|ngx_http_v2|h2c|\mh2\M'
                     r'|terrapin|prefix truncation|cipher block chaining|\mcbc\M|aes-gcm|\mbdat\M|chunking|ntlm|spa authenticator|starttls'
                     r'|smbv1|smb ?1|server message block|compression|unauthenticated attacker connects')


# --- web service features (featweb): HTTP/3, PHP on Windows, WebDAV, the VPN portals and SLP --------------------------------------------------
# Each rule quotes the advisory's own condition ("configured to use the HTTP/3 QUIC module", "PHP-CGI on Windows", "the WebDAV service in IIS",
# "SSL-VPN", "GlobalProtect portal or gateway", "configured with either WebVPN or AnyConnect", "configured as a Gateway ... or AAA virtual server",
# "access to port 427"). ``rule_out`` () never clears a match: the reading cannot prove the feature off (Alt-Svc absent is only "not
# advertised"; a module's WebDAV may sit below /, which one OPTIONS / does not read). Ivanti Connect Secure has no rule: its advisories name no
# portal setting, the portal is the product, and the reading is shown only.
_NEVER = re.compile(r'(?!)')
_H3 = r'(?:HTTP/3|QUIC)'
_WEBDAV_CLIENT = r'WebDAV (?:client|redirector|Mini-Redirector)|remote WebDAV (?:location|share|server)|\bWebDAV share'
FEATURE_RULES += (
    {'id': 'http3_quic_module', 'feature': 'http3', 'exposed': ('yes',), 'rule_out': (),
     'needs': re.compile(
         r'\bngx_http_v3_module\b|\bHTTP/3 (?:QUIC )?module\b|\bQUIC module\b'
         r'|\b(?:configured|configurations?) (?:to use|with|that use) (?:the )?' + _H3 + r'\b'
         r'|\b(?:when|if|where|only when|only if) (?:the )?' + _H3 + r'(?: support| protocol| module)? (?:is|are|has been|was) '
         r'(?:enabled|configured|turned on|in use|used|active)\b'
         r'|\bwith ' + _H3 + r' (?:support )?(?:enabled|turned on|configured)\b|\blisten\b[^.]{0,60}\bquic\b', re.IGNORECASE),
     'not_needed': re.compile(r'\bregardless of (?:the )?(?:HTTP )?protocol|\b(?:does not|doesn\'t|do not) (?:require|need) ' + _H3 + r'\b'
                              r'|\bHTTP/[12](?:\.[01x])?\s*(?:,|and|or|/)\s*(?:HTTP/)?3\b', re.IGNORECASE),
     'unread': _NEVER},
    {'id': 'php_cgi_windows', 'feature': 'php_windows', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bPHP[- ]CGI\b[^.]{0,80}\bon Windows\b|\bon Windows\b[^.]{0,80}\bPHP[- ]CGI\b|\bWindows[- ]based PHP\b'
                         r'|\bBest[- ]Fit\b[^.]{0,200}\bPHP\b|\bPHP\b.{0,300}?\bWindows (?:code ?pages?|"?Best[- ]Fit)', re.IGNORECASE),
     'not_needed': _NEVER, 'unread': _NEVER},
    {'id': 'webdav_iis', 'feature': 'webdav', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bWebDAV (?:service|extension|component)\b[^.]{0,80}\b(?:Internet Information Services|IIS)\b'
                         r'|\b(?:Internet Information Services|IIS)\b[^.]{0,40}\bWebDAV (?:service|extension|component)\b', re.IGNORECASE),
     'not_needed': re.compile(_WEBDAV_CLIENT, re.IGNORECASE), 'unread': _NEVER},
    {'id': 'webdav_module', 'feature': 'webdav', 'exposed': ('yes',), 'rule_out': (),
     'needs': re.compile(r'\bmod_dav(?:_fs|_lock|_svn)?\b|\bWebDAV (?:module|support)\b[^.]{0,40}\b(?:enabled|configured|turned on|loaded)\b'
                         r'|\bwhen (?:the )?WebDAV (?:module |support |service )?(?:is |was )?(?:enabled|configured|turned on)\b'
                         r'|\bwith WebDAV (?:enabled|turned on|configured)\b', re.IGNORECASE),
     'not_needed': re.compile(_WEBDAV_CLIENT + r'|\bmod_\w+ and (?:\(\d\) )?mod_dav\b|\bmod_dav (?:and|or) (?:\(\d\) )?mod_\w+', re.IGNORECASE),
     'unread': _NEVER},
    {'id': 'fortios_sslvpn', 'feature': 'vpn_fortinet', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bForti(?:OS|Proxy|Gate)\b.{0,400}?\bSSL[- ]?VPN\b|\bSSL[- ]?VPN\b.{0,200}?\bForti(?:OS|Proxy|Gate)\b', re.IGNORECASE),
     'not_needed': re.compile(r'\b(?:administrative|admin|management) (?:web )?(?:interface|GUI)\b|\bfgfmd\b', re.IGNORECASE), 'unread': _NEVER},
    {'id': 'panos_globalprotect', 'feature': 'vpn_globalprotect', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bGlobalProtect (?:portal|gateway|feature|interface)s?\b', re.IGNORECASE),
     'not_needed': re.compile(r'\bGlobalProtect (?:app|agent|client)\b|\bCaptive Portal\b|\bClientless VPN\b|\bweb interfaces?\b', re.IGNORECASE),
     'unread': _NEVER},
    {'id': 'cisco_webvpn', 'feature': 'vpn_cisco', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bconfigured with (?:either )?WebVPN or AnyConnect\b|\bWebVPN or AnyConnect (?:features?|configurations?)\b'
                         r'|\bAnyConnect and WebVPN configurations?\b|\bwebvpn (?:feature )?is enabled\b|\bwebvpn-configured interface\b'
                         r'|\bWebVPN login page\b|\bVPN web server\b|\bSSL VPN functionality\b', re.IGNORECASE),
     'not_needed': re.compile(r'\bAnyConnect Secure Mobility Client\b|\bSecure Client for\b|\bAnyConnect (?:client|for (?:Windows|Mac|Linux))\b'
                              r'|\bmanagement and VPN web servers?\b|\bmanagement web server\b|\bHTTPS management\b|\bASDM\b', re.IGNORECASE),
     'unread': _NEVER},
    {'id': 'netscaler_gateway_aaa', 'feature': 'vpn_citrix', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bconfigured as (?:a |an )?(?:Gateway|AAA virtual server)\b|\bGateway \(VPN virtual server, ICA Proxy, CVPN, RDP Proxy\)'
                         r'|\bAAA virtual server\b', re.IGNORECASE),
     'not_needed': re.compile(r'\bLB virtual servers?\b|\bCR virtual server\b|\bload balancing virtual server|\bmanagement interface\b'
                              r'|\bNSIP\b|\bCLIP\b|\bSNIP\b', re.IGNORECASE),
     'unread': _NEVER},
    {'id': 'openslp_port_427', 'feature': 'slp', 'exposed': ('yes',), 'rule_out': ('no',),
     'needs': re.compile(r'\bport 427\b|\bOpenSLP (?:as used in|service)\b|\bService Location Protocol\b', re.IGNORECASE),
     'not_needed': _NEVER,
     # the reading is TCP 427's: an advisory that names UDP (the CVE-2023-29552 amplification) keeps its precondition, but a refused TCP port
     # does not rule it out
     'unread': re.compile(r'\bUDP\b', re.IGNORECASE)},
)
FEATURE_PREFILTER += (r'|ngx_http_v3|http/3|quic|php[- ]cgi|windows-based php|best[- ]fit|webdav|mod_dav|ssl[- ]?vpn|globalprotect|webvpn|windows code ?pages?'
                      r'|anyconnect|vpn web server|aaa virtual server|configured as (a |an )?gateway|openslp|port 427|service location protocol')
# --- end of the web service features


def _sentences(text):
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+(?=[A-Z"\'(])|\n+', text) if s.strip()]


def feature_rule(feature):
    """The first rule of ``FEATURE_RULES`` for ``feature`` (what its readings mean), or None."""
    return next((r for r in FEATURE_RULES if r['feature'] == feature), None)


def feature_preconditions(title='', description=''):
    """``{feature: {'rule', 'quote', 'rule_out', 'exposed', 'clears'}}``: the service features the advisory says the flaw needs (the first rule
    of ``FEATURE_RULES`` that holds, per feature), each with the sentence that says so (the description's first, else the title; at most 300
    characters), whether a reading may rule a match out (False when the advisory also names a way to the feature no reading covers, such as
    h2c), the reading values that expose the host and those that clear it (None: every value that does not expose it). Empty when none is
    stated, or when the advisory says the flaw does not need it. Plain text from a third-party feed: quoted, never run."""
    from cvengine.ai_providers import clean_text
    title = clean_text(str(title or ''), 400) or ''
    text = clean_text(str(description or ''), 4000) or ''
    whole = f'{title}\n{text}'
    out = {}
    for rule in FEATURE_RULES:
        if rule['feature'] in out or rule['not_needed'].search(whole):
            continue
        quote = next((s for s in _sentences(text) if rule['needs'].search(s)), '') or (title if rule['needs'].search(title) else '')
        if not quote:
            continue
        out[rule['feature']] = {'rule': rule['id'], 'quote': quote if len(quote) <= 300 else quote[:297].rsplit(' ', 1)[0] + '...',
                                'rule_out': not rule['unread'].search(whole), 'exposed': tuple(rule['exposed']),
                                'clears': tuple(rule['rule_out']) if rule['rule_out'] is not None else None}
    return out
