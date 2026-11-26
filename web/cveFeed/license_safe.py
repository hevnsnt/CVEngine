"""The hosted license-safe switch: ``CVENGINE_HOSTED_LICENSE_SAFE=1`` turns off, on one install, every tool and data source whose free terms do not
allow a commercial hosted service.

A self-hosted install leaves it unset and keeps every default as it is. A hosted service that sells cvENGINE to its customers sets it in the
install's ``.env``. While it is on:

- The WordPress scanner: its two task kinds (``LICENSED_KINDS``, named in ``cveFeed.wpscan_scan``) are denied on every Sentinel, built-in and
  external, whatever any policy says (``agentapi.sentinel_policy``: source ``hosted license``), and the WordPress stage sends no task of them. Its
  license asks for a commercial license for managed or hosted use. WordPress detection and the WordPress templates of the template scan keep running.
- Its vulnerability database token is never sent (that API needs an Enterprise plan for use in a service).
- Shodan InternetDB (free for non-commercial use only): every discovery task leaves the ``shodan_idb`` module out.
- The Internet Archive (access granted for scholarship and research): the server's Wayback CDX lookups (``cveFeed.archive_urls``) are skipped and
  discovery leaves the ``wayback`` module out.
- Cloudflare Radar Zero Wire (CC BY-NC 4.0): the feed is not read and email reports name no briefing (``cveFeed.zero_wire``).
- Cert Spotter (its API without a key is for personal or evaluation use): the certificate transparency fallback is not asked (``cveFeed.ctmonitor``)
  and discovery leaves the ``certspotter`` module out.

Nothing is stored: unset the variable and restart to return to the defaults.
"""
import os

ENV = 'CVENGINE_HOSTED_LICENSE_SAFE'
ON_WORDS = ('1', 'true', 'yes', 'on')
BBOT_MODULES = ('certspotter', 'shodan_idb', 'wayback')  # the discovery modules that ask a source with non-commercial terms
REASON = 'off on this hosted install (CVENGINE_HOSTED_LICENSE_SAFE): its terms allow no commercial hosted use'


def enabled():
    """Whether this install runs as a hosted, license-safe service."""
    return os.environ.get(ENV, '').strip().lower() in ON_WORDS


def licensed_kinds():
    """The Sentinel task kinds of the WordPress scanner, denied on a hosted install."""
    from cveFeed import wpscan_scan
    return wpscan_scan.LICENSED_KINDS


def excluded_bbot_modules():
    """The discovery modules a discovery task leaves out on this install (sorted; none unless the switch is on)."""
    return sorted(BBOT_MODULES) if enabled() else []
