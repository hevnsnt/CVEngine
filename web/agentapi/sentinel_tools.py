"""Whether the tools a Sentinel runs are the versions this release ships: "tools behind", next to ``sentinel_version``'s "version behind".

A Sentinel reports ``info.tool_versions`` (``{tool: version}``, what its start-up version probes printed: contract version 5) in its registration and
heartbeat. The server compares each with the version the pinned Sentinel library's image installs (``cveFeed.software.TOOLS``, read from the Sentinel's
Dockerfile at the commit ``SENTINEL_PINS_COMMIT``, held equal by ``tests.test_about_page``). A Sentinel on Manual or Off, or whose updater stopped, keeps its tools for
weeks while ``main`` may not have moved: this says "nuclei 3.10.0, this release ships 3.11.1".

``state(agent)`` is ``{status, behind, reported, detail, flagged}``: ``status`` is ``unknown`` when the Sentinel sends no tool versions (an older
client: never "behind"), ``current`` when none of the tools it reports is older than shipped, ``behind`` otherwise; ``behind`` lists ``{tool, running, current}``. A tool
the Sentinel does not report is not named, and a version that cannot be read as numbers is not compared. Reads stored data only.
"""
import re

KNOWN_TOOLS = ('nmap', 'naabu', 'nuclei', 'testssl', 'wpscan', 'wafw00f', 'kingfisher', 'bbot')
MAX_VERSION = 40
_NUMBERS = re.compile(r'\d+(?:\.\d+)*')


def expected():
    """``{tool: version}`` this release's Sentinel image ships, for the tools a Sentinel reports."""
    from cveFeed import software
    return {item['key']: item['version'] for item in software.TOOLS if item['key'] in KNOWN_TOOLS and item.get('version')}


def _parts(version):
    found = _NUMBERS.search(str(version or ''))
    return tuple(int(p) for p in found.group(0).split('.')[:6]) if found else None


def older(running, shipped):
    """Whether ``running`` is an older release than ``shipped``; False when either cannot be read as numbers (nothing is claimed)."""
    a, b = _parts(running), _parts(shipped)
    if a is None or b is None:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def behind_of(reported):
    """``[{tool, running, current}]`` for each reported tool older than the one this release ships, in the order of ``KNOWN_TOOLS``."""
    shipped = expected()
    return [{'tool': tool, 'running': str(reported[tool])[:MAX_VERSION], 'current': shipped[tool]}
            for tool in KNOWN_TOOLS if tool in (reported or {}) and tool in shipped and older(reported[tool], shipped[tool])]


def state(agent):
    reported = (agent.info or {}).get('tool_versions')
    out = {'status': 'unknown', 'behind': [], 'reported': reported if isinstance(reported, dict) else None, 'detail': '', 'flagged': False}
    if not isinstance(reported, dict) or not reported:
        out['detail'] = 'this Sentinel does not report its tool versions (an older client), so they cannot be compared'
        return out
    behind = behind_of(reported)
    if not behind:
        out.update(status='current', detail='the tools it reports are the versions this release ships, or newer')
        return out
    out.update(status='behind', behind=behind, flagged=True,
               detail='tools behind: ' + ', '.join(f'{b["tool"]} {b["running"]} (this release ships {b["current"]})' for b in behind))
    return out
