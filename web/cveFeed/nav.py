"""The shell's navigation: eight rail entries, and a tab strip inside the page for the pages that share one entry.

Every page keeps its own address; this module only decides which entry a page belongs to and which sibling pages to offer.
Nothing here grants access: each page and API still enforce their own role checks. What it does is keep the links a person
cannot use (Bug bounty for someone not authorised for it, the project's Sentinels when it has none) out of their way.
"""
from django.urls import reverse

# the page a template names (``active`` in the view context) -> the rail entry it sits under
GROUP_OF = {
    'dashboard': 'overview', 'situations': 'overview',
    'vulns': 'findings', 'matches': 'findings', 'hygiene': 'findings', 'changes': 'findings', 'cves': 'findings',
    'hosts': 'assets', 'targets': 'assets', 'graph': 'assets', 'secrets': 'assets', 'suppliers': 'assets',
    'scans': 'scans', 'activity': 'scans',
    'scanners': 'scanners', 'sentinels': 'scanners', 'project-sentinels': 'scanners',
    'bounty': 'bounty',
}

# The rail entry that is highlighted for a page. It differs from GROUP_OF only for the two pages that have an entry of their own
# (Hygiene, Suppliers): there the page's own entry wins and its parent entry (Findings, Hosts) is NOT highlighted, so one entry
# is current at a time. The tab strip still comes from GROUP_OF, so the page keeps its sibling tabs.
OWN_ENTRY = {'hygiene': 'hygiene', 'suppliers': 'suppliers'}

# Pages that belong to the person, not to the work: no rail entry is current on them (by design), the account control is, and so is
# the one item of the account menu that opens the page. 'agents' is the API keys page (MCP and agents), whose menu item is 'API keys'.
UTILITY = {'account': 'My account', 'admin': 'Administration', 'settings': 'Settings', 'agents': 'API keys', 'about': 'About', 'setup': 'Connect AI model',
           'welcome': ''}

SECTION_ICON = {'overview': 'pulse', 'findings': 'bug', 'hygiene': 'shield', 'assets': 'server', 'suppliers': 'building', 'scans': 'radar',
                'scanners': 'bot', 'bounty': 'flag'}
SECTION_LABEL = {'overview': 'Overview', 'findings': 'Findings', 'hygiene': 'Hygiene', 'assets': 'Hosts', 'suppliers': 'Suppliers',
                 'scans': 'Scans', 'scanners': 'Scanners', 'bounty': 'Bug bounty'}


def _section(slug, name):
    return reverse('cve_section', args=[slug, name])


def _tabs(group, slug, sentinels_enabled):
    """(key, label, href) of the pages that share a rail entry, in order. The pages that need a project are left out when there is none."""
    out = []
    if group == 'overview':
        if slug:  # Situations is a page of one project (or all of them), so with no project there is no strip
            out += [('dashboard', 'Overview', reverse('cve_dashboard')), ('situations', 'Situations', _section(slug, 'situations'))]
    elif group == 'findings':
        if slug:
            out += [('vulns', 'Findings', _section(slug, 'vulns')), ('matches', 'CVE matches', _section(slug, 'matches')),
                    ('hygiene', 'Hygiene', _section(slug, 'hygiene')), ('changes', 'Changes', _section(slug, 'changes'))]
        out.append(('cves', 'CVE catalog', reverse('cve_explorer')))
    elif group == 'assets':
        if slug:
            out += [('hosts', 'Hosts', _section(slug, 'hosts')), ('targets', 'Targets', _section(slug, 'targets'))]
        out.append(('graph', 'Graph', reverse('cve_graph')))
        if slug:
            out += [('secrets', 'Secrets', _section(slug, 'secrets')), ('suppliers', 'Suppliers', _section(slug, 'suppliers'))]
    elif group == 'scans' and slug:
        out += [('scans', 'Scans', _section(slug, 'scans')), ('activity', 'Activity', _section(slug, 'activity'))]
    elif group == 'scanners':
        out += [('scanners', 'Scanners', reverse('cve_scanners')), ('sentinels', 'Sentinels', reverse('cve_sentinels'))]
        if sentinels_enabled and slug:
            out.append(('project-sentinels', 'This project', _section(slug, 'sentinels')))
    return out


def build(active, slug, *, bounty_enabled, sentinels_enabled, all_projects=False):
    """``{'rail': [...], 'tabs': [...], 'group': str (the tab strip's family), 'current': str (the one current rail entry or ''),
    'utility': the account-menu label for a utility page or None, 'index': [...], 'more': [...]}`` for the shell.

    rail: the entries of the left rail (and the phone's tab bar); tabs: the sibling pages of the current entry; index: every page the
    caller can reach, for the jump palette (it reads them from the page, so the six rail entries do not shrink what Ctrl K finds).
    """
    group = GROUP_OF.get(active, '')
    current = OWN_ENTRY.get(active, group)  # the one rail entry that is current ('' on a utility page)
    bounty_href = reverse('cve_bounty') + (f'?project={slug}' if slug and not all_projects else '')
    entries = [('overview', 'Overview', reverse('cve_dashboard'))]
    if slug:
        entries += [('findings', 'Findings', _section(slug, 'vulns')), ('hygiene', 'Hygiene', _section(slug, 'hygiene')),
                    ('assets', 'Hosts', _section(slug, 'hosts')), ('suppliers', 'Suppliers', _section(slug, 'suppliers')),
                    ('scans', 'Scans', _section(slug, 'scans'))]
    else:
        entries.append(('assets', 'Graph', reverse('cve_graph')))  # the one page of this entry that needs no project: named for what it opens
    entries.append(('scanners', 'Scanners', reverse('cve_scanners')))
    if bounty_enabled:
        entries.append(('bounty', 'Bug bounty', bounty_href))
    rail = [{'key': k, 'label': label, 'href': href, 'icon': SECTION_ICON[k], 'current': k == current} for k, label, href in entries]
    tabs = [{'key': k, 'label': label, 'href': href, 'current': k == active} for k, label, href in _tabs(group, slug, sentinels_enabled)]
    # A strip never links to the rail entry of another page (Hygiene and Suppliers have their own; Findings and Hosts are the entries of
    # the pages above them): the only rail entry it may repeat is the current one, as its first tab.
    rail_href = {e['href']: e['current'] for e in rail}
    tabs = [t for t in tabs if t['href'] not in rail_href or rail_href[t['href']]]
    tabs.sort(key=lambda t: t['href'] not in rail_href)
    # one entry for the page strip is not a strip
    if len(tabs) < 2:
        tabs = []
    index, seen = [], set()
    for g in ('overview', 'findings', 'assets', 'scans', 'scanners'):
        for k, label, href in _tabs(g, slug, sentinels_enabled):
            full = {'project-sentinels': 'Project Sentinels'}.get(k, label)  # every other page is listed under the name its rail entry and tab use
            if href not in seen:
                seen.add(href)
                index.append({'label': full, 'href': href})
    primary = {e['href'] for e in rail}
    more = [i for i in index if i['href'] not in primary]  # the phone's More sheet: everything the tab bar and the rail entries do not already open
    return {'rail': rail, 'tabs': tabs, 'group': group, 'group_label': SECTION_LABEL.get(group, ''), 'current': current, 'utility': UTILITY.get(active), 'index': index, 'more': more, 'bounty_href': bounty_href}
