"""No page goes unlinked without someone deciding it: every page route in cveFeed/urls.py (and every project section) is linked from the
shell (sidebar, account menu, phone bar, More sheet, Account sheet, jump palette index) for an App Admin, or is on ALLOWED_UNLINKED with a reason.
A page added with neither fails here."""
import re
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from cveFeed import urls
from dashboard.models import Org, Project
from tests.test_tenancy import client_for

# route name (or project section) -> why it has no link in the shell
ALLOWED_UNLINKED = {
    'cve_welcome': 'first run only; the dashboard has a button to open it again (?again=1)',
    'cve_update_questions': 'asked once after an update (the dashboard sends an App Admin here), then a reminder in the status strip and Settings > Questions about updates link to it',
    'cve_how': 'a card on the dashboard explains it and links here',
    'cve_scan': 'a scan detail page, reached from the Scans lists',
    'cve_host_screenshot': 'an image of a host, reached from the host page',
    'cve_host_rdp_screenshot': 'an image of a host, reached from the host page',
    'section:keys': 'legacy address that redirects to Settings, API keys',
}
# routes that are not pages: JSON endpoints
NOT_PAGES = re.compile(r'^cve_api')
SECTION_RE = re.compile(r'\(\?P<section>([^)]*)\)')


def page_routes():
    """[(key, path)] for each page route; a regex route with arguments is probed with an example project."""
    out = []
    for p in urls.urlpatterns:
        name = getattr(p, 'name', None) or ''
        if NOT_PAGES.match(name) or name == 'cve_section':
            continue
        if name in ('cve_scan', 'cve_host_screenshot', 'cve_host_rdp_screenshot'):
            out.append((name, None))
        else:
            out.append((name, reverse(name)))
    section = next(p for p in urls.urlpatterns if getattr(p, 'name', '') == 'cve_section')
    for s in SECTION_RE.search(section.pattern.regex.pattern).group(1).split('|'):
        out.append((f'section:{s}', reverse('cve_section', args=['alpha', s])))
    return out


def hrefs(chunk):
    return {h.split('#')[0].split('?')[0] for h in re.findall(r'href="(/[^"]*)"', chunk)}


class EveryPageIsLinkedTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('rc-root', 'root@example.test', 'pw-12345-long')
        Project.objects.create(name='Alpha', slug='alpha', insert_date=timezone.now(), org=Org.objects.create(name='Org', slug='org'))

    def shell(self):
        with mock.patch('agentapi.sentinel_broker.has_sentinels', return_value=True):
            html = client_for(self.root).get('/cve/alpha/hosts/').content.decode()
        rail = html[html.index('<aside class="rail"'):html.index('</aside>')]
        phone = html[html.index('class="tabbar"'):html.index('<dialog class="palette"')]
        return rail, phone

    def test_every_page_is_linked_or_allowed_with_a_reason(self):
        rail, phone = self.shell()
        linked = hrefs(rail) | hrefs(phone)
        routes = page_routes()
        self.assertGreater(len(routes), 15)
        unlinked = [k for k, path in routes if path is not None and path not in linked and k not in ALLOWED_UNLINKED]
        self.assertEqual(unlinked, [], f'page(s) with no link in the sidebar, account menu or phone sheets: {unlinked}. Link them (cveFeed/nav.py, base.html) or add them to ALLOWED_UNLINKED with a reason.')

    def test_the_allowlist_has_no_stale_entries_and_every_entry_has_a_reason(self):
        keys = {k for k, _ in page_routes()}
        for k, why in ALLOWED_UNLINKED.items():
            self.assertIn(k, keys, f'{k} is no longer a page route: remove it from ALLOWED_UNLINKED')
            self.assertGreater(len(why.split()), 2, k)
        rail, phone = self.shell()
        linked = hrefs(rail) | hrefs(phone)
        for k, path in page_routes():
            if k in ALLOWED_UNLINKED and path is not None and k != 'cve_welcome':
                self.assertNotIn(path, linked, f'{k} is linked now: drop it from ALLOWED_UNLINKED')

    def test_the_phone_reaches_what_the_desktop_account_menu_does(self):
        rail, phone = self.shell()
        menu = rail[rail.index('<details class="acct">'):]
        desktop = hrefs(menu)
        sheets = phone[phone.index('id="sheet"'):]
        phone_links = hrefs(sheets)
        missing = desktop - phone_links
        self.assertEqual(missing, set(), f'on the desktop menu but not on a phone sheet: {missing}')
        for path in ('/cve/admin/', '/cve/settings/', '/cve/agents/', '/cve/about/', '/cve/setup/', '/cve/bounty/'):
            self.assertIn(path, phone_links | hrefs(phone), path)
