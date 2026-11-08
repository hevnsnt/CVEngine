"""The API keys page (MCP and agents) is reachable: the account menu, the AI Model Usage page and the old Administration Agents deep link."""
import re
from pathlib import Path

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from cveFeed import nav
from dashboard.models import AIProviderSettings, Org, OrgMembership
from tests.test_tenancy import client_for

STATIC = Path(__file__).resolve().parents[1] / 'static' / 'cve'
WORDS = 'API keys for MCP and agents'


def menu_labels(html):
    return re.findall(r'<a data-nav="([^"]+)"', html[html.index('<details class="acct">'):html.index('</aside>')])


class ApiKeysMenuTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Org.objects.create(name='Org', slug='org')
        cls.root = User.objects.create_superuser('ak-root', 'root@example.test', 'pw-12345-long')
        cls.admin = User.objects.create_user('ak-admin', password='x')
        cls.member = User.objects.create_user('ak-member', password='x')
        OrgMembership.objects.create(user=cls.admin, org=cls.org, role='admin')
        OrgMembership.objects.create(user=cls.member, org=cls.org, role='user')

    def test_every_role_that_can_open_the_page_has_the_menu_item_after_settings(self):
        for user in (self.root, self.admin, self.member):
            r = client_for(user).get('/cve/agents/')
            self.assertEqual(r.status_code, 200, user.username)
            html = r.content.decode()
            labels = menu_labels(html)
            self.assertIn('API keys', labels, user.username)
            if 'Settings' in labels:
                self.assertEqual(labels.index('API keys'), labels.index('Settings') + 1)
            self.assertRegex(html, r'<a data-nav="API keys" aria-current="page" href="/cve/agents/"><svg[^>]*><use href="#i-key"/></svg>API keys</a>')
            self.assertIn('id="i-key"', html)  # the icon is in the sprite
            self.assertRegex(html, r'<summary aria-current="page"')  # the account control is marked
            self.assertEqual([m for m in re.findall(r'<a data-nav="[^"]+" href="[^"]+" aria-current="page"', html[html.index('aria-label="Sections"'):html.index('<details class="acct">')])], [])

    def test_the_item_is_not_current_elsewhere_and_the_phone_sheet_has_it(self):
        html = client_for(self.member).get('/cve/about/').content.decode()
        self.assertNotRegex(html, r'data-nav="API keys" aria-current')
        sheet = html[html.index('id="acct-sheet"'):]
        self.assertRegex(sheet, r'<a href="/cve/agents/" ><svg[^>]*><use href="#i-key"/></svg>API keys</a>')

    def test_the_page_uses_the_same_words_as_the_menu_and_links_to_the_docs(self):
        html = client_for(self.member).get('/cve/agents/').content.decode()
        self.assertIn(f'<h1>{WORDS}</h1>', html)
        self.assertIn(f'<title>CVEngine · {WORDS}', html)
        self.assertIn('docs/AGENT-API.md', html)
        self.assertIn('Settings, Discovery API keys', html)  # the other kind of key is named apart

    def test_the_agents_section_is_for_administrators_only(self):
        self.assertIn('id="agents-admin"', client_for(self.admin).get('/cve/agents/').content.decode())
        self.assertIn('id="agents-admin"', client_for(self.root).get('/cve/agents/').content.decode())
        self.assertNotIn('id="agents-admin"', client_for(self.member).get('/cve/agents/').content.decode())

    def test_the_palette_and_shortcut_layer_list_api_keys_and_not_the_old_names(self):
        keys = (STATIC / 'keys.js').read_text()
        self.assertIn('"API keys": "k"', keys)
        built = nav.build('vulns', 'alpha', bounty_enabled=False, sentinels_enabled=True)
        self.assertNotIn('Integrations', [t['label'] for t in built['tabs']])
        self.assertNotIn('API tokens and MCP', [i['label'] for i in built['index']])
        self.assertEqual(nav.build('agents', 'alpha', bounty_enabled=True, sentinels_enabled=True)['utility'], 'API keys')


class AiUsageLinksTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('au-root', 'root@example.test', 'pw-12345-long')
        cls.org = Org.objects.create(name='Org', slug='org')
        cls.member = User.objects.create_user('au-member', password='x')
        OrgMembership.objects.create(user=cls.member, org=cls.org, role='user')

    def connect(self):
        AIProviderSettings.objects.all().delete()
        cfg = AIProviderSettings.objects.create(provider='anthropic', model='claude-test', enabled=True)
        from django.utils import timezone
        cfg.verified_at, cfg.verified_provider, cfg.verified_model = timezone.now(), cfg.provider, cfg.model
        cfg.save()

    def check(self, connected):
        client = client_for(self.root)
        html = client.get('/cve/setup/').content.decode()
        page = html[html.index('<div class="ai-usage-page">'):html.index('</section>', html.index('ai-discovery-keys'))]  # the page's own content, not the shell's
        h1 = page.index('</h1>')
        links = re.search(r'<p class="ai-usage-links">(.*?)</p>', page, re.S)
        self.assertIsNotNone(links)
        self.assertLess(h1, links.start())
        self.assertLess(links.start(), page.index('<form'))  # above the fold: before any form or the usage table
        self.assertIn('>Adjust AI models and usage</a>', links.group(1))
        self.assertIn('>Create an API key for MCP</a>', links.group(1))
        self.assertIn('href="/cve/settings/#ai"', links.group(1))
        self.assertIn('href="/cve/agents/"', links.group(1))
        # every link on the page opens for a superuser (the fragment is the browser's)
        hrefs = {h.split('#')[0] for h in re.findall(r'<a [^>]*href="([^"#][^"]*)"', page)}
        self.assertTrue(hrefs >= {'/cve/settings/', '/cve/agents/'}, hrefs)
        for href in hrefs:
            self.assertEqual(client.get(href).status_code, 200, href)

    def test_links_at_the_top_of_the_not_connected_page(self):
        self.check(False)

    def test_links_at_the_top_of_the_connected_page(self):
        self.connect()
        html = client_for(self.root).get('/cve/setup/').content.decode()
        self.assertIn('AI Model Usage', html)
        self.check(True)

    def test_the_page_stays_superuser_only(self):
        self.assertNotEqual(client_for(self.member).get('/cve/setup/').status_code, 200)


class AdminAgentsTabTests(TestCase):
    def test_admin_page_script_has_no_agents_tab_and_redirects_the_old_link(self):
        admin = (STATIC / 'admin.js').read_text()
        self.assertNotIn('defs.agents', admin)
        self.assertNotIn('agentsTab', admin)
        self.assertIn('legacyAdminTarget(location.hash)', admin)
        self.assertIn("'/cve/sentinels/'", (STATIC / 'admin-legacy-logic.js').read_text())

    def test_the_moved_code_is_served_and_used_by_the_api_keys_page(self):
        root = User.objects.create_superuser('aa-root', 'root@example.test', 'pw-12345-long')
        client = client_for(root)
        self.assertIn('/staticfiles/cve/agents-admin.js', client.get('/cve/agents/').content.decode())
        self.assertEqual(client.get('/cve/sentinels/').status_code, 200)


class DocsTests(SimpleTestCase):
    def test_docs_name_the_page_and_not_the_removed_tab(self):
        docs = Path(__file__).resolve().parents[2] / 'docs'
        text = ''.join(p.read_text() for p in docs.glob('*.md'))
        self.assertNotIn('Administration, Agents', text)
        self.assertNotIn('API tokens and MCP', text)
        self.assertIn('**API keys** page (`/cve/agents/`', (docs / 'AGENT-API.md').read_text())
