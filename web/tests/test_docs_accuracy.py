"""The documentation says what the code does: the kinds of the result contract, the environment variables, the navigation and the stale claims 1.4 removed."""
import glob
import json
import os
import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / 'web'
NUMBER_WORDS = {10: 'ten', 11: 'eleven', 12: 'twelve', 15: 'fifteen', 29: 'twenty-nine', 30: 'thirty', 35: 'thirty-five', 36: 'thirty-six', 37: 'thirty-seven'}

# read by a script or a test hook of its own, not an operator setting
# design records written before 1.4 landed: they say what the plan was, not what runs
HISTORICAL = {'SECRETS-PLAN.md', 'SENTINEL-CLIENT-HANDOFF.md', 'SCANNER-ARCHITECTURE.md'}
NOT_SETTINGS = {
    'CVENGINE_AWK_VALUE',  # an awk variable inside scripts/
    'CVENGINE_ROOT',  # a test hook of the host inventory script
    'CVENGINE_SCALE_FIXTURE',  # the scale-test fixture
    'CVENGINE_TEST_BLOCK_NETWORK',  # the test runner
}


def doc_text(*names):
    return '\n'.join((ROOT / n).read_text(encoding='utf-8') for n in names)


def all_docs():
    return doc_text(*[str(Path(f).relative_to(ROOT)) for f in glob.glob(str(ROOT / 'docs' / '*.md'))], 'README.md')


def contract_kinds():
    from cvengine_scanner import contract
    return list(json.loads(Path(contract.__file__).with_name('sentinel_contract.json').read_text())['kind_since'])


class KindListTests(SimpleTestCase):
    def test_the_docs_name_every_kind_of_the_contract(self):
        kinds = contract_kinds()
        for name in ('docs/SENTINELS.md', 'docs/AGENT-API.md'):
            text = doc_text(name)
            missing = [k for k in kinds if f'`{k}`' not in text]
            self.assertEqual(missing, [], f'{name} does not name these kinds of the result contract: {missing}')

    def test_the_docs_count_the_kinds_right(self):
        kinds = contract_kinds()
        word = NUMBER_WORDS.get(len(kinds), str(len(kinds)))
        for name, needle in (('docs/SENTINELS.md', word.capitalize() + ' kinds'), ('docs/AGENT-API.md', f'{word} `SentinelTask` kinds'),
                             ('docs/ARCHITECTURE.md', f'{word} kinds'), ('docs/BUILTIN-SCANNER.md', f'{len(kinds)} task kinds')):
            self.assertTrue(needle in doc_text(name), f'{name} does not say "{needle}"')
        # no document gives another count of the kinds
        for name in glob.glob(str(ROOT / 'docs' / '*.md')) + [str(ROOT / 'README.md')]:
            text = Path(name).read_text(encoding='utf-8')
            for stated in re.findall(r'\b(?:(?:[Tt]wenty|[Tt]hirty|[Ff]ifteen|[Ee]leven)(?:-\w+)?|\d\d) (?:`SentinelTask` |task |scan-stage )?kinds\b', text):
                self.assertIn(stated.split(' ')[0].lower(), (word, str(len(kinds)), 'ten', 'twenty-five', '25', '10'), f'{name} says "{stated}"')

    def test_every_kind_is_dispatched_or_sentinel_only(self):
        from agentapi import sentinel_dispatch
        self.assertEqual(sorted(set(contract_kinds()) - set(sentinel_dispatch.NEVER_LOCAL)), ['discover'])


class EnvironmentVariableTests(SimpleTestCase):
    def documented(self):
        docs = all_docs()
        found = set(re.findall(r'CVENGINE_[A-Z0-9_]+', docs))
        for line in docs.splitlines():  # `CVENGINE_A_B`, `_C` is CVENGINE_A_C
            fulls = [(m.start(), m.group(0)) for m in re.finditer(r'CVENGINE_[A-Z0-9_]+', line)]
            for m in re.finditer(r'`(_[A-Z0-9_]+)`', line):
                before = [name for pos, name in fulls if pos < m.start()]
                if before:
                    parts = before[-1].split('_')
                    found |= {'_'.join(parts[:k]) + m.group(1) for k in range(1, len(parts))}
        return found

    def read_by_the_code(self):
        found = set()
        for folder, _, files in os.walk(WEB):
            if folder.endswith('tests') or '__pycache__' in folder or '/tests/' in folder + '/':
                continue
            for name in files:
                if name.endswith('.py'):
                    found |= set(re.findall(r"""['"](CVENGINE_[A-Z0-9_]+)['"]""", Path(folder, name).read_text(encoding='utf-8', errors='ignore')))
        for pattern in ('docker-compose*.yml', 'install.sh', 'Makefile', 'scripts/*.sh'):
            for name in glob.glob(str(ROOT / pattern)):
                found |= set(re.findall(r'CVENGINE_[A-Z0-9_]+', Path(name).read_text(encoding='utf-8', errors='ignore')))
        return {name for name in found if not name.endswith('_')}  # a trailing underscore is a prefix a name is built from

    def test_every_variable_the_code_reads_is_documented(self):
        missing = sorted(self.read_by_the_code() - self.documented() - NOT_SETTINGS)
        self.assertEqual(missing, [], f'read by the code or compose and named in no document: {missing}')

    def test_a_removed_variable_is_documented_as_ignored(self):
        config = doc_text('docs/CONFIGURATION.md')
        ignored = config.split('## Ignored or removed in 1.4', 1)[1]
        for name in ('CVENGINE_LOCAL_FALLBACK', 'CVENGINE_UDPSCAN_PORTS', 'CVENGINE_NAABU_RATE', 'CVENGINE_WPSCAN_TIMEOUT', 'CVENGINE_SCREENSHOT_MAX_RSS_MB'):
            self.assertIn(name, ignored)
            self.assertNotIn(name, self.read_by_the_code(), f'{name} is read again: take it off the ignored list')
        # a variable the code does not read must not sit in a settings table as if it worked
        for name in ('CVENGINE_UDPSCAN_PORTS', 'CVENGINE_NAABU_RATE', 'CVENGINE_WPSCAN_TIMEOUT', 'CVENGINE_OPENVAS_COST_MB'):
            self.assertNotIn(f'| `{name}`', config.split('## Ignored or removed in 1.4', 1)[0])


class OperatorNotesTests(SimpleTestCase):
    """docs/1.4-OPERATOR-NOTES.md names only variables that exist."""
    SENTINEL_SIDE = {'CVENGINE_SENTINEL_DENY_RANGES'}  # read by the Sentinel on its own machine (its README), not by this server

    def test_every_variable_the_operator_notes_name_exists_in_the_code_or_compose(self):
        text = doc_text('docs/1.4-OPERATOR-NOTES.md')
        named = set(re.findall(r'\bCVENGINE_[A-Z0-9_]*[A-Z0-9]\b', text))
        self.assertGreaterEqual(len(named), 8, 'the operator notes should name the new 1.4 variables')
        known = EnvironmentVariableTests().read_by_the_code()
        missing = sorted(named - known - self.SENTINEL_SIDE)
        self.assertEqual(missing, [], f'named in docs/1.4-OPERATOR-NOTES.md but read by no code or compose file: {missing}')

    def test_the_compose_and_postgres_names_exist_in_the_compose_files(self):
        text = doc_text('docs/1.4-OPERATOR-NOTES.md')
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        for name in sorted(set(re.findall(r'\b(?:POSTGRES_[A-Z_]+|[A-Z]+_MEM_LIMIT)\b', text))):
            self.assertIn(name, compose, f'{name} is named in the operator notes but not in docker-compose.yml')

    def test_the_notes_cover_what_the_owner_asked_for(self):
        text = doc_text('docs/1.4-OPERATOR-NOTES.md')
        for needle in ('CVENGINE_DB_CONN_MAX_AGE', 'CVENGINE_AGENT_TASK_RETENTION_DAYS', 'CVENGINE_NUCLEI_AI_MAX_PER_DAY', 'CVENGINE_REPORT_MAX_HOSTS',
                       'CVENGINE_REPORT_MAX_FINDINGS', 'CVENGINE_BULK_DISCOVER_NOW', 'CVENGINE_SENTINEL_DENY_RANGES', 'POSTGRES_SHARED_BUFFERS',
                       'Addresses we must never scan', 'BUILTIN-SCANNER.md', 'waiting for a free slot', 'Haiku', 'refusal', 'Rolling back'):
            self.assertIn(needle, text)
        self.assertNotIn('pin', re.sub(r'(?i)\b(?:pinned|pins|spinning)\b', '', text).lower().replace('chaining', ''), 'the scanner section must not describe pinning')

    def test_the_upgrade_notes_give_the_real_migration_ranges(self):
        text = doc_text('docs/UPGRADE.md').split('## Upgrading to 1.4', 1)[1].split('## Upgrading to 1.3', 1)[0]
        last = {app: max(int(p.name[:4]) for p in (WEB / app / 'migrations').glob('0*.py')) for app in ('agentapi', 'cveFeed', 'dashboard')}
        self.assertIn(f"`agentapi` 0010 to {last['agentapi']:04d}", text)
        self.assertIn(f"`cveFeed` 0129 to {last['cveFeed']:04d}", text)
        self.assertIn(f"`dashboard` {last['dashboard']:04d}", text)
        self.assertIn('CONCURRENTLY', text)
        for name in ('CVENGINE_DB_CONN_MAX_AGE', 'CVENGINE_NUCLEI_AI_MAX_PER_DAY'):
            self.assertIn(name, text)

    def test_the_do_not_scan_editor_is_in_the_configuration_doc(self):
        text = doc_text('docs/CONFIGURATION.md')
        self.assertIn('**Addresses we must never scan.** Administration, Organizations', text)
        self.assertIn('CVENGINE_DB_CONN_MAX_AGE', text)

    def test_the_changelog_unreleased_names_the_1_4_changes(self):
        text = doc_text('CHANGELOG.md').split('## Unreleased (1.4)', 1)[1].split('\n## v1.3', 1)[0]
        for needle in ('Addresses we must never scan', 'CVENGINE_SENTINEL_DENY_RANGES', 'CVENGINE_DB_CONN_MAX_AGE', 'agentapi` 0020', 'report PDF',
                       'waiting for a free slot', 'drop-down', 'refusal'):
            self.assertIn(needle, text)


class StaleClaimTests(SimpleTestCase):
    def test_no_document_says_the_server_still_runs_a_scan_tool_or_falls_back(self):
        stale = ('runs locally', 'falls back to running the tool locally', 'ran locally', 'the stage runs on the server, as before', 'always run on this server',
                 'always runs on the server', 'The worker image holds the scanners', 'fifteen kinds', 'Eleven kinds', 'twenty-nine kinds')
        for name in glob.glob(str(ROOT / 'docs' / '*.md')) + [str(ROOT / 'README.md')]:
            text = Path(name).read_text(encoding='utf-8')
            if os.path.basename(name) in HISTORICAL:
                continue
            for phrase in stale:
                self.assertFalse(phrase in text, f'{os.path.basename(name)} still says "{phrase}"')

    def test_the_front_end_doc_names_the_six_rail_entries(self):
        text = doc_text('docs/FRONTEND.md')
        from cveFeed import nav
        for label in ('Overview', 'Findings', 'Assets', 'Scans', 'Scanners', 'Bug bounty'):
            self.assertIn(f'**{label}**', text)
        self.assertEqual(len(nav.SECTION_ICON), 6)

    def test_the_upgrade_notes_cover_1_4(self):
        text = doc_text('docs/UPGRADE.md')
        section = text.split('## Upgrading to 1.4', 1)[1].split('## Upgrading to 1.3', 1)[0]
        for needle in ('agentapi` 0019', 'ScannerFallback', 'CVENGINE_LOCAL_FALLBACK', 'v1.4.0', 'built-in scanner', 'OpenVAS', 'setup wizard', 'last resort'):
            self.assertIn(needle, section)
        migrations = sorted(p.name for p in (WEB / 'agentapi' / 'migrations').glob('0019_*.py'))
        self.assertEqual(migrations, ['0019_drop_scanner_fallback.py'])

    def test_the_server_image_pins_no_scan_tool_the_docs_say_it_dropped(self):
        dockerfile = (WEB / 'Dockerfile').read_text()
        for tool in ('NMAPVERSION', 'NAABU_VERSION', 'WPSCAN_VERSION', 'TESTSSL_VERSION', 'BBOT_VERSION', 'WAFW00F_VERSION', 'PLAYWRIGHT', 'KINGFISHER', 'SSHAMBLE'):
            self.assertNotIn(tool, dockerfile)


def slug(heading):
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r'`', '', heading.strip().lower())
    text = re.sub(r'[^\w\- ]', '', text)
    return text.replace(' ', '-')


class LinkTests(SimpleTestCase):
    def test_every_relative_link_and_anchor_in_the_docs_resolves(self):
        files = glob.glob(str(ROOT / 'docs' / '*.md')) + [str(ROOT / n) for n in ('README.md', 'THIRD-PARTY.md')]
        anchors = {}

        def anchors_of(path):
            if path not in anchors:
                text = Path(path).read_text(encoding='utf-8')
                text = re.sub(r'```.*?```', '', text, flags=re.S)
                found, seen = set(), {}
                for heading in re.findall(r'^#{1,6} (.+)$', text, flags=re.M):
                    base = slug(heading)
                    count = seen.get(base, 0)
                    found.add(base if not count else f'{base}-{count}')
                    seen[base] = count + 1
                anchors[path] = found
            return anchors[path]

        broken = []
        for name in files:
            text = re.sub(r'```.*?```', '', Path(name).read_text(encoding='utf-8'), flags=re.S)
            for target in re.findall(r'\]\(([^)\s]+)\)', text):
                if re.match(r'(https?:|mailto:)', target):
                    continue
                path, _, anchor = target.partition('#')
                dest = Path(name) if not path else (Path(name).parent / path).resolve()
                if not dest.exists():
                    broken.append(f'{os.path.basename(name)}: {target} (no such file)')
                elif anchor and dest.suffix == '.md' and anchor not in anchors_of(str(dest)):
                    broken.append(f'{os.path.basename(name)}: {target} (no such heading)')
        self.assertEqual(broken, [])
