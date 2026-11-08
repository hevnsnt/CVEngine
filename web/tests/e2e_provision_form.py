"""Real-Chromium check of the Provision a Sentinel form. Not part of CI: run it against a throwaway stack with three example.com projects.

  PROVISION_BASE=http://127.0.0.1:28991 PROVISION_USER=... PROVISION_PASS=... SHOTS=/dir python web/tests/e2e_provision_form.py
"""
import glob
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ['PROVISION_BASE']
SHOTS = os.environ.get('SHOTS', '')
EXE = (glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome')) or [None])[0]
fails = []


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what)
    if not cond:
        fails.append(what)


def state(page):
    return page.evaluate("""() => { const b = document.getElementById('enroll-go');
      return {disabled: b.disabled, aria: b.getAttribute('aria-disabled'), why: document.getElementById('enroll-missing').textContent,
        projectHidden: document.getElementById('enroll-project-field').hidden, orgHidden: document.getElementById('enroll-org-field').hidden,
        values: ['scope','project','org','network','profile'].map(n => document.getElementById('enroll-' + n).value)}; }""")


def run(pw, width, height, mobile):
    browser = pw.chromium.launch(executable_path=EXE)
    ctx = browser.new_context(viewport={'width': width, 'height': height}, is_mobile=mobile, has_touch=mobile)
    page = ctx.new_page()
    page.goto(BASE + '/login/')
    page.fill('[name=username]', os.environ['PROVISION_USER'])
    page.fill('[name=password]', os.environ['PROVISION_PASS'])
    page.click('button[type=submit]')
    page.wait_for_load_state('networkidle')
    posts = []
    page.on('request', lambda r: posts.append(r.url) if r.method == 'POST' and 'enroll' in r.url else None)
    # a hostile or stale link cannot pre-select anything, and the shell's current project is no default either
    for url in ('/cve/sentinels/?project=xyz', '/cve/sentinels/?project=alpha&scope=project&network=internal&profile=full', '/cve/sentinels/'):
        resp = page.goto(BASE + url)
        if page.locator('#enroll-project').count() == 0:  # an unknown ?project= is refused by the shell itself: nothing to pre-select
            check(resp.status == 404, f'[{width}px {url}] an unknown project in the link is a 404, not a pre-selection')
            continue
        page.wait_for_function("document.getElementById('enroll-project').options.length > 1")
        s = state(page)
        tag = f'[{width}px {url}] '
        check(s['values'] == ['', '', '', '', ''], tag + 'nothing is pre-selected: ' + repr(s['values']))
        check(s['disabled'] and s['aria'] == 'true', tag + 'Provision is disabled and aria-disabled')
        check(s['why'] == 'Choose a scope to continue.', tag + 'says what is missing')
        check(s['projectHidden'] and s['orgHidden'], tag + 'dependent fields hidden before a scope')
        check(page.locator('body').inner_text().count('Pre-selected from the link you followed') == 0, tag + 'no prefill claim (no prefill link exists)')
    check(not posts, 'nothing was POSTed by loading the page')
    names = page.evaluate("[...document.querySelectorAll('#enroll-scope,#enroll-project,#enroll-org,#enroll-network,#enroll-profile')].map(s => s.labels[0].textContent)")
    check(names == ['Scope', 'Project', 'Organization', 'Where it runs', 'Size'], f'accessible names unchanged: {names}')
    check(page.evaluate("[...document.querySelectorAll('#enroll-scope option, #enroll-network option, #enroll-profile option, #enroll-project option')].filter(o => o.value === '').every(o => o.disabled)"), 'every placeholder is disabled (not selectable once a real option is chosen)')
    if SHOTS:
        page.screenshot(path=f'{SHOTS}/provision-{width}-initial.png', full_page=True)
    # walk the project flow: the button stays off until the last choice
    page.select_option('#enroll-scope', 'project')
    s = state(page)
    check(not s['projectHidden'] and s['orgHidden'] and s['why'] == 'Choose a project.' and s['disabled'], 'Scope=Project shows the Project dropdown and asks for it')
    check(page.evaluate("document.getElementById('enroll-project').value") == '', 'the Project dropdown starts on its placeholder')
    page.select_option('#enroll-project', 'bravo')
    s = state(page)
    check(s['disabled'] and s['why'] == 'Choose where it runs.', 'still disabled after the project: ' + s['why'])
    page.select_option('#enroll-network', 'external')
    s = state(page)
    check(s['disabled'] and s['why'] == 'Choose a size.', 'still disabled after where it runs: ' + s['why'])
    if SHOTS:
        page.screenshot(path=f'{SHOTS}/provision-{width}-partial.png', full_page=True)
    page.select_option('#enroll-profile', 'light')
    s = state(page)
    check(not s['disabled'] and s['aria'] == 'false' and s['why'] == '', 'enabled only when every choice is made')
    # changing Scope resets the dependent dropdown
    page.select_option('#enroll-scope', 'instance')
    s = state(page)
    check(s['projectHidden'] and s['orgHidden'] and not s['disabled'], 'Instance needs no dependent field')
    page.select_option('#enroll-scope', 'project')
    s = state(page)
    check(s['values'][1] == '' and s['disabled'] and s['why'] == 'Choose a project.', 'changing Scope reset the Project dropdown: ' + repr(s['values']))
    page.select_option('#enroll-project', 'bravo')
    page.select_option('#enroll-scope', 'org')
    page.select_option('#enroll-scope', 'project')
    check(state(page)['values'][1] == '', 'Project -> Organization -> Project also resets')
    page.select_option('#enroll-scope', 'org')
    s = state(page)
    check(not s['orgHidden'] and s['projectHidden'] and s['why'] == 'Choose an organization.' and s['disabled'], 'Scope=Organization asks for an organization')
    # a disabled button cannot submit, and Enter or a forced click posts nothing
    page.evaluate("document.getElementById('enroll-go').click()")
    page.wait_for_timeout(300)
    check(not posts, 'a forced click on the disabled button posts nothing')
    # complete the flow: one POST, only after the click
    page.select_option('#enroll-scope', 'project')
    page.select_option('#enroll-project', 'bravo')
    page.select_option('#enroll-network', 'internal')
    page.select_option('#enroll-profile', 'full')
    check(not posts, 'choosing everything does not POST by itself')
    page.click('#enroll-go')
    page.wait_for_selector('#enroll-out:not([hidden]) .enroll-tabs')
    check(len(posts) == 1 and '/projects/bravo/sentinels/enroll' in posts[0] and 'network=internal' in posts[0] and 'profile=full' in posts[0], 'one POST with the chosen values: ' + repr(posts))
    if SHOTS:
        page.screenshot(path=f'{SHOTS}/provision-{width}-done.png', full_page=True)
    browser.close()


with sync_playwright() as pw:
    run(pw, 1440, 900, False)
    run(pw, 390, 844, True)
print('FAILED' if fails else 'ALL OK', len(fails))
sys.exit(1 if fails else 0)
