"""Browser check (Playwright, real Chromium) of the page links of the host Web tab: the route path and the path in the PII note open the live page on the
scanned host. Not part of the Django suite (CI has no browser): run it with ``python web/tests/check_page_links_browser.py`` where Playwright and a Chromium
are installed. It serves ``web/static`` as ``/staticfiles/`` plus a tiny page that runs the real ``routeLine`` of ``app.js`` (cut out of its source) with the shipped ``ui.js`` and ``links.js``,
and a second local server that stands in for the scanned host, so a click really opens a page.

Checks: the href for http and https, for default and non-default ports, for paths with unsafe characters (encoded, never a query or another host), that a
non-http scheme gives no link (set CHROMIUM_EXECUTABLE to use a Chromium Playwright did not install); target _blank, rel noopener noreferrer, the title; the masked sample is not in any href; keyboard focus shows the outline; a
click opens the scanned host's page in a new tab that has no opener.
"""
import http.server
import json
import os
import socketserver
import sys
import threading

from playwright.sync_api import sync_playwright

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static')
SAMPLE = '%5**@****.com'

# the real routeLine of app.js, cut out of its source and run here with the real ui.js and links.js (app.js itself starts a whole page when loaded)
APP = open(os.path.join(STATIC, 'cve', 'app.js'), encoding='utf-8').read()
ROUTE_LINE = APP[APP.index('const SENSITIVE_GROUP'):APP.index('function shotPair(')]

PAGE = """<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/staticfiles/cve/cve.css"></head><body>
<div id="out"></div>
<script type="module">
import { el, badge } from "/staticfiles/cve/ui.js";
import { pageAnchor } from "/staticfiles/cve/links.js";
const authLabel = (s) => s;
%s
const routes = %s;
const out = document.getElementById("out");
for (const r of routes) {
  const line = routeLine(r);
  line.dataset.name = r.name;
  out.append(line);
}
window.ready = true;
</script></body></html>"""


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve(handler):
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    seen = []

    class Scanned(Quiet):  # the scanned host: answers any path with a page that says what it was asked
        def do_GET(self):
            seen.append(self.path)
            body = f'<html><title>scanned</title><body>asked for {self.path}</body></html>'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    scanned = serve(Scanned)
    scanned_port = scanned.server_address[1]
    routes = [
        {'name': 'https', 'url': 'https://www.example.com/admin/', 'host': 'www.example.com', 'path': '/admin/'},
        {'name': 'http', 'url': 'http://www.example.com/', 'host': 'www.example.com', 'path': '/'},
        {'name': 'port', 'url': 'https://www.example.com:8443/api/v1', 'host': 'www.example.com', 'path': '/api/v1'},
        {'name': 'httpport', 'url': 'http://192.0.2.7:8080/x', 'host': '192.0.2.7', 'path': '/x'},
        {'name': 'noscheme', 'url': '', 'host': 'www.example.com', 'path': '/from-host'},
        {'name': 'unsafe', 'url': '', 'host': 'www.example.com', 'path': '/a b/"q"<x>?y=1#z'},
        {'name': 'bad', 'url': 'javascript:alert(1)', 'host': 'www.example.com', 'path': '/js'},
        {'name': 'live', 'url': f'http://127.0.0.1:{scanned_port}/live%20page?x=1', 'host': '127.0.0.1', 'path': '/live page'},
    ]
    for r in routes:  # what the routes API sends: the state, the status and the masked counts
        r.update(auth_state='open', http_status=200, sensitive={'email': {'count': 3, 'sample': SAMPLE}, 'phone': {'count': 1, 'sample': '***'}})
    html = (PAGE % (ROUTE_LINE, json.dumps(routes))).encode()

    class Shell(Quiet):
        def translate_path(self, path):
            return os.path.join(STATIC, path.split('?')[0][len('/staticfiles/'):]) if path.startswith('/staticfiles/') else path

        def do_GET(self):
            if self.path.startswith('/staticfiles/'):
                return super().do_GET()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(html)))
            self.end_headers()
            self.wfile.write(html)

    shell = serve(Shell)
    failures = []

    def check(ok, what):
        print(('ok   ' if ok else 'FAIL ') + what)
        if not ok:
            failures.append(what)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_EXECUTABLE') or None)
        page = browser.new_page()
        page.goto(f'http://127.0.0.1:{shell.server_address[1]}/')
        page.wait_for_function('window.ready === true')

        def anchors(name):
            return page.eval_on_selector_all(f'[data-name="{name}"] a', 'els => els.map(a => ({href: a.href, target: a.target, rel: a.rel, title: a.title, text: a.textContent}))')

        want = {
            'https': 'https://www.example.com/admin/',
            'http': 'http://www.example.com/',
            'port': 'https://www.example.com:8443/api/v1',
            'httpport': 'http://192.0.2.7:8080/x',
            'noscheme': 'https://www.example.com/from-host',
            'unsafe': 'https://www.example.com/a%20b/%22q%22%3Cx%3E%3Fy=1%23z',
        }
        for name, href in want.items():
            found = anchors(name)
            check(len(found) == 2, f'{name}: the path on the row and the path in the PII note are both links')
            check(all(a['href'] == href for a in found), f'{name}: href is {href} (got {[a["href"] for a in found]})')
            check(all(a['target'] == '_blank' and a['rel'] == 'noopener noreferrer' for a in found), f'{name}: opens in a new tab with noopener noreferrer')
            check(all(a['title'] == 'Opens the live page on the scanned host' for a in found), f'{name}: title says it opens the live page on the scanned host')
        check(not anchors('bad'), 'a javascript: address gives no link at all')
        all_hrefs = page.eval_on_selector_all('a', 'els => els.map(a => a.href)')
        check(not any(SAMPLE in h or '%255' in h or 'email' in h for h in all_hrefs), 'the masked sample is in no address')
        check(SAMPLE in page.inner_text('[data-name="https"]'), 'the masked sample is still shown as text')

        page.focus('[data-name="https"] a')
        page.keyboard.press('Shift+Tab')
        page.keyboard.press('Tab')
        outline = page.evaluate('(() => { const s = getComputedStyle(document.activeElement); return [document.activeElement.tagName, s.outlineStyle, s.outlineWidth]; })()')
        check(outline[0] == 'A' and outline[1] != 'none' and outline[2] not in ('0px',), f'keyboard focus on the link shows an outline ({outline})')

        with page.expect_popup() as popup_info:
            page.click('[data-name="live"] a >> nth=0')
        popup = popup_info.value
        popup.wait_for_load_state()
        check(popup.url == f'http://127.0.0.1:{scanned_port}/live%20page?x=1', f'a click opens the scanned host page ({popup.url})')
        check(popup.evaluate('window.opener') is None, 'the opened page has no opener')
        check('/live%20page?x=1' in seen, f'the scanned host was asked for the encoded path ({seen})')
        browser.close()
    print('FAILED: %d' % len(failures) if failures else 'all checks passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
