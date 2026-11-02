#!/usr/bin/env python3
"""The browser half of the web screenshot capture (``cveFeed.web_shot`` is the other half). It runs as a child process, never inside a Celery
worker: the workers are gevent pools, which Playwright's own greenlets do not get along with, and a browser that leaks or crashes must die with
its process instead of growing the worker. One child serves one batch of pages, one after another (one browser, one fresh context per page),
then exits.

This file imports nothing of Django. The parent sends one JSON line on stdin: ``{"targets": [{"key", "url", "out"}], "settings": {...},
"proxy": {"server", "password"}}``, and the child answers one JSON line per page on stdout (``{"op": "result", "key", "outcome", "reason", ...}``),
then ``{"op": "done"}`` (or ``{"op": "fatal", "reason"}`` when the browser could not run).

The child never connects anywhere itself. Every page's browser context is pointed at the parent's vetting proxy (``cveFeed.shot_proxy``,
with the page key as the proxy user), and loopback is sent through it too, so the platform's guards judge the page, every redirect hop and
every sub-resource before a byte leaves; a job without a proxy is refused. A page gets a fresh context: no cookies or storage carry over,
downloads are refused, no permission is granted, service workers are blocked, dialogs and pop-ups are dismissed. HTTPS errors are ignored on
purpose: an expired or self-signed certificate is exactly the kind of host this is for. Nothing here is a scan; it loads a page once, the way a
person would, and takes a picture of it.
"""
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

VIEWPORT = (1280, 800)
NAV_TIMEOUT_MS = 15000       # for the page to commit and parse
TOTAL_SECONDS = 20           # the whole of one page: navigation, settling and the picture
SETTLE_MS = 600              # a last moment for fonts and late layout after the load event
LAUNCH_ARGS = ('--disable-dev-shm-usage', '--disable-gpu', '--mute-audio', '--no-first-run', '--disable-extensions',
               '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-notifications',
               '--hide-scrollbars',
               # WebRTC sends UDP straight from the browser, around the vetting proxy (a STUN URL in a page names a host and a port of its choosing, loopback
               # and the metadata address included, and its name is resolved by Chromium itself): with this policy only proxied traffic is allowed, and
               # none of it is UDP. QUIC is UDP too.
               '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic',
               # one renderer, with a heap ceiling: a hostile page cannot start a process per frame or grow without bound (the parent also kills the
               # whole tree above CVENGINE_SCREENSHOT_MAX_RSS_MB)
               '--renderer-process-limit=1', '--js-flags=--max-old-space-size=512')
LOCAL_SCHEMES = ('data', 'blob', 'about')
NETWORK_SCHEMES = ('http', 'https')


def classify_error(message):
    """``(outcome, reason)`` for what a failed navigation raised. The text is Chromium's (``net::ERR_...``) or Playwright's own."""
    text = str(message or '')
    low = text.lower()
    if 'download is starting' in low:
        return 'error', 'The address is a file download, not a page.'
    if 'timeout' in low or 'err_timed_out' in low or 'err_connection_timed_out' in low:
        return 'timeout', 'The page did not load within the time allowed.'
    if 'err_name_not_resolved' in low or 'err_name_resolution_failed' in low:
        return 'unreachable', 'The name does not resolve.'
    if 'err_connection_refused' in low:
        return 'unreachable', 'The connection was refused.'
    if 'err_connection_reset' in low or 'err_connection_closed' in low or 'err_empty_response' in low:
        return 'unreachable', 'The connection was closed without an answer.'
    if 'err_address_unreachable' in low or 'err_network_changed' in low or 'err_internet_disconnected' in low:
        return 'unreachable', 'The address could not be reached.'
    if 'err_ssl' in low or 'err_cert' in low or ('tls' in low and 'err_' in low):
        return 'tls_error', 'The TLS handshake failed.'
    if 'err_too_many_redirects' in low:
        return 'error', 'The page redirects in a loop.'
    if 'err_tunnel_connection_failed' in low or 'err_proxy_connection_failed' in low or 'err_empty_response' in low:
        return 'unreachable', 'The connection could not be made.'
    if 'err_blocked_by_client' in low:
        return 'error', 'The request was blocked.'
    if 'err_http2' in low or 'err_http_' in low or 'err_invalid_http' in low:
        return 'error', 'The server answered with an invalid HTTP response.'
    if 'closed' in low and ('target' in low or 'browser' in low):
        return 'error', 'The browser closed while loading the page.'
    return 'error', re.sub(r'\s+', ' ', text.split('\n', 1)[0])[:200] or 'The page could not be captured.'


class Capturer:
    """Captures one page at a time with a browser that is already running, every page through the parent's vetting proxy."""

    def __init__(self, browser, settings=None, clock=time.monotonic):
        self.browser, self.clock = browser, clock
        self.settings = dict(settings or {})
        proxy = self.settings.get('proxy') or {}
        if not proxy.get('server') or not proxy.get('password'):
            raise ValueError('no vetting proxy: the browser is never run without one')

    def _context(self, key):
        width, height = self.settings.get('viewport') or VIEWPORT
        proxy = self.settings['proxy']
        options = {'viewport': {'width': width, 'height': height}, 'ignore_https_errors': True, 'accept_downloads': False,
                   'service_workers': 'block', 'java_script_enabled': True, 'locale': 'en-US', 'timezone_id': 'UTC',
                   'permissions': [], 'bypass_csp': False,
                   # <-loopback>: localhost and 127.0.0.1 go through the proxy too (Chromium bypasses it for them otherwise), so a redirect to
                   # one is judged and refused there instead of reaching this container's own services
                   'proxy': {'server': proxy['server'], 'username': str(key), 'password': proxy['password'], 'bypass': '<-loopback>'}}
        agent = self.settings.get('user_agent')
        if agent:
            options['user_agent'] = agent
        return self.browser.new_context(**options)

    def capture(self, target):
        """The result dict of one page: ``outcome`` (ok, timeout, unreachable, tls_error or error), a plain ``reason``, and for a page that was
        reached ``final_url``, ``status``, ``title`` and the ``path`` of the PNG written. ``blocked`` is the parent's call: it knows which
        connections its proxy refused."""
        started = self.clock()
        total = float(self.settings.get('total_seconds') or TOTAL_SECONDS)
        nav_ms = int(self.settings.get('nav_timeout_ms') or NAV_TIMEOUT_MS)
        result = {'key': target['key'], 'outcome': 'error', 'reason': '', 'final_url': '', 'status': None, 'title': '', 'path': ''}
        context = page = None

        def remaining():
            return max(1.0, total - (self.clock() - started))
        try:
            context = self._context(target['key'])
            page = context.new_page()
            page.on('dialog', lambda dialog: _quietly(dialog.dismiss))
            page.on('popup', lambda popup: _quietly(popup.close))
            page.route('**/*', _only_web)
            try:
                response = page.goto(target['url'], wait_until='domcontentloaded', timeout=int(min(nav_ms, remaining() * 1000)))
            except Exception as exc:  # noqa: BLE001 - classified
                result['outcome'], result['reason'] = classify_error(exc)
                return result
            for wait, cap in (('load', 6000), ('networkidle', 2500)):  # a page that never goes idle is photographed as it is
                _quietly(lambda wait=wait, cap=cap: page.wait_for_load_state(wait, timeout=int(min(cap, remaining() * 1000))))
            _quietly(lambda: page.wait_for_timeout(SETTLE_MS))
            final = page.url or ''
            if final.startswith(('chrome-error:', 'about:')):
                result['outcome'], result['reason'] = 'unreachable', 'The browser showed an error page instead of the site.'
                return result
            result['final_url'] = final[:2000]
            result['status'] = response.status if response is not None else None
            result['title'] = _title(page)
            out = target['out']
            os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
            page.screenshot(path=out, type='png', full_page=False, timeout=int(min(10000, max(2000, remaining() * 1000))),
                            animations='disabled', caret='hide')
            if not os.path.isfile(out) or os.path.getsize(out) == 0:
                result['outcome'], result['reason'] = 'error', 'The browser produced an empty picture.'
                return result
            result.update(outcome='ok', path=out)
            return result
        except Exception as exc:  # noqa: BLE001 - one page failing must never end the batch
            result['outcome'], result['reason'] = classify_error(exc)
            return result
        finally:
            for closer in (page and page.close, context and context.close):
                if closer:
                    _quietly(closer)


def _only_web(route):
    """Anything that is not http, https or an inline ``data:`` or ``blob:`` URL never leaves the browser (``file:``, ``ftp:``, ``chrome:``)."""
    try:
        scheme = (urlsplit(route.request.url).scheme or '').lower()
        if scheme in LOCAL_SCHEMES + NETWORK_SCHEMES:
            return route.continue_()
        return route.abort('blockedbyclient')
    except Exception:  # noqa: BLE001 - when in doubt the request does not go out
        _quietly(lambda: route.abort('blockedbyclient'))


def _quietly(call):
    try:
        return call()
    except Exception:  # noqa: BLE001 - teardown and optional waits never decide the outcome
        return None


def _title(page):
    try:
        return re.sub(r'\s+', ' ', page.title() or '').strip()[:300]
    except Exception:  # noqa: BLE001 - a page that is gone has no title
        return ''


# ----------------------------------------------------------------------------- the child process

def _emit(stream, obj):
    stream.write(json.dumps(obj, separators=(',', ':')) + '\n')
    stream.flush()


def main(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or os.fdopen(os.dup(1), 'w', buffering=1)
    sys.stdout = sys.stderr  # whatever a library prints is not the protocol
    job = json.loads(stdin.readline() or '{}')
    settings = dict(job.get('settings') or {})
    settings['proxy'] = job.get('proxy') or {}
    if not (settings['proxy'].get('server') and settings['proxy'].get('password')):
        _emit(stdout, {'op': 'fatal', 'reason': 'No vetting proxy was given; the browser is never run without one.'})
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _emit(stdout, {'op': 'fatal', 'reason': 'Playwright is not installed.'})
        return 2
    try:
        with sync_playwright() as playwright:
            # 'per-context': every page's context names its own proxy (and credentials), see Capturer._context; nothing goes direct
            browser = playwright.chromium.launch(args=list(LAUNCH_ARGS), proxy={'server': 'per-context'})
            try:
                if not settings.get('user_agent'):
                    settings['user_agent'] = f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser.version} Safari/537.36'
                capturer = Capturer(browser, settings)
                for target in job.get('targets') or []:
                    _emit(stdout, {'op': 'result', **capturer.capture(target)})
                    if not browser.is_connected():
                        _emit(stdout, {'op': 'fatal', 'reason': 'The browser stopped.'})
                        return 3
            finally:
                _quietly(browser.close)
    except Exception as exc:  # noqa: BLE001 - the parent is told why nothing was captured
        _emit(stdout, {'op': 'fatal', 'reason': re.sub(r'\s+', ' ', str(exc))[:300] or type(exc).__name__})
        return 2
    _emit(stdout, {'op': 'done'})
    return 0


if __name__ == '__main__':
    sys.exit(main())
