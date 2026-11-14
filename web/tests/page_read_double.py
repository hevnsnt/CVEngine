"""A stand-in for the Sentinel that answers a ``page_read`` task, for the tests of the validation's script read.

The reading itself (a base's front page, the scripts it loads, searched whole) is the Sentinel's now (``cvengine_scanner.probes.page_read`` in the
cvENGINE-sentinel repo, with its own tests); what cvENGINE keeps, and what these tests hold it to, is what a reading *means* for a match
(``validation.library_outcome``) and the scope policy it sends (``probe_scope.for_page_read``). ``Site`` (tests.test_client_library_validation) is the
fake network. ``reading_from(site, ...)`` builds what a Sentinel would return from it: the functions below are the reader as it was written when this
server did the reading (kept here, network-free, as the reference the Sentinel's was copied from), and ``run_script_read(check, site)`` runs the
server's runner with ``agentapi.probe_dispatch.try_page_read`` answered that way. Nothing here opens a socket.
"""
import itertools
import re
import time
from contextlib import contextmanager
from unittest import mock
from urllib.parse import urljoin, urlsplit

from cveFeed import js_libraries, local_egress, validation

REQUEST_GAP = 0


_JS_STRING = re.compile(r'''["']([^"'\s<>]{1,300}?\.js(?:\?[^"'\s<>]{0,200})?)["']''')


def served_by(response, base):
    """Whether ``response`` (a ``fetch`` result) is the page of ``base``'s own host: where its redirects ended (``final_url``) is that host. A
    host that only redirects to another one serves none of the scripts of the page it sends visitors to."""
    final = response.get('final_url') or response.get('url') or ''
    try:
        here, there = (urlsplit(base).hostname or '').lower().rstrip('.'), (urlsplit(final).hostname or '').lower().rstrip('.')
    except ValueError:
        return False
    return not there or here == there


def lazy_libraries(body, page_url, entries):
    """The library keys a page names in a script file path that is not one of its ``<script src>`` tags (``parse_page`` ``entries``): a loader,
    a consent manager or inline code that adds the script at run time (``createElement('script')``, a ``src`` set later, an import map). Such a
    copy is not read by the page read, so it can never be ruled out."""
    seen = {e['url'] for e in entries or [] if e.get('url')}
    out = set()
    for found in itertools.islice(_JS_STRING.finditer((body or '').replace('\\/', '/')), 2000):
        url = js_libraries._absolute(found.group(1), page_url)
        key = js_libraries.identify(url)['library'] if url else ''
        if key and url not in seen:
            out.add(key)
    return sorted(out)


def _scanned(got, error=''):
    """What one fetched script says, searched whole (``js_libraries.whole_body``): ``status``, ``whole`` (a 2xx body read to its end, not a
    challenge), ``truncated`` and, for a whole body, ``versions``, ``unplaceable``, ``blocks``, ``loaders`` and ``overflow``."""
    if got is None:
        return {'status': 0, 'whole': False, 'error': error or 'not read'}
    status = got.get('status') or 0
    text = got.get('body') or ''
    raw = got.get('bytes')
    size = raw if isinstance(raw, int) else len(text.encode('utf-8', 'replace'))
    truncated = size >= js_libraries.MAX_SCRIPT_BYTES or bool(got.get('truncated'))
    out = {'status': status, 'truncated': truncated, 'whole': 200 <= status < 300 and not truncated and not got.get('challenge')}
    if not out['whole']:
        out['error'] = ('cut at the read limit' if truncated else f"challenged by {got['challenge']}" if got.get('challenge')
                        else f'answered {status}')
        return out
    return {**out, **js_libraries.whole_body(text)}


def _entry_kinds(entries, page_url):
    """The page's scripts with a source, as a script read needs them: ``url``, ``kind`` (``js_libraries.kind_of``), ``library`` (the library
    its name is, ``js_libraries.identify``) and ``fallback``."""
    out = []
    for entry in entries:
        if entry.get('url'):
            out.append({'url': entry['url'], 'kind': js_libraries.kind_of(entry['url'], page_url),
                        'library': js_libraries.identify(entry['url'])['library'], 'fallback': bool(entry.get('fallback'))})
    return out


def read_host_libraries(project_id, sub, bases, get, sleep=time.sleep, unattended=True):
    """The html-libraries read of every web base of ``sub`` for a validation re-test (``cveFeed.validation.run_script_read``): each base's front
    page through the same gated, pinned GET as every probe (a redirect is followed only on the host itself, so a redirect to another host is
    seen as it is), then the scripts of every page through ``js_libraries`` (its vetter, one fresh ``Reader`` with the usual budgets, the
    per-host script limit shared by the bases), past the script cache: every script is asked for in full (no ETag), and every script and
    page is searched whole (``js_libraries.whole_body``). Every hop of every request, redirects included, passes the probe gate and the
    scope rules of ``scope_hop`` (host scope, a one-host target, the bug bounty program; ``unattended`` for a run the system started).
    Nothing is stored. ``get(url, headers=None)`` replaces the network (tests). Returns ``{'pages': [...], 'scanned': {url: _scanned},
    'budget_left': n}``, one page per base: ``outcome`` is ``read`` (the host's own page answered 2xx and its scripts were read),
    ``redirect`` (``status`` and ``location``), ``challenged``, ``error_page``, ``unanswered``, ``refused`` (the gate refused the address)
    or ``held`` (this server's egress governor or skip list held the port: ``cveFeed.local_egress``; nothing was sent). Every connection
    goes through the pinned transport, so it is counted, logged and paced like any in-process connection; a read page carries ``records``
    (``js_libraries.resolve``), ``entries`` (its scripts with a source: ``_entry_kinds``), ``skipped`` (scripts it wanted and did not read,
    with why), ``truncated`` (scripts read only up to the size cap), ``read_whole`` (scripts whose file was read whole), ``capped`` (the
    parse could not see every script), ``page_truncated`` (the page itself was cut at the read limit), ``inline`` (``[library key,
    version]`` inline scripts state), ``inline_unread`` (inline code no rule reads), ``scripts`` (how many scripts with a source the page
    has), ``lazy`` (libraries the page adds at run time) and ``page_scan`` (the page's own text searched whole)."""
    scanned = {}
    page_get, raw_get = (lambda url: get(url)), (lambda url: get(url))

    def script_get(url, headers=None):
        # asked in full, never revalidated with an ETag: a 304 would leave nothing to search whole
        try:
            got = raw_get(url)
        except local_egress.PortHeld:
            scanned[url] = {'status': 0, 'whole': False, 'held': True, 'error': 'held by this server\'s egress governor'}
            raise
        except (OSError, ValueError) as exc:
            scanned[url] = {'status': 0, 'whole': False, 'error': 'refused by the scope gate' if isinstance(exc, ValueError) else type(exc).__name__}
            raise
        scanned[url] = _scanned(got)
        return got
    reader = js_libraries.Reader(project_id, fresh=True)
    budget = {'left': js_libraries.MAX_SCRIPTS_PER_HOST}
    pages = []
    for base in bases:
        page = {'base': base, 'outcome': '', 'status': 0}
        try:
            first = page_get(base.rstrip('/') + '/') or {}
        except ValueError:
            page['outcome'] = 'refused'
            pages.append(page)
            continue
        except local_egress.PortHeld as exc:  # this server's egress governor or skip list held the port: nothing was sent (cveFeed.local_egress)
            page.update(outcome='held', error=str(exc)[:200])
            pages.append(page)
            continue
        except OSError as exc:
            page.update(outcome='unanswered', error=type(exc).__name__)
            pages.append(page)
            continue
        status = first.get('status') or 0
        final = first.get('final_url') or first.get('url') or base
        page.update(status=status, final_url=str(final)[:500])
        if first.get('challenge'):
            page.update(outcome='challenged', challenge=first['challenge'])
        elif 300 <= status < 400:
            page.update(outcome='redirect', location=urljoin(final, (first.get('location') or '').strip())[:500])
        elif 200 <= status < 300 and not served_by(first, base):
            # followed to another host (a caller's fetch that follows): the host's own answer, when fetch kept it, says which redirect it was
            origin = first.get('redirected_from') or {}
            page.update(outcome='redirect', location=urljoin(origin.get('final_url') or base, (origin.get('location') or '').strip())[:500]
                        if origin.get('location') else str(final)[:500], status=origin.get('status') or status)
        elif not 200 <= status < 300:
            page['outcome'] = 'error_page'
        else:
            body = first.get('body', '')
            entries = js_libraries.parse_page(body, final)
            report, coverage = {}, {}
            records = js_libraries.read_page(entries, final, script_get, js_libraries.vetter(final, project_id, target=getattr(sub, 'target_domain', None)),
                                             budget, before_each=lambda: sleep(REQUEST_GAP), reader=reader, project=project_id, report=report,
                                             coverage=coverage)
            page.update(outcome='read', records=records, skipped=list(report.get('skipped') or [])[:40], truncated=list(report.get('truncated') or [])[:20],
                        scripts=sum(1 for e in entries if e.get('url')), read_whole=coverage.get('read', 0),
                        capped=bool(getattr(entries, 'capped', False)), inline_unread=int(getattr(entries, 'inline_unread', 0)),
                        inline=[list(pair) for pair in getattr(entries, 'inline', ())][:20],
                        lazy=lazy_libraries(body, final, entries), entries=_entry_kinds(entries, final)[:js_libraries.MAX_ENTRIES],
                        page_truncated=bool(first.get('truncated')), page_scan=js_libraries.whole_body(body, page=True))
        pages.append(page)
    return {'pages': pages, 'scanned': scanned, 'budget_left': budget['left']}


def refetch_script(project_id, sub, url, get=None, sleep=time.sleep, page_url=None, unattended=True):
    """A script file a match was made on (or the host was seen to load the library from), fetched again for a script read when the pages
    did not load it: through ``js_libraries.vetter`` for ``page_url`` (its port rule, a third-party or analytics host never, a same-site
    host only under the vetter's rules) and the same gated, scoped GET as the page read (``scope_hop``). Returns ``_scanned`` (the file
    searched whole), with ``held`` when this server's egress governor held the port, or ``{'status': 0, 'whole': False, 'error': why}``
    when it may not be read."""
    page_url = page_url or f'https://{sub.name}/'
    try:
        refusal = js_libraries.vetter(page_url, project_id, target=getattr(sub, 'target_domain', None))(url)
    except Exception:  # noqa: BLE001 - a host that cannot be vetted is not read
        refusal = 'not vetted'
    if refusal:
        return {'status': 0, 'whole': False, 'error': f'not read ({refusal})'}
    getter = get
    try:
        got = getter(url)
    except local_egress.PortHeld:
        return {'status': 0, 'whole': False, 'held': True, 'error': 'held by this server\'s egress governor'}
    except ValueError:
        return {'status': 0, 'whole': False, 'error': 'refused by the scope gate'}
    except OSError as exc:
        return {'status': 0, 'whole': False, 'error': type(exc).__name__}
    return _scanned(got or {})


def reading_row(site, read):
    """The row a Sentinel returns for ``read`` (``{'id', 'op', 'host', ...}`` of a ``page_read`` task) when the network is ``site``."""
    class Sub:  # the Sentinel needs no database row: the task names the host and its bases
        pass
    sub = Sub()
    sub.name, sub.target_domain = read['host'], None
    if read['op'] == 'head':
        got = site(read['url'])
        return {'id': read['id'], 'head': {'status': got.get('status'), 'method': 'HEAD', 'server': got.get('server', ''),
                                              'powered_by': got.get('powered_by', ''), 'title': got.get('title', '')}}
    reading = read_host_libraries(0, sub, read['bases'], get=site)
    reading['extra'] = {}
    scanned = reading.get('scanned') or {}
    if [p for p in reading['pages'] if p.get('outcome') == 'read' and (p.get('records') or {}).get(read['library'])]:
        page = next((p.get('final_url') or p.get('base') for p in reading['pages'] if p.get('outcome') == 'read'), None)
        for url in [u for u in read['seen_urls'] if u not in scanned][:js_libraries.MAX_SCRIPTS_PER_HOST]:
            if reading['budget_left'] <= 0:
                reading['extra'][url] = {'status': 0, 'whole': False, 'error': 'page host limit'}
                continue
            reading['budget_left'] -= 1
            reading['extra'][url] = refetch_script(0, sub, url, get=site, page_url=page)
    return {'id': read['id'], 'reading': reading}


@contextmanager
def answering(site, asked=None):
    """``agentapi.probe_dispatch.try_page_read`` answered by a Sentinel that reads ``site`` (a ``get(url, headers=None)``): the row of the result. ``asked``
    (a list) receives every ``(read, scope)`` the server sent."""
    def answer(project, read, scope, scan=None):
        if asked is not None:
            asked.append((read, scope))
        row = reading_row(site, read)
        if row.get('error'):
            raise RuntimeError(row['error'])
        return row
    with mock.patch('agentapi.probe_dispatch.try_page_read', side_effect=answer):
        yield


def run_script_read(check, site, asked=None):
    """``validation.run_script_read(check)`` against the fake network ``site``, through the double Sentinel above."""
    with answering(site, asked):
        return validation.run_script_read(check)

