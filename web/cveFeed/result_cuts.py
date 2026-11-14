"""What a scan result left out, in one shape, and the plain words for it.

A Sentinel's result (contract version 5) carries a ``cuts`` list on the nmap, nuclei, bbot and secrets kinds: every cap or clipped text it applied,
``{what, kind, limit, dropped, target}``. The server's own caps (the 500 ports of a host, the 500 findings of a nuclei or secrets result, the
five names of a discovered address) are written in the same shape, so one reader serves both: a result that was cut never reads as a whole one.
Everything in a cut came from a Sentinel (or from a host through it): ``clean`` rebuilds each row from known keys and bounds, ``words`` is the only
text made from it, and the pages escape it when they show it.
"""
import re

MAX_CUTS = 24
KINDS = ('items', 'chars', 'time')
_WHAT = re.compile(r'[a-z0-9_]{1,40}')
_LIMIT = 10 ** 9


def _count(value):
    return min(value, _LIMIT) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def clean(value):
    """The cuts of a result as a list of at most ``MAX_CUTS`` rows, each rebuilt from ``what`` (``[a-z0-9_]``, 40), ``kind`` (items, chars or time), ``limit``
    and ``dropped`` (whole numbers from 0, clamped; ``dropped`` is never kept for a time cut) and ``target`` (260 characters, one line). A row with
    another ``kind`` or a bad ``what`` is dropped. Anything that is not a list gives []."""
    out = []
    for item in value[:MAX_CUTS] if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        what, kind = item.get('what'), item.get('kind')
        if not (isinstance(what, str) and _WHAT.fullmatch(what) and kind in KINDS):
            continue
        row = {'what': what, 'kind': kind}
        for key in ('limit', 'dropped'):
            number = _count(item.get(key))
            if number is not None and not (key == 'dropped' and kind == 'time'):
                row[key] = number
        target = item.get('target')
        if isinstance(target, str) and target.strip():
            from reNgine.ai_providers import clean_text
            row['target'] = clean_text(target, 260)
        out.append(row)
    return out


def add(cuts, what, limit, dropped, kind='items', target=None):
    """Record in ``cuts`` (a list, changed in place) that ``dropped`` items of ``what`` were left out above ``limit``: the server's own cap, in the shape a
    Sentinel's cut has. A cut of the same thing on the same target is added to, not repeated (the smaller limit is the one that bit). Returns ``cuts``."""
    if not dropped or len(cuts) >= MAX_CUTS and not any(c['what'] == what and c.get('target') == target for c in cuts):
        return cuts
    for row in cuts:
        if row['what'] == what and row['kind'] == kind and row.get('target') == target:
            row['dropped'] = min(row.get('dropped', 0) + dropped, _LIMIT)
            row['limit'] = min(row.get('limit', limit), limit)
            return cuts
    row = {'what': what, 'kind': kind, 'limit': limit, 'dropped': min(dropped, _LIMIT)}
    if target:
        row['target'] = target
    cuts.append(row)
    return cuts


def merged(*lists):
    """The rows of several cut lists as one, at most ``MAX_CUTS``, the same cut of the same target counted once."""
    out = []
    for rows in lists:
        for row in rows or ():
            if row.get('kind') == 'items' and row.get('dropped'):
                add(out, row['what'], row.get('limit', 0), row['dropped'], 'items', row.get('target'))
            elif len(out) < MAX_CUTS and not any(o['what'] == row['what'] and o['kind'] == row['kind'] and o.get('target') == row.get('target') for o in out):
                out.append(dict(row))
    return out


_NAMES = {
    'ports': 'ports', 'findings': 'findings', 'events': 'events', 'http': 'HTTP responses', 'screenshots': 'screenshots', 'fetched': 'fetched pages',
    'references': 'references', 'cpes': 'CPEs', 'script_output': 'script output', 'banner': 'banner text', 'service': 'service text',
    'certificate': 'certificate text', 'os': 'operating system text', 'scanned_ranges': 'scanned port ranges', 'description': 'descriptions',
    'evidence': 'evidence', 'label': 'labels', 'title': 'titles', 'webserver': 'web server names', 'content_type': 'content types',
    'location': 'locations', 'names': 'host names',
}


# Cuts that are a setting at work, not a loss: the nuclei run left these installed checks out on purpose. They are said once as a plain sentence, never as a warning.
INFORMATIONAL = ('templates_with_credentials', 'templates_unreadable')


def informational(cut):
    """The plain sentence of an ``INFORMATIONAL`` cut ("377 checks that send a fixed credential were left out; turn on ... to run them"), else ``None``."""
    count = cut.get('dropped')
    if cut.get('what') == 'templates_with_credentials' and count:
        return (f"{count} check{'s' if count != 1 else ''} that send{'' if count != 1 else 's'} a fixed credential {'were' if count != 1 else 'was'} left out; "
                "turn on 'Allow checks that send credentials' to run them")
    if cut.get('what') == 'templates_unreadable' and count:
        return f"{count} installed check{'s' if count != 1 else ''} that could not be read or parsed {'were' if count != 1 else 'was'} left out"
    return None


def words(cut):
    """One cut in plain words: "findings: 120 dropped (kept 500)", "stopped at its time limit (480 s)", "banner text: 14 characters clipped (limit 1024)"."""
    sentence = informational(cut)
    if sentence:
        return sentence
    what = _NAMES.get(cut.get('what'), str(cut.get('what') or 'something').replace('_', ' '))
    where = f" on {cut['target']}" if cut.get('target') else ''
    limit = cut.get('limit')
    if cut.get('kind') == 'time':
        return f"{'stopped at its time limit' if cut.get('what') in ('time_limit', 'host_timeout') else what + ' stopped at its time limit'}{where}" + (f' ({limit} s)' if limit is not None else '')
    unit = 'characters clipped' if cut.get('kind') == 'chars' else 'dropped'
    dropped = cut.get('dropped')
    tail = f' (limit {limit})' if limit is not None else ''
    if dropped is None:
        return f'{what}{where}: cut{tail}'
    return f'{what}{where}: {dropped} {unit}{tail}'


def summary(result, losses_only=False):
    """Every cut of a stored result as plain sentences: its ``cuts``, the findings it kept only the strongest of (``dropped_findings``) and the ones on hosts the
    task did not name (``dropped``). [] for a result nothing was cut from (and for a result of a contract 4 Sentinel that sent no ``cuts``)."""
    if not isinstance(result, dict):
        return []
    rows = merged(clean(result.get('cuts')))
    if losses_only:  # leave out what a setting did on purpose (``INFORMATIONAL``): it is said on its own
        rows = [r for r in rows if r['what'] not in INFORMATIONAL]
    seen_findings = any(r['what'] == 'findings' for r in rows)
    out = [words(r) for r in rows]
    dropped_findings = _count(result.get('dropped_findings'))
    if dropped_findings and not seen_findings:  # a result stored before the cuts list: the same fact, from its own counter
        out.append(f'findings: {dropped_findings} dropped (only the strongest are kept)')
    dropped = _count(result.get('dropped'))
    if dropped:
        out.append(f'{dropped} entries about hosts or ports the task did not name were ignored')
    return out


def partial(result):
    """Whether what the result was cut from leaves its targets only partly checked: the tool stopped at its time limit, or findings were dropped. A cut text
    (a clipped banner) does not."""
    if not isinstance(result, dict):
        return False
    rows = clean(result.get('cuts'))
    return bool(any(r['kind'] == 'time' or (r['what'] == 'findings' and r.get('dropped')) for r in rows) or _count(result.get('dropped_findings')))
