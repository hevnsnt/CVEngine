#!/usr/bin/env python3
"""compare.py BEFORE_DIR AFTER_DIR SIZE [min_ms]: markdown rows for entries whose cold/warm wall or queries moved."""
import json, sys
b, a, n = sys.argv[1:4]
floor = float(sys.argv[4]) if len(sys.argv) > 4 else 0
def load(d):
    j = json.load(open(f'{d}/scale-{n}.json')); out = {}
    for e in j['entries']: out[(e['group'], e['label'])] = (e['cold']['wall_ms'], e['cold']['queries'], e['cold']['db_ms'], e['warm']['wall_ms'], e['warm']['queries']) if e.get('warm') else (e['cold']['wall_ms'], e['cold']['queries'], e['cold']['db_ms'], None, None)
    for r in j['reports']: out[('report', r['label'])] = (r['cold']['wall_ms'], r['cold']['queries'], r['cold']['db_ms'], None, None)
    return out
B, A = load(b), load(a)
print('| endpoint | hosts | before cold ms / q / db ms | after cold ms / q / db ms | before warm ms / q | after warm ms / q |\n|---|---|---|---|---|---|')
for k in B:
    if k not in A: continue
    x, y = B[k], A[k]
    if max(x[0], y[0], x[3] or 0, y[3] or 0) < floor: continue
    f = lambda v, i: f'{v[i]:.0f} / {v[i+1]} / {v[i+2]:.0f}' if i == 0 else (f'{v[3]:.0f} / {v[4]}' if v[3] is not None else '')
    print(f'| {k[0]}: {k[1]} | {n} | {f(x,0)} | {f(y,0)} | {f(x,3)} | {f(y,3)} |')
