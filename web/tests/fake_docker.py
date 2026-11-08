#!/usr/bin/env python3
"""A fake `docker` for tests/test_scanner_script.py: just enough of docker and `docker compose` to run scripts/scanner.sh against.

State lives in $STUB_DIR/state.json (the test reads and writes it): ``images`` (name or id -> image id), ``registry`` (reference -> image id a
pull delivers), ``container`` ({id, image_id, ref} or null), ``contract`` / ``release`` / ``healthy`` (image id -> what a container of it reports),
``server`` (what the web container answers: "version min_supported"), and the switches ``pull_fails``, ``busy``, ``no_scanner``. Every call is
appended to ``calls.log``. The scanner container's image is read the way Compose would: CVENGINE_SCANNER_IMAGE, else
CVENGINE_SCANNER_ROLLBACK_IMAGE (both from ./.env), else ``default_ref``; a name that is not on the host fails `up` (``--pull never``) or is
pulled first (the default).
"""
import json
import os
import re
import sys

DIR = os.environ['STUB_DIR']
STATE = os.path.join(DIR, 'state.json')
args = sys.argv[1:]
with open(os.path.join(DIR, 'calls.log'), 'a', encoding='utf-8') as log:
    log.write('docker ' + ' '.join(args) + '\n')
state = json.load(open(STATE, encoding='utf-8'))


def save():
    json.dump(state, open(STATE, 'w', encoding='utf-8'))


def env_value(key):
    value = os.environ.get(key, '')
    try:
        for line in open('.env', encoding='utf-8'):
            if line.startswith(key + '='):
                value = line.split('=', 1)[1].strip()
    except OSError:
        pass
    return value


def resolve(name):
    image_id = state['images'].get(name)
    known = set(state['images'].values()) | ({state['container']['image_id']} if state.get('container') else set())
    if image_id is None and name in known:  # docker accepts an image id wherever it accepts a name, and a container keeps its image
        image_id = name
    return image_id


def out(text):
    sys.stdout.write(str(text) + '\n')


sub = args
if sub and sub[0] == 'compose':
    rest = sub[1:]
    i = 0
    while i < len(rest) and rest[i] in ('-f', '--env-file', '-p'):
        i += 2
    rest = rest[i:]
    if rest[:2] == ['config', '--services']:
        out('web\ncelery\ncelery-beat\ndb\nredis')
        if not state.get('no_scanner'):
            out('scanner')
        sys.exit(0)
    if rest[:2] == ['ps', '-aq']:
        if state.get('container'):
            out(state['container']['id'])
        sys.exit(0)
    if rest[:1] == ['rm']:
        state['container'] = None
        save()
        sys.exit(0)
    if rest[:1] == ['up']:
        never = '--pull' in rest and rest[rest.index('--pull') + 1] == 'never'
        ref = env_value('CVENGINE_SCANNER_IMAGE') or env_value('CVENGINE_SCANNER_ROLLBACK_IMAGE') or state['default_ref']
        if resolve(ref) is None and not never and state.get('pull_policy') == 'always' and ref in state['registry'] and not state.get('pull_fails'):
            state['images'][ref] = state['registry'][ref]
        if resolve(ref) is None:
            sys.stderr.write(f'no such image: {ref}\n')
            sys.exit(1)
        if state.get('up_fails'):
            sys.exit(1)
        state['container'] = {'id': 'scannerid', 'image_id': resolve(ref), 'ref': ref}
        state['drained'] = False
        save()
        sys.exit(0)
    if rest[:3] == ['exec', '-T', 'web']:
        out(state.get('server', '3 1'))
        sys.exit(0 if state.get('server', '3 1') else 1)
    if rest[:3] == ['exec', '-T', 'scanner']:
        container = state.get('container')
        if not container:
            sys.exit(1)
        image_id = container['image_id']
        command = ' '.join(rest[3:])
        if 'client.control heartbeat' in command:
            sys.exit(0 if state['healthy'].get(image_id) else 1)
        if 'CONTRACT_VERSION' in command:
            if image_id in state['contract']:
                out(state['contract'][image_id])
            sys.exit(0)
        if 'config.version()' in command:
            out(state['release'].get(image_id, ''))
            sys.exit(0)
        if 'client.control drain' in command:
            state['drained'] = True
            save()
            sys.exit(0)
        if 'client.control undrain' in command:
            state['drained'] = False
            save()
            sys.exit(0)
        if 'client.control wait-idle' in command:
            sys.exit(1 if state.get('busy') else 0)
        if 'client.control report' in command:
            state.setdefault('reports', []).append(command)
            save()
            sys.exit(0)
        sys.exit(0)
    sys.exit(0)

if args[:2] == ['image', 'inspect']:
    name = args[-1]
    image_id = resolve(name)
    if image_id is None:
        sys.exit(1)
    if '-f' in args:
        out(image_id)
    sys.exit(0)
if args[:1] == ['pull']:
    ref = args[-1]
    if state.get('pull_fails') or ref not in state['registry']:
        sys.stderr.write('pull failed\n')
        sys.exit(1)
    state['images'][ref] = state['registry'][ref]
    save()
    sys.exit(0)
if args[:1] == ['tag']:
    image_id = resolve(args[1])
    if image_id is None:
        sys.exit(1)
    state['images'][args[2]] = image_id
    save()
    sys.exit(0)
if args[:1] == ['build']:
    if state.get('build_fails'):
        sys.exit(1)
    for index, arg in enumerate(args):
        if arg == '-t':
            state['images'][args[index + 1]] = 'sha256:built'
    save()
    sys.exit(0)
if args[:1] == ['inspect']:
    container = state.get('container')
    if not container:
        sys.exit(1)
    fmt = args[args.index('-f') + 1]
    out(container['image_id'] if fmt == '{{.Image}}' else container['ref'])
    sys.exit(0)
sys.exit(0)
