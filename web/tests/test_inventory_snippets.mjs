import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

// The commands the Host inventory dialog tells a person to run are built by pure functions, so what they say is checked here.
const source = readFileSync(new URL('../static/cve/inventory-snippets.js', import.meta.url), 'utf8');
const {snippets, ageWord, SCRIPT_PATH} = await import(`data:text/javascript,${encodeURIComponent(source)}`);

const base = {origin: 'https://cvengine.example.test', project: 'proj-a'};

test('each platform gets one command with the server and the project, and no token in it', () => {
  const s = snippets(base);
  assert.equal(
    s.linux,
    "(umask 077; printf 'Paste the cvENGINE inventory token and press Enter: ' >&2; stty -echo 2>/dev/null; IFS= read -r t; stty echo 2>/dev/null; echo >&2; " +
      "printf '%s\\n' \"$t\" > cvengine-inventory.token) && " +
      'curl -fsS --cacert ca.crt https://cvengine.example.test/staticfiles/cve/inventory/cvengine-inventory.sh -o cvengine-inventory.sh && ' +
      'sh cvengine-inventory.sh --server https://cvengine.example.test --project proj-a --token-file cvengine-inventory.token --ca-file ca.crt',
  );
  assert.match(s.python, /python3 cvengine-inventory\.py --server https:\/\/cvengine\.example\.test --project proj-a --token-file cvengine-inventory\.token --ca-file ca\.crt$/);
  assert.match(s.windows, /^\$env:CVENGINE_TOKEN = \[System\.Net\.NetworkCredential\]::new\('', \(Read-Host 'Token' -AsSecureString\)\)\.Password; curl\.exe -fsS --cacert ca\.crt https:\/\/cvengine\.example\.test\/staticfiles\/cve\/inventory\/cvengine-inventory\.ps1 -o cvengine-inventory\.ps1; /);
  // a publicly trusted certificate needs no CA file, and Invoke-WebRequest is fine there
  assert.match(snippets({...base, privateCa: false}).windows, /Invoke-WebRequest https:\/\/cvengine\.example\.test\/staticfiles\/cve\/inventory\/cvengine-inventory\.ps1 -OutFile/);
  assert.match(s.windows, /-Server https:\/\/cvengine\.example\.test -Project proj-a -CaFile \.\\ca\.crt$/);
  assert.equal(SCRIPT_PATH, '/staticfiles/cve/inventory/');
});

test('the Linux and macOS command asks for the token with a prompt and does not wait silently for Ctrl-D', () => {
  // vmi2645654, Nov 20: a bare `cat > cvengine-inventory.token` waited for the token with no prompt, and the pasted command looked hung
  for (const command of [snippets(base).linux, snippets(base).python]) {
    assert.ok(command.startsWith("(umask 077; printf 'Paste the cvENGINE inventory token and press Enter: '"), command);
    assert.ok(command.includes('stty -echo') && command.includes('IFS= read -r t'), command);
    assert.ok(!/\bcat >/.test(command), command);
  }
});

test('a token is never part of a command: not as an argument, not as an assignment that shell history would keep', () => {
  for (const command of Object.values(snippets(base))) {
    assert.ok(!/cve_/.test(command), command);
    assert.ok(!/CVENGINE_TOKEN=/.test(command.replace("$env:CVENGINE_TOKEN = [System.Net.NetworkCredential]", '')), command);
    assert.ok(!/--token(\s|=)/.test(command), command);
  }
  const withToken = snippets({...base, token: `cve_${'a'.repeat(43)}`});
  assert.ok(!Object.values(withToken).some((c) => c.includes('a'.repeat(43))), 'an extra token argument is ignored');
});

test('the private authority options go away when the server uses a public certificate', () => {
  const s = snippets({...base, privateCa: false});
  for (const command of [s.linux, s.python, s.windows]) assert.ok(!/ca\.crt|--cacert|--ca-file|-CaFile/.test(command), command);
});

test('the dry run and schedule helpers only print', () => {
  const s = snippets(base);
  assert.equal(s.check, 'sh cvengine-inventory.sh --dry-run');
  assert.match(s.schedule, /--install-cron --server https:\/\/cvengine\.example\.test --project proj-a$/);
  assert.match(s.scheduleWindows, /-Schedule -Server /);
});

test('nothing that could add a second command is accepted', () => {
  for (const bad of [{project: 'a; rm -rf /'}, {project: 'a b'}, {project: '$(id)'}, {origin: 'https://x.test`id`'}, {origin: 'https://x.test && curl evil'}, {origin: 'https://x.test\nid'}]) {
    assert.throws(() => snippets({...base, ...bad}), /do not belong in a command/);
  }
  assert.throws(() => snippets({...base, project: undefined}));
});

test('the age of a report is said in words', () => {
  assert.equal(ageWord(0), 'under an hour');
  assert.equal(ageWord(1), '1 hour');
  assert.equal(ageWord(5), '5 hours');
  assert.equal(ageWord(72), '3 days');
  assert.equal(ageWord(24 * 120), '4 months');
  assert.equal(ageWord(null), 'unknown age');
});
