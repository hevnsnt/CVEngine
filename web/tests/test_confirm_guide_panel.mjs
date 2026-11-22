import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {register} from 'node:module';
import {test} from 'node:test';

// The "Confirm it yourself" panel of the finding page: the guide every finding kind now has (confirm-guide.js, drawn against a tiny DOM) and
// the sentence it shows when no check has run (confirm-guide-logic.js), which says what is really true instead of "None has run yet".
const hook = `
export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/staticfiles/cve/')) {
    return next(new URL('../static/cve/' + specifier.slice('/staticfiles/cve/'.length), ${JSON.stringify(import.meta.url)}).href, context);
  }
  return next(specifier, context);
}`;
register('data:text/javascript,' + encodeURIComponent(hook));

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.dataset = {}; this._text = ''; this.className = ''; this.title = ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...kids) { kids.forEach((k) => this.children.push(typeof k === 'string' ? Object.assign(new Node('#text'), {_text: k}) : k)); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };
const find = (root, pred) => { const out = []; walk(root, (n) => pred(n) && out.push(n)); return out; };
globalThis.document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => Object.assign(new Node('#text'), {_text: t}),
  querySelector: () => null,
  querySelectorAll: () => [],
  cookie: '',
  documentElement: new Node('html'),
};

const {confirmBox} = await import('../static/cve/confirm-guide.js');
const {checkStateText} = await import('../static/cve/confirm-guide-logic.js');

// the guide agentapi.services.finding_detail returns for an OpenVAS PHP version check at QoD 30 on a Red Hat host (tests/test_finding_confirm.py)
const OPENVAS = {
  class: 'openvas', class_label: 'OpenVAS (Greenbone) result: version check', headline: 'Confirm PHP 7.4.33 on gecmedia.example.com:443',
  where: [{label: 'Host and port (as OpenVAS reported it)', text: 'gecmedia.example.com:443/tcp'},
    {label: 'Web server banner cvENGINE recorded for this host (seen on the host)', quote: 'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k'}],
  look_for: [{label: 'OpenVAS test (NVT) OID', text: '1.3.6.1.4.1.25623.1.0.153495'},
    {label: 'What OpenVAS reported (seen on the host)', quote: 'Installed version: 7.4.33\nFixed version:     8.1.31'},
    {label: 'How sure OpenVAS is', text: 'QoD 30%, remote_banner_unreliable: OpenVAS inferred this version; it was not read from the service. It is a guess, not proof.'}],
  steps: [{title: 'Hint only: read the X-Powered-By header', run_in: 'shell', detail: 'HEAD request.',
    command: "curl -gsS -I --max-time 15 https://gecmedia.example.com/ | grep -i -E '^(server|x-powered-by):'"}],
  verdict: {fixed: '8.1.31, 8.2.26, 8.3.14', affected: 'On the host, PHP reports a version below the fixed release of its line: affected.',
    not_affected: 'The distribution package carries a backported fix: not affected.', cant_tell: 'The on-host commands cannot be run.',
    notes: ['OpenVAS inferred this version; it was not read from the service. Confirm it on the host before acting on it.']},
  local: [{title: 'On the host: the version of the installed binary', commands: [{platform: 'linux', command: 'php -v', explain: 'Prints the PHP version.'}]},
    {title: 'On the host: the installed package', commands: [
      {platform: 'rhel', command: "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' php-common", explain: 'Prints the installed php-common version-release.'},
      {platform: 'rhel', command: 'rpm -q --changelog php-common | grep -F -e CVE-2024-11233 -e CVE-2024-8932', explain: 'A line means this build carries the fix.'}]}],
  links: [{label: 'Greenbone SecInfo page of NVT 1.3.6.1.4.1.25623.1.0.153495', url: 'https://secinfo.greenbone.net/nvt/1.3.6.1.4.1.25623.1.0.153495'},
    {label: 'Red Hat security tracker for CVE-2024-11233', url: 'https://access.redhat.com/security/cve/CVE-2024-11233'}],
  links_title: 'Trackers and references',
  fix: 'Upgrade PHP to 8.1.31 or later, or install your distribution\'s fixed PHP package; then let OpenVAS scan the host again.',
  notice: 'cvENGINE does not run these commands.',
};

test('an OpenVAS guide draws where, what, the steps, the on-host commands, the trackers and the fix', () => {
  const box = confirmBox(OPENVAS);
  const text = box.textContent;
  for (const part of ['Confirm PHP 7.4.33 on gecmedia.example.com:443', 'Where to look', 'gecmedia.example.com:443/tcp', 'What to look for',
    'OpenVAS inferred this version; it was not read from the service', 'Check it (read-only)', 'Hint only: read the X-Powered-By header',
    "curl -gsS -I --max-time 15 https://gecmedia.example.com/", 'How to read the result (fixed in 8.1.31, 8.2.26, 8.3.14)', 'php -v',
    'rpm -q --changelog php-common', 'RHEL / Fedora', 'Trackers and references', 'Fix it', 'cvENGINE does not run these commands.']) {
    assert.ok(text.includes(part), part);
  }
  const links = find(box, (n) => n.tag === 'a').map((a) => a.attrs.href);
  assert.deepEqual(links, ['https://secinfo.greenbone.net/nvt/1.3.6.1.4.1.25623.1.0.153495', 'https://access.redhat.com/security/cve/CVE-2024-11233']);
  find(box, (n) => n.tag === 'a').forEach((a) => assert.equal(a.attrs.rel, 'noopener noreferrer nofollow'));
  // what the host or a feed said is drawn as untrusted data, never as a command
  const untrusted = find(box, (n) => /\buntrusted\b/.test(n.className)).map((n) => n.textContent);
  assert.ok(untrusted.some((t) => t.includes('Red Hat Enterprise Linux')));
  assert.ok(untrusted.some((t) => t.includes('Installed version: 7.4.33')));
  // four commands, one copy button each
  assert.equal(find(box, (n) => n.tag === 'button' && n.textContent === 'Copy').length, 4);
});

test('a nuclei guide draws its template, the active re-run, the matched URL and the redacted request', () => {
  const box = confirmBox({
    class: 'nuclei', class_label: 'nuclei template match', headline: 'Confirm git-config on https://app.example.com/.git/config',
    where: [{label: 'Matched at', url: 'https://app.example.com/.git/config'}],
    steps: [{title: 'Repeat the request the scan sent', run_in: 'shell', command: "curl -gsS -i -H 'Accept: */*' --max-time 15 https://app.example.com/.git/config | head -c 4000",
      detail: 'The scan also sent Authorization, Cookie (left out here).'}],
    template: {template_id: 'git-config', result: 'matched', template_url: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/configs/git-config.yaml',
      command: 'nuclei -duc -ni -t http/exposures/configs/git-config.yaml -u https://app.example.com/.git/config', active: 'Active check: sends the template\'s own requests.',
      matched_at: 'https://app.example.com/.git/config', matcher: 'word', extracted: ['[core]'], request: 'GET /.git/config HTTP/1.1\nCookie: [redacted]'},
  });
  const text = box.textContent;
  for (const part of ['Repeat the request the scan sent', 'left out here', 'Template git-config, result matched.', 'Open the template', 'Active check: run the same template',
    'nuclei -duc -ni -t http/exposures/configs/git-config.yaml', 'Matcher: word', 'credentials redacted', 'Cookie: [redacted]']) {
    assert.ok(text.includes(part), part);
  }
  assert.ok(find(box, (n) => n.tag === 'span' && n.textContent === 'Active').length === 1);
});

test('only an http(s) address becomes a link, and the AI advice is drawn as the model\'s words', () => {
  const box = confirmBox({
    headline: 'Confirm this finding on ftp://192.0.2.5:21', where: [{label: 'Where it was found', url: 'javascript:alert(1)'}],
    steps: [{title: 'Open the page', run_in: 'browser', url: 'data:text/html,x'},
      {title: 'Suggested by the AI review', run_in: 'advice', detail: 'Check whether anonymous login is still allowed.'}],
  });
  assert.equal(find(box, (n) => n.tag === 'a').length, 0);
  assert.ok(box.textContent.includes('javascript:alert(1)')); // shown as text only
  assert.ok(box.textContent.includes('AI advice'));
  const advice = find(box, (n) => n.tag === 'p' && n.textContent === 'Check whether anonymous login is still allowed.')[0];
  assert.match(advice.className, /untrusted/);
  assert.equal(confirmBox(null), null);
});

test('the empty state says what is true for each state of the finding', () => {
  const when = (iso) => `[${iso}]`;
  const base = (validation, extra = {}) => ({kind: 'vulnerability', validation: {steps: [], ...validation}, ai: {status: 'triaged'}, automatic_validation: null, ...extra});
  // a scanner finding: no automatic check exists for its kind
  assert.equal(checkStateText(base({status: 'none', automatic: {check: false, lane: '', why: ''}}), when),
    'No automatic check exists for this finding; confirm it by hand with the steps above.');
  // its automatic AI review is queued: says so, and since when
  assert.equal(checkStateText(base({status: 'none', automatic: {check: false}}, {automatic_validation: {status: 'queued', created: '2026-11-20T10:00'}}), when),
    'An automatic AI review of this finding (no check is sent to the host for this kind of finding) is queued since [2026-11-20T10:00]; a validation worker takes it next, Fire first.');
  // a match whose check is queued or running
  const match = (validation, extra = {}) => ({...base(validation, extra), kind: 'match'});
  assert.equal(checkStateText(match({status: 'pending', automatic: {check: true, lane: 'fire'}}, {automatic_validation: {status: 'running', started: 'S'}}), when),
    'An automatic validation is running now, since [S].');
  assert.equal(checkStateText(match({status: 'none', automatic: {check: true, lane: 'fire'}}, {automatic_validation: {status: 'queued', source: 'manual', created: 'C'}}), when),
    'A requested validation is queued since [C]; a validation worker takes it next, Fire first.');
  // the sweep will queue it
  assert.match(checkStateText(match({status: 'none', automatic: {check: true, lane: 'smoke'}}), when),
    /^No check has run yet\. This finding is in the Smoke validation lane: the validation sweep, every 5 minutes, queues it/);
  // the sweep will not, and why
  assert.equal(checkStateText(match({status: 'none', automatic: {check: true, lane: '', why: 'its version is not known, so there is nothing to test it against'}}), when),
    'No automatic check will run for this finding: its version is not known, so there is nothing to test it against. Press Validate now, or confirm it by hand with the steps above.');
  // triage has not finished, or not started
  assert.equal(checkStateText(match({status: 'none', automatic: {check: true, lane: ''}}, {ai: {status: 'pending'}}), when),
    'Triage has not finished for this finding yet. Meanwhile, confirm it by hand with the steps above.');
  assert.equal(checkStateText(match({status: 'none', automatic: {check: true, lane: '', why: 'it is not tracked for triage yet'}}, {ai: {status: 'untracked'}}), when),
    'Triage has not started for this finding yet, so no check is planned. Meanwhile, confirm it by hand with the steps above.');
  // the stored states keep their meaning
  assert.equal(checkStateText(match({status: 'no_check', automatic: {check: true}}), when), "No automatic check fits this finding's evidence; confirm it by hand with the steps above.");
  assert.match(checkStateText(match({status: 'skipped_blocked', automatic: {check: true}}), when), /^The checks were not run: the host is outside this project/);
  assert.match(checkStateText(match({status: 'pending', automatic: {check: true}}), when), /^Checks are queued and run automatically/);
  // an older server that sends no plan still gets a sentence, never an empty panel
  assert.ok(checkStateText({kind: 'hygiene', validation: {status: 'none', steps: []}, ai: {}}).length > 20);
});

test('the finding page draws the panel from these modules and no longer promises checks that do not exist', () => {
  const app = readFileSync(new URL('../static/cve/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(app, /None has run yet/);
  assert.match(app, /import \{ OS_LABEL, confirmBox \} from "\/staticfiles\/cve\/confirm-guide\.js"/);
  assert.match(app, /checkStateText\(d, shortDate\)/);
  for (const name of ['confirm-guide.js', 'confirm-guide-logic.js']) {
    assert.doesNotMatch(readFileSync(new URL(`../static/cve/${name}`, import.meta.url), 'utf8'), /innerHTML|insertAdjacentHTML|outerHTML/);
  }
});
