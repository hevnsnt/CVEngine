import assert from 'node:assert/strict';
import {test} from 'node:test';

// The Reporting page's decisions (static/cve/reports-logic.js, drawn by reports.js): the picker's groups, the first selection, recipients and the words
// for an email report's schedule and last result.
const L = await import('../static/cve/reports-logic.js');

const SCOPES = [
  {kind: 'org', slug: 'acme', name: 'Acme Org', projects: 2, whole: true},
  {kind: 'org', slug: 'zeta', name: 'Zeta Org', projects: 1, whole: false},
  {kind: 'project', slug: 'acme-web', name: 'Acme Web', org: 'acme', org_name: 'Acme Org'},
  {kind: 'project', slug: 'acme-api', name: 'Acme API', org: 'acme', org_name: 'Acme Org'},
  {kind: 'project', slug: 'zeta-one', name: 'Zeta One', org: 'zeta', org_name: 'Zeta Org'},
  {kind: 'project', slug: 'loose', name: 'Loose', org: '', org_name: ''},
];

test('the picker has a group per organization, the whole organization first, and projects with no organization last', () => {
  const groups = L.scopeOptions(SCOPES);
  assert.deepEqual(groups.map((g) => g.name), ['Acme Org', 'Zeta Org', 'No organization']);
  assert.deepEqual(groups[0].options.map((o) => o.label), ['Whole organization (2 projects)', 'Acme Web', 'Acme API']);
  assert.equal(groups[0].options[0].value, 'org:acme');
  assert.equal(groups[0].options[1].value, 'project:acme-web');
  assert.equal(groups[2].options[0].value, 'project:loose');
});

test('an organization the person reads only in part says so', () => {
  assert.equal(L.scopeOptions(SCOPES)[1].options[0].label, '1 of your projects in Zeta Org');
});

test('the first selection prefers the address, then the shell project, then the first option', () => {
  assert.equal(L.initialScope(SCOPES, {project: 'acme-api', org: 'zeta', slug: 'loose'}), 'project:acme-api');
  assert.equal(L.initialScope(SCOPES, {org: 'zeta', slug: 'loose'}), 'org:zeta');
  assert.equal(L.initialScope(SCOPES, {slug: 'loose'}), 'project:loose');
  assert.equal(L.initialScope(SCOPES, {}), 'org:acme');
  assert.equal(L.initialScope(SCOPES, {project: 'nope', org: 'nope', slug: 'nope'}), 'org:acme');  // a scope the picker does not offer is never chosen
  assert.equal(L.initialScope([], {project: 'acme-web'}), '');
});

test('a value finds its scope, and the address of a page names it', () => {
  assert.equal(L.scopeOf(SCOPES, 'project:acme-web').name, 'Acme Web');
  assert.equal(L.scopeOf(SCOPES, 'org:nope'), null);
  assert.equal(L.pagePath(L.scopeOf(SCOPES, 'org:acme'), 'hosts'), '?org=acme#hosts');
  assert.equal(L.pagePath(L.scopeOf(SCOPES, 'project:acme-web')), '?project=acme-web');
  assert.equal(L.reportPath({org: 'acme'}), '/api/v1/orgs/acme/reports');
  assert.equal(L.reportPath({slug: 'a b'}), '/api/v1/projects/a%20b/reports');
});

test('the includes note names up to five projects and counts the rest', () => {
  assert.equal(L.includesNote(['A', 'B']), 'Includes: A, B');
  assert.equal(L.includesNote(['A', 'B', 'C', 'D', 'E', 'F', 'G']), 'Includes: A, B, C, D, E and 2 more');
  assert.equal(L.includesNote([]), '');
});

test('recipients are lower-cased, deduplicated, checked and capped at ten', () => {
  const out = L.parseRecipients('Dana@Example.org; dana@example.org, not-an-address\nops@example.org  x@y');
  assert.deepEqual(out.valid, ['dana@example.org', 'ops@example.org']);
  assert.deepEqual(out.duplicates, ['dana@example.org']);
  assert.deepEqual(out.invalid, ['not-an-address', 'x@y']);
  const many = Array.from({length: 12}, (_, i) => `u${i}@example.org`).join(',');
  const capped = L.parseRecipients(many);
  assert.equal(capped.valid.length, 10);
  assert.deepEqual(capped.over, ['u10@example.org', 'u11@example.org']);
  assert.deepEqual(L.parseRecipients('').valid, []);
});

test('a schedule reads as a plain sentence', () => {
  assert.equal(L.scheduleSummary({cadence: 'weekly', weekday: 0, send_time: '08:00:00', timezone: 'Europe/London'}), 'Weekly, Mondays 08:00 (Europe/London)');
  assert.equal(L.scheduleSummary({cadence: 'weekly', weekday: 6, send_time: '17:30', timezone: 'UTC'}), 'Weekly, Sundays 17:30 (UTC)');
  assert.equal(L.scheduleSummary({cadence: 'monthly', day_of_month: 1, send_time: '08:00', timezone: 'UTC'}), 'Monthly, day 1 at 08:00 (UTC)');
});

test('the next send and the last result are said in words', () => {
  const now = new Date('2026-11-21T08:00:00Z');
  assert.equal(L.relativeText('2026-11-23T08:00:00Z', now), 'in 2 days');
  assert.equal(L.relativeText('2026-11-21T11:00:00Z', now), 'in 3 hours');
  assert.equal(L.relativeText('2026-11-21T08:12:00Z', now), 'in 12 minutes');
  assert.equal(L.relativeText('2026-11-21T07:00:00Z', now), '60 minutes ago');
  assert.equal(L.nextSendText(null, now), 'Not scheduled');
  assert.match(L.nextSendText('2026-11-23T08:00:00Z', now, () => 'Nov 23, 08:00'), /^Nov 23, 08:00 \(in 2 days\)$/);
  assert.equal(L.lastResultText({}), 'Never sent');
  assert.equal(L.lastResultText({last_status: 'sent', last_sent_at: '2026-11-17T08:00:00Z', recipients: ['a@b.co', 'c@d.co', 'e@f.co']}, () => 'Nov 17, 08:00'), 'Sent Nov 17, 08:00 to 3 recipients');
  assert.equal(L.lastResultText({last_status: 'skipped', last_error: 'outgoing mail is not set up'}), 'Skipped: outgoing mail is not set up');
});

test('the partial result is the server\'s own "1 of 3 failed" sentence, and the card words are plain', () => {
  assert.equal(L.lastResultText({last_status: 'partial', last_error: '1 of 3 failed: the mail server refused the recipient address'}), '1 of 3 failed: the mail server refused the recipient address');
  assert.equal(L.lastResultText({last_status: 'failed', last_error: 'could not connect to the mail server'}), 'Failed: could not connect to the mail server');
  assert.equal(L.lastResultText({last_status: 'disabled', last_error: 'the owner no longer has access'}), 'Paused automatically: the owner no longer has access');
  assert.equal(L.recipientsText(['a@x.org', 'b@x.org', 'c@x.org', 'd@x.org']), 'a@x.org, b@x.org +2');
  assert.equal(L.recipientsText(['a@x.org']), 'a@x.org');
  assert.deepEqual(['none', 'pdf', 'csv'].map(L.attachText), ['No attachment', 'PDF attached', 'CSV attached']);
  assert.deepEqual(L.statusPill({enabled: true}), ['Active', '']);
  assert.deepEqual(L.statusPill({enabled: false, last_status: 'disabled'}), ['Paused automatically', 'failed']);
  assert.deepEqual(L.statusPill({enabled: false, last_status: 'sent'}), ['Paused', 'running']);
  assert.equal(L.defaultName('monthly', 'Acme Web'), 'Monthly report: Acme Web');
  assert.equal(L.defaultName('weekly', 'Acme Web'), 'Weekly report: Acme Web');
});

test('a server message is shown beside the field it names', () => {
  assert.equal(L.fieldOfError('not an email address: x'), 'recipients');
  assert.equal(L.fieldOfError('a@b.org unsubscribed on 2026-11-12; send confirm_opted_out to add it back'), 'recipients');
  assert.equal(L.fieldOfError('timezone must be an IANA time zone name'), 'timezone');
  assert.equal(L.fieldOfError('send_time must be HH:MM'), 'send_time');
  assert.equal(L.fieldOfError('name is required'), 'name');
  assert.equal(L.fieldOfError('audit role is read only'), '');
});
