import assert from 'node:assert/strict';
import {test} from 'node:test';

import {allHostsText, changesHref, foldedTitle, hostsHref, impactPanel, kpiHref, pillClass, readLink, rowHref, seeHostsText, sparkLabel, sparkPoints, toneClass} from '../static/cve/overview-logic.js';

test('a sparkline puts the lowest value at the bottom and the newest at the right', () => {
  const pts = sparkPoints([1, 2, 3]).split(' ').map((p) => p.split(',').map(Number));
  assert.equal(pts.length, 3);
  assert.deepEqual(pts[0], [3, 29]);
  assert.deepEqual(pts[2], [117, 3]);
  assert.ok(pts[0][1] > pts[1][1] && pts[1][1] > pts[2][1]);
});

test('a flat series is a flat line, one value is a point in the middle and nothing is nothing', () => {
  const ys = new Set(sparkPoints([5, 5, 5]).split(' ').map((p) => p.split(',')[1]));
  assert.equal(ys.size, 1);
  assert.equal(sparkPoints([7]).split(',')[0], '60.0');
  assert.equal(sparkPoints([]), '');
  assert.equal(sparkPoints(null), '');
  assert.equal(sparkPoints([1, NaN, 3]).split(' ').length, 2);
});

test('the sparkline says in words where the figure went', () => {
  assert.equal(sparkLabel('Exposed hosts', [41, 30, 55]), 'Exposed hosts over 3 days, rising from 41 to 55');
  assert.equal(sparkLabel('Exposed hosts', [9, 4]), 'Exposed hosts over 2 days, falling from 9 to 4');
  assert.equal(sparkLabel('Mean time to fix', [3.3, 3.3]), 'Mean time to fix over 2 days, flat at 3.3');
  assert.match(sparkLabel('Exposed hosts', [1]), /not enough days/);
});

test('worse is fire and better is ok; anything else is not coloured', () => {
  assert.equal(toneClass('worse'), 'worse');
  assert.equal(toneClass('better'), 'better');
  assert.equal(toneClass('flat'), '');
  assert.equal(toneClass(undefined), '');
  assert.equal(pillClass('fire'), 'fire');
  assert.equal(pillClass('nonsense'), 'smoke');
});

test('a tile links to the page it counts, and nowhere for a slug that is not one', () => {
  assert.equal(kpiHref('exposed', 'acme'), '/cve/acme/hosts/?exposed=1');
  assert.equal(kpiHref('exposed', '_all'), '/cve/_all/hosts/?exposed=1');
  assert.equal(kpiHref('critical', 'acme'), '/cve/acme/vulns/?severity=critical');
  assert.equal(kpiHref('needs', 'a/../b'), '');
  assert.equal(kpiHref('nope', 'acme'), '');
});

test('the hosts of a card are searched with the group query, encoded', () => {
  assert.equal(hostsHref('acme', {hosts_query: 'tech:"PHP"'}), '/cve/acme/hosts/?q=tech%3A%22PHP%22');
  assert.equal(hostsHref('acme', {hosts_query: ''}), '');
  assert.equal(hostsHref('bad slug', {hosts_query: 'x'}), '');
});

test('the second link is the Zero Wire briefing only when it is on radar.cloudflare.com/zero-wire, else the first CVE', () => {
  assert.deepEqual(readLink({link: 'https://radar.cloudflare.com/zero-wire/x', link_label: 'Read the Zero Wire briefing', cve_ids: ['CVE-2026-1234']}),
    {href: 'https://radar.cloudflare.com/zero-wire/x', label: 'Read the Zero Wire briefing', external: true});
  assert.equal(readLink({link: 'https://evil.example/zero-wire/', cve_ids: ['CVE-2026-1234']}).href, '/cve/cves/?id=CVE-2026-1234');
  assert.equal(readLink({link: 'javascript:alert(1)', cve_ids: ['CVE-2026-1234', 'CVE-2026-1235']}).label, 'Read CVE-2026-1234 and 1 more');
  assert.equal(readLink({cve_ids: ['<script>']}), null);
});

test('the impact panel names the hosts, splits them by project in the all-projects view and drops what is zero', () => {
  const g = {matched: 3, confirmed: 0, product_only: 4, product: 'PHP', by_project: {matched: [{project: 'Marino Management', n: 3}], product_only: [{project: 'Marino Management', n: 2}, {project: 'Trifident', n: 2}]}};
  assert.deepEqual(impactPanel(g), {matched: {big: '3 hosts', text: 'match by version, all in Marino Management'},
    unknown: {big: '+4 hosts', text: 'run PHP, version unknown (2 Marino Management, 2 Trifident)'}});
  assert.deepEqual(impactPanel({matched: 1, confirmed: 1, product_only: 0, product: 'PHP', by_project: null}), {matched: {big: '1 host', text: 'matches by version, 1 confirmed by a check'}, unknown: null});
  assert.deepEqual(impactPanel({matched: 0, product_only: 1, product: '', by_project: null}).unknown, {big: '1 host', text: 'runs the product, version unknown'});
  assert.deepEqual(impactPanel(null), {matched: null, unknown: null});
});

test('the small words', () => {
  assert.equal(foldedTitle(6), '6 more checked: none of your hosts run them');
  assert.equal(foldedTitle(1), '1 more checked: none of your hosts run it');
  assert.equal(allHostsText(693), 'All 693 hosts that need you →');
  assert.equal(allHostsText(1), 'All 1 host that needs you →');
  assert.equal(allHostsText(1345), 'All 1,345 hosts that need you →');
  assert.equal(seeHostsText(3), 'See the 3 hosts');
  assert.equal(seeHostsText(1), 'See the 1 host');
});

test('a row opens a host or a situations page of a project and nothing else', () => {
  assert.equal(rowHref('/cve/a/hosts/?host=x.example.com'), '/cve/a/hosts/?host=x.example.com');
  assert.equal(rowHref('/cve/a/situations/'), '/cve/a/situations/');
  assert.equal(rowHref('https://evil.example/'), '');
  assert.equal(rowHref('javascript:alert(1)'), '');
});

test('the changes link is the Changes page since the start of the week', () => {
  assert.equal(changesHref('acme', '2026-11-14T15:54:00+00:00'), '/cve/acme/changes/?since=2026-11-14');
  assert.equal(changesHref('acme', null), '/cve/acme/changes/');
  assert.equal(changesHref('a b', '2026-11-14'), '');
});
