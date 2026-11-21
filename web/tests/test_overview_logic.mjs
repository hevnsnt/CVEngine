import assert from 'node:assert/strict';
import {test} from 'node:test';

import {allHostsText, changesHref, foldedTitle, hostsHref, hostsLinkHref, impactPanel, kpiHref, pillClass, readLink, rowHref, seeHostsHref, seeHostsText, sparkLabel, sparkPoints, toneClass} from '../static/cve/overview-logic.js';

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
  const g = {matched: 3, confirmed: 0, product_only: 4, product: 'PHP', by_project: {matched: [{project: 'Marino Management', n: 3}], product_only: [{project: 'Marino Management', n: 2}, {project: 'Trifident', n: 2}, {project: 'Empty', n: 0}]}};
  const p = impactPanel(g);
  assert.deepEqual([p.matched.big, p.matched.text, p.matched.href], ['3 hosts', 'match by version, all in Marino Management', '']);
  assert.deepEqual([p.unknown.big, p.unknown.text], ['+4 hosts', 'run PHP, version unknown (2 Marino Management, 2 Trifident)']);
  const one = impactPanel({matched: 1, confirmed: 1, product_only: 0, product: 'PHP', by_project: null});
  assert.deepEqual([one.matched.big, one.matched.text, one.matched.parts, one.unknown], ['1 host', 'matches by version, 1 confirmed by a check', ['matches by version', ', 1 confirmed by a check'], null]);
  const unknown = impactPanel({matched: 0, product_only: 1, product: '', by_project: null}).unknown;
  assert.deepEqual([unknown.big, unknown.text], ['1 host', 'runs the product, version unknown']);
  assert.deepEqual(impactPanel(null), {matched: null, unknown: null});
});

const LINK = (names) => `/cve/acme/hosts/?names=${names}&label=PHP%3A%20two%20flaws`;
const linked = {
  matched: 2, confirmed: 0, product_only: 2, product: 'PHP', hosts_query: 'tech:"PHP"',
  links: {matched: {href: '/cve/oceanx/hosts/?names=a.example%2Cb.example&label=x', n: 2, exact: true}, product_only: {href: '/cve/_all/hosts/?names=dalio%2Fc.example%2Cmarino%2Fd.example', n: 2, exact: true}},
  by_project: {
    matched: [{project: 'OceanX', n: 2, slug: 'oceanx', href: '/cve/oceanx/hosts/?names=a.example%2Cb.example&label=x'}],
    product_only: [{project: 'DalioPhilantropies', n: 1, slug: 'dalio', href: LINK('c.example')}, {project: 'MarinoMgmt', n: 1, slug: 'marino', href: 'javascript:alert(1)'}],
  },
};

test('each count and each project share of it links to exactly those hosts', () => {
  const p = impactPanel(linked);
  assert.equal(p.matched.href, '/cve/oceanx/hosts/?names=a.example%2Cb.example&label=x');
  assert.equal(p.unknown.href, '/cve/_all/hosts/?names=dalio%2Fc.example%2Cmarino%2Fd.example');
  assert.deepEqual(p.matched.parts, ['match by version', ', ', {text: 'all in OceanX', href: '/cve/oceanx/hosts/?names=a.example%2Cb.example&label=x'}]);
  assert.deepEqual(p.unknown.parts, ['run PHP, version unknown', ' (', {text: '1 DalioPhilantropies', href: LINK('c.example')}, ', ', {text: '1 MarinoMgmt', href: ''}, ')']);
  assert.equal(p.unknown.text, 'run PHP, version unknown (1 DalioPhilantropies, 1 MarinoMgmt)');
});

test('"See the N hosts" opens the same hosts as the big number: matched first, else the version-unknown ones, else the old search', () => {
  assert.equal(seeHostsHref('acme', linked), linked.links.matched.href);
  assert.equal(seeHostsHref('acme', {...linked, matched: 0}), linked.links.product_only.href);
  assert.equal(seeHostsHref('acme', {...linked, links: null}), '/cve/acme/hosts/?q=tech%3A%22PHP%22');  // a summary from before the links
  assert.equal(seeHostsHref('acme', {...linked, links: {matched: {href: 'https://evil.example/cve/acme/hosts/?q=x'}}}), '/cve/acme/hosts/?q=tech%3A%22PHP%22');
  assert.equal(seeHostsHref('acme', null), '');
});

test('a count link may only open a Hosts page of this site with an encoded query', () => {
  for (const ok of ['/cve/acme/hosts/?names=a.example', '/cve/_all/hosts/?names=acme%2Fa.example%2Cb%2Fc.example&label=PHP%3A%20x', '/cve/acme/hosts/?q=cve%3ACVE-2026-1']) {
    assert.equal(hostsLinkHref(ok), ok);
  }
  for (const bad of ['//evil.example/cve/acme/hosts/?names=a', 'https://evil.example/cve/acme/hosts/?names=a', 'javascript:alert(1)', '/cve/acme/vulns/?names=a',
    '/cve/acme/hosts/?names=a"><script>', '/cve/acme/hosts/?names=a b', '/cve/../admin/hosts/?x=1', '/cve/acme/hosts/', null, undefined, 42, {href: '/cve/acme/hosts/?x=1'}]) {
    assert.equal(hostsLinkHref(bad), '', String(bad));
  }
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
