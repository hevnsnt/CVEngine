"""Fourth review of the library provenance rule, after its scope was narrowed: only a redirect alias and a version every copy of the library
on the whole page contradicts, each copy read to its end, ever close a technology scan's version (cveFeed.js_libraries, correlation). Each
test asserts the safe outcome."""
from django.test import SimpleTestCase
from django.utils import timezone

from cveFeed import js_libraries
from cveFeed.models import CVEMatch, RouteAuth
from startScan.models import ScanHistory, Subdomain
from tests.test_js_libraries_provenance import CONTRA, ReviewScenarioBase
from tests.test_js_library_versions import JQ_371_MIN

JQ_1124 = '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}'
JQ_351 = '/*! jQuery v3.5.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){"use strict"}(window);'
BS_337 = ('/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n * Copyright 2011-2016 Twitter, Inc.\n * Licensed under the MIT license\n */\n'
          'if("undefined"==typeof jQuery)throw new Error("Bootstrap\'s JavaScript requires jQuery");+function(a){"use strict";'
          'var c=function(b,c){this.$element=a(b)};c.VERSION="3.3.7"}(jQuery);')
FILLER = 'var _app_code_' + 'x' * 80 + '=function(){return 1};\n'


def filler(n):
    return FILLER * (n // len(FILLER) + 1)


class WholeFileTests(ReviewScenarioBase):
    """A file read to its end contradicts nothing when it says more than was found: a second library, a second copy, a licence block."""

    def test_a_vendor_bundle_with_bootstrap_after_jquery(self):
        host = 'vb.x.test'
        sub = self.host(host, ['Bootstrap:3.3.7', 'jQuery:3.7.1'])
        self.correlate(sub)
        bundle = JQ_371_MIN + '\n' + filler(90000) + '\n' + BS_337
        self.read_root(host, 200, '<script src="/js/vendor.min.js"></script>', scripts={f'https://{host}/js/vendor.min.js': bundle})
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2024-6484', '3.3.7')].ai_verdict, 'not_affected')

    def test_jquery_deep_in_an_app_bundle(self):
        host = 'ab.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        bundle = filler(140000) + '\n' + JQ_1124 + 'a.fn=a.prototype={jquery:"1.12.4",constructor:a};'
        self.read_root(host, 200, '<script src="/dist/app.js"></script>', scripts={f'https://{host}/dist/app.js': bundle})
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_a_bundle_with_two_jquery_copies(self):
        host = 'tw.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        bundle = JQ_351 + '\n' + filler(60000) + '\n' + JQ_1124  # the later copy is the one that runs
        self.read_root(host, 200, '<script src="/js/vendor.js"></script>', scripts={f'https://{host}/js/vendor.js': bundle})
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_a_file_cut_at_the_read_limit_is_not_read_whole(self):
        host = 'cut.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        big = JQ_371_MIN + '\n' + filler(js_libraries.MAX_SCRIPT_BYTES + 1000)
        self.read_root(host, 200, '<script src="/js/jquery.min.js"></script>', scripts={f'https://{host}/js/jquery.min.js': big})
        self.assertEqual(RouteAuth.objects.get(host=host).evidence['script_page']['unread'], 1)
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_states_all_rule(self):
        found = js_libraries.read_body(JQ_371_MIN)
        self.assertTrue(js_libraries._states_all(JQ_371_MIN, found))
        self.assertFalse(js_libraries._states_all(JQ_371_MIN + '\n/*! some-widget v2 */', found))
        self.assertFalse(js_libraries._states_all(JQ_371_MIN + filler(9000) + BS_337, found))


class EveryCopyReadTests(ReviewScenarioBase):
    """Every copy of the library the page references must be read whole: an unread, refused or third-party copy may be the one that runs."""

    def test_the_last_copy_was_not_served(self):
        host = 'ur.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                                  '<script src="/wp-content/themes/t/js/jquery.js"></script>',
                       scripts={f'https://{host}/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        self.assertTrue(RouteAuth.objects.get(host=host).evidence['libraries']['jquery']['copies_unresolved'])
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_last_copy_on_a_third_party_host(self):
        host = 'ur2.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/js/jquery.min.js"></script><script src="https://static.partner-widgets.example/jquery.min.js"></script>')
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_a_later_copy_named_by_its_ver_that_was_not_read(self):
        host = 'uq.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root(host, 200, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                                  '<script src="/wp-content/themes/t/js/jquery.js?ver=1.12.4"></script>',
                       scripts={f'https://{host}/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN})
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')

    def test_the_themes_own_copy_over_the_read_budget(self):
        host = 'ub.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        names = ['jquery/jquery.min.js?ver=3.7.1', 'jquery/jquery-migrate.min.js?ver=3.4.1', 'jquery/ui/core.min.js?ver=1.13.2',
                 'jquery/ui/datepicker.min.js?ver=1.13.2', 'underscore.min.js?ver=1.13.4', 'swiper.min.js?ver=8.4.5']
        page = (''.join(f'<script src="/wp-includes/js/{n}"></script>' for n in names)
                + '<script src="/wp-content/themes/t/js/jquery.min.js?ver=1.12.4"></script>')
        scripts = {f'https://{host}/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, f'https://{host}/wp-content/themes/t/js/jquery.min.js': JQ_1124}
        scripts.update({f'https://{host}/wp-includes/js/{n.split("?")[0]}': 'var x=1;' for n in names[1:]})
        self.read_root(host, 200, page, scripts=scripts)
        self.assertNotEqual(self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')


class NothingElseClosesTests(ReviewScenarioBase):
    def test_an_alternating_page_closes_at_most_once(self):
        from cveFeed.tasks import reconcile_library_provenance
        host = 'fl.x.test'
        sub = self.host(host, ['jQuery:1.12.4'])
        self.correlate(sub)
        states = []
        for i in range(8):
            self.read_root(host, 200, CONTRA if i % 2 == 0 else CONTRA + '<script src="/never-closes.js">')
            match = self.correlate(sub)[(host, 'CVE-2020-11023', '1.12.4')]
            reconcile_library_provenance()
            match.refresh_from_db()
            states.append('C' if match.ai_verdict == 'not_affected' else 'o')
        self.assertLessEqual(sum(1 for a, b in zip(states, states[1:]) if a != b), 1, ''.join(states))

    def test_an_absence_never_closes_old_rows_included(self):
        sub = self.host('old.x.test', ['jQuery:1.12.4'])
        self.correlate(sub)
        self.read_root('old.x.test', 200, '<script src="/site.js"></script>')
        self.assertEqual(self.correlate(sub)[('old.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')
        row = RouteAuth.objects.get(host='old.x.test')  # a row stored before the unread counts existed
        row.evidence['script_page'].pop('unread', None)
        row.evidence['script_page'].pop('inline_unread', None)
        row.save()
        self.assertEqual(self.correlate(sub)[('old.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')


class AliasTests(ReviewScenarioBase):
    def test_an_apex_that_redirects_to_www(self):
        apex = self.host('x.test', ['jQuery:1.12.4'])
        www = self.host('www.x.test', ['jQuery:1.12.4'])
        self.correlate(apex, www)
        self.read_root('x.test', 301, '', location='https://www.x.test/')
        self.read_root('www.x.test', 200, '<script src="/js/jquery-1.12.4.min.js"></script>', scripts={'https://www.x.test/js/jquery-1.12.4.min.js': JQ_1124})
        found = self.correlate(apex, www)
        self.assertEqual(found[('www.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, '')  # the page that serves it keeps it
        self.assertIn('only redirects to www.x.test', found[('x.test', 'CVE-2020-11023', '1.12.4')].ai_reason)

    def test_http_to_https_on_the_same_host(self):
        sub = self.host('hs.x.test', ['jQuery:1.12.4'], ports=(80, 443))
        self.correlate(sub)
        self.read_root('hs.x.test', 301, '', scheme='http', location='https://hs.x.test/')
        self.read_root('hs.x.test', 302, '', location='https://hs.x.test/en/')
        self.assertNotEqual(self.correlate(sub)[('hs.x.test', 'CVE-2020-11023', '1.12.4')].ai_verdict, 'not_affected')


class VouchedAcrossRescansTests(ReviewScenarioBase):
    """Whatever vouched for the match on an earlier scan's row (a comment, a validation hit, an AI affected verdict, an assignee, a
    remediation status) keeps the next row's match open against the page, through the correlation and the sweep."""

    def rescan(self, name, vouch, site=None):
        from cveFeed.tasks import reconcile_library_provenance
        sub = self.host(name, ['jQuery:1.12.4'])
        match = self.correlate(sub)[(name, 'CVE-2020-11023', '1.12.4')]
        if vouch:
            vouch(match)
        self.read_root(name, 200, CONTRA)  # the page's own jQuery file says 3.7.1
        self.correlate(sub)
        site = site or self.site
        scan = ScanHistory.objects.create(domain=site, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='y')
        later = Subdomain.objects.create(name=name, target_domain=site, scan_history=scan)
        later.ip_addresses.add(*sub.ip_addresses.all())
        later.technologies.add(*sub.technologies.all())
        self.correlate(later)
        reconcile_library_provenance()
        return match, CVEMatch.objects.filter(subdomain=later).first()

    def assert_kept(self, name, vouch):
        first, later = self.rescan(name, vouch)
        self.assertNotEqual(CVEMatch.objects.get(pk=first.pk).ai_verdict, 'not_affected', name)
        self.assertIsNotNone(later, name)
        self.assertNotEqual(later.ai_verdict, 'not_affected', name)
        return later

    def test_a_comment(self):
        from cveFeed.models import FindingComment
        self.assert_kept('vc.x.test', lambda m: FindingComment.objects.create(project=self.project, finding_kind='match', finding_id=m.pk,
                                                                              text='confirmed on the checkout page'))

    def test_a_validation_hit(self):
        from cveFeed.models import Triage
        self.assert_kept('vh.x.test', lambda m: Triage.objects.create(project=self.project, domain=self.site, kind='cve_match', match=m,
                                                                      host=m.subdomain.name, validation_status='hit'))

    def test_an_ai_affected_verdict(self):
        self.assert_kept('va.x.test', lambda m: CVEMatch.objects.filter(pk=m.pk).update(ai_verdict='affected', ai_reason='confirmed'))

    def test_an_assignee_and_a_remediation_status(self):
        from django.contrib.auth import get_user_model
        user = get_user_model().objects.create(username='owner4')
        later = self.assert_kept('vs.x.test', lambda m: CVEMatch.objects.filter(pk=m.pk).update(assignee=user, remediation_status='in_progress'))
        self.assertEqual((later.assignee_id, later.remediation_status), (user.pk, 'in_progress'))

    def test_nobody_vouched_or_another_target_vouched(self):
        _first, later = self.rescan('uv.x.test', None)
        self.assertIsNone(later)  # nobody vouched: the next row has no match
        from django.contrib.auth import get_user_model
        from targetApp.models import Domain
        user = get_user_model().objects.create(username='elsewhere')
        other = Domain.objects.create(name='other-target.test', project=self.project, insert_date=timezone.now())
        _first, later = self.rescan('ot.x.test', lambda m: CVEMatch.objects.filter(pk=m.pk).update(assignee=user), site=other)
        self.assertIsNone(later)  # the vouch was on another target's row of the same name: it does not carry


class InlineReadTests(SimpleTestCase):
    def test_an_inline_script_longer_than_is_read_counts_as_not_read(self):
        long = '<script>' + 'var a=1;' * (js_libraries.MAX_INLINE // 8 + 10) + '</script><script src="/a.js"></script>'
        self.assertEqual(js_libraries.parse_page(long, 'https://x.test/').inline_unread, 1)
