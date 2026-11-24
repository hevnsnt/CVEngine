class ContentSecurityPolicyMiddleware:
    """A Content-Security-Policy with the directives that cost the pages nothing: no <base> or plug-in injection, no framing, forms
    post only to this site. (A script policy needs the inline scripts removed first; this does not restrict them.)

    Beside it, a ``Content-Security-Policy-Report-Only`` header with the script policy the pages should be able to live with: scripts only
    from this site plus the import map (by its hash), styles from this site and inline. The browser blocks nothing for it and reports what
    it would have blocked in its console, so a release can show which pages still need changes before the policy is enforced."""
    POLICY = "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
    REPORT_ONLY_HEADER = 'Content-Security-Policy-Report-Only'
    _report_only = None  # built once per process: the import map only changes with the static files, which change only on a release

    def __init__(self, get_response):
        self.get_response = get_response

    @classmethod
    def report_only_policy(cls):
        if cls._report_only is None:
            from cveFeed.templatetags.assets import importmap_csp_source
            script = "script-src 'self'"
            source = importmap_csp_source()
            if source:
                script += ' ' + source
            cls._report_only = f"{cls.POLICY}; {script}; style-src 'self' 'unsafe-inline'"
        return cls._report_only

    def __call__(self, request):
        response = self.get_response(request)
        if 'Content-Security-Policy' not in response:  # a response with its own policy (an image, a framed preview) keeps only that one
            response['Content-Security-Policy'] = self.POLICY
            if self.REPORT_ONLY_HEADER not in response:
                response[self.REPORT_ONLY_HEADER] = self.report_only_policy()
        return response


class HtmlRevalidateMiddleware:
    """A page (HTML) that sets no Cache-Control of its own gets ``private, no-cache``: the browser keeps it but asks the server before showing it
    again, so no heuristic copy of a page from before an update is shown after it. Files (static, media, downloads) and JSON keep their own
    headers; a response that already sets one (``no-store`` on the sign-in pages, a download) is left alone."""

    def __init__(self, get_response):
        from cveFeed import updater
        updater.build_id()  # Django builds the middleware when the web process starts (not for manage.py commands or Celery): the build is fixed here
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if 'Cache-Control' not in response and not response.streaming and response.get('Content-Type', '').startswith('text/html'):
            response['Cache-Control'] = 'private, no-cache'
        return response
