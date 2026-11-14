class ContentSecurityPolicyMiddleware:
    """A Content-Security-Policy with the directives that cost the pages nothing: no <base> or plug-in injection, no framing, forms
    post only to this site. (A script policy needs the inline scripts removed first; this does not restrict them.)"""
    POLICY = "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if 'Content-Security-Policy' not in response:
            response['Content-Security-Policy'] = self.POLICY
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
