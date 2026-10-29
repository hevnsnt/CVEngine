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
