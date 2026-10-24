from django.http import HttpResponseRedirect
from django.urls import reverse


def home(request):
    """Root URL: CVEngine's own dashboard (the old reNgine project setup is replaced by the /cve/welcome/ wizard)."""
    return HttpResponseRedirect(reverse('cve_dashboard'))
