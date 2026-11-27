"""Root URL configuration for the project."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from cvengine import views as cvengine_views
from cvengine.admin_masking import mask_secret_fields
from cvengine.client_probe import probe
from cveFeed.report_digest_views import unsubscribe
from tenancy import views as tenancy_views

# Hide stored secrets in the admin before the routes are built.
mask_secret_fields()

urlpatterns = [
    path('', include('agentapi.urls')),
    # Must come before the stock admin: its login page would sign a staff
    # user in with the password alone and skip the second sign-in step.
    path('admin/login/', tenancy_views.admin_login_redirect, name='admin_login_redirect'),
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls')),
    path('mfa/', include('tenancy.urls')),
    path('cve/', include('cveFeed.urls')),
    path('scan/', include('startScan.urls')),
    path('invite/<str:token>/', tenancy_views.invite_view, name='invite'),
    path('unsubscribe/<str:token>/', unsubscribe, name='report_unsubscribe'),
    # Deliberately open: used by scripts/client-address-check.sh.
    path('client-address-probe/<str:token>/', probe, name='client_address_probe'),
    path(
        'login/',
        tenancy_views.MFALoginView.as_view(template_name='tenancy/login.html'),
        name='login',
    ),
    path(
        'logout/',
        tenancy_views.SignOutView.as_view(template_name='base/logout.html'),
        name='logout',
    ),
    path('media/<path:path>', cvengine_views.serve_protected_media, name='serve_protected_media'),
]

# Adds a static files route only in debug mode.
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
