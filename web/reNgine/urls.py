from django.conf import settings
from django.urls import re_path
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from tenancy.views import MFALoginView, SignOutView, admin_login_redirect
from reNgine.admin_masking import mask_secret_fields
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from reNgine.views import serve_protected_media

schema_view = get_schema_view(
   openapi.Info(
      title="CVEngine API",
      default_version='v1',
      description="CVEngine: AI-assisted vulnerability management.",
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

mask_secret_fields()  # the admin never shows a stored secret

urlpatterns = [
    path('', include('agentapi.urls')),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    # before admin/: the stock admin login would sign a staff user in with the password alone and skip the second step
    path('admin/login/', admin_login_redirect, name='admin_login_redirect'),
    path(
        'admin/',
        admin.site.urls),
    path(
        '',
        include('dashboard.urls')),
    path(
        'mfa/',
        include('tenancy.urls')),
    path(
        'cve/',
        include('cveFeed.urls')),
    path(
        'scan/',
        include('startScan.urls')),
    path(
        'login/',
        MFALoginView.as_view(template_name='tenancy/login.html'),
        name='login'),
    path(
        'logout/',
        SignOutView.as_view(template_name='base/logout.html'),
        name='logout'),
    path(
        'api/',
        include(
            'api.urls',
            'api')),
    path(
        'media/<path:path>', 
        serve_protected_media, 
        name='serve_protected_media'
    ),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
# ] + static(settings.MEDIA_URL, document_root=settings.RENGINE_RESULTS) + \
    
